// Copyright 2016 Jeffrey Burdges.

//! Sphinx header symmetric cryptographic routines
//!
//! ...


use std::fmt;
use std::ops::Range;

use clear_on_drop::ClearOnDrop;
use crypto::mac::Mac;
use crypto::poly1305::Poly1305;

use chacha::ChaCha as ChaCha20;
use keystream::{KeyStream,SeekableKeyStream};
use keystream::Error as KeystreamError;
impl<'a> From<KeystreamError> for SphinxError {
    fn from(ke: KeystreamError) -> SphinxError {
        match ke {
            KeystreamError::EndReached => {
                // We verify the maximum key stream length is not
                // exceeded inside `SphinxParams::stream_chunks`.
                panic!("Failed to unwrap ChaCha call!");
                SphinxError::InternalError("XChaCha20 stream exceeded!")
            },
        }
    }
}

use super::SphinxSecret;
use super::curve::*;
use super::header::{Length,SphinxParams};
use super::body::{BodyCipher,BODY_CIPHER_KEY_SIZE};

use super::replay::*;
use super::node::NodeToken;
use super::error::*;


// /// Sphinx onion encrypted routing information
// pub type BetaBytes = [u8];

pub const GAMMA_LENGTH : Length = 16;

/// Unwrapped Sphinx poly1305 MAC 
pub type GammaBytes = [u8; GAMMA_LENGTH];

/// Wrapped Sphinx poly1305 MAC
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gamma(pub GammaBytes);

/// Sphinx poly1305 MAC key
#[derive(Debug,Clone,Copy,Default)]
struct GammaKey(pub [u8; 32]);

/// Packet name used for unrolling SURBs
pub struct PacketName(pub [u8; 16]);

/// Sphinx KDF results consisting of the replay code, poly1305 key
/// for our MAC gamma, and a nonce and key for the IETF Chacha20
/// stream cipher used for everything else in the header.
///
/// Notes: We could improve performance by using the curve25519 point 
/// derived in the key exchagne directly as the key for an XChaCha20
/// instance, which includes some mixing, and using chacha for the 
/// replay code and gamma key.  We descided to use SHA3's SHAKE256
/// mode so that we have more and different mixing. 
pub struct SphinxKDF {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    /// Replay code
    replay_code: ReplayCode,

    /// Sphinx poly1305 MAC key
    gamma_key: GammaKey,

    /// IETF ChaCha20 12 byte nonce
    chacha_nonce: [u8; 12],

    /// IETF ChaCha20 32 byte key
    chacha_key: [u8; 32]
}

impl SphinxKDF {
    /// Run our KDF to produce our replay code, poly1305 MAC key, and
    /// nonce and key for Chacha20.
    pub fn new(params: &'static SphinxParams, nt: &NodeToken, ss: &SphinxSecret) 
      -> SphinxKDF {
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        let mut r = &mut [0u8; 16+16+32+32];  // ClearOnDrop
        let mut sha = Sha3::shake_256();
        sha.input_str( "Sphinx" );
        sha.input(&ss.0);
        sha.input_str( params.protocol_name );
        sha.input(&nt.0);
        sha.input(&ss.0);
        sha.input_str( params.protocol_name );
        sha.result(r);
        sha.reset();

        let (replay_code,nonce,_,gamma_key,key) = array_refs![r,16,12,4,32,32];        
        SphinxKDF {
            params: params,
            replay_code: ReplayCode(*replay_code),
            gamma_key: GammaKey(*gamma_key),
            chacha_nonce: *nonce,
            chacha_key: *key,
        }
    }

    /// Checks for packet replays using the suplied `ReplayChecker`.
    /// If none occur, then create the IETF ChaCha20 object to process
    /// the header. 
    ///
    /// Replay protection requires that `ReplayChecker::replay_check`
    /// returns `Err( SphinxError::Replay(hop.replay_code) )` when a
    /// replay occurs.
    ///
    /// You may however use `IgnoreReplay` as the `ReplayChecker` for 
    /// ratchet sub-hops  and for all subhops in packet creation. 
    pub fn replay_check<RC: ReplayChecker>(&self, replayer: RC) -> SphinxResult<SphinxHop> {
        replayer.replay_check(&self.replay_code) ?;

        Ok( SphinxHop {
            params: self.params,
            chunks: self.params.stream_chunks() ?,
            error_packet_id: self.replay_code.error_packet_id(),
            gamma_key: self.gamma_key,
            stream: ChaCha20::new_ietf(&self.chacha_key, &self.chacha_nonce)
        } )
    }
}


/// Allocation of cipher ranges for the IETF ChaCha20 inside
/// `SphinxHop` to various keys and stream cipher roles needed
/// to process a header.
struct Chunks {
    beta: Range<Length>,
    beta_tail: Range<Length>,
    surb_log: Range<Length>,
    surb: Range<Length>,
    lioness_key: Range<Length>,
    blinding: Range<Length>,
    packet_name: Range<Length>,
}

impl SphinxParams {
    #[inline]
    fn stream_chunks(&self) -> SphinxResult<Chunks> {
        let mut offset = 0;
        let chunks = {
            let mut reserve = |l: Length, block: bool| -> Range<Length> {
                if block { offset += 64 - offset % 64; }
                let previous = offset;
                offset += l;
                let r = previous..offset;
                debug_assert_eq!(r.len(), l);
                r
            };
            Chunks {
                beta:  reserve(self.beta_length,true),
                beta_tail:  reserve(self.max_beta_tail_length,false),
                surb_log:  reserve(self.surb_log_length,true),
                surb:  reserve(self.surb_log_length,true),
                lioness_key:  reserve(BODY_CIPHER_KEY_SIZE,true),
                blinding:  reserve(64,true),
                packet_name:  reserve(64,true),
            }
        }; // let chunks
        // We check that the maximum key stream length is not exceeded
        // here so that calls to both `seek_to` and `xor_read` can
        // safetly be `.unwrap()`ed, thereby avoiding `-> SphinxResult<_>`
        // everywhere.
        if offset > 2^38 {
            Err( SphinxError::InternalError("Paramaters exceed IETF ChaCha20 stream!") )
        } else { Ok(chunks) }
    }
}

/// Semetric cryptography for a single Sphinx sub-hop, usually
/// meaning the whole hop.
///
pub struct SphinxHop {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    /// Stream cipher ranges determined by `params`
    chunks: Chunks,

    error_packet_id: ErrorPacketId,

    /// Sphinx poly1305 MAC key
    gamma_key: GammaKey,

    /// XChaCha20 Stream cipher used when processing the header
    stream: ChaCha20,
}

// Declare a `SphinxHop` initalized after `ClearOnDrop` zeros it so
// that it may be dropped normally.  Requirs that `Drop::drop` does 
// not dereference `self.params`.
impl ::clear_on_drop::clear::InitializableFromZeroed for SphinxHop {
    unsafe fn initialize(hop: *mut SphinxHop) {
        (&mut *hop).params = super::header::INVALID_SPHINX_PARAMS;
    }
}

// `Drop::drop` should not dereference `self.params` as 
// `InitializableFromZeroed::initialize` leaves it invalid.
impl Drop for SphinxHop {
    fn drop(&mut self) { }
}

impl fmt::Debug for SphinxHop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SphinxHop {{ {:?}, .. }}", self.error_packet_id)
    }
}

impl SphinxHop {
    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    pub fn create_gamma(&self, beta: &[u8], surb: &[u8]) -> SphinxResult<Gamma> {
        if beta.len() != self.params.beta_length as usize {
            return Err( SphinxError::InternalError("Beta has the incorrect length for MAC!") );
        }
        if surb.len() != self.params.surb_length() {
            return Err( SphinxError::InternalError("SURB has the incorrect length for MAC!") );
        }

        // According to the current API gamma_out lies in a buffer supplied
        // by our caller, so no need for games to zero it here.
        let mut gamma_out: Gamma = Default::default();

        let mut poly = Poly1305::new(&self.gamma_key.0);
        // let mut poly = ClearOnDrop::new(&mut poly);
        poly.input(beta);
        poly.input(surb);
        poly.raw_result(&mut gamma_out.0);
        poly.reset();
        Ok(gamma_out)
    }

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet
    pub fn verify_gamma(&self, beta: &[u8], surb: &[u8],
      gamma_given: &Gamma) -> SphinxResult<()> {
        let gamma_found = self.create_gamma(beta, surb) ?;
        // let gamma_found = ClearOnDrop::new(&gamma_found);
        if ! ::consistenttime::ct_u8_slice_eq(&gamma_given.0, &gamma_found.0) {
            return Err( SphinxError::InvalidMac(self.error_packet_id) );
        }
        Ok(())
    }

    /// Returns full key schedule for the lioness cipher for the body.
    pub fn lioness_key(&mut self) -> [u8; BODY_CIPHER_KEY_SIZE] {
        let lioness_key = &mut [0u8; BODY_CIPHER_KEY_SIZE];
        self.stream.seek_to(self.chunks.lioness_key.start as u64).unwrap();
        self.stream.xor_read(lioness_key).unwrap();
        *lioness_key
    }

    pub fn body_cipher(&mut self) -> BodyCipher {
        BodyCipher {
            params: self.params,
            cipher: ::lioness::LionessDefault::new_raw(& self.lioness_key())
        }
    }

    /// Returns the curve25519 scalar for blinding alpha in Sphinx.
    pub fn blinding(&mut self) -> Scalar {
        let mut b = &mut [0u8; 64];
        self.stream.seek_to(self.chunks.blinding.start as u64).unwrap();
        self.stream.xor_read(b).unwrap();
        Scalar::make(b)
    }

    /// Returns our name for the packet for insertion into the SURB log
    /// if the packet gets reforwarded.
    pub fn packet_name(&mut self) -> PacketName {
        let mut packet_name = &mut [0u8; 16];
        self.stream.seek_to(self.chunks.blinding.start as u64).unwrap();
        self.stream.xor_read(packet_name).unwrap();
        PacketName(*packet_name)
    }

    pub fn xor_beta(&mut self, beta: &mut [u8]) -> SphinxResult<()> {
        if beta.len() < self.params.beta_length {
            return Err( SphinxError::InternalError("Beta too short to encrypt!") );
        }
        if beta.len() > (self.params.beta_length+self.params.max_beta_tail_length) as usize {
            return Err( SphinxError::InternalError("Beta too long to encrypt!") );
        }
        self.stream.seek_to(self.chunks.beta.start as u64).unwrap();
        self.stream.xor_read(beta).unwrap();
        Ok(())
    }

    pub fn set_beta_tail(&mut self, beta_tail: &mut [u8]) -> SphinxResult<()> {
        if beta_tail.len() > self.params.max_beta_tail_length {
            return Err( SphinxError::InternalError("Beta's tail is too long!") );
        }
        for i in beta_tail.iter_mut() { *i = 0; }
        self.stream.seek_to(self.chunks.beta_tail.start as u64).unwrap();
        self.stream.xor_read(beta_tail).unwrap();
        Ok(())
    }

    pub fn xor_surb_log(&mut self, surb_log: &mut [u8]) -> SphinxResult<()> {
        if surb_log.len() != self.params.surb_log_length {
            return Err( SphinxError::InternalError("SURB log has incorrect length!") );
        }
        self.stream.seek_to(self.chunks.surb_log.start as u64).unwrap();
        self.stream.xor_read(surb_log).unwrap();
        Ok(())
    }

    pub fn xor_surb(&mut self, surb: &mut [u8]) -> SphinxResult<()> {
        if surb.len() != self.params.surb_length() {
            return Err( SphinxError::InternalError("SURB has incorrect length!") );
        }
        self.stream.seek_to(self.chunks.surb.start as u64).unwrap();
        self.stream.xor_read(surb).unwrap();
        Ok(())
    }
}


