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
use super::keys::RoutingName;
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

pub const PACKET_NAME_LENGTH : Length = 16;
pub type PacketNameBytes = [u8; PACKET_NAME_LENGTH];

/// Packet name used for unrolling SURBs
#[derive(Copy, Clone, Default)]  // Debug??
pub struct PacketName(pub PacketNameBytes);


/// Results of our KDF consisting of the nonce and key for our
/// IETF Chacha20 stream cipher, which produces everything else
/// in the Sphinx header.
pub struct SphinxKey {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    /// IETF ChaCha20 12 byte nonce 
    pub chacha_nonce: [u8; 12],

    /// IETF ChaCha20 32 byte key 
    pub chacha_key: [u8; 32],
}

impl SphinxParams {
    /// Derive the key material for our IETF Chacha20 stream cipher.
    pub fn sphinx_kdf(&'static self, ss: &SphinxSecret, rn: &RoutingName) -> SphinxKey {
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        let mut r = &mut [0u8; 32+16];  // ClearOnDrop
        let mut sha = Sha3::shake_256();
        sha.input(&ss.0);
        sha.input_str( "Sphinx" );
        sha.input(&rn.0);
        sha.input_str( self.protocol_name );
        sha.input(&ss.0);
        sha.result(r);
        sha.reset();

        let (chacha_nonce,_,chacha_key) = array_refs![r,12,4,32];
        SphinxKey {
            params: self,
            chacha_nonce: *chacha_nonce,
            chacha_key: *chacha_key,
        }
    }
}

impl SphinxKey {
/*
    /// Derive the key material for our IETF Chacha20 stream cipher.
    pub fn new_kdf<N: NodeInfo>(node: &N, ss: &SphinxSecret) -> SphinxKey {
        node.params().sphinx_key(ss, node.name())
    }
*/

    /// Initalize an IETF ChaCha20 stream cipher with our key material
    /// and use it to generate the poly1305 key for our MAC gamma, and
    /// the packet's name for SURB unwinding.
    ///
    /// Notes: We could improve performance by using the curve25519 point
    /// derived in the key exchagne directly as the key for an XChaCha20
    /// instance, which includes some mixing, and using chacha for the
    /// replay code and gamma key.  We descided to use SHA3's SHAKE256
    /// mode so that we have more and different mixing.
    pub fn hop(&self) -> SphinxResult<SphinxHop> {
        let mut chacha = ChaCha20::new_ietf(&self.chacha_key, &self.chacha_nonce);
        let mut r = &mut [0u8; HOP_EATS];
        chacha.xor_read(r).unwrap();  // No KeystreamError::EndReached here.
        let (packet_name,replay_code,gamma_key) = array_refs![r,16,16,32];

        Ok( SphinxHop {
            params: self.params,
            chunks: self.params.stream_chunks() ?,
            packet_name: PacketName(*packet_name),
            replay_code: ReplayCode(*replay_code),
            gamma_key: GammaKey(*gamma_key),
            stream: chacha,
        } )
    }
}

/// Amount of key stream consumed by `hop()` itself
const HOP_EATS : Length = 64;

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
        let mut offset = HOP_EATS;  // 
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
                surb:  reserve(self.surb_length(),true),
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

    /// Replay code for replay protection
    replay_code: ReplayCode,

    /// The packet's name for SURB unwinding
    packet_name: PacketName,

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
        write!(f, "SphinxHop {{ {:?}, .. }}", self.replay_code.error_packet_id())
    }
}

impl SphinxHop {
    // TODO: CAn we abstract the lengths checks?
    // /// Raise errors if beta
    // fn check_lengths(&self, beta: &[u8], surb: &[u8]) -> SphinxResult<()> {
    // }

    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    pub fn create_gamma(&self, beta: &[u8], surb: &[u8]) -> Gamma {
        // According to the current API gamma_out lies in a buffer supplied
        // by our caller, so no need for games to zero it here.
        let mut gamma_out: Gamma = Default::default();

        let mut poly = Poly1305::new(&self.gamma_key.0);
        // let mut poly = ClearOnDrop::new(&mut poly);
        poly.input(beta);
        poly.input(surb);
        poly.raw_result(&mut gamma_out.0);
        poly.reset();
        gamma_out
    }

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet.
    ///
    /// Requires both Beta and the SURB, but not the SURB log.  Also,
    /// requires several key masks with which to attempt verification,
    /// given as a slice `&[GammaKey]`. 
    ///
    /// If gamma verifies with any given mask, then returns the index
    /// of the that passing mask.  At most one mask should ever pass.
    /// If gamma verification fails for all masks, then returns an
    /// InvalidMac error.
    pub fn verify_gamma(&self, beta: &[u8], surb: &[u8], gamma_given: &Gamma)
      -> SphinxResult<()> {
        if beta.len() != self.params.beta_length {
            return Err( SphinxError::InternalError("Beta has the incorrect length for MAC!") );
        }
        if surb.len() != self.params.surb_length() {
            return Err( SphinxError::InternalError("SURB has the incorrect length for MAC!") );
        }

        let gamma_found = self.create_gamma(beta, surb);
        // TODO: let gamma_found = ClearOnDrop::new(&gamma_found);
        if ! ::consistenttime::ct_u8_slice_eq(&gamma_given.0, &gamma_found.0) {
            Err( SphinxError::InvalidMac(self.replay_code.error_packet_id()) )
        } else { Ok(()) }
    }

    /// Checks for packet replays using the suplied `ReplayChecker`.
    ///
    /// Replay protection requires that `ReplayChecker::replay_check`
    /// returns `Err( SphinxError::Replay(hop.replay_code) )` when a
    /// replay occurs.
    ///
    /// You may however use `IgnoreReplay` as the `ReplayChecker` for 
    /// ratchet sub-hops  and for all subhops in packet creation. 
    pub fn replay_check<RC: ReplayChecker>(&self, replayer: RC) -> SphinxResult<()> {
        replayer.replay_check(&self.replay_code)
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
    pub fn packet_name(&mut self) -> &PacketName {
        &self.packet_name
    }

    pub fn xor_beta(&mut self, beta: &mut [u8]) -> SphinxResult<()> {
        if beta.len() < self.params.beta_length {
            return Err( SphinxError::InternalError("Beta too short to encrypt!") );
        }
        if beta.len() > self.params.beta_length+self.params.max_beta_tail_length {
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


