// Copyright 2016 Jeffrey Burdges.

//! Sphinx header symmetric cryptographic routines
//!
//! ...


use std::fmt;
use std::ops::Range;
use std::marker::PhantomData;


// use clear_on_drop::ClearOnDrop;
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
                // panic!("Failed to unwrap ChaCha call!");
                SphinxError::InternalError("XChaCha20 stream exceeded!")
            },
        }
    }
}

use super::*;
use super::layout::{Params};
use super::body::{BodyCipher,BODY_CIPHER_KEY_SIZE};
use super::replay::*;
use super::error::*;


// /// Sphinx onion encrypted routing information
// pub type BetaBytes = [u8];

pub const GAMMA_LENGTH : usize = 16;

/// Unwrapped Sphinx poly1305 MAC 
pub type GammaBytes = [u8; GAMMA_LENGTH];

/// Wrapped Sphinx poly1305 MAC
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gamma(pub GammaBytes);

/// Sphinx poly1305 MAC key
#[derive(Debug,Clone,Copy,Default)]
struct GammaKey(pub [u8; 32]);


/// Results of our KDF consisting of the nonce and key for our
/// IETF Chacha20 stream cipher, which produces everything else
/// in the Sphinx header.
pub struct SphinxKey<P: Params> {
    pub params: PhantomData<P>,

    /// IETF ChaCha20 12 byte nonce 
    pub chacha_nonce: [u8; 12],

    /// IETF ChaCha20 32 byte key 
    pub chacha_key: [u8; 32],
}

impl<P: Params> SphinxKey<P> {
    /// Derive the key material for our IETF Chacha20 stream cipher.
    pub fn new_kdf(ss: &SphinxSecret, rn: &keys::RoutingName) -> SphinxKey<P> {
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        let r = &mut [0u8; 32+16];  // ClearOnDrop
        let mut sha = Sha3::shake_256();
        sha.input(&ss.0);
        sha.input_str( "Sphinx" );
        sha.input(&rn.0);
        sha.input_str( P::PROTOCOL_NAME );
        sha.input(&ss.0);
        sha.result(r);
        sha.reset();

        let (chacha_nonce,_,chacha_key) = array_refs![r,12,4,32];
        SphinxKey {
            params: PhantomData,
            chacha_nonce: *chacha_nonce,
            chacha_key: *chacha_key,
        }
    }

    /// Initalize an IETF ChaCha20 stream cipher with our key material
    /// and use it to generate the poly1305 key for our MAC gamma, and
    /// the packet's name for SURB unwinding.
    ///
    /// Notes: We could improve performance by using the curve25519 point
    /// derived in the key exchagne directly as the key for an XChaCha20
    /// instance, which includes some mixing, and using chacha for the
    /// replay code and gamma key.  We descided to use SHA3's SHAKE256
    /// mode so that we have more and different mixing.
    pub fn hop(&self) -> SphinxResult<SphinxHop<P>> {
        let mut chacha = ChaCha20::new_ietf(&self.chacha_key, &self.chacha_nonce);
        let mut r = &mut [0u8; HOP_EATS];
        chacha.xor_read(r).unwrap();  // No KeystreamError::EndReached here.
        let (packet_name,replay_code,gamma_key) = array_refs![r,16,16,32];

        Ok( SphinxHop {
            params: PhantomData,
            chunks: StreamChunks::make::<P>() ?,
            packet_name: PacketName(*packet_name),
            replay_code: ReplayCode(*replay_code),
            gamma_key: GammaKey(*gamma_key),
            stream: chacha,
        } )
    }
}

/// Amount of key stream consumed by `hop()` itself
const HOP_EATS : usize = 64;

/// Allocation of cipher ranges for the IETF ChaCha20 inside
/// `SphinxHop` to various keys and stream cipher roles needed
/// to process a header.
struct StreamChunks {
    beta: Range<usize>,
    beta_tail: Range<usize>,
    surb_log: Range<usize>,
    lioness_key: Range<usize>,
    blinding: Range<usize>,
    delay: Range<usize>,
}

impl StreamChunks {
    #[inline]
    fn make<P: Params>() -> SphinxResult<StreamChunks> {
        let mut offset = HOP_EATS;  // 
        let chunks = {
            let mut reserve = |l: usize, block: bool| -> Range<usize> {
                if block { offset += 64 - offset % 64; }
                let previous = offset;
                offset += l;
                let r = previous..offset;
                debug_assert_eq!(r.len(), l);
                r
            };
            StreamChunks {
                beta:  reserve(P::BETA_LENGTH as usize,true),
                beta_tail:  reserve(P::MAX_BETA_TAIL_LENGTH as usize,false),
                surb_log:  reserve(P::SURB_LOG_LENGTH as usize,true),
                lioness_key:  reserve(BODY_CIPHER_KEY_SIZE,true),
                blinding:  reserve(64,true),
                delay:  reserve(64,true), // Actually 32
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
pub struct SphinxHop<P: Params> {
    params: PhantomData<P>,

    /// XChaCha20 Stream cipher used when processing the header
    stream: ChaCha20,

    /// Stream cipher ranges determined by `params`
    chunks: StreamChunks,

    /// Replay code for replay protection
    replay_code: ReplayCode,

    /// The packet's name for SURB unwinding
    packet_name: PacketName,

    /// Sphinx poly1305 MAC key
    gamma_key: GammaKey,
}

// Declare a `SphinxHop` initalized after `ClearOnDrop` zeros it so
// that it may be dropped normally.  Requirs that `Drop::drop` does 
// nothing interesting.
impl<P: Params> ::clear_on_drop::clear::InitializableFromZeroed for SphinxHop<P> {
    unsafe fn initialize(hop: *mut SphinxHop<P>) {
    }
}

// We implement `Drop::drop` so that `SphinxHop` cannot be copy.
// `InitializableFromZeroed::initialize` leaves it invalid, so
// `Drop::drop` must not do anything interesting.
impl<P: Params> Drop for SphinxHop<P> {
    fn drop(&mut self) { }
}

impl<P: Params> fmt::Debug for SphinxHop<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SphinxHop {{ {:?}, .. }}", self.replay_code.error_packet_id())
    }
}

impl<P: Params> SphinxHop<P> {
    // TODO: Can we abstract the lengths checks?  Operate on a pair
    // `(LayoutRefs,SphinxHop)` perhaps?

    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    ///
    /// Does not verify the lengths of Beta or the SURB.
    pub fn create_gamma(&self, beta: &[u8]) -> SphinxResult<Gamma> {
        if beta.len() != P::BETA_LENGTH as usize {
            return Err( SphinxError::InternalError("Beta has the incorrect length for MAC!") );
        }

        // According to the current API gamma_out lies in a buffer supplied
        // by our caller, so no need for games to zero it here.
        let mut gamma_out: Gamma = Default::default();

        let mut poly = Poly1305::new(&self.gamma_key.0);
        // let mut poly = ClearOnDrop::new(&mut poly);
        poly.input(beta);
        poly.raw_result(&mut gamma_out.0);
        poly.reset();
        Ok(gamma_out)
    }

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet.
    ///
    /// Returns an InvalidMac error if the check fails.  Does not
    /// verify the lengths of Beta or the SURB.
    pub fn verify_gamma(&self, beta: &[u8], gamma_given: &Gamma)
      -> SphinxResult<()> {
        let gamma_found = self.create_gamma(beta) ?;  // InternalError
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

    pub fn body_cipher(&mut self) -> BodyCipher<P> {
        BodyCipher {
            params: PhantomData,
            cipher: ::lioness::LionessDefault::new_raw(& self.lioness_key())
        }
    }

    /// Returns the curve25519 scalar for blinding alpha in Sphinx.
    pub fn blinding(&mut self) -> curve::Scalar {
        let mut b = &mut [0u8; 64];
        self.stream.seek_to(self.chunks.blinding.start as u64).unwrap();
        self.stream.xor_read(b).unwrap();
        curve::Scalar::make(b)
    }

    /// Returns our name for the packet for insertion into the SURB log
    /// if the packet gets reforwarded.
    pub fn packet_name(&mut self) -> &PacketName {
        &self.packet_name
    }

    pub fn xor_beta(&mut self, beta: &mut [u8], allow_tail: bool) -> SphinxResult<()> {
        let mut len = P::BETA_LENGTH as usize;
        if beta.len() < len {
            return Err( SphinxError::InternalError("Beta too short to encrypt!") );
        }
        if allow_tail { len += P::MAX_BETA_TAIL_LENGTH as usize }
        if beta.len() > len {
            return Err( SphinxError::InternalError("Beta too long to encrypt!") );
        }
        self.stream.seek_to(self.chunks.beta.start as u64).unwrap();
        self.stream.xor_read(beta).unwrap();
        Ok(())
    }

    pub fn set_beta_tail(&mut self, beta_tail: &mut [u8]) -> SphinxResult<()> {
        if beta_tail.len() > P::MAX_BETA_TAIL_LENGTH as usize {
            return Err( SphinxError::InternalError("Beta's tail is too long!") );
        }
        for i in beta_tail.iter_mut() { *i = 0; }
        self.stream.seek_to(self.chunks.beta_tail.start as u64).unwrap();
        self.stream.xor_read(beta_tail).unwrap();
        Ok(())
    }

    pub fn xor_surb_log(&mut self, surb_log: &mut [u8]) -> SphinxResult<()> {
        if surb_log.len() > P::SURB_LOG_LENGTH as usize {
            return Err( SphinxError::InternalError("SURB log too long!") );
        }
        self.stream.seek_to(self.chunks.surb_log.start as u64).unwrap();
        self.stream.xor_read(surb_log).unwrap();
        Ok(())
    }

    /// Sender's sugested delay for this packet
    pub fn delay(&mut self) -> ::std::time::Duration {
        use rand::{ChaChaRng, SeedableRng}; // Rng, Rand
        let mut rng = {
            let mut s = [0u32; 8];
            fn as_bytes_mut(t: &mut [u32; 8]) -> &mut [u8; 32] {
                unsafe { ::std::mem::transmute(t) }
            }
            self.stream.seek_to(self.chunks.delay.start as u64).unwrap();
            self.stream.xor_read(as_bytes_mut(&mut s)).unwrap();
            for i in s.iter_mut() { *i = u32::from_le(*i); }
            ChaChaRng::from_seed(&s)
        };

        use rand::distributions::{Exp, IndependentSample};
        let exp = Exp::new(P::DELAY_LAMBDA);
        let delay = exp.ind_sample(&mut rng);
        debug_assert!( delay.is_finite() && delay.is_sign_positive() );

        ::std::time::Duration::from_secs( delay.round() as u64 )
        // ::std::time::Duration::new(
        //   delay.trunc() as u64, 
        //   (1000*delay.fract()).round() as u32
        // )
    }

    // /// Approximate time when mix node should forward this packet
    // pub fn time(&mut self) -> ::std::time::SystemTime {
    //     ::std::time::SystemTime::now() + self.delay()
    // }
}


