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
            KeystreamError::EndReached =>
                SphinxError::InternalError("XChaCha20 stream exceeded!"),
        }
    }
}


use super::SphinxSecret;
use super::curve::*;
use super::header::{Length,SphinxParams};
use super::replay::*;
use super::node::NodeToken;
use super::error::*;

/// Portion of header key stream to reserve for the Lioness key
const LIONESS_KEY_SIZE: Length = 4*64;


struct Chunks {
    beta: Range<Length>,
    beta_tail: Range<Length>,
    surb_log: Range<Length>,
    surb: Range<Length>,
    lioness_key: Range<Length>,
}

impl SphinxParams {
    #[inline]
    fn stream_chunks(&self) -> Chunks {
        let mut offset = SphinxHop::NEW_OFFSET;
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
            lioness_key:  reserve(LIONESS_KEY_SIZE,true),
        }
    }
}

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

/// Semetric cryptography for a single Sphinx sub-hop, usually
/// meaning the whole hop.
///
pub struct SphinxHop {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    /// Stream cipher ranges determined by `params`
    chunks: Chunks,

    /// Replay code when reporting errors.
    ///
    /// We do replay protection in `SphinxHop::new()` so this exists
    /// so that `SphinxHop::replay_code()` can avoid seeking stream
    /// and safely take only an immutable reference.
    replay_code: ReplayCode,

    /// Sphinx poly1305 MAC key
    gamma_key: GammaKey,

    /// Sphinx blinding factor given by a curve25519 scalar
    blinding: Scalar,

    /// XChaCha20 Stream cipher used when processing the header
    stream: ChaCha20,
}

// Declare a `SphinxHop` initalized after `ClearOnDrop` zeros it so
// that it may be dropped normally.  Requirs that `Drop::drop` does 
// not dereference `self.params`.
impl ::clear_on_drop::clear::InitializableFromZeroed for SphinxHop {
    unsafe fn initialize(hop: *mut SphinxHop) {
        // (&mut *hop).params = INVALID_SPHINX_PARAMS;
        let _ = hop;  // silence warn(unused_variables)
    }
}

// `Drop::drop` should not dereference `self.params` as 
// `InitializableFromZeroed::initialize` leaves it invalid.
impl Drop for SphinxHop {
    fn drop(&mut self) { }
}

impl fmt::Debug for SphinxHop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let replay_code = self.replay_code().unwrap_or(REPLAY_CODE_UNKNOWN);
        write!(f, "SphinxHop {{ {:?}, .. }}", replay_code)
    }
}

impl SphinxHop {
    /// Amount of keystream consumed by `new()`.
    ///
    /// Keep this multiple of the ChaCha blocksize of 64 for optimal performance.
    const NEW_OFFSET: Length = 64+64;

    /// Begin semetric cryptography for a single Sphinx hop.
    pub fn new<RC>(params: &'static SphinxParams, replayer: RC, 
                   nt: &NodeToken,  ss: &SphinxSecret
      ) -> SphinxResult<SphinxHop>
      where RC: ReplayChecker
    {
        let mut hop = SphinxHop {
            params: params,
            chunks: params.stream_chunks(),
            replay_code: Default::default(),
            gamma_key: Default::default(),
            blinding: Scalar::from_bytes(&[0u8; 32]),
            stream: ChaCha20::new_xchacha20(&ss.0, &nt.0)
        };

        let mut b = &mut [0u8; 64];
        // let mut b = ClearOnDrop::new(&mut b);
        // let mut b = array_mut_ref![b.deref_mut(),0,64];

        hop.stream.xor_read(b) ?;
        // let (replay_code,_,gamma_key) = array_refs![mr,16,16,32];        
        hop.gamma_key = GammaKey(*array_ref![b,32,32]);
        hop.replay_code = ReplayCode(*array_ref![b,0,16]);

        // We require that, if a replay attack occurs, then `replay_check`
        // returns `Err( SphinxError::Replay(hop.replay_code) )`.
        replayer.replay_check(&hop.replay_code) ?;

        hop.stream.xor_read(b) ?;
        hop.blinding = Scalar::make(b);

        Ok(hop)
    }

    /// Regenerate the `ReplayCode` for error reporting.
    pub fn replay_code(&self) -> SphinxResult<ReplayCode> {
        // let mut rc = [0u8; 16];
        // self.stream.seek_to(0) ?;
        // self.stream.xor_read(&mut rc) ?;
        // ReplayCode(rc)
        Ok(self.replay_code)
    }

    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    pub fn create_gamma(&mut self, beta: &[u8], surb: &[u8]) -> SphinxResult<Gamma> {
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
    pub fn verify_gamma(&mut self, beta: &[u8], surb: &[u8],
      gamma_given: &Gamma) -> SphinxResult<()> {
        let gamma_found = self.create_gamma(beta, surb) ?;
        // let gamma_found = ClearOnDrop::new(&gamma_found);
        if ! ::consistenttime::ct_u8_slice_eq(&gamma_given.0, &gamma_found.0) {
            let replay_code = self.replay_code().unwrap_or(REPLAY_CODE_UNKNOWN);
            return Err( SphinxError::InvalidMac(replay_code) );
        }
        Ok(())
    }

    /// Assigns slice to contain the lionness key.
    ///
    /// TODO: Use a fixed length array for the lioness key
    pub fn lionness_key(&mut self,lioness_key: &mut [u8]) -> SphinxResult<()> {
        if lioness_key.len() > LIONESS_KEY_SIZE {
            return Err( SphinxError::InternalError("Lioness key too long!") );
        }
        self.stream.seek_to(self.chunks.lioness_key.start as u64) ?;
        for x in lioness_key.iter_mut() { *x=0; }
        self.stream.xor_read(lioness_key) ?;
        Ok(())
    }

    fn xor_beta(&mut self, beta: &mut [u8]) -> SphinxResult<()> {
        if beta.len() < self.params.beta_length {
            return Err( SphinxError::InternalError("Beta too short to encrypt!") );
        }
        if beta.len() > (self.params.beta_length+self.params.max_beta_tail_length) as usize {
            return Err( SphinxError::InternalError("Beta too long to encrypt!") );
        }
        self.stream.seek_to(self.chunks.beta.start as u64) ?;
        self.stream.xor_read(beta) ?;
        Ok(())
    }

    fn xor_beta_tail(&mut self, beta_tail: &mut [u8]) -> SphinxResult<()> {
        if beta_tail.len() > self.params.max_beta_tail_length {
            return Err( SphinxError::InternalError("Beta's tail is too long!") );
        }
        self.stream.seek_to(self.chunks.beta_tail.start as u64) ?;
        self.stream.xor_read(beta_tail) ?;
        Ok(())
    }

    pub fn xor_surb_log(&mut self, surb_log: &mut [u8]) -> SphinxResult<()> {
        if surb_log.len() != self.params.surb_log_length {
            return Err( SphinxError::InternalError("SURB log has incorrect length!") );
        }
        self.stream.seek_to(self.chunks.surb_log.start as u64) ?;
        self.stream.xor_read(surb_log) ?;
        Ok(())
    }

    pub fn xor_surb(&mut self, surb: &mut [u8]) -> SphinxResult<()> {
        if surb.len() != self.params.surb_length() {
            return Err( SphinxError::InternalError("SURB has incorrect length!") );
        }
        self.stream.seek_to(self.chunks.surb.start as u64) ?;
        self.stream.xor_read(surb) ?;
        Ok(())
    }
}


