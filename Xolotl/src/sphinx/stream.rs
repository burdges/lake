// Copyright 2016 Jeffrey Burdges.

//! Sphinx header symmetric cryptographic routines
//!
//! ...


use std::sync::RwLock;
use std::fmt;

use clear_on_drop::ClearOnDrop;
use consistenttime::ct_eq_slice;
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


use ::state::Filter;
use super::SphinxSecret;
use super::curve::*;
use super::error::*;
use super::state::*;


/// Alias for indexes into a Sphinx header
pub type Length = u64;

/// Portion of header key stream to reserve for the Lioness key
const LIONESS_KEY_SIZE: Length = 4*64;

#[inline(always)]
pub fn chacha_blocks(i: Length) -> Length {
    i/64 + 1  //  (if i%64==0 { 0 } else { 1 }) 
}

/// Sphinx `'static` runtime paramaters 
///
/// Amount of keystream consumed by `new()`.
/// Optimial performance requires this be a multiple of 64.

#[derive(Debug,Clone,Copy)]
pub struct SphinxParams {
    /// String 
    pub node_token_key: &'static str,

    /// Length of the routing information block `Beta`.
    ///
    /// A multiple of the ChaCha blocksize of 64 may produce better performance.
    pub beta_length: Length,

    /// Maximal amount of routing infomrmation in `Beta` consued
    /// by a single sub-hop.
    ///
    /// A multiple of the ChaCha blocksize of 64 may produce better performance.
    pub max_beta_tail_length: Length,

    /// Length of the SURB log
    ///
    /// A multiple of the ChaCha blocksize of 64 may produce better performance.
    pub surblog_length: Length,
}

impl SphinxParams {
    #[inline(always)]
    pub fn surb_length(&self) -> usize {
        ::std::mem::size_of::<AlphaBytes>()
        + ::std::mem::size_of::<Gamma>()
        + self.beta_length as usize
    }
}

const INVALID_SPHINX_PARAMS : &'static SphinxParams = &SphinxParams {
    node_token_key: "Invalid Sphinx!",
    beta_length: 0,
    max_beta_tail_length: 0,
    surblog_length: 0
};

/// Sphinx node curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodePublicKey(pub [u8; 32]);

/// Identifier for the current concenus 
pub struct ConcensusId(pub [u8; 32]);

/// XChaCha20 not-a-nonce for all packets with a given `NodePublicKey`
/// in a given `ConcensusId`.  Nodes should cache this with their
/// `NodePrivateKey` but clients may simply generate it when building
/// packets.
pub struct NodeToken(pub [u8; 24]);

impl NodeToken {
    pub fn generate(params: &SphinxParams, 
                    concensus: &ConcensusId, 
                    node: &NodePublicKey
      ) -> NodeToken {
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        let mut nk = [0u8; 24];
        let mut sha = Sha3::sha3_512();

        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.input_str(params.node_token_key);
        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.result(&mut nk);
        sha.reset();
        NodeToken(nk)
    }
}


/// Sphinx onion encrypted routing information
// #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub type Beta = [u8];

/// Sphinx poly1305 MAC
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gamma(pub [u8; 16]);

/// Sphinx poly1305 MAC key
#[derive(Debug,Clone,Copy,Default)]
struct GammaKey(pub [u8; 32]);

/// Semetric cryptography for a single Sphinx hop
///
///
pub struct SphinxHop {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

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
        (&mut *hop).params = INVALID_SPHINX_PARAMS;
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
    pub fn new<RC>(params: &'static SphinxParams, replayer: &RC, 
                   nt: &NodeToken,  ss: &SphinxSecret
      ) -> Result<SphinxHop,SphinxError>
      where RC: ReplayChecker
    {
        let mut hop = SphinxHop {
            params: params,
            replay_code: Default::default(),
            gamma_key: Default::default(),
            blinding: Scalar::from_bytes(&[0u8; 32),
            stream: ChaCha20::new_xchacha20(&ss.0, &nt.0)
        };

        let mut b = &mut [0u8; 64];
        // let mut b = ClearOnDrop::new(&mut b);
        /  let mut b = array_mut_ref![b.deref_mut(),0,64];

        hop.stream.xor_read(b);
        // let (replay_code,_,gamma_key) = array_refs![mr,16,16,32];        
        hop.gamma_key = GammaKey(*array_ref![b,32,32]);
        hop.replay_code = ReplayCode(*array_ref![b,0,16]);

        // We require that, if a replay attack occurs, then `replay_check`
        // returns `Err( SphinxError::Replay(hop.replay_code) )`.
        replayer.replay_check(&hop.replay_code) ?;

        hop.stream.xor_read(b);
        hop.blinding = Scalar::make(b);

        Ok(hop)
    }

    /// Regenerate the `ReplayCode` for error reporting.
    pub fn replay_code(&self) -> Result<ReplayCode,SphinxError> {
        // let mut rc = [0u8; 16];
        // self.stream.seek_to(0) ?;
        // self.stream.xor_read(&mut rc) ?;
        // ReplayCode(rc)
        Ok(self.replay_code)
    }

    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    pub fn create_gamma(&mut self, beta: &Beta, surb: &[u8]) -> Result<Gamma,SphinxError> {
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
    pub fn verify_gamma(&mut self, beta: &Beta, surb: &[u8], gamma_given: &Gamma) -> Result<(),SphinxError> {
        let mut gamma_found = [0u8; 16];
        let mut gamma_found = ClearOnDrop::new(&mut gamma_found);
        self.create_gamma(beta, gamma_found.as_mut()) ?;
        if ! ct_eq_slice(gamma_given, gamma_found.as_mut()) {
            let replay_code = self.replay_code().unwrap_or(REPLAY_CODE_UNKNOWN);
            return Err( SphinxError::InvalidMac(replay_code) );
        }
        Ok(())
    }

    /// Assigns slice to contain the lionness key.
    ///
    /// TODO: Use a fixed length array for the lioness key
    pub fn lionness_key(&mut self,lioness_key: &mut [u8]) -> Result<(), SphinxError> {
        if lioness_key.len() > LIONESS_KEY_SIZE as usize {
            return Err( SphinxError::InternalError("Lioness key too long!") );
        }
        self.stream.seek_to(SphinxHop::NEW_OFFSET) ?;
        for x in lioness_key.iter_mut() { *x=0; }
        self.stream.xor_read(lioness_key) ?;
        Ok(())
    }

    fn xor_beta(&mut self, beta: &mut Beta) -> Result<(), SphinxError> {
        if beta.len() < self.params.beta_length as usize {
            return Err( SphinxError::InternalError("Beta too short to encrypt!") );
        }
        if beta.len() > (self.params.beta_length+self.params.max_beta_tail_length) as usize {
            return Err( SphinxError::InternalError("Beta too long to encrypt!") );
        }
        self.stream.seek_to(
          SphinxHop::NEW_OFFSET + LIONESS_KEY_SIZE
        ) ?;
        self.stream.xor_read(beta) ?;
        Ok(())
    }

    fn xor_beta_tail(&mut self, beta_tail: &mut [u8]) -> Result<(), SphinxError> {
        if beta_tail.len() > self.params.max_beta_tail_length as usize {
            return Err( SphinxError::InternalError("Beta's tail is too long!") );
        }
        self.stream.seek_to(
          SphinxHop::NEW_OFFSET + LIONESS_KEY_SIZE
          + self.params.beta_length
        ) ?;
        self.stream.xor_read(beta_tail) ?;
        Ok(())
    }

    pub fn xor_surblog(&mut self, surb_log: &mut [u8]) -> Result<(), SphinxError> {
        if surb_log.len() != self.params.surblog_length as usize {
            return Err( SphinxError::InternalError("SURB log has incorrect length!") );
        }
        self.stream.seek_to(
          SphinxHop::NEW_OFFSET + LIONESS_KEY_SIZE 
          + self.params.beta_length
          + self.params.max_beta_tail_length
        ) ?;
        self.stream.xor_read(surb_log) ?;
        Ok(())
    }

    pub fn xor_surb(&mut self, surb: &mut [u8]) -> Result<(), SphinxError> {
        if surb.len() != self.params.surb_length() {
            return Err( SphinxError::InternalError("SURB has incorrect length!") );
        }
        self.stream.seek_to(
          SphinxHop::NEW_OFFSET + LIONESS_KEY_SIZE
          + self.params.beta_length
          + self.params.max_beta_tail_length
          + self.params.surblog_length
        ) ?;
        self.stream.xor_read(surb) ?;
        Ok(())
    }

}

/*
impl KeyStream for SphinxHop {
    /// Allow 
    fn xor_read(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.stream.xor_read(dest)
    }
}

impl SeekableKeyStream for SphinxHop {
    /// Hide any keystream 
    fn seek_to(&mut self, byte_offset: u64) -> Result<(), Error> {
        let skip = 64*chacha_blocks(SphinxHop::NEW_OFFSET+LIONESS_KEY_SIZE);
        self.stream.seek_to(byte_offset + skip)
    }
}
*/


