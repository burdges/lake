// Copyright 2016 Jeffrey Burdges.

//! Sphinx cryptographic routines
//!
//! ...


use ::state::Filter;
use super::SphinxSecret;

use consistenttime::ct_eq_slice;
// use crypto::mac::Mac;
use crypto::poly1305::Poly1305;

use keystream::{KeyStream,SeekableKeyStream};
type KeystreamError = ::keystream::Keystream::Error; 
use chacha::ChaCha20;

/// 
pub type Length = u16;

/// Portion of header key stream to reserve for the Lioness key
const LIONESS_KEY_SIZE: Length = 4*64;

#[inline(always)]
pub fn chacha_blocks(i: L) -> L {
    i/64 + 1  //  (if i%64==0 { 0 } else { 1 }) 
}

/// Sphinx 'static runtime paramaters 
#[derive(Debug,Clone,Copy)]
pub struct SphinxParams {
    pub beta_length: Length,
    pub max_beta_tail_length: Length,
    pub surblog_length: Length;
    pub node_token_key: &'static str,
}

impl SphinxParams {
    #[inline(always)]
    pub fn surb_length(&self) -> Length {
        ::std::mem::size_of::<Alpha>()
        + self.beta_length
        + ::std::mem::size_of::<Gamma>()
    }
}

/// Sphinx node curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub NodePublicKey(pub [u8; 32]);

/// Identifier for the current concenus 
pub ConcensusId(pub [u8; 32]);

/// XChaCha20 not-a-nonce for all packets with a given `NodePublicKey`
/// in a given `ConcensusId`.  Nodes should cache this with their
/// `NodePrivateKey` but clients may simply generate it when building
/// packets.
pub NodeToken(pub [u8; 24]);

impl NodeToken {
    pub fn generate(params: &SphinxParams, 
                    concensus: &ConcensusId, 
                    node: &NodePublicKey
      ) -> NodeToken {
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        let mut nk = [0u8; 24];
        debug_assert_eq!(::std::mem::size_of_val(&r),
          ::std::mem::size_of::<BranchName>());
        let mut sha = Sha3::sha3_512();

        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.input_str(params.node_token_key);
        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.result(&mut nk);
        sha.reset();
        NodeToken(nk);
    }
}

/// Sphinx packet curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Alpha(pub [u8; 32]);

/// Sphinx onion encrypted routing information
// #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub type Beta = [u8];

/// Sphinx poly1305 MAC
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Gamma(pub [u8; 16]);

/// Sphinx poly1305 MAC key
#[derive(Debug,Clone,Copy,Default)]
struct GammaKey(pub [u8; 32]);

/// Semetric cryptography for a single Sphinx hop
///
#[derive(Debug,Clone,Copy,Default)]
pub struct SphinxHop {
    params: &'static SphinxParams,
    gamma_key: GammaKey,
    stream: ChaCha20,
}

impl SphinxHop {
    /// Begin the semetric cryptography for a single Sphinx hop.
    pub fn new<F>(params: &'static SphinxParams,  replays: &mut F, 
                  nk: &NodeToken,  ss: &SphinxSecret,
      ) -> Result<::ClearedBox<SphinxHop>,SphinxError>
      where F: Filter<Key = ReplayCode>
    {
        let mut hop = ClearOnDrop::new(box SphinxHop {
            params: params,
            gamma_key: Default::default(),
            stream: ChaCha20::new_xchacha20(ss.as_ref(), &nk.0)
        });
        let mut mr = [0u8; 64];
        let mut mr = ClearOnDrop::new(&mut mr);
        hop.stream.xor_read(mr.as_mut());
        let (replay_code,_,gamma_key) = array_refs![mr.as_ref(),16,16,32];        
        // let replays: &mut F = replayer();
        if ! replays.insert(replay_code) { // opposite of replays.contains(replay_code)
            return Err( SphinxError::Replay(*replay_code) );
        }
        hop.gamma_key = *gamma_key;
        // ::std::mem::drop(replays);
        Ok(hop)
    }

    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    pub fn create_gamma(&mut self, beta: &Beta, gamma_out: &mut Gamma) -> Result<(),SphinxError> {
        if beta.len() != self.params.beta_length {
            return Err( SphinxError::InternalError("Beta has the incorrect length for MAC!") )
        }
        let mut poly = crypto::poly1305::Poly1305::new(&self.gamma_key.0);
        let mut poly = ClearOnDrop::new(&mut poly);
        poly.input(beta);
        poly.raw_result(&gamma_out);
        poly.reset();
        Ok(())
    }

    /// Regenerate the `ReplayCode` for error reporting.
    pub replay_code() -> Result<ReplayCode,SphinxError> {
        let mut mr = [0u8; 16];
        self.stream.seek_to(64) ?;
        hop.stream.xor_read(r) ?;
        ReplayCode(r)
    }

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet
    pub fn verify_gamma(&mut self, beta: &Beta, gamma_given: &Gamma) -> Result<(),SphinxError> {
        let mut gamma_found = [0u8; 16];
        let mut gamma_found = ClearOnDrop::new(&mut gamma_found);
        self.create_gamma(beta, gamma_found.as_mut()) ?;
        if ! ct_eq_slice(gamma_given, gamma_found.as_mut()) {
            let replay_code = self.replay_code() ?;
            return Err( SphinxError::InvalidMac(*replay_code) );
        }
        Ok(())
    }

    /// Return 
    pub fn lionness_key(lioness_key: &[u8]) -> {
        // TODO Use a fixed length array for the lioness key
        assert!(lioness_key.len() <= LIONESS_KEY_SIZE);
        self.stream.seek_to(64) ?;
        self.stream.xor_read(&lioness_key) ?;
        Ok(())
    }

    fn xor_beta(&mut self, beta: &mut Beta) -> Result<(), SphinxError> {
        if beta.len() < self.params.beta_length {
            return Err( SphinxError::InternalError("Beta too short to encrypt!") )
        } else if beta.len() > self.params.beta_length+self.params.max_beta_tail_length {
            return Err( SphinxError::InternalError("Beta too long to encrypt!") )
        }
        self.stream.seek_to(64+LIONESS_KEY_SIZE) ?;
        self.stream.xor_read(beta) ?;
        Ok(())
    }

    fn xor_beta_tail(&mut self, beta_tail: &mut [u8]) -> Result<(), SphinxError> {
        if beta_tail.len() > self.params.max_beta_tail_length {
            return Err( SphinxError::InternalError("Beta's tail is too long!") )
        }
        self.stream.seek_to(64+LIONESS_KEY_SIZE+self.params.beta_length) ?;
        self.stream.xor_read(beta_tail) ?;
        Ok(())
    }   
}

impl<'a> From<KeystreamError> for SphinxError {
    fn from(ke: KeystreamError) -> SphinxError {
        match ke {
            KeystreamError::EndReached =>
                SphinxError::InternalError("XChaCha20 stream exceeded!"),
        }
    }
}

/*
impl KeyStream for ChaCha {
    /// 
    fn xor_read(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.stream.xor_read(dest)
    }
}

impl SeekableKeyStream for ChaCha {
    /// 
    fn seek_to(&mut self, byte_offset: u64) -> Result<(), Error> {
        self.stream.seek_to(byte_offset+64+LIONESS_KEY_SIZE)
    }
}
*/


