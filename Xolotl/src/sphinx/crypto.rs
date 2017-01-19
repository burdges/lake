// Copyright 2016 Jeffrey Burdges.

//! Sphinx cryptographic routines
//!
//! ...


use ::state::Filter;
use super::SphinxSecret;

use consistenttime::ct_eq_slice;
use crypto::chacha::ChaCha20;
use crypto::poly1305::Poly1305;


/// Sphinx packet curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Alpha(pub [u8; 32]);

/// Sphinx onion encrypted header
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Beta(pub [u8; ????]);

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
    gamma_key: GammaKey,
    stream: ChaCha20,
}

impl SphinxHop {
    /// Begin the semetric cryptography for a single Sphinx hop.
    pub fn new<F>(s: &SphinxSecret, replays: &mut F) 
      -> Result<::ClearedBox<SphinxHop>,SphinxError>
      where F: Filter<Key = ReplayCode>
    {
        let nonce = &[0u8; 24];
        let mut hop = ClearOnDrop::new(box SphinxHop {
            gamma_key: Default::default(),
            stream: ChaCha20::new_xchacha20(s.as_ref(), nonce)
        });
        let mut mr = [0u8; 24];
        let mut mr = ClearOnDrop::new(&mut mr);
        hop.stream.process(&[0u8; 64], mr.as_mut());
        let (replay_code,_,gamma_key) = array_refs![mr.as_ref(),16,16,32];
        // let replays: &mut F = replayer();
        if ! replays.insert(replay_code) {
          // returns opposite of replays.contains(replay_code)
            return Err( SphinxError::Replay );
        }
        hop.gamma_key = *gamma_key;
        // ::std::mem::drop(replays);
        Ok(hop)
    }

    /// Compute the poly1305 MAC `Gamma` using the key found in a Sphinx key exchange.
    pub fn create_gamma(&mut self, beta: &Beta, gamma_out: &mut Gamma) {
        let mut poly = Poly1305::new(&self.gamma_key.0);
        let mut poly = ClearOnDrop::new(&mut poly);
        poly.input(beta);
        poly.raw_result(&gamma_out);
        poly.reset();
    }

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet
    pub fn verify_gamma(&mut self, beta: &Beta, gamma_given: &Gamma) -> Result<(),SphinxError> {
        let mut gamma_found = [0u8; 16];
        let mut gamma_found = ClearOnDrop::new(&mut gamma_found);
        self.create_gamma(beta_given, gamma_found.as_mut());
        if ! ct_eq_slice(gamma_given, gamma_found.as_mut()) {
            return Err( SphinxError::InvalidMac );
        }
        Ok(())
    }

    pub fn process(&mut self, b: &mut [u8]) {
        self.stream.process(b);
    }
}

