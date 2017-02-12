// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...


// pub ed25519_dalek::ed25519;

pub use super::curve::{Scalar,Point};
pub use super::header::SphinxParams;


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
        sha.input_str(params.protocol_name);
        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.result(&mut nk);
        sha.reset();
        NodeToken(nk)
    }
}

/// Secret supplied by the Diffie-Hellman key exchange in Sphinx. 
/// Also secret symmetric key supploied by Xolotl, which must be
/// 256 bits for post-quantum security.
// #[never_forget]
// #[derive(Debug, Default, Clone, Copy)]
pub struct PreSphinxSecret(pub [u8; 32]);  // StackSecret



/*

params: &'static SphinxParams, replayer: RC, 
nt: &NodeToken,  ss: &


    let alpha = alpha.decompress() ?;  // BadAlpha
    let ss: SphinxSecret = alpha.key_exchange(node.private);

    let mut hop = SphinxHop::new(params,replayer,&node.token,&ss);
    hop.verify_gamma(beta,surb,gamma) ?;  // InvalidMAC

    hop.xor_beta(beta)

*/

