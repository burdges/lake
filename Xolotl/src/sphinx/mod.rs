// Copyright 2016 Jeffrey Burdges.

//! Sphinx mix network packet format adapted to Xolotl ratchet
//!
//! ...


/// Secret supplied by the Diffie-Hellman key exchange in Sphinx. 
/// Also secret symmetric key supploied by Xolotl, which must be
/// 256 bits for post-quantum security.
// #[never_forget]
// #[derive(Debug, Default, Clone)]
pub struct SphinxSecret(pub [u8; 32]);  // StackSecret

impl SphinxSecret {
    pub fn new(ss: &[u8; 32]) -> SphinxSecret  {  SphinxSecret(*ss)  }
}


/*

::crypto::Poly1305::


trait Params {
    /// Maximum number of Sphinx and Ratchet hops
    const MAXHOPS: usize = 10;
}
*/
