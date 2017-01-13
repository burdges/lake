// Copyright 2016 Jeffrey Burdges.

//! Sphinx mix network packet format adapted to Xolotl ratchet
//!
//! ...


/// Secret supplied by the Diffie-Hellman key exchange in Sphinx. 
/// Also secret symmetric key supploied by Xolotl, which must be
/// 256 bits for post-quantum security.
// #[never_forget]
// #[derive(Debug, Default, Clone)]
pub type SphinxSecret = ::Secret<[u8; 32]>;

// impl_ZeroingDrop!(SphinxSecret, [0u8; 32]);

// impl SphinxSecret {
//     #[inline]
//     pub fn new(ss: [u8; 32]) -> SphinxSecret { SphinxSecret(ss) }
// }


