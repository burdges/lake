// Copyright 2016 Jeffrey Burdges.

//! Sphinx mix network packet format adapted to Xolotl ratchet
//!
//! ...

mod curve;
mod stream;
mod body;
mod replay;
mod node;
mod keys;
mod surbs;
mod mailbox;
mod error;

#[macro_use]
mod utils;

mod header;


pub use self::header::SphinxParams;


/// Secret supplied by the Diffie-Hellman key exchange in Sphinx. 
/// Also secret symmetric key supploied by Xolotl, which must be
/// 256 bits for post-quantum security.
// #[never_forget]
// #[derive(Debug, Default, Clone, Copy)]
pub struct SphinxSecret(pub [u8; 32]);  // StackSecret

impl SphinxSecret {
    pub fn new(ss: &[u8; 32]) -> SphinxSecret  {  SphinxSecret(*ss)  }
}


pub const PACKET_NAME_LENGTH : usize = 16;
pub type PacketNameBytes = [u8; PACKET_NAME_LENGTH];

/// Packet name used for unrolling SURBs
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
pub struct PacketName(pub PacketNameBytes);


