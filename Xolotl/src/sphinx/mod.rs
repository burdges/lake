// Copyright 2016 Jeffrey Burdges.

//! Sphinx mix network packet format adapted to Xolotl ratchet
//!
//! ...

mod stream;
mod body;
mod replay;
mod node;
mod client;
mod mailbox;
pub mod error;

#[macro_use]
mod slice;

mod commands;
mod layout;
mod surbs;


pub use self::layout::Params;


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


