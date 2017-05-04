// Copyright 2016 Jeffrey Burdges.

//! Xolotl ratchet
//!
//! ...

mod branch;
mod twig;
mod state;
mod advance;
pub mod error;

pub use self::branch::{BranchId,BRANCH_ID_LENGTH}; // BranchName,BRANCH_NAME_LENGTH
pub use self::twig::{TwigIdxT,TwigIdx,TwigId,TWIG_ID_LENGTH};
pub use self::advance::{Transaction,Advance,AdvanceNode,AdvanceUser};

pub use self::state::{State,ClientState};
pub type RatchetState = State;
pub type ClientRatchetState = ClientState;

pub use self::branch::ExtraKey;

use ::sphinx::SphinxSecret;

/// Secret symmetric key the Xolotl ratchet returns to Sphinx.
///
/// We require 256 bits here for post-quantum security of course,
/// which agrees with the secret supplied by the Diffie-Hellman key
/// exchange in Sphinx.  We reuse the SphinxSecret type as this gets
/// used in exactly the same palce on the Sphinx side.
pub type MessageKey = [u8; 32];


#[cfg(test)]
mod tests {
    // use super::*;
    // use rustc_serialize::hex::ToHex;

    #[test]
    fn need_tests() {
    }
}



