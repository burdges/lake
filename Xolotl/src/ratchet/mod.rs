// Copyright 2016 Jeffrey Burdges.

//! Xolotl ratchet
//!
//! ...

mod branch;
mod twig;
mod state;
mod advance;
mod error;

/*
pub use self::branch::{BranchId,BranchName};
pub use self::twig::{TwigIdxT,TwigIdx};
pub use self::state::{State};
pub use self::advance::{Transaction,Advance};
*/

use ::sphinx::SphinxSecret;

/// Secret symmetric key the Xolotl ratchet returns to Sphinx.
///
/// We require 256 bits here for post-quantum security of course,
/// which agrees with the secret supplied by the Diffie-Hellman key
/// exchange in Sphinx.  We reuse the SphinxSecret type as this gets
/// used in exactly the same palce on the Sphinx side.
pub type MessageKey = SphinxSecret;


