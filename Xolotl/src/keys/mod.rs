// Copyright 2016 Jeffrey Burdges.

//! Mix network key management.
//!
//! We need to be "polymorphic" over the particular public key 
//! intrastructure (PKI) required by the mix network, but this
//! requires being "polymorphic" over many types like `RoutingName`.
//! `RoutingName` need only be 16 bytes for a simpler directory
//! authority based system, but GNUNet's random peer sampling
//! system based on Brahms requires at least 32 bytes for a long
//! term key and 16 bytes to identify the ephemeral key.
//!
//! We could provide this polymorphism nicely if Rust ever gets 
//! paramaterized modules [#424](https://github.com/rust-lang/rfcs/issues/424).  
//! Right now, we would need to add type paramaters everywhere though,
//! including items that do not currently require `sphinx::Params`.  
//! Instead, we make the PKI interface a build time configuration,
//! which requires some duplicate test code here, but overall sounds
//! more sane.


pub mod time;
pub mod error;

pub mod concensus;
pub use self::concensus::Concensus;

pub mod dirauth;
pub use self::dirauth::*;

// pub mod gnunet;
// pub use self::gnunet::*;

pub type RoutingNameBytes = [u8; ROUTING_NAME_LENGTH];

/// Identifies a particular node and its routing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingName(pub RoutingNameBytes);

pub mod certs;
pub use self::certs::*;


