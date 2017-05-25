// Copyright 2016 Jeffrey Burdges.

//! Routing key handling based on GNUNet's CADET layer which lacks
//! any global consensus on routing keys, but instead depends upon
//! Brahms routed over CADET for peer discovery. 
//!
//! See Brahms: Byzantine Resilient Random Membership Sampling by 
//! Edward, Bortnikov, Maxim Gurevich, Idit Keidar, Gabriel Kliot,
//! and Alexander Shraer in PDOC or from 
//! https://people.csail.mit.edu/idish/ftp/Brahms-PODC.pdf
//! We discuss GNUnet's implementation in https://gnunet.org/brahms and 
//! https://www.net.in.tum.de/fileadmin/bibtex/publications/theses/totakura2015_brahms.pdf
// https://events.ccc.de/camp/2015/wiki/Session:Authority-free_Onion_Routing_with_BRAHMS

// TODO: Talk about epistimilogical attacks?


use crypto::digest::Digest;
use crypto::sha3::Sha3;
use ed25519_dalek as ed25519;
// TODO: Replace with SHA3, but fails right now hashes crate's SHA3 API is broken
use sha2::Sha512 as Ed25519Hash;

use sphinx::curve;
// use super::error::*;
// use super::super::*;


pub const ROUTING_NAME_LENGTH : usize = 32+2;

pub type RoutingNameBytes = [u8; ROUTING_NAME_LENGTH];

/// Identifies a particular node and its routing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingName(pub RoutingNameBytes);



