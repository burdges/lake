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


/// In GNUNet, a `RoutingName` consists of a peer identity along with
/// a routing key index, so that nodes can route packets without
/// recognizing the current routing key.
pub const ROUTING_NAME_LENGTH : usize = 32+2;

impl RoutingPublic {
    /// Issuers must ensure usinqueness of the routing name returned
    /// because different routing names differ by only 16 bits.
    pub fn name(&self) -> RoutingName {
        let mut rn = [0u8; ROUTING_NAME_LENGTH];
        let mut sha = Sha3::sha3_512();
        sha.input(&self.public);
        sha.input(& self.validity.to_bytes());
        sha.input(&self.issuer.0);
        sha.result(&mut rn[32..34]);
        sha.reset();
        rn[0..32].copy_from_slice(self.issuer.0);
        RoutingName(rn)
    }
}

pub const MAX_ROUTING_PER_ISSUER : usize = 2;


