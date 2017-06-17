// Copyright 2016 Jeffrey Burdges.

//! Routing key handling based on global concensus similar to Tor.

use std::collections::HashMap;
use std::time::SystemTime;

use rand::{Rng}; // Rand

use crypto::digest::Digest;
use crypto::sha3::Sha3;

use super::RoutingName;
use super::certs::*;
use super::concensus::*;
use super::error::*;


pub const ROUTING_NAME_LENGTH : usize = 16;

impl RoutingPublic {
    pub fn name(&self) -> RoutingName {
        let mut rn = [0u8; ROUTING_NAME_LENGTH];
        let mut sha = Sha3::sha3_512();
        sha.input(&self.public);
        sha.input(& self.validity.to_bytes());
        sha.input(&self.issuer.0);
        sha.result(&mut rn);
        sha.reset();
        RoutingName(rn)
    }
}

pub const MAX_ROUTING_PER_ISSUER : usize = 2;


struct Directory {
    // TODO: Use a better data strducture to avod collect() in issuer_choice.
    issuers: HashMap<IssuerPublicKey,(IssuerPublicKeyInfo,RpI)>,
    routing_keys: HashMap<RoutingName,RoutingPublic>,

    // TODO: See IssuerPublicKeyInfo TODOs
    // issuers_archives: Vec<HashMap<IssuerPublicKey,IssuerPublicKeyInfo>>,  ??
}

impl Concensus for Directory {
    fn routing_named(&self, routing_name: &RoutingName)
      -> KeysResult<&RoutingPublic>
    {
        self.routing_keys.get(routing_name)
          .ok_or( KeysError::Routing(*routing_name,"No RoutingPublic for given RoutingName.") )
    }

    fn routing_by_issuer<R: Rng>(&self, rng: &mut R,
          issuer: &IssuerPublicKey, 
          before: SystemTime
      ) -> KeysResult<(RoutingName,&RoutingPublic)>
    {
        let t = self.issuers.get(issuer)
          .ok_or( KeysError::Issuer(*issuer,"Issuer not found.") ) ?;
        let rpi = &t.1;
        if rpi.len() == 0 {
            return Err( KeysError::Issuer(*issuer,"No routing keys for given issuer.") ) 
        }
        self.rpi_picker(rng,rpi,before)
    }

    fn route_picker<'s>(&'s self, before: SystemTime)
      -> KeysResult<RoutePicker<'s,Directory>> {
        let issuers: Vec<_> 
          = self.issuers.values().map(|t| &t.1)
          .filter(|rpi| rpi.iter().any(|r| rpi_before(r,before))).collect();
        Ok( RoutePicker { concensus: self, before, issuers } ) 
    }
}



