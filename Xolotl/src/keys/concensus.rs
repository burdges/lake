// Copyright 2016 Jeffrey Burdges.

//!
//! 

use std::time::SystemTime;

use rand::{Rng, Rand};

use super::RoutingName;
use super::certs::*;
use super::error::*;


/// TODO: Make private once we get associated type constructors
pub type VPnRN = (super::time::ValidityPeriod,RoutingName);

/// TODO: Make private once we get associated type constructors
pub type RpI = [VPnRN; super::MAX_ROUTING_PER_ISSUER];

/// 
pub fn rpi_before(r: &VPnRN, before: SystemTime) -> bool {
    r.0.end() > before && r.0.start() < r.0.end() 
}

/// Access records for issuer and routing keys.
/// 
/// TODO: Algorithms and data structures suck ass here.  
///       Rewrite everything using well designed data structures.
/// TODO: Worry about leakage through validity period, especially with SURBs.
pub trait Concensus {
    /// Returns the routing public key record associated to a given
    /// routing name.
    ///
    /// Use `routing_by_routing` when using a SURB.  If you use this,
    /// the hop before the cross over point may learn their position.
    fn routing_named(&self, routing_name: &RoutingName)
      -> KeysResult<&RoutingPublic>;

    /// Fetch a routing key for some particular issuer
    fn routing_by_issuer<R: Rng>(&self, rng: &mut R,
          issuer: &IssuerPublicKey, 
          before: SystemTime
      ) -> KeysResult<(RoutingName,&RoutingPublic)>;

    /// Fetch a routing key with substancial validity period remaining.
    ///
    /// Used for building a header to connect with a SURB.
    fn routing_by_routing<R: Rng>(&self, rng: &mut R,
          routing_name: &RoutingName, 
          before: SystemTime
      ) -> KeysResult<(RoutingName,&RoutingPublic)> 
    {
        let r = self.routing_named(routing_name) ?;
        self.routing_by_issuer(rng, &r.issuer, before)
    }

    /// Randomly select a valid `RoutingName` from an array of exactly
    /// `MAX_ROUTING_PER_ISSUER` pairs `(ValidityPeriod,RoutingName)`.
    /// 
    /// TODO: Remove from public interface once associated type constructors,
    /// higher-kinded types, or `-> impl Trait` in traits allow us to write
    /// generalize `RoutePicker` to a trait and write `router_picker` without
    /// a trait object.
    fn rpi_picker<'a,R: Rng>(&'a self, rng: &mut R, rpi: &'a RpI, before: SystemTime) 
      -> KeysResult<(RoutingName,&'a RoutingPublic)> 
    {
        use arrayvec::ArrayVec;
        let mut v: ArrayVec<[&VPnRN; super::MAX_ROUTING_PER_ISSUER]>
          = rpi.iter().filter(|r| rpi_before(r,before)).collect();
        if v.len() == 0 {
            // let issuer = self.routing_named(&rpi[0])
            //   .map(|rp| rp.issuer)
            //   .map_err( IssuerPublicKey([0u8; 32]) );
            let issuer = IssuerPublicKey([0u8; 32]);
            return Err( KeysError::Issuer(issuer,"Issuer's routing keys all expire too soon.") ) 
        }
        let rn = v[ rng.gen_range(0, v.len()) ].1;
        Ok(( rn, self.routing_named(&rn) ? ))
    }

    /// TODO: As in `rand::Rand::gen_iter()`, an iterator might work
    /// here but only if we give up our random number generator.
    fn route_picker<'s>(&'s self, before: SystemTime)
      -> KeysResult<RoutePicker<'s,Self>>;
}

pub struct RoutePicker<'a,C> where C: Concensus + 'a + ?Sized  {
    pub concensus: &'a C,
    pub before: SystemTime,
    pub issuers: Vec<&'a RpI>,
}

impl<'a,C> RoutePicker<'a,C> where C: Concensus+'a {
    pub fn pick<R: Rng>(&self, rng: &mut R) -> KeysResult<(RoutingName,&RoutingPublic)> {
        let i = rng.gen_range(0, self.issuers.len());
        self.concensus.rpi_picker(rng,self.issuers[i],self.before)
    }
}



