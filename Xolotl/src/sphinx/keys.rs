// Copyright 2016 Jeffrey Burdges.

//! Sphinx node key management routines
//!
//! ...
//!
//! TODO: An [implicit certificate](https://en.wikipedia.org/wiki/Implicit_certificate)
//! scheme could shave 32 bytes off the `ROUTING_KEY_CERT_LENGTH`.
//! We must know that someone who compramises the node's long term
//! certificate for issuing routing keys, and some routing keys, 
//! cannot compute later routing keys, but the security proof in [0]
//! should show that the certificate issuer cannot compramise alpha,
//! whence our desired security property follows.
//! 
//! [0] Brown, Daniel R. L.; Gallant, Robert P.; Vanstone, Scott A. 
//! "Provably Secure Implicit Certificate Schemes".
//! Financial Cryptography 2001. Lecture Notes in Computer Science. 
//! Springer Berlin Heidelberg. 2339 (1): 156–165.
//! doi:10.1007/3-540-46088-8_15.


use std::collections::HashMap;
use std::ops::Range;
use std::time::{Duration,SystemTime,UNIX_EPOCH};

use rand::{Rng, Rand};

use arrayvec::ArrayVec;

use crypto::digest::Digest;
use crypto::sha3::Sha3;
use ed25519_dalek as ed25519;
// TODO: Replace with SHA3, but fails right now hashes crate's SHA3 API is broken
use sha2::Sha512 as Ed25519Hash;

use super::curve;
use super::error::*;
use super::*;

#[derive(Clone, Debug)] // Copy
pub struct ValidityPeriod(pub Range<u64>);

#[derive(Clone, Copy, Debug)]
pub enum ValidityResult {
    Pending(Duration),
    Valid(Duration),
    Expired(Duration),
}

impl ValidityPeriod {
    pub fn new(start: SystemTime, duration: Duration) -> ValidityPeriod {
        let start = start.duration_since(start).unwrap();
        ValidityPeriod( start.as_secs() .. (start+duration).as_secs() )
    }

    pub fn intersect(&self, other: &ValidityPeriod) -> ValidityPeriod {
        use std::cmp::{min,max};
        ValidityPeriod(max(self.0.start, other.0.start)..min(self.0.end, other.0.end))
    }

    pub fn intersect_assign(&mut self, other: &ValidityPeriod) {
        *self = self.intersect(other);
    }

    pub fn start(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.start)
    }
    pub fn end(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.end)
    }

    pub fn valid(&self) -> ValidityResult {
        use self::ValidityResult::*;
        let start = Duration::from_secs(self.0.start);
        let end = Duration::from_secs(self.0.end);
        let len = end-start;
        if start > end {
            return Expired( Duration::from_secs(0) ); 
        }
        let now = SystemTime::now();
        /*
        match now.duration_since(UNIX_EPOCH + end) {
            Ok(d) => Expired(d),
            Err(e) => {
                let d = e.duration();
                if d < len { Valid(d) } else { Pending(d-len) }
            },
        }
        */
        match now.duration_since(UNIX_EPOCH + start) {
            Ok(d) => if d>len { Expired(d-len) } else { Valid(len-d) },
            Err(e) => Pending(e.duration()),
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        use std::mem::transmute;
        let mut r = [0u8; 16];
        {
        let (start,end) = mut_array_refs![&mut r,8,8];
        *start = unsafe { transmute::<u64,[u8; 8]>(self.0.start.to_le()) };
        *end = unsafe { transmute::<u64,[u8; 8]>(self.0.end.to_le()) };
        }
        r
    }
    pub fn from_bytes(b: &[u8; 16]) -> ValidityPeriod {
        use std::mem::transmute;
        let (start,end) = array_refs![b,8,8];
        ValidityPeriod( Range {
            start: u64::from_le(unsafe { transmute::<[u8; 8],u64>(*start) }),
            end:   u64::from_le(unsafe { transmute::<[u8; 8],u64>(*end) }),
        } )
    }
}


pub const ROUTING_NAME_LENGTH : usize = 16;

pub type RoutingNameBytes = [u8; ROUTING_NAME_LENGTH];

/// Identifies a particular node and its routing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingName(pub RoutingNameBytes);

/// Routing public key certificate
#[derive(Clone, Debug)]  // Copy
pub struct RoutingPublic {
    pub public: curve::AlphaBytes,
    pub validity: ValidityPeriod,
    pub issuer: IssuerPublicKey,
    pub signature: ed25519::Signature,
}

pub type RoutingInfo = (RoutingName,RoutingPublic);

pub const ROUTING_PUBLIC_LENGTH: usize = 32+16+32+64;

impl RoutingPublic {
    pub fn valid(&self) -> ValidityResult { self.validity.valid() }

    pub fn verify(&self) -> bool {
        let b = self.to_bytes();
        ed25519::PublicKey::from_bytes(&self.issuer.0)
          .verify::<Ed25519Hash>(&b[..ROUTING_PUBLIC_LENGTH-64],&self.signature)
    }

    pub fn to_bytes(&self) -> [u8; ROUTING_PUBLIC_LENGTH] {
        let mut r = [0u8; ROUTING_PUBLIC_LENGTH];
        {
        let (public,validity,issuer,signature)
          = mut_array_refs![&mut r,32,16,32,64];
        *public = self.public;
        *validity = self.validity.to_bytes();
        *issuer = self.issuer.0;
        *signature = self.signature.to_bytes();
        }
        r
    }
    pub fn from_bytes(b: &[u8; ROUTING_PUBLIC_LENGTH]) -> RoutingPublic {
        use curve25519_dalek::curve::CompressedEdwardsY;
        let (public,validity,issuer,signature)
          = array_refs![b,32,16,32,64];
        RoutingPublic {
            public: *public,
            validity: ValidityPeriod::from_bytes(validity),
            issuer: IssuerPublicKey(*issuer),
            signature: ed25519::Signature(*signature),
        }
    }

    pub fn name(&self) -> RoutingName {
        let mut rn = [0u8; 16];
        let mut sha = Sha3::sha3_512();
        sha.input(&self.public);
        sha.input(& self.validity.to_bytes());
        sha.input(&self.issuer.0);
        sha.result(&mut rn);
        sha.reset();
        RoutingName(rn)
    }
}


/// Routing secret key
#[derive(Clone, Debug)]  // Copy
pub struct RoutingSecret {
    pub name: RoutingName,
    pub secret: curve::Scalar,
    pub validity: ValidityPeriod,
}

pub const ROUTING_SECRET_LENGTH: usize = 16+32+16;

// pub type RoutingSecretInfo = (RoutingName,RoutingSecret);

impl RoutingSecret {
    pub fn to_bytes(&self) -> [u8; ROUTING_SECRET_LENGTH] {
        let mut r = [0u8; ROUTING_SECRET_LENGTH];
        {
        let (name,secret,validity) = mut_array_refs![&mut r,16,32,16];
        *name = self.name.0;
        *secret = self.secret.to_bytes();
        *validity = self.validity.to_bytes();
        } 
        r
    }
    pub fn from_bytes(b: &[u8; ROUTING_SECRET_LENGTH]) -> RoutingSecret {
        let (name,secret,validity) = array_refs![b,16,32,16];
        RoutingSecret {
            name: RoutingName(*name),
            secret: curve::Scalar::from_bytes(secret),
            validity: ValidityPeriod::from_bytes(validity),
        }
    }
}


/// Identifies a particular node without specifying a routing key.
#[derive(Clone, Debug, Copy, PartialEq, Eq, Hash)]
pub struct IssuerPublicKey(pub [u8; 32]);

/// 
#[derive(Clone, Debug)]  // Copy
pub struct IssuerPublicKeyInfo {
    pub validity: ValidityPeriod,
    pub signature: ed25519::Signature,

    // TODO: Updates to validity?
    // TODO: Certificates by offline keys?
    // TODO: Signatures with older issuer keys?
}

fn issuer_signable(pk: &IssuerPublicKey, validity: &ValidityPeriod) -> [u8; 16+32] {
    let mut b = [0u8; 16+32];
    {
        let (v,p) = mut_array_refs![&mut b,16,32];
        *v = validity.to_bytes();
        *p = pk.0;
    }
    b
}

impl IssuerPublicKeyInfo {
    pub fn verify(&self, pk: &IssuerPublicKey) -> bool {
        ed25519::PublicKey::from_bytes(&pk.0)
          .verify::<Ed25519Hash>(& issuer_signable(pk,&self.validity),&self.signature)
    }
}

/// 
#[derive(Debug)]  // Clone, Copy
pub struct IssuerSecret {
    pub validity: ValidityPeriod,
    pub public: IssuerPublicKey,  // ed25519::PublicKey
    pub secret: ed25519::SecretKey,
}

impl IssuerSecret {
    pub fn new<R: Rng>(rng: &mut R, validity: ValidityPeriod) -> IssuerSecret {
        let keys = ed25519::Keypair::generate::<Ed25519Hash>(rng);
        IssuerSecret {
            validity: validity,
            public: IssuerPublicKey(keys.public.to_bytes()),
            secret: keys.secret,
        }
    }

    pub fn public(&self) -> (IssuerPublicKey,IssuerPublicKeyInfo) {
        let m = issuer_signable(&self.public,&self.validity);
        let signature = self.secret.sign::<Ed25519Hash>(&m);
        ( self.public, 
          IssuerPublicKeyInfo {
            validity: self.validity.clone(),
            signature: signature,
        })
    }

    pub fn issue<R: Rng>(&self, rng: &mut R, validity: ValidityPeriod)
      -> (RoutingName,RoutingPublic,RoutingSecret) {
        let mut s = RoutingSecret {
            name: RoutingName([0u8; 16]),
            secret: curve::Scalar::rand(rng),
            validity: validity.clone(),
        };
        let mut p = RoutingPublic {
            public: curve::Point::from_secret(&s.secret).compress(),
            validity: validity,
            issuer: self.public,
            signature: ed25519::Signature([0u8; 64]),
        };
        let b = p.to_bytes();
        p.signature = self.secret.sign::<Ed25519Hash>(&b[..ROUTING_SECRET_LENGTH-64]);
        s.name = p.name();
        (s.name,p,s)
    }
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
    /// Use `routing_by_routing` when using a SURB.  If you use this
    /// the hop before the cross over point may learn their position.
    fn routing_named(&self, routing_name: &RoutingName)
      -> SphinxResult<&RoutingPublic>;

    /// Fetch a routing key for some particular issuer
    fn routing_by_issuer<R: Rng>(&self, rng: &mut R,
          issuer: &IssuerPublicKey, 
          before: SystemTime
      ) -> SphinxResult<(RoutingName,&RoutingPublic)>;

    /// Fetch a routing key with substancial validity period remaining.
    ///
    /// Used for building a header to connect with a SURB.
    fn routing_by_routing<R: Rng>(&self, rng: &mut R,
          routing_name: &RoutingName, 
          before: SystemTime
      ) -> SphinxResult<(RoutingName,&RoutingPublic)> 
    {
        let r = self.routing_named(routing_name) ?;
        self.routing_by_issuer(rng, &r.issuer, before)
    }

    /// Randomly select a valid `RoutingName` from an array of exactly
    /// `MAX_ROUTING_PER_ISSUER` pairs `(ValidityPeriod,RoutingName)`.
    /// 
    /// TODO: Remove from public interface once associated type constructors,
    /// higher-kinded types, or `-> impl Trait` n traits allow us to write
    /// generalize `RoutePicker` to a trait and write `router_picker` without
    /// a trait object.
    fn rpi_picker<'a,R: Rng>(&'a self, rng: &mut R, rpi: &'a RpI, before: SystemTime) 
      -> SphinxResult<(RoutingName,&'a RoutingPublic)> 
    {
        let mut v: ArrayVec<[&VPnRN; MAX_ROUTING_PER_ISSUER]>
          = rpi.iter().filter(|r| rpi_pred(r,before)).collect();
        if v.len() == 0 {
            return Err( SphinxError::ConcensusLacking("Issuer's routing keys expire too soon.") ) 
        }
        let rn = v[ rng.gen_range(0, v.len()) ].1;
        Ok(( rn, self.routing_named(&rn) ? ))
    }

    /// TODO: As in `rand::Rand::gen_iter()`, an iterator might work
    /// here but only if we give up our random number generator.
    fn route_picker<'s>(&'s self, before: SystemTime)
      -> SphinxResult<RoutePicker<'s,Self>>;
}

pub const MAX_ROUTING_PER_ISSUER : usize = 2;

/// TODO: Make private once we get associated type constructors
type VPnRN = (ValidityPeriod,RoutingName);

/// TODO: Make private once we get associated type constructors
type RpI = [VPnRN; MAX_ROUTING_PER_ISSUER];

struct ConcensusMaps {
    // TODO: Use a better data strducture to avod collect() in issuer_choice.
    issuers: HashMap<IssuerPublicKey,IssuerPublicKeyInfo>,
    routing_by_name: HashMap<RoutingName,RoutingPublic>,
    routing_by_issuer: HashMap<IssuerPublicKey,RpI>,

    // TODO: See IssuerPublicKeyInfo TODOs
    // issuers_archives: Vec<HashMap<IssuerPublicKey,IssuerPublicKeyInfo>>,  ??
}

fn rpi_pred(r: &VPnRN, before: SystemTime) -> bool {
    r.0.end() > before && r.0.start() < r.0.end() 
}

impl Concensus for ConcensusMaps {
    fn routing_named(&self, routing_name: &RoutingName)
      -> SphinxResult<&RoutingPublic>
    {
        self.routing_by_name.get(routing_name)
          .ok_or( SphinxError::ConcensusLacking("No RoutingPublic for given RoutingName.") )
    }

    fn routing_by_issuer<R: Rng>(&self, rng: &mut R,
          issuer: &IssuerPublicKey, 
          before: SystemTime
      ) -> SphinxResult<(RoutingName,&RoutingPublic)>
    {
        let rpi = self.routing_by_issuer.get(issuer)
          .ok_or( SphinxError::ConcensusLacking("No routing keys for given issuer.") ) ?;
        if rpi.len() == 0 {
            return Err( SphinxError::ConcensusLacking("No routing keys for given issuer.") ) 
        }
        self.rpi_picker(rng,rpi,before)
    }

    fn route_picker<'s>(&'s self, before: SystemTime)
      -> SphinxResult<RoutePicker<'s,ConcensusMaps>> {
        let issuers: Vec<_> 
          = self.routing_by_issuer.values()
          .filter(|rpi| rpi.iter().any(|r| rpi_pred(r,before))).collect();
        Ok( RoutePicker { concensus: self, before, issuers } ) 
    }
}

struct RoutePicker<'a,C> where C: Concensus + 'a + ?Sized  {
    concensus: &'a C,
    before: SystemTime,
    issuers: Vec<&'a RpI>,
}

impl<'a,C> RoutePicker<'a,C> where C: Concensus+'a {
    fn pick<R: Rng>(&self, rng: &mut R) -> SphinxResult<(RoutingName,&RoutingPublic)> {
        let i = rng.gen_range(0, self.issuers.len());
        self.concensus.rpi_picker(rng,self.issuers[i],self.before)
    }
}



