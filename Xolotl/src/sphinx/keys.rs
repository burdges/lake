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


use std::ops::Range;
use std::time::{Duration,SystemTime,UNIX_EPOCH};

use rand::{Rng, Rand};

use crypto::digest::Digest;
use crypto::sha3::Sha3;
use ed25519_dalek as ed25519;

use super::curve;


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

/// Identifies a particular node and its routing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoutingName(pub [u8; ROUTING_NAME_LENGTH]);

/// Routing public key certificate
#[derive(Clone, Debug)]  // Copy
pub struct RoutingPublic {
    pub public: curve::AlphaBytes,
    pub validity: ValidityPeriod,
    pub issuer: ed25519::PublicKey,
    pub signature: ed25519::Signature,
}

pub type RoutingInfo = (RoutingName,RoutingPublic);

pub const ROUTING_PUBLIC_LENGTH: usize = 32+16+32+64;

impl RoutingPublic {
    pub fn valid(&self) -> ValidityResult { self.validity.valid() }

    pub fn verify(&self) -> bool {
        let b = self.to_bytes();
        self.issuer.verify(&b[..ROUTING_PUBLIC_LENGTH-64],&self.signature)
    }

    pub fn to_bytes(&self) -> [u8; ROUTING_PUBLIC_LENGTH] {
        let mut r = [0u8; ROUTING_PUBLIC_LENGTH];
        {
        let (public,validity,issuer,signature)
          = mut_array_refs![&mut r,32,16,32,64];
        *public = self.public;
        *validity = self.validity.to_bytes();
        *issuer = self.issuer.0.to_bytes();
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
            issuer: ed25519::PublicKey( CompressedEdwardsY(*public) ),
            signature: ed25519::Signature(*signature),
        }
    }

    pub fn name(&self) -> RoutingName {
        let mut rn = [0u8; 16];
        let mut sha = Sha3::sha3_512();
        sha.input(&self.public);
        sha.input(& self.validity.to_bytes());
        sha.input(&self.issuer.to_bytes());
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


/// 
#[derive(Clone, Debug)]  // Copy
pub struct IssuerPublic {
    pub validity: ValidityPeriod,
    pub public: ed25519::PublicKey,
    pub signature: ed25519::Signature,
}

// impl IssuerPublic {
// }

/// 
#[derive(Debug)]  // Clone, Copy
pub struct IssuerSecret {
    pub validity: ValidityPeriod,
    pub public: ed25519::PublicKey,
    pub secret: ed25519::SecretKey,
}

impl IssuerSecret {
    pub fn new<R: Rng>(rng: &mut R, validity: ValidityPeriod) -> IssuerSecret {
        let keys = ed25519::Keypair::generate(rng);
        IssuerSecret {
            validity: validity,
            public: keys.public,
            secret: keys.secret,
        }
    }

    pub fn public(&self) -> IssuerPublic {
        let mut b = [0u8; 16+32];
        {
        let (validity,public) = mut_array_refs![&mut b,16,32];
        *validity = self.validity.to_bytes();
        *public = self.public.to_bytes();
        }
        let signature = self.secret.sign(&b[..ROUTING_SECRET_LENGTH-64]);
        IssuerPublic {
            validity: self.validity.clone(),
            public: self.public,
            signature: signature,
        }
    }

    pub fn issue<R: Rng>(&self, rng: &mut R, validity: ValidityPeriod)
      -> (RoutingName,RoutingPublic,RoutingSecret) {
        let keys = ed25519::Keypair::generate(rng);
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
        p.signature = self.secret.sign(&b[..ROUTING_SECRET_LENGTH-64]);
        s.name = p.name();
        (s.name,p,s)
    }

}


