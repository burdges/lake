// Copyright 2016 Jeffrey Burdges.

//! Routing key certificate data structures


use rand::{Rng, Rand};

use ed25519_dalek as ed25519;
// TODO: Replace with SHA3, but fails right now hashes crate's SHA3 API is broken
use sha2::Sha512 as Ed25519Hash;

use curve;
// use super::error::*;
// use super::super::*;

use super::RoutingName;
use super::time::*;


/// Routing public key certificate
#[derive(Clone, Debug)]  // Copy
pub struct RoutingPublic {
    /// Actual public key used when routing packets and building headers.
    pub public: curve::AlphaBytes,
    /// Validity period for this record.
    pub validity: ValidityPeriod,
    /// Issuing mix nodes long term issuing key
    pub issuer: IssuerPublicKey,
    /// Signature over preceeding fields by issuer.
    pub signature: ed25519::Signature,
}

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
        // use curve25519_dalek::edwards::CompressedEdwardsY;
        let (public,validity,issuer,signature)
          = array_refs![b,32,16,32,64];
        RoutingPublic {
            public: *public,
            validity: ValidityPeriod::from_bytes(validity),
            issuer: IssuerPublicKey(*issuer),
            signature: ed25519::Signature(*signature),
        }
    }
}

pub type RoutingInfo = (RoutingName,RoutingPublic);


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
    // TODO: IP address, etc.
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
    pub keys: ed25519::Keypair,
}

impl IssuerSecret {
    pub fn new<R: Rng>(rng: &mut R, validity: ValidityPeriod) -> IssuerSecret {
        let keys = ed25519::Keypair::generate::<Ed25519Hash>(rng);
        IssuerSecret { validity, keys }
    }

    pub fn public(&self) -> (IssuerPublicKey,IssuerPublicKeyInfo) {
        let ipk = IssuerPublicKey(self.keys.public.to_bytes());
        let m = issuer_signable(&ipk,&self.validity);
        let signature = self.keys.sign::<Ed25519Hash>(&m);
        ( ipk,
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
            issuer: IssuerPublicKey(self.keys.public.to_bytes()),
            signature: ed25519::Signature([0u8; 64]),
        };
        let b = p.to_bytes();
        p.signature = self.keys.sign::<Ed25519Hash>(&b[..ROUTING_SECRET_LENGTH-64]);
        s.name = p.name();
        (s.name,p,s)
    }
}

