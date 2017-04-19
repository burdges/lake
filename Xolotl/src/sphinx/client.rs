// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...

use std::sync::Arc; // RwLock, RwLockReadGuard, RwLockWriteGuard
use std::marker::PhantomData;

use ratchet::{BranchId,BRANCH_ID_LENGTH,TwigId,TWIG_ID_LENGTH};
pub use ratchet::State as RatchetState;

pub use super::keys::{RoutingName};  // ROUTING_NAME_LENGTH,ValidityPeriod
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
pub use super::layout::{PreHeader};
use super::*;



struct Scaffold<'a,R: Rng,P: Params> {
    rng: &'a mut R,

    /// First hop that should process this header.
    start: RoutingName,

    /// Final hop that should process this header.
    end: RoutingName,

    /// Initial public curve point
    alpha0: AlphaBytes,

    /// Accumulator for the current private scalar `a`.
    aa: curve::Scalar,

    delay: Duration,

    /// Expected validity period
    validity: ValidityPeriod,

    /// Workspace for constructing `beta`.
    beta: Box<[u8]>,

    /// Available bytes of `beta` that remain unallocated to `commands`.
    remaining: usize,

    /// `Commands` for `beta`.
    ///
    /// We interpret `gamma` for `Sphinx` and `Ratchet` commands as
    /// an index into `hops` for the next `HeaderCipher`.
    commands: Vec<PreCommand<usize>>

    /// Stream ciphers for 
    cipher: Vec<HeaderCipher<P>>,

    /// Packet construction mode, either `Ok` for SURBs, or
    /// `None` for a normal forward packets. 
    /// Also, records unwinding keys and twig ids in SURB mode.
    surb: Option<Vec<SURBHop>>,

    /// Indexes of ciphers that encrypt the body and surb log
    body: Option<Vec<usize>>
}




/// We build `PreHeader`s using successive operations on `Scafold`.
/// 
/// We use our first command to set `PreHeader::route` and pad
/// `PreHeader::beta` for usage in transmission or in aSURB, but
/// do not encode it into `PreHeader::beta`.
struct Scaffold<'a,R: Rng,P: Params> {
    rng: &'a mut R,

    /// First hop that should process this header.
    start: RoutingName,

    /// Final hop that should process this header.
    end: RoutingName,

    /// Initial public curve point
    alpha0: AlphaBytes,

    /// Accumulator for the current private scalar `a`.
    aa: curve::Scalar,

    /// Expected delay
    delay: Duration,

    /// Expected validity period
    validity: ValidityPeriod,

    /// Workspace for constructing `beta`.
    beta: Box<[u8]>,

    /// Available bytes of `beta` that remain unallocated to `commands`.
    remaining: usize,

    /// `Commands` for `beta`.
    ///
    /// We interpret `gamma` for `Sphinx` and `Ratchet` commands as
    /// an index into `hops` for the next `HeaderCipher`.
    commands: Vec<PreCommand<usize>>

    /// Stream ciphers for 
    ciphers: Vec<HeaderCipher<P>>,

    /// Packet construction mode, either `Ok` for SURBs, or
    /// `None` for a normal forward packets. 
    /// Also, records unwinding keys and twig ids in SURB mode.
    surbs: Option<Vec<SURBHop>>,

    /// Indexes of ciphers that encrypt the body and surb log
    bodies: Option<Vec<usize>>
}


RoutingPublic

rp.name()



impl<R: Rng,P: Params> Scafold<R,P> {
    pub fn new(rng: R,
               route: RoutingName, 
               make_surb: bool,
               capacity: usize,
               commands: &[PreCommand<()>]) 
      -> SphinxResult<Scaffold<R,P>>
    {
        let mut seed: [u8; 64] = rng.gen();
        let aa = curve::Scalar::make(&seed);
        let alpha = curve::Point::from_secret(&aa).compress();
        // Should we test alpha?
        // curve::Point::decompress(&alpha) ?;

        lookup route

        // Divide by two since we assume a SURB oriented usage,
        // but this costs allocations if not using SURBs.
        let capacity = P::max_hops_capacity() / 2;
        let mut s = Scaffold {
            rng,
            start: route,
            end: RoutingName([0u8; ROUTING_NAME_LENGTH]),
            alpha, aa, 
            delay: Duration,
            validity: r.validity,
            remaining: P::BETA_LENGTH, 
            commands: Vec::with_capacity(capacity)),
            ciphers: Vec::with_capacity(capacity+1)),
            surb: if make_surb { Some(Vec::with_capacity(capacity)) } else { None },
            body: if ! make_surb { None } else { Some(Vec::with_capacity(capacity)) },
        }
        s.add_sphinx_cipher(route.p, command);
        Ok( s )
    }

    fn add_cipher<'a>(&mut self, key: SURBHopKey) -> SphinxResult<&'a mut HeaderCipher<P>> {
        // TODO: Fix code duplication with unwind_delivery_surbs
        //       including: Use protocol specified in the delivery surb
        let mut hop = stream::SphinxKey::<P> {
            params: PhantomData,
            chacha_nonce: surb.chacha_nonce,
            chacha_key: surb.chacha_key,
        }.header_cipher() ?;  // InternalError: ChaCha stream exceeded
        self.ciphers.push(hop);
        if Some(ref mut surbs) = self.surbs { surbs.push(surb); }
        if Some(ref mut bodies) = self.bodies { bodies.push(self.cipher.len()-1); }
        Ok( self.cipher.last_mut() )
    }

    fn add_ratchet_cipher<'a>(&mut self, key: SURBHopKey) -> SphinxResult<&'a mut HeaderCipher<P>> {
        // Remove keys records for Sphinx keys skipped over due to
        // using the ratchet key instead.
        if Some(ref mut surbs) = self.surbs { surbs.pop(); }
        if Some(ref mut bodies) = self.bodies { bodies.pop(); }
        self.add_cipher(key)
    }

    fn add_sphinx_cipher<'a>(&mut self, key: SURBHopKey) -> SphinxResult<&'a mut HeaderCipher<P>> {
        ;
    }



    fn add_command(&mut self, route: RoutingName, command: PreCommand<()>) -> SphinxResult<()> {
        if self.end == route
    }

    pub fn command(&mut self, command: PreCommand<()>) -> SphinxResult<()> {
        self.a  ??

        self.remaining -= command.length_as_bytes();

        match *self {
            Command::Transmit { route } => {
                .
            },
            Command::Ratchet { twig } => {
            },
            Command::CrossOver { alpha, surb_beta } => {
                unimplemented!();
            },
            Command::Contact { } => {
                unimplemented!();
            },
            Command::Greeting { } => {
                unimplemented!();
            },
            Command::Deliver { mailbox } => {
                unimplemented!();
            },
            // DropOff
            Command::ArrivalSURB { } => {
            },
            Command::ArrivalDirect { } => {
            },
            // Delete
        }
    }

    fn final(self) -> PreHeader {
        let gamma = ??;
        let mut beta = Vec::new();
        beta.extend_from_slice(self.beta[??..??]);
        PreHeader {
            validity: self.validity,
            route: self.start,
            alpha: self.alpha,
            gamma, beta,
        }
    }
}





struct Client<P: Params> {
    params: PhantomData<P>,

    outgoing: OutgoingStore, 

    consensus: Arc<Consensus>,

    surbs: Arc<surbs::SURBStore<P>>,

    // TODO: Foreign ratchets by node 
    ratchet: Arc<RatchetState>,
}




