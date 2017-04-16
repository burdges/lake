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


/// ...
///
/// ... specifies either the next hop, final delivery 
pub enum Activity {
    Sphinx {
        route: RoutingName,
    },
    Ratchet {
        route: RoutingName,
        branch: BranchId,
    },
    FromCrossOver {
        route: RoutingName,
    },

    // DropOff { },

    // Final activities

    Dummy { },

    /// Embed SURB into beta and use at the crossover point specified
    CrossOver {
        surb: PreHeader
    },

    /// Consume a SURB at the contact point specified
    Contact {
        route: RoutingName,
        // id
    },

    /// Consume a SURB at the greeting point specified
    Greeting {
        route: RoutingName,
        // id
    },

    /// Deliver message to the specified mailbox, roughly equivelent
    /// to transmition to a non-existant mix network node.
    Deliver {
        mailbox: MailboxName,
    },

    /// Arrival of a SURB we created and archived.
    ArrivalSURB { },

    /// Arrival of a message for a local application.
    ArrivalDirect { },

    // Delete { },
}

/*

impl Activity {
    /// Are we allowed as the initial `Activity` in route building?
    ///
    ///
    pub fn is_initial(&self) -> bool {
        use self::Activity::*;
        match *self {
            FromCrossOver {..} => true,
            Sphinx {..} | Ratchet {..} => true,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => false,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => false,
            // Delete {} | DropOff {} => false,
        }
    }

    /// Are we allowed as the final `Activity` in route building?
    ///
    /// Packets will be processed correctly without a valid final,
    /// but they likely do nothing except move ratchets.
    pub fn is_final(&self) -> bool {
        use self::Activity::*;
        match *self {
            FromCrossOver {..} => false,
            Sphinx {..} | Ratchet {..} => false,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => true,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => true,
            // Delete {} => true
            // DropOff {} => false,
        }
    }

    pub fn<F> commands(f: F)
      where F: FnOnce(&[u8]) -> R {
        ;
    }
}


enum Scafold<P: Params> {
}


// type CommandPlus = Command<Vec<u8>>;


/// We build `PreHeader`s using successive operations a `Scafold`.
/// 
/// We use our first command to set `PreHeader::route` and pad
/// `PreHeader::beta` for usage in transmission or in aSURB, but
/// do not encode it into `PreHeader::beta`.
struct Scaffold<P: Params> {
    /// First hop that should process this header.
    start: RoutingName,

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
    remaining_beta: usize,

    /// 
    commands: Vec<Command<Vec<u8>>>

    /// Stream ciphers for 
    hops: Vec<HeaderCipher<P>>,

    /// Packet construction mode, either `Ok` for SURBs, or
    /// `None` for a normal forward packets. 
    /// Also, records unwinding keys and twig ids in SURB mode.
    surb: Option<Vec<SURBHop>>,
}

impl<P: Params> Scafold<P> {
    pub fn new<R: Rng>(rng: &mut R) -> SphinxResult<Directives<P>> {
        let mut seed = [u8; 64];
        rng.fill_bytes(&mut seed);
        let a = curve::Scalar::make(&seed);
        let alpha = curve::Point::from_secret(&a).compress();
        // Should we test alpha?
        // curve::Point::decompress(&alpha) ?;
        Ok(( Directives { alpha, a, remaining: P::BETA_LENGTH, hop: Vec::new() } )
    }

    pub fn add(&mut self, activity: Activity) -> SphinxResult<()> {
    }

    pub fn add(&mut self, command: Command) -> SphinxResult<()> {
        self.a  ??

        self.remaining -= command.length_as_bytes();
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

*/




