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
enum Activity {
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

    // Final activities

    /// Embed SURB into beta and use at the crossover point is specifies
    CrossOverBeta {
        surb: PreHeader
    },

    /// Consume a SURB at the contact point specified
    CrossOverContact {
        route: RoutingName,
        // id
    },

    /// Consume a SURB at the greeting point specified
    CrossOverGreeting {
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

    // DropOff { },
    // Delete { },
}

impl Activity {
    /// Are we allowed as the initial `Activity` in route building?
    ///
    /// 
    pub fn is_initial(act: &Activity) -> bool {
        use self::Activity::*;
        match *act {
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
    pub fn is_final(act: &Activity) -> bool {
        use self::Activity::*;
        match *act {
            FromCrossOver {..} => false,
            Sphinx {..} | Ratchet {..} => false,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => true,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => true,
            // Delete {} => true
            // DropOff {} => false,
        }
    }

}


struct Activities<'a,P: Params> {
    params: PhantomData<P>,

    activities: &'a [Activity],

    // TODO: Foreign ratchets by node 
    ratchet: Arc<RatchetState>,
}


/*
impl Activities {
    pub fn make_header(&self) -> Header {
    }
}
*/


