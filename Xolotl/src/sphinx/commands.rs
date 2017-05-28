// Copyright 2016 Jeffrey Burdges.

//! Sphinx header commands
//!
//! ...


use std::iter::{Iterator};  // IntoIterator, TrustedLen, ExactSizeIterator

pub use ratchet::{TwigId,TWIG_ID_LENGTH};

use keys::{RoutingName,ROUTING_NAME_LENGTH}; // RoutingNameBytes
use curve::{AlphaBytes,ALPHA_LENGTH};
use super::stream::{Gamma,GammaBytes,GAMMA_LENGTH};
use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::error::*;
use super::slice::*;
use super::*; // {PacketName,PACKET_NAME_LENGTH};



/// Representation for any unsized extra data of a `Command`.
pub trait CommandData {
    fn length(&self) -> usize;
    fn data(&self) -> &[u8];
}

/// We leave any extra data for a command in beta when parsing
/// during mix node operation, so it requires only a length `usize`.
impl CommandData for usize {
    fn length(&self) -> usize { *self }
    fn data(&self) -> &[u8] { &[] }  // panic??
}

/// We hold unsized extra data as a `Vec[u8]` inside the `Command` 
/// when building headers on the client.
impl CommandData for Box<[u8]> {
    fn length(&self) -> usize { self.len() }
    fn data(&self) -> &[u8] { self }
}


/// Representation for `gamma` that might currently be unknown.
/// 
/// 
pub trait CommandGamma : Clone+Copy {
    fn gamma(&self) -> &[u8; GAMMA_LENGTH] {
        static INVALID_GAMMA: &[u8; GAMMA_LENGTH] = &[0u8; GAMMA_LENGTH];
        INVALID_GAMMA
    }
}

/// We return `gamma` itself when we know it, meaning when `G` has
/// type `Gamma`.
impl CommandGamma for Gamma {
    fn gamma(&self) -> &[u8; GAMMA_LENGTH] { &self.0 }
}

/// If we do not know `gamma` then we supply a fake `Gamma` set to
/// `[0u8; GAMMA_LENGTH]` so as to give a correct length when 
/// preparing `beta`.  
impl CommandGamma for () { }
impl CommandGamma for usize { }


/// Actual `Command` type produced when decoding `beta`.
pub type CommandNode = Command<Gamma,usize>;

/// Preliminay `Command` types used when encoding `beta`.
pub type PreCommand<G> = Command<G,Box<[u8]>>;


/// Commands to mix network nodes embedded in beta.
#[derive(Debug)] // Clone, Copy
pub enum Command<G,D> where G: CommandGamma, D: CommandData {
    /// Transmit packet to another mix network node
    Transmit {
        route: RoutingName,
        gamma: G,
    },

    /// Advance and integrate a ratchet state
    Ratchet {
        twig: TwigId,
        gamma: G,
    },

    /// Crossover with SURB in beta
    CrossOver {
        route: RoutingName,
        alpha: AlphaBytes,
        gamma: Gamma,
        surb_beta: D,
    },

    /// Crossover with SURB stored on node
    Contact {
        // unimplemented!()
    },
    Greeting {
        // unimplemented!()
    },

    /// Deliver message to the specified mailbox, roughly equivelent
    /// to transmition to a non-existant mix network node.
    Deliver {
        /// Mailbox name
        mailbox: MailboxName,
    },

    /// Arrival of a SURB we created and archived.
    ArrivalSURB { },

    /// Arrival of a message for a local application.
    ArrivalDirect { },

    // DropOff { },
    // Delete { },
    // Dummy { },
}

/// Hard maximum size of a SURB's `beta` supported by our encoding
/// of `Command::CrossOver`.  Actual maximum size is smaller and is
/// controlled in `layout` module.
pub const MAX_SURB_BETA_LENGTH : usize = 0x1000;

impl<G: CommandGamma,D: CommandData> Command<G,D> {
    /// Feed the closure a series of byte arrays that give our wire
    /// representation. 
    ///
    /// We could return a `-> impl Iterator+TrustedLen` here using
    /// `flat_map` except that Rust dislikes static literals unless
    /// they are strings, so no `&'static [0x00u8; 1]`.
    fn feed_bytes<F,R>(&self, f: F) -> R 
      where F: FnOnce(&[&[u8]]) -> R {
        use self::Command::*;
        match *self {
            Transmit { route, ref gamma } => {
                f(&[ &[0x80u8; 1], &route.0, gamma.gamma() ])
            },
            Ratchet { twig, ref gamma } => 
                f(&[ &[0x00u8; 1], & twig.to_bytes(), gamma.gamma() ]),
            CrossOver { route, alpha, ref gamma, ref surb_beta } => {
                let surb_beta_length = surb_beta.length();
                debug_assert!(surb_beta_length < MAX_SURB_BETA_LENGTH);
                debug_assert!(MAX_SURB_BETA_LENGTH <= 0x1000);
                let h = (surb_beta_length >> 8) as u8;
                let l = (surb_beta_length & 0xFF) as u8;
                f(&[ &[0x40u8 | h, l], &route.0, &alpha, &gamma.0, surb_beta.data() ])
            },
            Contact { } => 
                f(&[ &[0x60u8; 1], unimplemented!() ]),
            Greeting { } => 
                f(&[ &[0x61u8; 1], unimplemented!() ]),
            Deliver { mailbox } =>
                f(&[ &[0x50u8; 1], &mailbox.0 ]),
            // DropOff
            ArrivalSURB { } => 
                f(&[ &[0x70u8; 1] ]),
            ArrivalDirect { } =>
                f(&[ &[0x71u8; 1] ]),
            // Delete
        }
    }

    /// Length of `Command` on the wire.
    ///
    /// Include SURB's `beta` for `CrossOver` command only if `D`
    /// does so, meaming if `D` is a `Vec<u8>`.  As a result, this
    /// gives the length without the SURB's `beta` in nodes, but
    /// includes the SURB's `beta` in the client.
    pub fn command_length(&self) -> usize {
        self.feed_bytes( |x| { x.iter().map(|y| y.len()).sum() } )
    }

    pub fn write_command(&self, mut beta: &mut [u8]) -> usize {
        self.feed_bytes( |x| {
            let mut l = 0usize;
            for y in x.iter() {
                l += y.len();
                reserve_mut(&mut beta, y.len()).copy_from_slice(y);
            }
            l  // We do not currently use this return value
        } )
    }

    /// Prepends our command to slice `beta` by shifting `beta`
    /// rightward, destroys the trailing elements.
    pub fn prepend_bytes(&self, beta: &mut [u8]) -> usize {
        self.feed_bytes( |x| prepend_slice_of_slices(beta, x) )
    }
}

impl CommandNode {
    /// Read a command from the beginning of beta.
    ///
    /// We only return the SURBs length and do not seperate it
    /// because this only gets called from `peal_beta` which leaves
    /// the SURB in place.
    pub fn parse(mut beta: &[u8]) -> SphinxResult<(CommandNode,usize)> {
        use self::Command::*;
        let beta_len = beta.len();
        // We could tweak RoutingName or TwigId to shave off one byte
        // eventually, but sounds like premature optimization now.
        let b0 = reserve_fixed!(&mut beta,1)[0];
        let command = match b0 {
            // Transmit if the high bit is set.
            0x80..0xFF => Transmit {
                route: RoutingName(*reserve_fixed!(&mut beta,ROUTING_NAME_LENGTH)),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // Ratchet if the two high bits are clear.
            0x00..0x3F => Ratchet {
                twig: TwigId::from_bytes(reserve_fixed!(&mut beta,TWIG_ID_LENGTH)),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // Anything else has the form 0b01??_????
            // CrossOver from Beta if 0b0100_????
            0x40..0x4F => CrossOver {
                surb_beta: (
                    (((b0 & 0x0F) as u16) << 8) | (reserve_fixed!(&mut beta,1)[0] as u16)
                ) as usize,
                route: RoutingName(*reserve_fixed!(&mut beta,ROUTING_NAME_LENGTH)),
                alpha: *reserve_fixed!(&mut beta,ALPHA_LENGTH),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // Authenticated cross overs have the form 0b0110_????
            0x60 => Contact {
                // unimplemented!()
            },
            0x61 => Greeting {
                // unimplemented!()
            },
            0x62..0x6F => { return Err( SphinxError::BadPacket("Unknown authenticated cross over command",b0 as u64)); },
            // Deliveries have form 0b0110_????
            0x50 => Deliver {
                mailbox: MailboxName(*reserve_fixed!(&mut beta,MAILBOX_NAME_LENGTH)),
            },
            // 0x51 => DropOff { 
            // },
            0x51..0x5F => { return Err( SphinxError::BadPacket("Unknown deliver command",b0 as u64)); },
            // Arivals have the form 0b0111_????
            0x70 => ArrivalSURB { },
            0x71 => ArrivalDirect { },
            // 0x7F => Delete {
            // },
            0x72..0x7F => { return Err( SphinxError::BadPacket("Unknown arrival command",b0 as u64)); },
            c => { return Err( SphinxError::BadPacket("Unknown command",c as u64)); },
        };
        Ok((command, beta_len-beta.len()))
    }

}

impl<G0> PreCommand<G0> where G0: CommandGamma {
    pub fn map_gamma<F,E,G1>(self, mut f: F) -> Result<PreCommand<G1>,E>
      where G1: CommandGamma,
            F: FnMut(G0) -> Result<G1,E>
    {
        use self::Command::*;
        Ok( match self {
            Transmit { route, gamma } => Transmit { route, gamma: f(gamma) ? },
            Ratchet { twig, gamma } => Ratchet { twig, gamma: f(gamma) ? },
            CrossOver { route, alpha, gamma, surb_beta }
              => CrossOver { route, alpha, gamma, surb_beta },
            Contact { } => Contact { },
            Greeting { } => Greeting { },
            Deliver { mailbox } => Deliver { mailbox },
            ArrivalSURB { } => ArrivalSURB { },
            ArrivalDirect { } => ArrivalDirect { },
            // DropOff { } => DropOff { },
            // Delete { } => Delete { },
            // Dummy { } => Dummy { },
        } )
    }
}

impl<G0> PreCommand<G0> where G0: CommandGamma+Clone+Copy {
    pub fn get_gamma(&self) -> Option<G0> {
        match *self {
            Command::Transmit { route, gamma } => Some(gamma),
            Command::Ratchet { twig, gamma } => Some(gamma),
            _ => None,
        }
        // We wanted to reduce this to `map_gamma` but it benifits
        // from being by value.
        // self.map_gamma::<_,_,G0>( |g| Err(g) ).err()
    }
}

impl<G0> PreCommand<G0> where G0: CommandGamma {
    pub fn is_gamma(&self) -> bool {
        match *self {
            Command::Transmit { .. } => true,
            Command::Ratchet { .. } => true,
            _ => false,
        }
        // We can define this without needing any constraints on
        // `gamma`, so might as well.
        // self.get_gamma().is_some()
        // self.map_gamma( |g| Err::<(),()>(()) ).is_err()
    }
}


