// Copyright 2016 Jeffrey Burdges.

//! Sphinx header layout routines
//!
//! ...

use std::iter::{Iterator};  // IntoIterator, TrustedLen, ExactSizeIterator


pub use ratchet::{TwigId,TWIG_ID_LENGTH};

use super::*; // {PacketName,PACKET_NAME_LENGTH};
use super::curve::{AlphaBytes,ALPHA_LENGTH};
use super::stream::{Gamma,GammaBytes,GAMMA_LENGTH};
use super::stream::{SphinxHop};
pub use super::keys::{RoutingName,ROUTING_NAME_LENGTH};
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::error::*;
use super::slice::*;


/// We use `usize` for indexing, like all Rust programs, but we specify
/// a dramatically smaller type for user specified indexes.
pub type Length = usize;


/// Sphinx `'static` runtime paramaters 
///
/// We require a `&'static SphinxParams` when used because the
/// protocol specification should be compiled into the binary.
///
/// In some cases, there could be minor performance hits if some
/// of these are not multiples of the ChaCha blocksize of 64 byte.
#[derive(Debug)] // Clone, Copy
pub struct SphinxParams {
    /// Unique version identifier for the protocol
    pub protocol_name: &'static str,

    /// Length of the routing information block `Beta`.
    pub beta_length: Length,

    /// Maximal amount of routing infomrmation in `Beta` consued
    /// by a single sub-hop.
    pub max_beta_tail_length: Length,

    /// Maximum length of the SURB.  At most half of `beta_length - 48`.
    ///
    /// Alpha and Gamma are encoded into the "bottom" of beta, and
    /// hence do not contribute here.  This is unlikely to change.
    /// As a result this should not exceed `beta_length`
    pub max_surb_beta_length: Length,

    /// Length of the SURB log.
    pub surb_log_length: Length,

    /// Approved message body lengths
    pub body_lengths: &'static [Length],
}

impl SphinxParams {
    /// Sphinx header length
    #[inline(always)]
    pub fn header_length(&self) -> usize {
        ALPHA_LENGTH + GAMMA_LENGTH
        + self.beta_length as usize
        + self.surb_log_length as usize
    }

    /// Create a `Box<[u8]>` with the required header length
    /// and containing zeros.
    pub fn boxed_zeroed_header(&self) -> Box<[u8]> {
        let mut v = Vec::with_capacity(self.header_length());
        for _ in 0..self.header_length() { v.push(0); }
        v.into_boxed_slice()
    }

    /// Borrow a mutable slice `&mut [u8]` as a `HeaderRefs` consisting.
    /// of subspices for the various header components.  You may mutate
    /// these freely so that after the borrow ends the original slice
    /// contains the new header. 
    /// 
    pub fn slice_header<'a>(&'static self, mut header: &'a mut [u8])
      -> SphinxResult<HeaderRefs<'a>>
    {
        // Prevent configurations that support long SURB attacks.
        if 2*self.max_surb_beta_length > self.beta_length - ALPHA_LENGTH + GAMMA_LENGTH {
            return Err( SphinxError::BadLength("Maximum SURB is so long that it degrades sender security",
                self.max_surb_beta_length) );
        }
        if self.max_surb_beta_length > MAX_SURB_BETA_LENGTH as Length {
            return Err( SphinxError::BadLength("Maximum SURB length exceeds encoding",
                self.max_surb_beta_length) );
        }

        let orig_len = header.len();
        if orig_len < self.header_length() {
            return Err( SphinxError::BadLength("Header is too short",orig_len) );
        }
        let hr = HeaderRefs {
            params: self,
            alpha: reserve_fixed_mut!(&mut header,ALPHA_LENGTH),
            gamma: reserve_fixed_mut!(&mut header,GAMMA_LENGTH),
            beta: reserve_mut(&mut header,self.beta_length as usize),
            surb_log: reserve_mut(&mut header,self.surb_log_length as usize),
        };
        if header.len() > 0 {
            return Err( SphinxError::BadLength("Header is too long",orig_len) );
        }
        Ok(hr)
    }

    /// Returns an error if the body length is not approved by the paramaters.
    pub fn check_body_length(&self, body_length: usize) -> SphinxResult<()> {
        if self.body_lengths.len() == 0 {
            if body_length == 0 {
                Ok(())  // All body lengths are zero if no body lengths were specified
            } else {
                Err( SphinxError::BadLength("Nonempty body with no body lengths specified", body_length) )
            }
        } else if self.body_lengths.contains(&body_length) {
            Ok(())
        } else {
            Err( SphinxError::BadLength("Unapproaved body length",body_length) )
        }
    }

    /// Create a `Box<[u8]>` with the requested body length
    /// from `SphinxParams::body_lengths` and containing zeros.
    pub fn boxed_zeroed_body(&self, i: usize) -> Box<[u8]> {
        let length = self.body_lengths[i];
        let mut v = Vec::with_capacity(length);
        for _ in 0..length { v.push(0); }
        v.into_boxed_slice()
    }

}

pub const INVALID_SPHINX_PARAMS : &'static SphinxParams = &SphinxParams {
    protocol_name: "Invalid Sphinx!",
    beta_length: 0,
    max_beta_tail_length: 0,
    max_surb_beta_length: 0,
    surb_log_length: 0,
    body_lengths: &[0]
};


pub type LatencySeed = u8;

pub const MAX_LATENCY_SEED : u8 = 127;

/// Commands to mix network nodes embedded in beta.
#[derive(Debug, Clone, Copy)]
pub enum Command {
    /// Crossover from header to SURB
    CrossOver {
        alpha: AlphaBytes,
        gamma: Gamma,
        surb_beta_length: usize,
    },

    /// Advance and integrate a ratchet state
    Ratchet {
        twig: TwigId,
        gamma: Gamma,
    },

    /// Transmit packet to another mix network node
    Transmit {
        route: RoutingName,
        gamma: Gamma,
        latency_seed: LatencySeed,
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

    // Drop Off { },
    // Delete { },
}

pub const MAX_SURB_BETA_LENGTH : usize = 0x1000;

impl Command {
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
            Ratchet { twig, gamma } => 
                f(&[ &[0x00u8; 1], & twig.to_bytes(), &gamma.0 ]),
            Transmit { route, gamma, latency_seed } => {
                debug_assert!(latency_seed < MAX_LATENCY_SEED);
                f(&[ &[0x80u8 | latency_seed; 1], &route.0, &gamma.0 ])
            },
            Deliver { mailbox } =>
                f(&[ &[0x60u8; 1], &mailbox.0 ]),
            CrossOver { alpha, gamma, surb_beta_length } => {
                debug_assert!(surb_beta_length < MAX_SURB_BETA_LENGTH);
                debug_assert!(MAX_SURB_BETA_LENGTH <= 0x1000);
                let h = (surb_beta_length >> 8) as u8;
                let l = (surb_beta_length & 0xFF) as u8;
                f(&[ &[0x40u8 | h, l], &alpha, &gamma.0 ])
            },
            ArrivalSURB { } => 
                f(&[ &[0x50u8; 1] ]),
            ArrivalDirect { } =>
                f(&[ &[0x70u8; 1] ]),
            // Drop Off
            // Delete
        }
    }

    /// Length of `Command` on the wire.
    ///
    /// Does not include SURB's beta for `CrossOver` command. 
    pub fn length_as_bytes(&self) -> usize {
        self.feed_bytes( |x| { x.iter().map(|y| y.len()).sum() } )
    }

    /// Prepends our command to slice `beta` by shifting `beta`
    /// rightward, destroys the trailing elements.
    pub fn prepend_bytes(&self, beta: &mut [u8]) -> usize {
        self.feed_bytes( |x| { prepend_slice_of_slices(beta, x) } )
    }

    /// Read a command from the beginning of beta.
    fn parse(mut beta: &[u8]) -> SphinxResult<(Command,usize)> {
        use self::Command::*;
        let beta_len = beta.len();
        // We consider only the high four bits for now because
        // we might tweak TwigId, MailboxName, and RoutingName
        // to shave off one byte eventually.
        let b0 = reserve_fixed!(&mut beta,1)[0];
        let command = match b0 & 0xF0 {
            // Ratchet if the two high bits are clear.
            0x00..0x30 => Ratchet {
                twig: TwigId::from_bytes(reserve_fixed!(&mut beta,TWIG_ID_LENGTH)),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // Transmit if the high bit is set.
            0x80..0xF0  => Transmit {
                route: RoutingName(*reserve_fixed!(&mut beta,ROUTING_NAME_LENGTH)),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // Deliver, CrossOver, or Arival if 0x08 is clear while 0x04 is set.
            0x60 => Deliver {
                mailbox: MailboxName(*reserve_fixed!(&mut beta,MAILBOX_NAME_LENGTH)),
            },
            0x40 => CrossOver {
                surb_beta_length: (
                    (((b0 & 0x0F) as u16) << 8) | (reserve_fixed!(&mut beta,1)[0] as u16)
                ) as usize,
                alpha: *reserve_fixed!(&mut beta,ALPHA_LENGTH),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // Arivals are encoded with the low bit set.
            0x50 => ArrivalSURB { },
            0x70 => ArrivalDirect { },
            // Drop Off
            // Delete
            c => { return Err( SphinxError::BadPacket("Unknown command",c as u64)); },
        };
        Ok((command, beta_len-beta.len()))
    }

    /// Produce a random sequence of latency seeds that fit into.
    /// a the command.
    ///
    /// Uses [Robert Floyd's algorithm](http://fermatslibrary.com/s/a-sample-of-brilliance)
    /// to minimize calls to the random number generator.
    pub fn latency_seeds<R: rand::Rng>(rng: &mut R, trials: u8)
      -> SphinxResult<Box<[LatencySeed]>> 
    {
        if trials > MAX_LATENCY_SEED {
            return Err( SphinxError::InternalError("Too many trials for encoding") );
        }
        // Unnecesarily heavy usage of random number generator
        //   rand::sample(rng, 0..127, trials)
        // Switch to this eventually :
        //   rand::combination(rng, 0..127, trials)
        // see https://github.com/rust-lang-nursery/rand/pull/144
        let mut s = Vec::with_capacity(trials);
        let n = MAX_LATENCY_SEED+1;
        let m = trials;
        // Robert Floyd's algorithm
        for j in n-m+1...n {
            let t = rng.gen_range(0,j);
            s.push( if s.contains(t) { j-1 } else { t } );
        }
        s.into_boxed_slice()
    }
}


/// Reads a `PacketName` from the SURB log and trims the SURB log
/// to removing it.  Used in SURB unwinding.
///
/// We avoid making this a method to `HeaderRefs` because it trims
/// the SURB log by shortening the slice, violating the inveriant
/// assumed by `HeaderRef`.
pub fn read_n_trim_surb_log(surb_log: &mut &[u8]) -> PacketName {
    PacketName(*reserve_fixed!(surb_log,PACKET_NAME_LENGTH))
}


/*
use std::ops::{Deref,DerefMut};

struct HideMut<'a,T>(&'a mut T) where T: ?Sized + 'a;

impl<'a,T> HideMut<'a,T> where T: ?Sized {
    pub fn new(m: &'a mut T) -> HideMut<'a,T> { HideMut(m) }
}

impl<'a,T> Deref for HideMut<'a,T> where T: ?Sized {
    type Target = T;
    fn deref(&self) -> &T { self.0 }
}

impl<'a,T> DerefMut for HideMut<'a,T> where T: ?Sized {
    fn deref_mut(&mut self) -> &mut T { self.0 }
}
*/

/// A Sphinx header structured by individual components. 
///
/// Create by applying `slice_header` to `&mut [u8]` slice of the
/// correct length, like that created by `boxed_zeroed_header`.
/// We check all lengths in `slice_header` so that methods and
/// functions using `HeaderRefs` may assume all header lengths to
/// be correct, and even that the slices are contiguious.
///
/// We mostly handle `HeaderRefs` via mutable borrows so that we may
/// change the referred to values without interrior mutability. 
/// We thus do not make the slice references themselves non-public
/// because accessor methods would borrow the whole struct.  
/// As a result, any caller could invalidate our requirement that 
/// slices be contiguous.  If desired, this could be prevented using
/// the `HideMut` struct above.  See http://stackoverflow.com/a/42376165/667457
pub struct HeaderRefs<'a> {
    /// Sphinx `'static` runtime paramaters 
    pub params: &'static SphinxParams,

    pub alpha: &'a mut AlphaBytes,
    pub gamma: &'a mut GammaBytes,
    pub beta:  &'a mut [u8],
    pub surb_log: &'a mut [u8],
}

impl<'a> HeaderRefs<'a> {
/*
    pub fn alpha(&'a self) -> &'a AlphaBytes { self.alpha }
    pub fn gamma(&'a self) -> &'a GammaBytes { self.gamma }
    pub fn beta(&'a self) -> &'a [u8] { self.beta }
    pub fn surb_log(&'a self) -> &'a [u8] { self.surb_log }

    pub fn alpha_mut(&'a mut self) -> &'a mut AlphaBytes { self.alpha }
    pub fn gamma_mut(&'a mut self) -> &'a mut GammaBytes { self.gamma }
    pub fn beta_mut(&'a mut self) -> &'a mut [u8] { self.beta }
    pub fn surb_log_mut(&'a mut self) -> &'a mut [u8] { self.surb_log }
*/

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet by
    /// calling `SphinxHop::verify_gamma` with the provided fields.
    pub fn verify_gamma(&self, hop: &SphinxHop) -> SphinxResult<()> {
        hop.verify_gamma(self.beta, &Gamma(*self.gamma))
    }

    /// Compute gamma from Beta and the SURB.  Probably not useful.
    pub fn create_gamma(&self, hop: &SphinxHop) -> SphinxResult<Gamma> {
        hop.create_gamma(self.beta) // .map(|x| { x.0 })
    }

    /// Prepend a `PacketName` to the SURB log.
    /// Used in SURB rerouting so that SURB unwinding works.
    pub fn prepend_to_surb_log(&mut self, packet_name: &PacketName) {
        prepend_slice_of_slices(self.surb_log, &[&packet_name.0]);
        // prepend_iterator(self.surb_log, packet_name.0.iter().map(|x| *x));
    }

    /// Prepend a command to beta for creating beta.
    pub fn prepend_to_beta(&mut self, cmd: &Command) -> usize {
        cmd.prepend_bytes(self.beta)
    }

    /// Decrypt beta, read a command from an initial segment of beta,
    /// shift beta forward by the command's length, and pad the tail
    /// of beta.
    pub fn peal_beta(&mut self, hop: &mut SphinxHop) -> SphinxResult<Command> {
        hop.xor_beta(self.beta, false) ?;  // InternalError

        let (command, eaten) = Command::parse(self.beta) ?;  // BadPacket: Unknown Command
        if eaten > self.params.max_beta_tail_length as usize {
            return Err( SphinxError::InternalError("Ate too much Beta!") );
        }

        let length = self.beta.len();
        debug_assert_eq!(length, self.params.beta_length as usize);
        // let beta = &mut refs.beta[..length];
        for i in eaten..length { self.beta[i-eaten] = self.beta[i];  }
        hop.set_beta_tail(&mut self.beta[length-eaten..length]) ?;  // InternalError
        Ok(command)
    }
}

// TODO: Consider using owning_refs crate to provide
// pub fn new_sliced_header(&self) -> SphinxResult<OwningHandle<Box<[u8]>,HeaderRefs>> { }
// ref.  https://kimundi.github.io/owning-ref-rs/owning_ref/struct.OwningHandle.html

/*

pub struct HeaderIter<'a> {
    offset: usize,
    header_refs: HeaderRefs<'a>,
}

impl<'a> Iterator for HeaderIter<'a> {
    type Item=u8;

    fn next(&mut self) -> Option<u8> {
        let i = self.offset;
        self.offset += 1;
        if i < ALPHA_LENGTH { return Some(self.alpha[i]) }
        i -= ALPHA_LENGTH;
        if i < GAMMA_LENGTH { return Some(self.gamma[i]) }
        i -= GAMMA_LENGTH;
        if i < self.params.beta_length as usize { return Some(self.beta[i]) }
        i -= self.params.beta_length as usize;
        if i < self.params.surb_log_length as usize { return Some(self.surb_log[i]) }
        i -= self.params.surb_log_length as usize;
        if i < self.params.surb_length as usize { return Some(self.surb[i]) }
        i -= self.params.surb_length as usize;
        self.offset -= 1;  None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.params.header_length();
        (l, Some(l))
    }
}

impl<'a> Iterator ExactSizeIterator for HeaderIter<'a> {
    fn len(&self) -> usize { self.params.header_length() }
    // fn is_empty(&self) -> bool { false }
}

impl<'a> IntoIterator for HeaderRefs<'a> {
    type Item=u8;
    type IntoIter = HeaderIter<'a>;
    fn into_iter(self) -> HeaderIter<'a> {
        HeaderIter { offset: 0, header_refs: self }
    }
}
*/


