// Copyright 2016 Jeffrey Burdges.

//! Sphinx header layout routines
//!
//! ...

use std::iter::{Iterator,IntoIterator,TrustedLen};  // ExactSizeIterator

pub use ratchet::{TwigId,TWIG_ID_LENGTH};

use super::*; // {PacketName,PacketNameBytes,PACKET_NAME_LENGTH};
use super::curve::{AlphaBytes,ALPHA_LENGTH};
use super::stream::{Gamma,GammaBytes,GAMMA_LENGTH};
use super::stream::{SphinxHop};
pub use super::keys::{RoutingName,ROUTING_NAME_LENGTH};
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::error::*;


/// We use `usize` for indexing, like all Rust programs, but we specify
/// a dramatically smaller type for user specified indexes.
pub type Length = usize;


/// Sphinx `'static` runtime paramaters 
///
/// We require a `&'static SphinxParams` when used because the
/// protocol specification should be compiled into the binary.
#[derive(Debug)] // Clone, Copy
pub struct SphinxParams {
    /// Unique version identifier for the protocol
    pub protocol_name: &'static str,

    /// Length of the routing information block `Beta`.
    ///
    /// A multiple of the ChaCha blocksize of 64 may produce better performance.
    pub beta_length: Length,

    /// Maximal amount of routing infomrmation in `Beta` consued
    /// by a single sub-hop.
    ///
    /// A multiple of the ChaCha blocksize of 64 may produce better performance.
    pub max_beta_tail_length: Length,

    /// Length of the SURB log.
    ///
    /// A multiple of the ChaCha blocksize of 64 may produce better performance.
    pub surb_log_length: Length,

    /// Approved message body lengths
    pub body_lengths: &'static [Length],
}

/// Returns an initial segment of a `mut &[T]` replacing the inner
/// `&[T]` with the remainder.  In effect, this executes the command
/// `(return,heap) = heap.split_at(len)` without annoying the borrow
/// checker.  See http://stackoverflow.com/a/42162816/667457
fn reserve<'heap, T>(heap: &mut &'heap [T], len: usize) -> &'heap [T] {
    let tmp: &'heap [T] = ::std::mem::replace(&mut *heap, &[]);
    let (reserved, tmp) = tmp.split_at(len);
    *heap = tmp;
    reserved
}

/// A version of `reserve` for fixed length arrays.
macro_rules! reserve_fixed { ($heap:expr, $len:expr) => {
    array_ref![reserve($heap,$len),0,$len]
} }

/// Returns an initial segment of a `mut &mut [T]` replacing the inner
/// `&mut [T]` with the remainder.  In effect, this executes the command
/// `(return,heap) = heap.split_at_mut(len)` without annoying the borrow
/// checker.  See http://stackoverflow.com/a/42162816/667457
fn reserve_mut<'heap, T>(heap: &mut &'heap mut [T], len: usize) -> &'heap mut [T] {
    let tmp: &'heap mut [T] = ::std::mem::replace(&mut *heap, &mut []);
    let (reserved, tmp) = tmp.split_at_mut(len);
    *heap = tmp;
    reserved
}

/// A version of `reserve_mut` for fixed length arrays.
macro_rules! reserve_fixed_mut { ($heap:expr, $len:expr) => {
    array_mut_ref![reserve_mut($heap,$len),0,$len]
} }

/// Reads a `PacketName` from the SURB log and trims the SURB log
/// to removing it.  Used in SURB unwinding.
///
/// We avoid making this a method to `HeaderRefs` because it trims
/// the SURB log by shortening the slice, violating the inveriant
/// assumed by `HeaderRef`.
pub fn read_n_trim_surb_log(surb_log: &mut &[u8]) -> PacketName {
    PacketName(*reserve_fixed!(surb_log,PACKET_NAME_LENGTH))
}

impl SphinxParams {
    /// Sphinx SURB length
    ///
    /// Alpha and Gamma do not appear here currently because we encode
    /// them into the "bottom" of beta; however, this could be changed.
    #[inline(always)]
    pub fn surb_length(&self) -> usize {
         self.beta_length as usize
    }

    /// Sphinx header length
    #[inline(always)]
    pub fn header_length(&self) -> usize {
        ALPHA_LENGTH + GAMMA_LENGTH
        + self.beta_length as usize
        + self.surb_log_length as usize
        + self.surb_length()
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
    pub fn slice_header<'a>(&'static self, mut header: &'a mut [u8])
      -> SphinxResult<HeaderRefs<'a>>
    {
        if header.len() < self.header_length() {
            return Err( SphinxError::InternalError("Header is too short!") );
        }
        let hr = HeaderRefs {
            params: self,
            alpha: reserve_fixed_mut!(&mut header,ALPHA_LENGTH),
            gamma: reserve_fixed_mut!(&mut header,GAMMA_LENGTH),
            beta: reserve_mut(&mut header,self.beta_length),
            surb_log: reserve_mut(&mut header,self.surb_log_length),
            surb: reserve_mut(&mut header,self.surb_length()),
        };
        if header.len() > 0 {
            return Err( SphinxError::InternalError("Header is too long!") );
        }
        Ok(hr)
    }

    /// Returns an error if the body length is not approved by the paramaters.
    pub fn check_body_length(&self, body_length: Length) -> SphinxResult<()> {
        if self.body_lengths.len() == 0 {
            if body_length == 0 {
                Ok(())  // All body lengths are zero if no body lengths were specified
            } else {
                Err( SphinxError::InternalError("Nonempty body with no body lengths specified.") )
            }
        } else if self.body_lengths.contains(&body_length) {
            Ok(())
        } else {
            Err( SphinxError::BadBodyLength(body_length) )
        }
    }
}

pub const INVALID_SPHINX_PARAMS : &'static SphinxParams = &SphinxParams {
    protocol_name: "Invalid Sphinx!",
    beta_length: 0,
    max_beta_tail_length: 0,
    surb_log_length: 0,
    body_lengths: &[0]
};


/// Commands to mix network nodes embedded in beta.
#[derive(Debug, Clone, Copy)]
pub enum Command {
    /// Crossover from header to SURB
    CrossOver {
        alpha: AlphaBytes,
        gamma: Gamma,
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
    },

    /// Deliver message to the specified mailbox, roughly equivelent
    /// to transmition to a non-existant mix network node.
    Delivery {
        /// Mailbox name
        mailbox: MailboxName,
    },

    /// Arrival of a SURB we created and archived.
    ArrivalSURB { },

    /// Arrival of a message for a local application.
    ArrivalDirect { },
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


/// Shift a slice `s` rightward by `shift` elements.  Does not zero
/// the initial segment created, but does return its bounds. 
/// Destroys the trailing `shift` elements of `s`.
fn pre_shift_right_slice<T: Copy>(s: &mut [T], shift: usize) -> ::std::ops::Range<usize> {
    let len = s.len();
    if len <= shift { return 0..len; }
    let mut i = s.len();
    let s = &mut s[..i];  // elide bounds checks; see Rust commit 6a7bc47
    while i > shift {
        i -= 1;
        s[i] = s[i-shift];
    }    // I dislike  for i in (target.len()-1 .. start-1).step_by(-1) { }
    0 .. ::std::cmp::min(shift,len)
}

/// Prepends a slice to the slice `target`, shifting `target` rightward.
/// Destroys the trailing `shift` elements of `target`.
///
/// We sadly cannot require that `I::IntoIter: ExactSizeIterator` here
/// because `Chain` does not satisfy that, due to fears the length
/// might overflow.  See https://github.com/rust-lang/rust/issues/34433
/// Just requiring `TrustedLen` and asserting that `size_hint` gives
/// equal uper and lower bounds should be equevelent.
#[inline]
fn prepend_to_slice<I>(target: &mut [I::Item], prepend: I) -> usize
  where I: IntoIterator, I::IntoIter: TrustedLen, I::Item: Copy
{
    let mut prepend = prepend.into_iter();

    // let start = prepend.len();
    let (start,end) = prepend.size_hint();
    assert_eq!(Some(start), end);

    let r = pre_shift_right_slice(target,start);

    let end = r.end;
    // target[r].copy_from_slice(prepend[r]);
    for (i,j) in target[r].iter_mut().zip(prepend) { *i = j; }
    end
}


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
    pub surb:  &'a mut [u8],
}

impl<'a> HeaderRefs<'a> {
/*
    pub fn alpha(&'a self) -> &'a AlphaBytes { self.alpha }
    pub fn gamma(&'a self) -> &'a GammaBytes { self.gamma }
    pub fn beta(&'a self) -> &'a [u8] { self.beta }
    pub fn surb_log(&'a self) -> &'a [u8] { self.surb_log }
    pub fn surb(&'a self) -> &'a [u8]  { self.surb }

    pub fn alpha_mut(&'a mut self) -> &'a mut AlphaBytes { self.alpha }
    pub fn gamma_mut(&'a mut self) -> &'a mut GammaBytes { self.gamma }
    pub fn beta_mut(&'a mut self) -> &'a mut [u8] { self.beta }
    pub fn surb_log_mut(&'a mut self) -> &'a mut [u8] { self.surb_log }
    pub fn surb_mut(&'a mut self) -> &'a mut [u8]  { self.surb }
*/

    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet by
    /// calling `SphinxHop::verify_gamma` with the provided fields.
    pub fn verify_gamma(&self, hop: SphinxHop) -> SphinxResult<()> {
        hop.verify_gamma(self.beta, self.surb, &Gamma(*self.gamma))
    }

    /// Compute gamma from Beta and the SURB.  Probably not useful.
    pub fn create_gamma(&mut self, hop: SphinxHop) {
        *self.gamma = hop.create_gamma(self.beta, self.surb).0;
    }

    /// Prepend a `PacketName` to the SURB log.
    /// Used in SURB rerouting so that SURB unwinding works.
    pub fn prepend_to_surb_log(&mut self, prepend: &PacketName) {
        prepend_to_slice(self.surb_log, prepend.0.iter().map(|x| *x));
    }

    /// Prepend a command to beta for creating beta.
    pub fn prepend_to_beta(&mut self, cmd: &Command) {
        use self::Command::*;
        let l = match *cmd {
            CrossOver { alpha, gamma } => prepend_to_slice(self.beta,
                [0x00u8; 1].iter()
                .chain(&alpha)
                .chain(&gamma.0).map(|x| *x)
            ),
            Ratchet { twig, gamma } => prepend_to_slice(self.beta,
                [0x80u8; 1].iter()
                .chain(& twig.to_bytes())
                .chain(&gamma.0).map(|x| *x)
            ),
            Delivery { mailbox } => prepend_to_slice(self.beta,
                [0x40u8; 1].iter()
                .chain(&mailbox.0).map(|x| *x)
            ),
            Transmit { route, gamma } => prepend_to_slice(self.beta,
                [0x40u8; 1].iter()
                .chain(&route.0)
                .chain(&gamma.0).map(|x| *x)
            ),
            ArrivalSURB { } => prepend_to_slice(self.beta, [0x30u8; 1].iter().map(|x| *x) ),
            ArrivalDirect { } => prepend_to_slice(self.beta, [0x20u8; 1].iter().map(|x| *x) ),
            // _ => return Err( SphinxError::UnknownCommand(0x00) ),
        };
        debug_assert!(l <= self.params.max_beta_tail_length as usize);
    }

    /// Read a command from the beginning of beta.
    fn parse_beta(&self) -> SphinxResult<(Command,usize)> {
        use self::Command::*;
        let mut beta: &[u8] = self.beta;  // Do not change the referant of self.beta!
        let beta_len = beta.len();
        // We consider only the high four bits for now because
        // we might tweak TwigId, MailboxName, and RoutingName
        // to shave off one byte eventually.
        let b0 = reserve_fixed!(&mut beta,1)[0] & 0xF0;
        let command = match b0 {
            0x00 => CrossOver {
                alpha: *reserve_fixed!(&mut beta,ALPHA_LENGTH),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            0x80 => Ratchet {
                twig: TwigId::from_bytes(reserve_fixed!(&mut beta,TWIG_ID_LENGTH)),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // 0x90 through 0xF reserved
            0x60 => Delivery {
                mailbox: MailboxName(*reserve_fixed!(&mut beta,MAILBOX_NAME_LENGTH)),
            },
            0x40 => Transmit {
                route: RoutingName(*reserve_fixed!(&mut beta,ROUTING_NAME_LENGTH)),
                gamma: Gamma(*reserve_fixed!(&mut beta,GAMMA_LENGTH)),
            },
            // 0x70, 0x50, and 0x0x10 reserved
            0x30 => ArrivalSURB { },
            0x20 => ArrivalDirect { },
            c => return Err( SphinxError::UnknownCommand(c) ),
        };
        Ok((command, beta_len-beta.len()))
    }

    /// Read a command from the beginning of beta and .
    pub fn parse_n_shift_beta(&mut self, hop: &mut SphinxHop) -> SphinxResult<Command> {
        let (command, eaten) = self.parse_beta() ?;  // UnknownCommand
        if eaten > self.params.max_beta_tail_length as usize {
            return Err( SphinxError::InternalError("Ate too much Beta!") );
        }
        let length = self.beta.len();
        debug_assert_eq!(length, self.params.beta_length as usize);
        // let beta = &mut refs.beta[..length]; 
        for i in eaten..length { self.beta[i-eaten] = self.beta[i];  }
        hop.set_beta_tail(&mut self.beta[length-eaten..length]);
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


