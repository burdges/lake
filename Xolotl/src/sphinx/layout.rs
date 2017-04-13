// Copyright 2016 Jeffrey Burdges.

//! Sphinx header layout routines
//!
//! ...

use std::borrow::{Borrow,BorrowMut};
use std::iter::{Iterator};  // IntoIterator, TrustedLen, ExactSizeIterator
use std::marker::PhantomData;


pub use ratchet::{TwigId,TWIG_ID_LENGTH};

use super::*; // {PacketName,PACKET_NAME_LENGTH};
use super::curve::{AlphaBytes,ALPHA_LENGTH};
use super::stream::{Gamma,GammaBytes,GAMMA_LENGTH,HeaderCipher};
use super::stream::{};
pub use super::keys::{RoutingName,ROUTING_NAME_LENGTH,ValidityPeriod};
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::error::*;
use super::slice::*;


/// Commands to mix network nodes embedded in beta.
#[derive(Debug, Clone, Copy)]
pub enum Command {
    /// Transmit packet to another mix network node
    Transmit {
        route: RoutingName,
        gamma: Gamma,
    },

    /// Advance and integrate a ratchet state
    Ratchet {
        twig: TwigId,
        gamma: Gamma,
    },

    /// Crossover with SURB in beta
    CrossOver {
        alpha: AlphaBytes,
        gamma: Gamma,
        surb_beta_length: usize,
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
            Transmit { route, gamma } => {
                f(&[ &[0x80u8; 1], &route.0, &gamma.0 ])
            },
            Ratchet { twig, gamma } => 
                f(&[ &[0x00u8; 1], & twig.to_bytes(), &gamma.0 ]),
            CrossOver { alpha, gamma, surb_beta_length } => {
                debug_assert!(surb_beta_length < MAX_SURB_BETA_LENGTH);
                debug_assert!(MAX_SURB_BETA_LENGTH <= 0x1000);
                let h = (surb_beta_length >> 8) as u8;
                let l = (surb_beta_length & 0xFF) as u8;
                f(&[ &[0x40u8 | h, l], &alpha, &gamma.0 ])
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
    ///
    /// We only return the SURBs length and do not seperate it
    /// because this only gets called from `peal_beta` which leaves
    /// the SURB in place.
    fn parse(mut beta: &[u8]) -> SphinxResult<(Command,usize)> {
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
                surb_beta_length: (
                    (((b0 & 0x0F) as u16) << 8) | (reserve_fixed!(&mut beta,1)[0] as u16)
                ) as usize,
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

/// Reads a `PacketName` from the SURB log and trims the SURB log
/// to removing it.  Used in SURB unwinding.
///
/// We avoid making this a method to `HeaderRefs` because it trims
/// the SURB log by shortening the slice, violating the inveriant
/// assumed by `HeaderRef`.
pub fn read_n_trim_surb_log(surb_log: &mut &[u8]) -> PacketName {
    PacketName(*reserve_fixed!(surb_log,PACKET_NAME_LENGTH))
}


/// We use `usize` for indexing, like all Rust programs, but we may
/// specify a smaller type for user specified indexes.
pub type Length = usize;


/// Sphinx paramaters
///
/// We require a `&'static SphinxParams` when used because the
/// protocol specification should be compiled into the binary.
///
/// In some cases, there could be minor performance hits if some
/// of these are not multiples of the ChaCha blocksize of 64 byte.
pub trait Params: Sized {
    /// Unique version identifier for the protocol
    const PROTOCOL_NAME: &'static str;

    /// Length of the routing information block `Beta`.
    const BETA_LENGTH: Length;

    /// Maximal amount of routing infomrmation in `Beta` consued
    /// by a single sub-hop.
    const MAX_BETA_TAIL_LENGTH: Length;

    /// Maximum length of the SURB.  At most half of `BETA_LENGTH - 48`.
    ///
    /// Alpha and Gamma are encoded into the "bottom" of beta, and
    /// hence do not contribute here.  This is unlikely to change.
    /// As a result this should not exceed `BETA_LENGTH`
    const MAX_SURB_BETA_LENGTH: Length;

    /// Length of the SURB log.
    const SURB_LOG_LENGTH: Length;

    /// Approved message body lengths
    const BODY_LENGTHS: &'static [Length];

    /// Rate paramater lambda for the exponential distribution of
    /// from which we sample the senders' sugested delays in 
    /// `Stream::delay`.
    const DELAY_LAMBDA: f64;

    /// Sphinx header length
    #[inline(always)]
    fn header_length() -> usize {
        ALPHA_LENGTH + GAMMA_LENGTH
        + Self::BETA_LENGTH as usize
        + Self::SURB_LOG_LENGTH as usize
    }
}

/*
pub struct ParamsEtc<P: Params>(PhantomData<P>);
impl<P> Params for ParamsEtc<P> where P: Params, PhantomData<P>: 'static  {
    const PROTOCOL_NAME: &'static str
     = P::PROTOCOL_NAME;
    const BETA_LENGTH: Length
     = P::BETA_LENGTH;
    const MAX_BETA_TAIL_LENGTH: Length
     = P::MAX_BETA_TAIL_LENGTH;
    const MAX_SURB_BETA_LENGTH: Length
     = P::MAX_SURB_BETA_LENGTH;
    const SURB_LOG_LENGTH: Length
     = P::SURB_LOG_LENGTH;
    const BODY_LENGTHS: &'static [Length]
     = P::BODY_LENGTHS;
    const DELAY_LAMBDA: f64
     = P::DELAY_LAMBDA;
}
*/

/// Just a helper trait to provide inherent methods on types
/// satisfying `Params`.
pub trait ImplParams: Params {
    fn boxed_zeroed_header() -> Box<[u8]>;
    fn boxed_zeroed_body(i: usize) -> Box<[u8]>;
    fn check_body_length(body_length: usize) -> SphinxResult<()>;
}

impl<P: Params> ImplParams for P {
    /// Create a `Box<[u8]>` with the required header length
    /// and containing zeros.
    fn boxed_zeroed_header() -> Box<[u8]> {
        let l = P::header_length();
        let mut v = Vec::with_capacity(l);
        for _ in 0..l { v.push(0); }
        v.into_boxed_slice()
    }

    /// Create a `Box<[u8]>` with the requested body length
    /// from `SphinxParams::BODY_LENGTHS` and containing zeros.
    fn boxed_zeroed_body(i: usize) -> Box<[u8]> {
        let length = P::BODY_LENGTHS[i];
        let mut v = Vec::with_capacity(length);
        for _ in 0..length { v.push(0); }
        v.into_boxed_slice()
    }

    /// Returns an error if the body length is not approved by the paramaters.
    fn check_body_length(body_length: usize) -> SphinxResult<()> {
        // Just for debugging convenience we check all lengths
        // instead of only the one we need.
        for l in P::BODY_LENGTHS {
            use super::body::BodyCipher;
            BodyCipher::<P>::compatable_length(*l) ?;
        }
        if P::BODY_LENGTHS.len() == 0 {
            if body_length == 0 {
                Ok(())  // All body lengths are zero if no body lengths were specified
            } else {
                Err( SphinxError::BadLength("Nonempty body with no body lengths specified", body_length) )
            }
        } else if P::BODY_LENGTHS.contains(&body_length) {
            Ok(())
        } else {
            Err( SphinxError::BadLength("Unapproaved body length",body_length) )
        }
    }
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
/// Create by applying `new_sliced` to `&mut [u8]` slice of the
/// correct length, like that created by `boxed_zeroed_header`.
/// We check all lengths in `new_sliced` so that methods and
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
pub struct HeaderRefs<'a,P> where P: Params {
    params: PhantomData<P>,
    pub alpha: &'a mut AlphaBytes,
    pub gamma: &'a mut GammaBytes,
    pub beta:  &'a mut [u8],
    pub surb_log: &'a mut [u8],
}

impl<'a,P> HeaderRefs<'a,P> where P: Params {
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

    /// Borrow a mutable slice `&mut [u8]` as a `HeaderRefs` consisting.
    /// of subspices for the various header components.  You may mutate
    /// these freely so that after the borrow ends the original slice
    /// contains the new header. 
    ///
    pub fn new_sliced<'s>(mut header: &'s mut [u8]) -> SphinxResult<HeaderRefs<'s,P>>
    {
        // Prevent configurations that support long SURB attacks.
        if 2*P::MAX_SURB_BETA_LENGTH > P::BETA_LENGTH - ALPHA_LENGTH + GAMMA_LENGTH {
            return Err( SphinxError::BadLength("Maximum SURB is so long that it degrades sender security",
                P::MAX_SURB_BETA_LENGTH) );
        }
        if P::MAX_SURB_BETA_LENGTH > MAX_SURB_BETA_LENGTH as Length {
            return Err( SphinxError::BadLength("Maximum SURB length exceeds encoding",
                P::MAX_SURB_BETA_LENGTH) );
        }

        let orig_len = header.len();
        if orig_len < P::header_length() {
            return Err( SphinxError::BadLength("Header is too short",orig_len) );
        }
        let hr = HeaderRefs {
            params: PhantomData,
            alpha: reserve_fixed_mut!(&mut header,ALPHA_LENGTH),
            gamma: reserve_fixed_mut!(&mut header,GAMMA_LENGTH),
            beta: reserve_mut(&mut header,P::BETA_LENGTH as usize),
            surb_log: reserve_mut(&mut header,P::SURB_LOG_LENGTH as usize),
        };
        if header.len() > 0 {
            return Err( SphinxError::BadLength("Header is too long",orig_len) );
        }
        Ok(hr)
    }


    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet by
    /// calling `HeaderCipher::verify_gamma` with the provided fields.
    pub fn verify_gamma(&self, hop: &HeaderCipher<P>) -> SphinxResult<()> {
        hop.verify_gamma(self.beta, &Gamma(*self.gamma))
    }

    /// Compute gamma from Beta and the SURB.  Probably not useful.
    pub fn create_gamma(&self, hop: &HeaderCipher<P>) -> SphinxResult<Gamma> {
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
    pub fn peal_beta(&mut self, hop: &mut HeaderCipher<P>) -> SphinxResult<Command> {
        hop.xor_beta(self.beta, false) ?;  // InternalError

        let (command, eaten) = Command::parse(self.beta) ?;  // BadPacket: Unknown Command
        if eaten > P::MAX_BETA_TAIL_LENGTH as usize {
            return Err( SphinxError::InternalError("Ate too much Beta!") );
        }

        // We could reduce our calls to ChaCha by partially processing
        // commands here, like zeroing beta's during cross over, or 
        // ignoring beta entirely for delivery commands. 
        let length = self.beta.len();
        debug_assert_eq!(length, P::BETA_LENGTH as usize);
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

pub struct HeaderIter<'a,P: Params> {
    offset: usize,
    header_refs: HeaderRefs<'a>,
}

impl<'a,P: Params> Iterator for HeaderIter<'a,P> {
    type Item=u8;

    fn next(&mut self) -> Option<u8> {
        let i = self.offset;
        self.offset += 1;
        if i < ALPHA_LENGTH { return Some(self.alpha[i]) }
        i -= ALPHA_LENGTH;
        if i < GAMMA_LENGTH { return Some(self.gamma[i]) }
        i -= GAMMA_LENGTH;
        if i < P::BETA_LENGTH as usize { return Some(self.beta[i]) }
        i -= P::BETA_LENGTH as usize;
        if i < P::SURB_LOG_LENGTH as usize { return Some(self.surb_log[i]) }
        i -= P::SURB_LOG_LENGTH as usize;
        if i < P::surb_length as usize { return Some(self.surb[i]) }
        i -= P::surb_length as usize;
        self.offset -= 1;  None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = P::header_length();
        (l, Some(l))
    }
}

impl<'a, P: Params> Iterator ExactSizeIterator for HeaderIter<'a> {
    fn len(&self) -> usize { P::header_length() }
    // fn is_empty(&self) -> bool { false }
}

impl<'a, P: Params> IntoIterator for HeaderRefs<'a,P> {
    type Item=u8;
    type IntoIter = HeaderIter<'a>;
    fn into_iter(self) -> HeaderIter<'a> {
        HeaderIter { offset: 0, header_refs: self }
    }
}
*/


/// Unsent full or partial Sphinx headers, including SURBs.
///
/// TODO: Avoid one needless allocation by using DSTs.  We could
/// eliminate the extra allocation by using `Box::<T>::into_raw()`
/// and `Box::<U>::from_raw` along with a cast `*T as *U` and the
/// endianness conversion, except that our `T` and `U` are `[u8]`
/// and `PreHeader` with `Box<[u8]>` replaced by `[u8]`, which are
/// unsized, so this being careful.
pub struct PreHeader {
    pub validity: ValidityPeriod,
    pub route: RoutingName,
    pub alpha: AlphaBytes,
    pub gamma: Gamma,
    pub beta: Box<[u8]>
}

impl PreHeader {
    /// Encode a SURB for storage or transmission
    pub fn encode_surb(self) -> Box<[u8]> {
        let mut v = Vec::with_capacity(
            16 + ROUTING_NAME_LENGTH + ALPHA_LENGTH + GAMMA_LENGTH + self.beta.len()
        );
        v.extend_from_slice( & self.validity.to_bytes() );
        v.extend_from_slice( &self.route.0 );
        v.extend_from_slice( &self.alpha );
        v.extend_from_slice( &self.gamma.0 );
        v.extend_from_slice( self.beta.borrow() );
        v.into_boxed_slice()
    }

    /// Encode a SURB from storage or transmission.
    pub fn decode_surb(mut surb: &[u8]) -> PreHeader {
        PreHeader {
            route: RoutingName(*reserve_fixed!(&mut surb, ROUTING_NAME_LENGTH)),
            validity: ValidityPeriod::from_bytes(reserve_fixed!(&mut surb, 16)),
            alpha: *reserve_fixed!(&mut surb, ALPHA_LENGTH),
            gamma: Gamma(*reserve_fixed!(&mut surb, GAMMA_LENGTH)),
            beta: surb.to_owned().into_boxed_slice(),
        }
    }
}

use rand::Rng;

pub fn encode_header<P: Params,R: Rng>(rng: &mut Rng, preheader: PreHeader) -> Box<[u8]> {
    let mut h = P::boxed_zeroed_header();
    {
        let mut refs = HeaderRefs::<P>::new_sliced(h.borrow_mut()).unwrap();
        *refs.alpha = preheader.alpha;
        *refs.gamma = preheader.gamma.0;
        refs.beta.copy_from_slice(preheader.beta.borrow());
        rng.fill_bytes(refs.surb_log);
        // argument: seed: &[u8; 32]
        // use chacha::ChaCha as ChaCha20;
        // use keystream::{KeyStream};
        // let mut chacha = ChaCha20::new_chacha20(seed, &[0u8; 8]);
        // self.stream.xor_read(refs.surb_log).unwrap();
    }
    h
}


