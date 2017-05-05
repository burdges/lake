// Copyright 2016 Jeffrey Burdges.

//! Sphinx header layout routines
//!
//! ...

use std::borrow::{Borrow,BorrowMut};
use std::marker::PhantomData;

use super::curve::{AlphaBytes,ALPHA_LENGTH};
use super::stream::{Gamma,GammaBytes,GAMMA_LENGTH,HeaderCipher};
use super::keys::{RoutingName,RoutingNameBytes,ROUTING_NAME_LENGTH};
use super::keys::{ValidityPeriod};
use super::commands::{Command,CommandGamma,CommandData,CommandNode,MAX_SURB_BETA_LENGTH};
use super::error::*;
use super::slice::*;
use super::*; // {PacketName,PACKET_NAME_LENGTH};


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
    /// Unique numeric identifier for the protocol
    const PROTOCOL_ID: surbs::ProtocolId;

    /// Unique string identifier for the protocol
    const PROTOCOL_NAME: &'static str;

    /// Length of the routing information block `Beta`.
    const BETA_LENGTH: Length;

    /// Maximal amount of routing infomrmation in `Beta` consumed
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

    fn max_hops_capacity() -> usize {
        /// Rust bug: https://github.com/rust-lang/rust/issues/26264
        /// Write CommandNode::Transmit here when fixed.
        let c = Command::Transmit::<Gamma,usize> {
            route: RoutingName([0u8; ROUTING_NAME_LENGTH]),
            gamma: Gamma([0u8; GAMMA_LENGTH]),
        };
        Self::BETA_LENGTH / c.command_length()
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
        vec![0u8; P::header_length()].into_boxed_slice()
    }

    /// Create a `Box<[u8]>` with the requested body length
    /// from `SphinxParams::BODY_LENGTHS` and containing zeros.
    fn boxed_zeroed_body(i: usize) -> Box<[u8]> {
        vec![0u8; P::BODY_LENGTHS[i]].into_boxed_slice()
    }

    /// Returns an error if the body length is not approved by the paramaters.
    fn check_body_length(body_length: usize) -> SphinxResult<()> {
        // Just for debugging convenience we check all lengths
        // instead of only the one we need.
        for l in P::BODY_LENGTHS {
            body::BodyCipher::<P>::compatable_length(*l) ?;
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
    pub route: &'a mut RoutingNameBytes,
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
            route: reserve_fixed_mut!(&mut header,ROUTING_NAME_LENGTH),
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
    ///
    /// TODO: Remove as this should never be used.
    pub fn prepend_to_beta<G,D>(&mut self, cmd: &Command<G,D>) -> usize
      where G: CommandGamma, D: CommandData {
        cmd.prepend_bytes(self.beta)
    }

    /// Decrypt beta, read a command from an initial segment of beta,
    /// shift beta forward by the command's length, and pad the tail
    /// of beta.
    pub fn peal_beta(&mut self, hop: &mut HeaderCipher<P>) -> SphinxResult<CommandNode> {
        hop.xor_beta(self.beta,0,0) ?;  // InternalError

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
    pub beta: Box<[u8]>,
    // pub keys: ...,
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

pub fn encode_header<P: Params,R: Rng>(rng: &mut Rng, preheader: PreHeader)
  -> SphinxResult<Box<[u8]>> {
    if preheader.beta.len() != P::BETA_LENGTH as usize {
        return Err( SphinxError::InternalError("Used SURB as sending header!") );
    }
    let mut h = P::boxed_zeroed_header();
    {
        let mut refs = HeaderRefs::<P>::new_sliced(h.borrow_mut()).unwrap();
        *refs.route = preheader.route.0;
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
    Ok(h)
}


