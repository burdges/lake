// Copyright 2016 Jeffrey Burdges.

//! Sphinx header layout routines
//!
//! ...


use super::curve::{AlphaBytes,ALPHA_LENGTH};
use super::stream::{Gamma,GammaBytes,GAMMA_LENGTH,SphinxHop};
use super::node::NodeToken;
use super::error::*;


/// Alias for indexes into a Sphinx header
pub type Length = usize;

/// Sphinx `'static` runtime paramaters 
///
/// We require a `&'static SphinxParams` when used because the
/// protocol specification should be compiled into the binary.
#[derive(Debug,Clone,Copy)]
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
}

/// Returns an initial segment of a `mut &mut [T]` replacing the inner
/// `&mut [T]` with the remainder.  In effect, this executes the command
/// `(return,heap) = heap.split_at_mut(len)` without annoying the borrow
/// checker.  See http://stackoverflow.com/a/42162816/667457
fn reserve<'heap, T>(heap: &mut &'heap mut [T], len: usize) -> &'heap mut [T] {
    let tmp: &'heap mut [T] = ::std::mem::replace(&mut *heap, &mut []);
    let (reserved, tmp) = tmp.split_at_mut(len);
    *heap = tmp;
    reserved
}

/// A version of `reserve` for fixed length arrays.
macro_rules! reserve_fixed { ($heap:expr, $len:expr) => {
    array_mut_ref![reserve($heap,$len),0,$len]
} }

impl SphinxParams {
    /// Sphinx SURB length
    ///
    /// Alpha and Gamma do not appear here currently because we encode
    /// them into the "bottom" of beta; however, this could be changed.
    #[inline(always)]
    pub fn surb_length(&self) -> usize {
         self.beta_length
    }

    /// Sphinx header length
    #[inline(always)]
    pub fn header_length(&self) -> usize {
        ALPHA_LENGTH + GAMMA_LENGTH + self.beta_length
        + self.surb_log_length
        + self.surb_length()
    }

    pub fn boxed_zeroed_header(&self) -> Box<[u8]> {
        let mut v = Vec::with_capacity(self.header_length());
        for _ in 0..self.header_length() { v.push(0); }
        v.into_boxed_slice()
    }

    pub fn slice_header<'a>(&'static self, mut header: &'a mut [u8])
      -> SphinxResult<HeaderRefs<'a>>
    {
        if header.len() < self.header_length() {
            return Err( SphinxError::InternalError("Header is too short!") );
        }
        let hr = HeaderRefs {
            params: self,
            alpha: reserve_fixed!(&mut header,ALPHA_LENGTH),
            gamma: reserve_fixed!(&mut header,GAMMA_LENGTH),
            beta: reserve(&mut header,self.beta_length),
            surb_log: reserve(&mut header,self.surb_log_length),
            surb: reserve(&mut header,self.surb_length()),
        };
        if header.len() > 0 {
            return Err( SphinxError::InternalError("Header is too long!") );
        }
        Ok(hr)
    }

    // TODO: Consider using owning_refs crate to provide
    // pub fn new_sliced_header(&self) -> SphinxResult<OwningHandle<Box<[u8]>,HeaderRefs>> { }
    // ref.  https://kimundi.github.io/owning-ref-rs/owning_ref/struct.OwningHandle.html
}

pub const INVALID_SPHINX_PARAMS : &'static SphinxParams = &SphinxParams {
    protocol_name: "Invalid Sphinx!",
    beta_length: 0,
    max_beta_tail_length: 0,
    surb_log_length: 0
};

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
    /// Verify the poly1305 MAC `Gamma` given in a Sphinx packet by
    /// calling `SphinxHop::verify_gamma` with the provided fields.
    pub fn verify_gamma(&self, hop: SphinxHop) -> SphinxResult<()> {
        hop.verify_gamma(self.beta, self.surb, &Gamma(*self.gamma))
    }
}

/*
use std::iter::{Iterator,IntoIterator};

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
        if i < self.params.beta_length { return Some(self.beta[i]) }
        i -= self.params.beta_length;
        if i < self.params.surb_log_length { return Some(self.surb_log[i]) }
        i -= self.params.surb_log_length;
        if i < self.params.surb_length { return Some(self.surb[i]) }
        i -= self.params.surb_length;
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



