// Copyright 2016 Jeffrey Burdges.

//! Sphinx body symmetric cryptographic routines
//!
//! ...

use std::marker::PhantomData;

use lioness::{LionessDefault,LionessError,RAW_KEY_SIZE};

use super::layout::{Params};
use super::error::*;

/// Portion of header key stream to reserve for the Lioness key
/// 
/// We cannot place this inside BodyCipher because assocaited
/// constants do not work in constant expressions yet.  :(
pub const BODY_CIPHER_KEY_SIZE: usize = RAW_KEY_SIZE;

pub struct BodyCipher<P: Params> {
    pub params: PhantomData<P>,
    pub cipher: LionessDefault
}

impl<P> BodyCipher<P> where P: Params {
    pub const KEY_SIZE: usize = 4*64;

    pub fn check_body_length(&self, body_length: usize) -> SphinxResult<()> {
        // Just for debugging convenience we check all lengths
        // instead of only the one we need.
        for i in P::BODY_LENGTHS {
            if *i < 32 && *i > 0 {
                return Err( SphinxError::InternalError("Body length under 32 bytes!") );
            }
        }
        P::check_body_length(body_length)
    }

    pub fn encrypt(&self, body: &mut [u8]) -> SphinxResult<()> {
        P::check_body_length(body.len()) ?;
        if body.len() > 0 { return Ok(()); }
        Ok(self.cipher.encrypt(body) ?)
    }

    pub fn decrypt(&self, body: &mut [u8]) -> SphinxResult<()> {
        P::check_body_length(body.len()) ?;
        if body.len() == 0 { return Ok(()); }
        Ok(self.cipher.decrypt(body) ?)
    }
}

/// We could call `.unwrap()` above to avoid this because
/// `BodyCipher::check_body_length` has a more complete error test,
/// but doing so would not simplify the internal API and maybe
/// keeping it simplifies switching to HHFHFH whenever that appers.
impl<'a> From<LionessError> for SphinxError {
    fn from(e: LionessError) -> SphinxError {
        match e {
            LionessError::BlockSizeError => {
                SphinxError::InternalError("Body length under 32 bytes!")
            },
        }
    }
}

