// Copyright 2016 Jeffrey Burdges.

//! Sphinx header symmetric cryptographic routines
//!
//! ...

use lioness::{LionessDefault,LionessError,RAW_KEY_SIZE};

use super::header::{Length,SphinxParams};
use super::error::*;

/// Portion of header key stream to reserve for the Lioness key
/// 
/// We cannot place this inside BodyCipher because assocaited
/// constants do not work in constant expressions yet.  :(
pub const BODY_CIPHER_KEY_SIZE: Length = RAW_KEY_SIZE;

pub struct BodyCipher {
    pub params: &'static SphinxParams,
    pub cipher: LionessDefault
}

impl BodyCipher {
    pub const KEY_SIZE: Length = 4*64;

    pub fn check_body_length(&self,body_length: Length) -> SphinxResult<()> {
        // Just for debugging convenience we check all lengths
        // instead of only the one we need.
        for i in self.params.body_lengths {
            if *i < 32 && *i > 0 {
                return Err( SphinxError::InternalError("Body length under 32 bytes!") );
            }
        }
        self.params.check_body_length(body_length)
    }

    pub fn encrypt(&self, body: &mut [u8]) -> SphinxResult<()> {
        self.check_body_length(body.len()) ?;
        if body.len() > 0 { return Ok(()); }
        Ok(self.cipher.encrypt(body) ?)
    }

    pub fn decrypt(&self, body: &mut [u8]) -> SphinxResult<()> {
        self.check_body_length(body.len()) ?;
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

