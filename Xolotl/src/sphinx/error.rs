// Copyright 2016 Jeffrey Burdges 

//! Error reporting for Sphinx
//!

use std::error::Error;
use std::convert::From;
use std::fmt;

// use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError

// use rustc_serialize::hex::ToHex;


use super::Length;
use super::replay::*;
use ratchet::error::RatchetError;

/// `ErrorPacketId` is a `ReplayCode` in testing and empty otherwise.
#[cfg(not(test))]
#[derive(Copy,Clone)]
pub struct ErrorPacketId;

/// `ErrorPacketId` is a `ReplayCode` in testing and empty otherwise.
#[cfg(test)]
pub type ErrorPacketId = ReplayCode;

#[cfg(not(test))]
impl ReplayCode {
    pub fn error_packet_id(&self) -> ErrorPacketId { ErrorPacketId }
}

#[cfg(test)]
impl ReplayCode {
    pub fn error_packet_id(&self) -> ErrorPacketId { *self }
}

#[cfg(not(test))]
impl fmt::Debug for ErrorPacketId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "packet details scrubed")
    }
}


#[derive(Debug, Clone)]
pub enum SphinxError {
    InternalError(&'static str),
    BadBodyLength(Length),
    PoisonError(&'static str,&'static str),
    Replay(ErrorPacketId), 
    InvalidMac(ErrorPacketId),
    BadAlpha([u8; 32]),
}

pub type SphinxResult<T> = Result<T,SphinxError>;

impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use rustc_serialize::hex::ToHex;
        use self::SphinxError::*;
        match *self {
            InternalError(s)
                => write!(f, "Internal error: {}", s),
            BadBodyLength(l)
                => write!(f, "Invalid body length of {}", l),
            PoisonError(l,t)
                => write!(f, "Internal error: PoisonError< {}<'_,{}> >.", l, t),
            Replay(id)
                => write!(f, "Replay attack detected on {:?}.", id),
            InvalidMac(id)
                => write!(f, "Invalid MAC with {:?}.", id),
            BadAlpha(alpha)
                => write!(f, "Invalid Alpha {}.", alpha.to_hex()),
        }
    }
}

impl Error for SphinxError {
    fn description(&self) -> &str {
        "I'm a Sphinx error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::SphinxError::*;
        match *self {
            InternalError(_) => None,
            BadBodyLength(_) => None,
            PoisonError(_,_) => None, // Maybe here
            Replay(_) => None, 
            InvalidMac(_) => None,
            BadAlpha(_) => None,
        }
    }
}



macro_rules! impl_SphinxPoisonError {
    ($l:ident, $t:ident) => {
        impl<'a> From<::std::sync::PoisonError<$l<'a, $t>>> for SphinxError {
            fn from(_: ::std::sync::PoisonError<$l<'a, $t>>) -> SphinxError {
                // _.get_mut()
                SphinxError::PoisonError(stringify!($l),stringify!($t))
            }
        }
    };
    ($t:ident) => {
        impl_XolotlPoisonError!(RwLockReadGuard, $t);
        impl_XolotlPoisonError!(RwLockWriteGuard, $t);
    };
    /* $b:block */
    // ($t:ident) => {
    //     impl_XolotlPoisonError!($t; {  });
    // };
} // impl_XolotlPoisonError

// impl_XolotlPoisonError!(ReplayStorage);
// impl_XolotlPoisonError!(NodeInfoStorage);


