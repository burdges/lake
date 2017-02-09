// Copyright 2016 Jeffrey Burdges 

//! Error reporting for Xolotl ratchet

use std::error::Error;
use std::convert::From;
use std::fmt;

use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError

use rustc_serialize::hex::ToHex;


use super::state::*;
use ratchet::error::RatchetError;


#[derive(Debug, Clone)]
pub enum SphinxError {
    InternalError(&'static str),
    PoisonError(&'static str,&'static str),
    Replay(ReplayCode), 
    InvalidMac(ReplayCode),
    BadAlpha([u8; 32]),
}


impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxError::*;
        match *self {
            InternalError(s)
                => write!(f, "Internal error: {}", s),
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



