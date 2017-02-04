// Copyright 2016 Jeffrey Burdges 

//! Error reporting for Xolotl ratchet

use std::error::Error;
use std::convert::From;
// use std::marker::PhantomData;
use std::fmt;

use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError


use super::state::*;
use self::ratchet::error::XolotlError;


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
                => write!(f, "Replay attack detected on {:x}.", id),
            InvalidMac(id)
                => write!(f, "Invalid mac on {:x}.", id),
            BadAlpha(alpha)
                => write!(f, "Invalid mac on {:x}.", alpha),
        }
    }
}

impl Error for XolotlError {
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


macro_rules! impl_XolotlPoisonError {
    ($l:ident, $t:ident) => {
        impl<'a> From<::std::sync::PoisonError<$l<'a, $t>>> for XolotlError {
            fn from(_: ::std::sync::PoisonError<$l<'a, $t>>) -> XolotlError {
                // _.get_mut()
                XolotlError::PoisonError(stringify!($l),stringify!($t))
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



