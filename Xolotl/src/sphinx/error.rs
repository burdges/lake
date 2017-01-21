// Copyright 2016 Jeffrey Burdges 

//! Error reporting for Xolotl ratchet

use std::error::Error;
use std::convert::From;
// use std::marker::PhantomData;
use std::fmt;

use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError

#[derive(Debug, Clone)]
pub enum SphinxError {
    InternalError(&'static str),
    PoisonError(&'static str,&'static str),
    Replay(ReplayCode), 
    InvalidMac(ReplayCode), 
}


impl fmt::Display for SphinxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::XolotlError::*;
        match *self {
            InternalError(s)
                => write!(f, "Internal error: ", s),
            PoisonError(l,t)
                => write!(f, "Internal error: PoisonError< {}<'_,{}> >.", l, t),
            Replay(id)
                => write!(f, "Replay attack detected on {:x}.", id),
            InvalidMac(id)
                => write!(f, "Invalid mac on {:x}.", id),
        }
    }
}

impl Error for XolotlError {
    fn description(&self) -> &str {
        "I'm a Xolotl error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::XolotlError::*;
        match *self {
            BranchAlreadyLocked(_) => None,
            MissingTwig(_) => None,
            WrongTwigType(_,_,_) => None,
            MissingBranch(_) => None,
            MissingParent(_) => None,
            CorruptBranch(_,_) => None,
            PoisonError(_,_) => None, // Maybe here
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

impl_XolotlPoisonError!(BranchStorage);
impl_XolotlPoisonError!(ParentStorage);
impl_XolotlPoisonError!(TwigStorage);
impl_XolotlPoisonError!(BranchLocks);
impl_XolotlPoisonError!(AdvanceFailCache);
impl_XolotlPoisonError!(AdvanceDropErrors);



