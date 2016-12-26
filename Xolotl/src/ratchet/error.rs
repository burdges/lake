// Copyright 2016 Jeffrey Burdges 

//! Error reporting for Xolotl ratchet

use std::error::Error;
use std::convert::From;
use std::marker::PhantomData;
use std::fmt;

use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError

use super::branch::*;
use super::twig::*;
use super::state::*;


#[derive(Debug)]
pub enum XolotlError {
    BranchAlreadyLocked(BranchId),
    MissingBerry(u8,TwigId),
    MissingBranch(BranchId),
    MissingParent(BranchName),
    CorruptBranch(BranchId, &'static str),
    PoisonError(&'static str,&'static str),
}

impl fmt::Display for XolotlError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::XolotlError::*;
        match *self {
            BranchAlreadyLocked(bid)
                => write!(f, "Branch {} already locked.  Did you make a promise?", bid),
            MissingBerry(tid)
                => write!(f, "Missing berry {}.", tid),
            MissingBranch(bid)
                => write!(f, "Missing branch {}.", bid),
            MissingParent(bn)
                => write!(f, "Missing parent branch {}", bn),
            CorruptBranch(s,bid)
                => write!(f, "Found corrupted branch {} {}.", bid, s),
            PoisonError(l,t)
                => write!(f, "Internal error: PoisonError< {}<'_,{}> >.", l, t),
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
            MissingBerry(_) => None,
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
            fn from(e: ::std::sync::PoisonError<$l<'a, $t>>) -> XolotlError {
                // e.get_mut()
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


