// Copyright 2016 Jeffrey Burdges 

//! Error reporting for Xolotl ratchet

use std::error::Error;
use std::convert::From;
// use std::marker::PhantomData;
use std::fmt;

use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError


use super::branch::*;
use super::twig::*;
use super::state::*;


#[derive(Debug, Clone)]
pub enum RatchetError {
    // InternalError(&'static str),
    PoisonError(&'static str,&'static str),
    BranchAlreadyLocked(BranchId),
    MissingTwig(TwigId),
    WrongTwigType(TwigId,u8,u8),
    MissingBranch(BranchId),
    MissingParent(BranchName),
    CorruptBranch(BranchId, &'static str),
}

pub type RatchetResult<T> = Result<T,RatchetError>;

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::RatchetError::*;
        match *self {
            PoisonError(l,t)
                => write!(f, "Internal error: PoisonError< {}<'_,{}> >.", l, t),
            BranchAlreadyLocked(bid)
                => write!(f, "Branch {} already locked.  Did you make a promise?", bid),
            MissingTwig(tid)
                => write!(f, "Missing train key {}.", tid),
            WrongTwigType(tid,found,expected)
                => write!(f, "Twig {} had type {:x} when {:x} expected.", tid, found, expected),
            MissingBranch(bid)
                => write!(f, "Missing branch {}.", bid),
            MissingParent(bn)
                => write!(f, "Missing parent branch {}", bn),
            CorruptBranch(s,bid)
                => write!(f, "Found corrupted branch {} {}.", bid, s),
        }
    }
}

impl Error for RatchetError {
    fn description(&self) -> &str {
        "I'm a Xolotl error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::RatchetError::*;
        match *self {
            PoisonError(_,_) => None, // Maybe here
            BranchAlreadyLocked(_) => None,
            MissingTwig(_) => None,
            WrongTwigType(_,_,_) => None,
            MissingBranch(_) => None,
            MissingParent(_) => None,
            CorruptBranch(_,_) => None,
        }
    }
}


macro_rules! impl_XolotlPoisonError {
    ($l:ident, $t:ident) => {
        impl<'a> From<::std::sync::PoisonError<$l<'a, $t>>> for RatchetError {
            fn from(_: ::std::sync::PoisonError<$l<'a, $t>>) -> RatchetError {
                // _.get_mut()
                RatchetError::PoisonError(stringify!($l),stringify!($t))
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


