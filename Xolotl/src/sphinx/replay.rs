// Copyright 2016 Jeffrey Burdges.

//! Sphinx state storage
//!
//! ...

use std::collections::HashSet;
use std::sync::RwLock;
// use std::sync::{Arc, RwLock}; // RwLockReadGuard, RwLockWriteGuard
// use std::ops::{Deref,DerefMut};
// use std::hash::{Hash, Hasher};
use std::fmt;

use super::error::*;
use ::state::*;


/// Replay code used both for replay protection and when reporting errors.
#[derive(Clone,Copy,Default,PartialEq,Eq,Hash)]
pub struct ReplayCode(pub [u8; 16]);
pub const REPLAY_CODE_UNKNOWN : ReplayCode = ReplayCode([0u8; 16]);

/// Use hexidecimal when displaying `ReplayCode` in error messages.
impl fmt::Debug for ReplayCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use rustc_serialize::hex::ToHex;
        write!(f, "ReplayCode({:})", self.0.to_hex())
    }
}


/// Replay attack detection table
pub trait ReplayChecker {
    /// Replay detection logic.
    ///
    /// Attempts to insert `replay_code` into the replay table,
    /// If `replay_code` is already present, then error with
    /// `SphinxError::Replay(replay_code)`.  If `replay_code` is
    /// not present, then insert it and return `Ok`.
    ///
    /// We use a by-value reciever as a cheap way to abstract over
    /// the mutability differences of `&mut R` vs `&RwLock<R>`.
    fn replay_check(self, replay_code: &ReplayCode) -> Result<(),SphinxError>;
}

/// Non-functional replay filter for Sphinx packet and SURB creation.
pub struct IgnoreReplays;

impl ReplayChecker for IgnoreReplays {
    fn replay_check(self, replay_code: &ReplayCode) -> Result<(),SphinxError> {
        let _ = self;  let _ = replay_code;  Ok(())
    }
}

impl<'r,R> ReplayChecker for &'r mut R where R: Filter<Key=ReplayCode> + 'r {
    /// Replay detection logic for a `Filter<Key=ReplayCode>`.
    fn replay_check(self, replay_code: &ReplayCode) -> Result<(),SphinxError> {
        // if ! ::consistenttime::ct_eq_slice(&replay_code.0, &REPLAY_CODE_UNKNOWN.0) {
        //     Err( SphinxError::InternalError("Replay Code Unknown !!") )
        // } else 
        if self.insert(*replay_code) {  // opposite of replays.contains(replay_code)
            Ok(())
        } else { 
            Err( SphinxError::Replay(*replay_code) )
        }
    }
}

impl<'l,R> ReplayChecker for &'l RwLock<R> where for <'r> &'r mut R: ReplayChecker {
    /// Replay detection logic layer for `RwLock`
    fn replay_check(self, replay_code: &ReplayCode) -> Result<(),SphinxError> {
        // We just log and ignore PoisonError here for now because
        // (a) we imagine that the routine that saves the replay table
        // should use only readers and thus cannot poison even if
        // it panics, and (b) the routine that loads the replay table
        // must complete before passing it to threads.
        let mut replays = self.write().unwrap_or_else(|x| {
            // TODO Log PoisonError
            x.into_inner()
        });
        replays.replay_check(replay_code)
    }
}

// pub type trait ReplayFilter = Filter<Key = ReplayCode>;

pub struct State {

}

//         let mut replay = state.replay.write() ?; // PoisonError
