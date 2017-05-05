// Copyright 2016 Jeffrey Burdges.

//! Xolotl DH ratchet state storage
//!
//! ...

use std::collections::{HashMap,HashSet};
use std::sync::{RwLock}; // RwLockReadGuard, RwLockWriteGuard
use std::ops::{Deref,DerefMut};
// use std::hash::{Hash, Hasher};


use super::branch::*;
use super::twig::*;
use super::error::*;
use ::state::*;


pub type TwigStorage = HashMapStorage<TwigId,TwigKey>;
pub type BranchStorage = HashMapStorage<BranchId,Branch>;
pub type ParentStorage = HashMapStorage<BranchName,BranchId>;

pub type BranchLocks = HashSet<BranchId>;


/// The value site of a cached record of a failed advance transaction,
/// excludes the BranchId which acts as a key.
#[derive(Debug)] // Clone
pub struct AdvanceFailValue {
    /// Copy of the branch data in case it does not exist in the table
    pub branch: Branch,

    /// Branch itself needs insertion, record it's starting train key
    pub insert_branch: Option<TwigIS>,

    /// Keys to insert upon confirmation
    pub inserts: HashMap<TwigIdx,TwigState>,
}

/// A cache for of failed advance transactions.
pub type AdvanceFailCache = HashMap<BranchId,AdvanceFailValue>;

pub type AdvanceDropErrors = Vec<RatchetError>;

#[derive(Debug)]
pub struct State {
    /// Branch storage tabel, saved to disk.
    pub branches: RwLock<BranchStorage>,

    /// Branch parent mapping storage tabel, saved to disk.
    pub parents: RwLock<ParentStorage>,

    /// Twig storage tabel, saved to disk.
    pub twigs: RwLock<TwigStorage>,

    /// Set of locked branches, not saved to disk.
    pub locked: RwLock< BranchLocks >,

    /// Cache for ratchet advancements that fail authentication.
    /// Just an anti-DoS measure, not saved to disk.
    pub cached: RwLock< AdvanceFailCache >,

    /// Errors encountered when dropping Advance
    pub advance_drop_errors: RwLock<AdvanceDropErrors>
}

impl State {
    /// Identify a branch's parent branch.
    pub fn parent_id(&self, family: BranchName) -> RatchetResult<BranchId> {
        let parents = self.parents.read() ?; // PoisonError
        if let Some(parent_bid) = parents.get(&family) {
            Ok(*parent_bid)
        } else {
            Err(RatchetError::MissingParent(family))
        }
    }
}

/// Create a locked branch identifier.
pub fn lock_branch_id<'a>(state: &'a State, bid: &BranchId) -> RatchetResult<BranchIdGuard<'a>> {
    let mut locked = state.locked.write() ?; // PoisonError
    if locked.insert(*bid) {
        Ok( BranchIdGuard( state, *bid ) )
    } else {
        Err(RatchetError::BranchAlreadyLocked(*bid))
    }
}

/// RAII lock for a branch identifier.
#[derive(Debug, Clone)]
pub struct BranchIdGuard<'a>(pub &'a State, pub BranchId);

impl<'a> Drop for BranchIdGuard<'a> {
    /// Unlock a branch identifier.
    fn drop(&mut self) {
        let mut err = self.0.advance_drop_errors.write().unwrap(); // Panic on PoisonError
        match self.0.locked.write() {
            Ok(mut l) => { l.deref_mut().remove(self.id()); },
            Err(e) => { err.push(e.into()); }
        }
    }
}

impl<'a> BranchIdGuard<'a> {
    pub fn state(&self) -> &State { self.0.deref() }
    pub fn id(&self)-> &BranchId { &self.1 }
    pub fn family(&self) -> BranchName { self.id().family }
    pub fn berry(&self) -> TwigIdx { self.id().berry }

    /// Retrieve unspecified twig type.  Throw MissingTwig error if
    /// not found.  Avoids holding twigs read lock.
    pub fn get_twig(&self, tid: &TwigId) -> RatchetResult<TwigState> {
        let twigs = self.state().twigs.read() ?;  // PoisonError
        if let Some(tk) = twigs.get(tid) {
            Ok( TwigState::new(*tk) )
        } else {
            Err( RatchetError::MissingTwig(*tid) )
        }
    }

    /// Retrieve a specific twig type.  Throw error `MissingTwig` if
    /// not found or `WrongTwigType` error if type does not match.
    /// Avoids holding twigs read lock.
    pub fn get_twigy<T: Twigy>(&self, tid: &TwigId) -> RatchetResult<T> {
        let twigs = self.state().twigs.read() ?;  // PoisonError
        if let Some(x) = twigs.get(tid) {
            verify_twigy::<T>(tid,x)
        } else {
            Err( RatchetError::MissingTwig(*tid) )
        }
    }
}


/// Create an branch from a messaging layer post-quantum key exchange,
/// so no transaction necessary. Only `create_initial_branch` and
/// `Transaction::confirm` should write to `State::{branchs,parents,twigs}`
pub fn create_initial_branch(state: &State, seed: &[u8])
  -> RatchetResult<(BranchId,Branch,TwigId,TrainKey)> {
    let (bid, branch, tk): (BranchId, Branch, TrainKey) = Branch::new_kdf(seed);
    let tid = TwigId(bid,TRAIN_START);

    let branch_id = lock_branch_id(state,&bid) ?;  // PoisonError, BranchAlreadyLocked

    // FIXME How do we ensure these write locks do not persist beyond
    //   their lines?  logging?
    let mut branches = state.branches.write() ?;  // PoisonError
    let bs: &mut BranchStorage = branches.deref_mut();  
    bs.insert(bid, branch.clone());
    let mut parents = state.parents.write() ?;  // PoisonError
    let ps: &mut ParentStorage = parents.deref_mut();  
    ps.insert(branch.child_family_name(), bid);
    let mut twigs = state.twigs.write() ?;  // PoisonError
    let ts: &mut TwigStorage = twigs.deref_mut();  
    ts.insert(tid, tk.0);

    // FIXME How do we ensure branch_id lives this long?  logging?
    ::std::mem::drop(branch_id);

    Ok((bid, branch, tid, tk))
}



/// TODO:
/// - Abstract keys from the sphinx module
pub type ClientState = HashMap<::sphinx::keys::IssuerPublicKey,State>;


#[cfg(test)]
mod tests {
    // use super::*;
    // use rustc_serialize::hex::ToHex;

    #[test]
    fn need_tests() {
    }
}




