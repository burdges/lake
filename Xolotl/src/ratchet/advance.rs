// Copyright 2016 Jeffrey Burdges 

//! Advance transaction for Xolotl ratchet

use std::collections::{HashMap,HashSet};
use std::sync::Arc; // RwLock, RwLockReadGuard, RwLockWriteGuard
use std::ops::Deref; // DerefMut

use super::branch::*;
use super::twig::*;
use super::error::*;

use super::state::*;
use super::super::state::*;


pub trait Transaction {
    /// Access Xolotl Branch and Twig state data.
    ///
    /// Immutably borrows ourselve so we must call `self.state()`
    /// each time, and cannot write `let s = self.state()`.
    /// Trait fields might improve this :
    /// https://github.com/rust-lang/rfcs/pull/1546
    fn state(&self) -> &State;

    /// Confirm the transaction and commit all updates.
    /// Used when MAC check succeeds.  Only `create_initial_branch`
    /// and `confirm` should write to `State::{branchs,parents,twigs}`
    fn confirm(&mut self) -> Result<(),XolotlError>;

    /// Forget the inserted elements without caching them for future updates.
    /// Used when creating SURBs, which must identify themselves to us.
    fn forget(&mut self);

    /// Abandon this transaction but cache any cryptographic computations
    /// for future updates.  Used when MAC check fails, including Drop.
    fn abandon(&mut self) -> Result<(),XolotlError>;
}

/// A transaction for an attempt to advance our hash iteration ratchet.
/// All real writes to state occur in `Transaction::confirm` although 
/// cache manipulation occurs in `Drop::drop` as well.
pub struct Advance {
    /// Locked Branch identifier together with Xolotl Branch and Twig state data.
    pub branch_id: BranchIdGuard,

    /// Our local copy of the branch data
    pub branch: Branch,

    /// Branch itself needs insertion, record it's starting train key
    insert_branch: Option<TwigIS>,

    /// Keys to insert upon confirmation
    inserts: Vec<TwigIS>,
}

impl Transaction for Advance {
    /// Use `self.branch_id.0` directly if this conflicts with borrow checker.
    fn state(&self) -> &State {
        self.branch_id.0.deref()
    }

    fn confirm(&mut self) -> Result<(),XolotlError> {
        let mut berry: Option<TwigId> = None;

        if self.inserts.len() == 0 { return Ok(()); }
        if self.insert_branch.is_none() {
            // Add branch data
            let mut branches = self.state().branches.write() ?; //  PoisonError
            branches.insert(*self.branch_id.id(), self.branch.clone());

            // Add parents link from children's family name to our branch_id
            let mut parents = self.state().parents.write() ?; // PoisonError
            parents.insert(self.branch.child_family_name(), *self.branch_id.id());

            // Identify the berry from which we grew
            let parent_bid: BranchId = self.state()
              .parent_id(self.branch_id.family()) ?;  // PoisonError, MissingParent
            berry = Some( TwigId(parent_bid, self.branch_id.berry()) );
        }

        let mut twigs = self.branch_id.0.twigs.write() ?; // PoisonError

        // Erase the berry from which we grew
        let _ = berry.map(|b| twigs.remove(&b));

        // Do the transaction's iserts
        for TwigIS(idx,tk) in self.inserts.drain(..) {
            twigs.insert(TwigId(*self.branch_id.id(),idx), tk.data());
        }
        Ok(())
    }

    fn forget(&mut self) {
        //! We leave insert_branch possibly set, so that the object remains valid,
        //! but the branch must not be updated unless inserts occur.
        if self.inserts.len() != 0 {  self.inserts.clear();  }
    }

    fn abandon(&mut self) -> Result<(),XolotlError> {
        if self.inserts.len() == 0 { return Ok(()); }
        let mut inserts0 = ::std::mem::replace(&mut self.inserts, Vec::new());
        let inserts = inserts0.drain(..).map( |TwigIS(idx,tk)| (idx,tk) );

        // let insert_branch = self.insert_branch.map(|| Some(self.branch));
        let mut cached = self.state().cached.write() ?; //  PoisonError
        if let Some( &mut AdvanceFailValue {
            branch: ref mut c_branch,
            insert_branch: ref mut c_insert_branch,
            inserts: ref mut hm
          } ) = cached.get_mut(self.branch_id.id()) {

            let s: &'static str = match (self.insert_branch.is_some(),c_insert_branch.is_some()) {
                (false,false) => "in abandon() when inserting from neither self nor cache",
                (true,false) => panic!("Branch lost from cached"),
                (false,true) => "in abandon() when inserting from cache",
                (true,true) => "in abandon() when inserting ???",
            };
            if self.branch.extra != c_branch.extra {  // constant time
                return Err(XolotlError::CorruptBranch(*self.branch_id.id(), s));
            }

            // FIXME Not Good !!!
            c_branch.chain = self.branch.chain;

            hm.reserve(self.inserts.len());
            hm.extend(inserts);
            // Sadly extend does not call reserve with size information, 
            // making it equivelent to:
            // for TwigIS(idx,tk) in self.inserts.drain(..) {
            //    hm.insert(idx,tk);
            // }

            return Ok(());
        }

        let hm: HashMap<TwigIdx,TwigState> = inserts.collect();
        // In fact collect() does handle length correctly,
        // making it equivelent to:
        // let hm = HashMap::<TwigIdx,TwigState>::with_capacity(self.inserts.len());
        // hm.extend(self.inserts.drain(..));

        cached.insert(*self.branch_id.id(), AdvanceFailValue {
            branch: self.branch.clone(),
            insert_branch: self.insert_branch.clone(),
            inserts: hm
        } );

        Ok(())
    }
}

impl Drop for Advance {
    fn drop(&mut self) {
        let err = match self.abandon() { 
            Err(e) => e.clone(),  // Only place XolotlError gets cloned?
            Ok(()) => return,
        };

        let mut ade = self.state().advance_drop_errors.write().unwrap(); // Panic on PoisonError
        ade.push(err);
        // ::std::mem::drop(self.branch_id);
    }
}

impl Advance {
    /// Begin a transaction to advance the ratchet on the branch `bid`.
    pub fn new(state: &Arc<State>, bid: BranchId)
      -> Result<Advance,XolotlError> {

        // We found passing in branch_id required an unecessary call to clone
        let branch_id = lock_branch_id(state,bid) ?;

        let branches = state.branches.read() ?;  // PoisonError

        if let Some(br) = branches.get(branch_id.id()) {
            return Ok(Advance {
                branch: br.clone(),
                branch_id: branch_id,
                insert_branch: None,
                inserts: Vec::new(), // zero capasity, no allocation
            })
        }

        /* branch_id.state() */
        let parent_bid = state.parent_id(branch_id.family()) ?;
          // PoisonError, MissingParentBranch
        let parent = if let Some(p) = branches.get(&parent_bid) { p.clone() } else {
            return Err(XolotlError::MissingBranch(parent_bid));
        };
        
        // Avoid holding branches read lock during crypto.  
        // We could do this lexically perhaps, but this should work fine.
        ::std::mem::drop(branches);

        let tid = TwigId(parent_bid, branch_id.berry());
        let berrykey: BerryKey = branch_id.get_twigy(&tid) ?;
          // PoisonError, MissingTwig, WrongTwigType

        let (child_bid,branch,tk) = parent.kdf_branch(branch_id.berry(), &berrykey);
        if child_bid != *branch_id.id() {
            // The parent's table entry or extra key looks corrupted.
            return Err(XolotlError::CorruptBranch(parent_bid,"as parent"));
        }
        Ok(Advance {
            branch_id: branch_id,
            branch: branch,
            insert_branch: Some(TwigIS(TRAIN_START,TwigState::Train(tk))),
            inserts: Vec::new(), // zero capasity, no allocation
        })
    }

    /// Retrieve an unspecified twig type using `BranchIdGuard::get_twig(...)`
    fn get_twig(&self, idx: TwigIdx) -> Result<TwigState,XolotlError> {
        let tid = TwigId(*self.branch_id.id(), idx);
        self.branch_id.get_twig(&tid)
    }

    /// Retrieve a specific twig type using `BranchIdGuard::get_twigy(...)`
    fn get_twigy<T: Twigy>(&self, idx: TwigIdx) -> Result<T,XolotlError> {
        let tid = TwigId(*self.branch_id.id(), idx);
        self.branch_id.get_twigy(&tid)
    }

    /// Add a twig to an advance transaction's insert queue.
    fn insert_twig<T>(&mut self, idx: TwigIdx, t: T) 
      where /* T: Twigy, */ TwigState: From<T> {
        self.inserts.push( TwigIS(idx,t.into()) );
    }

}


/*

impl Advance {

    fn do_chain_step(&mut self, idx: TwigIdx) -> R<LinkKey> {
        let linkkey: LinkKey;

        let sk = match self.branch_id.get_twig(idx) ?;

fetch_key(idx) {
            None => return Err(KeyNotFound),
            Some(x) => x
        };
        if stashed_key.dump() == Default::default() {
            stashed_key = sk;
        }

        let (i,j) = idx.split();
        if j==0 /* idx.is_pure_train() */ {

            let tk = match sk {
                Train(tk) => tk,
                Chain(_) => return Err(UnexpectedChain),
                Link(lk) => return Some(lk),  // FIXME Questionable
                Berry(_) => return Err(UnexpectedBerry);
            }

            let x,y,z;
            (x,y,z,linkkey) = self.branch.kdf_train(idx,tk);
            if let Some(a,b) = TwigIdx::train_children(j) {
                self.add_key(TwigIdx::make(a,0),x);
                self.add_key(TwigIdx::make(b,0),y);
            } // Not addressable otherwise so no error needed

            if let Some(next) = idx.increment() {
                self.add_key(next,z);
            }

        } else {

            let ck = match sk {
                Train(_) => return Err(UnexpectedTrain),
                Chain(ck) => ck,
                Link(lk) => return Some(lk),  // FIXME Questionable
                Berry(_) => return Err(UnexpectedBerry);
            }

            let z;
            (z,linkkey) = self.branch.kdf_chain(idx,ck);
            if let Some(next) = idx.increment() && ! next.is_pure_train() {
                self.add_key(next,z);
            }

        }

        self.add_key(idx,linkkey);
        if let Some(next) = idx.increment() && next > self.branch.chain {
            self.branch.chain = next;
        }
        Some(linkkey)
    }

    fn done_known_link(&mut self, idx: TwigIdx, linkkey: LinkKey, s: SphinxSecret)
            -> R<MessageKey> {
        let (messagekey,berrykey) = self.branch.kdf_berry(linkkey,s);
        self.add_key(idx,berrykey);
        Some(messagekey)
    }

    fn done_fetched_link(&self, idx: TwigIdx, s: SphinxSecret) -> R<MessageKey> {
        let sk = match self.fetch_key(idx) {
            None => return Err(KeyNotFound),
            Some(sk) => sk
        };
        match sk {
            Train(tk) => Err(UnexpectedTrain),  // FIXME Recover?
            Chain(ck) => Err(UnexpectedChain),  // FIXME Recover?
            Link(linkkey) => self.done_known_link(idx,linkkey,s),
            Berry(_) => Err(UnexpectedBerry);
        }
    }
}
*/


/* 

pub struct AdvanceTwigUser(AdvanceTwig);

impl AdvanceTwigUser {
    pub fn click(&self, s: SphinxSecret) -> R<MessageKey> {
        let ci = self.0.branch.chain;
        let linkkey = try!(self.0.do_chain_step(ci));
        self.0.done_known_link(ci,linkkey,s)
    }
}


pub struct AdvanceTwigNode(AdvanceTwig);

impl AdvanceTwigNode {
    fn clicks_chain_only(&self, s: SphinxSecret, cidx,tidx: TwigIdx) -> R<MessageKey> {
        debug_assert!(tidx.split().0 == cidx.split().0);
        let linkkey: LinkKey;
        if cidx > tidx {
            return self.0.done_fetched_link(tidx,s);
        }
        self.0.inserts.reserve(tidx.0-cidx.0+2);
        for ii in cidx.0 .. tidx.0+1 {
            linkkey = try!(self.0.do_chain_step( TwigIdx(ii) ));
            // It's safer to call  self.0.add_key(idx,linkkey);
            // in do_chain_step() rather than usng complex loop
            // structure to avert one extra write here.
        }
        // we effectively have cidx==tidx+1 now.
        self.done_known_link(tidx,linkkey,s)
    }

    fn clicks(&self, s: SphinxSecret, target: TwigIdx ) -> R<MessageKey> {
        let (ti,_) = target.split();
        let cidx = self.0.branch.chain;
        let (ci,_) = cidx.split();

        if ti == ci {
            return self.clicks_chain_only(s,cidx,target);
        }

        let mut (i,j) = (ti,0);
        while i>0 {
            match self.0.fetch_key(TwigIdx::make(i,0)) {
                None => i = TwigIdx::train_parent(i),
                Some(Train(_)) => break,
                Some(Chain(_)) => return Err(UnexpectedChain),
                Some(Link(_)) => return Err(UnexpectedLink),
                Some(Berry(_)) => return Err(UnexpectedBerry),
            }
            j++;
        }
        self.0.inserts.reserve(3*j+1);
        while j>=0 {
            i = ti >> j;  // Iterate TwigIdx::train_parent j times.
            try!(self.0.do_chain_step( TwigIdx::make(i,0) ));
            j--;
        }
        self.clicks_chain_only(s,TwigIdx::make(i,0),target)
    }
}

*/

