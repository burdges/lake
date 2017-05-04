// Copyright 2016 Jeffrey Burdges 

//! Advance transaction for Xolotl ratchet

use std::collections::HashMap; // HashSet
use std::sync::Arc; // RwLock, RwLockReadGuard, RwLockWriteGuard
use std::ops::Deref; // DerefMut

use super::MessageKey;
use ::sphinx::SphinxSecret;
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
    fn confirm(&mut self) -> RatchetResult<()>;

    /// Forget the inserted elements without caching them for future updates.
    /// Used when creating SURBs, which must identify themselves to us.
    fn forget(&mut self);

    /// Abandon this transaction but cache any cryptographic computations
    /// for future updates.  Used when MAC check fails, including Drop.
    fn abandon(&mut self) -> RatchetResult<()>;
}

/// A transaction for attempts to advance our hash iteration ratchet.
///
/// All writes to state occur in `Transaction::confirm` although cache
/// manipulation occurs in `Drop::drop` as well.
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
    fn state(&self) -> &State {
        //! Use `self.branch_id.0` directly if this conflicts with borrow checker.
        self.branch_id.0.deref()
    }

    fn confirm(&mut self) -> RatchetResult<()> {
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

    fn abandon(&mut self) -> RatchetResult<()> {
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
                return Err(RatchetError::CorruptBranch(*self.branch_id.id(), s));
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
            Err(e) => e,
            Ok(()) => return,
        };

        let mut ade = self.state().advance_drop_errors.write().unwrap(); // Panic on PoisonError
        ade.push(err);
        // ::std::mem::drop(self.branch_id);
    }
}

impl Advance {
    /// Begin a transaction to advance the ratchet on the branch `bid`.
    ///
    /// Remove Arc<> since we do not need it at this level
    pub fn new(state: &Arc<State>, bid: &BranchId) -> RatchetResult<Advance> {

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
          // PoisonError, MissingParent
        let parent = if let Some(p) = branches.get(&parent_bid) { p.clone() } else {
            return Err(RatchetError::MissingBranch(parent_bid));
        };
        
        // Avoid holding branches read lock during crypto.  
        // We could do this lexically perhaps, but this should work fine.
        // We still need to verify that however:
        // https://stackoverflow.com/questions/41560442/is-there-any-safe-way-to-ensure-an-arbitrary-drop-happens-before-some-expensive
        ::std::mem::drop(branches);

        let tid = TwigId(parent_bid, branch_id.berry());
        let berrykey: BerryKey = branch_id.get_twigy(&tid) ?;
          // PoisonError, MissingTwig, WrongTwigType

        let (child_bid,branch,tk) = parent.kdf_branch(branch_id.berry(), &berrykey);
        if child_bid != *branch_id.id() {
            // The parent's table entry or extra key looks corrupted.
            return Err(RatchetError::CorruptBranch(parent_bid,"as parent"));
        }
        Ok(Advance {
            branch_id: branch_id,
            branch: branch,
            insert_branch: Some(TwigIS(TRAIN_START,TwigState::Train(tk))),
            inserts: Vec::new(), // zero capasity, no allocation
        })
    }

    /// Retrieve an unspecified twig type using `BranchIdGuard::get_twig(...)`
    fn get_twig(&self, idx: TwigIdx) -> RatchetResult<TwigState> {
        let tid = TwigId(*self.branch_id.id(), idx);
        self.branch_id.get_twig(&tid)
    }

    /// Retrieve a specific twig type using `BranchIdGuard::get_twigy(...)`
    fn get_twigy<T: Twigy>(&self, idx: TwigIdx) -> RatchetResult<T> {
        let tid = TwigId(*self.branch_id.id(), idx);
        self.branch_id.get_twigy(&tid)
    }

    /// Add a twig to an advance transaction's insert queue.
    fn insert_twig<T>(&mut self, idx: TwigIdx, t: T) 
      where /* T: Twigy, */ TwigState: From<T> {
        self.inserts.push( TwigIS(idx,t.into()) );
    }

    fn verify_twigy<T: Twigy>(&self, idx: TwigIdx, twigkey: &TwigKey) -> RatchetResult<T> {
        let tid = TwigId(*self.branch_id.id(), idx);
        verify_twigy::<T>(&tid, twigkey)
    }

    fn verify_twigstate<T: Twigy>(&self, idx: TwigIdx, twigstate: &TwigState)
      -> RatchetResult<T> {
        // TODO Remove enum from TwigState
        /* assert_eq!(T::KEYTYPE, match *twigstate { 
            TwigState::Train(_) => <TrainKey as Twigy>::KEYTYPE,
            TwigState::Chain(_) => <ChainKey as Twigy>::KEYTYPE,
            TwigState::Link(_)  => <LinkKey as Twigy>::KEYTYPE,
            TwigState::Berry(_) => <BerryKey as Twigy>::KEYTYPE,
        } ); */
        // TODO Refactor to avoid this clone
        self.verify_twigy::<T>(idx, &twigstate.clone().data())
    }

    fn do_chain_step(&mut self, idx: TwigIdx) -> RatchetResult<LinkKey> {
        let twig = self.get_twig(idx) ?; // ???
          // PoisonError, MissingTwig
        if let TwigState::Link(lk) = twig { return Ok(lk); }  // FIXME Questionable

        let linkkey: LinkKey;

        let (_i,j) = idx.split();
        if j==0 /* idx.is_pure_train() */ {

            let trainkey = self.verify_twigstate::<TrainKey>(idx, &twig) ?;

            let (x,y,z,lk) = self.branch.kdf_train(idx,&trainkey);
            linkkey = lk;
            if let Some((a,b)) = TwigIdx::train_children(j) {
                self.insert_twig(TwigIdx::make(a,0), x);
                self.insert_twig(TwigIdx::make(b,0), y);
            } // Not addressable otherwise so no error needed

            if let Some(next) = idx.increment() {
                self.insert_twig(next,z);
            }

        } else {

            let chainkey = self.verify_twigstate::<ChainKey>(idx, &twig) ?;

            let (z,lk) = self.branch.kdf_chain(idx,&chainkey);
            linkkey = lk;
            if let Some(next) = idx.increment() { if ! next.is_pure_train() {
                self.insert_twig(next,z);
            } }

        }

        self.insert_twig(idx,linkkey.clone());
        if let Some(next) = idx.increment() { if next > self.branch.chain {
                self.branch.chain = next;
        } }
        Ok(linkkey)
    }

    fn done_known_link(&mut self, idx: TwigIdx, linkkey: &LinkKey, ss: &SphinxSecret)
      -> RatchetResult<MessageKey> {
        let (messagekey,berrykey) = self.branch_id.id().kdf_berry(linkkey,ss);
        self.insert_twig(idx, berrykey);
        Ok(messagekey)
    }

    fn done_fetched_link(&mut self, idx: TwigIdx, ss: &SphinxSecret)
      -> RatchetResult<MessageKey> {
        let linkkey: LinkKey = self.get_twigy::<LinkKey>(idx) ?; 
          // PoisonError, MissingTwig, WrongTwigType
        self.done_known_link(idx,&linkkey,ss)
    }
}


/// A transaction for a user iterating their hash iteration ratchet
/// by a single step.
///
/// All writes to state occur in `Transaction::confirm` although cache
/// manipulation occurs in `Drop::drop` as well.
pub struct AdvanceUser(Advance);

impl Transaction for AdvanceUser {
    fn state(&self) -> &State
      { self.0.state() }
    fn confirm(&mut self) -> RatchetResult<()>
      { self.0.confirm() }
    fn forget(&mut self)
      { self.0.forget() }
    fn abandon(&mut self) -> RatchetResult<()>
      { self.0.abandon() }
}

impl AdvanceUser {
    pub fn new(state: &Arc<State>, bid: &BranchId)
      -> RatchetResult<AdvanceUser> {
        Ok( AdvanceUser(Advance::new(state,bid) ?) )
    }

    pub fn click(&mut self, ss: &SphinxSecret) 
      -> RatchetResult<(TwigId,MessageKey)> {
        let cidx = self.0.branch.chain;
        let linkkey = self.0.do_chain_step(cidx) ?;
          // .. PoisonError, MissingTwig, WrongTwigType .. ??
        let twig = TwigId(self.0.branch_id.1, cidx);
        Ok(( twig, self.0.done_known_link(cidx,&linkkey,ss) ? ))
    }
}


/// A transaction for a mix node iterating a hash iteration ratchet
/// as directed by a Sphinx packet.
///
/// All writes to state occur in `Transaction::confirm` although cache
/// manipulation occurs in `Drop::drop` as well.
pub struct AdvanceNode(Advance);

impl Transaction for AdvanceNode {
    fn state(&self) -> &State
      { self.0.state() }
    fn confirm(&mut self) -> RatchetResult<()>
      { self.0.confirm() }
    fn forget(&mut self)
      { self.0.forget() }
    fn abandon(&mut self) -> RatchetResult<()>
      { self.0.abandon() }
}

impl AdvanceNode {
    pub fn new(state: &Arc<State>, bid: &BranchId)
      -> RatchetResult<AdvanceNode> {
        Ok( AdvanceNode(Advance::new(state,bid) ?) )
    }

    /// 
    fn clicks_chain_only(&mut self, ss: &SphinxSecret, cidx: TwigIdx,tidx: TwigIdx)
      -> RatchetResult<MessageKey> {
        debug_assert!(tidx.split().0 == cidx.split().0);
        let mut linkkey = LinkKey(Default::default());
        // Assign a range to try to show that linkkey gets initialized.
        let r = cidx.0 .. tidx.0+1;
        if r.len()==0 /* or r.is_empty() or cidx > tidx */ {
            return self.0.done_fetched_link(tidx,ss);
        }
        self.0.inserts.reserve(r.len() + 1);
        for ii in r {
            linkkey = self.0.do_chain_step( TwigIdx(ii) ) ?;
            // Always runs at least once, so linkkey cannot remain `Default::default()`.
            // It's safer to call  self.0.insert_twig(idx,linkkey);
            // in do_chain_step() rather than usng complex loop
            // structure to avert one extra write here.
        }
        // we effectively have cidx==tidx+1 now.
        self.0.done_known_link(tidx,&linkkey,ss)
    }

    ///
    pub fn clicks(&mut self, ss: &SphinxSecret, target: TwigIdx )
      -> RatchetResult<MessageKey> {
        let (ti,_) = target.split();
        let cidx = self.0.branch.chain;
        let (ci,_) = cidx.split();

        if ti == ci {
            return self.clicks_chain_only(ss,cidx,target);
        }

        let mut i = ti;
        let mut j: i16 = 0;
        while i>0 {
            let idx = TwigIdx::make(i,0);
            match self.0.get_twig(idx) {
                Ok(TwigState::Train(_)) => break,  // Train key found :)
                Err( RatchetError::MissingTwig(_) ) => {
                    // Not found, progress to parent train key index 
                    if let Some(ii) = TwigIdx::train_parent(i) {
                        i = ii;
                    } else {
                        return Err( RatchetError::CorruptBranch(
                            *self.0.branch_id.id(), 
                            "lacks twig data."
                        ) );
                    }
                },
                    // Not found, progress to parent train key index 
                Ok(twig) => {
                    // Non-train key found, internal error.
                    self.0.verify_twigstate::<TrainKey>(idx, &twig) ?; 
                    unreachable!(); 
                },
                Err(e) => return Err(e),  // PoisonError
            };
            j += 1;
        }
        self.0.inserts.reserve((3*j+1) as usize);
        while j>=0 {
            i = ti >> j;  // Iterate TwigIdx::train_parent j times.
            self.0.do_chain_step( TwigIdx::make(i,0) ) ?;
            j -= 1;
        }
        self.clicks_chain_only(ss,TwigIdx::make(i,0),target)
    }

    pub fn single_click(state: &Arc<State>, ss: &SphinxSecret, tid: &TwigId)
      -> RatchetResult<(AdvanceNode,MessageKey)> {
        let TwigId(bid, idx) = *tid;
        let mut advance = AdvanceNode::new(state,&bid) ?;
        let message = advance.clicks(ss,idx) ?;
        Ok((advance,message))
    }
}


#[cfg(test)]
mod tests {
    // use super::*;
    // use rustc_serialize::hex::ToHex;

    #[test]
    fn need_tests() {
    }
}




