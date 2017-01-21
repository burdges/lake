// Copyright 2016 Jeffrey Burdges.

//! Sphinx state storage
//!
//! ...

use ::state::*;

/// 
#[derive(Debug,Clone,Copy,Default,PartialEq,Eq,Hash)]
pub struct ReplayCode(pub [u8; 16]);

// pub type trait ReplayFilter = Filter<Key = ReplayCode>;

pub struct State {

}

//         let mut replay = state.replay.write() ?; // PoisonError
