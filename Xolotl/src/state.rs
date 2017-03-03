// Copyright 2016 Jeffrey Burdges.

//! Storage for Xolotl ratchet
//!
//! ...

use std::borrow::Borrow;
use std::collections::{HashMap,HashSet};
use std::hash::{Hash, Hasher, BuildHasher};

use siphasher::sip::SipHasher24;
use rand::{self, Rng};


/// Sets our Hasher choice.  Also removes insecure `new()` methods.
#[derive(Debug)] // Clone, Copy
#[allow(deprecated)]
pub struct SecureHasher(SipHasher24);

impl Hasher for SecureHasher {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.write(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }
}


/// Initial state for our secure hashers
#[derive(Debug,Clone,Copy)]
pub struct HasherState(u64,u64);

impl HasherState {
    /// Constructs a new `HasherState` that is initialized with random keys.
    #[inline]
    pub fn new() -> HasherState {
        // use std::result::Result::expect;
        let r = rand::OsRng::new();
        let mut r = r.expect("failed to create an OS RNG");
        HasherState(r.gen(),r.gen())
    }

    // fn to_le(self) -> Self { HasherState(self.0.to_le(),self.0.to_le()) }
    // fn from_le(self) -> Self { HasherState(self.0.from_le(),self.0.from_le()) }
}

impl BuildHasher for HasherState {
    type Hasher = SecureHasher;

    #[inline]
    fn build_hasher(&self) -> SecureHasher {
        #![allow(deprecated)]
        SecureHasher( SipHasher24::new_with_keys(self.0, self.1) )
    }
}


/// Key-value stores for Xolotl
///
/// We keep the method signature similar to HashMap, but provide
/// only methods needed generically for Xolotl ratchet unit tests.
pub trait Storage {
    type Key;
    type Value;

    fn new(hs: HasherState) -> Self;

    fn get<Q: ?Sized>(&self, k: &Q) -> Option<&Self::Value> 
        where Self::Key: Borrow<Q>, Q: Hash + Eq;

    fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut Self::Value> 
        where Self::Key: Borrow<Q>, Q: Hash + Eq;

    fn contains_key<Q: ?Sized>(&self, k: &Q) -> bool
        where Self::Key: Borrow<Q>, Q: Hash + Eq;

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Option<Self::Value>;

    fn remove<Q: ?Sized>(&mut self, value: &Q) -> Option<Self::Value>
        where Self::Key: Borrow<Q>, Q: Hash + Eq;
}

/// Rudementary `HashMap` based `Storage`
#[derive(Debug)] // Clone
pub struct HashMapStorage<K,V>(pub HashMap<K,V,HasherState>)
  where K: Hash+PartialEq+Eq;

impl<K,V> Storage for HashMapStorage<K,V> 
  where K: Eq + Hash {
    type Key = K;
    type Value = V;

    #[inline]
    fn new(hs: HasherState) -> HashMapStorage<K,V> {
        HashMapStorage(HashMap::with_hasher(hs))
    }

    #[inline]
    fn get<Q: ?Sized>(&self, k: &Q) -> Option<&V> 
        where K: Borrow<Q>, Q: Hash + Eq
        {  self.0.get(k)  }

    #[inline]
    fn get_mut<Q: ?Sized>(&mut self, k: &Q) -> Option<&mut V> 
        where K: Borrow<Q>, Q: Hash + Eq
        {  self.0.get_mut(k)  }

    #[inline]
    fn contains_key<Q: ?Sized>(&self, k: &Q) -> bool
        where K: Borrow<Q>, Q: Hash + Eq 
        {  self.0.contains_key(k)  }

    #[inline]
    fn insert(&mut self, key: K, value: V) -> Option<V> 
        {  self.0.insert(key,value)  }

    #[inline]
    fn remove<Q: ?Sized>(&mut self, value: &Q) -> Option<V>
        where K: Borrow<Q>, Q: Hash + Eq 
        {  self.0.remove(value) }
}


/*
pub struct CuckooStorage<K,V> {
}

impl<K,V> Storage for CuckooStorage<K,V>
  where K: Eq + Hash {
    type Key = K;
    type Value = V;
    ...
}
*/


/// Filter for Xolotl
///
/// We keep the method signature similar to HashSet, but provide
/// only methods needed generically for Sphinx unit tests.
pub trait Filter {
    type Key;

    fn new(hs: HasherState) -> Self;

    fn contains<Q: ?Sized>(&self, value: &Q) -> bool
        where Self::Key: Borrow<Q>, Q: Hash + Eq;

    fn insert(&mut self, value: Self::Key) -> bool;

    fn remove<Q: ?Sized>(&mut self, value: &Q) -> bool
        where Self::Key: Borrow<Q>, Q: Hash + Eq;
}

/// Rudementary `HashSet` based `Filter`
#[derive(Debug)] // Clone
pub struct HashSetFilter<K>(pub HashSet<K,HasherState>)
  where K: Hash+PartialEq+Eq;

impl<K> Filter for HashSetFilter<K> 
  where K: Eq + Hash {
    type Key = K;

    fn new(hs: HasherState) -> HashSetFilter<K> 
        {  HashSetFilter(HashSet::with_hasher(hs))  }

    #[inline]
    fn contains<Q: ?Sized>(&self, value: &Q) -> bool
        where K: Borrow<Q>, Q: Hash + Eq
        {  self.0.contains(value)  }

    #[inline]
    fn insert(&mut self, value: K) -> bool 
        {  self.0.insert(value)  }

    #[inline]
    fn remove<Q: ?Sized>(&mut self, value: &Q) -> bool
        where K: Borrow<Q>, Q: Hash + Eq 
        {  self.0.remove(value)  }
}


/*
pub struct CuckooFilter<K,V> {
}

impl<K> Filter for CuckooFilter<K>
  where K: Eq + Hash {
    type Key = K;
    ...
}
*/





#[cfg(test)]
mod tests {
    // use super::*;

}


