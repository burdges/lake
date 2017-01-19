// Copyright 2016 Jeffrey Burdges.

//! Xolotl ratchet variation on Sphinx mixnet
//! 
//! <code>git clone https://..</code>
//! 
//! ...

// TODO Remove this !!!
#![allow(dead_code)]

#![feature(core_intrinsics)]
#![feature(associated_consts)]

// #![doc(html_root_url="...")]

// Sphinx could be built on only core, but Xolotl needs allocation.
// extern crate core;  

extern crate rustc_serialize;

extern crate rand;
extern crate crypto;
extern crate consistenttime;

extern crate siphasher;  // better than #![feature(sip_hash_13)]

#[macro_use]
extern crate arrayref;

// extern crate zerodrop;
// type Secret<T> = zerodrop::ZeroDrop<T>;

/// Code marker for stack variables that should be zeroed when dropped.
/// In fact stack variables cannot be zeroed safely, so this does
/// nothing for now.
/// See https://github.com/rust-lang/rfcs/issues/1853
// type StackSecret<T> = T;

extern crate clear_on_drop;
type ClearedBox<T> = clear_on_drop::ClearOnDrop<T, Box<T>>;

#[macro_use]
mod macros;

mod state;
mod ratchet;
mod sphinx;



// pub use self::...;
// use self::...;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}


