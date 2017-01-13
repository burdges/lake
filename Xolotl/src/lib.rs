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

// #![feature(sip_hash_13)]
extern crate siphasher;

extern crate zerodrop;
type Secret<T> = zerodrop::ZeroDrop<T>;

#[macro_use]
extern crate arrayref;

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


