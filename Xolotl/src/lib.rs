// Copyright 2016 Jeffrey Burdges.

//! Xolotl ratchet variation on Sphinx mixnet
//! 
//! <code>git clone https://..</code>
//! 
//! ...

// TODO Remove this !!!
#![allow(dead_code)]

// #![feature(conservative_impl_trait)]
#![feature(core_intrinsics)] // Remove with ClearOnDrop

#![feature(step_by)]
#![feature(box_syntax)]
#![feature(associated_consts)]

// #![doc(html_root_url="...")]

// Sphinx could be built on only core, but Xolotl needs allocation.
// extern crate core;  

#[macro_use]
extern crate arrayref;

extern crate rustc_serialize;

extern crate siphasher;  // better than #![feature(sip_hash_13)]

extern crate rand;
extern crate consistenttime;
extern crate clear_on_drop;
type ClearedBox<T> = clear_on_drop::ClearOnDrop<Box<T>>;

extern crate curve25519_dalek;
extern crate ed25519_dalek;
extern crate keystream;
extern crate chacha;
extern crate lioness;

extern crate crypto;  //  SHA3, Poly1305, checking curve25519_dalek


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


