// Copyright 2016 Jeffrey Burdges.

//! Xolotl ratchet variation on Sphinx mixnet
//! 
//! <code>git clone https://..</code>
//! 
//! ...

#![feature(associated_consts)]

// #![doc(html_root_url="...")]

// Sphinx could be built on only core, but Xolotl needs allocation.
// extern crate core;  

extern crate rand;
extern crate crypto;
extern crate consistenttime;

// #![feature(sip_hash_13)]
extern crate siphasher;

#[macro_use]
extern crate arrayref;

mod state;
mod ratchet;
mod sphinx;


// TODO: Write flexible macro for tuple structs.
macro_rules! impl_Display_as_hex_for_WrapperStruct {
    ($t:ident) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, concat!(stringify!($t), "({:x})"), self.0)
            }
        }
    }
}


// pub use self::...;
// use self::...;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}


