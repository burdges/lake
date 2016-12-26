// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...

/// Maximum number of Sphinx hops
pub const MAXHOPS: usize = 8;
/// Maximum number of Xolotl ratchet hops
pub const MAXHOPS: usize = 8;



use std::hash::Hash;

use crypto::digest::Digest;
// use crypto::hmac::Hmac;
use crypto::sha3::Sha3;



/// Sphinx node curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub NodeKey(pub [u8; 32]);

/// Secret supplied by the Diffie-Hellman key exchange in Sphinx. 
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SphinxSecret(pub [u8; 32]);


/// Sphinx packet curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Alpha(pub [u8; 32]);

/// Sphinx onion encrypted header
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Beta(pub [u8; ??]);

/// Sphinx poly1305 MAC
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub Gamma(pub [u8; 16]);


/*

fn mac()



fn kdf_sphinx(npk: NodeKey, alpha: Alpha, s: SphinxSecret)
        -> (MessageKey, LeafKey) {
    let mut r = [0u8; 32+16];
    debug_assert_eq!(::std::mem::size_of_val(&r),
      ::std::mem::size_of::<(MessageKey, LeafKey)>());
    // let mut r: (MessageKey, LeafKey) = Default::default();
    // debug_assert_eq!(mem::size_of_val(&r), 384/8);
    let mut sha = Sha3::sha3_384();

    sha.input_str( TIGER[4] );
    sha.input(&iter.name.0);
    sha.input(&linkkey.0);
    sha.input_str( TIGER[5] );
    sha.input(&s.0);
    sha.input(&iter.extra.0);
    sha.input_str( TIGER[6] );
    sha.input(&s.0);
    sha.input(&linkkey.0);
    sha.input_str( TIGER[7] );
    sha.result(&mut r);
    // sha.result(
    //   unsafe { mem::transmute::<&mut (MessageKey, SphinxSecret),&mut [u8;32+16]>(&mut r) } 
    // );
    sha.reset();

    // (MessageKey(r[0..31]), LeafKey(r[32..47]))
    let (a,b) = array_refs![&r,32,16];
    (MessageKey(*a), LeafKey(*b))
    // r
}





fn kdf_sphinx(npk,alpha,s: &[u8]) -> [u8; 64] {
    let r: [u8; 64];
    let sha = Sha3::sha3_512;
    sha.input(alpha);
    sha.input(s);
    sha.input(npk);
    sha.input(alpha);   
    sha.input(s);
    sha.input(npk);
    sha.result(r);
    sha.reset();
    r
}



//  let mut cc = ChaCha20::new(header_key, [0u8; 12]);



type K = [u8; 32];

fn curve25519_fixbits(e: &mut [u8]) {
    // Zero bottom three bits, so that 2, 4, and 8 do not divide e.
    // Protects against active small subgroup attacks
    e[0] &= 248;
    // Clear above high bit.
    e[31] &= 127;
    // Set high bit to simplify timing
    e[31] |= 64;
}

fn create_alphas_fun(a0: &[u8], nodekeys: &[NodeKeys],) ->  ([K; MAXHOPS+1],[K; MAXHOPS]) {
    let mut alphas: [K; MAXHOPS+1];
    let mut ss: [K; MAXHOPS];
    alphas[0] = curve25519_base(a0);
    let mut a = a0;
    for (n,i) in nodekeys.zip(0..MAXHOPS) {
        let NodeDHKey(npk) = n.pubkey;
        let s0 = curve25519(npk,a);
        let (s1,ss[i]) = kdf_sphinx(npk,alpha,s0);
        curve25519_fixbits(s1);
        a = (Fe::from_bytes(a) * Fe::from_bytes(s1)).to_bytes();
        alphas[i+1] = curve25519_base(a);
    }
    (alphas,ss)
}

fn create_alphas(a0: &[u8], nodekeys: &[NodeKeys],) ->  ([K; MAXHOPS+1],[K; MAXHOPS]) {
    let mut alphas: [K; MAXHOPS+1];
    let mut ss: [K; MAXHOPS];
    alphas[0] = curve25519_base(a0);
    let mut a = Fe::from_bytes(a0);
    for (n,i) in nodekeys.zip(0..MAXHOPS) {
        let NodeDHKey(npk) = n.pubkey;
        let mut s0 = curve25519(npk,a);
        for (b,_) in bs.zip(0..i) {
            s0 = curve25519(s0,b);
        }
        let (s1,ss[i]) = kdf_sphinx(npk,alpha,s0);
        let bs[i] = Fe::from_bytes(s1);
        // twiddle bits?
        alphas[i+1] = curve25519(alpha[i],bs[i]);
    }
    (alphas,ss)
}

// Need to insert Xolotl s terms before doing padding

fn create_padding(a0: &[u8]; ) ->  (,) {
    let mut messagekey: MessageKey;

    ChaCha20::new_xchacha20(messagekey, [0;24]);
}


fn create_header(a0: &[u8]; ) ->  (,) {

}


*/

