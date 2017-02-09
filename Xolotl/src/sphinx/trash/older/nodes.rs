
/* 

use std:time::SystemTime;


// At 128 bits, there is a 2^64ish quantum attack to fake NodeNames
// using Grover's algorithm, but the signing algorithm is far more
// vulnerable. 
pub struct NodeName([u8; 16]);


pub struct NodeSigningKey([u8; 32]);
pub struct NodeSigningKeyPriv([u8; 64]);

pub struct NodeInfo {
    pub name: NodeName,
    pub signingkey: NodeSigningKey,
}


pub struct NodeDHKey([u8; 32]);
pub struct NodeDHKeyPriv([u8; 32]);

pub struct NodeKeys {
    pub name: NodeName,
    pub pubkey: NodeDHKey,
    pub hash: u64,  /* = Hash(publickey) */
    pub start, stop: SystemTime,
}


*/



