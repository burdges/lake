// Copyright 2016 Jeffrey Burdges.

//! Sphinx SURB management
//!
//! ...

use std::collections::HashMap;
use std::hash::Hash; // Hasher
use std::sync::{RwLock}; // Arc, RwLockReadGuard, RwLockWriteGuard
use std::iter::Iterator;

pub use ratchet::{TwigId,TWIG_ID_LENGTH};

use super::curve;
use super::keys::RoutingName;
use super::stream::{SphinxKey,SphinxHop};
use super::node::Action;
use super::error::*;
use super::slice::*;
use super::*;

use ::state::{HasherState,Filter};

pub struct SURBHop {
    /// IETF ChaCha20 12 byte nonce 
    pub chacha_nonce: [u8; 12],

    /// IETF ChaCha20 32 byte key 
    pub chacha_key: [u8; 32],

    pub berry_twig: Option<TwigId>,
}


struct ArrivalSURB  {
    delivery_name: PacketName,
}

struct DeliverySURB {
    // TODO: protocol: Protocol,
    hops: Vec<SURBHop>,
}

// pub type RwMap<K,V> = RwLock<HashMap<K,V,HasherState>>;
use super::mailbox::RwMap;

pub struct SURBStore {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    arrivals: RwMap<PacketName,ArrivalSURB>,
    deliverys: RwMap<PacketName,DeliverySURB>,
}


impl SURBStore {
    /// Unwind a chain of SURBs from an arival packet name.
    /// 
    /// There is no reason to authenticate arrival SURBs because nobody
    /// but us should ever learn their packet name.
    pub fn unwind_surbs_on_arivial(&self, arival_packet_name: &PacketName,
        surb_log: &mut [u8], body: &mut [u8]
      ) -> SphinxResult<(PacketName,Action)> 
    {
        let guard_packet_name = {
            let mut arrivals = self.arrivals.write().unwrap();  // PoisonError ??
            if let Some(gpn) = arrivals.remove(arival_packet_name) { gpn.delivery_name } else {
                return Err( SphinxError::BadPacketName(*arival_packet_name) );
            }
        };
        // TODO: Check that protocol agrees with how we were called
        let action = self.unwind_delivery_surbs(guard_packet_name, surb_log, body) ?;
        Ok((*arival_packet_name,action))
    }

    /// Unwind a chain of SURBs using delivery packet names.
    /// 
    /// We do nothing extra to authenticate SURBs beyond checking the
    /// packet name exists because only the hop and client ever sees
    /// any given packet name.  We should discuss if this decission
    /// creates and strange packet volume attacks or if it conflicts
    /// poorly trusted mix nodes generating SURBs for users.
    pub fn unwind_delivery_surbs(&self, mut packet_name: PacketName, mut surb_log: &mut [u8], body: &mut [u8]) -> SphinxResult<Action> 
    {
        let cap = surb_log.len() / PACKET_NAME_LENGTH + 1;
        let mut purposes = Vec::<PacketName>::with_capacity(cap);

        loop {
            let delivery_surb = {
                let mut deliverys = self.deliverys.write().unwrap(); // PoisonError ???
                if let Some(s) = deliverys.remove(&packet_name) { s } else { break; }
            };
            purposes.push(packet_name);
            for surb in delivery_surb.hops.iter().rev() {
                if let Some(berry_twig) = surb.berry_twig {
                    unimplemented!(); 
                }
                // TODO: Use protocol specified in delivery_surb
                let mut hop = SphinxKey {
                    params: self.params,
                    chacha_nonce: surb.chacha_nonce,
                    chacha_key: surb.chacha_key,
                }.hop() ?;  // InternalError: ChaCha stream exceeded
                hop.xor_surb_log(surb_log) ?;  // InternalError
                hop.body_cipher().encrypt(body) ?;  // InternalError
            }
            packet_name = if surb_log.len() >= PACKET_NAME_LENGTH {
                PacketName(*reserve_fixed_mut!(&mut surb_log, PACKET_NAME_LENGTH))
            } else { break; };
            if packet_name == PacketName::default() { break; }
        }

        return Ok( Action::Arrival { surbs: purposes } )
    }
}

