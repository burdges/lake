// Copyright 2016 Jeffrey Burdges.

//! Sphinx SURB management
//!
//! ...

use std::collections::HashMap;
// use std::hash::Hash; // Hasher
use std::sync::{RwLock}; // RwLockReadGuard, RwLockWriteGuard
use std::iter::Iterator;
use std::marker::PhantomData;

pub use ratchet::{TwigId,TWIG_ID_LENGTH};

// use super::stream::{HeaderCipher};
use super::node::Action;
use super::error::*;
use super::slice::*;
use super::*;

use ::state::{HasherState};


pub const MAX_SURB_METADATA : usize = 8;

#[derive(Debug, Clone, Copy, Default)]
pub struct Metadata(pub u64);


pub struct SURBHopKey {
    /// IETF Chacha20 stream cipher key and nonce.
    pub chacha: stream::ChaChaKnN,

    pub berry_twig: Option<TwigId>,
}


struct ArrivalSURB  {
    
    delivery_name: PacketName,
}

// TODO: Make protocol name reference params
pub struct ProtocolId(u16);

pub struct DeliverySURB {
    pub protocol: ProtocolId,
    pub meta: Metadata,
    pub hops: Vec<SURBHopKey>,
}

// pub type RwMap<K,V> = RwLock<HashMap<K,V,HasherState>>;
use super::mailbox::RwMap;

pub struct SURBStore<P: Params> {
    params: PhantomData<P>,
    arrivals: RwMap<PacketName,ArrivalSURB>,
    deliverys: RwMap<PacketName,DeliverySURB>,
}


impl<P: Params> SURBStore<P> {
    // pub new() -> SURBStore {
    //     ;
    // }

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
        let mut metadata = Vec::<Metadata>::with_capacity(cap);

        loop {
            let DeliverySURB { protocol, meta, hops } = {
                let mut deliverys = self.deliverys.write().unwrap(); // PoisonError ???
                if let Some(s) = deliverys.remove(&packet_name) { s } else { break; }
            };
            metadata.push(meta);
            for key in hops.iter().rev() {
                if let Some(berry_twig) = key.berry_twig {
                    unimplemented!();
                    // TODO: Should we write to the data base here, taking
                    // and releasing locks frequently?  Or return the list
                    // to add all at once? 
                }
                // TODO: Use protocol specified in the delivery surb
                let mut hop = key.chacha.header_cipher::<P>() ?;
                  // InternalError: ChaCha stream exceeded
                hop.xor_surb_log(surb_log) ?;  // InternalError
                hop.body_cipher().encrypt(body) ?;  // InternalError
            }
            packet_name = if surb_log.len() >= PACKET_NAME_LENGTH {
                PacketName(*reserve_fixed_mut!(&mut surb_log, PACKET_NAME_LENGTH))
            } else { break; };
            if packet_name == PacketName::default() { break; }
        }

        return Ok( Action::Arrival { metadata } )
    }
}





