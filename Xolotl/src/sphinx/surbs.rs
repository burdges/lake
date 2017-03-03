// Copyright 2016 Jeffrey Burdges.

//! Sphinx SURB management
//!
//! ...

use std::collections::HashMap;
use std::hash::Hash; // Hasher
use std::sync::{RwLock}; // Arc, RwLockReadGuard, RwLockWriteGuard

// use super::header::{};
use super::curve;
use super::keys::RoutingName;
use super::error::*;
use super::*;

use ::state::{HasherState,Filter};

struct ArrivalSURB  {
    delivery_name: PacketName,
}

struct DeliverySURB {
    surb_log_xor: &[u8];
}




    /// Unwind a chain of SURBs from an arival packet name.
    /// 
    /// There is no reason to authenticate arrival SURBs because nobody
    /// but us should ever learn their packet name.
    fn unwind_surbs_on_arivial(&self, arival_packet_name: &PacketName,
        mut surb_log: &mut [u8], body: &mut [u8]
      ) -> SphinxResult<(PacketName,Action)> 
    {
        let guard_packet_name = {
unimplemented!();
/*
            let arrivals = self.arrivals.write().unwrap();  // PoisonError ??
            if let Some(gpn) = arrivals.remove(arival_packet_name) { gpn } else {
                return Err( BadPacketName(*arival_packet_name) );
            }
*/
        };
        let action = self.unwind_delivery_surbs(guard_packet_name, refs.surb_log, body) ?;
        Ok((*arival_packet_name,action))
    }

    /// Unwind a chain of SURBs using delivery packet names.
    /// 
    /// We do nothing extra to authenticate SURBs beyond checking the
    /// packet name exists because only the hop and client ever sees
    /// any given packet name.  We should discuss if this decission
    /// creates and strange packet volume attacks or if it conflicts
    /// poorly trusted mix nodes generating SURBs for users.
    fn unwind_delivery_surbs(&self, mut packet_name: PacketName, mut surb_log: &mut [u8], body: &mut [u8]) -> SphinxResult<Action> 
    {
        let cap = surb_log.len() / PACKET_NAME_LENGTH + 1;
        let mut purposes = Vec::<PacketName>::with_capacity(cap);

/*
        loop {
            let ss = { 
                let surb_archive = self.surb_archive.write().unwrap();  // PoisonError ???
                if let Some(sh) = surb_archive.remove(packet_name) { *sh } else {
                    // If any SURBs existed 
                    if ! starting { break; }
                    return SphinxError::BadSURBPacketName;
                }
            };
            if ! starting {
                let key = self.params.sphinx_kdf(&ss, self.routing_secret.name);
                let mut hop = key.hop() ?;  // InternalError: ChaCha stream exceeded
                hop.xor_surb_log(surb_log) ?;  // InternalError
                hop.body_cipher().encrypt(body) ?;  // InternalError
            } else {
                purposes.push(packet_name);
                starting = false; 
            }

            packet_name = if surb_hop.preceeding != PacketName::default() {
                surb_hop.preceeding
            } else if surb_log.len() >= PACKET_NAME_LENGTH {
                PacketName(*reserve_fixed!(surb_log, PACKET_NAME_LENGTH))
            } else { break; };
            if packet_name == PacketName::default() { break; }
        }

        let surb_archive = self.surb_archive.write() ?;  // PoisonError
        ;
*/

        return Ok( Action::Arrival { surbs: purposes } )
    }



