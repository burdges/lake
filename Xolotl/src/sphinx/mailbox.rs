// Copyright 2016 Jeffrey Burdges.

//! Sphinx node mailbox routines


use std::collections::HashMap;
use std::hash::Hash; // Hasher
use std::sync::{RwLock}; // Arc, RwLockReadGuard, RwLockWriteGuard

use super::curve;
use super::keys::RoutingName;
use super::error::*;
use super::*;

use ::state::HasherState;


pub struct ArivingPacket {
    pub surbs: Vec<PacketName>,
    pub body: Box<[u8]>
}

pub type ArrivingStore = RwLock<Vec<ArivingPacket>>;


pub type RwMap<K,V> = RwLock<HashMap<K,V,HasherState>>;

pub type PacketMap<V> = RwMap<PacketName,V>;

pub trait PacketMapy : Sized {
    type Packet;
    fn packets(&self) -> &PacketMap<Self::Packet>;
    fn new_unfamiliar(hs: HasherState) -> Self;
}

pub struct PacketMapMap<K,PM>(pub HasherState, pub RwMap<K,PM>)
  where K: Eq+Hash, PM: PacketMapy;

impl<K,PM> PacketMapMap<K,PM>
  where K: Eq+Hash, PM: PacketMapy 
{
    pub fn new(hs: HasherState) -> PacketMapMap<K,PM> {
        PacketMapMap( hs, RwLock::new(HashMap::with_hasher(hs)) )
    }

    // TODO: Remove the `IntoIterator<Item=(PacketName,PM::Packet)>`
    // as these are only called on singletons. 

    pub fn new_queue<'a,I>(&self, new_packets: I) -> PM
      where I: IntoIterator<Item=(PacketName,PM::Packet)>,
            PM::Packet: 'a
    {
        let pm = PM::new_unfamiliar(self.0);
        {
        let mut packets = pm.packets().write().unwrap();  // Owned here
        for (k,v) in new_packets { packets.insert(k,v); }
        }
        pm
    }

    fn enqueue_familiar(&self, k: &K, packet_name: PacketName, packet: PM::Packet)
      -> SphinxResult<Option<PM>>
    {
        let queues = self.1.read().unwrap();  // PoisonError  ???
        let queue = if let Some(q) = queues.get(k) { q } else {
            let i = ::std::iter::once((packet_name,packet));
            return Ok(Some( self.new_queue(i) ));
        };
        let mut packets = queue.packets().write().unwrap();  // PoisonError ???
        if let Some(old) = packets.insert(packet_name,packet) {
            // TODO Improve this error somehow?  Either replay protection failed,
            // or else the hash itself function is broken, or else ??
            Err( SphinxError::InternalError("Packet name collision detected!") )
        } else { Ok(None) }
    }

    pub fn enqueue(&self, k: K, packet_name: PacketName, packet: PM::Packet)
      -> SphinxResult<()> 
    {
        if let Some(pm) = self.enqueue_familiar(&k,packet_name,packet) ? {
            let mut queues = self.1.write().unwrap(); // PoisonError ???
            queues.insert(k, pm );  // Ignore return because get(k) just failed
        }
        Ok(())
    }

}


pub const MAILBOX_NAME_LENGTH : usize = 16;
pub type MailboxNameBytes = [u8; MAILBOX_NAME_LENGTH];

/// Identifier for a mailbox where we store messages to be
/// picked up latr.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct MailboxName(pub MailboxNameBytes);

pub struct MailboxPacket {
    pub surb_log: Box<[u8]>,
    pub body: Box<[u8]>
}

/// TODO: We must replace this structure by a trait that abstracts
/// the storage backend.
pub struct Mailbox {
    // We could create mailbox authentication beyond our issuing 
    // of SURBs by adding a mailbox key here.  An incoming packet 
    // contains a nonce that hashed with this mailbox key yields 
    // a 32 byte key for a poly1305 MAC that runs over the SURB.
    // In this way, we can dstribute our mailbox servers addres
    // along with pairs of nonces and corresponding MAC keys to
    // trusted contacts.  See AGL's plans for replacing the BBS
    // signature scheme authentication in Pond. 

    packets: PacketMap<MailboxPacket>,
}

impl PacketMapy for Mailbox {
    type Packet = MailboxPacket;
    fn packets(&self) -> &PacketMap<MailboxPacket> { &self.packets }
    fn new_unfamiliar(hs: HasherState) -> Mailbox {
        Mailbox { packets : RwLock::new(HashMap::with_hasher(hs)) }
    }
}

pub type MailboxStore = PacketMapMap<MailboxName,Mailbox>;


pub struct OutgoingPacket {
    pub route: RoutingName,
    pub header: Box<[u8]>,
    pub body: Box<[u8]>
}

/// TODO: We must replace this structure by a trait that abstracts
/// the storage backend.
pub struct Outgoing {
    packets: PacketMap<OutgoingPacket>
}

impl PacketMapy for Outgoing {
    type Packet = OutgoingPacket;
    fn packets(&self) -> &PacketMap<OutgoingPacket> { &self.packets }
    fn new_unfamiliar(hs: HasherState) -> Outgoing {
        Outgoing { packets: RwLock::new(HashMap::with_hasher(hs)) }
    }
}

// TODO Replace RoutingName with longer term key's name here.
pub type OutgoingStore = PacketMapMap<RoutingName,Outgoing>;



