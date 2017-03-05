// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...

use std::borrow::{Borrow,BorrowMut};
use std::sync::{Arc,RwLock};

// pub ed25519_dalek::ed25519;

pub use ratchet::{TwigId,TWIG_ID_LENGTH,Transaction,AdvanceNode};
pub use ratchet::State as RatchetState;

use super::curve::{AlphaBytes,Scalar,Point};
use super::stream::{Gamma,SphinxKey,SphinxHop};
use super::layout::{SphinxParams,HeaderRefs,Command};
use super::keys::{RoutingName,RoutingSecret}; // RoutingPublic
use super::replay::*;
use super::mailbox::*;
use super::surbs::SURBStore;
use super::utils::*;
use super::error::*;
use super::*;


/// Action the node should take with a given packet.
/// We pair PacketName
pub enum Action {
    /// Deliver message to a local mailbox
    Deliver {
        /// Mailbox name
        mailbox: MailboxName,
        ///
        surb_log: Box<[u8]>,
    },

    /// Forward this message to another hop.
    Transmit {
        /// Next hop
        route: RoutingName,
    },

    /// Arrival of a message for some local application.
    ///
    /// There are situations where we could know the sender because
    /// either we could know who we gave every SURB to, or else by
    /// trusting them to identify themselves as a hint and doing the
    /// authentication later.  Yet, these cases seem tricky to exploit.
    Arrival {
        surbs: Vec<PacketName>,
    },
}


struct SphinxRouter {
    params: &'static SphinxParams,

    // routing_public: RoutingPublic,
    routing_secret: RoutingSecret,

    replayer: ReplayFilterStore,

    outgoing: OutgoingStore,
    mailboxes: MailboxStore,
    arrivals: ArrivingStore,

    surbs: Arc<SURBStore>,
    ratchet: Arc<RatchetState>,
}


impl SphinxRouter {
    /// Invokes ratchet and cross over functionality itself, but
    /// must return an `Action` for functionality that requires
    /// ownership of the header and/or body.
    fn do_crypto(&self, mut refs: HeaderRefs, body: &mut [u8])
      -> SphinxResult<(PacketName,Action)> {
        // Compute shared secret from the Diffie-Helman key exchange.
        let alpha = Point::decompress(refs.alpha) ?;  // BadAlpha
        let ss = alpha.key_exchange(&self.routing_secret.secret);

        // Initalize the stream cipher
        let mut key = self.params.sphinx_kdf(&ss, &self.routing_secret.name);
        let mut hop = key.hop() ?;  // InternalError: ChaCha stream exceeded

        // Abort if our MAC gamma fails to verify
        refs.verify_gamma(&hop) ?;  // InvalidMac

        // Abort if the packet is a reply
        hop.replay_check(&self.replayer) ?; // Replay

        // Onion decrypt beta to extract first command.
        let mut command = refs.peal_beta(&mut hop) ?;  // InternalError, BadPacket: Unknown Command

        // Process `Command::Ratchet` before decrypting the surb log or body.
        if let Command::Ratchet { twig, gamma } = command {
            let TwigId(branch_id, twig_idx) = twig;
            let mut advance = AdvanceNode::new(&self.ratchet, &branch_id) ?;  // RatchetError
            key.chacha_key = (advance.clicks(&ss, twig_idx) ?).0;  // RatchetError
            hop = key.hop() ?;  // InternalError: ChaCha stream exceeded
            *refs.gamma = gamma.0;
            if let Err(e) = refs.verify_gamma(&hop) {
                advance.abandon().unwrap();  // RatchetError ??
                return Err(e);  // InvalidMac
            }
            advance.confirm() ?;  // RatchetError
            command = refs.peal_beta(&mut hop) ?;  // InternalError, BadPacket: Unknown Command
            if let Command::Ratchet { .. } = command {
                return Err( SphinxError::BadPacket("Tried two ratchet subhops.",0) );
            }
        }

        // No need to constant time here.  Should just pass the bool really.
        let already_crossed_over = ::consistenttime::ct_u8_eq( 0u8, 
            refs.surb_log.iter().fold(0u8, |x,y| { x | *y })
        );

        // Short circut decrypting the body, SURB and SURB log if
        // we're unwinding an arriving SURB anyways.
        // TODO: Should we better authenticate that SURB were created by us?
        if let Command::ArrivalSURB { } = command {
            // hop.xor_surb(refs.surb);
            // hop.xor_surb_log(refs.surb_log);
            // hop.body_cipher().decrypt(body) ?;  // InternalError 
            return self.surbs.unwind_surbs_on_arivial(hop.packet_name(), refs.surb_log, body);
        }

        // Decrypt body
        hop.body_cipher().decrypt(body) ?;  // InternalError 

        Ok(( *hop.packet_name(), match command {
            Command::ArrivalSURB { } => unreachable!(),
            Command::Ratchet {..} => unreachable!(),

            // We cross over to running the SURB by moving the SURB
            // into postion and recursing. 
            Command::CrossOver { alpha, gamma } => {
                if already_crossed_over {
                    return Err( SphinxError::BadPacket("Tried two crossover subhops.",0) );
                }
                // Put SURB in control of packet.
                *refs.alpha = alpha;
                *refs.gamma = gamma.0;
                refs.beta.copy_from_slice(refs.surb);
                // We must zero the SURB feld so that our SURB's gammas
                // cover values known by its creator.  We might improve
                // SURB unwinding by zeroing the SURB log field too. 
                // These two fields are safe to zero now because they 
                // will immediately be encrypted.
                for i in refs.surb.iter_mut() { *i = 0; }
                for i in refs.surb_log.iter_mut() { *i = 0; }
                // Process the local SURB hop.
                return self.do_crypto(refs,body);
            },

            // We mutate all `refs.*` in place, along with body, so
            // `Transmit` merely drops this mutable borrow of the 
            // header and queues the now mutated header and body.
            // As a result, we require that both the original header 
            // and SURB use the same protocol version as specified 
            // by `self.params`.
            //
            // Also, we must never change the referant of any of our 
            // references in `refs`, even though `refs` must itself 
            // be mutable.  We may fix this with either simple guards
            // types or smaybe interior mutability depneding upon how
            // this code evolves. 
            Command::Transmit { route, gamma } => {
                // Only transmit need to mask the SURB.
                hop.xor_surb(refs.surb);
                hop.xor_surb_log(refs.surb_log);
                // Prepare packet for next hop as usual in Sphinx.
                *refs.gamma = gamma.0;
                *refs.alpha = alpha.blind(& hop.blinding()).compress();
                Action::Transmit { route }
            },

            // We box the SURB log because we must store it for pickup
            // via SURB.  At that time, we embed the packet name with
            // roughly `refs.prepend_to_surb_log(& hop.packet_name());`
            Command::Deliver { mailbox } =>
                Action::Deliver { mailbox, surb_log: refs.surb_log.to_vec().into_boxed_slice() },

            Command::ArrivalDirect { } =>
                Action::Arrival { surbs: vec![] },
        } ))
    }

    /// Process an incoming Sphinx packet.
    pub fn process(&self, mut header: Box<[u8]>, mut body: Box<[u8]>)
      -> SphinxResult<()>
    {
        assert!(self.params.max_beta_tail_length < self.params.beta_length);
        // assert lengths ...

        self.params.check_body_length(body.len()) ?; // BadLength
        let (packet, action) = {
            let refs = self.params.slice_header(header.borrow_mut()) ?;  // BadLength
            self.do_crypto(refs,body.borrow_mut()) ? 
        };
        match action {
            Action::Transmit { route } =>
                self.outgoing.enqueue(route, packet, OutgoingPacket { route, header, body } ),
            Action::Deliver { mailbox, surb_log } =>
                self.mailboxes.enqueue(mailbox, packet, MailboxPacket { surb_log, body } ),
            Action::Arrival { surbs } => {
                let mut arrivals = self.arrivals.write().unwrap(); // PoisonError ???
                arrivals.push( ArivingPacket { surbs, body } );
                Ok(())
            },
        }
    }

}


