// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...


// pub ed25519_dalek::ed25519;


use super::*; // Length
use super::curve::{AlphaBytes,Scalar,Point};
use super::stream::{Gamma,SphinxKey,SphinxHop};
pub use super::header::{SphinxParams,HeaderRefs,Command};
pub use super::keys::RoutingName;
pub use super::mailbox::MailboxName;






/// Action the node should take with a given packet.
enum Action {
    /// Deliver message to a local mailbox
    Deliver {
        /// Mailbox name
        mailbox_name: MailboxName,
        /// Packet name for SURB unwinding
        packet_name: PacketName,
    },

    /// Forward this message to another hop.
    Transmit {
        /// Next hop
        routing_name: RoutingName,
        /// Packet name for SURB unwinding
        packet_name: PacketName,
    },

    /// Arrival of a message for some local application.
    ///
    /// There are situations where we could know the sender because
    /// either we could know who we gave every SURB to, or else by
    /// trusting them to identify themselves as a hint and doing the
    /// authentication later.  Yet, these cases seem tricky to exploit.
    Arrival { },
}


/*


struct SphinxRouter {
    params: &'static SphinxParams,
    routing_secret: RoutingSecret,
    replayer: RwLock<Filter<Key=ReplayCode>>
}

impl SphinxRouter {
    fn routing_name(&self) -> RoutineName {
        self.routing_secret.name
    }
}



impl SphinxRouter {
    fn command(&self, &[u8]) -> SphinxError<(usize,Command)> {
    }

    .

    fn do_crypto(&self, refs: HeaderRefs, body: &mut [u8]) -> SphinxError<()> {
        let length = self.params.beta_length;
        assert!(self.params.max_beta_tail_length < length);

        // Compute shared secret from the Diffie-Helman key exchange.
        let alpha = refs.alpha.decompress() ?;  // BadAlpha
        let mut ss = alpha.key_exchange(node.private);

        // Initalize stream ciphers and check gamma cases.
        let mut key = self.params.sphinx_key(&ss, self.node_info.public_token());
        let mut hop = key.hop();

        refs.verify_gamma(&hop) ?;  // InvalidMac

        hop.replay_check(&self.replayer) ?; // Replay

        // Onion decrypt beta, extracting commands, and processing the ratchet.
        // TODO: Restrict to a single ratchet invokation?
        let mut command: Command;
        let mut ratchets = 0;
        loop {
            hop.xor_beta(refs.beta);

            let eaten: usize;
            (eaten,command) = self.command(refs.beta) ?;  // ????
            if eaten > self.params.max_beta_tail_length {
                return Err( SphinxError::InternalError("Ate too much Beta!") );
            }

            // We could reduce copies with box, or preferably alloca, 
            // but no point so long as the loop executes at most twice.
            for i in eaten..length {  beta[i-eaten] = beta[i];  }
            hop.set_beta_tail(refs.beta[length-eaten..length]);

            let command = refs.parse_n_shift_beta(&mut hop);

            if r @ Ratchet {..} = command {
                if ratchets>0 {
                    return Err( SphinxError::BadPacket("Tried to two 2+ ratchet subhops.") );
                }
                ratchets += 1;
                key.chacha_key = AdvanceNode::single_click(state, &r.twig) ?; // RatchetError
                hop = key.hop();
                *refs.gamma = r.gamma;
                if ! refs.verify_gamma(&hop) {
                    return hop.invalid_mac_error();  // InvalidMac
                }
            } else { break; }
        }
        if c @ ArivalSURB {..} = command {
            for (i,j) in key.chacha_key.iter_mut().zip(node.secret_mask.iter()) { *i ^= *j; }
            hop = key.hop();
            // Should we return a different error here?
            refs.verify_gamma(&hop) ?;  // InvalidMac
        }

        // Decrypt remander of header
        hop.xor_surb_log(refs.surb_log);
        hop.xor_surb(refs.surb);

        // Decrypt body
        hop.lionness_cipher().decrypt(body) ?;  // InternalError 

        // Carry out required command
        match command {
            c @ Command::CrossOver {..} => {
                // Put SURB in control of packet.
                *refs.alpha = c.alpha;
                *refs.gamma = c.gamma;
                *refs.beta.copy_from_slice(refs.surb);
                // We must zero the SURB feld so that our SURB's gammas
                // cover values known by its creator.  We must zero the
                // SURB log field so that SURB unwinding can stop. 
                // These fields are safe to zero now because they will 
                // immediately be encrypted.
                for i in refs.surb.iter_mut() { *i = 0; }
                for i in refs.surb_log.iter_mut() { *i = 0; }
                // Process the local SURB hop.
                self.do_crypto(refs,body)
            },
            // All variants below depend upon refs being immutable here.
            c @ Command::Transmit {..} => {
                // Prepare packet for next hop as usual in Sphinx.
                *refs.gamma = c.gamma;
                *refs.alpha = alpha.blind(& (hop.blinding() ?)).compress();
                Ok( Action::Transmit {
                    routing_name: c.routing_name,
                    packet_name: hop.packet_name() 
                } )
            },
            c @ Command::Deliver {..} => {
                let packet_name = hop.packet_name();
                self.params.prepend_to_surb_log(refs.surb_log,&packet_name);
                surb_log[0..start].copy_from_slice();
                Ok( Action::Deliver {
                    mailbox_name: c.mailbox_name,
                    packet_name: packet_name,
                } )
            },
            c @ Command::ArrivalSURB => {
                /*
                for (i,j) in key.chacha_key.iter_mut().zip(node.secret_mask.iter()) { *i ^= *j; }
                hop = key.hop();
                // Should we return a different error here?
                refs.verify_gamma(&hop) ?;  // InvalidMac
                */
                self.surb_unwind(hop.packet_name(),refs.surb_log,body)
            },
            c @ Command::ArrivalDirect => {
                Ok( Action::Arrival { } )
            },
            Ratchet {..} => unreachable!(),
        }
    }

    pub fn process(&self, header: &mut [u8], body &mut [u8]) -> SphinxError<()>
        ...
        let action = {
            let refs = self.params.slice_header(header);
            let mut kdf = SphinxKDF {
                ss: self.do_alpha(refs) ?;
            };
            self.do_crypto(kdf,refs,body) ? 
        };
        match action {
            Action::Enqueue(node_name) =>
                self.enqueue(header,body),
            Action::Deliver(??) =>
                self.enqueue(header,body),
            Action::Arrival {..} =>
                self.arrival(c.sender,c.application,body),
        }
    }

    fn enqueue(&self, header: &[u8], body: &[u8]) -> SphinxError<()> {
    }

    fn deliver(&self, header: &[u8], body: &[u8]) -> SphinxError<()> {
    }


    fn surb_unwind(&self, mut epoch_id: EpochId, mut surb_seed: SurbSeed,
            surb_log: &mut [u8], body: &mut [u8]) -> SphinxError<()> 
    {
        let mut eaten = 0usize;
        while {
            eaten += PACKET_NAME_LENGTH;
            if eaten > self.params.surb_log_leng {
                return Err( ??? );
            }
            // let surb = self.??(epoch_id,surb_seed) ?;  // ??

            // TODO: Record any ratchet successes
            // OOPS!  How can we delete the ratchet state if
            // we need to keep it for SURB unwinding?

            // What are we checking to verify that the surb_seed is legitimate?
            // refs.alpha might work for the final surb, but do we know it before that?

            // surb.unwind(surb_log,body);

            if surb_log.iter().all(|x| x == 0) { break; }
            (epoch_id.0,surb_seed.0) = array_refs![surb_log,0,EPOCH_ID_LENGTH,SURB_SEED_LENGTH];
        } {}
        Ok( Action::Arrival {
            sender: ??,
            application: ??,
        } )
    }

}

*/

