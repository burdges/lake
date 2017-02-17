// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...


// pub ed25519_dalek::ed25519;

pub use super::curve::{Scalar,Point};
pub use super::header::SphinxParams;


/// Sphinx node curve25519 public key.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodePublicKey(pub [u8; 32]);

/// Identifier for the current concenus 
pub struct ConcensusId(pub [u8; 32]);

/// XChaCha20 not-a-nonce for all packets with a given `NodePublicKey`
/// in a given `ConcensusId`.  Nodes should cache this with their
/// `NodePrivateKey` but clients may simply generate it when building
/// packets.
pub struct NodeToken(pub [u8; 24]);

impl NodeToken {
    pub fn generate(params: &SphinxParams, 
                    concensus: &ConcensusId, 
                    node: &NodePublicKey
      ) -> NodeToken {
        use crypto::digest::Digest;
        use crypto::sha3::Sha3;

        let mut nk = [0u8; 24];
        let mut sha = Sha3::sha3_512();

        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.input_str(params.protocol_name);
        sha.input(&concensus.0);
        sha.input(&node.0);
        sha.result(&mut nk);
        sha.reset();
        NodeToken(nk)
    }
}

pub trait NodeInfo {
}

pub struct NodePublic {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    token: NodeToken,
}

pub struct NodeSecrets {
    /// Sphinx `'static` runtime paramaters 
    params: &'static SphinxParams,

    token: NodeToken,

    ,
}


/*

pub const APP_ID_LENGTH : Length = 16;
pub type AppIdBytes = [u8; APP_ID_LENGTH];
pub struct AppId(AppIdBytes)

EpochId,
SurbSeed,


/// Commands packets give to mix network nodes.
pub enum Command {
    /// Crossover from header to SURB
    CrossOver {
        alpha: AlphaBytes,
        gamma: GammaBytes,
    },

    /// Advance and integrate a ratchet state
    Ratchet {
        twig: TwigId,
        gamma: GammaBytes,
    },

    /// Transmit packet to another mix network node
    Transmit {
        node_name: NodeName,
        gamma: GammaBytes,
    },

    /// Deliver message to the specified mailbox, roughly equivelent
    /// to transmition to a non-existant mix network node.
    Delivery {
        /// Mailbox name
        mailbox_name: MailboxName,
    },

    /// Arrival of a SURB we created and archived.
    ArrivalSURB { },

    /// Arrival of a message for a local application.
    ArrivalDirect { },
}

impl Command {
}


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
        node_name: NodeName,
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




struct SphinxNode {
    params: &'static SphinxParams, 
    node_token: NodeToken, 
    replayer: RwLock<Filter<Key=ReplayCode>>
}

impl SphinxNode {
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
        let okay = refs.verify_gamma(&hop);

        let mykey = self.params.sphinx_kdf(&ss, self.node_info.secret_token());
        let mut myhop = mykey.hop();
        let mine = refs.verify_gamma(&myhop);

        if !mine && !okay {
            return hop.invalid_mac_error();  // InvalidMac
        }
        if mine { hop = myhop; }  // First timing leak

        // Replay protection uses the replay code built with the secret token.
        mykey.replay_check(&self.replayer) ?; // Replay

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

            if r @ Ratchet {..} = command {
                if mine {
                    return Err( SphinxError::BadPacket("You ratcheted yourself?") );
                }
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
                    node_name: c.node_name,
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
            c @ Command::Arrival => {
                if mine {
                    self.surb_unwind(hop.packet_name(),refs.surb_log,body)
                } else {  Ok( Action::Arrival { } )  }
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

