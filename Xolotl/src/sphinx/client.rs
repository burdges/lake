// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...

use std::sync::Arc; // RwLock, RwLockReadGuard, RwLockWriteGuard
use std::marker::PhantomData;
use std::time::{Duration,SystemTime,UNIX_EPOCH};

use rand::{Rng, Rand};

use ratchet::{BranchId,BRANCH_ID_LENGTH,TwigId,TWIG_ID_LENGTH,Transaction,AdvanceUser};
pub use ratchet::ClientState as ClientRatchetState;

use super::stream::{Gamma}; // GammaBytes,GAMMA_LENGTH,HeaderCipher

pub use keys::{RoutingName,RoutingPublic,Concensus};
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::commands::{PreCommand}; // Command
use super::layout::{Params,ImplParams,PreHeader};
use super::error::*;
use super::*;


/// World of key material in which we build a header.
pub struct World<'a,C,P> where C: Concensus+'a, P: Params {
    params: PhantomData<P>,

    /// Network concensus information for looking up nodes.
    concensus: &'a C,

    /// Our ratchets with other nodes.
    ratchets: &'a ClientRatchetState,
}

/// We cannot #[derive(Clone)] if we need a where clause.
impl<'a,C,P> Clone for World<'a,C,P> where C: Concensus+'a, P: Params {
    fn clone(&self) -> World<'a,C,P> { World::new(self.concensus, self.ratchets) }
}

impl<'a,C,P> World<'a,C,P> where C: Concensus+'a, P: Params {
    pub fn new(concensus: &'a C, ratchets: &'a ClientRatchetState) -> World<'a,C,P> {
        World {
            params: PhantomData,
            concensus, ratchets,
        }
    }

    pub fn start_header<R: Rng+'a>(&self,
          rng: &'a mut R,
          route: RoutingName,
          make_surb: bool,
          capacity: usize 
      ) -> SphinxResult<Scaffold<'a,R,C,P>>
    {
        let aa = rng.gen();
        let alpha0 = ::curve::Point::from_secret(&aa).compress();
        // TODO: Any tests for alpha?  ::curve::Point::decompress(&alpha) ?;

        // Initial value for `self.key` that our call to `add_sphinx` below replaces.
        let key = stream::SphinxKey {
            params: PhantomData,
            chacha_nonce: [0u8; 12],
            chacha_key: [0u8; 32],
        };
        let rp = self.concensus.routing_named(&route) ?;
        let mut s = Scaffold {
            world: self.clone(),
            rng,
            route: route..route,
            route_public: rp.clone(),
            key, alpha0, aa, 
            delay: Duration::from_secs(0),
            validity: rp.validity.clone(),
            eaten: 0, 
            commands: Vec::with_capacity(capacity),
            advances: Vec::with_capacity(capacity),
            ciphers: Vec::with_capacity(capacity+1),
            surb_keys: if make_surb { Some(Vec::with_capacity(capacity)) } else { None },
            bodies: if ! make_surb { None } else { Some(Vec::with_capacity(capacity)) },
        };
        s.add_sphinx(route);
        Ok( s )
    }

    /// Prepare a sending header that does not expect to cross over to a SURB.
    pub fn send_header_long<R: Rng+'a>(&self, rng: &'a mut R, route: RoutingName)
      -> SphinxResult<Scaffold<'a,R,C,P>>
    {
        self.start_header(rng,route,false,P::max_hops_capacity())
    }

    /// Prepare a sending header that expects to cross over to a SURB.
    pub fn send_header<R: Rng+'a>(&self, rng: &'a mut R, route: RoutingName)
      -> SphinxResult<Scaffold<'a,R,C,P>>
    {
        // Divide by two since we assume a SURB oriented usage,
        // but this costs allocations if not using SURBs.
        let capacity = P::max_hops_capacity() / 2;
        self.start_header(rng,route,false,capacity)
    }

    /// Prepare a SURB with which to recieve a message.
    pub fn recieve_header<R: Rng+'a>(&self, rng: &'a mut R, route: RoutingName)
      -> SphinxResult<Scaffold<'a,R,C,P>>
    {
        let capacity = P::max_hops_capacity() / 2;
        self.start_header(rng,route,true,capacity)
    }
}


/// We build `PreHeader`s using successive operations on `Scafold`.
/// 
/// We use our first command to set `PreHeader::route` and pad
/// `PreHeader::beta` for usage in transmission or in aSURB, but
/// do not encode it into `PreHeader::beta`.
struct Scaffold<'a,R,C,P> where R: Rng+'a, C: Concensus+'a, P: Params {
    world: World<'a,C,P>,

    rng: &'a mut R,

    /// First and last hop that should process this header.
    ///
    /// TODO: `Range` makes and odd choice for this, but the field
    /// names work out nicely.
    route: ::std::ops::Range<RoutingName>,

    /// `RoutingPublic` information for `range.end`.
    route_public: RoutingPublic,

    /// We use this as the key arguemnt to `self.add_cipher()`
    /// because we want to keep the last used nonce for ratchet
    /// hops.  It is always defined, unlike `surb_keys.unwrap().last_mut()` 
    ///
    /// TODO: Should we make this a real argument to `add_cipher`
    /// somehow?  Should we not keep the nonce from key exchange? 
    key: stream::SphinxKey<P>,

    /// Initial public curve point
    alpha0: ::curve::AlphaBytes,

    /// Accumulator for the current private scalar `a`.
    aa: ::curve::Scalar,

    /// Expected delay
    delay: Duration,

    /// Expected validity period
    validity: ::keys::time::ValidityPeriod,

    /// Amount of `beta` used by `commands`.
    eaten: usize,

    /// `Commands` for `beta`.
    ///
    /// We interpret `gamma` for `Sphinx` and `Ratchet` commands as
    /// an index into `hops` for the next `HeaderCipher`.
    commands: Vec<PreCommand<usize>>,

    /// TODO: Refactor to have only one transaction.
    advances: Vec<AdvanceUser<'a>>,

    /// Stream ciphers for 
    ciphers: Vec<stream::HeaderCipher<P>>,

    /// Packet construction mode, either `Ok` for SURBs, or
    /// `None` for a normal forward packets. 
    /// Also, records unwinding keys and twig ids in SURB mode.
    surb_keys: Option<Vec<surbs::SURBHopKey>>,

    /// Indexes of ciphers that encrypt the body and surb log
    bodies: Option<Vec<usize>>
}

impl<'a,R,C,P> Scaffold<'a,R,C,P> where R: Rng+'a, C: Concensus+'a, P: Params {
    /// 
    fn add_route(&mut self, route: RoutingName) -> SphinxResult<&RoutingPublic> {
        if self.route.end != route {
            let rp = self.world.concensus.routing_named(&route) ?; // ??
            self.route_public = rp.clone();
            self.route.end = route;
        } else {
            return Err( SphinxError::InternalError("Repeated hop!") );
        }
        Ok( &self.route_public )
    }

    fn add_cipher(&mut self, berry_twig: Option<TwigId>)
      -> SphinxResult<usize> {
        let mut hop = self.key.header_cipher() ?;  // InternalError: ChaCha stream exceeded
        let l = self.ciphers.len();
        self.ciphers.push(hop);
        if let Some(ref mut bodies) = self.bodies { bodies.push(l); }
        if let Some(ref mut sh) = self.surb_keys {
            sh.push( surbs::SURBHopKey {
                chacha_nonce: self.key.chacha_nonce,
                chacha_key: self.key.chacha_key,
                berry_twig,
            } ); 
        }
        Ok(l)
    }

    fn add_sphinx(&mut self, route: RoutingName)
      -> SphinxResult<usize> {
        // We avoid unecessary blinding by keeping `aa` one hop
        // behind and only blinding right before use.  We always
        // blind here except when called from `Scaffold::new`.
        if let Some(c) = self.ciphers.last_mut() { self.aa.blind(& c.blinding()); }
          // Annoyingly we cannot use `map` here because the borrow checker cannot
          // tell that we're borrowing different parts of `self`
        self.add_route(route) ?; // ??
          // Annoyingly we cannot use the reference returned by
          // `add_route` because the borrow checker cannot tell
          // that that the immutable borrow returned does not hide
          // some mutable borrow.
        // TODO: Figure out how to prevent leakage via validity
        self.validity.intersect_assign(&self.route_public.validity);  
        let rpoint = ::curve::Point::decompress(&self.route_public.public) ?;  // BadAlpha
        let ss = rpoint.key_exchange(&self.aa);
        self.key = stream::SphinxKey::<P>::new_kdf(&ss, &route);
        self.add_cipher(None)
    }

    fn add_ratchet_twig(&mut self, twig: TwigId)
      -> SphinxResult<usize> {
        // Remove keys records for Sphinx keys skipped over due to
        // using the ratchet key instead. 
        if let Some(ref mut sh) = self.surb_keys { sh.pop(); }
        if let Some(ref mut bodies) = self.bodies { bodies.pop(); }
        self.add_cipher( Some(twig) )
    }

    /// Assumes ...  !!!!!!!!!!
    fn add_ratchet(&mut self, branch_id: BranchId)
      -> SphinxResult<(TwigId,usize)> {
        let ratchet = self.world.ratchets.get(&self.route_public.issuer)
          .ok_or( SphinxError::IsserHasNoRatchet(self.route_public.issuer) ) ?;
        let mut advance = AdvanceUser::new(ratchet,&branch_id) ?;  // RatchetError
        let ss = SphinxSecret(self.key.chacha_key);
        let (twig,key) = advance.click(&ss) ?; // RatchetError
        self.key.chacha_key = key;
        let i = self.add_ratchet_twig(twig) ?;
        self.advances.push(advance);  // TODO: Refactor to have only one transaction
        Ok(( twig, i ) )
    }

/*
    pub fn command(&mut self, command: PreCommand<()>) -> SphinxResult<()> {
        use self::Command::*;
        let l0 = 0usize;
        let command = match *self {
            Transmit { route, gamma: _ } => 
                Transmit { route, gamma: self.add_sphinx_cipher(route) ? },
            Ratchet { twig: branch_id, gamma: _ } => {
                let (twig,gamma) = self.add_ratchet(branch_id);
                Ratchet { twig, gamma }
            },
            CrossOver { route, alpha, gamma, surb_beta } => {
                l0 = surb_beta.len();
                CrossOver { route, alpha, gamma, surb_beta }
            },
            Contact { } => Contact { },
            Greeting { } => Greeting { },
            Deliver { mailbox } => Deliver { mailbox },
            ArrivalSURB { } => ArrivalSURB { },
            ArrivalDirect { } => ArrivalDirect { },
            // DropOff { } => DropOff { },
            // Delete { } => Delete { },
            // Dummy { } => Dummy { },
        };
        let l = command.command_length() - l0;        
        if l > P::MAX_BETA_TAIL_LENGTH {
            unimplemented!();
        }
        self.eaten += l;
        if self.eaten >= P::BETA_LENGTH {
            unimplemented!();
        }


        match *self {
            Command::Transmit { route } => {
                .
            },
            Command::Ratchet { twig } => {
            },
            Command::CrossOver { alpha, surb_beta } => {
                unimplemented!();
            },
            Command::Contact { } => {
                unimplemented!();
            },
            Command::Greeting { } => {
                unimplemented!();
            },
            Command::Deliver { mailbox } => {
                unimplemented!();
            },
            // DropOff
            Command::ArrivalSURB { } => {
            },
            Command::ArrivalDirect { } => {
            },
            // Delete
        }
    }
*/

    /// Write fully encrypted tails `phi` to `beta`.
    ///
    /// We place the SURB for a cross over point inside `beta` so
    /// our SURB's `beta` must be shorter, so our cross over points
    /// zeros the remainder of `beta` not coming form the SURB and
    /// processes a hop.  We must plan for this zeroing behavior
    /// when creating SURBs by treating that portion of `beta` like
    /// a tail `phi` from the Sphinx paper.  We specify the initial
    /// stream cipher offset into `beta` with `offset` for this
    /// purpose.
    ///
    /// TODO: Right now, we construct these tails inside a single
    /// enlarged `beta` buffer.  We put in the commands with their
    /// `gamma` values into this same buffer as we construct the
    /// final `beta` with onion encryption.  This makes the system
    /// conceptially cleaner, but increases the stream cipher load
    /// by 25% for forward packets containing SURBs, or 75% more
    /// when creating a SURB.  We should improve performance by 
    /// returning a `Vec<Vec<u8>>` of seperate tails here, and making
    /// `create_gamma` take beta in two parts, and refactoring
    /// everything else acordingly.
    fn do_beta_tails(&mut self, mut offset: usize, mut beta_tail: &mut [u8])
      -> SphinxResult<()> {
        let mut length = beta_tail.len() - self.eaten;
        let mut tail = 0;
        let mut j = 0;
        for c in self.commands.iter() {
            tail += c.command_length();
            let g = if let Some(g) = c.get_gamma() { g } else { continue; };
            debug_assert_eq!(g,j+1);  // Test that every cipher gets used
            self.ciphers[j].xor_beta(&mut beta_tail[..length],offset,tail) ?;
            offset -= tail;
            length += tail;
            tail = 0;
            j = g;
        }
        self.ciphers[j].xor_beta(&mut beta_tail[..length],offset,0) ?;
        Ok(())
    }

    /// Write commands with correct `gamma` tags to `beta`.
    ///
    /// We store the SURB's `beta` in the `CrossOver` command,
    /// so this must consume `self.commands`, and hence it may
    /// only be called once by `done`.
    fn do_beta_with_gammas(&mut self, beta: &mut [u8]) -> SphinxResult<Gamma> {
        // We insert our newly created PreCommand<Gamma> directly
        // into `beta` and do not constrcut a Vec<PreCommand<Gamma>>.
        let mut o = self.eaten;
        let mut j = None;
        let mut tail = 0;
        while let Some(c) = self.commands.pop() {
            let l = c.command_length();
            let c: PreCommand<Gamma> = c.map_gamma( |g| {
                // Test that every cipher gets used
                debug_assert_eq!(g+1, j.unwrap_or(self.ciphers.len()) );
                j = Some(g);
                // Test that the tail gets zeroed, but only in debug mode
                if ! cfg!(test) { tail=0; }
                let beta = &mut beta[o..o+P::BETA_LENGTH+tail];
                self.ciphers[g].xor_beta(beta,0,tail) ?;
                tail=0;
                // if let Ratchet { twig, gamma } = c { ??.push(twig) }
                self.ciphers[g].create_gamma(beta)
            } ) ?;
            tail += l;
            o -= l;
            c.write_command(&mut beta[o..o+l]);
        }
        debug_assert!(j == Some(1) || j == None);
        self.ciphers[0].xor_beta(beta,0,tail) ?;
        // Test that the tail gets zeroed, but only in debug mode
        if cfg!(test) {
            assert!( beta.iter().skip(P::BETA_LENGTH).all(|x| *x==0) );
        }
        self.ciphers[0].create_gamma(&beta)
    }

    pub fn done(mut self) -> SphinxResult<NewHeader<P>> {
        let eaten = self.eaten;
        let mut beta = vec![0u8; P::BETA_LENGTH+eaten];
        if let None = self.surb_keys {
            self.rng.fill_bytes(&mut beta[eaten..P::BETA_LENGTH]);
            self.do_beta_tails(P::BETA_LENGTH, &mut beta[P::BETA_LENGTH..]) ?;
        } else {
            self.do_beta_tails(eaten, &mut beta[eaten..]) ?;
        }
        let gamma = self.do_beta_with_gammas(beta.as_mut()) ?;

        let Scaffold { route, alpha0, mut validity, surb_keys, bodies, mut advances, mut ciphers, .. } = self;

        // TODO: Fuzz validity to prevent leaking route information
        let preheader = PreHeader {
            validity: validity.clone(),
            route: route.end.clone(),
            alpha: alpha0,
            gamma,
            beta: {
                beta.truncate(P::BETA_LENGTH);
                beta.into_boxed_slice()
            },
        };

        use std::mem::replace;  // We should not need this with the above destructuring
        let surb = surb_keys.map( |surbs| surbs::DeliverySURB { 
            protocol: P::PROTOCOL_ID,
            meta: surbs::Metadata(0), // TODO: Where does this come from?
            hops: surbs
        } );
        let bodies = bodies.map( |bs| {
            bs.iter().map( |b| ciphers[*b].body_cipher() ).collect()
        } );
        for mut t in advances.drain(..) { t.confirm() ?; }
        Ok( NewHeader { preheader, surb, bodies } )
    }
}

struct NewHeader<P: Params> {
    preheader: PreHeader,
    surb: Option<surbs::DeliverySURB>, 
    bodies: Option<Vec<body::BodyCipher<P>>>
}



/// TODO: Remove Arcs
struct Client<P: Params, C: Concensus> {
    params: PhantomData<P>,

    outgoing: mailbox::OutgoingStore, 

    consensus: Arc<C>,

    surbs: Arc<surbs::SURBStore<P>>,

    // TODO: Foreign ratchets by node 
    ratchet: Arc<ClientRatchetState>,
}




