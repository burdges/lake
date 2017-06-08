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

use super::stream::{Gamma,GAMMA_LENGTH}; // GammaBytes,HeaderCipher

pub use keys::{RoutingName,RoutingPublic,Concensus};
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::commands::{PreCommand,Command};
use super::layout::{Params,ImplParams,PreHeader};
use super::error::*;
use super::*;


/// `Instruction`s are translated into sequences of `Command`s when
/// building a header.
pub enum Instruction {
    /// Transmit packet to another mix network node
    Transmit {
        route: RoutingName,
    },

    /// Advance and integrate a ratchet state
    Ratchet {
        // We considered add a Sphinx hop here too, but this makes it harder
        // to add a ratchet hop right after the first mandatory Sphinx hop.
        // route: RoutingName,
        branch: BranchId,
    },

    /// Crossover with SURB in beta
    CrossOver {
        surb: PreHeader,
    },

    /// Crossover with SURB stored on node
    Contact {
        // unimplemented!()
    },
    Greeting {
        // unimplemented!()
    },

    /// Deliver message to the specified mailbox, roughly equivelent
    /// to transmition to a non-existant mix network node.
    Deliver {
        /// Mailbox name
        mailbox: MailboxName,
    },

    /// Arrival of a SURB we created and archived.
    ArrivalSURB { },

    /// Arrival of a message for a local application.
    ArrivalDirect { },

    // DropOff { },
    // Delete { },
    // Dummy { },
}

impl Instruction {
    pub fn commands_length(&self) -> usize {
        let gamma = Gamma([0u8; GAMMA_LENGTH]);
        let p = |c: commands::CommandNode| c.command_length();
        match *self {
            Instruction::Transmit { route } =>
                p(Command::Transmit { route, gamma }),
            Instruction::Ratchet { branch } => {
                let twig = TwigId(branch,::ratchet::TwigIdx(0));
                p(Command::Ratchet { twig, gamma })
            },
            Instruction::CrossOver { surb: PreHeader { ref validity, route, alpha, gamma, ref beta } } =>
                p(Command::CrossOver { route, alpha, gamma, surb_beta: beta.len() }),
            Instruction::Contact { } =>
                p(Command::Contact { }),
            Instruction::Greeting { } => 
                p(Command::Greeting { }),
            Instruction::Deliver { mailbox } =>
                p(Command::Deliver { mailbox }),
            Instruction::ArrivalSURB { } =>
                p(Command::ArrivalSURB { }),
            Instruction::ArrivalDirect { } => 
                p(Command::ArrivalDirect { }),
            // Instruction::DropOff { } => 
            //     p(Command::DropOff { },
            // Instruction::Delete { } => 
            //     p(Command::Delete { },
            // Instruction::Dummy { } => 
            //     p(Command::Dummy { },
        }
    }
}


/// World of key material in which we build a header.
pub struct World<'a,C,P> where C: Concensus+'a, P: Params {
    params: PhantomData<P>,

    /// Network concensus information for looking up nodes.
    ///
    /// TODO: We might not need this here if RoutingPublic were
    /// supplied in `Command::Transmit::route`
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

        let rp = self.concensus.routing_named(&route) ?;
        let v = Values {
            route: route..route,
            route_public: rp.clone(),
            key: None,
            alpha0, aa, 
            delay: Duration::from_secs(0),
            validity: rp.validity.clone(),
            eaten: 0, 
        };
        let mut s = Scaffold {
            world: self.clone(),
            rng, v,
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


/// 
#[derive(Debug,Clone,Copy)]
enum SaveKeys {
    Bodies,
    SURB,
}


/// All singleton values mutated while building a header,
/// except for the random number generator.  
///
/// We include these values into both `Scaffold` and `Hoist`,
/// with those in `Hoist` being used to rollback a failed
/// transaction on the `Scaffold`.  
///
/// We cannot include the random number generator becuase they
/// lack a rollback function and any such function would be
/// inherently insecure.  As a result, any rolled backs of the 
/// `Scaffold` may prevent the resulting `PreHeader` from being 
/// regenerated from the same seed and `Instructon`s.
#[derive(Clone)]
struct Values<P: Params> {
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
    key: Option<stream::SphinxKey<P>>,

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
}

/*
impl<P> Clone for Values<P> where P: Params {
    fn clone(&self) -> Values<P> {
        let Values {
            ref route, ref route_public, ref key,
            alpha0, aa, delay, ref validity, eaten, 
        } = *self;
        Values {
            route: route.clone(),
            route_public: route_public.clone(),
            key: key.clone(),
            alpha0, aa, delay,
            validity: validity.clone(),
            eaten, 
        }
    }
}
*/

/// We build `PreHeader`s using successive operations on `Scafold`.
/// 
/// We use our first command to set `PreHeader::route` and pad
/// `PreHeader::beta` for usage in transmission or in aSURB, but
/// do not encode it into `PreHeader::beta`.
struct Scaffold<'a,R,C,P> where R: Rng+'a, C: Concensus+'a, P: Params {
    world: World<'a,C,P>,

    rng: &'a mut R,

    /// All singleton values mutated while building a header,
    /// except for the random number generator `rng`.
    /// 
    /// In future, we should fold incorporate this directly into
    /// `Scafold` via `..v` or whatever syntax emerges for that.
    v: Values<P>,

    /// `Commands` for `beta`.
    ///
    /// We interpret `gamma` for `Sphinx` and `Ratchet` commands as
    /// an index into `hops` for the next `HeaderCipher`.
    commands: Vec<PreCommand<usize>>,

    /// Ratchet advance transactions 
    ///
    /// TODO: Refactor to have only one transaction and/or support repeats?!?
    advances: Vec<AdvanceUser<'a>>,

    /// Stream ciphers for 
    ciphers: Vec<stream::HeaderCipher<P>>,

    /// Packet construction mode, either `Ok` for SURBs, or
    /// `None` for a normal forward packets. 
    /// Also, records unwinding keys and twig ids in SURB mode.
    surb_keys: Option<Vec<surbs::SURBHopKey>>,

    /// Indexes of ciphers that encrypt the body and surb log
    bodies: Option<Vec<usize>>,
}


impl<'a,R,C,P> Scaffold<'a,R,C,P>
  where R: Rng+'a, C: Concensus+'a, P: Params {
    fn intersect_validity(&mut self, other: Option<&::keys::time::ValidityPeriod>)
      -> SphinxResult<()> {
        let mut other = other.unwrap_or(&self.v.route_public.validity).clone();
        other += self.v.delay;
        self.v.validity = self.v.validity.intersect(&other)
          .ok_or( SphinxError::InternalError("Validity Error") ) ?;
        Ok(())
    }

    /// 
    fn add_route(&mut self, route: RoutingName) -> SphinxResult<&RoutingPublic> {
        if self.v.route.end != route {
            let rp = self.world.concensus.routing_named(&route) ?; // ??
            self.v.route_public = rp.clone();
            self.v.route.end = route;
        } else {
            return Err( SphinxError::InternalError("Repeated hop!") );
        }
        Ok( &self.v.route_public )
    }

    fn add_cipher(&mut self, berry_twig: Option<TwigId>)
      -> SphinxResult<usize> {
        let key = self.v.key.as_ref().expect("Cannot add cipher if no key is given!");
        let mut hop = key.header_cipher() ?;  // InternalError: ChaCha stream exceeded
        let l = self.ciphers.len();
        self.ciphers.push(hop);
        if let Some(ref mut bodies) = self.bodies { bodies.push(l); }
        if let Some(ref mut sh) = self.surb_keys {
            sh.push( surbs::SURBHopKey {
                chacha: key.chacha.clone(),
                berry_twig,
            } ); 
        }
        Ok(l)
    }

    fn add_sphinx(&mut self, route: RoutingName)
      -> SphinxResult<usize> {
        if let Some(c) = self.ciphers.last_mut() {
            // We avoid unecessary blinding by keeping `aa` one hop
            // behind and only blinding right before use.  We always
            // blind here except when called from `Scaffold::new`.
            self.v.aa.blind(& c.blinding());
            // We keep delay one hop behind as well because delays
            // only happen when packets are queued for delivery.
            // TODO: Make delays optional!
            self.v.delay += c.delay();
        } // We cannot use `map` here because the borrow checker
          // cannot tell we're borrowing different parts of `self`.
        self.add_route(route) ?; // ??
          // We cannot use the reference returned by `add_route`
          // because the borrow checker cannot tell that the immutable
          // borrow returned does not hide some mutable borrow via
          // interior mutability, ala `RefCell`.
        // TODO: Figure out how to prevent leakage via validity
        self.intersect_validity(None) ?;
        let rpoint = ::curve::Point::decompress(&self.v.route_public.public) ?;  // BadAlpha
        let ss = rpoint.key_exchange(&self.v.aa);
        self.v.key = Some(stream::SphinxKey::<P>::new_kdf(&ss, &route));
        self.add_cipher(None)
    }

    /// 
    /// FIXME: This will corrupt our tansaction !!!
    ///  We must save this somehow !!
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
        let ratchet = self.world.ratchets.get(&self.v.route_public.issuer)
          .ok_or( SphinxError::IssuerHasNoRatchet(self.v.route_public.issuer) ) ?;
        let mut advance = AdvanceUser::new(ratchet,&branch_id) ?;  // RatchetError
        let twig = {
            let key = self.v.key.as_mut().expect("Cannot add ratchet without a previous key!");
            let (twig,k) = advance.click(&SphinxSecret(key.chacha.key)) ?; // RatchetError
            key.chacha.key = k;
            twig
        };
        let i = self.add_ratchet_twig(twig) ?;
        self.advances.push(advance);
          // TODO: Refactor to have only one transaction and/or support repeats
        Ok(( twig, i ) )
    }

    pub fn add<'s: 'a>(&'s mut self) -> Hoist<'s,'a,R,C,P> {
        Hoist {
            saved_v: self.v.clone(),
            commands_len: self.commands.len(),
            advances_len: self.advances.len(),
            ciphers_len: self.ciphers.len(),
            surb_keys: self.surb_keys.clone(),
            bodies: self.bodies.clone(),
            s: self
        }
    }
}


/// A transaction to extend a `Scaffold` with additional instructions.
///
/// Holds only a mutable reference to the `Scaffold` itself,
/// along with its state saved when starting this transaction.
///
/// We save this state as a copy of the singleton values `Values`
/// along with lengths of all `Vec`s.
struct Hoist<'s,'a,R,C,P> where 'a: 's, R: Rng+'a, C: Concensus+'a, P: Params+'s {
    /// Our `Scaffold` to which we mutate to add commands.
    s: &'s mut Scaffold<'a,R,C,P>,

    /// Saved singleton values `Values` components `s.v` of our
    /// `Scaffold` for roll back.
    saved_v: Values<P>,

    /// Saved number of `Command`s recorded by our `Scaffold`
    /// when this `Hoist` transaction started.
    commands_len: usize,

    /// Saved number of ratchet `Advance` transactions recorded by our
    /// `Scaffold` when this `Hoist` transaction started.
    advances_len: usize,

    /// Saved length of `HeaderCipher`s recorded by our `Scaffold`
    /// when this `Hoist` transaction started.
    ciphers_len: usize,

    /// Saved clone of all `SURBHopKey`s ecorded by our `Scaffold`
    /// when this `Hoist` transaction started.
    ///
    /// We clone here instead of just recording the length because
    /// `add_ratchet_twig` needs to pop these off `Scaffold::surb_keys`.
    /// We expect only one of `surb_keys` and `bodies` to be non-`None`.
    surb_keys: Option<Vec<surbs::SURBHopKey>>,

    /// Saved clone of indexes of ciphers that encrypt the body and
    /// surb log
    ///
    /// We clone here instead of just recording the length because
    /// `add_ratchet_twig` needs to pop these off `Scaffold::surb_keys`.
    /// We expect only one of `surb_keys` and `bodies` to be non-`None`.
    bodies: Option<Vec<usize>>,
}


impl<'s,'a,R,C,P> Hoist<'s,'a,R,C,P>
  where 'a: 's, R: Rng+'a, C: Concensus+'a, P: Params+'s {
    /// Add `Command`(s) corresponding to the provided `Instruction`. 
    ///
    /// TODO: We 
    pub fn instruct(&mut self, instrustion: Instruction)
      -> SphinxResult<&mut Hoist<'s,'a,R,C,P>> {
        { // s
        // Destructure `self` to prevent access to saved values.
        let Hoist { ref mut s, .. } = *self;

        use arrayvec::ArrayVec;
        let mut commands = ArrayVec::<[PreCommand<usize>; 2]>::new();
        let mut eaten = 0usize;
        let mut extra = 0usize;
        let l = instrustion.commands_length();

        { // p
        let mut p = |c: PreCommand<usize>| {
            eaten += c.command_length();
            commands.push(c);
            // eaten += commands.last().unwrap().command_length();
        };
        match instrustion {
            Instruction::Transmit { route } => {
                p(Command::Transmit { route, gamma: s.add_sphinx(route) ? });
            },
            Instruction::Ratchet { branch } => {
                let (twig,gamma) = s.add_ratchet(branch) ?;
                p(Command::Ratchet { twig, gamma });
            },
            Instruction::CrossOver { surb: PreHeader { validity, route, alpha, gamma, beta } } => {
                s.intersect_validity(Some(&validity));
                extra = beta.len();
                p(Command::CrossOver { route, alpha, gamma, surb_beta: beta });
            },
            Instruction::Contact { } =>
                p(Command::Contact { }),
            Instruction::Greeting { } => 
                p(Command::Greeting { }),
            Instruction::Deliver { mailbox } =>
                p(Command::Deliver { mailbox }),
            Instruction::ArrivalSURB { } =>
                p(Command::ArrivalSURB { }),
            Instruction::ArrivalDirect { } => 
                p(Command::ArrivalDirect { }),
            // Instruction::DropOff { } => 
            //     p(Command::DropOff { },
            // Instruction::Delete { } => 
            //     p(Command::Delete { },
            // Instruction::Dummy { } => 
            //     p(Command::Dummy { },
        }
        } // p

        debug_assert_eq!(l,eaten);
        if eaten - extra  > P::MAX_BETA_TAIL_LENGTH {
            return Err( SphinxError::InternalError("Command exceeded beta tail length") );
        }
        if s.v.eaten + eaten >= P::BETA_LENGTH {
            return Err( SphinxError::InternalError("Commands exceed length of beta") );
        }
        s.v.eaten += eaten;
        s.commands.extend(commands.drain(..));

        } // s
        Ok(self)
    }

    /// Destructure the `Hoist` to avoid drop, thereby avoiding
    /// the roll back build into `Hoist`'s as `Drop`.
    pub fn approve(mut self) {
        let Hoist { .. } = self;
        // We could use `::std::mem::forget(self)` but this assumes
        // the `Host` itself contains no `Drop` types, which might
        // change in future.
    }
}

impl<'s,'a,R,C,P> Drop for Hoist<'s,'a,R,C,P>
  where 'a: 's, R: Rng+'a, C: Concensus+'a, P: Params+'s {
    /// Roll back the transaction represented by this `Hoist` if
    /// not consumed by `Hoist::approve`.
    ///
    /// We can truncate an `Option<Vec<T>>` back to `None`.
    /// There is no way to repair an `Option<Vec<T>>` converted into
    /// `None` though, so no transaction may do that.
    fn drop(&mut self) {
        let Hoist { ref mut s, ref saved_v, commands_len, advances_len, ciphers_len, ref mut surb_keys, ref mut bodies } = *self;
        s.v.clone_from(saved_v);
        s.commands.truncate(commands_len);
        s.advances.truncate(advances_len);
        s.ciphers.truncate(ciphers_len);
        ::std::mem::swap(&mut s.surb_keys, surb_keys);
        ::std::mem::swap(&mut s.bodies, bodies);
    }
}


impl<'a,R,C,P> Scaffold<'a,R,C,P>
  where R: Rng+'a, C: Concensus+'a, P: Params {
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
        let mut length = beta_tail.len() - self.v.eaten;
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
        let mut j = None;  // Previous ciphers index for testing in debug mode.
        let mut o = self.v.eaten;
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
        let eaten = self.v.eaten;
        let mut beta = vec![0u8; P::BETA_LENGTH+eaten];
        if let None = self.surb_keys {
            self.rng.fill_bytes(&mut beta[eaten..P::BETA_LENGTH]);
            self.do_beta_tails(P::BETA_LENGTH, &mut beta[P::BETA_LENGTH..]) ?;
        } else {
            // Padding ??
            // self.rng.fill_bytes(&mut beta[eaten..???]);
            self.do_beta_tails(eaten, &mut beta[eaten..]) ?;
        }
        let gamma = self.do_beta_with_gammas(beta.as_mut()) ?;

        let Scaffold { v, surb_keys, bodies, mut advances, mut ciphers, .. } = self;
        let Values { route, alpha0, mut validity, .. } = v;

        // TODO: Fuzz validity to prevent leaking route information
        let preheader = PreHeader {
            validity: validity.clone(),
            route: route.start.clone(),
            alpha: alpha0,
            gamma,
            beta: {
                beta.truncate(P::BETA_LENGTH);
                beta.into_boxed_slice()
            },
        };

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




