// Copyright 2016 Jeffrey Burdges.

//! Sphinx component of Xolotl
//!
//! ...

use std::sync::Arc; // RwLock, RwLockReadGuard, RwLockWriteGuard
use std::marker::PhantomData;
use std::time::{Duration}; // SystemTime, UNIX_EPOCH

use rand::{Rng, Rand, ChaChaRng, SeedableRng};

use ratchet::{BranchId,TwigId,Transaction,AdvanceUser}; // BRANCH_ID_LENGTH,TWIG_ID_LENGTH
pub use ratchet::ClientState as ClientRatchetState;

pub use keys::{RoutingName,RoutingPublic,Concensus};
pub use super::mailbox::{MailboxName,MAILBOX_NAME_LENGTH};
use super::commands::{PreCommand,Command,Instruction};
use super::layout::{Params,PreHeader}; // ImplParams
use super::error::*;
use super::*;



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

/// We cannot `#[derive(Clone)]` if we need a where clause.
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

    pub fn build_headers<R: Rng>(&self, rng: R) -> BuildScaffold<'a,C,P,R> {
        BuildScaffold {
            world: self.clone(),  rng,
            orientation: Orientation::Send { bodies: Vec::new() },
            capacity: P::max_hops_capacity() / 2,
        }
    }
}


/// Builds the `Scaffold`s with which we build headers.
pub struct BuildScaffold<'a,C,P,R> where C: Concensus+'a, P: Params, R: Rng {
    pub world: World<'a,C,P>,

    /// Random number generator used for building header
    /// TODO: How should we deal with this and its seeds? 
    pub rng: R,

    /// Initial header orientation.
    orientation: ScaffoldOrientation,

    pub capacity: usize,
}

impl<'a,C,P,R> BuildScaffold<'a,C,P,R> where C: Concensus+'a, P: Params, R: Rng {
    /// Spawns a new `Scaffold` builder with a specified random number
    /// generator.
    pub fn spawn<R0: Rng>(&self, rng: R0) -> BuildScaffold<'a,C,P,R0> {
        BuildScaffold {
            world: self.world.clone(),  rng,
            orientation: self.orientation.clone(),
              // No allocation here so long as `Vec::capacity()` stays zero.
            capacity: self.capacity,
        }
    }

    /// Spawn a new `Scaffold` builder by seeding a new `Rng` with 
    /// output form `self.rng`. 
    pub fn fork<S, Seed, R0>(&mut self) -> (BuildScaffold<'a,C,P,R0>, Seed) 
      where S: ?Sized,
            Seed: Rand + AsRef<S>,
            R0: Rng + for<'x> SeedableRng<&'x S> {
        let seed: Seed = self.rng.gen();
        (self.spawn(R0::from_seed(seed.as_ref())), seed)
    }

    /// Spawn a new `Scaffold` builder based on `ChaChaRng` by
    /// first generating its `[u32; 8]` seed from `self.rng`.
    pub fn fork_chacha(&mut self) -> (BuildScaffold<'a,C,P,ChaChaRng>, [u32; 8])
      { self.fork::<[u32],[u32; 8],ChaChaRng>() }

    /// Avoid excess allocations when preparing a sending header
    /// that is neither a SURB itself, nor crosses over to a SURB.
    /// We set capacity to half this by default in `build_headers`.
    pub fn long(mut self) -> BuildScaffold<'a,C,P,R>
      { self.capacity = P::max_hops_capacity(); self.make_send() }

    /// Prepare a `Send` header for sending messges.
    pub fn make_send(mut self) -> BuildScaffold<'a,C,P,R>
      { self.orientation = Orientation::Send { bodies: Vec::new() }; self }

    /// Prepare a `SURB` header for recieving messges.
    pub fn make_surb(mut self) -> BuildScaffold<'a,C,P,R>
      { self.orientation = Orientation::SURB { surb_keys: Vec::new() }; self }

    /// Produce the `Scaffold` with which we build one header.
    fn go(self, route: RoutingName) -> SphinxResult<Scaffold<'a,C,P,R>> {
        let BuildScaffold { world, mut rng, mut orientation, capacity } = self;

        let aa = rng.gen();
        let alpha0 = ::curve::Point::from_secret(&aa).compress();
        // TODO: Any tests for alpha?  ::curve::Point::decompress(&alpha) ?;

        let rp = world.concensus.routing_named(&route) ?;
        let v = Values {
            route: route..route,
            route_public: rp.clone(),
            key: None,
            alpha0, aa, // seed,
            delay: Duration::from_secs(0),
            validity: rp.validity.clone(),
            eaten: 0, 
        };

        orientation.reserve(capacity);
        let mut s = Scaffold {
            world: world.clone(),
            rng, v, orientation,
            commands: Vec::with_capacity(capacity),
            advances: Vec::with_capacity(capacity),
            ciphers: Vec::with_capacity(capacity+1),
        };
        s.add_sphinx(route) ?;
        Ok( s )
    }
}


pub trait SURBKeys { }
impl SURBKeys for surbs::DeliverySURB { }
impl SURBKeys for Vec<surbs::SURBHopKey> { }

pub trait BodyCipherish { }
impl BodyCipherish for usize { }
impl<P: Params> BodyCipherish for body::BodyCipher<P> { }

pub trait BodyCiphers { }
impl<B: BodyCipherish> BodyCiphers for Vec<B> { }

/// An `Orientation` used during building a header with a `Scaffold`
/// provides direct access to `Vec`s that reference key material.
type ScaffoldOrientation = Orientation<Vec<usize>, Vec<surbs::SURBHopKey>>;

/// An `Orientation` returned by `Scaffold::done` along with a completed 
/// `PreHeader` provides exactly the needed key material encapsulated 
/// for usage or storage.
pub type HeaderOrientation<P> = Orientation<Vec<body::BodyCipher<P>>, surbs::DeliverySURB>;

/// Packet construction orientation. 
///
/// determines cryptographic material for  ????
#[derive(Clone)]
pub enum Orientation<BCs: BodyCiphers,SKs: SURBKeys> {
    // Unknown { surb_keys: SKs, bodies: BCs },

    /// An outgoing packet whose construction collects `BodyCipher`s
    /// to encrypt an outgoing body.
    ///
    /// We take `B` to be `usize` to collect the indexes of the
    /// `HeaderCipher`s that encrypt the body.
    Send { bodies: BCs },

    /// A returning packet whose construction collects `SURBHopKey`s
    /// for SURB unwinding.
    SURB { surb_keys: SKs },

    /// A packet that acts first as an outgoing packet and later
    /// as returning packet, so its construction collects first.
    /// `BodyCipher`s and then `SURBHopKey`s for SURB unwinding.
    SendAndSURB { surb_keys: SKs, bodies: BCs },
}

impl<BCs: BodyCiphers,SKs: SURBKeys> Orientation<BCs,SKs> {
    /// Run closures on both whichever of `Orientation` exist.
    fn map<BCs1,SKs1,BCM,SKM>(self, mut bcm: BCM, mut skm: SKM) -> Orientation<BCs1,SKs1>
      where BCs1: BodyCiphers,
            SKs1: SURBKeys,
            BCM: FnMut(BCs) -> BCs1,
            SKM: FnMut(SKs) -> SKs1 {
        use self::Orientation::*;
        match self {
            // Unknown { surb_keys, bodies } => 
            //     Unknown { surb_keys: skm(surb_keys), bodies: bcm(bodies) },
            Send { bodies } => Send { bodies: bcm(bodies) },
            SURB { surb_keys } => SURB { surb_keys: skm(surb_keys) },
            SendAndSURB { surb_keys, bodies } => 
                SendAndSURB { surb_keys: skm(surb_keys), bodies: bcm(bodies) },
        }
    }
}

impl ScaffoldOrientation {
    /// Run approporaite closure on whichever member `Vec` currently
    /// collects key material.
    fn do_active<BCM,SKM>(&mut self, bcm: BCM, skm: SKM)
      where BCM: FnOnce(&mut Vec<usize>),
            SKM: FnOnce(&mut Vec<surbs::SURBHopKey>) {
        use self::Orientation::*;
        match *self {
            // Unknown { surb_keys, bodies } => { skm(surb_keys); bcm(bodies); },
            Send { ref mut bodies } => bcm(bodies),
            SURB { ref mut surb_keys } => skm(surb_keys),
            SendAndSURB { ref mut surb_keys, .. } => skm(surb_keys),
        }
    }

    fn reserve(&mut self, additional: usize) {
        self.do_active(
            |bodies| bodies.reserve(additional), 
            |surb_keys| surb_keys.reserve(additional) 
        );
    }

    fn pop(&mut self) {
        self.do_active(
            |bodies| { bodies.pop(); },
            |surb_keys| { surb_keys.pop(); } 
        );
    }

    fn push(&mut self, bci: usize, surb_key: surbs::SURBHopKey) {
        self.do_active( 
            |bodies| bodies.push(bci), 
            |surb_keys| surb_keys.push(surb_key) 
        );
    }

    fn do_send_and_surb(&mut self) -> SphinxResult<()> {
        use self::Orientation::*;
        let bodies = match *self {
            // Unknown { .. } => Err("Can only transition to SendAndSURB from Send, not Unknown."),
            Send { ref mut bodies } => Ok( ::std::mem::replace(bodies, Vec::new()) ),
            SURB { .. } => Err("Can only transition to SendAndSURB from Send, not SURB."),
            SendAndSURB { .. } => Err("Can only transition to SendAndSURB from Send, not Unknown"),
        }.map_err( |s| SphinxError::InternalError(s) ) ?;
        let surb_keys = Vec::with_capacity( bodies.capacity() ); // TODO: Assume equal!!
        *self = SendAndSURB { bodies, surb_keys };
        Ok(())
    }
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

/// We build `PreHeader`s using successive operations on `Scaffold`.
/// 
/// We use our first command to set `PreHeader::route` and pad
/// `PreHeader::beta` for usage in transmission or in aSURB, but
/// do not encode it into `PreHeader::beta`.
pub struct Scaffold<'a,C,P,R>
  where C: Concensus+'a, P: Params, R: Rng {
    pub world: World<'a,C,P>,

    pub rng: R,

    /// All singleton values mutated while building a header,
    /// except for the random number generator `rng`.
    /// 
    /// In future, we should fold incorporate this directly into
    /// `Scaffold` via `..v` or whatever syntax emerges for that.
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

    /// Header orientation along with associated key material.
    /// 
    /// A sending packet records the indexes of header ciphers that
    /// encrypt the body and surb log. A recieving packet records the
    /// `SURBHopKey`s used for SURB unwinnding, which consist of keys
    /// and twig ids.
    orientation: ScaffoldOrientation,
}


impl<'a,C,P,R> Scaffold<'a,C,P,R>
  where C: Concensus+'a, P: Params, R: Rng {
    pub fn capacity(&self) -> usize { self.commands.capacity() }

    pub fn reserve(&mut self, additional: usize) {
        self.commands.reserve(additional);
        self.advances.reserve(additional);
        self.ciphers.reserve(additional);
        self.orientation.reserve(additional);
    }

    fn intersect_validity(&mut self, other: Option<&::keys::time::ValidityPeriod>)
      -> SphinxResult<()> {
        let mut other = other.unwrap_or(&self.v.route_public.validity).clone();
        other += self.v.delay;
        self.v.validity = self.v.validity.intersect(&other)
          .ok_or( SphinxError::InternalError("Validity Error") ) ?;
        Ok(())
    }

    /// Add routing information for a Sphinx sub-hop.
    ///
    /// We only call this from `add_sphinx` but it provides a handy
    /// place to seperate out the concensus database access.  
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

    /// Add a `HeaderCipher` derived from `key` to `ciphers` and
    /// update `surb_keys` and `bodies` accordingly for both body
    /// building and SURB unwinding of the body and SURB log. 
    ///
    /// We call this from both `add_sphinx` and `add_ratchet`, so
    /// it handles possibly removing ciphers that a ratchet superceeds
    /// for processing the body and SURB log.
    fn add_cipher(&mut self, berry_twig: Option<TwigId>)
      -> SphinxResult<usize> {
        // We only decrypt the body and SURB logs with the most secure
        // key produced in `node::Router::do_crypto`, so if we add a
        // ratchet sub-hop then we must first remove the key for the
        // preceeding Sphinx sub-hop before adding the key for the
        // ratchet sub-hop.
        if let Some(..) = berry_twig { self.orientation.pop(); }

        let key = self.v.key.as_ref().expect("Cannot add cipher if no key is given!");
        let hop = key.header_cipher() ?;  // InternalError: ChaCha stream exceeded
        let l = self.ciphers.len();
        self.ciphers.push(hop);
        let chacha = key.chacha.clone();
        self.orientation.push(l, surbs::SURBHopKey { chacha, berry_twig });
        Ok(l)
    }

    fn add_sphinx(&mut self, route: RoutingName)
      -> SphinxResult<usize> {
        if let Some(c) = self.ciphers.last_mut() {
            // We avoid unecessary blinding or needing `aa` to be a
            // `Vec<::curve::Scalar>` by keeping `aa` one hop behind
            // and only blinding right before use.  We always blind
            // here except when called from `Scaffold::new`.
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
        let i = self.add_cipher( Some(twig) ) ?;
        self.advances.push(advance);
          // TODO: Refactor to have only one transaction and/or support repeats
        Ok(( twig, i ) )
    }

    pub fn add<'s: 'a>(&'s mut self) -> Hoist<'s,'a,C,P,R> {
        Hoist {
            saved_v: self.v.clone(),
            commands_len: self.commands.len(),
            advances_len: self.advances.len(),
            ciphers_len: self.ciphers.len(),
            orientation: self.orientation.clone(),
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
pub struct Hoist<'s,'a,C,P,R>
  where 'a: 's, C: Concensus+'a, P: Params+'s, R: Rng+'s {
    /// Our `Scaffold` to which we mutate to add commands.
    s: &'s mut Scaffold<'a,C,P,R>,

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

    /// Saved clone of header orientation along with associated key
    /// material encoded by our `Scaffold` when this `Hoist`
    /// transaction started.
    ///
    /// A sending packet records the indexes of ciphers that encrypt
    /// the body and surb log. A recieving packet records the keys
    /// and twig ids used in for SURB unwinnding.
    orientation: ScaffoldOrientation,
}


impl<'s,'a,C,P,R> Hoist<'s,'a,C,P,R>
  where 'a: 's, C: Concensus+'a, P: Params+'s, R: Rng+'s {
    /// Add `Command`(s) corresponding to the provided `Instruction`. 
    ///
    /// TODO: We 
    pub fn instruct(&mut self, instrustion: Instruction)
      -> SphinxResult<&mut Hoist<'s,'a,C,P,R>> {
        { // s
        // Destructure `self` to prevent access to saved values.
        let Hoist { ref mut s, .. } = *self;

        use arrayvec::ArrayVec;
        let mut commands = ArrayVec::<[PreCommand<usize>; 2]>::new();
        let mut eaten = 0usize;
        let mut extra = 0usize;
        let l = instrustion.beta_length();

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
                s.intersect_validity(Some(&validity)) ?;
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
    pub fn approve(self) {
        let Hoist { .. } = self;
        // We could use `::std::mem::forget(self)` but this assumes
        // the `Host` itself contains no `Drop` types, which might
        // change in future.
    }
}

impl<'s,'a,C,P,R> Drop for Hoist<'s,'a,C,P,R>
  where 'a: 's, C: Concensus+'a, P: Params+'s, R: Rng+'s {
    /// Roll back the transaction represented by this `Hoist` if
    /// not consumed by `Hoist::approve`.
    ///
    /// We can truncate an `Option<Vec<T>>` back to `None`.
    /// There is no way to repair an `Option<Vec<T>>` converted into
    /// `None` though, so no transaction may do that.
    fn drop(&mut self) {
        let Hoist { ref mut s, ref saved_v, commands_len, advances_len, ciphers_len, ref mut orientation } = *self;
        s.v.clone_from(saved_v);
        s.commands.truncate(commands_len);
        s.advances.truncate(advances_len);
        s.ciphers.truncate(ciphers_len);
        ::std::mem::swap(&mut s.orientation, orientation);
    }
}


impl<'a,C,P,R> Scaffold<'a,C,P,R>
  where C: Concensus+'a, P: Params, R: Rng {
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
    fn do_beta_tails(&mut self, mut offset: usize, beta_tail: &mut [u8])
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
    fn do_beta_with_gammas(&mut self, beta: &mut [u8]) -> SphinxResult<stream::Gamma> {
        // We insert our newly created PreCommand<Gamma> directly
        // into `beta` and do not constrcut a Vec<PreCommand<Gamma>>.
        let mut j = None;  // Previous ciphers index for testing in debug mode.
        let mut o = self.v.eaten;
        let mut tail = 0;
        while let Some(c) = self.commands.pop() {
            let l = c.command_length();
            let c: PreCommand<stream::Gamma> = c.map_gamma( |g| {
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
        match self.orientation {
            // Unknown {..} => return Err( SphinxError::InternalError("Cannot build header without knowing if sending or recieving") );
            Orientation::Send {..} | Orientation::SendAndSURB {..} => {
                self.rng.fill_bytes(&mut beta[eaten..P::BETA_LENGTH]);
                self.do_beta_tails(P::BETA_LENGTH, &mut beta[P::BETA_LENGTH..]) ?;
            },
            Orientation::SURB {..} => {
                // Padding ??
                // self.rng.fill_bytes(&mut beta[eaten..???]);
                self.do_beta_tails(eaten, &mut beta[eaten..]) ?;
            },
        }
        let gamma = self.do_beta_with_gammas(beta.as_mut()) ?;

        let Scaffold { v, orientation, mut advances, mut ciphers, .. } = self;
        let Values { route, alpha0, validity, .. } = v;

        // TODO: Fuzz validity to prevent leaking route information
        let preheader = PreHeader {
            validity: validity,
            route: route.start,
            alpha: alpha0,
            gamma,
            beta: {
                beta.truncate(P::BETA_LENGTH);
                beta.into_boxed_slice()
            },
        };

        let orientation = orientation.map(
            |bs| { bs.iter().map( |b| ciphers[*b].body_cipher() ).collect() },
            |surbs| surbs::DeliverySURB {
                protocol: P::PROTOCOL_ID,
                meta: surbs::Metadata(0), // TODO: Where does this come from?
                hops: surbs
            }
        );
        for mut t in advances.drain(..) { t.confirm() ?; }
        Ok( NewHeader { preheader, orientation } )
    }
}


// Do we want to expose HeaderOrientation like this?
pub struct NewHeader<P: Params> {
    preheader: PreHeader,
    orientation: HeaderOrientation<P>,
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




