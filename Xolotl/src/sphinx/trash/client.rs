




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
        let orientation = if make_surb {
            Orientation::SURB { surb_keys: Vec::with_capacity(capacity) }
        } else {
            Orientation::Send { bodies: Vec::with_capacity(capacity) }
        };
        let mut s = Scaffold {
            world: self.clone(),
            rng, v, orientation,
            commands: Vec::with_capacity(capacity),
            advances: Vec::with_capacity(capacity),
            ciphers: Vec::with_capacity(capacity+1),
        };
        s.add_sphinx(route) ?;
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






        use self::Orientation::*;
        let orientation = match self.orientation {
            SURB {..} => SURB { surb_keys: Vec::with_capacity(capacity) }
            Send {..} => Send { bodies: Vec::with_capacity(capacity) }
            _ => return Err( SphinxError::InternalError("We must begin packet consgtruction with an orientation of either Send or SURB.") ),
        };






/*
pub struct BuildScaffold<'a,R,C,P>
  where R: Rng+'a, C: Concensus+'a, P: Params {
    world: World<'a,C,P>,

    rng: &'a mut R,

    /// All singleton values mutated while building a header,
    /// except for the random number generator `rng`.
    v: Values<P>,

    pub capacity: usize,

    /// Initial header orientation.
    orientation: ScaffoldOrientation,
}
    
impl<'a,R,C,P> PreScaffold<'a,R,C,P>
  where R: Rng+'a, C: Concensus+'a, P: Params {
    fn make_surb(&mut self) {
        self.orientation = Orientation::SURB { surb_keys: Vec::new() }
    }

    fn go(mut self) -> SphinxResult<Scaffold<'a,R,C,P>> {
        let PreScaffold { world, rng, v, capacity, orientation } = self;
        orientation.reserve(capacity);
        let mut s = Scaffold {
            world: self.clone(),
            rng, v, orientation,
            commands: Vec::with_capacity(capacity),
            advances: Vec::with_capacity(capacity),
            ciphers: Vec::with_capacity(capacity+1),
        };
        s.add_sphinx(route) ?;
        Ok( s )
    }
}

/// We convert an `InitialOrientation`
pub enum InitialOrientation {
    /// An outgoing packet whose construction collects `BodyCipher`s
    /// to encrypt an outgoing body.  Can result in `Send` or `SendAndSURB`
    Send,

    /// A returning packet whose construction collects `SURBHopKey`s
    /// for SURB unwinding.
    SURB,
}

pub const SEND : InitialOrientation = InitialOrientation::Send;
pub const SURB : InitialOrientation = InitialOrientation::SURB;
*/







    fn map_bodies<P,F>(self, f: F) -> ScaffoldOrientation<body::BodyCipher<P>>
      where P: Params, F: FnMut(usize) -> body::BodyCipher<P> {
        let g = |bodies| bodies.iter().map( |b| f(b) ).collect();
        match self {
            Unknown { surb_keys, bodies } => {
                surb_keys, bodies: g(bodies),
            },
            Send { bodies } => Send { bodies: g(bodies) },
            SURB { surb_keys } => SURB { surb_keys },
            SendAndSURB { surb_keys, bodies } => SendAndSURB {
                surb_keys, bodies: g(bodies),
            },
        }
    }









impl Orientation<usize> {
    pub fn reserve(&mut self, additional: usize) {
        match *self {
            Unknown { ref mut surb_keys, ref mut bodies } => {
                surb_keys.reserve(additional);
                bodies.reserve(additional);
            },
            Send { ref mut bodies } => bodies.reserve(additional),
            SURB { ref mut surb_keys } => surb_keys.reserve(additional),
            SendAndSURB { ref mut surb_keys, ref mut bodies } => surb_keys.reserve(additional),
        }
    }

    fn pop(&mut self) {
        match *self {
            Unknown { ref mut surb_keys, ref mut bodies } => {
                surb_keys.pop();
                bodies.pop();
            },
            Send { ref mut bodies } => bodies.pop(),
            SURB { ref mut surb_keys } => surb_keys.pop(),
            SendAndSURB { ref mut surb_keys, ref mut bodies } => surb_keys.pop(),
        }
    }

    fn push(&mut self, bci: usize, surb_key: surbs::SURBHopKey) {
        match *self {
            Unknown { ref mut surb_keys, ref mut bodies } => {
                surb_keys.push(surb_key);
                bodies.push(bci);
            },
            Send { ref mut bodies } => bodies.push(bci),
            SURB { ref mut surb_keys } => surb_keys.push(surb_key),
            SendAndSURB { ref mut surb_keys, ref mut bodies } => surb_keys.push(surb_key),
        }
    }

    fn doSendAndSURB(&mut self) -> SphinxResult<()> {
        let surb_keys = match *self {
            Unknown { .. } => Err("Can only transition to SendAndSURB from Send, not Unknown."),
            Send { ref mut bodies } => Err("Can only transition to SendAndSURB from Send, not SURB."),
            SURB { ref mut surb_keys } => ::std::mem::replace(surb_keys, Vec::new()),
            SendAndSURB { .. } => Err("Can only transition to SendAndSURB from Send, not Unknown"),
        }.map_err( |s| SphinxError::InternalError(s) ) ?;
        let bodies = Vec::with_capacity( surb_keys.capacity() ); // TODO: Assume equal!!
        *self = SendAndSURB { bodies, surb_keys };
        Ok(())
    }

    fn map_bodies<P,F>(self, f: F) -> Orientation<body::BodyCipher<P>>
      where P: Params, F: FnMut(usize) -> body::BodyCipher<P> {
        let g = |bodies| bodies.iter().map( |b| f(b) ).collect();
        match self {
            Unknown { surb_keys, bodies } => {
                surb_keys, bodies: g(bodies),
            },
            Send { bodies } => Send { bodies: g(bodies) },
            SURB { surb_keys } => SURB { surb_keys },
            SendAndSURB { surb_keys, bodies } => SendAndSURB {
                surb_keys, bodies: g(bodies),
            },
        }
    }
}








impl<B: BodyCipherish> Orientation<B> {
    fn pop(&mut self) {
        let r = match *self {
            Send(ref mut v) => { v.pop(); return },
            SURB(ref mut v) => { v.pop(); return },
            SendNSURB(ref mut v, ref mut o) => {
                v.pop();
                if v.is_empty() {
                    Orientation::Send( ::std::mem::replace(o,Vec::new()) )
                } else { return }
            },
        }
        *self = r;
    }
}









        fn rb_opt_vec<T>(saved: Option<usize>, t: &mut Option<Vec<T>>) {
            if let Some(l) = saved {
                debug_assert!( t.is_some() );
                t.as_mut().map( |z| z.truncate(l) );
            } else { *t = None; }
        }
        rb_opt_vec(surb_keys_len, &mut s.surb_keys);
        rb_opt_vec(bodies_len, &mut s.bodies);






















    fn do_gammas(&mut self, beta: &mut [u8])
      -> SphinxResult<()> {
        // We insert our newly created PreCommand<Gamma> directly
        // into `beta` and do not constrcut a Vec<PreCommand<Gamma>>.
        let mut o = self.eaten;
        let beta = |n: usize| &mut self.beta[o..o+P::BETA_LENGTH+n];
        let mut y = None;
        for c in self.commands.iter().rev() {
            let l = c.length_as_bytes();
            let c: PreCommand<Gamma> = c.map_gamma( |g| {
                // y.map_or(Ok(()), |j| self.ciphers[j].xor_beta(beta(l),false) ) ?;
                if let Some(j) = y {
                    debug_assert_eq!(g+1,j);
                    self.ciphers[j].xor_beta(beta(l),0,0) ?;
                }
                y = Some(g);
                // if let Ratchet { twig, gamma } = c { r.push(twig) }
                self.ciphers[g].create_gamma(beta(0))
            } ) ?;
            o -= l;
            c.put_bytes(beta(l));  // CLEAN UP
        }
        if let Some(g) = y {
            self.ciphers[g].xor_beta(beta(),0,0) ?;
        } else { return Err( SphinxError::WTF("No Transmit commands!") ); }
    }















/// ...
///
/// ... specifies either the next hop, final delivery 
pub enum Activity {
    Sphinx {
        route: RoutingName,
    },
    Ratchet {
        route: RoutingName,
        branch: BranchId,
    },
    FromCrossOver {
        route: RoutingName,
    },

    // DropOff { },

    // Final activities

    Dummy { },

    /// Embed SURB into beta and use at the crossover point specified
    CrossOver {
        surb: PreHeader
    },

    /// Consume a SURB at the contact point specified
    Contact {
        route: RoutingName,
        // id
    },

    /// Consume a SURB at the greeting point specified
    Greeting {
        route: RoutingName,
        // id
    },

    /// Deliver message to the specified mailbox, roughly equivelent
    /// to transmition to a non-existant mix network node.
    Deliver {
        mailbox: MailboxName,
    },

    /// Arrival of a SURB we created and archived.
    ArrivalSURB { },

    /// Arrival of a message for a local application.
    ArrivalDirect { },

    // Delete { },
}


impl Activity {
    /// Are we allowed as the initial `Activity` in route building?
    ///
    ///
    pub fn is_initial(&self) -> bool {
        use self::Activity::*;
        match *self {
            FromCrossOver {..} => true,
            Sphinx {..} | Ratchet {..} => true,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => false,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => false,
            // Delete {} | DropOff {} => false,
        }
    }

    /// Are we allowed as the final `Activity` in route building?
    ///
    /// Packets will be processed correctly without a valid final,
    /// but they likely do nothing except move ratchets.
    pub fn is_final(&self) -> bool {
        use self::Activity::*;
        match *self {
            FromCrossOver {..} => false,
            Sphinx {..} | Ratchet {..} => false,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => true,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => true,
            // Delete {} => true
            // DropOff {} => false,
        }
    }

    pub fn<F> feed_commands(self, f: &mut F) -> SphinxResult<()>
      where F: FnMut(PreCommand<()>) {
        let gamma = ();
        match *self {
            Sphinx { route } => {
                f(Transmit { route, gamma });
            },

            Ratchet { route, branch } => {
                f(Transmit { route, gamma });
                let twig = unimplemented!();
                f(Ratchet { twig, gamma });
            },

            FromCrossOver { route } => {
                // unimplemented!();
            },

            // DropOff { },

            // Final activities

            Dummy { } => {
                unimplemented!(); // f(Dummy { });
            },

            CrossOver { surb: PreHeader { validity, route, alpha, gamma, beta } } => {
                unimplemented!();
                // TODO Check validity
                // TODO Check route
                f(CrossOver { alpha, gamma, beta });
            },

            /// Consume a SURB at the contact point specified
            Contact { route } => {
                unimplemented!();
                // TODO Check validity
                // TODO Everything else
            },

            /// Consume a SURB at the greeting point specified
            Greeting { route } => {
                unimplemented!();
                // TODO Check validity
                // TODO Everything else
            },

            Deliver { mailbox } => {
                unimplemented!();
            },

            ArrivalSURB { } => {
                f(ArrivalSURB { });
            },

            ArrivalDirect { } => {
                f(ArrivalDirect { });
            },

            // Delete { ... } => {
            //    f(Delete { ... });
            // },
        }
    }
}


enum Scafold<P: Params> {
}





















/// A `Directive` consists of a routing `Command` along with
/// contextual cryptographic details for prepending [the next] to
/// `PreHeader::beta` and recording any local records.

struct KC<P: Params> {  // CKC Prescript Instructions Pescription
    key: SphinxKey<P>,
    hop: ,
}






a -> AlphaBytes
    pub fn(a,Activity) -> (a,[Command<P>],Box<[u8]>)


impl Activity 


Activities -> (Alpha,Idx,Keys,..,Transaction)

activities.zip(keys) -> 

ActivitiesKey

impl<P: Params>  Client<P> {
}

    activities: &'a [Activity],

/*
impl Activities {
    pub fn make_header(&self) -> Header {
    }
}
*/














    /// Are we allowed as the initial `Activity` in route building?
    ///
    /// 
    pub fn is_initial(act: &Activity) -> bool {
        use self::Activity::*;
        match *act {
            FromCrossOver {..} => true,
            Sphinx {..} | Ratchet {..} => true,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => false,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => false,
            // Delete {} | DropOff {} => false,
        }
    }

    /// Are we allowed as the final `Activity` in route building?
    ///
    /// Packets will be processed correctly without a valid final,
    /// but they likely do nothing except move ratchets. 
    pub fn is_final(act: &Activity) -> bool {
        use self::Activity::*;
        match *act {
            FromCrossOver {..} => false,
            Sphinx {..} | Ratchet {..} => false,
            CrossOverBeta {..} | CrossOverContact {..} | CrossOverGreeting {..} => true,
            Deliver {..} | ArrivalSURB {} | ArrivalDirect {} => true,
            // Delete {} => true
            // DropOff {} => false,
        }
    }

    ;



















/*

    let replayer = RwLock::new(IgnoreReplays);
    let nt = NodeToken::generate(params,concensus,node);
    let mut hop = SphinxHop::new(params,&replayer,&nt,s);



    create_gamma(&mut self, beta: &Beta, gamma_out: &mut Gamma) {

*/

/*









fn mac()



fn kdf_sphinx(npk: NodeKey, alpha: Alpha, s: SphinxSecret)
        -> (MessageKey, LeafKey) {
    let mut r = [0u8; 32+16];
    debug_assert_eq!(::std::mem::size_of_val(&r),
      ::std::mem::size_of::<(MessageKey, LeafKey)>());
    // let mut r: (MessageKey, LeafKey) = Default::default();
    // debug_assert_eq!(mem::size_of_val(&r), 384/8);
    let mut sha = Sha3::sha3_384();

    sha.input_str( TIGER[4] );
    sha.input(&iter.name.0);
    sha.input(&linkkey.0);
    sha.input_str( TIGER[5] );
    sha.input(&s.0);
    sha.input(&iter.extra.0);
    sha.input_str( TIGER[6] );
    sha.input(&s.0);
    sha.input(&linkkey.0);
    sha.input_str( TIGER[7] );
    sha.result(&mut r);
    // sha.result(
    //   unsafe { mem::transmute::<&mut (MessageKey, SphinxSecret),&mut [u8;32+16]>(&mut r) } 
    // );
    sha.reset();

    // (MessageKey(r[0..31]), LeafKey(r[32..47]))
    let (a,b) = array_refs![&r,32,16];
    (MessageKey(*a), LeafKey(*b))
    // r
}





fn kdf_sphinx(npk,alpha,s: &[u8]) -> [u8; 64] {
    let r: [u8; 64];
    let sha = Sha3::sha3_512;
    sha.input(alpha);
    sha.input(s);
    sha.input(npk);
    sha.input(alpha);   
    sha.input(s);
    sha.input(npk);
    sha.result(r);
    sha.reset();
    r
}



//  let mut cc = ChaCha20::new(header_key, [0u8; 12]);



type K = [u8; 32];

fn curve25519_fixbits(e: &mut [u8]) {
    // Zero bottom three bits, so that 2, 4, and 8 do not divide e.
    // Protects against active small subgroup attacks
    e[0] &= 248;
    // Clear above high bit.
    e[31] &= 127;
    // Set high bit to simplify timing
    e[31] |= 64;
}

fn create_alphas_fun(a0: &[u8], nodekeys: &[NodeKeys],) ->  ([K; MAXHOPS+1],[K; MAXHOPS]) {
    let mut alphas: [K; MAXHOPS+1];
    let mut ss: [K; MAXHOPS];
    alphas[0] = curve25519_base(a0);
    let mut a = a0;
    for (n,i) in nodekeys.zip(0..MAXHOPS) {
        let NodeDHKey(npk) = n.pubkey;
        let s0 = curve25519(npk,a);
        let (s1,ss[i]) = kdf_sphinx(npk,alpha,s0);
        curve25519_fixbits(s1);
        a = (Fe::from_bytes(a) * Fe::from_bytes(s1)).to_bytes();
        alphas[i+1] = curve25519_base(a);
    }
    (alphas,ss)
}

fn create_alphas(a0: &[u8], nodekeys: &[NodeKeys],) ->  ([K; MAXHOPS+1],[K; MAXHOPS]) {
    let mut alphas: [K; MAXHOPS+1];
    let mut ss: [K; MAXHOPS];
    alphas[0] = curve25519_base(a0);
    let mut a = Fe::from_bytes(a0);
    for (n,i) in nodekeys.zip(0..MAXHOPS) {
        let NodeDHKey(npk) = n.pubkey;
        let mut s0 = curve25519(npk,a);
        for (b,_) in bs.zip(0..i) {
            s0 = curve25519(s0,b);
        }
        let (s1,ss[i]) = kdf_sphinx(npk,alpha,s0);
        let bs[i] = Fe::from_bytes(s1);
        // twiddle bits?
        alphas[i+1] = curve25519(alpha[i],bs[i]);
    }
    (alphas,ss)
}

// Need to insert Xolotl s terms before doing padding

fn create_padding(a0: &[u8]; ) ->  (,) {
    let mut messagekey: MessageKey;

    ChaCha20::new_xchacha20(messagekey, [0;24]);
}


fn create_header(a0: &[u8]; ) ->  (,) {

}


*/



