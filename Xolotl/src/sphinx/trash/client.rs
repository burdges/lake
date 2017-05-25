




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



