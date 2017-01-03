// Copyright 2016 Jeffrey Burdges.

//! Xolotl hash iteration ratchet twigs
//!
//! ...

use super::branch::*;

use std::hash::{Hash, Hasher};

use std::fmt;
use rustc_serialize::hex::ToHex;


/// We store only a 128-2 = 126 bit secret symetric keys in a hash
/// iteration ratchet step to reduce our storage reuirements.  
/// We therefore enjoy 126 bits of classical security for our forward
/// secrecy properties arising from the hash iteration ratchet.
/// We use the remaining 2 bits to identify the twig type.
pub type TwigKey = [u8; 16];

/// Train keys are faster chain keys that iterate in a tree.
/// Iterating the train key with index i yields the train keys with
/// indices 2 i and 2 i+1 along with a chain key and a link key.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct TrainKey(pub TwigKey); 

impl_KeyDrop!(TrainKey);

/// Chain keys iterate linearly, yielding the next chain key and
/// a link key.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct ChainKey(pub TwigKey);

impl_KeyDrop!(ChainKey);

/// Link keys are combined with a Sphinx shared secret to produce
/// a message key and a berry key to be stored.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct LinkKey(pub TwigKey);

impl_KeyDrop!(LinkKey);

/// Berry keys can be used to start a new hash iteration ratchet.
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct BerryKey(pub TwigKey);

impl_KeyDrop!(BerryKey);

/// Mask for teh two bits we deduct from a TwigKey to identify its type.
const TWIG_KEY_TYPE_MASK: u8 = 0x03;

/// Associated constant to record the twig key type for storage
pub trait Twigy : Sized {
    /// Key Type
    const KEYTYPE: u8;

    #[inline]
    fn verify(t: TwigKey) -> Result<Self,u8>;

    #[inline]
    fn debug_assert_twigy(&self);
}

/// Enum for twig keys types returned by fetch
#[derive(Debug, Clone)] // Default, Copy
pub enum TwigState {
    Train(TrainKey),
    Chain(ChainKey),
    Link(LinkKey),
    Berry(BerryKey)
}

macro_rules! impl_Twigy {
    ($a:ident,$e:ident,$v:expr) => {
        impl $a {
            pub fn make(mut t: TwigKey) -> $a {
                t[0] &= ! TWIG_KEY_TYPE_MASK;
                t[0] |= $v;
                $a(t)
            }
        }

        impl From<$a> for TwigState {
            fn from(k: $a) -> TwigState {
                k.debug_assert_twigy();
                TwigState::$e(k)
            }
        }

        impl Twigy for $a { 
            const KEYTYPE: u8 = $v;

            fn verify(t: TwigKey) -> Result<$a,u8> {
                let ty: u8 = t[0] & TWIG_KEY_TYPE_MASK;
                if ty == $v { Ok($a(t)) } else { Err(ty) }
            }

            fn debug_assert_twigy(&self) {
                debug_assert_eq!(self.0[0] & TWIG_KEY_TYPE_MASK, Self::KEYTYPE);
            }
        }
    };
}

impl_Twigy!(TrainKey, Train, 0x00);
impl_Twigy!(ChainKey, Chain, 0x01);
impl_Twigy!(LinkKey, Link, 0x02);
impl_Twigy!(BerryKey, Berry, 0x03);

impl TwigState {
    pub fn new(k: TwigKey) -> TwigState {
        use self::TwigState::*;
        match k[0] & TWIG_KEY_TYPE_MASK {
            TrainKey::KEYTYPE => Train(TrainKey(k)),
            ChainKey::KEYTYPE => Chain(ChainKey(k)),
            LinkKey::KEYTYPE  => Link(LinkKey(k)),
            BerryKey::KEYTYPE => Berry(BerryKey(k)),
            _ => unreachable!(),
        }
    }

    pub fn data(self) -> TwigKey {
        use self::TwigState::*;
        match self {
            Train(trainkey) => trainkey.0,
            Chain(chainkey) => chainkey.0,
            Link(linkkey) => linkkey.0,
            Berry(berrykey) => berrykey.0,
        }
    }
}


/// Type of the index of a twig in a Xolotl ratchet.
///
/// We imagine 2^16 to be excessively large already, but unusual
/// usages of a ratchet might need more hash iteration steps.
pub type TwigIdxT = u16;

/// Index of a twig in a Xolotl ratchet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TwigIdx(pub TwigIdxT);


/// An TwigIdx's low CHAIN_V_TRAIN_WIDTH bits determin the chain
/// position.  It's high 16-CHAIN_V_TRAIN_WIDTH bits determine the
/// train position. 
///
/// Increasing optimizes storage for honest packets recieved in
/// order, while decreasing optimizes storage for malicious packets.
/// We choose 5 bits giving 32 chain keys per chain, or 512 bytes,
/// along with at most 3*(16-5) = 33 additional train and chain keys
/// to reach the chan, so malicious packets can waste at most 1kb.  
const CHAIN_V_TRAIN_WIDTH : u8 = 5;

pub const TRAIN_START : TwigIdx = TwigIdx( 1 << CHAIN_V_TRAIN_WIDTH );

const CHAIN_MASK : TwigIdxT = TRAIN_START.0 - 1;

impl TwigIdx {
    /// Convert an index into a hash iteration ratchet into a pair of
    /// bytes in little endian.
    pub fn to_bytes(self) -> [u8; 2] {
        [ (self.0 & 0xFF) as u8, (self.0 >> 8) as u8 ]
    }

    /// Convert a pair of bytes in little endian into an index into a
    /// hash iteration ratchet. 
    pub fn from_bytes(b : [u8; 2]) -> TwigIdx {
        TwigIdx( ((b[1] as u16) << 8) | (b[0] as u16) )
    }

    /// Split an TwigIdx into train and chain parts.
    fn split(idx : TwigIdx) -> (u16,u16) {
        (idx.0 >> CHAIN_V_TRAIN_WIDTH, idx.0 & CHAIN_MASK)
    }

    /// Make an TwigIdx from train and chain parts.
    fn make(i: u16, j: u16) -> TwigIdx {
        TwigIdx( (i << CHAIN_V_TRAIN_WIDTH) + (j & CHAIN_MASK) )
    }

    // /// Increment TwigIdx when wrapping cannot happen.
    // fn increment_branch(self) -> TwigIdx
    //     { TwigIdx(self.0+1) }

    /// Increment TwigIdx while preventing wrapping.
    fn increment(self) -> Option<TwigIdx> {
        if self.0 < TwigIdxT::max_value() { Some(TwigIdx(self.0+1)) } else { None }
    }

    /// Says if we progress to the next train step.
    fn is_pure_train(self) -> bool  {  (self.0 & CHAIN_MASK) == 0  }

    fn is_okay_train(i: u16) -> bool  {  i < (TwigIdxT::max_value() >> CHAIN_V_TRAIN_WIDTH)  }

    /// Unique parent of train position
    fn train_parent(i: u16) -> Option<u16>
        {  if i>=1 { Some(i/2) } else { None }  }

    /// Two children of train position
    fn train_children(i: u16) -> Option<(u16,u16)>
        {  if Self::is_okay_train(2*i) { Some((2*i, 2*i+1)) } else { None }  }
        // Assumes CHAIN_V_TRAIN_WIDTH > 0 so fix if that changes
}

/// We manually implement Hash for TwigIdx to impose little
/// endianness, just in case our data is moved between machines.
impl Hash for TwigIdx {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // self.to_bytes().hash(state);
        self.0.to_le().hash(state);
    }
}

// In storage, twigs are identified by the branch they inhabit
// along with their index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TwigId(pub BranchId, pub TwigIdx);

impl fmt::Display for TwigId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TwigId({},{})", self.0, (self.1).0)
    }
}


/// A twigs' index and state together
#[derive(Debug, Clone)]
pub struct TwigIS(pub TwigIdx,pub TwigState);


/* -- branch:: -- */


#[derive(Debug)]
pub enum TwigErr {
    UnexpectedTrain,
    UnexpectedChain,
    UnexpectedLink,
    UnexpectedBerry,
    KeyNotFound,
    // Poisoned(PoisonError<??>)
}
type R<T> = Result<T,TwigErr>;





#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twig_endianness_test() {
        assert_eq!(TwigIdx::from_bytes([0xE5,0x37]), TwigIdx(0x37E5));
        assert_eq!(TwigIdx(0xC249).to_bytes(), [0x49,0xC2]);
        assert_eq!(TwigIdx::from_bytes([0x27,0x6D]).to_bytes(), [0x27,0x6D]);
        assert_eq!(TwigIdx::from_bytes(TwigIdx(0xF912).to_bytes()), TwigIdx(0xF912));
    }

    #[test]
    fn twigy_test() {
        for i in 0..3 {
            let mut t: TwigKey = Default::default();
            t[0] = i;
            let ts1 = TwigState::new(t);
            let ts2: TwigState = match ts1 {
                TwigState::Train(k) => { k.into() },
                TwigState::Chain(k) => { k.into() },
                TwigState::Link(k) => { k.into() },
                TwigState::Berry(k) => { k.into() },
            };
            // assert_eq!(ts1, ts2);
        }
    }
}




