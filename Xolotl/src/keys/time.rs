// Copyright 2016 Jeffrey Burdges.

//! Validity periods for key material
//!
//! TODO: Add serialization options using Serde.

use std::ops::{Range,AddAssign,Add,SubAssign,Sub};
use std::time::{Duration,SystemTime,UNIX_EPOCH};

#[derive(Clone, Debug)] // Copy
pub struct ValidityPeriod(pub Range<u64>);

#[derive(Clone, Copy, Debug)]
pub enum ValidityResult {
    Pending(Duration),
    Valid(Duration),
    Expired(Duration),
}

impl ValidityPeriod {
    pub fn new(start: SystemTime, duration: Duration) -> ValidityPeriod {
        let start = start.duration_since(start).unwrap();
        ValidityPeriod( start.as_secs() .. (start+duration).as_secs() )
    }

    pub fn intersect(&self, other: &ValidityPeriod) -> Option<ValidityPeriod> {
        use std::cmp::{min,max};
        let start = max(self.0.start, other.0.start);
        let end = min(self.0.end, other.0.end);
        if start < end { Some(ValidityPeriod(start..end)) } else { None }
    }

    // pub fn intersect_assign(&mut self, other: &ValidityPeriod) {
    //     *self = self.intersect(other);
    // }

    pub fn start(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.start)
    }
    pub fn end(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.0.end)
    }

    pub fn valid(&self) -> ValidityResult {
        use self::ValidityResult::*;
        let start = Duration::from_secs(self.0.start);
        let end = Duration::from_secs(self.0.end);
        let len = end-start;
        if start > end {
            return Expired( Duration::from_secs(0) ); 
        }
        let now = SystemTime::now();
        /*
        match now.duration_since(UNIX_EPOCH + end) {
            Ok(d) => Expired(d),
            Err(e) => {
                let d = e.duration();
                if d < len { Valid(d) } else { Pending(d-len) }
            },
        }
        */
        match now.duration_since(UNIX_EPOCH + start) {
            Ok(d) => if d>len { Expired(d-len) } else { Valid(len-d) },
            Err(e) => Pending(e.duration()),
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        use std::mem::transmute;
        let mut r = [0u8; 16];
        {
        let (start,end) = mut_array_refs![&mut r,8,8];
        *start = unsafe { transmute::<u64,[u8; 8]>(self.0.start.to_le()) };
        *end = unsafe { transmute::<u64,[u8; 8]>(self.0.end.to_le()) };
        }
        r
    }
    pub fn from_bytes(b: &[u8; 16]) -> ValidityPeriod {
        use std::mem::transmute;
        let (start,end) = array_refs![b,8,8];
        ValidityPeriod( Range {
            start: u64::from_le(unsafe { transmute::<[u8; 8],u64>(*start) }),
            end:   u64::from_le(unsafe { transmute::<[u8; 8],u64>(*end) }),
        } )
    }
}

impl<'a> Add<Duration> for &'a ValidityPeriod {
    type Output = ValidityPeriod;

    fn add(self, rhs: Duration) -> ValidityPeriod {
        let e = "overflow when adding seconds to a validity period";
        let f = |x: u64| x.checked_add(rhs.as_secs()).expect(e);
        ValidityPeriod(f(self.0.start)..f(self.0.end))
    }
}

impl Add<Duration> for ValidityPeriod {
    type Output = ValidityPeriod;

    #[inline(always)]
    fn add(self, rhs: Duration) -> ValidityPeriod {
        &self + rhs
    }
}

impl AddAssign<Duration> for ValidityPeriod {
    fn add_assign(&mut self, rhs: Duration) {
        *self = &*self + rhs;
    }
}

impl<'a> Sub<Duration> for &'a ValidityPeriod {
    type Output = ValidityPeriod;

    fn sub(self, rhs: Duration) -> ValidityPeriod {
        let e = "overflow when subtracting seconds from a validity period";
        let f = |x: u64| x.checked_sub(rhs.as_secs()).expect(e);
        ValidityPeriod(f(self.0.start)..f(self.0.end))
    }
}

impl Sub<Duration> for ValidityPeriod {
    type Output = ValidityPeriod;

    #[inline(always)]
    fn sub(self, rhs: Duration) -> ValidityPeriod {
        &self - rhs
    }
}

impl SubAssign<Duration> for ValidityPeriod {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = &*self - rhs;
    }
}


