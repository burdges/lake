

// TODO: Write flexible macro for tuple structs.
macro_rules! impl_Display_as_hex_for_WrapperStruct {
    ($t:ident) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, concat!(stringify!($t), "({:x})"), self.0)
            }
        }
    }
}


#[derive(Debug, Default)]
pub struct Secret<T>(pub T) where T: Copy;

impl<T> Drop for Secret<T> where T: Copy {
    fn drop(&mut self) {
        unsafe { ::std::intrinsics::volatile_set_memory::<Secret<T>>(self, 0, 1); }
    }
}


/// Zeroing drop impl for secret key material.
///
/// Rust does not zero non-`Drop` types when it drops them.  
/// Avoid leaking these type as doing so obstructs zeroing them.
/// In particular, if you are working with secret key material then
/// - do not call `::std::mem::forget`, 
/// - do not unsafely zero types with owning pointers,
/// - ensure your code cannot panic. 
/// - take care with `Weak`, and
/// - examine the data structures you use for violations of these rules.
/// All such rules are collectively termed `#[never_forget]` in honor
/// of the first and other reasons.
/// See https://github.com/rust-lang/rfcs/pull/320#issuecomment-270680263
/// and https://github.com/isislovecruft/curve25519-dalek/issues/11
macro_rules! impl_ZeroingDrop {
    ($t:ident,$zero:expr) => {
        impl Drop for $t {
            fn drop(&mut self) {
                unsafe { ::std::ptr::write_volatile::<$t>(self, $t($zero)); }
                assert_eq!(self.0,$zero);
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use crypto::digest::Digest;
    use crypto::sha3::Sha3;
    use ::sphinx::SphinxSecret;
    use ::ratchet::ExtraKey;

    macro_rules! zeroing_drop_test {
        ($n:path) => {
            let p : *const $n;
            {
                let mut s = $n([3u8; 32]);  p = &s; 
                // ::std::mem::drop(s); 
                unsafe { ::std::intrinsics::drop_in_place(&mut s); }  
            }
            /*
            let mut sha = Sha3::sha3_512();
            let mut r = [0u8; 2*32];
            for i in 0..1000 {
                sha.input(&mut r);
                sha.result(&mut r);
                sha.reset();
            }
            */
            // ::std::thread::sleep(::std::time::Duration::from_secs(10));
            unsafe { assert_eq!((*p).0,[0u8; 32]); }
        }
    }
    #[test]
    fn zeroing_drops() {
        // zeroing_drop_test!(super::DropSecret<[u8; 32]>);
        zeroing_drop_test!(super::Secret<[u8; 32]>);
        zeroing_drop_test!(SphinxSecret);
        zeroing_drop_test!(ExtraKey);
/*
        zeroing_drop_test!(self::ratchet::twig::TrainKey);
        zeroing_drop_test!(self::ratchet::twig::ChainKey);
        zeroing_drop_test!(self::ratchet::twig::LinkKey);
        zeroing_drop_test!(self::ratchet::twig::BerryKey);
*/
    }
}


