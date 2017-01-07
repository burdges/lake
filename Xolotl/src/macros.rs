
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
/// See https://github.com/rust-lang/rfcs/pull/320#issuecomment-270680263
/// and https://github.com/isislovecruft/curve25519-dalek/issues/11
macro_rules! impl_KeyDrop {
    ($t:ident,$zero:expr) => {
        impl Drop for $t {
            fn drop(&mut self) {
                unsafe { ::std::ptr::write_volatile::<$t>(self, $t($zero)); }
            }
        }
    }
}


#[cfg(test)]
mod tests {
    use xolotl::branch::ExtraKey;
    // #[derive(Debug,PartialEq,Eq)]
    // struct SecretKey(pub [u8; 32]);

    #[test]
    fn zeroing_drop() {
        let p : *const SecretKey;
        { let s = ExtraKey([1u8; 32]); p = &s; ::std::mem::drop(s); }
        unsafe { assert_eq!(*p,ExtraKey([0u8; 32])); }
    }
}



