
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


/// Rust should zero non-`Drop` types when it drops them.  We should 
/// verify this with a test thought.  It also useful to uncomment this
/// ocasionally to test the build with non-`Copy` key material.

macro_rules! impl_KeyDrop {
    ($t:ident) => {
/*
        impl Drop for $t {
            fn drop(&mut self) {
                for c in self.0.iter_mut() { *c = 0; }
            }
        }
*/
    }
}


