// Copyright 2016 Jeffrey Burdges.

//! Storage for Xolotl ratchet
//!
//! ...

use std::any::TypeId;
use std::error::Error;
use std::convert::From;
use std::fmt;

use std::sync::{RwLockReadGuard, RwLockWriteGuard}; // PoisonError



macro_rules! impl_type_PoisonError {
    ($l:ident, $t:ident) => {
        impl<'a> From<::std::sync::PoisonError<$l<'a, $t>>> for XolotlError {
            fn from(_: ::std::sync::PoisonError<$l<'a, $t>>) -> XolotlError {
                // _.get_mut()
                XolotlError::PoisonError(stringify!($l),stringify!($t),TypeId::of::<$t>)
            }
        }
    };
    ($t:ident) => {
        impl_type_PoisonError!(RwLockReadGuard, $t);
        impl_type_PoisonError!(RwLockWriteGuard, $t);
    };
} // impl_type_PoisonError

// impl_XolotlPoisonError!(ReplayStorage);
// impl_XolotlPoisonError!(NodeInfoStorage);


macro_rules! impl_trait_PoisonError {
    ($l:ident, $t:ident) => {
        impl<'a,T> From<::std::sync::PoisonError<$l<'a, T>>> for XolotlError where T: $t + 'a {
            fn from(_: ::std::sync::PoisonError<$l<'a, T>>) -> XolotlError {
                // _.get_mut()
                XolotlError::PoisonError(stringify!($l),stringify!($t),TypeId::of::<T>)
            }
        }
    };
    ($t:ident) => {
        impl_XolotlPoisonError!(RwLockReadGuard, $t);
        impl_XolotlPoisonError!(RwLockWriteGuard, $t);
    };
} // impl_XolotlPoisonError


