// Copyright 2016 Jeffrey Burdges.

//! Errors arising from key material functions.

use std::error::Error;
use std::convert::From;
use std::fmt;


#[derive(Debug, Clone)]
pub enum KeysError {
    InternalError(&'static str),
    Routing(super::RoutingName,&'static str),
    Issuer(super::certs::IssuerPublicKey,&'static str),
}

pub type KeysResult<T> = Result<T,KeysError>;

impl fmt::Display for KeysError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use hex::ToHex;
        use self::KeysError::*;
        match *self {
            InternalError(s)
                => write!(f, "Internal error: {}", s),
            Routing(r,t)
                => write!(f, "Routing key error: {} ({})", t, r.0.to_hex()),
            Issuer(i,t)
                => write!(f, "Issuer key error: {} ({})", t, i.0.to_hex()),
        }
    }
}

impl Error for KeysError {
    fn description(&self) -> &str {
        "I'm a Keys error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::KeysError::*;
        match *self {
            InternalError(_) => None,
            Routing(_,_) => None,
            Issuer(_,_) => None,
        }
    }
}


