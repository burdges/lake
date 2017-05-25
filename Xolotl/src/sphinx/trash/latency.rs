// Copyright 2016 Jeffrey Burdges.

//! Sphinx latency creation and representation tools for a Poisson
//! mix netowrk, aka a Stop-and-Go mix network.
//!
//!


/// We represent latency as a 2^20 bit number because this meshes
/// well with our mix command format and 2^20 seconds gives roughly
/// 12 days.  We expect 12 days already exceeds the mix key rotation
/// schedule, but 2^32 seconds is clearly excessive.  We feel 2^16
/// seconds, or 3/4th of a day, was too short for some use cases.
///
/// There are several variable length encodings optimized for
/// distributions with long tails, like the 
/// [Even-Rodeh coding](https://en.wikipedia.org/wiki/Even-Rodeh_coding)
/// or the Elias
/// [omega](https://en.wikipedia.org/wiki/Elias_omega_coding),
/// [delta](https://en.wikipedia.org/wiki/Elias_omega_coding), or
/// [gamma](https://en.wikipedia.org/wiki/Elias_gamma_coding) coding.
/// In our case, we might treat the high four bits as an exponent
/// denoted `e` and the treat the low 16 bits as a mantissa `m`, so
/// that `m * 2^e` seconds can be almost 25,000 years.  One should
/// not leave the low bits zero, but non-zero `e` is unlikely enough
/// that they can be taken from another distribution, even uniform.
/// We doubt such an encoding would be useful though. 



