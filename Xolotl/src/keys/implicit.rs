//! TODO: An [implicit certificate](https://en.wikipedia.org/wiki/Implicit_certificate)
//! scheme could shave 32 bytes off the `ROUTING_KEY_CERT_LENGTH`.
//! We must know that someone who compramises the node's long term
//! certificate for issuing routing keys, and some routing keys, 
//! cannot compute later routing keys, but the security proof in [0]
//! should show that the certificate issuer cannot compramise alpha,
//! whence our desired security property follows.
//! 
//! [0] Brown, Daniel R. L.; Gallant, Robert P.; Vanstone, Scott A. 
//! "Provably Secure Implicit Certificate Schemes".
//! Financial Cryptography 2001. Lecture Notes in Computer Science. 
//! Springer Berlin Heidelberg. 2339 (1): 156–165.
//! doi:10.1007/3-540-46088-8_15.

