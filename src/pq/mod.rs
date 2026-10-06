/*
Post-quantum algorithms: the NIST standards of August 2024.

Three of them: ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS
205). SLH-DSA and ML-KEM are here; ML-DSA is not yet. `docs/post-quantum.md`
says why that order: SLH-DSA is a construction over SHA-2 and SHAKE, both
of which this library already had and had checked against `hashlib` over
tens of thousands of cases, so nothing new sat underneath it. The lattice
pair need polynomial arithmetic in `Z_q[X]/(X^256+1)` and an NTT, which
is a new numeric layer rather than a new use of an old one - and each
has its own ring, since their moduli differ.

## These do not rest on `bignum`, and should not be made to

Every other public-key algorithm in this library is arithmetic on
arbitrary precision integers. None of the three post-quantum standards
has a big integer anywhere in it. SLH-DSA has no arithmetic at all - it
is Merkle trees and one-time signatures made of hashes - and the lattice
pair are fixed-width machine integers in arrays of 256. Reaching for
`BigUint` here would be actively wrong: it is variable width and
normalised, and these coefficients are neither.

So this module depends on `hash_functions` and on nothing else in the
library.

## What "quantum resistant" is and is not being claimed

These algorithms are believed to resist an adversary with a large quantum
computer, which the RSA and elliptic-curve algorithms elsewhere in this
library are not. That belief is about the mathematics, not about this
code: an implementation bug is as fatal here as anywhere, and the
hash-based scheme in particular has a failure mode with no equivalent in
RSA or ECDSA - see the warning about one-time keys in `slh_dsa.rs`.
*/

pub mod ml_dsa;
pub mod ml_kem;
pub mod prehash;
pub mod slh_dsa;
pub mod sntrup;
