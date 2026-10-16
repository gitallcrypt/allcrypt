/*
Message authentication codes.

The `Mac` trait itself lives in the crate root next to `HashFunction`, since
GOST implements it directly on the cipher. This module holds the standalone
constructions.
*/

pub mod cbc_mac;
pub mod chaskey;
pub mod cmac;
mod cmac_polynomials;
pub mod hmac;
pub mod michael;
pub mod pmac;
pub mod poly1305;
pub mod siphash;
pub mod umac;
pub mod vmac;

pub use cmac::Cmac;
pub use pmac::Pmac;
pub use hmac::Hmac;
pub use poly1305::Poly1305;
