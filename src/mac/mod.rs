/*
Message authentication codes.

The `Mac` trait itself lives in the crate root next to `HashFunction`, since
GOST implements it directly on the cipher. This module holds the standalone
constructions.
*/

pub mod cbc_mac;
pub mod cmac;
pub mod hmac;
pub mod michael;
pub mod poly1305;
pub mod umac;

pub use cmac::Cmac;
pub use hmac::Hmac;
pub use poly1305::Poly1305;
