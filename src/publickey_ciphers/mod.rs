/*
Public key algorithms.

RSA lives in `rsa`, DSA in `dsa`, finite-field Diffie-Hellman in `dh`, and ElGamal in
`elgamal` - which is built on `dh`'s group type, because ElGamal is
Diffie-Hellman turned into an encryption scheme and needs exactly the
same validation. Elliptic curve work is in the top level `ec` module,
since curves are a great deal more than a cipher.
*/

pub mod dh;
pub mod dsa;
pub mod elgamal;
pub mod rsa;

/// The shape every public key cipher here shares.
///
/// This used to be a trait with `unimplemented!()` bodies, which panicked
/// rather than erroring - the opposite of the rule this library runs on. It
/// now returns `Result` like everything else, and padding is chosen by the
/// function you call rather than by a method that might not exist.
pub trait PublicKeyCipher {
    /// The size in bytes of the values this key operates on: for RSA, the
    /// modulus size, which is also the ciphertext and signature size.
    fn size(&self) -> usize;
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, String>;
}
