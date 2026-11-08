pub mod chacha;
#[cfg(all(feature = "simd", target_arch = "x86_64"))]
mod chacha_simd;
pub mod chacha20poly1305;
pub mod grain;
pub mod grain128aead;
pub mod hc;
pub mod isaac;
pub mod mobile;
pub mod office_xor;
pub mod rabbit;
pub mod rc4;
pub mod rc4_hmac;
pub mod salsa20;
pub mod snow3g;
pub mod sosemanuk;
mod spec_tables;
pub mod strumok;
pub mod tkip;
pub mod trivium;
pub mod wep;
pub mod zipcrypto;
pub mod zuc;
mod zuc256_constants;

pub trait StreamCipher {
    fn crypt(&mut self, _input: &[u8], _result: &mut Vec<u8>);
    fn encrypt(&mut self, input: &[u8], result: &mut Vec<u8>){
        self.crypt(input, result);
    }
    fn decrypt(&mut self, input: &[u8], result: &mut Vec<u8>){
        self.crypt(input, result);
    }
}