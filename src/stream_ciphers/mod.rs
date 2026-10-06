pub mod chacha;
pub mod chacha20poly1305;
pub mod office_xor;
pub mod rc4;
pub mod salsa20;
pub mod tkip;
pub mod wep;
pub mod zipcrypto;

pub trait StreamCipher {
    fn crypt(&mut self, _input: &[u8], _result: &mut Vec<u8>);
    fn encrypt(&mut self, input: &[u8], result: &mut Vec<u8>){
        self.crypt(input, result);
    }
    fn decrypt(&mut self, input: &[u8], result: &mut Vec<u8>){
        self.crypt(input, result);
    }
}