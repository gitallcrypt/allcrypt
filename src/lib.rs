
pub mod asn1;
pub mod bignum;
pub mod block_ciphers;
pub mod checksum;
pub mod ec;
pub mod stream_ciphers;

pub mod hash_functions;
pub mod kdf;
pub mod mac;
pub mod pem;
pub mod prng;
pub mod random;
pub mod registry;
pub mod pq;
pub mod publickey_ciphers;
pub mod ssh;
pub mod tls;
pub mod trust;
pub mod x509;

pub mod api;
pub mod proxy;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "c-api")]
pub mod capi;

pub fn to_hex(input: &[u8]) -> String {
    let mut s = String::new();
    for c in input {
        s += &format!("{:02X}", c).to_string();
    }
    s
}

/// XOR two byte slices. The result is as long as the *shorter* input, which
/// the stream-like modes rely on for their final partial block. Callers that
/// need equal lengths should use [`xor_checked`], or verify the lengths first:
/// silently returning a short buffer is exactly how a broken keystream turns
/// into short "ciphertext" instead of an error.
pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    x.iter().zip(y.iter()).map(|(&x1, &y1)| x1^y1).collect()
}

/// XOR two byte slices of identical length, erroring on any mismatch.
pub fn xor_checked(x: &[u8], y: &[u8]) -> Result<Vec<u8>, String> {
    if x.len() != y.len() {
        return Err(format!("xor length mismatch: {} vs {}", x.len(), y.len()));
    }
    Ok(xor(x, y))
}

pub trait Mac {
    fn digest(&mut self) -> Vec<u8>;
    fn update(&mut self, _input: &[u8]);
}
