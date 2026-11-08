//! The zuc 0.4.1 crate: ZUC-128 and ZUC-256 keystreams, 128-EEA3, 128-EIA3,
//! and the ZUC-128 and ZUC-256 MACs with a raw IV.

use gpp_witness::{Witness, pack_iv, serve, words_to_bytes};
use zuc::eea3::eea3_xor_inplace;
use zuc::eia3::Eia3Mac;
use zuc::zuc128::{Zuc128Keystream, Zuc128Mac};
use zuc::zuc256::{Zuc256Keystream, Zuc256Mac};

struct Crate;

impl Witness for Crate {
    fn stream(&self, cipher: &str, key: &[u8], iv: &[u8], n: usize) -> Result<Vec<u8>, String> {
        match cipher {
            "zuc128" => {
                let key: &[u8; 16] = key.try_into().map_err(|_| "key or iv length")?;
                let iv: &[u8; 16] = iv.try_into().map_err(|_| "key or iv length")?;
                let mut z = Zuc128Keystream::new(key, iv);
                Ok(words_to_bytes(|| z.generate(), n))
            }
            "zuc256" => {
                let key: &[u8; 32] = key.try_into().map_err(|_| "key or iv length")?;
                let mut z = Zuc256Keystream::new(key, &pack_iv(iv)?);
                Ok(words_to_bytes(|| z.generate(), n))
            }
            _ => Err("unsupported".into()),
        }
    }

    fn f8(&self, alg: &str, key: &[u8; 16], count: u32, bearer: u32, dir: u32, data: &mut [u8],
          bits: u32) -> Result<(), String> {
        if alg != "eea3" {
            return Err("unsupported".into());
        }
        eea3_xor_inplace(count, bearer as u8, dir as u8, key, data, bits as usize);
        Ok(())
    }

    fn f9(&self, alg: &str, key: &[u8; 16], count: u32, fresh: u32, dir: u32, data: &[u8],
          bits: u32) -> Result<[u8; 4], String> {
        if alg != "eia3" {
            return Err("unsupported".into());
        }
        Ok(Eia3Mac::compute(count, fresh as u8, dir as u8, key, data, bits as usize).to_be_bytes())
    }

    fn zucmac(&self, tagbits: u32, key: &[u8], iv: &[u8], data: &[u8], bits: u32)
        -> Result<Vec<u8>, String> {
        let bits = bits as usize;
        if key.len() == 16 {
            let key: &[u8; 16] = key.try_into().unwrap();
            let iv: &[u8; 16] = iv.try_into().map_err(|_| "iv length")?;
            if tagbits != 32 {
                return Err("unsupported".into());
            }
            return Ok(Zuc128Mac::compute(key, iv, data, bits).to_be_bytes().to_vec());
        }
        let key: &[u8; 32] = key.try_into().map_err(|_| "key or iv length")?;
        let iv = pack_iv(iv)?;
        Ok(match tagbits {
            32 => Zuc256Mac::<u32>::compute(key, &iv, data, bits).to_be_bytes().to_vec(),
            64 => Zuc256Mac::<u64>::compute(key, &iv, data, bits).to_be_bytes().to_vec(),
            _ => Zuc256Mac::<u128>::compute(key, &iv, data, bits).to_be_bytes().to_vec(),
        })
    }
}

fn main() {
    serve(&Crate);
}
