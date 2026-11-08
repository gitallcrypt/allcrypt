//! oxirush-security 0.3.0: the SNOW 3G and ZUC-128 keystreams, and 128-NEA1
//! (= 128-EEA1, UEA2's construction), 128-NIA1, 128-NEA3 and 128-NIA3
//! through nea_cipher_bits and nia_mac_bits. UIA2 with an arbitrary FRESH
//! and the raw-IV MAC are not in the crate. The modes take only the
//! crate's key types, so the key goes in as a 5GS NAS key.

use gpp_witness::{Witness, serve, words_to_bytes};
use oxirush_security::{
    Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, Snow3G, Zuc, nea_cipher_bits,
    nia_mac_bits,
};
use oxirush_security::nas_5gs::{KNasEnc, KNasInt};

struct Crate;

fn inputs(bearer: u32, dir: u32) -> Result<(Bearer, Direction), String> {
    let b = Bearer::try_from(bearer as u8).map_err(|e| format!("bearer {e:?}"))?;
    let d = Direction::try_from(dir as u8).map_err(|e| format!("direction {e:?}"))?;
    Ok((b, d))
}

impl Witness for Crate {
    fn stream(&self, cipher: &str, key: &[u8], iv: &[u8], n: usize) -> Result<Vec<u8>, String> {
        let key: &[u8; 16] = key.try_into().map_err(|_| "key or iv length")?;
        let iv: &[u8; 16] = iv.try_into().map_err(|_| "key or iv length")?;
        match cipher {
            "snow3g" => {
                let mut s = Snow3G::from_bytes(key, iv);
                Ok(words_to_bytes(|| s.next_word(), n))
            }
            "zuc128" => {
                let mut z = Zuc::new(key, iv);
                Ok(words_to_bytes(|| z.next_word(), n))
            }
            _ => Err("unsupported".into()),
        }
    }

    fn f8(&self, alg: &str, key: &[u8; 16], count: u32, bearer: u32, dir: u32, data: &mut [u8],
          bits: u32) -> Result<(), String> {
        let algorithm = match alg {
            "uea2" => CipheringAlgorithm::Snow3g,
            "eea3" => CipheringAlgorithm::Zuc,
            _ => return Err("unsupported".into()),
        };
        let (b, d) = inputs(bearer, dir)?;
        let key = KNasEnc::from_slice(key).map_err(|e| format!("{e:?}"))?;
        nea_cipher_bits(&key, count, b, d, data, u64::from(bits), algorithm)
            .map_err(|e| format!("{e:?}"))
    }

    fn f9(&self, alg: &str, key: &[u8; 16], count: u32, fresh: u32, dir: u32, data: &[u8],
          bits: u32) -> Result<[u8; 4], String> {
        let algorithm = match alg {
            "eia1" => IntegrityAlgorithm::Snow3g,
            "eia3" => IntegrityAlgorithm::Zuc,
            _ => return Err("unsupported".into()),
        };
        let (b, d) = inputs(fresh, dir)?;
        let key = KNasInt::from_slice(key).map_err(|e| format!("{e:?}"))?;
        nia_mac_bits(&key, count, b, d, data, u64::from(bits), algorithm)
            .map(u32::to_be_bytes)
            .map_err(|e| format!("{e:?}"))
    }

    fn zucmac(&self, _: u32, _: &[u8], _: &[u8], _: &[u8], _: u32) -> Result<Vec<u8>, String> {
        Err("unsupported".into())
    }
}

fn main() {
    serve(&Crate);
}
