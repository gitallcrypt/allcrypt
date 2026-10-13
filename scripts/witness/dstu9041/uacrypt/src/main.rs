//! DSTU 9041:2020 through uacrypt's `hazmat::dstu9041`, with
//! li0ard/driver.ts's request format, one per line, hex fields:
//!
//!     pub <bits> <e>                        the public key e*P, x || y
//!     enc <bits> <Q> <epsilon> <M> [<l(M)>] the ciphertext r || t
//!     dec <bits> <e> <C>                    the message, or "error"
//!
//! <bits> is 256 or 512. Scalars are big endian, of the field's width.
//! `enc` takes the message's length in bits when it is not a whole
//! number of bytes; `dec` answers with the message's bytes and, after a
//! space, its length in bits.
#![allow(dead_code)]

// The modules sit at the root, where uacrypt's own `super::` paths
// between them resolve, and `hazmat` re-exports them for its
// `crate::hazmat::` paths.
#[path = "../../../src/uacrypt/hazmat/limb.rs"]
mod limb;
#[path = "../../../src/uacrypt/hazmat/tables.rs"]
mod tables;
#[path = "../../../src/uacrypt/hazmat/kalyna.rs"]
mod kalyna;
#[path = "../../../src/uacrypt/hazmat/kalyna_kw.rs"]
mod kalyna_kw;
#[path = "../../../src/uacrypt/hazmat/kupyna.rs"]
mod kupyna;
#[path = "../../../src/uacrypt/hazmat/dstu9041/mod.rs"]
mod dstu9041;

#[allow(unused_imports)]
mod hazmat {
    pub(crate) use super::{dstu9041, kalyna, kalyna_kw, kupyna, limb, tables};
}

use dstu9041::{curve256, curve512, encryption, encryption512, fp256, fp512};
use std::io::{BufRead, Write};

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s == "-" {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err("hex".into());
    }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "hex".to_string()))
        .collect()
}

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    unhex(s)?.try_into().map_err(|_| format!("length, want {N}"))
}

/// The message's low `l(M)` bits, as the bytes `M~` ends with.
fn tail(m_tilde: &[u8], bits: usize) -> Vec<u8> {
    m_tilde[m_tilde.len() - bits.div_ceil(8)..].to_vec()
}

fn answer(line: &str) -> Result<String, String> {
    let w: Vec<&str> = line.split_whitespace().collect();
    let (op, bits) = (*w.first().ok_or("op")?, *w.get(1).ok_or("bits")?);
    let arg = |i: usize| w.get(i).copied().ok_or_else(|| "argument".to_string());
    match (op, bits) {
        ("pub", "256") => {
            let q = curve256::base_point().scalar_multiply(&fixed::<32>(arg(2)?)?);
            Ok(hex(&[q.x.to_be_bytes(), q.y.to_be_bytes()].concat()))
        }
        ("pub", "512") => {
            let q = curve512::base_point().scalar_multiply(&fixed::<64>(arg(2)?)?);
            Ok(hex(&[q.x.to_be_bytes(), q.y.to_be_bytes()].concat()))
        }
        ("enc", "256") => {
            let q: [u8; 64] = fixed(arg(2)?)?;
            let q = curve256::Point {
                x: fp256::FieldElement::from_be_bytes(&q[..32].try_into().unwrap()),
                y: fp256::FieldElement::from_be_bytes(&q[32..].try_into().unwrap()),
            };
            let m = unhex(arg(4)?)?;
            let mbits = match w.get(5) { Some(b) => b.parse().map_err(|_| "l(M)")?, None => 8 * m.len() };
            let c = encryption::encrypt(&m, mbits, q, &fixed(arg(3)?)?)
                .map_err(|e| format!("{e:?}"))?;
            Ok(hex(&c))
        }
        ("enc", "512") => {
            let q: [u8; 128] = fixed(arg(2)?)?;
            let q = curve512::Point {
                x: fp512::FieldElement::from_be_bytes(&q[..64].try_into().unwrap()),
                y: fp512::FieldElement::from_be_bytes(&q[64..].try_into().unwrap()),
            };
            let m = unhex(arg(4)?)?;
            let mbits = match w.get(5) { Some(b) => b.parse().map_err(|_| "l(M)")?, None => 8 * m.len() };
            let c = encryption512::encrypt(&m, mbits, q, &fixed(arg(3)?)?)
                .map_err(|e| format!("{e:?}"))?;
            Ok(hex(&c))
        }
        ("dec", "256") => {
            let (m, l) = encryption::decrypt(&fixed(arg(3)?)?, &fixed(arg(2)?)?)
                .map_err(|e| format!("{e:?}"))?;
            Ok(format!("{} {l}", hex(&tail(&m, l))))
        }
        ("dec", "512") => {
            let (m, l) = encryption512::decrypt(&fixed(arg(3)?)?, &fixed(arg(2)?)?)
                .map_err(|e| format!("{e:?}"))?;
            Ok(format!("{} {l}", hex(&tail(&m, l))))
        }
        _ => Err("request".into()),
    }
}

fn main() {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() {
            continue;
        }
        match answer(&line) {
            Ok(s) => writeln!(out, "{s}").unwrap(),
            Err(e) => writeln!(out, "error {e}").unwrap(),
        }
    }
    out.flush().unwrap();
}
