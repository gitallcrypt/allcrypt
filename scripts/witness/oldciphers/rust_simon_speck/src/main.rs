//! Two more Simon and Speck witnesses, at every block and key size, speaking
//! ../nessie/driver.h's request format as lwbc_driver.rs does:
//!
//!     enc <key hex> <block hex>          one block
//!     dec <key hex> <block hex>
//!     enc-n <key hex> <block hex> <n>    the block encrypted n times over
//!     dec-n <key hex> <block hex> <n>
//!
//! The arguments are the cipher (speck32 .. speck128, simon32 .. simon128)
//! and the implementation:
//!
//! - `rustcrypto`: RustCrypto's speck-cipher 0.1.0, Speck only. It writes
//!   the paper's numbers big endian, x before y and the key's last word
//!   first, so every key, block and result is byte-reversed here from the
//!   designers' encoding, which Crypto++, the Linux kernel and inmcm read.
//! - `cryptographyrs`: cryptography-rs 0.8.0, both families. Its words are
//!   little endian and its key's first word comes first, as the designers'
//!   are, but its block has x before y, so the two halves of every block
//!   and result are exchanged here.
//!
//! The key length picks the variant; another length answers "error
//! lengths".
use std::io::{BufRead, Write};

use speck_cipher::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

type Step = Box<dyn Fn(bool, &mut [u8])>;

/// RustCrypto's Speck under `key`, in the designers' encoding.
fn rustcrypto(cipher: &str, key: &[u8]) -> Option<Step> {
    macro_rules! speck {
        ($ty:ty) => {{
            let mut k = key.to_vec();
            k.reverse();
            let c = <$ty>::new_from_slice(&k).ok()?;
            Some(Box::new(move |enc: bool, block: &mut [u8]| {
                block.reverse();
                let mut b = speck_cipher::cipher::Block::<$ty>::try_from(&*block)
                    .expect("block_len checked the length");
                if enc { c.encrypt_block(&mut b) } else { c.decrypt_block(&mut b) }
                block.copy_from_slice(&b);
                block.reverse();
            }) as Step)
        }};
    }
    use speck_cipher::*;
    match (cipher, key.len()) {
        ("speck32", 8) => speck!(Speck32_64),
        ("speck48", 9) => speck!(Speck48_72),
        ("speck48", 12) => speck!(Speck48_96),
        ("speck64", 12) => speck!(Speck64_96),
        ("speck64", 16) => speck!(Speck64_128),
        ("speck96", 12) => speck!(Speck96_96),
        ("speck96", 18) => speck!(Speck96_144),
        ("speck128", 16) => speck!(Speck128_128),
        ("speck128", 24) => speck!(Speck128_192),
        ("speck128", 32) => speck!(Speck128_256),
        _ => None,
    }
}

/// cryptography-rs's Simon or Speck under `key`, in the designers'
/// encoding.
fn cryptographyrs(cipher: &str, key: &[u8]) -> Option<Step> {
    macro_rules! both {
        ($ty:ty) => {{
            let c = <$ty>::new(key.try_into().ok()?);
            Some(Box::new(move |enc: bool, block: &mut [u8]| {
                let half = block.len() / 2;
                block.rotate_left(half);
                if enc { c.encrypt(block) } else { c.decrypt(block) }
                block.rotate_left(half);
            }) as Step)
        }};
    }
    use cryptography::*;
    match (cipher, key.len()) {
        ("speck32", 8) => both!(Speck32_64),
        ("speck48", 9) => both!(Speck48_72),
        ("speck48", 12) => both!(Speck48_96),
        ("speck64", 12) => both!(Speck64_96),
        ("speck64", 16) => both!(Speck64_128),
        ("speck96", 12) => both!(Speck96_96),
        ("speck96", 18) => both!(Speck96_144),
        ("speck128", 16) => both!(Speck128_128),
        ("speck128", 24) => both!(Speck128_192),
        ("speck128", 32) => both!(Speck128_256),
        ("simon32", 8) => both!(Simon32_64),
        ("simon48", 9) => both!(Simon48_72),
        ("simon48", 12) => both!(Simon48_96),
        ("simon64", 12) => both!(Simon64_96),
        ("simon64", 16) => both!(Simon64_128),
        ("simon96", 12) => both!(Simon96_96),
        ("simon96", 18) => both!(Simon96_144),
        ("simon128", 16) => both!(Simon128_128),
        ("simon128", 24) => both!(Simon128_192),
        ("simon128", 32) => both!(Simon128_256),
        _ => None,
    }
}

fn block_len(cipher: &str) -> usize {
    cipher.trim_start_matches(|c: char| c.is_ascii_alphabetic()).parse::<usize>().unwrap_or(0) / 8
}

fn answer(cipher: &str, source: &str, line: &str) -> Result<String, &'static str> {
    let f: Vec<&str> = line.split_whitespace().collect();
    let op = *f.first().ok_or("error op")?;
    let iterated = op == "enc-n" || op == "dec-n";
    if !iterated && op != "enc" && op != "dec" || f.len() != if iterated { 4 } else { 3 } {
        return Err("error op");
    }
    let unhex = |s: &str| -> Option<Vec<u8>> {
        (0..s.len()).step_by(2)
            .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
            .collect()
    };
    let (key, mut block) = (unhex(f[1]).ok_or("error op")?, unhex(f[2]).ok_or("error op")?);
    let n: u64 = if iterated { f[3].parse().map_err(|_| "error op")? } else { 1 };
    if block.len() != block_len(cipher) || n == 0 {
        return Err("error lengths");
    }
    let step = match source {
        "rustcrypto" => rustcrypto(cipher, &key),
        _ => cryptographyrs(cipher, &key),
    }
    .ok_or("error lengths")?;
    for _ in 0..n {
        step(op.starts_with("enc"), &mut block);
    }
    Ok(block.iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(cipher), Some(source)) = (args.get(1), args.get(2)) else {
        eprintln!("usage: simon-speck-witness <cipher> rustcrypto|cryptographyrs");
        std::process::exit(2);
    };
    if !["rustcrypto", "cryptographyrs"].contains(&source.as_str()) {
        eprintln!("unknown implementation {source}");
        std::process::exit(2);
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let reply = answer(cipher, source, &line.expect("stdin")).unwrap_or_else(|e| e.to_string());
        writeln!(out, "{reply}").unwrap();
        out.flush().unwrap();
    }
}
