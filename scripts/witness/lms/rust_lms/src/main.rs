//! The hbs-lms 0.2.0-alpha.1 crate as a witness, under the request lines
//! `../selftest.py` describes. It verifies: its keys come from its own
//! derivation of the top tree, not from a SEED and I given, so it signs
//! no request. Only the SHA-256/256 parameter sets, at every level: the
//! crate takes the hash as a type parameter, one for the whole hierarchy,
//! and reads the SHA-256/256 type codes for every hash, so RFC 9858's
//! codes are unknown to it. An unknown code panics in
//! its parser, which this catches and answers "bad".

use std::io::{self, BufRead, Write};
use std::panic;

use hbs_lms::{verify, Sha256_256};

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s == "-" {
        return Some(Vec::new());
    }
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Whether every tree the signature names, and the public key, is of a
/// SHA-256/256 parameter set; `true` for a signature too short to say.
fn sha256_only(public: &[u8], signature: &[u8]) -> bool {
    let word = |b: &[u8], at: usize| b.get(at..at + 4)
        .map(|w| u32::from_be_bytes(w.try_into().unwrap()));
    let p = |ots: u32| [265usize, 133, 67, 34][(ots - 1) as usize];
    let h = |lms: u32| [5usize, 10, 15, 20, 25][(lms - 5) as usize];
    if !matches!(word(public, 4), Some(5..=9)) || !matches!(word(public, 8), Some(1..=4)) {
        return false;
    }
    let Some(nspk) = word(signature, 0) else { return true };
    let mut at = 4;
    for level in 0..=nspk.min(8) {
        let Some(ots) = word(signature, at + 4) else { return true };
        if !(1..=4).contains(&ots) {
            return false;
        }
        let lms_at = at + 8 + 32 * (p(ots) + 1);
        let Some(lms) = word(signature, lms_at) else { return true };
        if !(5..=9).contains(&lms) {
            return false;
        }
        at = lms_at + 4 + 32 * h(lms);
        if level < nspk {
            match (word(signature, at), word(signature, at + 4)) {
                (Some(5..=9), Some(1..=4)) => at += 24 + 32,
                (Some(_), Some(_)) => return false,
                _ => return true,
            }
        }
    }
    true
}

fn answer(line: &str) -> String {
    let f: Vec<&str> = line.split_whitespace().collect();
    match f.first() {
        Some(&"verify") if f.len() == 4 => {}
        Some(&"lms") | Some(&"hss") => return "error unsupported".into(),
        _ => return "error request".into(),
    }
    let (Some(public), Some(message), Some(signature)) = (unhex(f[1]), unhex(f[2]), unhex(f[3]))
    else {
        return "error request".into();
    };
    if public.len() < 8 {
        return "bad".into();
    }
    if !sha256_only(&public, &signature) {
        return "error unsupported".into();
    }
    let ok = panic::catch_unwind(|| verify::<Sha256_256>(&message, &signature, &public).is_ok())
        .unwrap_or(false);
    if ok { "ok" } else { "bad" }.into()
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        writeln!(stdout, "{}", answer(&line.unwrap())).unwrap();
        stdout.flush().unwrap();
    }
}
