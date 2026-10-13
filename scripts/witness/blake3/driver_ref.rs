// The BLAKE3 team's reference implementation (reference_impl.rs), which
// follows the specification's structure rather than the fast one's.
// Requests as driver_c.c's: MODE/LENGTH/SEEK PATH, one per line on stdin.
// The reference has no seek, so the output is computed from byte 0 and
// cut. The data goes in in pieces of 1, 2, 3 ... bytes. build.sh puts
// reference_impl.rs beside this file as a module.
mod reference_impl;

use reference_impl::Hasher;

fn unhex(hex: &str) -> Option<Vec<u8>> {
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect()
}

fn answer(line: &str) -> Option<String> {
    let (name, path) = line.trim().split_once(' ')?;
    let mut parts = name.split('/');
    let (mode, length, seek) = (parts.next()?, parts.next()?.parse::<usize>().ok()?,
                                parts.next()?.parse::<usize>().ok()?);
    let mut hasher = if mode == "hash" {
        Hasher::new()
    } else if let Some(key) = mode.strip_prefix("keyed=") {
        Hasher::new_keyed(&unhex(key)?.try_into().ok()?)
    } else {
        Hasher::new_derive_key(std::str::from_utf8(&unhex(mode.strip_prefix("derive=")?)?).ok()?)
    };
    let data = std::fs::read(path).ok()?;
    let (mut at, mut step) = (0, 1);
    while at < data.len() {
        let end = (at + step).min(data.len());
        hasher.update(&data[at..end]);
        at = end;
        step += 1;
    }
    let mut out = vec![0u8; seek + length];
    hasher.finalize(&mut out);
    Some(out[seek..].iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    use std::io::BufRead;
    for line in std::io::stdin().lock().lines() {
        println!("{}", answer(&line.expect("a line")).unwrap_or_else(|| "error".to_string()));
    }
}
