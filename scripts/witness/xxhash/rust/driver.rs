// twox-hash 2.1.5, Jake Goulding's Rust xxHash, compiled with its scalar
// XXH3 path. One request per line on stdin, "NAME KEY PATH", KEY "seed:"
// and sixteen hex digits or "secret:" and a path; answered with the big
// endian hash of the file's bytes as lowercase hex, or "error". Seeded
// hashes stream, in pieces of 1, 2, 3 ... bytes; a secret goes through
// the one-shot functions, because the streaming hasher takes a secret
// only together with a seed, and uses the default secret for short
// inputs when it does.
use std::hash::Hasher;
use std::io::{BufRead, Write};
use twox_hash::{XxHash32, XxHash3_128, XxHash3_64, XxHash64};

fn pieces(data: &[u8], mut write: impl FnMut(&[u8])) {
    let (mut at, mut step) = (0, 1);
    while at < data.len() {
        let end = (at + step).min(data.len());
        write(&data[at..end]);
        at = end;
        step += 1;
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn answer(name: &str, key: &str, data: &[u8]) -> Option<String> {
    if let Some(seed) = key.strip_prefix("seed:") {
        let seed = u64::from_str_radix(seed, 16).ok().filter(|_| seed.len() == 16)?;
        return Some(match name {
            "xxh32" => {
                let mut h = XxHash32::with_seed(u32::try_from(seed).ok()?);
                pieces(data, |p| h.write(p));
                hex(&h.finish_32().to_be_bytes())
            }
            "xxh64" => {
                let mut h = XxHash64::with_seed(seed);
                pieces(data, |p| h.write(p));
                hex(&h.finish().to_be_bytes())
            }
            "xxh3" => {
                let mut h = XxHash3_64::with_seed(seed);
                pieces(data, |p| h.write(p));
                hex(&h.finish().to_be_bytes())
            }
            "xxh128" => {
                let mut h = XxHash3_128::with_seed(seed);
                pieces(data, |p| h.write(p));
                hex(&h.finish_128().to_be_bytes())
            }
            _ => return None,
        });
    }
    let secret = std::fs::read(key.strip_prefix("secret:")?).ok()?;
    match name {
        "xxh3" => XxHash3_64::oneshot_with_secret(&secret, data).ok()
            .map(|v| hex(&v.to_be_bytes())),
        "xxh128" => XxHash3_128::oneshot_with_secret(&secret, data).ok()
            .map(|v| hex(&v.to_be_bytes())),
        _ => None,
    }
}

fn main() {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let parts: Vec<&str> = line.split_whitespace().collect();
        let reply = match parts.as_slice() {
            [name, key, path] => std::fs::read(path).ok().and_then(|d| answer(name, key, &d)),
            _ => None,
        };
        writeln!(out, "{}", reply.unwrap_or_else(|| "error".to_string())).unwrap();
        out.flush().unwrap();
    }
}
