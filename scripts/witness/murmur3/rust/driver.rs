// The murmur3 crate 0.5.2 (stusmall/murmur3), Rust: x86_32, x86_128 and
// x64_128, each reading from a `Read`. One request per line on stdin,
// "NAME KEY PATH", KEY "seed:" and eight hex digits; answered with the
// hash of the file's bytes, each word big endian, first word first, or
// "error". The reader hands the data over in pieces of 1, 2, 3 ...
// bytes, whatever the crate asks for.
use std::io::{BufRead, Read, Write};

struct Pieces<'a> {
    data: &'a [u8],
    step: usize,
}

impl Read for Pieces<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let n = self.step.min(self.data.len()).min(out.len());
        out[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        self.step += 1;
        Ok(n)
    }
}

fn answer(name: &str, key: &str, data: &[u8]) -> Option<String> {
    let digits = key.strip_prefix("seed:").filter(|d| d.len() == 8)?;
    let seed = u32::from_str_radix(digits, 16).ok()?;
    let mut source = Pieces { data, step: 1 };
    Some(match name {
        "murmur3_32" => format!("{:08x}", murmur3::murmur3_32(&mut source, seed).ok()?),
        "murmur3_x86_128" => {
            // h1 in the low 32 bits up to h4 in the top.
            let v = murmur3::murmur3_x86_128(&mut source, seed).ok()?;
            format!("{:08x}{:08x}{:08x}{:08x}", v as u32, (v >> 32) as u32, (v >> 64) as u32,
                    (v >> 96) as u32)
        }
        "murmur3_x64_128" => {
            // h1 in the low half.
            let v = murmur3::murmur3_x64_128(&mut source, seed).ok()?;
            format!("{:016x}{:016x}", v as u64, (v >> 64) as u64)
        }
        _ => return None,
    })
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
