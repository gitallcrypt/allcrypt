// fletcher16, fletcher32 and fletcher64 from the fletcher crate, which
// sums words the caller makes: here little endian, the last one padded
// with zeros. One request per line on stdin, "NAME PATH", answered with
// the checksum of the file's bytes as lowercase big endian hex, or
// "error". The words go in in pieces of 1, 2, 3 ... words.
use std::io::{self, BufRead, Write};

use fletcher::{Fletcher16, Fletcher32, Fletcher64};

fn words(data: &[u8], width: usize) -> Vec<u64> {
    data.chunks(width)
        .map(|w| w.iter().rev().fold(0u64, |acc, &b| acc << 8 | u64::from(b)))
        .collect()
}

fn pieces<T: Copy>(words: &[T], mut update: impl FnMut(&[T])) {
    let (mut at, mut step) = (0, 1);
    while at < words.len() {
        update(&words[at..(at + step).min(words.len())]);
        at += step;
        step += 1;
    }
}

fn checksum(name: &str, data: &[u8]) -> Option<String> {
    Some(match name {
        "fletcher16" => {
            let mut f = Fletcher16::new();
            pieces(data, |w| f.update(w));
            format!("{:04x}", f.value())
        }
        "fletcher32" => {
            let w: Vec<u16> = words(data, 2).into_iter().map(|w| w as u16).collect();
            let mut f = Fletcher32::new();
            pieces(&w, |w| f.update(w));
            format!("{:08x}", f.value())
        }
        "fletcher64" => {
            let w: Vec<u32> = words(data, 4).into_iter().map(|w| w as u32).collect();
            let mut f = Fletcher64::new();
            pieces(&w, |w| f.update(w));
            format!("{:016x}", f.value())
        }
        _ => return None,
    })
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in io::stdin().lock().lines() {
        let line = line.expect("a line");
        let parts: Vec<&str> = line.split_whitespace().collect();
        let answer = match parts.as_slice() {
            [name, path] => std::fs::read(path).ok().and_then(|data| checksum(name, &data)),
            _ => None,
        };
        writeln!(out, "{}", answer.as_deref().unwrap_or("error")).expect("stdout");
        out.flush().expect("stdout");
    }
}
