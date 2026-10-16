// jedisct1/rust-lwbc's Speck and Simon as a witness, speaking
// ../nessie/driver.h's request format on stdin and stdout:
//
//     enc <key hex> <block hex>          one block
//     dec <key hex> <block hex>
//     enc-n <key hex> <block hex> <n>    the block encrypted n times over
//     dec-n <key hex> <block hex> <n>
//
// answered with hex, or "error lengths" or "error op". The one argument is
// the cipher: speck32, speck48, speck64, speck96, simon32, simon48,
// simon64 or simon96, each at the one key length lwbc has for it.
//
// The key goes to the crate's own from_bytes. Its block functions take
// the word x first; the designers' encoding, which Crypto++, the Linux
// kernel and inmcm read, has y first, so the block goes through the
// crate's word functions here, y read from the first half of the bytes and
// x from the second, each little-endian, and the result written the same
// way.
use std::io::{BufRead, Write};

macro_rules! cipher {
    ($kind:ident, $word:ty, $bytes:expr, $keylen:expr) => {
        |op: &str, key: &[u8], block: &mut [u8], n: u64| -> Result<(), ()> {
            let key: [u8; $keylen] = key.try_into().map_err(|_| ())?;
            if block.len() != 2 * $bytes {
                return Err(());
            }
            let c = lwbc::$kind::from_bytes(key);
            let word = |b: &[u8]| b.iter().rev().fold(0 as $word, |w, &x| w << 8 | x as $word);
            let (mut y, mut x) = (word(&block[..$bytes]), word(&block[$bytes..]));
            for _ in 0..n {
                [x, y] = if op.starts_with("enc") { c.encrypt([x, y]) } else { c.decrypt([x, y]) };
            }
            for (i, w) in [y, x].into_iter().enumerate() {
                block[i * $bytes..(i + 1) * $bytes].copy_from_slice(&w.to_le_bytes()[..$bytes]);
            }
            Ok(())
        }
    };
}

type Step = fn(&str, &[u8], &mut [u8], u64) -> Result<(), ()>;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_default();
    let step: Step = match name.as_str() {
        "speck32" => cipher!(Speck32, u16, 2, 8),
        "speck48" => cipher!(Speck48, u32, 3, 12),
        "speck64" => cipher!(Speck64, u32, 4, 16),
        "speck96" => cipher!(Speck96, u64, 6, 18),
        "simon32" => cipher!(Simon32, u16, 2, 8),
        "simon48" => cipher!(Simon48, u32, 3, 12),
        "simon64" => cipher!(Simon64, u32, 4, 16),
        "simon96" => cipher!(Simon96, u64, 6, 18),
        _ => {
            eprintln!("usage: lwbc-driver speck32|speck48|speck64|speck96|simon32|simon48|simon64|simon96");
            std::process::exit(2);
        }
    };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let f: Vec<&str> = line.split_whitespace().collect();
        let answer = (|| {
            let op = *f.first().ok_or("error op")?;
            let iterated = op == "enc-n" || op == "dec-n";
            if !iterated && op != "enc" && op != "dec" || f.len() < 3 {
                return Err("error op");
            }
            let unhex = |s: &str| -> Option<Vec<u8>> {
                (0..s.len()).step_by(2)
                    .map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
                    .collect()
            };
            let n: u64 = if iterated {
                f.get(3).and_then(|t| t.parse().ok()).filter(|&n| n >= 1 && f.len() == 4)
                    .ok_or("error lengths")?
            } else if f.len() == 3 {
                1
            } else {
                return Err("error lengths");
            };
            let key = unhex(f[1]).ok_or("error lengths")?;
            let mut block = unhex(f[2]).ok_or("error lengths")?;
            step(op, &key, &mut block, n).map_err(|_| "error lengths")?;
            Ok(block.iter().map(|b| format!("{b:02x}")).collect::<String>())
        })();
        writeln!(out, "{}", answer.unwrap_or_else(|e| e.to_string())).expect("stdout");
        out.flush().expect("stdout");
    }
}
