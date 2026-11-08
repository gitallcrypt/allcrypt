//! The crc 3.4.0 crate as a witness, under the request lines
//! `../crc_python.py` describes: `Crc::<u128>` over an `Algorithm` built from
//! the request, its default table implementation, and the same CRC again
//! through `NoTable` and `Table<16>`, which must agree. The data goes in
//! pieces of 1, 2, 3 .. bytes through a `Digest`.

use std::io::{self, BufRead, Write};

use crc::{Algorithm, Crc, NoTable, Table};

fn answer(line: &str) -> Result<String, &'static str> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() != 8 || f[0] != "crc" {
        return Err("error request");
    }
    let width: u8 = f[1].parse().map_err(|_| "error request")?;
    let hex = |s: &str| u128::from_str_radix(s, 16).map_err(|_| "error request");
    let data: Vec<u8> = if f[7] == "-" {
        Vec::new()
    } else {
        (0..f[7].len()).step_by(2)
            .map(|i| u8::from_str_radix(&f[7][i..i + 2], 16).map_err(|_| "error request"))
            .collect::<Result<_, _>>()?
    };
    if width == 0 || width > 128 {
        return Err("error unsupported");
    }
    // The crate's Algorithm wants 'static: one per request, leaked.
    let algorithm: &'static Algorithm<u128> = Box::leak(Box::new(Algorithm {
        width,
        poly: hex(f[2])?,
        init: hex(f[3])?,
        refin: f[4] == "1",
        refout: f[5] == "1",
        xorout: hex(f[6])?,
        check: 0,
        residue: 0,
    }));
    let default = Crc::<u128>::new(algorithm);
    let mut digest = default.digest();
    let (mut at, mut piece) = (0, 1);
    while at < data.len() {
        let take = piece.min(data.len() - at);
        digest.update(&data[at..at + take]);
        at += take;
        piece += 1;
    }
    let value = digest.finalize();
    let plain = Crc::<u128, NoTable>::new(algorithm).checksum(&data);
    let sliced = Crc::<u128, Table<16>>::new(algorithm).checksum(&data);
    if plain != value || sliced != value {
        return Err("error the crate's implementations disagree");
    }
    let bytes = (width as usize).div_ceil(8);
    Ok(value.to_be_bytes()[16 - bytes..].iter().map(|b| format!("{b:02x}")).collect())
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let reply = answer(&line.unwrap()).unwrap_or_else(|e| e.to_string());
        writeln!(stdout, "{reply}").unwrap();
        stdout.flush().unwrap();
    }
}
