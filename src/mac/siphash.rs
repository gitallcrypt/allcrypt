/*!
SipHash (Aumasson and Bernstein, 2012) and HalfSipHash: keyed hashes
for short inputs, which hash tables use to keep an attacker from
choosing keys that collide.

SipHash keeps four 64 bit words, initialised from a 128 bit key and four
constants (the ASCII of "somepseudorandomlygeneratedbytes"), and runs
`c` rounds of add, rotate and XOR per 8 byte word of message and `d`
more at the end; SipHash-2-4 is the standard choice and SipHash-1-3 the
faster one Rust's and Python's hash tables use. The last word carries
the message's length in its top byte. The 128 bit output XORs 0xee
into the state where the 64 bit one leaves it, and 0xdd before a second
finalisation.

HalfSipHash is the same on 32 bit words, with a 64 bit key and 32 or 64
bits out, for where 64 bit arithmetic is slow; its rotations are
different and two of its constants are halves of SipHash's. Its designers
call it not to be used where SipHash fits.

Nothing about either is typed: the reference implementation's
`vectors.h`, vendored as `rfcs/siphash-vectors.h`, is read by
`tests/test_siphash.rs`, and Bouncy Castle and OpenSSL check SipHash at
other round counts.
*/

/// The initial values: "somepseudorandomlygeneratedbytes", big endian.
const C: [u64; 4] = {
    let text = b"somepseudorandomlygeneratedbytes";
    let mut out = [0u64; 4];
    let mut i = 0;
    while i < 32 {
        out[i / 8] = out[i / 8] << 8 | text[i] as u64;
        i += 1;
    }
    out
};

fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

fn half_round(v: &mut [u32; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(5) ^ v[0];
    v[0] = v[0].rotate_left(16);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(8) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(7) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[2];
    v[2] = v[2].rotate_left(16);
}

fn check(c: usize, d: usize, out_len: usize, lengths: [usize; 2], name: &str)
         -> Result<(), String> {
    if c == 0 || d == 0 {
        return Err(format!("{name} needs at least one round of each kind, not {c} and {d}."));
    }
    if !lengths.contains(&out_len) {
        return Err(format!("{name} gives {} or {} bytes, not {out_len}.", lengths[0],
                           lengths[1]));
    }
    Ok(())
}

/// SipHash-`c`-`d` of `data` under a 16 byte `key`, 8 or 16 bytes out.
///
/// # Errors
/// No rounds of either kind, or another output length.
pub fn siphash(key: &[u8; 16], data: &[u8], c: usize, d: usize, out_len: usize)
               -> Result<Vec<u8>, String> {
    check(c, d, out_len, [8, 16], "SipHash")?;
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
    let mut v = [k0 ^ C[0], k1 ^ C[1], k0 ^ C[2], k1 ^ C[3]];
    if out_len == 16 {
        v[1] ^= 0xee;
    }
    let words = data.chunks_exact(8);
    let tail = words.remainder();
    let mut last = [0u8; 8];
    last[..tail.len()].copy_from_slice(tail);
    last[7] = data.len() as u8;
    for word in words.map(|w| w.try_into().expect("8 bytes")).chain([last]) {
        let m = u64::from_le_bytes(word);
        v[3] ^= m;
        for _ in 0..c {
            sip_round(&mut v);
        }
        v[0] ^= m;
    }
    // The first half of the output after 0xff, or 0xee for 16 bytes;
    // the second after 0xdd, in another word.
    v[2] ^= if out_len == 16 { 0xee } else { 0xff };
    let mut out = Vec::with_capacity(out_len);
    for half in 0..out_len / 8 {
        if half == 1 {
            v[1] ^= 0xdd;
        }
        for _ in 0..d {
            sip_round(&mut v);
        }
        out.extend_from_slice(&(v[0] ^ v[1] ^ v[2] ^ v[3]).to_le_bytes());
    }
    Ok(out)
}

/// HalfSipHash-`c`-`d` of `data` under an 8 byte `key`, 4 or 8 bytes out.
///
/// # Errors
/// No rounds of either kind, or another output length.
pub fn halfsiphash(key: &[u8; 8], data: &[u8], c: usize, d: usize, out_len: usize)
                   -> Result<Vec<u8>, String> {
    check(c, d, out_len, [4, 8], "HalfSipHash")?;
    let k0 = u32::from_le_bytes(key[..4].try_into().expect("4 bytes"));
    let k1 = u32::from_le_bytes(key[4..].try_into().expect("4 bytes"));
    // The top halves of SipHash's last two constants.
    let mut v = [k0, k1, (C[2] >> 32) as u32 ^ k0, (C[3] >> 32) as u32 ^ k1];
    if out_len == 8 {
        v[1] ^= 0xee;
    }
    let words = data.chunks_exact(4);
    let tail = words.remainder();
    let mut last = [0u8; 4];
    last[..tail.len()].copy_from_slice(tail);
    last[3] = data.len() as u8;
    for word in words.map(|w| w.try_into().expect("4 bytes")).chain([last]) {
        let m = u32::from_le_bytes(word);
        v[3] ^= m;
        for _ in 0..c {
            half_round(&mut v);
        }
        v[0] ^= m;
    }
    v[2] ^= if out_len == 8 { 0xee } else { 0xff };
    let mut out = Vec::with_capacity(out_len);
    for half in 0..out_len / 4 {
        if half == 1 {
            v[1] ^= 0xdd;
        }
        for _ in 0..d {
            half_round(&mut v);
        }
        out.extend_from_slice(&(v[1] ^ v[3]).to_le_bytes());
    }
    Ok(out)
}
