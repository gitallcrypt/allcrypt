/*
Unix `crypt(3)`: the password hashes that live in `/etc/shadow`, the
NIS maps, and every `.htpasswd` and LDAP `userPassword` written in the
last fifty years. One function dispatches on the setting string's prefix,
as the C library does, and returns the whole hash string.

| prefix | method | since |
|---|---|---|
| (two base64 chars) | traditional DES, 25 rounds, 12-bit salt | 1979 |
| `_` | BSDi extended DES, variable rounds, 24-bit salt | 1980s |
| (long, no prefix) | bigcrypt: DES over every 8 chars, not just the first | HP-UX, Digital |
| `$1$` | MD5-crypt (Poul-Henning Kamp, FreeBSD) | 1994 |
| `$2a$` `$2b$` `$2x$` `$2y$` | bcrypt (Provos and Mazières) | 1999 |
| `$3$` | NT hash in crypt clothing (MD4 of UTF-16LE) | Samba |
| `$5$` `$6$` | SHA-256 / SHA-512 crypt (Drepper) | 2007 |
| `$sha1$` | PBKDF1-style HMAC-SHA-1 crypt | NetBSD |
| `$md5` | Sun's MD5 crypt, with Hamlet in the loop | Solaris |

None of these is what you would choose today - that is Argon2, or scrypt,
or at the very least bcrypt with a high cost. They are here because the
hashes already exist and something has to read them, which is the whole
premise of this library.

## The shape they share, and where they differ

A `crypt(3)` setting is both the salt and the choice of algorithm: the
prefix names the method, the rest carries the salt (and, for the modern
ones, a cost). `crypt(password, hash)` returns a string that begins with
the same setting, so verifying a password is `crypt(pw, stored) ==
stored`, in constant time (`verify`).

The base64 is **not** RFC 4648. It is the alphabet `./0-9A-Za-z`, and the
hashes pack their 24-bit groups least-significant-six-bits first - except
bcrypt, which has its own alphabet (`./A-Za-z0-9`) and packs the other
way. Getting the alphabet or the bit order wrong gives a string that
decodes to the right bytes nowhere.

## Pitfalls that cost a wrong hash and no error

  * **DES crypt packs each password byte shifted left one bit** into the
    56-bit key, and truncates the password to 8 bytes. bigcrypt is the
    same cipher over each 8-byte block, the salt carried from the
    previous block's output. The salt perturbs DES's E-box, which is why
    this uses `des::crypt_des` and not the plain cipher.
  * **MD5-crypt and the SHA-crypts add the password to the digest one bit
    at a time** at the end of the priming phase - for each 1 bit of the
    length, a byte of the digest; for each 0, a byte of the password.
    This looks like a bug and is load-bearing.
  * **The SHA-crypts' main loop runs `rounds` times** (default 5,000,
    clamped to 1,000..=999,999,999), folding the password and salt in on
    a schedule keyed by the index mod 3 and mod 7.
  * **bcrypt's `$2a$`, `$2x$` and `$2y$` differ only in how a password
    byte with the top bit set is read.** `$2x$` reproduces a
    sign-extension bug; `$2a$` adds a safety step that flips one key bit
    for the passwords where the bug would collide; `$2b$` and `$2y$` are
    the correct reading. For an all-ASCII password all four agree, which
    is why the difference went unnoticed for years.
  * **Sun's MD5 crypt feeds a passage of Hamlet into the hash** on rounds
    chosen by a "coin toss" over the previous digest. The text is a
    constant of the algorithm; `unix_crypt_hamlet.txt` holds it.
*/

use crate::block_ciphers::blowfish::Blowfish;
use crate::block_ciphers::des;
use crate::hash_functions::md4::Md4;
use crate::hash_functions::md5::MD5;
use crate::hash_functions::sha1::SHA1;
use crate::hash_functions::sha2::{SHA256, SHA512};
use crate::hash_functions::HashFunction;
use crate::mac::Hmac;
use crate::Mac;

/// The `crypt(3)` base64 alphabet: `.`, `/`, digits, upper, lower.
const CRYPT64: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// bcrypt's alphabet, which is the other common order.
const BCRYPT64: &[u8; 64] =
    b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn index_in(alphabet: &[u8; 64], ch: u8) -> Option<usize> {
    alphabet.iter().position(|&c| c == ch)
}

/// `n` base64 characters of `value`, least-significant six bits first -
/// the order md5-crypt and the SHA-crypts use for each 24-bit group.
fn b64_low_first(out: &mut String, value: u32, n: usize) {
    let mut v = value;
    for _ in 0..n {
        out.push(CRYPT64[(v & 0x3f) as usize] as char);
        v >>= 6;
    }
}

/// `seed` repeated and truncated to exactly `n` bytes - the SHA-crypts'
/// P and S byte sequences.
fn stretch(seed: &[u8], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        let take = (n - out.len()).min(seed.len());
        out.extend_from_slice(&seed[..take]);
    }
    out
}

/// A digest byte index in a permutation, or `ZERO` for the literal zero
/// byte the last group of each method substitutes (C's
/// `b64_from_24bit(0, ...)`).
const ZERO: usize = usize::MAX;

fn permuted_value(digest: &[u8], triple: [usize; 3]) -> u32 {
    let byte = |i: usize| if i == ZERO { 0u32 } else { digest[i] as u32 };
    (byte(triple[0]) << 16) | (byte(triple[1]) << 8) | byte(triple[2])
}

// ----------------------------------------------------------- DES crypt ---

/// The 56-bit DES key from up to eight password bytes, each shifted left
/// one bit (the low bit is parity, which PC1 drops). Bytes past the
/// eighth are ignored - the defining weakness of traditional crypt.
fn des_key(password: &[u8]) -> u64 {
    let mut key = 0u64;
    for i in 0..8 {
        let byte = password.get(i).copied().unwrap_or(0);
        key = (key << 8) | u64::from(byte << 1);
    }
    key
}

/// The 11-character encoding `crypt`'s DES hash uses: the eight output
/// bytes, big-endian, in groups that straddle characters (not the
/// least-significant-first packing the other methods use).
fn des_encode(block: u64) -> String {
    let bytes = block.to_be_bytes();
    let mut out = String::with_capacity(11);
    let mut i = 0;
    let mut carry;
    // Mirrors libxcrypt's des_gen_hash loop exactly.
    let mut push = |v: usize| out.push(CRYPT64[v & 0x3f] as char);
    loop {
        let c1 = bytes[i] as usize;
        push(c1 >> 2);
        carry = (c1 & 0x03) << 4;
        if i + 1 >= 8 {
            push(carry);
            break;
        }
        let c2 = bytes[i + 1] as usize;
        push(carry | (c2 >> 4));
        carry = (c2 & 0x0f) << 2;
        if i + 2 >= 8 {
            push(carry);
            break;
        }
        let c3 = bytes[i + 2] as usize;
        push(carry | (c3 >> 6));
        push(c3 & 0x3f);
        i += 3;
    }
    out
}

fn descrypt(password: &[u8], setting: &str) -> Result<String, String> {
    let s = setting.as_bytes();
    if s.len() < 2 {
        return Err("A DES crypt setting is at least two salt characters.".to_string());
    }
    let s0 = index_in(CRYPT64, s[0]).ok_or("Bad salt character.")?;
    let s1 = index_in(CRYPT64, s[1]).ok_or("Bad salt character.")?;
    let salt = (s0 | (s1 << 6)) as u32;
    let block = des::crypt_des(des_key(password), salt, 0, 25);
    Ok(format!("{}{}{}", s[0] as char, s[1] as char, des_encode(block)))
}

fn bigcrypt(password: &[u8], setting: &str) -> Result<String, String> {
    let s = setting.as_bytes();
    let s0 = index_in(CRYPT64, s[0]).ok_or("Bad salt character.")?;
    let s1 = index_in(CRYPT64, s[1]).ok_or("Bad salt character.")?;
    let mut salt = (s0 | (s1 << 6)) as u32;
    let mut out = format!("{}{}", s[0] as char, s[1] as char);
    let mut offset = 0;
    // At most sixteen segments: bigcrypt hashes the first 128 bytes and
    // ignores the rest, as the original did.
    for _ in 0..16 {
        let segment = &password[offset.min(password.len())..];
        let block = des::crypt_des(des_key(segment), salt, 0, 25);
        let encoded = des_encode(block);
        out.push_str(&encoded);
        offset += 8;
        if offset >= password.len() {
            break;
        }
        // The next segment's salt is the first two characters of this
        // segment's output - "found by dowsing", as the C comment says.
        let b = encoded.as_bytes();
        salt = (index_in(CRYPT64, b[0]).unwrap_or(0)
            | (index_in(CRYPT64, b[1]).unwrap_or(0) << 6)) as u32;
    }
    Ok(out)
}

fn bsdicrypt(password: &[u8], setting: &str) -> Result<String, String> {
    let s = setting.as_bytes();
    if s.len() < 9 || s[0] != b'_' {
        return Err("A BSDi crypt setting is '_' then four count and four salt \
                    characters.".to_string());
    }
    let mut count = 0u32;
    let mut salt = 0u32;
    for i in 0..4 {
        count |= (index_in(CRYPT64, s[1 + i]).ok_or("Bad count character.")? as u32) << (6 * i);
        salt |= (index_in(CRYPT64, s[5 + i]).ok_or("Bad salt character.")? as u32) << (6 * i);
    }
    // Fold a long password into one 64-bit key (BSDi's scheme): the next
    // key is this block, shifted, XORed with the previous block's DES
    // output under itself (salt 0). The first "previous output" is zero.
    let mut pk = 0u64;
    let mut offset = 0;
    let key = loop {
        let mut block = 0u64;
        for i in 0..8 {
            let byte = password.get(offset + i).copied().unwrap_or(0);
            block = (block << 8) | u64::from(byte << 1);
        }
        let kb = pk ^ block;
        // The phrase pointer advances only over real bytes, so it reaches
        // the terminator once every byte has been consumed.
        offset = (offset + 8).min(password.len());
        if offset >= password.len() {
            break kb;
        }
        // pk = DES(plaintext = kb) under key = kb.
        pk = des::crypt_des(kb, 0, kb, 1);
    };
    let hash = des::crypt_des(key, salt, 0, count);
    Ok(format!("{}{}", &setting[..9], des_encode(hash)))
}

// --------------------------------------------- MD5-crypt and SHA-crypt ---

/// The common skeleton of md5-crypt and the SHA-crypts, parameterised by
/// the digest. `block` is the digest length; `permute` lists the output
/// byte triples and how many characters each produces.
struct ShaLike {
    prefix: &'static str,
    block: usize,
    default_rounds: Option<u64>,
    permute: &'static [([usize; 3], usize)],
}

fn digest_of<H: HashFunction>(mut h: H, parts: &[&[u8]]) -> Vec<u8> {
    for p in parts {
        h.update(p);
    }
    h.digest()
}

impl ShaLike {
    fn hash(&self, parts: &[&[u8]]) -> Vec<u8> {
        match self.block {
            16 => digest_of(MD5::new(&[]), parts),
            32 => digest_of(SHA256::new(&[]), parts),
            _ => digest_of(SHA512::new(&[], 512), parts),
        }
    }

    fn run(&self, password: &[u8], setting: &str) -> Result<String, String> {
        let rest = setting.strip_prefix(self.prefix)
            .ok_or("Setting does not start with this method's prefix.")?;
        let (rounds, rounds_custom, salt_text) = self.parse_rounds(rest)?;
        let alt = self.hash(&[password, salt_text.as_bytes(), password]);
        self.finish(password, salt_text.as_bytes(), &alt, rounds, rounds_custom, &salt_text)
    }

    fn parse_rounds(&self, rest: &str) -> Result<(u64, bool, String), String> {
        let (mut rounds, mut custom) = (self.default_rounds.unwrap_or(1000), false);
        let mut body = rest;
        if let Some(after) = rest.strip_prefix("rounds=") {
            let end = after.find('$').ok_or("rounds= without a following '$'.")?;
            let digits = &after[..end];
            if digits.starts_with('0') || digits.is_empty()
                || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err("A rounds value is a positive decimal without leading zeros."
                           .to_string());
            }
            let value: u64 = digits.parse().map_err(|_| "rounds value out of range.")?;
            rounds = value.clamp(1000, 999_999_999);
            custom = true;
            body = &after[end + 1..];
        }
        let salt_end = body.find('$').unwrap_or(body.len());
        let salt = &body[..salt_end.min(16)];
        Ok((rounds, custom, salt.to_string()))
    }

    fn finish(&self, password: &[u8], salt: &[u8], alt: &[u8], rounds: u64,
              rounds_custom: bool, salt_text: &str) -> Result<String, String> {
        // Primary digest, done properly here rather than in `run`.
        let mut parts: Vec<&[u8]> = vec![password, salt];
        let full = password.len() / self.block;
        for _ in 0..full {
            parts.push(alt);
        }
        parts.push(&alt[..password.len() % self.block]);
        let mut parts2: Vec<Vec<u8>> = Vec::new();
        let mut len = password.len();
        while len > 0 {
            if len & 1 != 0 {
                parts2.push(alt.to_vec());
            } else {
                parts2.push(password.to_vec());
            }
            len >>= 1;
        }
        let mut refs: Vec<&[u8]> = parts.clone();
        for p in &parts2 {
            refs.push(p);
        }
        let mut digest = self.hash(&refs);

        // P sequence: SHA(password repeated once per password byte),
        // then stretched to exactly the password's length.
        let p_reps: Vec<&[u8]> = (0..password.len()).map(|_| password).collect();
        let p_seq = stretch(&self.hash(&p_reps), password.len());
        // S sequence: SHA(salt repeated 16 + digest[0] times), stretched
        // to the salt's length.
        let s_reps: Vec<&[u8]> = (0..16 + digest[0] as usize).map(|_| salt).collect();
        let s_seq = stretch(&self.hash(&s_reps), salt.len());

        for i in 0..rounds {
            let mut r: Vec<&[u8]> = Vec::new();
            let p: &[u8] = &p_seq;
            let s: &[u8] = &s_seq;
            if i & 1 != 0 {
                r.push(p);
            } else {
                r.push(&digest);
            }
            if i % 3 != 0 {
                r.push(s);
            }
            if i % 7 != 0 {
                r.push(p);
            }
            if i & 1 != 0 {
                r.push(&digest);
            } else {
                r.push(p);
            }
            digest = self.hash(&r);
        }

        let mut out = String::new();
        out.push_str(self.prefix);
        if rounds_custom {
            out.push_str(&format!("rounds={rounds}$"));
        }
        out.push_str(salt_text);
        out.push('$');
        for &(triple, n) in self.permute {
            b64_low_first(&mut out, permuted_value(&digest, triple), n);
        }
        Ok(out)
    }
}

const MD5_CRYPT: ShaLike = ShaLike {
    prefix: "$1$",
    block: 16,
    default_rounds: None,
    permute: &[([0, 6, 12], 4), ([1, 7, 13], 4), ([2, 8, 14], 4), ([3, 9, 15], 4),
               ([4, 10, 5], 4), ([ZERO, ZERO, 11], 2)],
};
const SHA256_CRYPT: ShaLike = ShaLike {
    prefix: "$5$",
    block: 32,
    default_rounds: Some(5000),
    permute: &[([0, 10, 20], 4), ([21, 1, 11], 4), ([12, 22, 2], 4), ([3, 13, 23], 4),
               ([24, 4, 14], 4), ([15, 25, 5], 4), ([6, 16, 26], 4), ([27, 7, 17], 4),
               ([18, 28, 8], 4), ([9, 19, 29], 4), ([ZERO, 31, 30], 3)],
};
const SHA512_CRYPT: ShaLike = ShaLike {
    prefix: "$6$",
    block: 64,
    default_rounds: Some(5000),
    permute: &[([0, 21, 42], 4), ([22, 43, 1], 4), ([44, 2, 23], 4), ([3, 24, 45], 4),
               ([25, 46, 4], 4), ([47, 5, 26], 4), ([6, 27, 48], 4), ([28, 49, 7], 4),
               ([50, 8, 29], 4), ([9, 30, 51], 4), ([31, 52, 10], 4), ([53, 11, 32], 4),
               ([12, 33, 54], 4), ([34, 55, 13], 4), ([56, 14, 35], 4), ([15, 36, 57], 4),
               ([37, 58, 16], 4), ([59, 17, 38], 4), ([18, 39, 60], 4), ([40, 61, 19], 4),
               ([62, 20, 41], 4), ([ZERO, ZERO, 63], 2)],
};

/// md5-crypt's `$1$`: the "weird" 1000-round loop with the md5-specific
/// construction, separate from the SHA-crypts because its length-bit step
/// uses a NUL for the 1 case and the digest for 0.
fn md5_crypt(password: &[u8], setting: &str) -> Result<String, String> {
    let rest = setting.strip_prefix("$1$").ok_or("Not an md5-crypt setting.")?;
    let salt_end = rest.find('$').unwrap_or(rest.len());
    let salt = &rest.as_bytes()[..salt_end.min(8)];

    let alt = digest_of(MD5::new(&[]), &[password, salt, password]);
    let mut parts: Vec<&[u8]> = vec![password, b"$1$", salt];
    let full = password.len() / 16;
    for _ in 0..full {
        parts.push(&alt);
    }
    parts.push(&alt[..password.len() % 16]);
    // For each 1 bit of the length: a NUL byte; for each 0: the first
    // password byte.
    let nul = [0u8];
    let first = [password.first().copied().unwrap_or(0)];
    let mut len = password.len();
    let mut extra: Vec<&[u8]> = Vec::new();
    while len > 0 {
        extra.push(if len & 1 != 0 { &nul[..] } else { &first[..] });
        len >>= 1;
    }
    for e in &extra {
        parts.push(e);
    }
    let mut digest = digest_of(MD5::new(&[]), &parts);

    for i in 0..1000usize {
        let mut r: Vec<&[u8]> = Vec::new();
        if i & 1 != 0 {
            r.push(password);
        } else {
            r.push(&digest);
        }
        if i % 3 != 0 {
            r.push(salt);
        }
        if i % 7 != 0 {
            r.push(password);
        }
        if i & 1 != 0 {
            r.push(&digest);
        } else {
            r.push(password);
        }
        digest = digest_of(MD5::new(&[]), &r);
    }

    let mut out = format!("$1${}$", core::str::from_utf8(salt).unwrap_or(""));
    for &(triple, n) in MD5_CRYPT.permute {
        b64_low_first(&mut out, permuted_value(&digest, triple), n);
    }
    Ok(out)
}

// ------------------------------------------------------------------ NT ---

/// `$3$`: the NT hash (MD4 of the password as UTF-16LE), in crypt
/// clothing. The salt is ignored - two accounts with the same password
/// have the same `$3$` hash, which is the NT hash's original sin.
fn nt_crypt(password: &[u8]) -> String {
    let mut ucs2 = Vec::with_capacity(password.len() * 2);
    for &byte in password {
        ucs2.push(byte);
        ucs2.push(0);
    }
    let digest = digest_of(Md4::new(&[]), &[&ucs2]);
    let mut out = String::from("$3$$");
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------- sha1crypt ---

fn sha1_crypt(password: &[u8], setting: &str) -> Result<String, String> {
    let rest = setting.strip_prefix("$sha1$").ok_or("Not a sha1crypt setting.")?;
    let end = rest.find('$').ok_or("sha1crypt needs an iteration count.")?;
    let iterations: u64 = rest[..end].parse().map_err(|_| "Bad iteration count.")?;
    let after = &rest[end + 1..];
    let salt_end = after.find('$').unwrap_or(after.len());
    let salt = &after[..salt_end];

    // Prime with "<salt>$sha1$<iterations>", keyed by the password.
    let primer = format!("{salt}$sha1${iterations}");
    let mut hmac = Hmac::new(SHA1::new(&[]), password);
    hmac.update(primer.as_bytes());
    let mut buf = hmac.digest();
    for _ in 1..iterations {
        let mut h = Hmac::new(SHA1::new(&[]), password);
        h.update(&buf);
        buf = h.digest();
    }

    let mut out = format!("$sha1${iterations}${salt}$");
    // 20 bytes in big-endian triples, low-six-first, with the last two
    // bytes wrapping to byte 0.
    let mut i = 0;
    while i + 3 <= 18 {
        let v = (buf[i] as u32) << 16 | (buf[i + 1] as u32) << 8 | buf[i + 2] as u32;
        b64_low_first(&mut out, v, 4);
        i += 3;
    }
    let v = (buf[18] as u32) << 16 | (buf[19] as u32) << 8 | buf[0] as u32;
    b64_low_first(&mut out, v, 4);
    Ok(out)
}

// ------------------------------------------------------------- bcrypt ---

/// The eighteen key words bcrypt XORs into P, built as libxcrypt's
/// `BF_set_key` builds them, so that the `$2a$`, `$2b$`, `$2x$` and `$2y$`
/// variants differ exactly as the C does. Returns `(initial, expanded)`:
/// the first with the `$2a$` safety bit applied to word zero, the second
/// without. For `$2b$` and `$2y$` the two are equal.
fn bcrypt_key_words(password: &[u8], bug: bool, safety: bool) -> ([u32; 18], [u32; 18]) {
    const P_INIT0: u32 = 0x243f6a88;
    // The key is the password followed by a NUL, read cyclically.
    let mut key = password.to_vec();
    key.push(0);
    let mut pos = 0usize;
    let mut next = || {
        let b = key[pos];
        pos = (pos + 1) % key.len();
        b
    };
    let mut expanded = [0u32; 18];
    let mut initial = [0u32; 18];
    let mut sign = 0u32;
    let mut diff = 0u32;
    for i in 0..18 {
        let (mut tmp0, mut tmp1) = (0u32, 0u32);
        for j in 0..4 {
            let b = next();
            tmp0 = (tmp0 << 8) | u32::from(b);
            tmp1 = (tmp1 << 8) | ((b as i8) as i32 as u32);
            if j != 0 {
                sign |= tmp1 & 0x80;
            }
        }
        diff |= tmp0 ^ tmp1;
        let word = if bug { tmp1 } else { tmp0 };
        expanded[i] = word;
        initial[i] = word;
    }
    // Only the word 0 of `initial` gets the safety bit, and it is
    // `P_init[0] ^ word` in the C; here `initial` is just the key words
    // that get XORed into P, so we XOR the safety bit in directly.
    diff |= diff >> 16;
    diff &= 0xffff;
    diff = diff.wrapping_add(0xffff);
    sign <<= 9;
    let safety_mask = if safety { 0x10000 } else { 0 };
    sign &= !diff & safety_mask;
    initial[0] ^= sign;
    let _ = P_INIT0;
    (initial, expanded)
}

fn bcrypt_decode_salt(chars: &str) -> Result<Vec<u8>, String> {
    let s = chars.as_bytes();
    if s.len() != 22 {
        return Err("A bcrypt salt is 22 base64 characters.".to_string());
    }
    let mut out = Vec::with_capacity(16);
    let val = |c: u8| index_in(BCRYPT64, c).ok_or("Bad bcrypt salt character.".to_string());
    let mut i = 0;
    while out.len() < 16 {
        let c1 = val(s[i])? as u8;
        let c2 = val(s[i + 1])? as u8;
        out.push((c1 << 2) | ((c2 & 0x30) >> 4));
        if out.len() == 16 {
            break;
        }
        let c3 = val(s[i + 2])? as u8;
        out.push(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2));
        if out.len() == 16 {
            break;
        }
        let c4 = val(s[i + 3])? as u8;
        out.push(((c3 & 0x03) << 6) | c4);
        i += 4;
    }
    Ok(out)
}

fn bcrypt_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    loop {
        let c1 = bytes[i] as usize;
        out.push(BCRYPT64[c1 >> 2] as char);
        let mut c = (c1 & 0x03) << 4;
        if i + 1 >= bytes.len() {
            out.push(BCRYPT64[c] as char);
            break;
        }
        let c2 = bytes[i + 1] as usize;
        c |= c2 >> 4;
        out.push(BCRYPT64[c] as char);
        c = (c2 & 0x0f) << 2;
        if i + 2 >= bytes.len() {
            out.push(BCRYPT64[c] as char);
            break;
        }
        let c3 = bytes[i + 2] as usize;
        out.push(BCRYPT64[c | (c3 >> 6)] as char);
        out.push(BCRYPT64[c3 & 0x3f] as char);
        i += 3;
    }
    out
}

/// "OrpheanBeholderScryDoubt" as six big-endian words - bcrypt's magic.
const BCRYPT_MAGIC: [u32; 6] =
    [0x4f72_7068, 0x6561_6e42, 0x6568_6f6c, 0x6465_7253, 0x6372_7944, 0x6f75_6274];

fn bcrypt(password: &[u8], setting: &str) -> Result<String, String> {
    let s = setting.as_bytes();
    if s.len() < 7 || s[0] != b'$' || s[1] != b'2' {
        return Err("Not a bcrypt setting.".to_string());
    }
    let (bug, safety) = match s[2] {
        b'b' | b'y' => (false, false),
        b'a' => (false, true),
        b'x' => (true, false),
        _ => return Err(format!("Unknown bcrypt variant $2{}$.", s[2] as char)),
    };
    if s[3] != b'$' || !s[4].is_ascii_digit() || !s[5].is_ascii_digit() || s[6] != b'$' {
        return Err("A bcrypt setting is $2?$NN$ then a 22-character salt.".to_string());
    }
    let cost = (s[4] - b'0') as u32 * 10 + (s[5] - b'0') as u32;
    if !(4..=31).contains(&cost) {
        return Err(format!("bcrypt's cost is 04 to 31; this is {cost:02}."));
    }
    let salt = bcrypt_decode_salt(&setting[7..7 + 22])?;

    // bcrypt truncates the password (with its NUL) to 72 bytes.
    let password = &password[..password.len().min(72)];
    let (initial, expanded) = bcrypt_key_words(password, bug, safety);

    // EksBlowfish: key-and-salt expand, then 2^cost rounds of key, salt.
    let mut state = Blowfish::initial();
    state.expand_state_words(&salt, &initial);
    let rounds = 1u64 << cost;
    for _ in 0..rounds {
        state.expand0_state_words(&expanded);
        state.expand0_state(&salt);
    }

    // Encrypt the magic 64 times, each word-pair independently.
    let mut words = BCRYPT_MAGIC;
    for pair in words.chunks_mut(2) {
        let (mut l, mut r) = (pair[0], pair[1]);
        for _ in 0..64 {
            (l, r) = state.encrypt_words(l, r);
        }
        pair[0] = l;
        pair[1] = r;
    }
    let mut bytes = Vec::with_capacity(24);
    for w in words {
        bytes.extend_from_slice(&w.to_be_bytes());
    }
    // 23 of the 24 bytes, bug-compatibly.
    Ok(format!("{}{}", &setting[..7 + 22], bcrypt_encode(&bytes[..23])))
}

// ----------------------------------------------------------- Sun MD5 ---

/// Hamlet's soliloquy, which Sun's MD5 crypt feeds into the hash. Read
/// from a file rather than inlined so the long text is not in the middle
/// of the code; `unix_crypt_hamlet.txt` is the passage as libxcrypt
/// carries it.
const HAMLET: &str = include_str!("unix_crypt_hamlet.txt");

fn sunmd5_nth_bit(digest: &[u8], n: usize) -> u32 {
    u32::from(digest[(n % 128) / 8] >> ((n % 128) % 8) & 1)
}

/// The "muffet coin toss": whether round `round` of Sun's MD5 crypt folds
/// Hamlet into the hash, decided by a walk over the previous digest.
fn muffet_coin_toss(digest: &[u8], round: u32) -> bool {
    let (mut x, mut y) = (0u32, 0u32);
    for i in 0..8usize {
        let step = |off: usize, acc: &mut u32| {
            let a = digest[(i + off) % 16] as usize;
            let b = digest[(i + off + 3) % 16] as usize;
            let r = a >> (b % 5);
            let mut v = digest[r % 16] as usize;
            if b & (1 << (a % 8)) != 0 {
                v /= 2;
            }
            *acc |= sunmd5_nth_bit(digest, v) << i;
        };
        step(0, &mut x);
        step(8, &mut y);
    }
    if sunmd5_nth_bit(digest, round as usize) != 0 {
        x /= 2;
    }
    if sunmd5_nth_bit(digest, round as usize + 64) != 0 {
        y /= 2;
    }
    sunmd5_nth_bit(digest, x as usize) ^ sunmd5_nth_bit(digest, y as usize) != 0
}

fn sunmd5(password: &[u8], setting: &str) -> Result<String, String> {
    // The setting is $md5[,rounds=N]$salt[$ or $$].
    let body = setting.strip_prefix("$md5").ok_or("Not a Sun MD5 setting.")?;
    let body = body.strip_prefix('$').or_else(|| body.strip_prefix(','))
        .ok_or("A Sun MD5 setting is $md5$ or $md5,.")?;
    let mut nrounds = 4096u32;
    let mut rest = body;
    if let Some(after) = body.strip_prefix("rounds=") {
        let end = after.find('$').ok_or("rounds= without a '$'.")?;
        let digits = &after[..end];
        if digits.starts_with('0') || digits.is_empty() {
            return Err("A Sun MD5 rounds value is a positive decimal without leading zeros."
                       .to_string());
        }
        let extra: u32 = digits.parse().map_err(|_| "rounds out of range.")?;
        nrounds = nrounds.wrapping_add(extra);
        rest = &after[end + 1..];
    }
    // The salt runs to the next '$'; a '$' followed by '$' or end is part
    // of the salt (a libxcrypt bug-compatibility quirk). The setting that
    // precedes the hash is everything up to there.
    let salt_len = rest.find('$').unwrap_or(rest.len());
    let mut setting_len = setting.len() - rest.len() + salt_len;
    if rest.as_bytes().get(salt_len) == Some(&b'$')
        && matches!(rest.as_bytes().get(salt_len + 1), Some(&b'$') | None) {
        setting_len += 1;
    }
    let setting_part = &setting[..setting_len];

    let mut digest = digest_of(MD5::new(&[]), &[password, setting_part.as_bytes()]);
    for i in 0..nrounds {
        let mut parts: Vec<&[u8]> = vec![&digest];
        if muffet_coin_toss(&digest, i) {
            // The trailing NUL is deliberately included.
            parts.push(HAMLET.as_bytes());
            parts.push(&[0u8]);
        }
        let number = i.to_string();
        parts.push(number.as_bytes());
        digest = digest_of(MD5::new(&[]), &parts);
    }

    let mut out = format!("{setting_part}$");
    for &(triple, n) in MD5_CRYPT.permute {
        b64_low_first(&mut out, permuted_value(&digest, triple), n);
    }
    Ok(out)
}

// ------------------------------------------------------------ dispatch ---

/// Hash `password` under `setting`, returning the full `crypt(3)` string.
/// `setting` is a complete hash (to verify) or just its prefix and salt
/// (to make a new one). The method is chosen from the prefix.
pub fn crypt(password: &[u8], setting: &str) -> Result<String, String> {
    if let Some(rest) = setting.strip_prefix('$') {
        // The method token runs to the first '$' or ',' - Sun's MD5 is
        // `$md5,rounds=...` as well as `$md5$...`.
        let tag = &rest[..rest.find(['$', ',']).unwrap_or(rest.len())];
        return match tag {
            "1" => md5_crypt(password, setting),
            "2a" | "2b" | "2x" | "2y" => bcrypt(password, setting),
            "3" => Ok(nt_crypt(password)),
            "5" => SHA256_CRYPT.run(password, setting),
            "6" => SHA512_CRYPT.run(password, setting),
            "sha1" => sha1_crypt(password, setting),
            "md5" => sunmd5(password, setting),
            other => Err(format!("Unknown crypt method ${other}$.")),
        };
    }
    if setting.starts_with('_') {
        return bsdicrypt(password, setting);
    }
    // No prefix: traditional DES, or bigcrypt for a long password.
    if password.len() > 8 && setting.len() > 13 {
        return bigcrypt(password, setting);
    }
    descrypt(password, setting)
}

/// Whether `password` hashes to `stored`, comparing in constant time.
/// `false` rather than an error when `stored` is not a hash this
/// understands, so a caller cannot mistake a parse failure for a match.
pub fn verify(password: &[u8], stored: &str) -> bool {
    let computed = match crypt(password, stored) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let (a, b) = (computed.as_bytes(), stored.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    for (i, &byte) in a.iter().enumerate() {
        diff |= byte ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_des_crypt_truncates_at_eight_bytes() {
        // The ninth byte onward is ignored, the defining weakness.
        assert_eq!(crypt(b"password", "ab").unwrap(),
                   crypt(b"password123", "ab").unwrap());
        assert_ne!(crypt(b"passwor", "ab").unwrap(), crypt(b"password", "ab").unwrap());
    }

    #[test]
    fn test_verify_rejects_a_wrong_password() {
        let h = crypt(b"secret", "$1$abcdefgh").unwrap();
        assert!(verify(b"secret", &h));
        assert!(!verify(b"Secret", &h));
        assert!(!verify(b"secret", "not a hash"));
    }

    #[test]
    fn test_bcrypt_variants_agree_on_ascii_and_differ_on_high_bytes() {
        let salt = "$2b$05$CCCCCCCCCCCCCCCCCCCCC.";
        let ascii = b"abcABC123";
        for v in ["$2a", "$2b", "$2x", "$2y"] {
            let s = format!("{v}{}", &salt[3..]);
            assert_eq!(crypt(ascii, &s).unwrap()[..3].to_string() + &crypt(ascii, &s).unwrap()[3..],
                       crypt(ascii, &s).unwrap());
        }
        // A password with the top bit set separates $2x$ from $2b$.
        let high = b"\xa3bcABC";
        let b = crypt(high, &format!("$2b{}", &salt[3..])).unwrap();
        let x = crypt(high, &format!("$2x{}", &salt[3..])).unwrap();
        assert_ne!(b, x);
    }
}
