/*
Password based key derivation.

A password is not a key. It is short, it is drawn from a small and badly
distributed alphabet, and somebody chose it. These functions exist to make
guessing it expensive: they turn a password and a salt into a key of the
length the caller wants, at a cost the caller sets.

    pbkdf2(sha2::SHA256::new(&[]), password, salt, 600_000, 32)

## What the cost parameter buys, and what it does not

PBKDF2 (RFC 8018 section 5.2) is iterated HMAC. Its cost is *time* and
nothing else, which is the whole of its weakness: an attacker with a GPU or
an FPGA runs the same computation thousands of times in parallel for the
price of one, because each guess needs a few hundred bytes of state. That
is what `scrypt` and `Argon2` were designed to fix, by demanding memory as
well - see the sibling functions once they land.

PBKDF2 is nonetheless the one that matters most here, because it is what
*already encrypted files* use. Every encrypted PKCS#8 private key, every
PKCS#12 bundle, every WPA2 handshake and every older password database
derives its key this way, and no amount of preferring Argon2 helps read
those. The same reasoning as the rest of this library: the old thing is
still out there and refusing to implement it does not make it go away.

## No minimum iteration count is enforced

Deliberately, and it is worth saying why, because it looks like an
oversight. RFC 8018 suggested 1000 in 2000; NIST SP 800-132 says 10,000;
OWASP currently says 600,000 for HMAC-SHA-256. A file written in 2009 with
c=1000 still has to be readable in 2026, and a library that refuses to
compute it is a library that cannot open the file - which is exactly the
failure this project exists to avoid.

So the floor is the standard's: c must be at least 1. Choosing a sensible
count is the caller's problem, and `pbkdf2_recommended_iterations` is there
to answer it for new work rather than to police old work.
*/

use crate::hash_functions::HashFunction;
use crate::mac::hmac::Hmac;
use crate::Mac;

/// PBKDF2, RFC 8018 section 5.2.
///
/// `hash` is a freshly constructed, empty hash of the type to use as the
/// PRF's inner function - `pbkdf2(sha2::SHA256::new(&[]), ..)` is
/// PBKDF2-HMAC-SHA-256. `iterations` is the RFC's `c` and `length` its
/// `dkLen`.
///
/// # Errors
/// Zero iterations, or a `length` past what the counter can address.
pub fn pbkdf2<H: HashFunction + Clone>(hash: H, password: &[u8], salt: &[u8],
                                       iterations: u32, length: usize)
                                       -> Result<Vec<u8>, String> {
    if iterations == 0 {
        return Err("PBKDF2 needs at least one iteration.".to_string());
    }
    let hash_len = hash.digest_len();

    // RFC 8018: "if dkLen > (2^32 - 1) * hLen, output 'derived key too
    // long' and stop". The block counter is four bytes, so past this the
    // construction has no more distinct blocks to give and would start
    // repeating - which is a silent loss of entropy rather than an error,
    // hence the explicit check.
    let ceiling = (u32::MAX as u64) * (hash_len as u64);
    if length as u64 > ceiling {
        return Err(format!("PBKDF2 can produce at most {} bytes with this hash, \
                            asked for {}.", ceiling, length));
    }
    if length == 0 {
        return Ok(Vec::new());
    }

    // Primed once. Every call below clones this rather than re-deriving
    // K' ^ ipad and K' ^ opad, which is half the work of an HMAC over a
    // message this short.
    let prf = Hmac::new(hash, password);

    let mut out = crate::kdf::output_buffer(length, "PBKDF2")?;
    let mut block = 1u32;
    while out.len() < length {
        // U_1 = PRF(P, S || INT(i)), with INT big endian and i counting
        // from one. Counting from zero is the classic way to get an
        // implementation that is self-consistent and agrees with nobody.
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.digest();

        // T_i = U_1 xor U_2 xor ... xor U_c
        let mut t = u.clone();
        for _ in 1..iterations {
            let mut mac = prf.clone();
            mac.update(&u);
            u = mac.digest();
            for (accumulated, next) in t.iter_mut().zip(u.iter()) {
                *accumulated ^= next;
            }
        }

        let take = core::cmp::min(t.len(), length - out.len());
        out.extend_from_slice(&t[..take]);
        block += 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------- PBKDF1 ---

/// PBKDF1, RFC 8018 section 5.1.
///
/// ```text
/// T_1 = Hash(P || S),  T_i = Hash(T_{i-1}),  DK = T_c[..dkLen]
/// ```
///
/// Superseded in 1999 and here only because PBES1 uses it, which is what
/// `pbeWithMD5AndDES-CBC` and its relatives in older PKCS#8 files are
/// built on. New work has no reason to call this.
///
/// Note what it cannot do: the output is one hash digest, so `dkLen` can
/// never exceed 16 bytes for MD2 and MD5 or 20 for SHA-1. That ceiling
/// is the reason PBES1 has no AES variant - there is no way to get 32
/// bytes out of it.
///
/// # Errors
/// Zero iterations, or `length` past the hash's output.
pub fn pbkdf1<H: HashFunction + Clone>(hash: H, password: &[u8], salt: &[u8],
                                       iterations: u32, length: usize)
                                       -> Result<Vec<u8>, String> {
    if iterations == 0 {
        return Err("PBKDF1 needs at least one iteration.".to_string());
    }
    let hash_len = hash.digest_len();
    if length > hash_len {
        return Err(format!("PBKDF1 can produce at most {} bytes with this hash \
                            (its whole output), asked for {}.", hash_len, length));
    }

    let mut round = hash.clone();
    round.update(password);
    round.update(salt);
    let mut t = round.digest();

    // Each round hashes the previous *digest* from a clean state. Feeding
    // it into the running hash instead would extend the message, which
    // produces a plausible looking answer that agrees with nothing - so
    // `hash` is kept as an untouched template and cloned per round.
    for _ in 1..iterations {
        let mut round = hash.clone();
        round.update(&t);
        t = round.digest();
    }

    t.truncate(length);
    Ok(t)
}

// ------------------------------------------- the JDK's MD5 and 3DES PBE ---

/// The key and IV of `PBEWithMD5AndTripleDES`, the JDK's own scheme
/// (`com.sun.crypto.provider.PBES1Core.deriveCipherKey`): JCEKS's key
/// protector and its sealed secret keys use it.
///
/// Neither PBKDF1 nor anything in a standard. The 8-byte salt is split
/// in two; each half is hashed by MD5 with the password, and the digest
/// rehashed with the password `iterations - 1` more times. The two
/// 16-byte results are 3DES's 24-byte key followed by its 8-byte IV. If
/// the halves are equal the first is reversed, or the key's outer two
/// DES keys would be equal.
///
/// # Errors
/// A salt that is not 8 bytes, or no iterations.
pub fn jdk_pbe_md5_3des_key(password: &[u8], salt: &[u8], iterations: u32)
                            -> Result<(Vec<u8>, Vec<u8>), String> {
    if salt.len() != 8 {
        return Err(format!("A PBEWithMD5AndTripleDES salt is 8 bytes, not {}.", salt.len()));
    }
    if iterations == 0 {
        return Err("PBEWithMD5AndTripleDES needs at least one iteration.".to_string());
    }
    let mut salt = salt.to_vec();
    if salt[..4] == salt[4..] {
        salt[..4].reverse();
    }
    let md5 = |parts: &[&[u8]]| {
        let mut h = crate::hash_functions::md5::MD5::new(&[]);
        for part in parts {
            h.update(part);
        }
        h.digest()
    };
    let mut result = Vec::with_capacity(32);
    for half in salt.chunks(4) {
        let mut h = md5(&[half, password]);
        for _ in 1..iterations {
            h = md5(&[&h, password]);
        }
        result.extend(h);
    }
    let iv = result.split_off(24);
    Ok((result, iv))
}

// ----------------------------------------------------- the PKCS#12 KDF ---

/// What the derived bytes are for. PKCS#12 derives the key, the IV and
/// the MAC key from the same password with a different `ID` byte, which
/// is the only thing keeping them apart.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pkcs12Purpose {
    /// `ID = 1`.
    Key,
    /// `ID = 2`.
    Iv,
    /// `ID = 3`.
    Mac,
}

impl Pkcs12Purpose {
    fn id(self) -> u8 {
        match self {
            Pkcs12Purpose::Key => 1,
            Pkcs12Purpose::Iv => 2,
            Pkcs12Purpose::Mac => 3,
        }
    }
}

/// The password as PKCS#12 wants it: a BMPString.
///
/// UTF-16 big endian with a terminating NUL *character* - two zero bytes
/// on the end, not one. This is the single most common reason an
/// implementation of this KDF produces confident wrong answers: get the
/// encoding wrong and every step afterwards is arithmetic on the wrong
/// input, with no error anywhere.
///
/// The empty password is genuinely ambiguous and implementations
/// disagree: OpenSSL passes zero bytes, some others pass the two NUL
/// bytes alone. `None` is returned here for empty so the caller can try
/// both, which is what reading somebody else's file requires.
pub fn pkcs12_bmp_password(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// The PKCS#12 key derivation, RFC 7292 Appendix B.2.
///
/// Not PBKDF1 and not PBKDF2: a third construction, with its own
/// padding rules and a big-endian addition over whole blocks. It exists
/// because `.p12` files and OpenSSL's default `-v1` PBE use it —
/// `PBE-SHA1-3DES`, which is still what `openssl pkcs8 -topk8 -v1` writes
/// and what a great many old key files on disk are encrypted with.
///
/// `password` must already be a BMPString; see `pkcs12_bmp_password`.
///
/// The RFC's `v` is the hash's input block, 64 bytes for MD5, SHA-1 and
/// SHA-256 and 128 for SHA-384/512 - **and 64 for MD2**, by the table in
/// Appendix B.2, even though MD2's compression function takes 16 byte
/// blocks (which is what `block_size()` reports, correctly, for HMAC).
/// So `v` is the block size with a floor of 64 bytes, and
/// `pkcs12_kdf(Md2::new(&[]), ..)` is the RFC's construction rather
/// than a self-consistent one that agrees with nobody.
///
/// # Errors
/// Zero iterations, an output past `kdf::MAX_OUTPUT_BYTES`, or a hash
/// with no fixed output length (a SHAKE), which has no `u`.
pub fn pkcs12_kdf<H: HashFunction + Clone>(hash: H, password: &[u8], salt: &[u8],
                                           purpose: Pkcs12Purpose, iterations: u32,
                                           length: usize) -> Result<Vec<u8>, String> {
    if iterations == 0 {
        return Err("The PKCS#12 KDF needs at least one iteration.".to_string());
    }
    let u = hash.digest_len();      // the RFC's u, the hash output
    if u == 0 {
        return Err("The PKCS#12 KDF needs a hash with a fixed output length.".to_string());
    }
    let v = hash.block_size().max(64);      // the RFC's v, with the MD2 floor
    if length == 0 {
        return Ok(Vec::new());
    }

    // Step 1: D, v bytes all equal to the purpose byte.
    let d = vec![purpose.id(); v];

    // Steps 2 and 3: S and P, each the input repeated to a whole number
    // of v-byte blocks. An *empty* input stays empty rather than
    // becoming one block of padding - the RFC says "if s = 0 then S is
    // the empty string", and a zero-length salt is common.
    let s = repeat_to_blocks(salt, v);
    let p = repeat_to_blocks(password, v);

    // Step 4: I = S || P. Mutated in place by step 6c below, which is
    // what makes each round depend on the last.
    let mut i_blocks = s;
    i_blocks.extend_from_slice(&p);

    let mut out = crate::kdf::output_buffer(length, "The PKCS#12 KDF")?;
    while out.len() < length {
        // Step 6a: A = H^r(D || I).
        let mut round = hash.clone();
        round.update(&d);
        round.update(&i_blocks);
        let mut a = round.digest();
        for _ in 1..iterations {
            let mut round = hash.clone();
            round.update(&a);
            a = round.digest();
        }

        let take = core::cmp::min(a.len(), length - out.len());
        out.extend_from_slice(&a[..take]);
        if out.len() >= length {
            break;
        }

        // Step 6b: B, the v-byte block made by repeating A.
        let b = repeat_to_blocks(&a[..u], v);

        // Step 6c: each v-byte block of I becomes (I_j + B + 1) mod 2^v.
        //
        // Big-endian addition over the whole block, carrying from the
        // last byte to the first, with the +1 folded in as the initial
        // carry. Overflow past the top byte is discarded, which is what
        // "mod 2^v" means and is why this cannot be done with integers
        // of any normal width - v is 64 bytes for SHA-1.
        for block in i_blocks.chunks_mut(v) {
            let mut carry = 1u16;
            for index in (0..block.len()).rev() {
                let sum = block[index] as u16 + b[index] as u16 + carry;
                block[index] = (sum & 0xff) as u8;
                carry = sum >> 8;
            }
        }
    }
    Ok(out)
}

/// `input` repeated (and truncated) to a whole number of `block` sized
/// blocks; empty in, empty out.
fn repeat_to_blocks(input: &[u8], block: usize) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    let rounded = input.len().div_ceil(block) * block;
    (0..rounded).map(|index| input[index % input.len()]).collect()
}

/// OpenPGP's string-to-key (RFC 9580 3.7.1.1 to 3.7.1.3; RFC 4880
/// 3.7.1): `salt || passphrase` repeated end to end until `count` octets
/// have been hashed, or once if `count` is shorter - so the simple S2K is
/// an empty salt and a count of zero, and the salted one a count of zero.
/// A key longer than the hash takes more contexts, the n-th preloaded
/// with n zero octets, their digests concatenated.
///
/// `count` is the decoded octet count (`openpgp_s2k_count`), not the
/// coded byte a packet carries.
pub fn openpgp_s2k<H: HashFunction + Clone>(hash: H, passphrase: &[u8], salt: &[u8],
                                            count: usize, key_len: usize) -> Vec<u8> {
    let mut unit = salt.to_vec();
    unit.extend_from_slice(passphrase);
    // Nothing repeated any number of times is nothing: an empty
    // passphrase with no salt hashes no octets whatever the count.
    let total = if unit.is_empty() { 0 } else { count.max(unit.len()) };
    // Whole copies end to end, so that any prefix continues the
    // repetition where the previous piece stopped.
    let mut repeated = Vec::new();
    while repeated.len() < total.min(65536) {
        repeated.extend_from_slice(&unit);
    }
    let mut key = Vec::with_capacity(key_len + hash.digest_len());
    let mut preload = 0;
    while key.len() < key_len {
        let mut h = hash.clone();
        h.update(&vec![0u8; preload]);
        let mut done = 0;
        while done < total {
            let n = repeated.len().min(total - done);
            h.update(&repeated[..n]);
            done += n;
        }
        key.extend_from_slice(&h.digest());
        preload += 1;
    }
    key.truncate(key_len);
    key
}

/// The octet count an iterated S2K's coded count stands for:
/// `(16 + (c & 15)) << ((c >> 4) + 6)`, 1024 to 65,011,712.
pub fn openpgp_s2k_count(coded: u8) -> usize {
    (16 + (coded as usize & 15)) << ((coded >> 4) + 6)
}

/// The smallest coded count standing for at least `octets`, or 255.
pub fn openpgp_s2k_coded_count(octets: usize) -> u8 {
    (0..=255u8).find(|&c| openpgp_s2k_count(c) >= octets).unwrap_or(255)
}

/// 7-Zip's AES key (7zAES, `CPP/7zip/Crypto/7zAes.cpp`): SHA-256 over
/// `salt || password || i` for i from 0 to 2^cycles - 1, the round
/// number eight bytes little endian. `password` is already UTF-16LE.
///
/// A `cycles` of 0x3f is no derivation at all: salt and password
/// concatenated, cut or zero-padded to 32 bytes.
///
/// No ceiling below 2^62 rounds is imposed - 7-Zip itself reads at most
/// 2^24 - so a caller reading an archive from somebody else should set
/// one.
///
/// # Errors
/// `cycles` above 0x3f, which the format's six-bit field cannot hold.
pub fn sevenzip_aes_key(password: &[u8], salt: &[u8], cycles: u8) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    if cycles == 0x3f {
        let material: Vec<u8> = salt.iter().chain(password).copied().take(32).collect();
        key[..material.len()].copy_from_slice(&material);
        return Ok(key);
    }
    if cycles > 0x3f {
        return Err(format!("7zAES's cycle count is six bits; {cycles} is not one."));
    }
    let unit = salt.len() + password.len() + 8;
    let rounds = 1u64 << cycles;
    // A batch of rounds per update: one update per round costs more than
    // the compression function for short inputs.
    let batch = rounds.min(1024);
    let mut buffer = Vec::with_capacity(unit * batch as usize);
    let mut hash = crate::hash_functions::sha2::SHA256::new(&[]);
    let mut round = 0u64;
    while round < rounds {
        buffer.clear();
        for i in round..round + batch {
            buffer.extend_from_slice(salt);
            buffer.extend_from_slice(password);
            buffer.extend_from_slice(&i.to_le_bytes());
        }
        hash.update(&buffer);
        round += batch;
    }
    key.copy_from_slice(&hash.digest());
    Ok(key)
}

/// KeePass's AES-KDF (KDBX 3.1 `TransformRounds`; KDBX 4's AES-KDF
/// parameters): the 32-byte composite key encrypted `rounds` times with
/// AES-256-ECB under `seed`, then SHA-256. The two halves never mix
/// until the hash, which is what let KeePass run them on two cores.
///
/// # Errors
/// A key or seed that is not 32 bytes.
pub fn keepass_aes_kdf(key: &[u8], seed: &[u8], rounds: u64) -> Result<[u8; 32], String> {
    if key.len() != 32 || seed.len() != 32 {
        return Err(format!("KeePass's AES-KDF takes a 32-byte key and a 32-byte seed, not {} \
                            and {}.", key.len(), seed.len()));
    }
    use crate::block_ciphers::BlockCipher;
    let mut cipher = crate::block_ciphers::aes::AesCrypto::new(seed)?;
    let mut block = key.to_vec();
    let mut out = Vec::with_capacity(32);
    for _ in 0..rounds {
        out.clear();
        cipher.ecb_encrypt(&block, &mut out)?;
        std::mem::swap(&mut block, &mut out);
    }
    let mut hash = crate::hash_functions::sha2::SHA256::new(&[]);
    hash.update(&block);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash.digest());
    Ok(result)
}

/// BitLocker's key stretching: 2^20 rounds of SHA-256 over an 88-byte
/// record - the previous round's hash, the initial hash, the 16-byte
/// salt and the round number as 64 bits little endian - starting from a
/// previous hash of zeros. The result is the AES-256 key that opens one
/// protector's copy of the volume master key.
///
/// `initial` is SHA-256 of SHA-256 of the UTF-16LE password for a
/// password protector (`bitlocker_password_hash`), and SHA-256 of the
/// 16-byte key for a recovery password (`bitlocker_recovery_key`).
pub fn bitlocker_stretch(initial: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    bitlocker_stretch_rounds(initial, salt, 1 << 20)
}

fn bitlocker_stretch_rounds(initial: &[u8; 32], salt: &[u8; 16], rounds: u64) -> [u8; 32] {
    use crate::hash_functions::sha2::SHA256;
    let mut record = [0u8; 88];
    record[32..64].copy_from_slice(initial);
    record[64..80].copy_from_slice(salt);
    for count in 0..rounds {
        record[80..88].copy_from_slice(&count.to_le_bytes());
        let mut h = SHA256::new(&[]);
        h.update(&record);
        record[..32].copy_from_slice(&h.digest());
    }
    record[..32].try_into().unwrap()
}

/// SHA-256 of SHA-256 of the password as UTF-16LE, no terminator: a
/// BitLocker password protector's starting point.
pub fn bitlocker_password_hash(password: &str) -> [u8; 32] {
    use crate::hash_functions::sha2::SHA256;
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut h = SHA256::new(&[]);
    h.update(&utf16);
    let once = h.digest();
    let mut h = SHA256::new(&[]);
    h.update(&once);
    h.digest().try_into().unwrap()
}

/// A recovery password's 16-byte key: the eight six-digit groups, each
/// a multiple of 11 whose eleventh is below 65,536, as eight 16-bit
/// little-endian numbers. The dashes are required; a trailing newline
/// is forgiven.
pub fn bitlocker_recovery_key(recovery: &str) -> Result<[u8; 16], String> {
    let text = recovery.strip_suffix('\n').unwrap_or(recovery);
    let groups: Vec<&str> = text.split('-').collect();
    let six_digits = |g: &&str| g.len() == 6 && g.bytes().all(|b| b.is_ascii_digit());
    if groups.len() != 8 || !groups.iter().all(six_digits) {
        return Err("A BitLocker recovery password is eight groups of six digits, separated by \
                    dashes.".to_string());
    }
    let mut key = [0u8; 16];
    for (i, group) in groups.iter().enumerate() {
        let value: u32 = group.parse().map_err(|_| "Not a number.".to_string())?;
        if !value.is_multiple_of(11) || value / 11 > 0xffff {
            return Err(format!("Group {} of the recovery password, {group}, is not a multiple \
                                of 11 below 720,896: a typing mistake.", i + 1));
        }
        key[2 * i..2 * i + 2].copy_from_slice(&((value / 11) as u16).to_le_bytes());
    }
    Ok(key)
}

/// What to use for *new* work, as of 2026: OWASP's current figures.
///
/// Here so that a caller writing a new file has an answer that is not a
/// number somebody half remembered, and so that there is one place to
/// update when the advice moves again. Nothing in the library consults
/// this when *reading*, where the count comes from the file.
///
/// Unknown hash names get the most conservative of the figures rather
/// than a guess or an error: being too slow is survivable.
pub fn pbkdf2_recommended_iterations(hash_name: &str) -> u32 {
    match hash_name.to_ascii_lowercase().replace('-', "").as_str() {
        "sha1" => 1_300_000,
        "sha256" | "sha224" => 600_000,
        "sha512" | "sha384" => 210_000,
        _ => 1_300_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_functions::{sha1::SHA1, sha2};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// `pbkdf2` reserved its whole output with `Vec::with_capacity`
    /// before the first HMAC, and the only ceiling was RFC 8018's
    /// `(2^32 - 1) * hLen` - 137 GB for SHA-256 - so `dklen = 10^11`
    /// from Python aborted the process at the allocator. The existing
    /// tests asked for a few dozen bytes. The request here is refused
    /// by the cap before any allocation.
    #[test]
    fn test_an_oversized_output_is_an_error_not_an_abort() {
        let reason = pbkdf2(sha2::SHA256::new(&[]), b"pw", b"salt", 1,
                            crate::kdf::MAX_OUTPUT_BYTES + 1).unwrap_err();
        assert!(reason.contains("at most"), "{reason}");
        assert!(pbkdf2(sha2::SHA256::new(&[]), b"pw", b"salt", 1, 100_000_000_000)
                    .is_err());
    }

    /// RFC 6070, the PBKDF2-HMAC-SHA-1 test vectors.
    ///
    /// The fifth vector of the RFC (c = 16,777,216) is deliberately not
    /// here: it takes minutes and tests nothing the others do not, since
    /// the iteration loop is the same code at every count. It is in
    /// `tools/src/bin/diff_pbkdf2.rs` behind a flag if it is ever wanted.
    #[test]
    fn test_rfc6070_sha1_vectors() {
        let cases: &[(&str, &str, u32, usize, &str)] = &[
            ("password", "salt", 1, 20,
             "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
            ("password", "salt", 2, 20,
             "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
            ("password", "salt", 4096, 20,
             "4b007901b765489abead49d926f721d065a429c1"),
            ("passwordPASSWORDpassword",
             "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
             "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
        ];
        for (password, salt, iterations, length, expected) in cases {
            let got = pbkdf2(SHA1::new(&[]), password.as_bytes(), salt.as_bytes(),
                             *iterations, *length).unwrap();
            assert_eq!(hex(&got), *expected,
                       "RFC 6070: password {:?} salt {:?} c={}",
                       password, salt, iterations);
        }
    }

    /// RFC 6070's sixth vector, which is the one with embedded NULs.
    ///
    /// Separate because it cannot be written as a `&str` literal pair
    /// without the NUL being easy to misread, and because a password
    /// containing NUL is exactly where a C implementation truncates and
    /// this one must not.
    #[test]
    fn test_a_password_containing_nul_is_not_truncated() {
        let got = pbkdf2(SHA1::new(&[]), b"pass\0word", b"sa\0lt", 4096, 16).unwrap();
        assert_eq!(hex(&got), "56fa6aa75548099dcc37d7f03425e0c3");

        // And the property behind the vector: truncating at the NUL must
        // give a different answer. Without this the test above passes on
        // an implementation that ignores everything after the NUL, as
        // long as it does so on both sides.
        let truncated = pbkdf2(SHA1::new(&[]), b"pass", b"sa", 4096, 16).unwrap();
        assert_ne!(hex(&truncated), "56fa6aa75548099dcc37d7f03425e0c3");
    }

    /// RFC 7914 section 11: PBKDF2-HMAC-SHA-256, which is what scrypt
    /// uses at both ends and what most modern files are written with.
    #[test]
    fn test_rfc7914_sha256_vectors() {
        let got = pbkdf2(sha2::SHA256::new(&[]), b"passwd", b"salt", 1, 64).unwrap();
        assert_eq!(hex(&got),
                   "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                    49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783");

        let got = pbkdf2(sha2::SHA256::new(&[]), b"Password", b"NaCl", 80000, 64).unwrap();
        assert_eq!(hex(&got),
                   "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
                    a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d");
    }

    /// Output longer than one hash block, which is where the block
    /// counter matters.
    ///
    /// The 64 byte vectors above already cross the boundary for SHA-256,
    /// but only just - two blocks, so a counter stuck at 1 and a counter
    /// that increments correctly differ, while a counter that increments
    /// by the wrong amount might not. This walks far enough out that the
    /// third and fourth blocks have to be right too.
    #[test]
    fn test_the_block_counter_advances_correctly() {
        let long = pbkdf2(sha2::SHA256::new(&[]), b"passwd", b"salt", 1, 128).unwrap();
        let short = pbkdf2(sha2::SHA256::new(&[]), b"passwd", b"salt", 1, 64).unwrap();

        // A prefix property: asking for more must not change what was
        // already there. This is the invariant that a wrongly seeded
        // counter breaks.
        assert_eq!(&long[..64], &short[..],
                   "the first blocks changed when more output was asked for");

        // And the later blocks must not repeat the earlier ones, which is
        // what a counter that never advances produces.
        assert_ne!(&long[..32], &long[32..64]);
        assert_ne!(&long[..32], &long[64..96]);
        assert_ne!(&long[32..64], &long[96..128]);
    }

    /// The salt must reach the PRF, and so must the iteration count.
    ///
    /// Guards against the two ways this construction silently degenerates:
    /// ignoring the salt turns it into an unsalted hash, and ignoring `c`
    /// turns it into one round of HMAC.
    #[test]
    fn test_every_input_changes_the_answer() {
        let base = pbkdf2(sha2::SHA256::new(&[]), b"password", b"salt", 100, 32).unwrap();
        let other_salt = pbkdf2(sha2::SHA256::new(&[]), b"password", b"pepper", 100, 32).unwrap();
        let other_count = pbkdf2(sha2::SHA256::new(&[]), b"password", b"salt", 101, 32).unwrap();
        let other_password = pbkdf2(sha2::SHA256::new(&[]), b"Password", b"salt", 100, 32).unwrap();
        assert_ne!(base, other_salt, "the salt did not reach the PRF");
        assert_ne!(base, other_count, "the iteration count did not reach the PRF");
        assert_ne!(base, other_password, "the password did not reach the PRF");
    }

    /// An empty salt and an empty password are legal, and are not the
    /// same as each other.
    #[test]
    fn test_empty_inputs_are_legal() {
        let no_salt = pbkdf2(sha2::SHA256::new(&[]), b"password", b"", 10, 32).unwrap();
        let no_password = pbkdf2(sha2::SHA256::new(&[]), b"", b"password", 10, 32).unwrap();
        let neither = pbkdf2(sha2::SHA256::new(&[]), b"", b"", 10, 32).unwrap();
        assert_ne!(no_salt, no_password);
        assert_ne!(no_salt, neither);
        assert_ne!(no_password, neither);
    }

    #[test]
    fn test_zero_iterations_is_an_error() {
        assert!(pbkdf2(sha2::SHA256::new(&[]), b"p", b"s", 0, 32).is_err());
    }

    #[test]
    fn test_zero_length_is_empty_not_an_error() {
        // The element type is written out because with the `python`
        // feature on, pyo3 adds `impl PartialEq<Bound<PyInt>> for u8`
        // and a bare `Vec::new()` then has two candidates.
        assert_eq!(pbkdf2(sha2::SHA256::new(&[]), b"p", b"s", 10, 0).unwrap(),
                   Vec::<u8>::new());
    }

    /// A length that would need more than 2^32 - 1 blocks.
    ///
    /// Not reachable by allocating it - the point is that the check
    /// happens before anything is allocated, so the error arrives rather
    /// than the machine running out of memory.
    #[test]
    fn test_an_unreachable_length_is_an_error_not_an_allocation() {
        let hash_len = sha2::SHA256::new(&[]).digest_len() as u64;
        let too_long = (u32::MAX as u64) * hash_len + 1;
        if let Ok(size) = usize::try_from(too_long) {
            assert!(pbkdf2(sha2::SHA256::new(&[]), b"p", b"s", 1, size).is_err());
        }
    }

    /// Output must not depend on how the caller sliced the request.
    ///
    /// PBKDF2 has no streaming interface, but it does have a length
    /// parameter, and the prefix property is what a caller deriving an
    /// encryption key and a MAC key from one call relies on.
    #[test]
    fn test_a_longer_request_extends_a_shorter_one() {
        for length in [1usize, 15, 16, 31, 32, 33, 63, 64, 65, 100] {
            let long = pbkdf2(sha2::SHA256::new(&[]), b"pw", b"salt", 5, 100).unwrap();
            let short = pbkdf2(sha2::SHA256::new(&[]), b"pw", b"salt", 5, length).unwrap();
            assert_eq!(&long[..length], &short[..],
                       "asking for {} bytes did not give the first {} of 100",
                       length, length);
        }
    }

    /// The recommendation table answers for every hash the library has,
    /// and never answers zero.
    #[test]
    fn test_the_recommendation_is_usable_for_every_hash() {
        for name in crate::api::HASHES {
            let count = pbkdf2_recommended_iterations(name);
            assert!(count > 0, "{} got a recommendation of zero", name);
        }
        assert!(pbkdf2_recommended_iterations("no such hash") >= 600_000,
                "an unknown hash should get a conservative answer, not a weak one");
    }

    /// `pkcs12_kdf` took the RFC's `v` from `block_size()`, which for
    /// MD2 is 16 - right for HMAC, and not what RFC 7292 Appendix B.2
    /// fixes for the KDF (512 bits for MD2 as for MD5 and SHA-1). Only
    /// SHA-1 is used in the tree, so the generic signature's MD2 path
    /// was a construction that agreed with nobody. The expected value
    /// is the RFC's own first step written out with v = 64: D is 64
    /// purpose bytes, and S and P are repeated to 64 byte blocks.
    #[test]
    fn test_pkcs12_kdf_uses_a_64_byte_block_for_md2() {
        use crate::hash_functions::md2::Md2;
        let password = pkcs12_bmp_password("pw");
        let salt = [7u8; 8];
        let by_hand = {
            let mut round = Md2::new(&[]);
            round.update(&[Pkcs12Purpose::Key.id(); 64]);
            round.update(&repeat_to_blocks(&salt, 64));
            round.update(&repeat_to_blocks(&password, 64));
            round.digest()
        };
        let got = pkcs12_kdf(Md2::new(&[]), &password, &salt, Pkcs12Purpose::Key, 1, 16)
            .unwrap();
        assert_eq!(got, by_hand);
        // And the floor leaves SHA-1's 64 and SHA-512's 128 alone.
        assert_eq!(sha2::SHA512::new(&[], 512).block_size().max(64), 128);
        // A hash with no fixed output length has no `u`.
        let shake = crate::hash_functions::keccak::Keccak::shake(128, 0).unwrap();
        assert!(pkcs12_kdf(shake, &password, &salt, Pkcs12Purpose::Key, 1, 16).is_err());
    }

    /// Equal salt halves would make 3DES's first and third keys equal;
    /// the JDK reverses the first half before deriving, so the two
    /// halves of the derived key still differ.
    #[test]
    fn test_jdk_pbe_equal_salt_halves_are_broken_up() {
        let (key, _) = jdk_pbe_md5_3des_key(b"pw", &[1, 2, 3, 4, 1, 2, 3, 4], 3).unwrap();
        let (reversed, _) = jdk_pbe_md5_3des_key(b"pw", &[4, 3, 2, 1, 1, 2, 3, 4], 3).unwrap();
        assert_eq!(key, reversed);
        assert_ne!(key[..8], key[16..24]);
        assert!(jdk_pbe_md5_3des_key(b"pw", &[0; 7], 1).is_err());
        assert!(jdk_pbe_md5_3des_key(b"pw", &[0; 8], 0).is_err());
    }

    /// The halves are independent: each is MD5 iterated over one half of
    /// the salt and the password, the first giving 16 bytes of key and
    /// the second 8 of key and 8 of IV.
    #[test]
    fn test_jdk_pbe_is_two_md5_chains() {
        use crate::hash_functions::md5::MD5;
        let chain = |half: &[u8], n: u32| {
            let mut h = MD5::new(&[]);
            h.update(half);
            h.update(b"pw");
            let mut d = h.digest();
            for _ in 1..n {
                let mut h = MD5::new(&[]);
                h.update(&d);
                h.update(b"pw");
                d = h.digest();
            }
            d
        };
        let (key, iv) = jdk_pbe_md5_3des_key(b"pw", &[1, 2, 3, 4, 5, 6, 7, 8], 5).unwrap();
        let (a, b) = (chain(&[1, 2, 3, 4], 5), chain(&[5, 6, 7, 8], 5));
        assert_eq!(key, [&a[..], &b[..8]].concat());
        assert_eq!(iv, b[8..]);
    }

    fn sha1_of(parts: &[&[u8]]) -> Vec<u8> {
        let mut h = SHA1::new(&[]);
        for part in parts {
            h.update(part);
        }
        h.digest()
    }

    /// RFC 9580 3.7.1.3's coded count, at both ends and in between.
    #[test]
    fn test_openpgp_s2k_count_coding() {
        assert_eq!(openpgp_s2k_count(0), 1024);
        assert_eq!(openpgp_s2k_count(0x60), 65536);
        assert_eq!(openpgp_s2k_count(0xff), 65_011_712);
        assert_eq!(openpgp_s2k_coded_count(65_011_712), 0xff);
        assert_eq!(openpgp_s2k_coded_count(usize::MAX), 0xff);
        assert_eq!(openpgp_s2k_count(openpgp_s2k_coded_count(1_000_000)), 1_015_808);
        for c in 0..=255u8 {
            assert_eq!(openpgp_s2k_coded_count(openpgp_s2k_count(c)), c);
        }
    }

    /// The simple S2K is the hash of the passphrase; a second context
    /// starts with one zero octet; an iterated count shorter than one
    /// copy hashes one copy; a count that is not a multiple of the unit
    /// cuts the last copy short.
    #[test]
    fn test_openpgp_s2k_by_hand() {
        let h = SHA1::new(&[]);
        assert_eq!(openpgp_s2k(h.clone(), b"pw", b"", 0, 20), sha1_of(&[b"pw"]));
        let long = openpgp_s2k(h.clone(), b"pw", b"salt", 0, 32);
        assert_eq!(long[..20], sha1_of(&[b"saltpw"])[..]);
        assert_eq!(long[20..], sha1_of(&[&[0], b"saltpw"])[..12]);
        // The third context takes two zero octets, not one.
        let longer = openpgp_s2k(h.clone(), b"pw", b"salt", 0, 60);
        assert_eq!(longer[40..], sha1_of(&[&[0, 0], b"saltpw"])[..]);
        assert_eq!(openpgp_s2k(h.clone(), b"pw", b"salt", 3, 20), sha1_of(&[b"saltpw"]));
        assert_eq!(openpgp_s2k(h.clone(), b"pw", b"salt", 15, 20),
                   sha1_of(&[b"saltpwsaltpwsal"]));
        // Past the 64 KiB of repetitions kept in memory, the repetition
        // continues where the buffer stopped: 65,536 is not a multiple
        // of 6.
        let count = 65536 + 45;
        let string: Vec<u8> = b"saltpw".iter().cycle().take(count).copied().collect();
        assert_eq!(openpgp_s2k(h.clone(), b"pw", b"salt", count, 20), sha1_of(&[&string]));
        // Nothing to repeat is nothing hashed, rather than a loop
        // waiting for the count.
        assert_eq!(openpgp_s2k(h, b"", b"", 1024, 20), sha1_of(&[]));
    }

    /// The round counter is in every repetition, so hashing rounds in
    /// batches gives the key hashing them one at a time does.
    #[test]
    fn test_sevenzip_key_round_by_round() {
        for cycles in [0u8, 1, 6, 10, 11, 12] {
            let mut hash = sha2::SHA256::new(&[]);
            for i in 0..1u64 << cycles {
                hash.update(&[1, 2, 3]);
                hash.update(&[b'p', 0, b'w', 0]);
                hash.update(&i.to_le_bytes());
            }
            assert_eq!(sevenzip_aes_key(&[b'p', 0, b'w', 0], &[1, 2, 3], cycles).unwrap()[..],
                       hash.digest()[..], "{cycles}");
        }
    }

    /// 0x3f is no derivation: salt and password, zero-padded or cut to
    /// 32 bytes. Past 0x3f the six-bit field cannot hold the value.
    #[test]
    fn test_sevenzip_raw_key_and_range() {
        let key = sevenzip_aes_key(b"ab", &[9, 8], 0x3f).unwrap();
        let mut expected = [0u8; 32];
        expected[..4].copy_from_slice(&[9, 8, b'a', b'b']);
        assert_eq!(key, expected);
        assert_eq!(sevenzip_aes_key(&[7; 40], &[], 0x3f).unwrap(), [7; 32]);
        assert!(sevenzip_aes_key(b"pw", b"", 0x40).is_err());
    }

    /// Each half of the key is encrypted on its own, by the same rounds.
    #[test]
    fn test_keepass_aes_kdf_halves() {
        use crate::block_ciphers::aes::AesCrypto;
        use crate::block_ciphers::BlockCipher;
        let (key, seed): (Vec<u8>, Vec<u8>) = ((0..32).collect(), (100..132).collect());
        let mut aes = AesCrypto::new(&seed).unwrap();
        let mut halves = Vec::new();
        for half in key.chunks(16) {
            let mut block = half.to_vec();
            for _ in 0..3 {
                let mut out = Vec::new();
                aes.block_encrypt(&block, &mut out);
                block = out;
            }
            halves.extend(block);
        }
        let mut h = sha2::SHA256::new(&[]);
        h.update(&halves);
        assert_eq!(keepass_aes_kdf(&key, &seed, 3).unwrap()[..], h.digest()[..]);
        let mut h = sha2::SHA256::new(&[]);
        h.update(&key);
        assert_eq!(keepass_aes_kdf(&key, &seed, 0).unwrap()[..], h.digest()[..]);
        assert!(keepass_aes_kdf(&key[..16], &seed, 1).is_err());
        assert!(keepass_aes_kdf(&key, &seed[..16], 1).is_err());
    }

    /// The eight groups are the key's eight 16-bit words, each times 11.
    #[test]
    fn test_bitlocker_recovery_key() {
        let key = bitlocker_recovery_key(
            "000011-000022-720885-000000-000110-011011-000033-000044").unwrap();
        let words: Vec<u16> = key.chunks(2).map(|w| u16::from_le_bytes([w[0], w[1]])).collect();
        assert_eq!(words, [1, 2, 65535, 0, 10, 1001, 3, 4]);
        assert_eq!(bitlocker_recovery_key(
            "000011-000022-720885-000000-000110-011011-000033-000044\n").unwrap(), key);
        for bad in ["000011-000022-720885-000000-000110-011011-000033",
                    "000012-000022-720885-000000-000110-011011-000033-000044",
                    "720896-000022-720885-000000-000110-011011-000033-000044",
                    "00011-0000022-720885-000000-000110-011011-000033-000044",
                    "000011 000022 720885 000000 000110 011011 000033 000044"] {
            assert!(bitlocker_recovery_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_bitlocker_password_hash_is_utf16le_hashed_twice() {
        let mut h = sha2::SHA256::new(&[]);
        h.update(&[b'p', 0, 0xa3, 0]);
        let once = h.digest();
        let mut h = sha2::SHA256::new(&[]);
        h.update(&once);
        assert_eq!(bitlocker_password_hash("p£")[..], h.digest()[..]);
    }

    /// The record's layout, on three rounds rather than 2^20 (nine
    /// seconds unoptimised): previous hash, initial hash, salt, count.
    /// The full count is checked by opening Windows's volumes in the
    /// BitLocker example.
    #[test]
    fn test_bitlocker_stretch_record() {
        let (initial, salt) = ([7u8; 32], [9u8; 16]);
        let full = bitlocker_stretch_rounds(&initial, &salt, 3);
        let mut last = [0u8; 32];
        for count in 0..3u64 {
            let mut h = sha2::SHA256::new(&[]);
            h.update(&last);
            h.update(&initial);
            h.update(&salt);
            h.update(&count.to_le_bytes());
            last.copy_from_slice(&h.digest());
        }
        assert_eq!(full, last);
    }
}
