/*!
Password hashes used by databases and web forums. Like `unix_crypt`,
these are verifiers already sitting in dumps and backups, kept so the
dumps can be read; none is a good way to store a new password.

| function | scheme | form |
|---|---|---|
| `mysql_old_password` | MySQL pre-4.1 `OLD_PASSWORD()` (`mysql323`) | 16 hex |
| `mysql_password` | MySQL 4.1+ `PASSWORD()` | `*` + 40 upper hex |
| `postgres_md5` | PostgreSQL `md5` authentication | `md5` + 32 hex |
| `phpass` | portable `$P$` (WordPress) / `$H$` (phpBB3) | crypt string |
| `vbulletin` | vBulletin / MyBB `md5(md5(pw) . salt)` | 32 hex |

**None is fit for storing a password.** `mysql_old_password` is a
non-cryptographic 64-bit hash that a laptop reverses by brute force in
seconds; the MySQL, PostgreSQL and vBulletin schemes are one or two
unsalted-or-barely-salted rounds of MD5 or SHA-1, so a GPU tries them in
the billions per second. Only `phpass` iterates, and even its default of
2^13 MD5s is far below a modern password KDF. For new work use Argon2id
or scrypt (`crate::kdf`).

## The two that are their own algorithm

**`mysql_old_password`** is MySQL's `hash_password`: two 32-bit words
stepped over the password, with space and tab bytes skipped, printed as
`%08x%08x`. MySQL's source writes it in `unsigned long`, which is 64-bit
on a modern server, but the result is masked to 31 bits per word and the
low 31 bits are identical whether the arithmetic is 32- or 64-bit - every
step is a ring operation mod 2^32 plus a left shift that reads only low
bits, so the low 32 bits are congruent throughout. That is why the hash
is the same on 32- and 64-bit servers, and why this uses `u32`. Checked
against MariaDB's own compiled `hash_password`.

**`phpass`** is the portable hash shared by WordPress (`$P$`) and phpBB3
(`$H$`). The setting is `$X$` + one cost character + eight salt
characters; the cost character's index in phpass's base64 alphabet is
`log2` of the iteration count. The hash is `md5(salt . password)` folded
with `md5(hash . password)` that many times, then the 16 bytes are
encoded in phpass's own base64 (least-significant six bits first, its
alphabet `./0-9A-Za-z`). `verify` takes the first twelve characters of a
stored hash as the setting and recomputes.

## Where the vectors come from

`vectors/app_passwords.vec`, written by
`scripts/make_app_password_vectors.py`: `mysql_old` from MariaDB's
compiled `hash_password`; `phpass` from WordPress 6.4's
`class-phpass.php` run as is; the MD5/SHA-1 schemes from PHP's own
`md5`/`sha1`, which are independent of this library's. `tests/
test_app_passwords.rs` reads them offline.
*/

use crate::hash_functions::{md5::MD5, sha1::SHA1, HashFunction};

/// phpass's base64 alphabet. Not RFC 4648, and not `unix_crypt`'s
/// `CRYPT64` either - this one is `.`, `/`, digits, upper, lower.
const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn md5_of(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = MD5::new(&[]);
    for p in parts {
        h.update(p);
    }
    h.digest()
}

fn sha1_of(data: &[u8]) -> Vec<u8> {
    SHA1::new(data).digest()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A constant-time byte comparison for the `verify` paths.
fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for (i, &byte) in a.iter().enumerate() {
        diff |= byte ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// MySQL's pre-4.1 `OLD_PASSWORD()` (the `mysql323` scheme): sixteen
/// lowercase hex characters. Space and tab bytes in the password are
/// skipped, as the server does.
pub fn mysql_old_password(password: &[u8]) -> String {
    let (mut nr, mut nr2, mut add) = (1_345_345_333u32, 0x1234_5671u32, 7u32);
    for &b in password {
        if b == b' ' || b == b'\t' {
            continue;
        }
        let tmp = u32::from(b);
        nr ^= (((nr & 63).wrapping_add(add)).wrapping_mul(tmp)).wrapping_add(nr << 8);
        nr2 = nr2.wrapping_add((nr2 << 8) ^ nr);
        add = add.wrapping_add(tmp);
    }
    format!("{:08x}{:08x}", nr & 0x7fff_ffff, nr2 & 0x7fff_ffff)
}

/// MySQL 4.1+ `PASSWORD()`: `*` followed by the uppercase hex of
/// `SHA1(SHA1(password))`, forty-one characters in all.
pub fn mysql_password(password: &[u8]) -> String {
    let inner = sha1_of(password);
    let outer = sha1_of(&inner);
    let mut out = String::from("*");
    for b in outer {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// PostgreSQL's `md5` authentication token: the literal `md5` followed
/// by the lowercase hex of `md5(password . username)`.
pub fn postgres_md5(password: &[u8], username: &[u8]) -> String {
    format!("md5{}", hex_lower(&md5_of(&[password, username])))
}

/// vBulletin and MyBB: `md5(md5(password) . salt)`, as thirty-two
/// lowercase hex characters. The salt is stored beside it.
pub fn vbulletin(password: &[u8], salt: &[u8]) -> String {
    let inner = hex_lower(&md5_of(&[password]));
    hex_lower(&md5_of(&[inner.as_bytes(), salt]))
}

/// phpass's own base64 of `input`, least-significant six bits first.
/// `count` is the number of input bytes; sixteen gives twenty-two
/// characters.
fn encode64(input: &[u8], count: usize) -> String {
    let mut out = String::new();
    let mut i = 0;
    loop {
        let mut value = input[i] as u32;
        i += 1;
        out.push(ITOA64[(value & 0x3f) as usize] as char);
        if i < count {
            value |= (input[i] as u32) << 8;
        }
        out.push(ITOA64[((value >> 6) & 0x3f) as usize] as char);
        if i >= count {
            break;
        }
        i += 1;
        if i < count {
            value |= (input[i] as u32) << 16;
        }
        out.push(ITOA64[((value >> 12) & 0x3f) as usize] as char);
        if i >= count {
            break;
        }
        i += 1;
        out.push(ITOA64[((value >> 18) & 0x3f) as usize] as char);
        if i >= count {
            break;
        }
    }
    out
}

/// The portable phpass hash (`$P$` for WordPress, `$H$` for phpBB3).
/// `setting` is the stored hash or just its first twelve characters:
/// `$X$`, one cost character, and eight salt characters. The result
/// begins with that setting.
///
/// # Errors
/// A setting that is not `$P$`/`$H$`, whose cost character is outside
/// phpass's accepted 7..=30 (an iteration count of 2^7 to 2^30), or whose
/// salt is not eight ASCII bytes. phpass writes the salt from its own
/// base64 alphabet, so a multi-byte character there is a malformed
/// stored string, and refusing it is also what keeps the twelve-byte
/// setting prefix on a character boundary.
pub fn phpass(password: &[u8], setting: &str) -> Result<String, String> {
    let s = setting.as_bytes();
    if s.len() < 12 || s[0] != b'$' || (s[1] != b'P' && s[1] != b'H') || s[2] != b'$' {
        return Err("A phpass setting begins with \"$P$\" or \"$H$\".".to_string());
    }
    let cost_log2 = ITOA64.iter().position(|&c| c == s[3])
        .ok_or("The phpass cost character is not in its base64 alphabet.")?;
    if !(7..=30).contains(&cost_log2) {
        return Err(format!("phpass's cost is 7 to 30, and this one is {cost_log2}."));
    }
    let salt = &s[4..12];
    let prefix = match setting.get(..12) {
        Some(prefix) if salt.iter().all(u8::is_ascii) => prefix,
        _ => return Err("A phpass salt is eight ASCII characters.".to_string()),
    };
    let mut hash = md5_of(&[salt, password]);
    for _ in 0..(1u32 << cost_log2) {
        hash = md5_of(&[&hash, password]);
    }
    Ok(format!("{}{}", prefix, encode64(&hash, 16)))
}

/// Whether `password` produces the stored phpass hash, using its first
/// twelve characters as the setting. `false` for a stored string phpass
/// does not understand, so a parse failure cannot read as a match.
pub fn phpass_verify(password: &[u8], stored: &str) -> bool {
    // `get` rather than a byte-length check and a slice: a stored string
    // from a database dump can hold a multi-byte character at byte 11,
    // and slicing inside it would panic rather than report a mismatch.
    let Some(setting) = stored.get(..12) else {
        return false;
    };
    match phpass(password, setting) {
        Ok(h) => bytes_equal(h.as_bytes(), stored.as_bytes()),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_old_skips_spaces_and_tabs() {
        // The server strips space and tab before hashing, so these three
        // are one password.
        let a = mysql_old_password(b"my password");
        assert_eq!(a, mysql_old_password(b"mypassword"));
        assert_eq!(a, mysql_old_password(b"m y\tp a s s w o r d"));
        // The empty password is the initial state, masked.
        assert_eq!(mysql_old_password(b""), "5030573512345671");
    }

    #[test]
    fn test_mysql_password_is_double_sha1() {
        // *<upper hex of SHA1(SHA1(pw))>, 41 characters.
        let h = mysql_password(b"a");
        assert!(h.starts_with('*') && h.len() == 41);
        assert!(h[1..].bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
    }

    #[test]
    fn test_phpass_round_trips_and_checks_the_cost() {
        let hash = phpass(b"secret", "$P$Bsaltsalt").unwrap();
        assert!(hash.starts_with("$P$Bsaltsalt") && hash.len() == 34);
        assert!(phpass_verify(b"secret", &hash));
        assert!(!phpass_verify(b"Secret", &hash));
        // phpBB3's id over the same salt and cost gives a different hash
        // string (the setting is part of the output) but verifies.
        let phpbb = phpass(b"secret", "$H$Bsaltsalt").unwrap();
        assert!(phpbb.starts_with("$H$B") && phpass_verify(b"secret", &phpbb));
        // Out-of-range and malformed settings are errors, not panics.
        assert!(phpass(b"x", "$P$0saltsalt").is_err());   // cost 0 < 7
        assert!(phpass(b"x", "$1$saltsalt").is_err());
        assert!(!phpass_verify(b"x", "not a hash"));
    }

    #[test]
    fn test_phpass_refuses_a_multi_byte_character_inside_the_setting() {
        // `phpass` sliced the setting at byte 12 and `phpass_verify`
        // checked only the byte length before slicing the stored string
        // the same way, so a stored hash with a two-byte character
        // straddling byte 12 panicked with "not a char boundary" instead
        // of failing. Every existing test used an ASCII salt, on which a
        // byte index and a character index agree.
        let setting = "$P$Bsaltsal\u{e9}";
        assert_eq!(setting.len(), 13);
        assert!(phpass(b"x", setting).is_err());
        assert!(!phpass_verify(b"x", setting));
        let stored = format!("{setting}{}", "0".repeat(21));
        assert!(!phpass_verify(b"x", &stored));
        // A multi-byte character after the setting is a mismatch, not a
        // panic: the setting prefix itself is still ASCII.
        let hash = phpass(b"secret", "$P$Bsaltsalt").unwrap();
        assert!(!phpass_verify(b"secret", &format!("{}\u{e9}", &hash[..33])));
    }

    #[test]
    fn test_encode64_length() {
        // Sixteen bytes become twenty-two phpass base64 characters.
        assert_eq!(encode64(&[0u8; 16], 16).len(), 22);
        assert_eq!(encode64(&[0xff; 16], 16), "zzzzzzzzzzzzzzzzzzzzz1");
    }
}
