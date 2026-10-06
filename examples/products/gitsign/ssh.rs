//! Git's SSH signatures: SSHSIG under the `git` namespace, and the parts
//! of `ssh-keygen -Y` git calls - `sign`, `verify` against an allowed
//! signers file, `find-principals` and `check-novalidate` - with the
//! output lines git reads back (`gpg-interface.c`, `parse_ssh_output`).

use allcrypt::ssh::keys::{self, PublicKey};
use allcrypt::ssh::private_key::{self, PrivateKey};
use allcrypt::ssh::signature;

/// One line of an allowed signers file (ssh-keygen(1), "ALLOWED
/// SIGNERS"): principals, options, and a key.
#[derive(Debug)]
pub struct Signer {
    pub principals: String,
    pub namespaces: Option<Vec<String>>,
    pub valid_after: Option<u64>,
    pub valid_before: Option<u64>,
    pub cert_authority: bool,
    pub key: PublicKey,
}

/// `YYYYMMDD`, `YYYYMMDDHHMM` or `YYYYMMDDHHMMSS`, with an optional `Z`;
/// read as UTC either way.
pub fn parse_time(text: &str) -> Result<u64, String> {
    let digits = text.strip_suffix(['Z', 'z']).unwrap_or(text);
    if !digits.bytes().all(|c| c.is_ascii_digit()) || ![8, 12, 14].contains(&digits.len()) {
        return Err(format!("{text}: not a time (YYYYMMDD[HHMM[SS]][Z])."));
    }
    let n = |a: usize, b: usize| -> i64 { digits.get(a..b).map_or(0, |s| s.parse().unwrap_or(0)) };
    let (y, m, d) = (n(0, 4), n(4, 6), n(6, 8));
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return Err(format!("{text}: not a date."));
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Ok((days * 86400 + n(8, 10) * 3600 + n(10, 12) * 60 + n(12, 14)) as u64)
}

/// The value of `name="..."` or `name=...` in an options field.
fn option<'a>(options: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = options;
    while !rest.is_empty() {
        let end = field_end(rest);
        let field = &rest[..end];
        if let Some(value) = field.strip_prefix(name).and_then(|v| v.strip_prefix('=')) {
            return Some(value.trim_matches('"'));
        }
        rest = rest[end..].trim_start_matches(',');
    }
    None
}

/// The end of one comma-separated option, quotes respected.
fn field_end(text: &str) -> usize {
    let mut quoted = false;
    for (i, c) in text.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => return i,
            _ => {}
        }
    }
    text.len()
}

pub fn read_allowed_signers(text: &str) -> Result<Vec<Signer>, String> {
    let mut out = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |e: String| format!("allowed signers line {}: {e}", number + 1);
        // The principals field may be quoted, and runs to the first space
        // outside quotes.
        let mut quoted = false;
        let end = line.char_indices().find(|&(_, c)| {
            if c == '"' {
                quoted = !quoted;
            }
            !quoted && (c == ' ' || c == '\t')
        }).map(|(i, _)| i).ok_or_else(|| at("a principal and no key.".to_string()))?;
        let principals = line[..end].trim_matches('"').to_string();
        let key_line = keys::parse_line(&line[end..]).map_err(at)?;
        let options = key_line.options;
        let time = |name| option(options, name).map(parse_time).transpose().map_err(at);
        out.push(Signer {
            principals,
            namespaces: option(options, "namespaces")
                .map(|v| v.split(',').map(str::to_string).collect()),
            valid_after: time("valid-after")?,
            valid_before: time("valid-before")?,
            cert_authority: options.split(',').any(|o| o.eq_ignore_ascii_case("cert-authority")),
            key: key_line.key,
        });
    }
    Ok(out)
}

/// OpenSSH's `match_pattern`: `*` any run, `?` any one character.
fn wildcard(text: &[u8], pattern: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'*', rest)) => (0..=text.len()).any(|i| wildcard(&text[i..], rest)),
        Some((b'?', rest)) => !text.is_empty() && wildcard(&text[1..], rest),
        Some((c, rest)) => text.first() == Some(c) && wildcard(&text[1..], rest),
    }
}

/// `match_pattern_list`: a comma-separated list, `!` negating; a negated
/// match wins over any positive one.
pub fn matches_list(name: &str, list: &str) -> bool {
    let mut positive = false;
    for pattern in list.split(',') {
        let (negated, pattern) = match pattern.strip_prefix('!') {
            Some(p) => (true, p),
            None => (false, pattern),
        };
        if wildcard(name.as_bytes(), pattern.as_bytes()) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

impl Signer {
    /// Whether this line lets `key` sign under `namespace` at `time`.
    /// `find-principals` asks without a namespace.
    fn admits(&self, key: &PublicKey, namespace: Option<&str>, time: Option<u64>) -> bool {
        // A cert-authority line trusts certificates signed by its key,
        // and certificates are not read here: such a line admits nothing.
        if self.cert_authority || self.key.to_blob() != key.to_blob() {
            return false;
        }
        if let (Some(namespaces), Some(namespace)) = (&self.namespaces, namespace) {
            if !namespaces.iter().any(|n| matches_list(namespace, n)) {
                return false;
            }
        }
        if let Some(t) = time {
            if self.valid_after.is_some_and(|a| t < a) || self.valid_before.is_some_and(|b| t > b) {
                return false;
            }
        }
        true
    }
}

/// `ssh-keygen` names a key type in its verdicts by its short name.
pub fn type_name(key: &PublicKey) -> &'static str {
    match key {
        PublicKey::Rsa(_) => "RSA",
        PublicKey::Ecdsa { .. } => "ECDSA",
        PublicKey::Ed25519(_) => "ED25519",
        PublicKey::Dsa(_) => "DSA",
    }
}

/// A private key file, OpenSSH's format, with an optional passphrase.
pub fn read_private(path: &str, passphrase: Option<&[u8]>) -> Result<PrivateKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    Ok(private_key::read(&text, passphrase)?.0)
}

pub fn sign(key: &PrivateKey, namespace: &str, payload: &[u8]) -> Result<String, String> {
    signature::sshsig_sign(key, namespace, payload, "sha512")
}

/// `ssh-keygen -Y verify`: the signature good, and its key allowed for
/// `principal` under `namespace` at `time`. The line git reads back.
pub fn verify(signers: &[Signer], principal: &str, namespace: &str, armoured: &str,
              payload: &[u8], time: Option<u64>) -> Result<String, String> {
    let key = signature::sshsig_verify(armoured, namespace, payload)?;
    let allowed = signers.iter().any(|s| matches_list(principal, &s.principals)
                                     && s.admits(&key, Some(namespace), time));
    if !allowed {
        return Err(format!("{} key {} is not allowed for {principal} under {namespace:?}.",
                           type_name(&key), key.fingerprint_sha256()));
    }
    Ok(format!("Good \"{namespace}\" signature for {principal} with {} key {}",
               type_name(&key), key.fingerprint_sha256()))
}

/// `ssh-keygen -Y find-principals`: the principals of the lines that
/// admit the signature's key. The signature itself is not checked here,
/// as ssh-keygen does not check it; `verify` does.
pub fn find_principals(signers: &[Signer], armoured: &str, time: Option<u64>)
                       -> Result<Vec<String>, String> {
    let key = signature::sshsig_public_key(armoured)?;
    let found: Vec<String> = signers.iter()
        .filter(|s| s.admits(&key, None, time) && !s.principals.is_empty())
        .map(|s| s.principals.clone()).collect();
    if found.is_empty() {
        return Err(format!("No principal matched {} key {}.", type_name(&key),
                           key.fingerprint_sha256()));
    }
    Ok(found)
}

/// `ssh-keygen -Y check-novalidate`: the signature good, whoever made it.
pub fn check_novalidate(namespace: &str, armoured: &str, payload: &[u8])
                        -> Result<String, String> {
    let key = signature::sshsig_verify(armoured, namespace, payload)?;
    Ok(format!("Good \"{namespace}\" signature with {} key {}", type_name(&key),
               key.fingerprint_sha256()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patterns() {
        assert!(matches_list("alice@example.com", "*@example.com"));
        assert!(matches_list("alice@example.com", "bob@x,alice@example.com"));
        assert!(!matches_list("alice@example.com", "*@example.com,!alice@*"));
        assert!(matches_list("a1", "a?"));
        assert!(!matches_list("a12", "a?"));
        assert!(!matches_list("Alice@example.com", "alice@example.com"));
    }

    #[test]
    fn test_times() {
        assert_eq!(parse_time("19700101").unwrap(), 0);
        assert_eq!(parse_time("20240229123456Z").unwrap(), 1709210096);
        assert_eq!(parse_time("202402291234").unwrap(), 1709210040);
        assert!(parse_time("2024022").is_err());
        assert!(parse_time("20241301").is_err());
    }

    #[test]
    fn test_an_allowed_signers_file() {
        let key = PrivateKey::ed25519([7; 32]).unwrap().public();
        let line = key.to_openssh("a comment");
        let text = format!("# comment\n\n\"alice@example.com,*@example.org\" \
                            namespaces=\"git,file\",valid-after=\"20240101\" {line}\n\
                            bob@example.com cert-authority {line}\n");
        let signers = read_allowed_signers(&text).unwrap();
        assert_eq!(signers.len(), 2);
        assert_eq!(signers[0].principals, "alice@example.com,*@example.org");
        assert_eq!(signers[0].namespaces.as_deref().unwrap(), ["git", "file"]);
        assert_eq!(signers[0].valid_after, Some(parse_time("20240101").unwrap()));
        assert!(signers[0].admits(&key, Some("git"), Some(parse_time("20250101").unwrap())));
        assert!(!signers[0].admits(&key, Some("git"), Some(parse_time("20230101").unwrap())));
        assert!(!signers[0].admits(&key, Some("email"), None));
        assert!(signers[0].admits(&key, None, None));
        assert!(signers[1].cert_authority);
        assert!(!signers[1].admits(&key, Some("git"), None));
    }
}
