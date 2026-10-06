/*
What the shim offers, and where that comes from.

**Permissive by default**, which is the opposite of every other entry
point into this library - and deliberate.

`ClientConfig::new` offers modern suites and a TLS 1.2 floor because a
program written against this library chose to use it and can say
otherwise. A program being shimmed said nothing: it asked for OpenSSL
and got us. And it got us because somebody typed `LD_PRELOAD=...` in
front of a command that had already failed. A shim that then refuses the
same connection for the same reason is an elaborate way to print the
same error.

So the default here is the widest thing that still finishes a handshake:
every implemented suite, a TLS 1.0 floor, SHA-1 and MD5 accepted in a
chain, 1024 bit RSA, 512 bit Diffie-Hellman.

Three things that are **not** loosened, because they are the program's
own business rather than ours:

  - **Whether the certificate is verified at all.** That comes from the
    program's `SSL_CTX_set_verify`, which is what `curl -k` and
    `wget --no-check-certificate` set. The result is reported through
    `SSL_get_verify_result` and let it decide, exactly as OpenSSL does.
  - **Which roots to trust.** From `SSL_CTX_load_verify_locations` and
    `SSL_CTX_set_default_verify_paths`, which is `--cacert` and the
    system store.
  - **SSLv3.** Its CBC padding is unspecified, which is POODLE. The
    floor is TLS 1.0 and reaching below it needs `ALLCRYPT_MIN_VERSION`
    said out loud.

Everything is overridable by environment variable, because there is no
other channel: the program's command line belongs to the program.
*/

use std::env;

use allcrypt::tls::suites::Selection;
use allcrypt::tls::Version;

/// One setting, read once.
pub struct Settings {
    pub ciphers: String,
    pub min_version: Version,
    pub max_version: Version,
    pub allow_sha1: bool,
    pub allow_md5: bool,
    pub allow_expired: bool,
    pub min_rsa_bits: usize,
    pub min_dh_bits: usize,
    /// Print one line per connection saying what was negotiated.
    pub verbose: bool,
    /// Append that line to a file as well. The tests use it: a shim
    /// that silently failed to load leaves the program working
    /// perfectly against the real OpenSSL, and every assertion about
    /// the *connection* would still pass. The only way to know we were
    /// in the path is to have left a mark.
    pub log_path: Option<String>,
    /// Say nothing at all on stderr. For a program whose output is
    /// being parsed.
    pub quiet: bool,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            // Everything implemented, including the insecure suites.
            // `Selection::all` rather than `legacy`: legacy still drops
            // the NULL ciphers, and a shim that silently narrows what
            // was asked for is the thing this whole file is against.
            ciphers: "all".to_string(),
            min_version: Version::TLS10,
            max_version: Version::TLS13,
            allow_sha1: true,
            allow_md5: true,
            // **Not** loosened: an expired certificate is reported
            // through SSL_get_verify_result, and the program decides.
            // Loosening it here would hide the expiry from a program
            // that would have refused.
            allow_expired: false,
            min_rsa_bits: 1024,
            min_dh_bits: 512,
            verbose: false,
            log_path: None,
            quiet: false,
        }
    }
}

impl Settings {
    /// Read the environment. Called once, behind a `OnceLock`.
    pub fn from_environment() -> Settings {
        let mut settings = Settings::default();

        if let Some(value) = variable("ALLCRYPT_CIPHERS") {
            settings.ciphers = value;
        }
        if let Some(value) = variable("ALLCRYPT_MIN_VERSION") {
            match parse_version(&value) {
                Some(version) => settings.min_version = version,
                None => complain(&format!(
                    "ALLCRYPT_MIN_VERSION={:?} is not a version I know; \
                     leaving the floor at {}.",
                    value, settings.min_version.name())),
            }
        }
        if let Some(value) = variable("ALLCRYPT_MAX_VERSION") {
            match parse_version(&value) {
                Some(version) => settings.max_version = version,
                None => complain(&format!(
                    "ALLCRYPT_MAX_VERSION={:?} is not a version I know; \
                     leaving the ceiling at {}.",
                    value, settings.max_version.name())),
            }
        }
        if let Some(value) = variable("ALLCRYPT_MIN_RSA_BITS") {
            if let Ok(bits) = value.parse() {
                settings.min_rsa_bits = bits;
            } else {
                complain(&format!(
                    "ALLCRYPT_MIN_RSA_BITS={:?} is not a number.", value));
            }
        }
        if let Some(value) = variable("ALLCRYPT_MIN_DH_BITS") {
            if let Ok(bits) = value.parse() {
                settings.min_dh_bits = bits;
            } else {
                complain(&format!(
                    "ALLCRYPT_MIN_DH_BITS={:?} is not a number.", value));
            }
        }
        settings.allow_sha1 = !flag("ALLCRYPT_NO_SHA1");
        settings.allow_md5 = !flag("ALLCRYPT_NO_MD5");
        settings.verbose = flag("ALLCRYPT_VERBOSE");
        settings.quiet = flag("ALLCRYPT_QUIET");
        settings.log_path = variable("ALLCRYPT_LOG");
        settings
    }

    /// The suite selection, or the default if the name is not one.
    ///
    /// A bad name complains and carries on rather than failing the
    /// connection: the alternative is a program that dies with
    /// "handshake failure" because of a typo in an environment
    /// variable, which is the least debuggable outcome available.
    pub fn selection(&self) -> Selection {
        match self.ciphers.to_ascii_lowercase().as_str() {
            "modern" | "default" => Selection::modern(),
            "legacy" => Selection::legacy(),
            "all" | "everything" => Selection::all(),
            list => {
                let names: Vec<&str> = list.split(',').map(|n| n.trim()).collect();
                match Selection::named(&names) {
                    Ok(selection) => selection,
                    Err(reason) => {
                        complain(&format!(
                            "ALLCRYPT_CIPHERS={:?}: {} Offering everything \
                             instead.", self.ciphers, reason));
                        Selection::all()
                    }
                }
            }
        }
    }
}

fn variable(name: &str) -> Option<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

fn flag(name: &str) -> bool {
    matches!(variable(name).as_deref(), Some("1") | Some("true") | Some("yes"))
}

fn parse_version(name: &str) -> Option<Version> {
    match name.to_ascii_uppercase().replace(['_', ' ', '.'], "").as_str() {
        "SSLV3" | "SSL3" => Some(Version::SSL30),
        "TLSV1" | "TLSV10" | "TLS1" => Some(Version::TLS10),
        "TLSV11" => Some(Version::TLS11),
        "TLSV12" => Some(Version::TLS12),
        "TLSV13" => Some(Version::TLS13),
        _ => None,
    }
}

/// Say something on stderr, unless told not to.
///
/// Every message is prefixed, because it is appearing in the middle of
/// another program's output and the first question anybody will ask is
/// where it came from.
pub fn complain(message: &str) {
    if flag("ALLCRYPT_QUIET") {
        return;
    }
    eprintln!("allcrypt: {}", message);
}
