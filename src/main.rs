/*
`allcrypt-proxy`: a local HTTPS proxy for reaching equipment nobody will
upgrade.

A browser will not speak RC4, or TLS 1.0, or to a certificate that ran
out in 2014. That is right for the open web and wrong for the switch in
the rack that has one management interface and no firmware left. This
sits between them: it terminates TLS on the browser's side and speaks
whatever the box speaks on the other.

The browser cannot be fixed directly. Chromium links BoringSSL
statically - `nm -D` on the binary shows zero TLS imports and
`SSL_connect` as a local text symbol, so there is nothing for
`LD_PRELOAD` to interpose on. Firefox's NSS is a shared library, so it is
mechanically possible and impractical: about five hundred entry points,
plus NSPR's layered file descriptors, PKCS#11 and the certificate
database. A proxy is the way through.

## What it shows the browser

**Not a blanket padlock.** The usual terminating proxy signs everything
with its own CA, which means every server behind it looks equally
trustworthy and the browser's padlock stops meaning anything. This one
mirrors instead: the certificate it presents is as trustworthy as the
one the server actually sent, with the subject, the alternative names,
the validity window and the serial copied across. An expired certificate
mirrors as expired; a self-signed one as self-signed; one from a CA
nobody trusts as one from a CA nobody trusts. `proxy.rs` has the detail.

So the browser warns exactly when it would have warned, and the decision
stays with the person at the keyboard.

## What you are agreeing to

**Installing this proxy's CA certificate means anything holding its key
can impersonate any site to that browser** - not only the ones you meant
to reach. Generate the CA on the machine that will use it, keep the key
there, point one browser at the proxy, and remove the certificate from
the store when you are done. The proxy listens on loopback only, and
refuses to do otherwise.

## Usage

    allcrypt-proxy --ca-dir ~/.allcrypt-proxy        # makes a CA the
                                                     # first time
    allcrypt-proxy --ca-dir ~/.allcrypt-proxy --legacy --port 8080

Then set the browser's HTTPS proxy to 127.0.0.1:8080 and import
`~/.allcrypt-proxy/ca.pem`.
*/

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use allcrypt::proxy::{self, Issuer, Trust};
use allcrypt::tls::client::{ClientConfig, ClientConnection};
use allcrypt::tls::server::{ServerConfig, ServerConnection, ServerKey};
use allcrypt::tls::suites::Selection;
use allcrypt::tls::Version;
use allcrypt::trust::TrustStore;
use allcrypt::x509::verify::Policy;
use allcrypt::x509::Certificate;

/// One TLS record is at most 16 KB plus its header and its tag.
const CHUNK: usize = 17 * 1024;

// ----------------------------------------------------------------- log ---

/*
Why this exists at all.

The first version of this program printed one line per connection and
only when `-v` was given, and every failure went into a `Result` that
`main` threw away. The effect on the far side was a socket that closed
with nothing said: a capture showed the ServerHello, then FIN from us.
That is the single worst thing a tool like this can do, because the
whole reason to run it is that something is already going wrong and you
are trying to find out what.

So: **a failure is never silent.** `Level::ERROR` and `Level::INFO`
print unless `--quiet`, and they say which connection, which phase and
what the reason was. `-v` adds the negotiation - what we offered, what
was chosen, what the certificate said, what the verdict was and why -
and `-vv` adds the bytes, because the question "what did that box
actually send" has no other answer.

Every line carries the connection number, since a browser opens six at
once and their lines interleave. The clock is UTC, to the millisecond,
so a line can be lined up with a packet capture.
*/

mod level {
    /// Something failed. Printed unless `--quiet`.
    pub const ERROR: u8 = 0;
    /// One line per connection, either way it ends. The default.
    pub const INFO: u8 = 1;
    /// What was negotiated, and what was made of the certificate. `-v`.
    pub const DETAIL: u8 = 2;
    /// Bytes on the wire. `-vv`.
    pub const TRACE: u8 = 3;
}

#[derive(Clone, Copy)]
struct Log {
    level: u8,
}

impl Log {
    fn enabled(&self, level: u8) -> bool {
        self.level >= level
    }

    /// One line, written in one call so that two threads cannot
    /// interleave halves of it.
    fn at(&self, level: u8, id: u64, message: impl std::fmt::Display) {
        if !self.enabled(level) {
            return;
        }
        let _ = writeln!(std::io::stderr(), "{} #{:<3} {}", stamp(), id, message);
    }

    /// A line with no connection to attach it to - startup, mostly.
    fn plain(&self, level: u8, message: impl std::fmt::Display) {
        if !self.enabled(level) {
            return;
        }
        let _ = writeln!(std::io::stderr(), "{}", message);
    }

    /// Bytes, for the question this tool exists to answer.
    ///
    /// Capped, because a 16 KB record dumped in full buries the line
    /// that mattered; the first bytes are the ones that say what a
    /// message was.
    fn bytes(&self, level: u8, id: u64, what: &str, bytes: &[u8]) {
        if !self.enabled(level) || bytes.is_empty() {
            return;
        }
        const CAP: usize = 256;
        let shown = &bytes[..bytes.len().min(CAP)];
        self.at(level, id, format!("{} ({} bytes{})", what, bytes.len(),
                                   if bytes.len() > CAP { ", first 256" } else { "" }));
        for (offset, row) in shown.chunks(16).enumerate() {
            self.at(level, id, format!("  {:04x}  {}", offset * 16, hex_spaced(row)));
        }
    }
}

fn hex_spaced(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
}

/// UTC, to the millisecond, computed rather than formatted: this crate
/// has no dependencies and a timestamp is not a reason to gain one.
/// The date is left off - a line is being matched against a capture
/// taken minutes ago, not filed.
fn stamp() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = now.as_secs();
    format!("{:02}:{:02}:{:02}.{:03}Z",
            (seconds / 3600) % 24, (seconds / 60) % 60, seconds % 60,
            now.subsec_millis())
}

fn main() {
    let options = match Options::parse(std::env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => return,
        Err(reason) => {
            eprintln!("allcrypt-proxy: {}", reason);
            eprintln!("Try --help.");
            std::process::exit(2);
        }
    };
    if let Err(reason) = run(options) {
        eprintln!("allcrypt-proxy: {}", reason);
        std::process::exit(1);
    }
}

// --------------------------------------------------------------- options ---

struct Options {
    port: u16,
    ca_dir: PathBuf,
    /// Suites to offer the server behind us. The browser's side is
    /// always modern; only this half goes back in time.
    upstream_ciphers: String,
    upstream_min: Version,
    upstream_max: Version,
    allow_sha1: bool,
    allow_md5: bool,
    min_rsa_bits: usize,
    min_dh_bits: usize,
    /// Extra roots for judging the server, on top of the system store.
    extra_roots: Vec<PathBuf>,
    /// How much to print. See `mod level`.
    verbosity: u8,
    /// Whether a plain `http://` request is forwarded rather than
    /// refused. See `forward_plain`.
    plain_http: bool,
    /// Where to write the upstream connection's secrets, for reading a
    /// capture back. See `Proxy::write_keylog`.
    keylog: Option<PathBuf>,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Option<Options>, String> {
        let mut options = Options {
            port: 8080,
            ca_dir: default_ca_dir(),
            upstream_ciphers: "modern".to_string(),
            upstream_min: Version::TLS12,
            upstream_max: Version::TLS13,
            allow_sha1: false,
            allow_md5: false,
            min_rsa_bits: 2048,
            min_dh_bits: 2048,
            extra_roots: Vec::new(),
            verbosity: level::INFO,
            plain_http: true,
            keylog: std::env::var_os("SSLKEYLOGFILE").map(PathBuf::from),
        };
        let mut args = args.peekable();
        while let Some(argument) = args.next() {
            let mut value = || args.next().ok_or(format!("{} needs a value.",
                                                         argument));
            match argument.as_str() {
                "-h" | "--help" => { print_help(); return Ok(None); }
                "--port" | "-p" => {
                    options.port = value()?.parse()
                        .map_err(|_| "--port needs a number.".to_string())?;
                }
                "--ca-dir" => options.ca_dir = PathBuf::from(value()?),
                "--ciphers" => options.upstream_ciphers = value()?,
                "--min-version" => options.upstream_min = parse_version(&value()?)?,
                "--max-version" => options.upstream_max = parse_version(&value()?)?,
                "--allow-sha1" => options.allow_sha1 = true,
                "--allow-md5" => options.allow_md5 = true,
                "--min-rsa-bits" => {
                    options.min_rsa_bits = value()?.parse()
                        .map_err(|_| "--min-rsa-bits needs a number.".to_string())?;
                }
                "--min-dh-bits" => {
                    options.min_dh_bits = value()?.parse()
                        .map_err(|_| "--min-dh-bits needs a number.".to_string())?;
                }
                "--root" => options.extra_roots.push(PathBuf::from(value()?)),
                "--legacy" => {
                    // Everything at once, for a box that predates all of
                    // it. **The floor stays at TLS 1.0**: SSLv3's CBC
                    // padding is unspecified, which is POODLE, and
                    // reaching it has to be asked for by name rather
                    // than inherited from a preset.
                    options.upstream_ciphers = "legacy".to_string();
                    options.upstream_min = Version::TLS10;
                    options.allow_sha1 = true;
                    options.allow_md5 = true;
                    options.min_rsa_bits = 1024;
                    options.min_dh_bits = 512;
                }
                // Repeatable, and `-vv` is the same as `-v -v`. The
                // second level is the one that prints bytes, and it is
                // deliberately two keystrokes away rather than the
                // default: a browser opening six connections to a page
                // full of images would otherwise bury the handshake.
                "-v" | "--verbose" => options.verbosity =
                    if options.verbosity >= level::DETAIL { level::TRACE }
                    else { level::DETAIL },
                "-vv" => options.verbosity = level::TRACE,
                "-q" | "--quiet" => options.verbosity = level::ERROR,
                "--no-plain-http" => options.plain_http = false,
                "--keylog" => options.keylog = Some(PathBuf::from(value()?)),
                other => return Err(format!("Unknown option {:?}.", other)),
            }
        }
        Ok(Some(options))
    }
}

fn parse_version(name: &str) -> Result<Version, String> {
    match name.to_ascii_uppercase().replace(['_', ' ', '.'], "").as_str() {
        "SSLV3" | "SSL3" => Ok(Version::SSL30),
        "TLSV1" | "TLSV10" | "TLS1" => Ok(Version::TLS10),
        "TLSV11" => Ok(Version::TLS11),
        "TLSV12" => Ok(Version::TLS12),
        "TLSV13" => Ok(Version::TLS13),
        other => Err(format!("Unknown TLS version {:?}.", other)),
    }
}

fn default_ca_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".allcrypt-proxy")
}

fn print_help() {
    println!("\
allcrypt-proxy - a local HTTPS proxy for equipment nobody will upgrade

    allcrypt-proxy [options]

It terminates TLS on the browser's side and speaks whatever the box
behind it speaks. The certificate it presents MIRRORS the real one: the
subject, the alternative names, the validity window and the serial are
copied, and it is signed by the proxy's CA only when the real chain
actually verified. So an expired certificate still looks expired, a
self-signed one still looks self-signed, and the browser warns exactly
when it would have warned.

INSTALLING THE CA MEANS ANYTHING HOLDING ITS KEY CAN IMPERSONATE ANY
SITE TO THAT BROWSER. Keep the key on this machine and remove the
certificate from the store when you are finished.

Options:
  -p, --port N          Listen on 127.0.0.1:N (default 8080)
      --ca-dir PATH     Where ca.pem and ca.key live; made if absent
                        (default ~/.allcrypt-proxy)
      --legacy          Loosen the UPSTREAM side all at once: legacy
                        suites, TLS 1.0 floor, SHA-1 and MD5 signatures,
                        1024 bit RSA, 512 bit DH. The browser's side is
                        unaffected. SSLv3 still has to be asked for by
                        name - its CBC padding is unspecified, which is
                        POODLE.
      --ciphers SET     modern, legacy, all, or a comma separated list
      --min-version V   TLSv1, TLSv1.1, TLSv1.2, TLSv1.3, SSLv3
      --max-version V
      --allow-sha1      Accept a SHA-1 signature in the server's chain
      --allow-md5       Accept an MD5 one
      --min-rsa-bits N
      --min-dh-bits N
      --root FILE       A PEM file of extra roots to judge the server
                        against. The narrowest way to reach a box with
                        its own certificate: not a relaxation at all,
                        but authentication against one you chose.
      --no-plain-http   Refuse a plain http:// request instead of
                        forwarding it. By default one is forwarded
                        unchanged, because a browser sends every
                        protocol to the one proxy it was given
      --keylog FILE     Write the UPSTREAM connection's secrets here in
                        NSS key log format, so a capture of the far
                        side can be read in Wireshark. $SSLKEYLOGFILE
                        is used if this is not given. ANYONE WHO CAN
                        READ THIS FILE CAN READ THOSE CONNECTIONS
  -v, --verbose         What was offered, what was chosen, what the
                        certificate said and what was made of it.
                        Repeat (-vv) for the bytes on the wire
  -q, --quiet           Failures only
  -h, --help

Without -v there is still one line per connection and one per failure,
saying which phase it failed in and why. A handshake this proxy refuses
is also refused out loud: the far end is sent the fatal alert that says
what was wrong with what it sent, rather than having the socket shut on
it.

Then point the browser's HTTPS proxy at 127.0.0.1:PORT and import
ca.pem.");
}

// ----------------------------------------------------------------- state ---

/// Everything a connection needs, shared across threads.
struct Proxy {
    options: Options,
    /// The CA the user installed. Signs a mirror only when the server's
    /// own chain verified.
    ca: Issuer,
    /// A CA generated at startup that nobody trusts, for mirroring a
    /// chain that did not verify. One per process rather than per
    /// connection, so a client meeting two bad servers sees one unknown
    /// issuer - which is how a real untrusted CA behaves.
    untrusted: Issuer,
    roots: TrustStore,
    log: Log,
    /// The number on each connection's log lines. A browser opens six
    /// at once and their lines interleave; without this they cannot be
    /// told apart.
    next_id: AtomicU64,
    /// Mirrors already built, by host. A browser opens several
    /// connections to a host at once, and a different certificate on
    /// each is not wrong but makes a capture unreadable and costs a key
    /// generation per tab.
    cache: Mutex<HashMap<String, Arc<CachedMirror>>>,
}

impl Proxy {
    /// One line of NSS key log, appended.
    ///
    /// The point of this program is that the far side speaks something
    /// unusual, and the way anybody finds out what actually went over
    /// that half of the wire is to open the capture in Wireshark - for
    /// which it needs these secrets. Only the *upstream* connection's
    /// are written: the browser's half is this proxy's own doing and
    /// its plaintext is already the thing being relayed.
    ///
    /// Opened and closed per line, which is a syscall apiece and
    /// correct when six threads are writing: `O_APPEND` on a short
    /// write is atomic, a kept handle shared between threads is not.
    fn write_keylog(&self, line: &str) {
        let path = match &self.options.keylog {
            Some(path) => path,
            None => return,
        };
        let opened = std::fs::OpenOptions::new().create(true).append(true)
            .open(path);
        match opened {
            Ok(mut file) => { let _ = writeln!(file, "{}", line); }
            Err(reason) => self.log.plain(level::ERROR, format!(
                "cannot write the key log {}: {}", path.display(), reason)),
        }
    }
}

struct CachedMirror {
    chain: Vec<Vec<u8>>,
    private: Vec<u8>,
    trust: Trust,
    /// When the *mirror* stops being usable, which is not the copied
    /// validity window: an expired mirror is the correct answer for an
    /// expired server and must not be re-issued in the hope of a
    /// different one.
    cached_until: u64,
}

fn run(options: Options) -> Result<(), String> {
    let ca = load_or_make_ca(&options.ca_dir)?;

    let now = now_seconds() as i64;
    let untrusted = Issuer::untrusted(
        "allcrypt-proxy untrusted issuer",
        &allcrypt::asn1::format_time(now - 86_400),
        &allcrypt::asn1::format_time(now + 365 * 86_400))?;

    let log = Log { level: options.verbosity };

    let mut roots = TrustStore::system()
        .unwrap_or_else(|_| TrustStore::new());
    for path in &options.extra_roots {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;
        // **How many it added, not how many the file had.** A PEM file
        // holding something that is not a certificate - a key, a
        // request, a certificate this parser cannot read - used to be
        // accepted in silence, and the only sign was that the server
        // it was meant to authenticate still came out untrusted.
        let added = roots.add_pem(&text)?;
        for skipped in roots.skipped_reasons() {
            log.plain(level::INFO, format!("  {} skipped: {}",
                                           path.display(), skipped));
        }
        if added == 0 {
            return Err(format!(
                "{} added no roots. A PEM file of extra roots must hold at \
                 least one CERTIFICATE block.", path.display()));
        }
        log.plain(level::INFO, format!("  +{} root{} from {}", added,
                                       if added == 1 { "" } else { "s" },
                                       path.display()));
    }

    let address = ("127.0.0.1", options.port);
    let listener = TcpListener::bind(address)
        .map_err(|e| format!("Cannot listen on 127.0.0.1:{}: {}",
                             options.port, e))?;
    let port = listener.local_addr()
        .map_err(|e| e.to_string())?.port();

    log.plain(level::INFO,
              format!("allcrypt-proxy listening on 127.0.0.1:{}", port));
    log.plain(level::INFO, format!("  CA certificate: {}",
                                   options.ca_dir.join("ca.pem").display()));
    log.plain(level::INFO, format!("  upstream: {}, {} to {}",
                                   options.upstream_ciphers,
                                   options.upstream_min.name(),
                                   options.upstream_max.name()));
    log.plain(level::INFO, format!("  roots: {} ({})",
                                   roots.len(), roots.source()));
    // What we will actually offer, by name. A server that answers with
    // something else - which is how one of these gets stuck - can then
    // be compared against this list without guessing what "modern"
    // meant on the day.
    if log.enabled(level::DETAIL) {
        match selection(&options.upstream_ciphers) {
            Ok(chosen) => {
                log.plain(level::DETAIL,
                          format!("  offering {} suites upstream:",
                                  chosen.codes().len()));
                for code in chosen.codes() {
                    log.plain(level::DETAIL, format!(
                        "    {}", allcrypt::tls::suites::describe_code(*code)));
                }
            }
            Err(reason) => log.plain(level::ERROR,
                                     format!("  cipher selection: {}", reason)),
        }
    }
    log.plain(level::INFO,
              format!("Set the browser's HTTPS proxy to 127.0.0.1:{} and \
                       import ca.pem.", port));

    let proxy = Arc::new(Proxy { options, ca, untrusted, roots, log,
                                 next_id: AtomicU64::new(1),
                                 cache: Mutex::new(HashMap::new()) });

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            // One failed accept must not take the listener down: the
            // whole point of this program is reaching things that may
            // not answer.
            Err(_) => continue,
        };
        let proxy = Arc::clone(&proxy);
        let id = proxy.next_id.fetch_add(1, Ordering::Relaxed);
        std::thread::spawn(move || {
            // **Every failure is printed here**, at ERROR, which
            // `--quiet` is the only thing that silences. `handle`
            // returning an error used to be the end of it, and a
            // connection that died in the handshake left no trace at
            // all in the default configuration.
            if let Err(reason) = handle(&proxy, id, stream) {
                proxy.log.at(level::ERROR, id, reason);
            }
        });
    }
    Ok(())
}

// -------------------------------------------------------------------- CA ---

fn load_or_make_ca(dir: &Path) -> Result<Issuer, String> {
    let certificate_path = dir.join("ca.der");
    let key_path = dir.join("ca.key");

    if certificate_path.exists() && key_path.exists() {
        let certificate = std::fs::read(&certificate_path)
            .map_err(|e| format!("Cannot read {}: {}",
                                 certificate_path.display(), e))?;
        let key = std::fs::read(&key_path)
            .map_err(|e| format!("Cannot read {}: {}", key_path.display(), e))?;
        return Issuer::new("P-256", &key, certificate);
    }

    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Cannot make {}: {}", dir.display(), e))?;

    let now = now_seconds() as i64;
    let authority = allcrypt::api::CertificateAuthority::generate(
        "allcrypt-proxy CA",
        &allcrypt::asn1::format_time(now - 86_400),
        &allcrypt::asn1::format_time(now + 365 * 86_400))?;

    let key = authority.private_bytes()?;
    write_private(&key_path, &key)?;
    std::fs::write(&certificate_path, authority.certificate())
        .map_err(|e| format!("Cannot write {}: {}",
                             certificate_path.display(), e))?;
    std::fs::write(dir.join("ca.pem"), authority.certificate_pem())
        .map_err(|e| format!("Cannot write ca.pem: {}", e))?;

    eprintln!("Generated a new CA in {}.", dir.display());
    eprintln!("Import ca.pem into the browser you are pointing here - and \
               remember that");
    eprintln!("anything holding ca.key can then impersonate any site to it.");

    Issuer::new("P-256", &key, authority.certificate().to_vec())
}

/// Write a private key so only its owner can read it.
///
/// The mode is set **at creation** rather than afterwards: a `chmod`
/// after the write leaves a window in which the key is world readable,
/// and that window is the whole of the exposure.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true).create(true).truncate(true).mode(0o600)
        .open(path)
        .map_err(|e| format!("Cannot write {}: {}", path.display(), e))?;
    file.write_all(bytes)
        .map_err(|e| format!("Cannot write {}: {}", path.display(), e))
}

/// The same, where there is no mode to set.
///
/// A file created under the user's profile inherits that directory's
/// ACL, which is the user. Said here rather than left to be assumed:
/// the unix branch above makes a promise this one keeps differently.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes)
        .map_err(|e| format!("Cannot write {}: {}", path.display(), e))
}

// ----------------------------------------------------------- connections ---

fn handle(proxy: &Proxy, id: u64, mut browser: TcpStream) -> Result<(), String> {
    browser.set_nodelay(true).ok();
    let request = read_request(proxy, id, &mut browser)?;
    let (host, port) = (request.host.clone(), request.port);

    let address = resolve(&host, port)
        .inspect_err(|reason| {
            let _ = refuse(&mut browser, 502, reason);
        })?;
    proxy.log.at(level::DETAIL, id,
                 format!("{}:{} resolves to {}", host, port, address));

    let upstream = TcpStream::connect_timeout(&address, Duration::from_secs(10))
        .map_err(|e| {
            // Reported *before* the tunnel is opened. Answering 200 and
            // then failing means the browser starts a TLS handshake
            // into a dead tunnel and reports it as a certificate error,
            // which sends whoever is debugging to the wrong place.
            let _ = refuse(&mut browser, 502,
                           &format!("Cannot reach {}:{}: {}", host, port, e));
            format!("{}:{} unreachable: {}", host, port, e)
        })?;
    upstream.set_nodelay(true).ok();
    proxy.log.at(level::DETAIL, id, format!("connected to {}", address));

    if let Method::Plain(head) = request.method {
        return forward_plain(proxy, id, &format!("{}:{}", host, port),
                             browser, upstream, head, request.leftover);
    }

    browser.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .map_err(|e| e.to_string())?;

    let started = Instant::now();
    match bridge(proxy, id, &host, port, browser, upstream, request.leftover) {
        Ok(()) => {
            proxy.log.at(level::INFO, id,
                         format!("{}:{} closed after {:.1}s",
                                 host, port, started.elapsed().as_secs_f64()));
            Ok(())
        }
        Err(reason) => Err(format!("{}:{} {}", host, port, reason)),
    }
}

/// What the browser asked for.
enum Method {
    /// `CONNECT host:port` - a tunnel, which is every https:// URL.
    Connect,
    /// A plain request, carried across as it stands. The head is the
    /// whole request line and headers, already rewritten to origin
    /// form.
    Plain(Vec<u8>),
}

struct Request {
    method: Method,
    host: String,
    port: u16,
    /// Whatever came after the headers. For CONNECT this is a
    /// pipelined ClientHello; for a plain request it is the body.
    leftover: Vec<u8>,
}

/// A plain `http://` request, forwarded and not touched again.
///
/// **This used to be a 400.** The comment justifying that said a plain
/// request needs no TLS and forwarding one would make this a general
/// web proxy. The first half is true and the second is the mistake: a
/// browser is configured with *one* proxy for everything, or with a
/// PAC file most people will not write, so refusing plain HTTP does
/// not send it around another way - it breaks that half of the browser
/// while the proxy is set. The box with the expired certificate
/// usually has a plain port too, and its redirect to https:// is how
/// you get to the part this program is for.
///
/// It is a byte relay and nothing more: no caching, no rewriting
/// beyond the request line, no pooling. `Connection: close` is not
/// forced - the two sides keep their own ideas about keep-alive, and
/// since nothing here parses a response body there is nothing to get
/// out of step.
fn forward_plain(proxy: &Proxy, id: u64, target: &str,
                 browser: TcpStream, mut upstream: TcpStream,
                 head: Vec<u8>, leftover: Vec<u8>) -> Result<(), String> {
    proxy.log.at(level::INFO, id,
                 format!("{} plain HTTP, forwarded in the clear", target));
    proxy.log.bytes(level::TRACE, id, "request head", &head);

    upstream.write_all(&head).map_err(|e| e.to_string())?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).map_err(|e| e.to_string())?;
    }

    let started = Instant::now();
    let back = upstream.try_clone().map_err(|e| e.to_string())?;
    let out = browser.try_clone().map_err(|e| e.to_string())?;
    let up = std::thread::spawn(move || copy_until_closed(browser, upstream));
    let down = copy_until_closed(back, out);
    let sent = up.join().unwrap_or(0);
    proxy.log.at(level::INFO, id,
                 format!("{} closed after {:.1}s, {} bytes up, {} down",
                         target, started.elapsed().as_secs_f64(), sent, down));
    Ok(())
}

/// Bytes across until one end stops, returning how many.
fn copy_until_closed(mut source: TcpStream, mut sink: TcpStream) -> u64 {
    let mut buffer = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        match source.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if sink.write_all(&buffer[..read]).is_err() {
                    break;
                }
                total += read as u64;
            }
        }
    }
    let _ = sink.shutdown(Shutdown::Write);
    total
}

/// The browser's request line and headers, and whatever came after them.
///
/// `CONNECT host:port HTTP/1.1` is the interesting one and every
/// https:// URL arrives as one. A plain `GET http://host/path` is
/// carried across instead of refused - see `forward_plain` for why.
fn read_request(proxy: &Proxy, id: u64, browser: &mut TcpStream)
                -> Result<Request, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 2048];
    while !buffer.windows(4).any(|w| w == b"\r\n\r\n") {
        let read = browser.read(&mut chunk).map_err(|e| e.to_string())?;
        if read == 0 {
            return Err("The client closed before sending a request.".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 64 * 1024 {
            return Err("Request headers too long.".into());
        }
    }
    let split = buffer.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let leftover = buffer[split..].to_vec();

    let head = String::from_utf8_lossy(&buffer[..split]).to_string();
    let line = head.lines().next().unwrap_or("").to_string();
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_authority(&target)?;
        proxy.log.at(level::INFO, id, format!("CONNECT {}:{}", host, port));
        return Ok(Request { method: Method::Connect, host, port, leftover });
    }

    if !proxy.options.plain_http {
        let message = format!(
            "This proxy is running with --no-plain-http and got {:?} {:?}.",
            method, target);
        let _ = refuse(browser, 400, &message);
        return Err(message);
    }

    // An absolute-form target is what a browser sends to a proxy:
    // `GET http://host/path HTTP/1.1`. Anything else means this was
    // reached as though it were an ordinary web server, and there is
    // no host to send it to.
    let rest = target.strip_prefix("http://").ok_or_else(|| {
        let message = format!(
            "{:?} is not a proxy request. A browser sends an absolute URL \
             to a proxy ({:?} http://host/path), and https:// arrives as \
             CONNECT. Point the browser's proxy settings at this port \
             rather than opening it as a page.", target, method);
        let _ = refuse(browser, 400, &message);
        message
    })?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority_with_default(authority, 80)?;
    proxy.log.at(level::INFO, id, format!("{} http://{}{}", method, authority, path));

    // The request line goes out in origin form, which is what a server
    // expects; every header is passed through untouched.
    let tail = head.split_once("\r\n").map(|(_, rest)| rest).unwrap_or("\r\n");
    let version = parts.next().unwrap_or("HTTP/1.1");
    let rewritten = format!("{} {} {}\r\n{}", method, path, version, tail);
    Ok(Request { method: Method::Plain(rewritten.into_bytes()),
                 host, port, leftover })
}

fn split_authority(authority: &str) -> Result<(String, u16), String> {
    split_authority_with_default(authority, 443)
}

/// The default differs by scheme: a CONNECT with no port means 443, a
/// plain `http://host/` means 80. One function with the default passed
/// in rather than two that drift.
fn split_authority_with_default(authority: &str, default: u16)
                                -> Result<(String, u16), String> {
    // An IPv6 authority is bracketed, and the name a certificate carries
    // is the address without the brackets.
    if let Some(rest) = authority.strip_prefix('[') {
        let (address, tail) = rest.split_once(']')
            .ok_or("Unclosed [ in the authority.")?;
        let port = match tail.strip_prefix(':') {
            Some(port) => port.parse()
                .map_err(|_| format!("Bad port in {:?}.", authority))?,
            None => default,
        };
        return Ok((address.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((
            host.to_string(),
            port.parse().map_err(|_| format!("Bad port in {:?}.", authority))?)),
        _ => Ok((authority.to_string(), default)),
    }
}

fn resolve(host: &str, port: u16) -> Result<std::net::SocketAddr, String> {
    use std::net::ToSocketAddrs;
    (host, port).to_socket_addrs()
        .map_err(|e| format!("Cannot resolve {}: {}", host, e))?
        .next()
        .ok_or_else(|| format!("{} resolved to nothing.", host))
}

fn refuse(browser: &mut TcpStream, status: u16, reason: &str)
          -> Result<(), String> {
    let text = format!("HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\
                        Content-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                       status,
                       if status == 502 { "Bad Gateway" } else { "Bad Request" },
                       reason.len(), reason);
    browser.write_all(text.as_bytes()).map_err(|e| e.to_string())
}

// -------------------------------------------------------------- bridging ---

fn bridge(proxy: &Proxy, id: u64, host: &str, port: u16, browser: TcpStream,
          upstream: TcpStream, leftover: Vec<u8>) -> Result<(), String> {
    // **The server is reached first**, and that is the whole design:
    // the certificate presented to the browser is built from the one
    // the server sent, so it cannot exist before the server has sent
    // it. Every other terminating proxy can answer the browser
    // immediately because it has nothing to copy.
    let mut client = start_upstream(proxy, host)?;
    let mut upstream = Pump::new(upstream, proxy.log, id, "server");
    if let Err(reason) = upstream.handshake_client(&mut client) {
        // **The browser is told too.** It is sitting inside a tunnel
        // this proxy answered 200 to, and dropping the socket leaves
        // it to time out or to report a certificate error for a
        // certificate that was never sent. A fatal alert at least
        // makes it say the connection failed, now.
        alert_the_browser(browser);
        return Err(describe_handshake_failure(proxy, id, &client, reason));
    }
    let version = client.negotiated_version().map(|v| v.name())
        .unwrap_or_else(|| "?".into());
    let suite = client.negotiated_suite().map(|s| s.name).unwrap_or("?");
    proxy.log.at(level::DETAIL, id, format!(
        "server chose {} {}{}{}", version, suite,
        client.named_group().map(|g| format!(" over {}", g)).unwrap_or_default(),
        if client.resumed() { ", resumed" } else { "" }));
    if let Some(line) = client.key_log_line() {
        proxy.write_keylog(&line);
    }

    let chain = client.peer_certificates().to_vec();
    describe_chain(proxy, id, &chain);
    let trust = judge(proxy, id, host, &chain);
    proxy.log.at(level::INFO, id, format!("{}:{} {} {} [{}]", host, port,
                                          version, suite, trust.describe()));

    let mirror = mirror_for(proxy, id, host, &chain, trust)?;

    // --- the browser's side, with the mirrored certificate ---
    let mut config = ServerConfig::new(
        mirror.chain.clone(),
        ServerKey::Ec { curve: "P-256", private:
                        allcrypt::bignum::BigUint::from_bytes_be(&mirror.private) });
    config.suites = Selection::modern();
    let mut server = ServerConnection::new(config)
        .map_err(|e| e.describe())?;

    let mut browser = Pump::new(browser, proxy.log, id, "browser");
    if !leftover.is_empty() {
        // A client may pipeline its ClientHello straight after the
        // CONNECT. Dropping those bytes makes the handshake hang with
        // nothing to say about why.
        proxy.log.at(level::TRACE, id, format!(
            "{} bytes were pipelined behind the CONNECT", leftover.len()));
        server.push_incoming(&leftover);
    }
    if let Err(reason) = browser.handshake_server(&mut server) {
        return Err(format!("the browser's handshake failed: {}", reason));
    }
    proxy.log.at(level::DETAIL, id, format!(
        "browser side up: {} {}",
        server.version().map(|v| v.name()).unwrap_or_else(|| "?".into()),
        server.negotiated_suite().map(|s| s.name).unwrap_or("?")));

    relay(browser, server, upstream, client, proxy.log, id)
}

/// The failure, and everything that makes it actionable.
///
/// A handshake against equipment nobody will upgrade fails for one of a
/// handful of reasons, and which one it was is the entire question. So
/// this says what we offered as well as what went wrong, and at `-v`
/// the bytes that were being read when it went wrong.
fn describe_handshake_failure(proxy: &Proxy, id: u64, client: &ClientConnection,
                              reason: String) -> String {
    if let Some(alert) = client.alert() {
        proxy.log.at(level::ERROR, id, format!(
            "sent the server a fatal alert: {}", alert.description.name()));
    }
    if let Some(suite) = client.negotiated_suite() {
        proxy.log.at(level::DETAIL, id,
                     format!("it had got as far as {}", suite.name));
    }
    if !proxy.log.enabled(level::DETAIL) {
        proxy.log.at(level::INFO, id,
                     "run with -v for what was offered and -vv for the bytes");
    }
    format!("the handshake with the server failed: {}", reason)
}

/// What the server's certificate says, for the log.
///
/// Printed before the verdict rather than after it, because the verdict
/// is usually a sentence about one of these fields and reading it
/// without them is guesswork.
fn describe_chain(proxy: &Proxy, id: u64, chain: &[Vec<u8>]) {
    if !proxy.log.enabled(level::DETAIL) {
        return;
    }
    proxy.log.at(level::DETAIL, id, format!("the server sent {} certificate{}",
                                            chain.len(),
                                            if chain.len() == 1 { "" } else { "s" }));
    for (depth, der) in chain.iter().enumerate() {
        match Certificate::parse(der) {
            Ok(certificate) => proxy.log.at(level::DETAIL, id, format!(
                "  [{}] subject {} / issuer {} / {} to {} / {} / signed with {}",
                depth,
                certificate.subject.common_name()
                    .unwrap_or_else(|| "(no common name)".into()),
                certificate.issuer.common_name()
                    .unwrap_or_else(|| "(no common name)".into()),
                allcrypt::asn1::format_time(certificate.not_before),
                allcrypt::asn1::format_time(certificate.not_after),
                describe_key(&certificate.public_key),
                certificate.signature_algorithm.describe())),
            Err(reason) => proxy.log.at(level::DETAIL, id, format!(
                "  [{}] unreadable: {}", depth, reason)),
        }
    }
}

/// The key, in the terms that decide whether we can speak to it: what
/// algorithm, and how big or on which curve.
fn describe_key(key: &allcrypt::x509::PublicKey<'_>) -> String {
    use allcrypt::x509::PublicKey;
    match key {
        PublicKey::Rsa { n, .. } => format!("RSA-{}", n.bit_len()),
        PublicKey::Ec { curve, .. } => format!("EC {}", curve),
        PublicKey::UnsupportedCurve { oid, family } =>
            format!("{} on an unimplemented parameter set ({})", family, oid),
        // **Which generation, not just "GOST".** A 2001 key and a
        // 2012 key are the same point on the same curve under
        // different OIDs, and which one a box has decides which
        // cipher suite it can use - so a log line saying only "GOST"
        // leaves the reader with the question they opened the log
        // for.
        PublicKey::Gost { curve, legacy: true, .. } =>
            format!("GOST R 34.10-2001 {}", curve),
        PublicKey::Gost { curve, .. } => format!("GOST R 34.10-2012 {}", curve),
        PublicKey::Eddsa { curve, .. } => curve.to_string(),
        PublicKey::MlDsa { parameter_set, .. } => parameter_set.to_string(),
        PublicKey::Dsa { parameters: Some((p, _, _)), .. } => format!("DSA-{}", p.bit_len()),
        PublicKey::Dsa { parameters: None, .. } => "DSA with inherited parameters".to_string(),
        PublicKey::Unsupported { .. } => "an unsupported algorithm".to_string(),
    }
}

/// A fatal alert, written straight onto the socket.
///
/// There is no TLS connection to produce it: the browser's ClientHello
/// may not even have arrived. But an alert record is five bytes of
/// header and two of body and needs no state, and a browser that gets
/// one says the connection failed instead of hanging until it times
/// out. `internal_error` rather than `handshake_failure` because the
/// failure was ours to report, not the browser's to fix.
fn alert_the_browser(mut browser: TcpStream) {
    const INTERNAL_ERROR: u8 = 80;
    let record = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, INTERNAL_ERROR];
    let _ = browser.write_all(&record);
    let _ = browser.shutdown(Shutdown::Both);
}

/// What to make of the chain the server sent.
///
/// **Verification happens here rather than inside the client**, which
/// is why the client above is configured not to verify. A client that
/// refuses is a client that has closed the connection, and then there
/// is nothing left to mirror - the failure has to become information
/// rather than a dropped connection.
fn judge(proxy: &Proxy, id: u64, host: &str, chain: &[Vec<u8>]) -> Trust {
    if chain.is_empty() {
        return Trust::Untrusted("the server sent no certificate".into());
    }

    // **The server's own certificate, handed to us as a root.**
    //
    // `--root box.pem` where `box.pem` *is* the box's self-signed
    // certificate is the narrowest thing anybody can do here: it says
    // "this exact certificate, on this host, and nothing else". It did
    // not work, and the reason was invisible - a chain verifier looks
    // for an issuer for the leaf, and a self-signed server certificate
    // is not a CA (no basicConstraints, no keyCertSign), so it cannot
    // be its own issuer no matter which store it is in. The result was
    // a certificate that mirrored as untrusted while its own bytes sat
    // in the trust store, with nothing said about why.
    //
    // An exact DER match is not a chain at all; it is a pin, and it is
    // checked here because no amount of chain building will reach it.
    //
    // **A pin is not a free pass.** It replaces the question "who
    // issued this" and nothing else: the certificate must still be for
    // the host being asked for and still be inside its validity
    // window. Written without those two checks first, it made a
    // certificate for another name verify on this one, and
    // `test_the_verdict_is_reported_and_is_about_this_host` - which
    // exists because the mirror hides a wrong-name verdict from the
    // browser - caught it.
    if proxy.roots.roots().iter().any(|root| root == &chain[0]) {
        match Certificate::parse(&chain[0]) {
            Ok(leaf) => {
                let now = now_seconds() as i64;
                if !allcrypt::x509::verify::matches_hostname(&leaf, host) {
                    proxy.log.at(level::DETAIL, id, format!(
                        "the pinned certificate is not for {}", host));
                } else if now < leaf.not_before || now > leaf.not_after {
                    proxy.log.at(level::DETAIL, id,
                                 "the pinned certificate is outside its \
                                  validity window");
                } else {
                    proxy.log.at(level::DETAIL, id,
                                 "the leaf is itself one of the configured \
                                  roots: pinned");
                    return Trust::Verified;
                }
            }
            Err(reason) => proxy.log.at(level::DETAIL, id, format!(
                "a root matched the leaf byte for byte but will not parse: {}",
                reason)),
        }
    }

    let options = allcrypt::api::VerifyOptions {
        now: now_seconds() as i64,
        allow_sha1: proxy.options.allow_sha1,
        allow_md5: proxy.options.allow_md5,
        min_rsa_bits: proxy.options.min_rsa_bits,
        hostname: Some(host.to_string()),
        ..Default::default()
    };
    match allcrypt::api::verify_chain(chain, proxy.roots.roots(), &options) {
        Ok(()) => Trust::Verified,
        Err(reason) => {
            // **Said out loud even when the shape of the answer
            // swallows it.** `Trust::SelfSigned` carries no reason, so
            // for the commonest case on this equipment the log used to
            // print the word "self-signed" and nothing about what the
            // verifier had actually objected to - which matters when
            // the objection was the hostname, or the dates, rather
            // than the signature.
            proxy.log.at(level::DETAIL, id,
                         format!("the chain did not verify: {}", reason));
            // Self-signed is singled out because it is the ordinary
            // case on the equipment this exists for, and because its
            // mirror is a *different shape* - self-signed rather than
            // issued by an unknown CA - and a client says different
            // things about the two.
            match Certificate::parse(&chain[0]) {
                Ok(leaf) if proxy::is_self_signed(&leaf) => Trust::SelfSigned,
                _ => Trust::Untrusted(reason),
            }
        }
    }
}

/// The mirror for this host, built once and kept.
///
/// Keyed by the host **and** by the bytes of the server's certificate:
/// a box that gets a new certificate must not keep being mirrored by
/// the old one, and the check costs a hash of something already in
/// hand.
fn mirror_for(proxy: &Proxy, id: u64, host: &str, chain: &[Vec<u8>], trust: Trust)
              -> Result<Arc<CachedMirror>, String> {
    let fingerprint = {
        use allcrypt::hash_functions::HashFunction;
        allcrypt::hash_functions::sha2::SHA256::new(&chain[0]).digest()
    };
    let key = format!("{}\u{0}{}", host, hex(&fingerprint));

    let now = now_seconds();
    if let Ok(cache) = proxy.cache.lock() {
        if let Some(found) = cache.get(&key) {
            if found.cached_until > now && found.trust == trust {
                proxy.log.at(level::DETAIL, id,
                             format!("mirror: reused, {} seconds left",
                                     found.cached_until - now));
                return Ok(Arc::clone(found));
            }
        }
    }

    proxy.log.at(level::DETAIL, id, format!(
        "mirror: building a new one, signed by {}",
        if trust == Trust::Verified { "the proxy CA the browser trusts" }
        else { "nothing the browser trusts" }));
    let built = proxy::mirror(&chain[0], trust, &proxy.ca, &proxy.untrusted)?;
    let entry = Arc::new(CachedMirror {
        chain: built.chain,
        private: built.private,
        trust: built.trust,
        // An hour. Long enough that a page full of resources reuses
        // one certificate; short enough that a box whose certificate
        // changes is noticed within a session.
        cached_until: now + 3600,
    });
    if let Ok(mut cache) = proxy.cache.lock() {
        cache.insert(key, Arc::clone(&entry));
    }
    Ok(entry)
}

fn start_upstream(proxy: &Proxy, host: &str) -> Result<ClientConnection, String> {
    let mut config = ClientConfig::new(proxy.roots.clone(),
                                       now_seconds() as i64);
    config.suites = selection(&proxy.options.upstream_ciphers)?;
    config.min_version = proxy.options.upstream_min;
    config.max_version = proxy.options.upstream_max;
    config.policy = Policy {
        now: now_seconds() as i64,
        allow_sha1: proxy.options.allow_sha1,
        allow_md5: proxy.options.allow_md5,
        allow_expired: true,
        min_rsa_bits: proxy.options.min_rsa_bits,
        ..Policy::at(now_seconds() as i64)
    };
    config.min_dh_bits = proxy.options.min_dh_bits;

    // **Not the client's job here.** `judge` decides, after the
    // handshake, so that a failure can be mirrored instead of ending
    // the connection. Leaving this on would mean the only servers
    // reachable through the proxy are the ones that did not need it.
    config.verify_certificate = false;
    config.verify_hostname = false;

    ClientConnection::new(config, host).map_err(|e| e.describe())
}

fn selection(name: &str) -> Result<Selection, String> {
    Ok(match name.to_ascii_lowercase().as_str() {
        "modern" | "default" => Selection::modern(),
        "legacy" => Selection::legacy(),
        "all" | "everything" => Selection::all(),
        list => Selection::named(&list.split(',').map(|n| n.trim())
                                 .collect::<Vec<_>>())?,
    })
}

// ------------------------------------------------------------ the sockets ---

/// A socket, and the only place this program does I/O.
///
/// Both TLS connections are sans-I/O: they take bytes and produce
/// bytes and have never heard of a socket. So the reading and writing
/// is here, once, and looks the same for the client and the server.
struct Pump {
    socket: TcpStream,
    log: Log,
    id: u64,
    /// Which end this is, for the trace. "server" or "browser".
    side: &'static str,
    /// The last thing read, kept so that a failure can show what was
    /// being read when it failed. That is the one question a capture
    /// would have answered and the log could not.
    last_read: Vec<u8>,
}

impl Pump {
    fn new(socket: TcpStream, log: Log, id: u64, side: &'static str) -> Pump {
        socket.set_read_timeout(Some(Duration::from_secs(300))).ok();
        Pump { socket, log, id, side, last_read: Vec::new() }
    }

    fn write_out(&mut self, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.log.at(level::TRACE, self.id,
                    format!("-> {} {} bytes", self.side, bytes.len()));
        self.log.bytes(level::TRACE, self.id, &format!("-> {}", self.side), bytes);
        self.socket.write_all(bytes).map_err(|e| e.to_string())
    }

    fn read_in(&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        let read = self.socket.read(buffer).map_err(|e| e.to_string())?;
        self.log.at(level::TRACE, self.id,
                    format!("<- {} {} bytes", self.side, read));
        self.log.bytes(level::TRACE, self.id, &format!("<- {}", self.side),
                       &buffer[..read]);
        self.last_read.clear();
        self.last_read.extend_from_slice(&buffer[..read]);
        Ok(read)
    }

    /// Whatever the connection has queued, written before the error is
    /// returned.
    ///
    /// **This is the bug this method exists for.** `process` puts a
    /// fatal alert in the outgoing queue for every failure - the alert
    /// that says *which* thing was wrong with what the peer sent - and
    /// the loops below used to return on the error and drop the
    /// socket, so the queue went out of scope unsent. On the wire that
    /// is a ServerHello followed by FIN from us and nothing else: no
    /// alert, no reason, nothing for the operator of the far end to
    /// look at either. A protocol that has a way of saying what was
    /// wrong should use it.
    fn flush_alert(&mut self, pending: Vec<u8>) {
        if pending.is_empty() {
            return;
        }
        self.log.at(level::DETAIL, self.id,
                    format!("sending {} the alert for that failure", self.side));
        let _ = self.write_out(&pending);
    }

    /// What was on the wire when it went wrong, since that is the
    /// question.
    fn report_failure(&self, reason: &str) -> String {
        self.log.bytes(level::DETAIL, self.id,
                       &format!("the {}'s last bytes, unprocessed", self.side),
                       &self.last_read);
        reason.to_string()
    }

    fn handshake_client(&mut self, connection: &mut ClientConnection)
                        -> Result<(), String> {
        let mut buffer = [0u8; CHUNK];
        for _ in 0..64 {
            let out = connection.take_outgoing();
            self.write_out(&out)?;
            if !connection.is_handshaking() {
                return Ok(());
            }
            let read = self.read_in(&mut buffer)?;
            if read == 0 {
                return Err(self.report_failure(
                    "the server closed during the handshake without an alert. \
                     It usually means it did not like the ClientHello - run \
                     with -v to see what was offered"));
            }
            connection.push_incoming(&buffer[..read]);
            if let Err(error) = connection.process() {
                let pending = connection.take_outgoing();
                self.flush_alert(pending);
                return Err(self.report_failure(&error.describe()));
            }
        }
        Err("the handshake did not settle in 64 rounds".into())
    }

    fn handshake_server(&mut self, connection: &mut ServerConnection)
                        -> Result<(), String> {
        let mut buffer = [0u8; CHUNK];
        for _ in 0..64 {
            if let Err(error) = connection.process() {
                let pending = connection.take_outgoing();
                self.flush_alert(pending);
                return Err(self.report_failure(&error.describe()));
            }
            let out = connection.take_outgoing();
            self.write_out(&out)?;
            if connection.is_established() {
                return Ok(());
            }
            let read = self.read_in(&mut buffer)?;
            if read == 0 {
                return Err(self.report_failure(
                    "the browser closed during the handshake"));
            }
            connection.push_incoming(&buffer[..read]);
        }
        Err("the handshake did not settle in 64 rounds".into())
    }
}

/// Plaintext across, in both directions, until one end stops.
///
/// One thread per direction. Each locks **one** connection at a time -
/// decrypt, release, encrypt, release - so the two can never be held in
/// opposite orders and there is nothing to deadlock.
fn relay(browser: Pump, server: ServerConnection, upstream: Pump,
         client: ClientConnection, log: Log, id: u64) -> Result<(), String> {
    let server = Arc::new(Mutex::new(server));
    let client = Arc::new(Mutex::new(client));

    let browser_read = browser.socket;
    let upstream_read = upstream.socket;
    let browser_write = browser_read.try_clone().map_err(|e| e.to_string())?;
    let upstream_write = upstream_read.try_clone().map_err(|e| e.to_string())?;

    let to_server = {
        let server = Arc::clone(&server);
        let client = Arc::clone(&client);
        std::thread::spawn(move || {
            pump_direction(browser_read, upstream_write,
                           Peer::Server(server), Peer::Client(client),
                           log, id, "browser to server")
        })
    };
    let to_browser = {
        let server = Arc::clone(&server);
        let client = Arc::clone(&client);
        std::thread::spawn(move || {
            pump_direction(upstream_read, browser_write,
                           Peer::Client(client), Peer::Server(server),
                           log, id, "server to browser")
        })
    };

    let _ = to_server.join();
    let _ = to_browser.join();
    Ok(())
}

/// One of the two connections, so the loop below can be written once.
///
/// An enum rather than a trait: the two types have the same three
/// methods and different concrete types, and a trait here would be
/// three lines of `impl` apiece to say what the enum says in one.
enum Peer {
    Server(Arc<Mutex<ServerConnection>>),
    Client(Arc<Mutex<ClientConnection>>),
}

impl Peer {
    /// Plaintext this connection decrypted before the relay started, and
    /// has not handed over yet. See the note in `pump_direction`.
    fn pending(&self) -> Vec<u8> {
        match self {
            Peer::Server(inner) => match inner.lock() {
                Ok(mut guard) => guard.take_incoming(),
                Err(_) => Vec::new(),
            },
            Peer::Client(inner) => match inner.lock() {
                Ok(mut guard) => guard.take_incoming(),
                Err(_) => Vec::new(),
            },
        }
    }

    /// Decrypt what has arrived, and return (plaintext, bytes to send
    /// back on this same connection).
    fn receive(&self, bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        match self {
            Peer::Server(inner) => {
                let mut guard = inner.lock().map_err(|_| "poisoned")?;
                guard.push_incoming(bytes);
                guard.process().map_err(|e| e.describe())?;
                Ok((guard.take_incoming(), guard.take_outgoing()))
            }
            Peer::Client(inner) => {
                let mut guard = inner.lock().map_err(|_| "poisoned")?;
                guard.push_incoming(bytes);
                guard.process().map_err(|e| e.describe())?;
                Ok((guard.take_incoming(), guard.take_outgoing()))
            }
        }
    }

    /// Encrypt for sending, and return the bytes.
    fn send(&self, payload: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Peer::Server(inner) => {
                let mut guard = inner.lock().map_err(|_| "poisoned")?;
                guard.write(payload).map_err(|e| e.describe())?;
                Ok(guard.take_outgoing())
            }
            Peer::Client(inner) => {
                let mut guard = inner.lock().map_err(|_| "poisoned")?;
                guard.write(payload).map_err(|e| e.describe())?;
                Ok(guard.take_outgoing())
            }
        }
    }

    /// The alert `process` queued for the failure that just happened,
    /// so it can go back to the peer that caused it rather than being
    /// dropped with the socket.
    fn pending_alert(&self) -> Vec<u8> {
        match self {
            Peer::Server(inner) => match inner.lock() {
                Ok(mut guard) => guard.take_outgoing(),
                Err(_) => Vec::new(),
            },
            Peer::Client(inner) => match inner.lock() {
                Ok(mut guard) => guard.take_outgoing(),
                Err(_) => Vec::new(),
            },
        }
    }

    fn close(&self) -> Vec<u8> {
        match self {
            Peer::Server(inner) => match inner.lock() {
                Ok(mut guard) => { let _ = guard.close(); guard.take_outgoing() }
                Err(_) => Vec::new(),
            },
            Peer::Client(inner) => match inner.lock() {
                Ok(mut guard) => { let _ = guard.close(); guard.take_outgoing() }
                Err(_) => Vec::new(),
            },
        }
    }
}

fn pump_direction(mut source: TcpStream, mut sink: TcpStream,
                  from: Peer, to: Peer, log: Log, id: u64, way: &'static str) {
    let mut buffer = vec![0u8; CHUNK];
    let mut back = match source.try_clone() {
        Ok(handle) => handle,
        Err(_) => return,
    };

    // **Whatever the handshake already decrypted goes first.**
    //
    // The handshake loop reads whole TCP segments, and the last one can
    // carry application data behind the final handshake message. At TLS
    // 1.2 that was rare - a client usually waits for the server's
    // Finished before writing - but at 1.3 the client's Finished and its
    // first request are one flight, so the request is *normally* already
    // inside the connection by the time the handshake returns.
    //
    // Reading the socket first, as this loop used to, then blocks
    // forever: the bytes are in the connection's buffer, not on the
    // wire, and the peer is waiting for a reply to a request we are
    // holding. It shows up as a read timeout with no error anywhere,
    // and `pytests/test_proxy.py` caught it as a flaky row rather than
    // a failing one, because whether the two land in one segment is up
    // to the kernel.
    let pending = from.pending();
    if !pending.is_empty() {
        match to.send(&pending) {
            Ok(bytes) => {
                if sink.write_all(&bytes).is_err() {
                    return;
                }
            }
            Err(reason) => {
                log.at(level::ERROR, id,
                       format!("{}: {}", way, reason));
                return;
            }
        }
    }

    loop {
        let read = match source.read(&mut buffer) {
            Ok(0) => break,
            Err(reason) => {
                // A timeout is the interesting one: 300 seconds with
                // neither end saying anything, which is what a
                // half-closed relay looks like from here.
                log.at(level::DETAIL, id, format!("{}: {}", way, reason));
                break;
            }
            Ok(read) => read,
        };
        let (payload, reply) = match from.receive(&buffer[..read]) {
            Ok(pair) => pair,
            // **Not silent.** A record that fails to decrypt mid
            // connection - a MAC that did not check, a sequence number
            // past its limit, a peer alert - used to end the relay with
            // no more trace than a closed socket, which from the
            // browser is indistinguishable from the server hanging up.
            Err(reason) => {
                log.at(level::ERROR, id, format!("{}: {}", way, reason));
                let bytes = from.pending_alert();
                if !bytes.is_empty() {
                    let _ = back.write_all(&bytes);
                }
                break;
            }
        };
        // A record that arrived may have been a handshake one - a
        // session ticket, say - and then there is something to send
        // back on the connection it came from and nothing to forward.
        if !reply.is_empty() && back.write_all(&reply).is_err() {
            break;
        }
        if payload.is_empty() {
            continue;
        }
        match to.send(&payload) {
            Ok(bytes) => {
                if sink.write_all(&bytes).is_err() {
                    break;
                }
            }
            Err(reason) => {
                log.at(level::ERROR, id, format!("{}: {}", way, reason));
                break;
            }
        }
    }
    // Tell the other end, so it closes rather than waiting out its read
    // timeout.
    let bytes = to.close();
    let _ = sink.write_all(&bytes);
    let _ = sink.shutdown(Shutdown::Write);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn now_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).unwrap_or(0)
}
