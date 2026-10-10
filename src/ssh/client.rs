/*
An SSH client, sans-I/O: bytes in, bytes out, like `tls::client`.

What it does: the version exchange, KEXINIT negotiation, every key
exchange in `ssh::kex`, the server's host key checked against what the
caller expects and its signature over the exchange hash verified, the
switch to the negotiated cipher and MAC, `ssh-userauth` with a public
key or a password, and one session channel running one command, with
its output, its exit status, and data sent to it. A key re-exchange the
server starts is followed.

# Pitfalls

**Strict key exchange (Terrapin, CVE-2023-48795).** Both sides
advertise `kex-strict-*-v00@openssh.com` in their first KEXINIT; when
both do, the initial key exchange must contain nothing but key exchange
messages, KEXINIT must be the very first packet, and the sequence
numbers restart at every NEWKEYS. Without it, an attacker who can
insert an IGNORE before NEWKEYS and delete the server's first encrypted
packet (EXT_INFO, usually) shifts the sequence numbers so that nothing
detects the deletion. This client advertises it and holds the server
to it when both have.

**The host key's signature is over `H`, and the algorithm is the
negotiated one.** An RSA host key negotiated as `rsa-sha2-512` must sign
as `rsa-sha2-512`; a signature that names `ssh-rsa` instead is a
downgrade to SHA-1 and is refused.

**RSA user authentication needs the server to have said which hashes it
takes.** A server that sends `server-sig-algs` (RFC 8308) gets
`rsa-sha2-512` or `rsa-sha2-256`; one that sends no EXT_INFO is old and
gets `ssh-rsa`, which is the only thing it knows - and which OpenSSH 8.8
and later refuse by default, hence the extension.

**`first_kex_packet_follows`** in a KEXINIT means a guessed key exchange
packet comes next; if the guess was wrong it is to be ignored, not
treated as an error.

**Only the channel's window says how much may be sent.** Data beyond
the peer's window is a protocol violation; and a client that never
sends WINDOW_ADJUST stalls a server with more output than the initial
window.
*/

use super::kex::{self, Ephemeral, GroupExchange, Method, Transcript};
use super::keys::PublicKey;
use super::msg;
use super::negotiate::{self, KexInit, Side, EXT_INFO_CLIENT, STRICT_CLIENT, STRICT_SERVER};
use super::private_key::PrivateKey;
use super::signature;
use super::transport::{Keys, Opener, Sealer};
use super::wire::{Reader, Writer};
use crate::bignum::BigUint;
use crate::publickey_ciphers::dh::DhGroup;

pub use super::negotiate::Algorithms;

const WINDOW: u32 = 2 * 1024 * 1024;
const MAX_PACKET: u32 = 32 * 1024;

/// What the caller will accept as the server's host key.
pub enum HostKeyCheck {
    /// Exactly this key.
    Key(PublicKey),
    /// A key with this fingerprint, `SHA256:...` or `MD5:..:..`.
    Fingerprint(String),
    /// Anything, recorded in `Client::host_key` for the caller to judge.
    /// For a first connection, and for tests.
    AcceptAny,
}

/// How to authenticate.
pub enum Auth {
    PublicKey(PrivateKey),
    Password(String),
}

/// Where the client's random bytes come from: the operating system,
/// normally - see `Client::with_random`.
pub type RandomSource = Box<dyn FnMut(&mut [u8]) -> Result<(), String> + Send + Sync>;

pub struct ClientConfig {
    pub user: String,
    /// Tried in order until one succeeds.
    pub auth: Vec<Auth>,
    pub host_key: HostKeyCheck,
    /// The algorithms offered, in preference order. The defaults are the
    /// non-legacy entries of each table; a legacy one is reached by
    /// naming it here.
    pub kex: Vec<&'static str>,
    pub host_key_algorithms: Vec<&'static str>,
    pub ciphers: Vec<&'static str>,
    pub macs: Vec<&'static str>,
    /// Without the `\r\n`.
    pub version: String,
    /// Ask for a group exchange with RFC 4419's pre-standard request
    /// (`KEX_DH_GEX_REQUEST_OLD`, which names `n` alone) instead of the
    /// `min, n, max` form. Off by default; for a server old enough to
    /// understand only the old form.
    pub legacy_group_exchange_request: bool,
}

impl ClientConfig {
    pub fn new(user: &str, host_key: HostKeyCheck) -> ClientConfig {
        ClientConfig {
            user: user.to_string(),
            auth: Vec::new(),
            host_key,
            kex: negotiate::default_kex(),
            host_key_algorithms: negotiate::HOST_KEY_ALGORITHMS.to_vec(),
            ciphers: negotiate::CIPHERS.to_vec(),
            macs: negotiate::MACS.to_vec(),
            version: format!("SSH-2.0-allcrypt_{}", env!("CARGO_PKG_VERSION")),
            legacy_group_exchange_request: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Phase {
    Version,
    /// KEXINIT sent, waiting for the server's.
    KexInit,
    /// The method's first message sent, waiting for its reply.
    KexReply,
    /// Waiting for the server's NEWKEYS.
    NewKeys,
    ServiceAccept,
    Auth,
    ChannelOpen,
    ExecReply,
    Session,
    Closed,
}

/// One key exchange in progress.
struct Exchange {
    client_kexinit: Vec<u8>,
    server_kexinit: Vec<u8>,
    algorithms: Algorithms,
    ephemeral: Option<Ephemeral>,
    /// Group exchange: the request sent, before the group arrives.
    gex_request: Option<(u32, u32, u32)>,
    /// The server guessed wrong; drop its next packet.
    skip_guess: bool,
    pending_keys: Option<(Keys, Keys)>,
}

pub struct Client {
    config: ClientConfig,
    fill: RandomSource,
    sealer: Sealer,
    opener: Opener,
    outgoing: Vec<u8>,
    phase: Phase,
    /// Where to return after a re-exchange the server started.
    resume: Phase,
    authenticated: bool,
    server_version: Vec<u8>,
    session_id: Option<Vec<u8>>,
    strict: bool,
    first_kex: bool,
    exchange: Option<Exchange>,
    algorithms: Algorithms,
    host_key: Option<PublicKey>,
    server_sig_algs: Option<Vec<String>>,
    auth_index: usize,
    auth_methods_left: Vec<String>,
    banner: String,
    command: Option<String>,
    remote_channel: u32,
    remote_window: u64,
    remote_max_packet: u32,
    local_consumed: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_status: Option<u32>,
    eof_received: bool,
    pending_send: Vec<u8>,
    send_eof: bool,
}

impl Client {
    /// A client that will connect as `config` says. Randomness comes from
    /// the operating system.
    pub fn new(config: ClientConfig) -> Result<Client, String> {
        Client::with_random(config, Box::new(|buf: &mut [u8]| crate::random::fill(buf)))
    }

    /// The same, drawing every random byte - padding, cookie, ephemeral
    /// keys - from `fill`. A fixed `fill` makes the client's whole side
    /// of a session reproducible, which is what lets a recorded server
    /// side be replayed against it offline.
    pub fn with_random(config: ClientConfig,
                       fill: RandomSource)
                       -> Result<Client, String> {
        let mut client = Client {
            config,
            fill,
            sealer: Sealer::new()?,
            opener: Opener::new()?,
            outgoing: Vec::new(),
            phase: Phase::Version,
            resume: Phase::Session,
            authenticated: false,
            server_version: Vec::new(),
            session_id: None,
            strict: false,
            first_kex: true,
            exchange: None,
            algorithms: Algorithms::default(),
            host_key: None,
            server_sig_algs: None,
            auth_index: 0,
            auth_methods_left: Vec::new(),
            banner: String::new(),
            command: None,
            remote_channel: 0,
            remote_window: 0,
            remote_max_packet: 0,
            local_consumed: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_status: None,
            eof_received: false,
            pending_send: Vec::new(),
            send_eof: false,
        };
        client.outgoing.extend_from_slice(client.config.version.as_bytes());
        client.outgoing.extend_from_slice(b"\r\n");
        client.send_kexinit()?;
        Ok(client)
    }

    // ------------------------------------------------------- the caller ---

    /// Run `command` once authenticated. Must be called before the
    /// session channel opens - normally right after `new`.
    pub fn exec(&mut self, command: &str) {
        self.command = Some(command.to_string());
    }

    /// Data for the command's standard input. Sent as the window allows.
    pub fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.pending_send.extend_from_slice(data);
        self.flush_channel()
    }

    /// Close the command's standard input once what was written has gone.
    pub fn send_eof(&mut self) -> Result<(), String> {
        self.send_eof = true;
        self.flush_channel()
    }

    pub fn push_incoming(&mut self, bytes: &[u8]) {
        self.opener.push(bytes);
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }

    pub fn take_stdout(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stdout)
    }

    pub fn take_stderr(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.stderr)
    }

    pub fn exit_status(&self) -> Option<u32> {
        self.exit_status
    }

    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn closed(&self) -> bool {
        self.phase == Phase::Closed
    }

    pub fn host_key(&self) -> Option<&PublicKey> {
        self.host_key.as_ref()
    }

    pub fn algorithms(&self) -> &Algorithms {
        &self.algorithms
    }

    pub fn server_version(&self) -> &[u8] {
        &self.server_version
    }

    /// Whether strict key exchange is in force.
    pub fn strict_kex(&self) -> bool {
        self.strict
    }

    pub fn banner(&self) -> &str {
        &self.banner
    }

    /// Handle everything received so far.
    pub fn process(&mut self) -> Result<(), String> {
        if self.phase == Phase::Version {
            loop {
                let Some(line) = self.opener.take_line() else {
                    if self.opener.buffered().len() > 8192 {
                        return Err("SSH: no version line in the first 8 KiB.".to_string());
                    }
                    return Ok(());
                };
                // RFC 4253 4.2: lines before the version are allowed, and
                // are not part of the protocol.
                if line.starts_with(b"SSH-") {
                    let end = line.len() - if line.ends_with(b"\r\n") { 2 } else { 1 };
                    self.server_version = line[..end].to_vec();
                    if !self.server_version.starts_with(b"SSH-2.0-")
                        && !self.server_version.starts_with(b"SSH-1.99-") {
                        return Err(format!("SSH: the server speaks {:?}, not SSH 2.",
                                           String::from_utf8_lossy(&self.server_version)));
                    }
                    self.phase = Phase::KexInit;
                    break;
                }
            }
        }
        while let Some(payload) = self.opener.open()? {
            self.handle(&payload)?;
            if self.phase == Phase::Closed {
                break;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------- sending ---

    fn send(&mut self, payload: &[u8]) -> Result<(), String> {
        let packet = self.sealer.seal(payload, &mut *self.fill)?;
        self.outgoing.extend_from_slice(&packet);
        Ok(())
    }

    fn send_kexinit(&mut self) -> Result<(), String> {
        let mut cookie = [0u8; 16];
        (self.fill)(&mut cookie)?;
        let mut kex_names: Vec<&str> = self.config.kex.clone();
        if self.first_kex {
            kex_names.push(EXT_INFO_CLIENT);
            kex_names.push(STRICT_CLIENT);
        }
        let mut macs: Vec<&str> = self.config.macs.clone();
        if macs.is_empty() {
            macs.push("hmac-sha2-256");
        }
        let payload = negotiate::encode(&cookie, &kex_names, &self.config.host_key_algorithms,
                                        &self.config.ciphers, &macs)?;
        self.send(&payload)?;
        self.exchange = Some(Exchange {
            client_kexinit: payload,
            server_kexinit: Vec::new(),
            algorithms: Algorithms::default(),
            ephemeral: None,
            gex_request: None,
            skip_guess: false,
            pending_keys: None,
        });
        Ok(())
    }

    // ------------------------------------------------------- receiving ---

    fn handle(&mut self, payload: &[u8]) -> Result<(), String> {
        let kind = *payload.first().ok_or("SSH: an empty packet.")?;
        let in_kex = self.exchange.as_ref().is_some_and(|e| !e.server_kexinit.is_empty())
            || matches!(self.phase, Phase::KexInit | Phase::KexReply | Phase::NewKeys);

        if let Some(exchange) = self.exchange.as_mut() {
            if exchange.skip_guess && kind != msg::KEXINIT {
                exchange.skip_guess = false;
                return Ok(());
            }
        }
        // Strict key exchange: until the initial exchange's NEWKEYS, only
        // key exchange messages - not even IGNORE.
        if self.strict && self.first_kex && !(msg::KEXINIT..=49).contains(&kind) {
            return Err(format!("SSH: message {kind} during a strict key exchange."));
        }
        match kind {
            msg::DISCONNECT => {
                let mut reader = Reader::new(&payload[1..]);
                let code = reader.uint32().unwrap_or(0);
                let text = reader.text().unwrap_or("");
                self.phase = Phase::Closed;
                return Err(format!("SSH: the server disconnected ({code}): {text}"));
            }
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => return Ok(()),
            msg::KEXINIT => return self.on_kexinit(payload),
            msg::NEWKEYS => return self.on_newkeys(),
            msg::KEX_30..=49 if in_kex => return self.on_kex_message(kind, payload),
            msg::EXT_INFO => return self.on_ext_info(payload),
            msg::GLOBAL_REQUEST => {
                let mut reader = Reader::new(&payload[1..]);
                let _name = reader.text()?;
                if reader.boolean()? {
                    self.send(&[msg::REQUEST_FAILURE])?;
                }
                return Ok(());
            }
            _ => {}
        }
        match self.phase {
            Phase::ServiceAccept if kind == msg::SERVICE_ACCEPT => self.start_auth(),
            Phase::Auth => self.on_auth(kind, payload),
            Phase::ChannelOpen if kind == msg::CHANNEL_OPEN_CONFIRMATION => {
                let mut reader = Reader::new(&payload[1..]);
                let _ours = reader.uint32()?;
                self.remote_channel = reader.uint32()?;
                self.remote_window = u64::from(reader.uint32()?);
                // A maximum packet size of zero would make every chunk
                // empty and the flush below spin forever. Treated as 1,
                // as the server side treats a client's zero: the peer
                // said nothing fits, so send the least that is something.
                self.remote_max_packet = reader.uint32()?.max(1);
                let command = self.command.clone().unwrap_or_default();
                let mut writer = Writer::new();
                writer.byte(msg::CHANNEL_REQUEST).uint32(self.remote_channel)
                    .string(b"exec").boolean(true).string(command.as_bytes());
                self.send(&writer.finish())?;
                self.phase = Phase::ExecReply;
                Ok(())
            }
            Phase::ChannelOpen if kind == msg::CHANNEL_OPEN_FAILURE => {
                let mut reader = Reader::new(&payload[1..]);
                let _ours = reader.uint32()?;
                let code = reader.uint32()?;
                let text = reader.text().unwrap_or("");
                Err(format!("SSH: the server refused a session channel ({code}): {text}"))
            }
            Phase::ExecReply if kind == msg::CHANNEL_SUCCESS => {
                self.phase = Phase::Session;
                self.flush_channel()
            }
            Phase::ExecReply if kind == msg::CHANNEL_FAILURE =>
                Err("SSH: the server refused to run the command.".to_string()),
            Phase::Session | Phase::ExecReply => self.on_channel(kind, payload),
            _ => Err(format!("SSH: message {kind} was not expected now ({:?}).", self.phase)),
        }
    }

    // ---------------------------------------------------- key exchange ---

    fn on_kexinit(&mut self, payload: &[u8]) -> Result<(), String> {
        if self.exchange.is_none() {
            // The server starts a re-exchange; answer with ours, and come
            // back to where we were once it is done.
            self.resume = self.phase;
            self.send_kexinit()?;
        }
        let theirs = KexInit::parse(payload)?;
        if self.first_kex {
            self.strict = theirs.kex.contains(&STRICT_SERVER);
            // Strict mode: the server's KEXINIT must have been its first
            // packet.
            if self.strict && self.opener.sequence != 1 {
                return Err("SSH: strict key exchange, and KEXINIT was not the \
                            server's first packet.".to_string());
            }
        }
        let ours = &self.exchange.as_ref().ok_or("state")?.client_kexinit;
        let algorithms = negotiate::negotiate(&KexInit::parse(ours)?, &theirs)?;
        let skip_guess = theirs.guess_is_wrong(&algorithms);
        let method = kex::lookup(&algorithms.kex)?.method;

        let exchange = self.exchange.as_mut().ok_or("state")?;
        exchange.server_kexinit = payload.to_vec();
        exchange.algorithms = algorithms;
        exchange.skip_guess = skip_guess;

        match method {
            Method::DhGroupExchange { .. } => {
                let request = (2048, 4096, 8192);
                exchange.gex_request = Some(request);
                let mut writer = Writer::new();
                if self.config.legacy_group_exchange_request {
                    writer.byte(msg::KEX_DH_GEX_REQUEST_OLD).uint32(request.1);
                } else {
                    writer.byte(msg::KEX_DH_GEX_REQUEST)
                        .uint32(request.0).uint32(request.1).uint32(request.2);
                }
                self.send(&writer.finish())?;
            }
            _ => {
                let ephemeral = Ephemeral::client(method, None, &mut *self.fill)?;
                let mut writer = Writer::new();
                writer.byte(msg::KEX_30);
                ephemeral.write_public(&mut writer);
                self.send(&writer.finish())?;
                self.exchange.as_mut().ok_or("state")?.ephemeral = Some(ephemeral);
            }
        }
        self.phase = Phase::KexReply;
        Ok(())
    }

    fn on_kex_message(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        let exchange = self.exchange.as_mut().ok_or("SSH: key exchange message \
                                                       outside a key exchange.")?;
        let method = kex::lookup(&exchange.algorithms.kex)?.method;
        let is_gex = matches!(method, Method::DhGroupExchange { .. });
        let mut reader = Reader::new(&payload[1..]);

        if is_gex && kind == msg::KEX_31 && exchange.ephemeral.is_none() {
            // KEX_DH_GEX_GROUP: the server's p and g.
            let p = BigUint::from_bytes_be(reader.mpint()?);
            let g = BigUint::from_bytes_be(reader.mpint()?);
            reader.finish("a group exchange's group")?;
            let group = DhGroup::new(p, g)?;
            let (min, preferred, max) = exchange.gex_request.ok_or("state")?;
            if group.bits() < min as usize || group.bits() > max as usize {
                return Err(format!("SSH: the server's group is {} bits, outside the \
                                    {min} to {max} asked for.", group.bits()));
            }
            group.check_prime(16)?;
            let old = self.config.legacy_group_exchange_request;
            let ephemeral = Ephemeral::client(
                method, Some(GroupExchange { min, preferred, max, group, old }),
                &mut *self.fill)?;
            let mut writer = Writer::new();
            writer.byte(msg::KEX_DH_GEX_INIT);
            ephemeral.write_public(&mut writer);
            exchange.ephemeral = Some(ephemeral);
            let packet = writer.finish();
            return self.send(&packet);
        }
        let expected = if is_gex { msg::KEX_DH_GEX_REPLY } else { msg::KEX_31 };
        if kind != expected || self.phase != Phase::KexReply {
            return Err(format!("SSH: key exchange message {kind} out of order."));
        }
        let host_blob = reader.string()?;
        let server_public = if matches!(method, Method::DhGroup { .. } | Method::DhGroupExchange { .. }) {
            reader.mpint()?
        } else {
            reader.string()?
        };
        let host_signature = reader.string()?;
        reader.finish("the key exchange reply")?;

        let host_key = PublicKey::from_blob(host_blob)?;
        self.check_host_key(&host_key)?;
        let exchange = self.exchange.as_mut().ok_or("state")?;
        let transcript = Transcript {
            client_version: self.config.version.as_bytes(),
            server_version: &self.server_version,
            client_kexinit: &exchange.client_kexinit,
            server_kexinit: &exchange.server_kexinit,
            host_key: host_blob,
        };
        let ephemeral = exchange.ephemeral.take().ok_or("state")?;
        let (shared, h) = ephemeral.finish(&transcript, server_public)?;

        // The host key signs H, under the negotiated algorithm.
        let verified = signature::verify(&host_key, &h, host_signature)?;
        match verified {
            Some(name) if name == exchange.algorithms.host_key => {}
            Some(name) => return Err(format!(
                "SSH: the host key signed as {name}, and {} was negotiated.",
                exchange.algorithms.host_key)),
            None => return Err("SSH: the host key's signature over the exchange does \
                                not verify.".to_string()),
        }
        let session_id = self.session_id.get_or_insert_with(|| h.clone()).clone();
        let keys = negotiate::derive_keys(method.hash_name(), &shared, &h, &session_id,
                                          &exchange.algorithms, Side::Client)?;
        exchange.pending_keys = Some(keys);
        self.host_key = Some(host_key);

        self.send(&[msg::NEWKEYS])?;
        let exchange = self.exchange.as_mut().ok_or("state")?;
        let (send_keys, receive_keys) = exchange.pending_keys.take().ok_or("state")?;
        exchange.pending_keys = Some((Keys::none()?, receive_keys));
        self.sealer.rekey(send_keys, self.strict);
        self.phase = Phase::NewKeys;
        Ok(())
    }

    fn check_host_key(&self, key: &PublicKey) -> Result<(), String> {
        // A re-exchange must present the same key.
        if let Some(known) = &self.host_key {
            if known != key {
                return Err("SSH: the host key changed during a re-exchange.".to_string());
            }
        }
        match &self.config.host_key {
            HostKeyCheck::AcceptAny => Ok(()),
            HostKeyCheck::Key(expected) if expected == key => Ok(()),
            HostKeyCheck::Fingerprint(expected)
                if *expected == key.fingerprint_sha256() || *expected == key.fingerprint_md5() =>
                Ok(()),
            _ => Err(format!("SSH: the server's host key is {} {}, which is not the one \
                              expected.", key.algorithm(), key.fingerprint_sha256())),
        }
    }

    fn on_newkeys(&mut self) -> Result<(), String> {
        if self.phase != Phase::NewKeys {
            return Err("SSH: NEWKEYS out of order.".to_string());
        }
        let mut exchange = self.exchange.take().ok_or("state")?;
        let (_, receive_keys) = exchange.pending_keys.take().ok_or("state")?;
        self.opener.rekey(receive_keys, self.strict);
        self.algorithms = exchange.algorithms;
        if self.first_kex {
            self.first_kex = false;
            let mut writer = Writer::new();
            writer.byte(msg::SERVICE_REQUEST).string(b"ssh-userauth");
            self.send(&writer.finish())?;
            self.phase = Phase::ServiceAccept;
        } else {
            self.phase = self.resume;
        }
        Ok(())
    }

    fn on_ext_info(&mut self, payload: &[u8]) -> Result<(), String> {
        let mut reader = Reader::new(&payload[1..]);
        let count = reader.uint32()?;
        for _ in 0..count {
            let name = reader.text()?;
            let value = reader.string()?;
            if name == "server-sig-algs" {
                let names = core::str::from_utf8(value)
                    .map_err(|_| "SSH: server-sig-algs is not text.".to_string())?;
                self.server_sig_algs = Some(names.split(',').map(str::to_string).collect());
            }
        }
        Ok(())
    }

    // -------------------------------------------------- authentication ---

    fn start_auth(&mut self) -> Result<(), String> {
        self.phase = Phase::Auth;
        self.auth_index = 0;
        self.try_auth()
    }

    fn try_auth(&mut self) -> Result<(), String> {
        let Some(auth) = self.config.auth.get(self.auth_index) else {
            return Err(format!("SSH: authentication failed; the server would take {}.",
                               self.auth_methods_left.join(", ")));
        };
        let mut writer = Writer::new();
        writer.byte(msg::USERAUTH_REQUEST)
            .string(self.config.user.as_bytes())
            .string(b"ssh-connection");
        match auth {
            Auth::Password(password) => {
                writer.string(b"password").boolean(false).string(password.as_bytes());
            }
            Auth::PublicKey(key) => {
                let public = key.public();
                let algorithm = match &public {
                    PublicKey::Rsa(_) => match &self.server_sig_algs {
                        Some(list) if list.iter().any(|a| a == "rsa-sha2-512") => "rsa-sha2-512",
                        Some(list) if list.iter().any(|a| a == "rsa-sha2-256") => "rsa-sha2-256",
                        Some(_) => "ssh-rsa",
                        // No EXT_INFO: an old server, which knows ssh-rsa.
                        None => "ssh-rsa",
                    },
                    other => other.algorithm(),
                };
                let blob = public.to_blob();
                let session_id = self.session_id.as_ref().ok_or("state")?;
                let mut signed = Writer::new();
                signed.string(session_id).byte(msg::USERAUTH_REQUEST)
                    .string(self.config.user.as_bytes()).string(b"ssh-connection")
                    .string(b"publickey").boolean(true)
                    .string(algorithm.as_bytes()).string(&blob);
                let signature = signature::sign(key, &signed.finish(), Some(algorithm))?;
                writer.string(b"publickey").boolean(true)
                    .string(algorithm.as_bytes()).string(&blob).string(&signature);
            }
        }
        self.send(&writer.finish())
    }

    fn on_auth(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        match kind {
            msg::USERAUTH_SUCCESS => {
                self.authenticated = true;
                let mut writer = Writer::new();
                writer.byte(msg::CHANNEL_OPEN).string(b"session")
                    .uint32(0).uint32(WINDOW).uint32(MAX_PACKET);
                self.send(&writer.finish())?;
                self.phase = Phase::ChannelOpen;
                Ok(())
            }
            msg::USERAUTH_FAILURE => {
                let mut reader = Reader::new(&payload[1..]);
                self.auth_methods_left = reader.name_list()?.iter().map(|s| s.to_string()).collect();
                self.auth_index += 1;
                self.try_auth()
            }
            msg::USERAUTH_BANNER => {
                let mut reader = Reader::new(&payload[1..]);
                self.banner.push_str(reader.text()?);
                Ok(())
            }
            other => Err(format!("SSH: message {other} during authentication.")),
        }
    }

    // ------------------------------------------------------- the channel ---

    fn on_channel(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        let mut reader = Reader::new(&payload[1..]);
        let _ours = reader.uint32()?;
        match kind {
            msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA => {
                let stream = if kind == msg::CHANNEL_EXTENDED_DATA { reader.uint32()? } else { 0 };
                let data = reader.string()?;
                if stream == 1 {
                    self.stderr.extend_from_slice(data);
                } else {
                    self.stdout.extend_from_slice(data);
                }
                self.local_consumed = self.local_consumed.saturating_add(data.len() as u32);
                if self.local_consumed > WINDOW / 2 {
                    let mut writer = Writer::new();
                    writer.byte(msg::CHANNEL_WINDOW_ADJUST).uint32(self.remote_channel)
                        .uint32(self.local_consumed);
                    self.local_consumed = 0;
                    self.send(&writer.finish())?;
                }
                Ok(())
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                self.remote_window += u64::from(reader.uint32()?);
                self.flush_channel()
            }
            msg::CHANNEL_REQUEST => {
                let name = reader.text()?;
                let want_reply = reader.boolean()?;
                if name == "exit-status" {
                    self.exit_status = Some(reader.uint32()?);
                }
                if want_reply {
                    let mut writer = Writer::new();
                    writer.byte(msg::CHANNEL_FAILURE).uint32(self.remote_channel);
                    self.send(&writer.finish())?;
                }
                Ok(())
            }
            msg::CHANNEL_EOF => {
                self.eof_received = true;
                Ok(())
            }
            msg::CHANNEL_CLOSE => {
                let mut writer = Writer::new();
                writer.byte(msg::CHANNEL_CLOSE).uint32(self.remote_channel);
                self.send(&writer.finish())?;
                let mut writer = Writer::new();
                writer.byte(msg::DISCONNECT).uint32(msg::reason::BY_APPLICATION).string(b"done").string(b"");
                self.send(&writer.finish())?;
                self.phase = Phase::Closed;
                Ok(())
            }
            msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE => Ok(()),
            other => Err(format!("SSH: unexpected channel message {other}.")),
        }
    }

    fn flush_channel(&mut self) -> Result<(), String> {
        if self.phase != Phase::Session {
            return Ok(());
        }
        while !self.pending_send.is_empty() && self.remote_window > 0 {
            let room = (self.remote_window as usize).min(self.remote_max_packet as usize)
                .min(self.pending_send.len());
            if room == 0 {
                // Cannot happen with the three operands above all
                // positive; kept so that the loop can only ever make
                // progress, whatever the fields hold.
                break;
            }
            let chunk: Vec<u8> = self.pending_send.drain(..room).collect();
            let mut writer = Writer::new();
            writer.byte(msg::CHANNEL_DATA).uint32(self.remote_channel).string(&chunk);
            self.send(&writer.finish())?;
            self.remote_window -= room as u64;
        }
        if self.send_eof && self.pending_send.is_empty() {
            self.send_eof = false;
            let mut writer = Writer::new();
            writer.byte(msg::CHANNEL_EOF).uint32(self.remote_channel);
            self.send(&writer.finish())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client past the key exchange, as far as the channel-open
    /// handshake, with no cipher on either direction so that packets can
    /// be fed and read as plaintext.
    fn client_waiting_for_channel_open() -> Client {
        let config = ClientConfig::new("user", HostKeyCheck::AcceptAny);
        let mut client = Client::with_random(
            config, Box::new(|buf: &mut [u8]| { buf.fill(0); Ok(()) })).unwrap();
        client.outgoing.clear();
        client.exchange = None;
        client.phase = Phase::ChannelOpen;
        client.command = Some("cat".to_string());
        client
    }

    /// A CHANNEL_OPEN_CONFIRMATION announcing a maximum packet size of
    /// zero must not make `write` loop forever.
    ///
    /// What was wrong: `remote_max_packet` was stored unchecked, so the
    /// chunk size in `flush_channel` was `min(window, 0, pending)` = 0,
    /// every iteration drained nothing, sent an empty CHANNEL_DATA and
    /// left the window untouched - a loop that never ended and grew
    /// `outgoing` until memory ran out, on the first `write` after
    /// CHANNEL_SUCCESS. The server side already clamped the same field
    /// with `max(1)`; the replay tests could not reach the case because
    /// sshd never sends a zero. The value is now clamped to 1 and the
    /// loop also stops on a zero-sized chunk.
    #[test]
    fn test_a_zero_maximum_packet_size_does_not_hang_write() {
        let mut client = client_waiting_for_channel_open();

        let mut confirmation = Writer::new();
        confirmation.byte(msg::CHANNEL_OPEN_CONFIRMATION)
            .uint32(0)          // the client's channel
            .uint32(7)          // the server's channel
            .uint32(1024)       // initial window
            .uint32(0);         // maximum packet size: the bad value
        client.handle(&confirmation.finish()).unwrap();
        assert_eq!(client.remote_max_packet, 1);
        assert_eq!(client.phase, Phase::ExecReply);

        client.handle(&[msg::CHANNEL_SUCCESS]).unwrap();
        assert_eq!(client.phase, Phase::Session);
        client.outgoing.clear();

        // On the old code this call never returned.
        client.write(b"abc").unwrap();
        assert!(client.pending_send.is_empty());
        assert_eq!(client.remote_window, 1024 - 3);

        // Three one-byte CHANNEL_DATA packets, each carrying something.
        let mut sent = 0;
        let mut rest: &[u8] = &client.outgoing;
        while !rest.is_empty() {
            let length = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let payload_len = length - 1 - rest[4] as usize;
            let payload = &rest[5..5 + payload_len];
            assert_eq!(payload[0], msg::CHANNEL_DATA);
            let mut reader = Reader::new(&payload[1..]);
            assert_eq!(reader.uint32().unwrap(), 7);
            assert_eq!(reader.string().unwrap().len(), 1);
            sent += 1;
            rest = &rest[4 + length..];
        }
        assert_eq!(sent, 3);
    }
}
