/*
An SSH server, sans-I/O: bytes in, bytes out, like `client`.

What it does: the version exchange, KEXINIT negotiation by the client's
preference, every key exchange in `ssh::kex` (the group exchange picks
from RFC 3526's MODP groups), the exchange hash signed with whichever
host key the negotiated algorithm names, `ssh-userauth` by public key
or password against a list the caller gives, and one session channel.
What runs on that channel is the caller's business: the server reports
the request (`exec` with its command, or `shell`) with any terminal and
environment variables the client asked for, hands over standard input,
and sends what the caller writes, the exit status and the close.
A re-exchange is followed when the client starts one and can be started
here with `rekey`.

# Pitfalls

**The client's order decides** (`negotiate`). The server's preference
counts only in what it offers at all.

**The host key signs `H` under the negotiated algorithm, not its own
favourite.** An RSA key negotiated as `ssh-rsa` must sign with SHA-1,
and one negotiated as `rsa-sha2-256` with SHA-256; the client checks the
name in the signature against the negotiation. With several host keys,
the algorithm picks the key.

**A public key query proves nothing.** RFC 4252 7: a request without a
signature asks whether the key *would* be accepted, and gets
`USERAUTH_PK_OK`; only the request with the signature authenticates.
The signature covers the session identifier as a string and then the
request exactly as sent, so it is checked against the received bytes
rather than a re-encoding of them.

**The algorithm in the request must be the one in the signature.** A
request naming `rsa-sha2-512` whose blob says `ssh-rsa` is a signature
over SHA-1 offered under a SHA-512 name, and is refused.

**EXT_INFO goes right after the first NEWKEYS, and only if asked.** RFC
8308: the client's `ext-info-c` asks for it, and the server sends it as
its first packet under the new keys. Before that would break strict key
exchange, which allows nothing but key exchange messages until NEWKEYS;
without it, a client that cannot tell which RSA hashes the server takes
for user authentication falls back to `ssh-rsa` - and an OpenSSH client
from 8.8 on will not.

**During a key exchange, only key exchange messages.** RFC 4253 7.1:
once a side has sent KEXINIT it sends nothing else until its NEWKEYS.
Data the caller writes during a re-exchange is held and sent under the
new keys.

**The window is the client's to give.** Data beyond what the client's
window allows is a protocol violation; and the server's own window is
re-opened only as the caller takes standard input, so a client cannot
make it buffer without bound.

**`exit-status` before CLOSE.** OpenSSH's `ssh` takes its exit code
from the `exit-status` request, and a channel closed without one ends
`ssh` with 255 - the same as a failed connection.
*/

use std::collections::VecDeque;

use super::kex::{self, GroupExchange, Method, Transcript, MODP_SIZES};
use super::keys::PublicKey;
use super::msg::{self, open_failure, reason};
use super::negotiate::{self, Algorithms, KexInit, Side, EXT_INFO_CLIENT, STRICT_CLIENT,
                       STRICT_SERVER};
use super::private_key::PrivateKey;
use super::signature;
use super::transport::{Keys, Opener, Sealer};
use super::wire::{Reader, Writer};
use crate::api::AnyHash;
use crate::hash_functions::HashFunction;

const WINDOW: u32 = 2 * 1024 * 1024;
const MAX_PACKET: u32 = 32 * 1024;
/// The id this server gives its one channel.
const CHANNEL_ID: u32 = 0;

/// What a user may authenticate with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    PublicKey(PublicKey),
    Password(String),
}

/// One entry of what the server accepts.
#[derive(Clone, Debug)]
pub struct Authorized {
    pub user: String,
    pub credential: Credential,
}

/// Where the server's random bytes come from: see `Server::with_random`.
pub type RandomSource = super::client::RandomSource;

pub struct ServerConfig {
    /// At least one. Each key serves the algorithms it can sign under.
    pub host_keys: Vec<PrivateKey>,
    pub authorized: Vec<Authorized>,
    /// The algorithms offered. The defaults are the client's: the
    /// non-legacy ones, with a legacy one reached by naming it.
    pub kex: Vec<&'static str>,
    pub host_key_algorithms: Vec<&'static str>,
    pub ciphers: Vec<&'static str>,
    pub macs: Vec<&'static str>,
    /// Without the `\r\n`.
    pub version: String,
    /// Sent before the first authentication reply.
    pub banner: Option<String>,
    /// Authentication requests allowed before the server disconnects.
    pub max_auth_attempts: u32,
    /// The group sizes a group exchange may pick from, each one of
    /// `kex::MODP_SIZES`: what `/etc/ssh/moduli` is to OpenSSH.
    pub group_exchange_sizes: Vec<usize>,
}

impl ServerConfig {
    pub fn new(host_keys: Vec<PrivateKey>) -> ServerConfig {
        ServerConfig {
            host_keys,
            authorized: Vec::new(),
            kex: negotiate::default_kex(),
            host_key_algorithms: negotiate::HOST_KEY_ALGORITHMS.to_vec(),
            ciphers: negotiate::CIPHERS.to_vec(),
            macs: negotiate::MACS.to_vec(),
            version: format!("SSH-2.0-allcrypt_{}", env!("CARGO_PKG_VERSION")),
            banner: None,
            max_auth_attempts: 20,
            group_exchange_sizes: MODP_SIZES.to_vec(),
        }
    }

    /// Accept `key` for `user`.
    pub fn authorize_key(&mut self, user: &str, key: PublicKey) {
        self.authorized.push(Authorized { user: user.to_string(),
                                          credential: Credential::PublicKey(key) });
    }

    /// Accept `password` for `user`.
    pub fn authorize_password(&mut self, user: &str, password: &str) {
        self.authorized.push(Authorized { user: user.to_string(),
                                          credential: Credential::Password(password.to_string()) });
    }
}

/// What the client asked the session channel to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionRequest {
    Exec(String),
    Shell,
}

/// What a `pty-req` asked for: the terminal type and its size in
/// characters. The encoded terminal modes are not kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terminal {
    pub term: String,
    pub columns: u32,
    pub rows: u32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Phase {
    Version,
    /// Keyed, waiting for the `ssh-userauth` service request.
    Service,
    Auth,
    Connected,
    Closed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Stage {
    /// Our KEXINIT sent, the client's awaited.
    KexInit,
    /// Both KEXINITs exchanged; the method's first client message awaited.
    Method,
    /// Group exchange: the group sent, the client's value awaited.
    GexInit,
    /// Our NEWKEYS sent, the client's awaited.
    NewKeys,
}

/// One key exchange in progress.
struct Exchange {
    server_kexinit: Vec<u8>,
    client_kexinit: Vec<u8>,
    algorithms: Algorithms,
    /// Which of `host_keys` signs.
    host_key: usize,
    gex: Option<GroupExchange>,
    /// The client guessed wrong; drop its next packet.
    skip_guess: bool,
    stage: Stage,
    receive_keys: Option<Keys>,
}

/// The session channel.
struct Channel {
    remote_id: u32,
    remote_window: u64,
    remote_max_packet: u32,
    /// What the client may still send before a WINDOW_ADJUST.
    local_window: u32,
    request: Option<SessionRequest>,
    terminal: Option<Terminal>,
    environment: Vec<(String, String)>,
    stdin: Vec<u8>,
    stdin_closed: bool,
    /// What the caller wrote and the window has not let out yet:
    /// `(stream, bytes)`, stream 0 for standard output and 1 for error.
    pending: VecDeque<(u32, Vec<u8>)>,
    exit_status: Option<u32>,
    close_sent: bool,
    close_received: bool,
}

pub struct Server {
    config: ServerConfig,
    /// Each host key's public half and blob, in `config.host_keys` order.
    host_publics: Vec<(PublicKey, Vec<u8>)>,
    fill: RandomSource,
    sealer: Sealer,
    opener: Opener,
    outgoing: Vec<u8>,
    /// Payloads written during a key exchange, sent after our NEWKEYS.
    held: Vec<Vec<u8>>,
    phase: Phase,
    client_version: Vec<u8>,
    session_id: Option<Vec<u8>>,
    strict: bool,
    ext_info: bool,
    first_kex: bool,
    exchange: Option<Exchange>,
    algorithms: Algorithms,
    key_exchanges: u32,
    auth_attempts: u32,
    banner_sent: bool,
    user: Option<String>,
    auth_method: Option<String>,
    channel: Option<Channel>,
    disconnect: Option<(u32, String)>,
}

impl Server {
    /// A server for one connection. Randomness comes from the operating
    /// system.
    pub fn new(config: ServerConfig) -> Result<Server, String> {
        Server::with_random(config, Box::new(|buf: &mut [u8]| crate::random::fill(buf)))
    }

    /// The same, drawing every random byte - padding, cookie, ephemeral
    /// keys, the ML-KEM encapsulation - from `fill`. With the signatures
    /// deterministic as well (Ed25519, RFC 6979 ECDSA and DSA, RSA), a
    /// fixed `fill` makes the server's side of a session a function of
    /// what the client sent: what lets a recorded session be replayed.
    pub fn with_random(config: ServerConfig, fill: RandomSource) -> Result<Server, String> {
        if config.host_keys.is_empty() {
            return Err("SSH: a server needs at least one host key.".to_string());
        }
        let host_publics = config.host_keys.iter().map(|key| {
            let public = key.public();
            let blob = public.to_blob();
            (public, blob)
        }).collect();
        let mut server = Server {
            config,
            host_publics,
            fill,
            sealer: Sealer::new()?,
            opener: Opener::new()?,
            outgoing: Vec::new(),
            held: Vec::new(),
            phase: Phase::Version,
            client_version: Vec::new(),
            session_id: None,
            strict: false,
            ext_info: false,
            first_kex: true,
            exchange: None,
            algorithms: Algorithms::default(),
            key_exchanges: 0,
            auth_attempts: 0,
            banner_sent: false,
            user: None,
            auth_method: None,
            channel: None,
            disconnect: None,
        };
        if server.offered_host_key_algorithms().is_empty() {
            return Err(format!(
                "SSH: none of the host keys signs under any of {}.",
                server.config.host_key_algorithms.join(", ")));
        }
        server.outgoing.extend_from_slice(server.config.version.as_bytes());
        server.outgoing.extend_from_slice(b"\r\n");
        server.send_kexinit()?;
        Ok(server)
    }

    // ------------------------------------------------------- the caller ---

    pub fn push_incoming(&mut self, bytes: &[u8]) {
        self.opener.push(bytes);
    }

    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outgoing)
    }

    /// The user who authenticated, once one has.
    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    /// How the user authenticated: `password`, or `publickey` and the
    /// signature algorithm.
    pub fn auth_method(&self) -> Option<&str> {
        self.auth_method.as_deref()
    }

    /// What the client asked the session to do, once it has.
    pub fn request(&self) -> Option<&SessionRequest> {
        self.channel.as_ref().and_then(|channel| channel.request.as_ref())
    }

    /// The terminal the client asked for, if it did, at its latest size.
    pub fn terminal(&self) -> Option<&Terminal> {
        self.channel.as_ref().and_then(|channel| channel.terminal.as_ref())
    }

    /// The `env` requests received, in order.
    pub fn environment(&self) -> &[(String, String)] {
        self.channel.as_ref().map_or(&[], |channel| channel.environment.as_slice())
    }

    /// Standard input received so far. Taking it re-opens the client's
    /// window, which is what lets the client send more.
    pub fn take_stdin(&mut self) -> Result<Vec<u8>, String> {
        let Some(channel) = self.channel.as_mut() else {
            return Ok(Vec::new());
        };
        let data = std::mem::take(&mut channel.stdin);
        if channel.local_window < WINDOW / 2 && !channel.close_received {
            let grant = WINDOW - channel.local_window;
            channel.local_window = WINDOW;
            let mut writer = Writer::new();
            writer.byte(msg::CHANNEL_WINDOW_ADJUST).uint32(channel.remote_id).uint32(grant);
            self.send(writer.finish())?;
        }
        Ok(data)
    }

    /// Whether the client has sent EOF (or closed the channel): standard
    /// input is complete once taken.
    pub fn stdin_closed(&self) -> bool {
        self.channel.as_ref().is_some_and(|c| c.stdin_closed || c.close_received)
    }

    /// Standard output for the client, sent as its window allows.
    pub fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.queue(0, data)
    }

    /// Standard error, as extended data of type 1.
    pub fn write_stderr(&mut self, data: &[u8]) -> Result<(), String> {
        self.queue(1, data)
    }

    /// End the session once what was written has gone: `exit-status`,
    /// EOF and CLOSE.
    pub fn finish(&mut self, exit_status: u32) -> Result<(), String> {
        let channel = self.channel.as_mut().ok_or("SSH: no session to finish.")?;
        if channel.exit_status.is_none() {
            channel.exit_status = Some(exit_status);
        }
        self.flush_channel()
    }

    /// Start a key re-exchange.
    pub fn rekey(&mut self) -> Result<(), String> {
        if self.first_kex || self.exchange.is_some() {
            return Err("SSH: a key exchange is already in progress.".to_string());
        }
        self.send_kexinit()
    }

    /// Whether the session is over: both CLOSEs crossed, or the
    /// connection ended.
    pub fn closed(&self) -> bool {
        self.phase == Phase::Closed
            || self.channel.as_ref().is_some_and(|c| c.close_sent && c.close_received)
    }

    /// The client's DISCONNECT, if it sent one: reason code and text.
    pub fn disconnect_reason(&self) -> Option<(u32, &str)> {
        self.disconnect.as_ref().map(|(code, text)| (*code, text.as_str()))
    }

    pub fn algorithms(&self) -> &Algorithms {
        &self.algorithms
    }

    pub fn client_version(&self) -> &[u8] {
        &self.client_version
    }

    pub fn strict_kex(&self) -> bool {
        self.strict
    }

    /// Key exchanges completed: 1 for the initial one, and one more for
    /// each re-exchange, whichever side started it.
    pub fn key_exchanges(&self) -> u32 {
        self.key_exchanges
    }

    /// Handle everything received so far. An error has already been
    /// reported to the client with a DISCONNECT, and ends the connection.
    pub fn process(&mut self) -> Result<(), String> {
        let result = self.process_inner();
        if let Err(error) = &result {
            if self.phase != Phase::Closed {
                self.phase = Phase::Closed;
                let mut writer = Writer::new();
                writer.byte(msg::DISCONNECT).uint32(reason::PROTOCOL_ERROR)
                    .string(error.as_bytes()).string(b"");
                // Best effort: the error is what the caller needs.
                let _ = self.send_now(&writer.finish());
            }
        }
        result
    }

    fn process_inner(&mut self) -> Result<(), String> {
        if self.phase == Phase::Version {
            let Some(line) = self.opener.take_line() else {
                if self.opener.buffered().len() > 255 {
                    return Err("SSH: no version line in the first 255 bytes.".to_string());
                }
                return Ok(());
            };
            // RFC 4253 4.2: the server may send lines before its version;
            // the client may not.
            let end = line.len() - if line.ends_with(b"\r\n") { 2 } else { 1 };
            let version = &line[..end];
            if !version.starts_with(b"SSH-2.0-") {
                return Err(format!("SSH: the client sent {:?}, not an SSH 2 version line.",
                                   String::from_utf8_lossy(version)));
            }
            self.client_version = version.to_vec();
            self.phase = Phase::Service;
        }
        while self.phase != Phase::Closed {
            let Some(payload) = self.opener.open()? else { break };
            self.handle(&payload)?;
        }
        Ok(())
    }

    // -------------------------------------------------------- sending ---

    fn send_now(&mut self, payload: &[u8]) -> Result<(), String> {
        let packet = self.sealer.seal(payload, &mut *self.fill)?;
        self.outgoing.extend_from_slice(&packet);
        Ok(())
    }

    /// Send, or hold until our NEWKEYS if a key exchange is under way.
    fn send(&mut self, payload: Vec<u8>) -> Result<(), String> {
        if self.exchange.as_ref().is_some_and(|e| e.stage != Stage::NewKeys) {
            self.held.push(payload);
            Ok(())
        } else {
            self.send_now(&payload)
        }
    }

    fn offered_host_key_algorithms(&self) -> Vec<&'static str> {
        self.config.host_key_algorithms.iter().copied().filter(|name| {
            self.host_publics.iter().any(|(public, _)| {
                signature::algorithms_for(public).contains(name)
            })
        }).collect()
    }

    fn send_kexinit(&mut self) -> Result<(), String> {
        let mut cookie = [0u8; 16];
        (self.fill)(&mut cookie)?;
        let mut kex_names: Vec<&str> = self.config.kex.clone();
        if self.first_kex {
            kex_names.push(STRICT_SERVER);
        }
        let host_keys = self.offered_host_key_algorithms();
        let payload = negotiate::encode(&cookie, &kex_names, &host_keys,
                                        &self.config.ciphers, &self.config.macs)?;
        self.send_now(&payload)?;
        self.exchange = Some(Exchange {
            server_kexinit: payload,
            client_kexinit: Vec::new(),
            algorithms: Algorithms::default(),
            host_key: 0,
            gex: None,
            skip_guess: false,
            stage: Stage::KexInit,
            receive_keys: None,
        });
        Ok(())
    }

    // ------------------------------------------------------- receiving ---

    fn handle(&mut self, payload: &[u8]) -> Result<(), String> {
        let kind = *payload.first().ok_or("SSH: an empty packet.")?;
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
        // Once the client's KEXINIT is in, it may send only key exchange
        // and transport messages until its NEWKEYS.
        let client_in_kex = self.exchange.as_ref().is_some_and(|e| e.stage != Stage::KexInit);
        if client_in_kex && kind > 49 {
            return Err(format!("SSH: message {kind} in the middle of a key exchange."));
        }
        match kind {
            msg::DISCONNECT => {
                let mut reader = Reader::new(&payload[1..]);
                let code = reader.uint32().unwrap_or(0);
                let text = String::from_utf8_lossy(reader.string().unwrap_or(b"")).into_owned();
                self.disconnect = Some((code, text));
                self.phase = Phase::Closed;
                return Ok(());
            }
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => return Ok(()),
            msg::KEXINIT => return self.on_kexinit(payload),
            msg::NEWKEYS => return self.on_newkeys(),
            msg::KEX_30..=49 => return self.on_kex_message(kind, payload),
            // The client's own EXT_INFO answers an `ext-info-s` this
            // server does not send.
            msg::EXT_INFO => return Ok(()),
            _ => {}
        }
        if self.first_kex {
            return Err(format!("SSH: message {kind} before the key exchange finished."));
        }
        match (self.phase, kind) {
            (Phase::Service, msg::SERVICE_REQUEST) => {
                let mut reader = Reader::new(&payload[1..]);
                let service = reader.string()?;
                if service != b"ssh-userauth" {
                    return Err(format!("SSH: the client asked for the service {:?}, and \
                                        only ssh-userauth is offered.",
                                       String::from_utf8_lossy(service)));
                }
                let mut writer = Writer::new();
                writer.byte(msg::SERVICE_ACCEPT).string(b"ssh-userauth");
                self.send(writer.finish())?;
                self.phase = Phase::Auth;
                Ok(())
            }
            (Phase::Auth, msg::USERAUTH_REQUEST) => self.on_userauth(payload),
            // RFC 4252 5.1: requests after success are ignored.
            (Phase::Connected, msg::USERAUTH_REQUEST) => Ok(()),
            (Phase::Connected, msg::GLOBAL_REQUEST) => {
                let mut reader = Reader::new(&payload[1..]);
                let _name = reader.string()?;
                if reader.boolean()? {
                    self.send(vec![msg::REQUEST_FAILURE])?;
                }
                Ok(())
            }
            (Phase::Connected, msg::CHANNEL_OPEN..=msg::CHANNEL_FAILURE) =>
                self.on_channel(kind, payload),
            (Phase::Connected, _) => {
                // RFC 4253 11.4: an unknown message gets UNIMPLEMENTED,
                // with its sequence number.
                let mut writer = Writer::new();
                writer.byte(msg::UNIMPLEMENTED).uint32(self.opener.sequence.wrapping_sub(1));
                self.send(writer.finish())
            }
            (phase, kind) => Err(format!("SSH: message {kind} was not expected now \
                                          ({phase:?}).")),
        }
    }

    // ---------------------------------------------------- key exchange ---

    fn on_kexinit(&mut self, payload: &[u8]) -> Result<(), String> {
        if self.exchange.is_none() {
            // The client starts a re-exchange; answer with ours.
            self.send_kexinit()?;
        }
        let exchange = self.exchange.as_ref().ok_or("state")?;
        if exchange.stage != Stage::KexInit {
            return Err("SSH: a second KEXINIT in one key exchange.".to_string());
        }
        let theirs = KexInit::parse(payload)?;
        if self.first_kex {
            self.strict = theirs.kex.contains(&STRICT_CLIENT);
            if self.strict && self.opener.sequence != 1 {
                return Err("SSH: strict key exchange, and KEXINIT was not the \
                            client's first packet.".to_string());
            }
            self.ext_info = theirs.kex.contains(&EXT_INFO_CLIENT);
        }
        let algorithms = negotiate::negotiate(&theirs, &KexInit::parse(&exchange.server_kexinit)?)?;
        let skip_guess = theirs.guess_is_wrong(&algorithms);
        let host_key = self.host_publics.iter().position(|(public, _)| {
            signature::algorithms_for(public).contains(&algorithms.host_key.as_str())
        }).ok_or("state: a host key algorithm offered with no key for it")?;

        let exchange = self.exchange.as_mut().ok_or("state")?;
        exchange.client_kexinit = payload.to_vec();
        exchange.algorithms = algorithms;
        exchange.host_key = host_key;
        exchange.skip_guess = skip_guess;
        exchange.stage = Stage::Method;
        Ok(())
    }

    fn on_kex_message(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        let exchange = self.exchange.as_mut().ok_or("SSH: key exchange message \
                                                       outside a key exchange.")?;
        let method = kex::lookup(&exchange.algorithms.kex)?.method;
        let is_gex = matches!(method, Method::DhGroupExchange { .. });
        let mut reader = Reader::new(&payload[1..]);
        match (exchange.stage, kind) {
            (Stage::Method, msg::KEX_DH_GEX_REQUEST) if is_gex => {
                let min = reader.uint32()?;
                let preferred = reader.uint32()?;
                let max = reader.uint32()?;
                reader.finish("a group exchange request")?;
                if !(min <= preferred && preferred <= max) {
                    return Err(format!("SSH: a group exchange request of {min} <= \
                                        {preferred} <= {max} is out of order."));
                }
                let sizes = &self.config.group_exchange_sizes;
                let bits = choose_group(sizes, min, preferred, max).ok_or_else(|| format!(
                    "SSH: no group between {min} and {max} bits; this server has {}.",
                    sizes.iter().map(|bits| bits.to_string()).collect::<Vec<_>>().join(", ")))?;
                let group = kex::modp(bits)?;
                let mut writer = Writer::new();
                writer.byte(msg::KEX_31)
                    .mpint(&group.p().to_bytes_be()).mpint(&group.g().to_bytes_be());
                exchange.gex = Some(GroupExchange { min, preferred, max, group });
                exchange.stage = Stage::GexInit;
                self.send_now(&writer.finish())
            }
            (Stage::Method, msg::KEX_30) if !is_gex => {
                let value = if method.values_are_mpints() { reader.mpint()? } else { reader.string()? };
                reader.finish("the key exchange's first message")?;
                self.respond(method, value, msg::KEX_31)
            }
            (Stage::GexInit, msg::KEX_DH_GEX_INIT) => {
                let value = reader.mpint()?;
                reader.finish("a group exchange's value")?;
                self.respond(method, value, msg::KEX_DH_GEX_REPLY)
            }
            (stage, kind) => Err(format!("SSH: key exchange message {kind} out of order \
                                          ({stage:?}).")),
        }
    }

    /// The reply to the client's value: our value, the host key, and its
    /// signature over `H`; then NEWKEYS, and our side's new keys.
    fn respond(&mut self, method: Method, client_value: &[u8], reply_kind: u8)
               -> Result<(), String> {
        let exchange = self.exchange.as_mut().ok_or("state")?;
        let (_, host_blob) = &self.host_publics[exchange.host_key];
        let transcript = Transcript {
            client_version: &self.client_version,
            server_version: self.config.version.as_bytes(),
            client_kexinit: &exchange.client_kexinit,
            server_kexinit: &exchange.server_kexinit,
            host_key: host_blob,
        };
        let (value, shared, h) = kex::server_respond(method, exchange.gex.take(), &transcript,
                                                     client_value, &mut *self.fill)?;
        let host_signature = signature::sign(&self.config.host_keys[exchange.host_key], &h,
                                             Some(&exchange.algorithms.host_key))?;
        let mut writer = Writer::new();
        writer.byte(reply_kind).string(host_blob);
        method.write_value(&mut writer, &value);
        writer.string(&host_signature);

        let session_id = self.session_id.get_or_insert_with(|| h.clone());
        let (send_keys, receive_keys) = negotiate::derive_keys(
            method.hash_name(), &shared, &h, session_id, &exchange.algorithms, Side::Server)?;
        exchange.receive_keys = Some(receive_keys);
        exchange.stage = Stage::NewKeys;

        self.send_now(&writer.finish())?;
        self.send_now(&[msg::NEWKEYS])?;
        self.sealer.rekey(send_keys, self.strict);
        if self.first_kex && self.ext_info {
            self.send_ext_info()?;
        }
        for payload in std::mem::take(&mut self.held) {
            self.send_now(&payload)?;
        }
        Ok(())
    }

    /// RFC 8308 `server-sig-algs`: what user keys may sign with.
    fn send_ext_info(&mut self) -> Result<(), String> {
        let names = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,\
                     ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss";
        let mut writer = Writer::new();
        writer.byte(msg::EXT_INFO).uint32(1)
            .string(b"server-sig-algs").string(names.as_bytes());
        self.send_now(&writer.finish())
    }

    fn on_newkeys(&mut self) -> Result<(), String> {
        let exchange = self.exchange.take().filter(|e| e.stage == Stage::NewKeys)
            .ok_or("SSH: NEWKEYS out of order.")?;
        self.opener.rekey(exchange.receive_keys.ok_or("state")?, self.strict);
        self.algorithms = exchange.algorithms;
        self.first_kex = false;
        self.key_exchanges += 1;
        self.flush_channel()
    }

    // -------------------------------------------------- authentication ---

    fn on_userauth(&mut self, payload: &[u8]) -> Result<(), String> {
        self.auth_attempts += 1;
        if self.auth_attempts > self.config.max_auth_attempts {
            let mut writer = Writer::new();
            writer.byte(msg::DISCONNECT).uint32(reason::NO_MORE_AUTH_METHODS_AVAILABLE)
                .string(b"too many authentication attempts").string(b"");
            self.send_now(&writer.finish())?;
            self.phase = Phase::Closed;
            return Err("SSH: too many authentication attempts.".to_string());
        }
        if !self.banner_sent {
            self.banner_sent = true;
            if let Some(banner) = &self.config.banner {
                let mut writer = Writer::new();
                writer.byte(msg::USERAUTH_BANNER).string(banner.as_bytes()).string(b"");
                self.send(writer.finish())?;
            }
        }
        let mut reader = Reader::new(&payload[1..]);
        let user = reader.text()?;
        let service = reader.string()?;
        let method = reader.string()?;
        if service != b"ssh-connection" {
            return self.auth_failure();
        }
        let accepted = match method {
            b"publickey" => {
                let signed = reader.boolean()?;
                let algorithm = reader.text()?;
                let blob = reader.string()?;
                let Ok(key) = PublicKey::from_blob(blob) else {
                    return self.auth_failure();
                };
                if !self.key_authorized(user, &key)
                    || !signature::algorithms_for(&key).contains(&algorithm) {
                    return self.auth_failure();
                }
                if !signed {
                    // A query: this key would do. Proof comes next.
                    let mut writer = Writer::new();
                    writer.byte(msg::USERAUTH_PK_OK).string(algorithm.as_bytes()).string(blob);
                    return self.send(writer.finish());
                }
                let request_end = payload.len() - reader.rest().len();
                let mut check = Reader::new(&payload[request_end..]);
                let signature_blob = check.string()?;
                check.finish("a public key authentication request")?;
                let session_id = self.session_id.as_ref().ok_or("state")?;
                if !request_signed(session_id, &payload[..request_end], &key, algorithm,
                                   signature_blob) {
                    return self.auth_failure();
                }
                self.auth_method = Some(format!("publickey {algorithm}"));
                true
            }
            b"password" => {
                let change = reader.boolean()?;
                let password = reader.string()?;
                let accepted = !change && self.password_matches(user, password)?;
                if accepted {
                    self.auth_method = Some("password".to_string());
                }
                accepted
            }
            _ => false,
        };
        if !accepted {
            return self.auth_failure();
        }
        self.user = Some(user.to_string());
        self.phase = Phase::Connected;
        self.send(vec![msg::USERAUTH_SUCCESS])
    }

    fn key_authorized(&self, user: &str, key: &PublicKey) -> bool {
        self.config.authorized.iter().any(|entry| entry.user == user
            && matches!(&entry.credential, Credential::PublicKey(known) if known == key))
    }

    /// Every password for `user` is compared, each through SHA-256 and a
    /// comparison that does not stop at the first difference, so the
    /// time taken says neither where a guess went wrong nor how long the
    /// password is.
    fn password_matches(&self, user: &str, offered: &[u8]) -> Result<bool, String> {
        let digest = |bytes: &[u8]| -> Result<Vec<u8>, String> {
            let mut hash = AnyHash::new("sha256")?;
            hash.update(bytes);
            Ok(hash.digest())
        };
        let offered = digest(offered)?;
        let mut found = false;
        for entry in &self.config.authorized {
            if let Credential::Password(known) = &entry.credential {
                let known = digest(known.as_bytes())?;
                let differ = known.iter().zip(&offered).fold(0u8, |acc, (a, b)| acc | (a ^ b));
                found |= differ == 0 && entry.user == user;
            }
        }
        Ok(found)
    }

    fn auth_failure(&mut self) -> Result<(), String> {
        let mut methods: Vec<&str> = Vec::new();
        for entry in &self.config.authorized {
            let name = match entry.credential {
                Credential::PublicKey(_) => "publickey",
                Credential::Password(_) => "password",
            };
            if !methods.contains(&name) {
                methods.push(name);
            }
        }
        let mut writer = Writer::new();
        writer.byte(msg::USERAUTH_FAILURE);
        writer.name_list(&methods)?.boolean(false);
        self.send(writer.finish())
    }

    // ------------------------------------------------------- the channel ---

    fn on_channel(&mut self, kind: u8, payload: &[u8]) -> Result<(), String> {
        let mut reader = Reader::new(&payload[1..]);
        if kind == msg::CHANNEL_OPEN {
            let channel_type = reader.string()?;
            let sender = reader.uint32()?;
            let window = reader.uint32()?;
            let max_packet = reader.uint32()?;
            let refusal = if channel_type != b"session" {
                Some((open_failure::UNKNOWN_CHANNEL_TYPE, "only session channels"))
            } else if self.channel.is_some() {
                Some((open_failure::RESOURCE_SHORTAGE, "one session per connection"))
            } else {
                None
            };
            let mut writer = Writer::new();
            if let Some((code, text)) = refusal {
                writer.byte(msg::CHANNEL_OPEN_FAILURE).uint32(sender).uint32(code)
                    .string(text.as_bytes()).string(b"");
            } else {
                self.channel = Some(Channel {
                    remote_id: sender,
                    remote_window: u64::from(window),
                    remote_max_packet: max_packet.max(1),
                    local_window: WINDOW,
                    request: None,
                    terminal: None,
                    environment: Vec::new(),
                    stdin: Vec::new(),
                    stdin_closed: false,
                    pending: VecDeque::new(),
                    exit_status: None,
                    close_sent: false,
                    close_received: false,
                });
                writer.byte(msg::CHANNEL_OPEN_CONFIRMATION).uint32(sender).uint32(CHANNEL_ID)
                    .uint32(WINDOW).uint32(MAX_PACKET);
            }
            return self.send(writer.finish());
        }
        let recipient = reader.uint32()?;
        let channel = self.channel.as_mut().filter(|_| recipient == CHANNEL_ID)
            .ok_or_else(|| format!("SSH: message {kind} for channel {recipient}, which \
                                    is not open."))?;
        match kind {
            msg::CHANNEL_DATA | msg::CHANNEL_EXTENDED_DATA => {
                if kind == msg::CHANNEL_EXTENDED_DATA {
                    let _stream = reader.uint32()?;
                }
                let data = reader.string()?;
                if data.len() > channel.local_window as usize {
                    return Err(format!("SSH: {} bytes of data with {} left in the window.",
                                       data.len(), channel.local_window));
                }
                channel.local_window -= data.len() as u32;
                // Extended data from a client means nothing in a session;
                // RFC 4254 5.2 has it only server to client. Counted, dropped.
                if kind == msg::CHANNEL_DATA && !channel.stdin_closed {
                    channel.stdin.extend_from_slice(data);
                }
                Ok(())
            }
            msg::CHANNEL_WINDOW_ADJUST => {
                let grant = u64::from(reader.uint32()?);
                channel.remote_window = (channel.remote_window + grant).min(u64::from(u32::MAX));
                self.flush_channel()
            }
            msg::CHANNEL_EOF => {
                channel.stdin_closed = true;
                Ok(())
            }
            msg::CHANNEL_CLOSE => {
                channel.close_received = true;
                channel.stdin_closed = true;
                if !channel.close_sent {
                    channel.close_sent = true;
                    channel.pending.clear();
                    let mut writer = Writer::new();
                    writer.byte(msg::CHANNEL_CLOSE).uint32(channel.remote_id);
                    return self.send(writer.finish());
                }
                Ok(())
            }
            msg::CHANNEL_REQUEST => {
                let name = reader.string()?;
                let want_reply = reader.boolean()?;
                let before_command = channel.request.is_none();
                let accepted = match name {
                    b"exec" => match core::str::from_utf8(reader.string()?) {
                        Ok(command) if before_command => {
                            channel.request = Some(SessionRequest::Exec(command.to_string()));
                            true
                        }
                        _ => false,
                    },
                    b"shell" if before_command => {
                        channel.request = Some(SessionRequest::Shell);
                        true
                    }
                    // RFC 4254 6.2. Recorded for the caller, who decides
                    // what a terminal means for the command; no pty is
                    // made here.
                    b"pty-req" if before_command => {
                        let term = String::from_utf8_lossy(reader.string()?).into_owned();
                        let columns = reader.uint32()?;
                        let rows = reader.uint32()?;
                        channel.terminal = Some(Terminal { term, columns, rows });
                        true
                    }
                    b"window-change" => {
                        let columns = reader.uint32()?;
                        let rows = reader.uint32()?;
                        if let Some(terminal) = channel.terminal.as_mut() {
                            terminal.columns = columns;
                            terminal.rows = rows;
                        }
                        channel.terminal.is_some()
                    }
                    // RFC 4254 6.4, recorded for the caller to pass on or
                    // ignore - which variables a command may be given is
                    // the caller's policy, as `AcceptEnv` is sshd's.
                    b"env" if before_command => {
                        let variable = String::from_utf8_lossy(reader.string()?).into_owned();
                        let value = String::from_utf8_lossy(reader.string()?).into_owned();
                        channel.environment.push((variable, value));
                        true
                    }
                    // x11-req, subsystem, signal, auth-agent-req and the
                    // rest: not offered.
                    _ => false,
                };
                if want_reply {
                    let mut writer = Writer::new();
                    writer.byte(if accepted { msg::CHANNEL_SUCCESS } else { msg::CHANNEL_FAILURE })
                        .uint32(channel.remote_id);
                    return self.send(writer.finish());
                }
                Ok(())
            }
            msg::CHANNEL_SUCCESS | msg::CHANNEL_FAILURE => Ok(()),
            other => Err(format!("SSH: unexpected channel message {other}.")),
        }
    }

    fn queue(&mut self, stream: u32, data: &[u8]) -> Result<(), String> {
        let channel = self.channel.as_mut().filter(|c| c.request.is_some())
            .ok_or("SSH: no session to write to.")?;
        if channel.exit_status.is_some() || channel.close_sent {
            return Err("SSH: the session is finished.".to_string());
        }
        if !data.is_empty() {
            channel.pending.push_back((stream, data.to_vec()));
        }
        self.flush_channel()
    }

    /// Send what the window allows; once everything has gone and the
    /// caller has finished, the exit status, EOF and CLOSE.
    fn flush_channel(&mut self) -> Result<(), String> {
        let Some(channel) = self.channel.as_mut() else {
            return Ok(());
        };
        let mut packets = Vec::new();
        while channel.remote_window > 0 {
            let Some((stream, data)) = channel.pending.front_mut() else { break };
            let room = (channel.remote_window as usize)
                .min(channel.remote_max_packet as usize).min(data.len());
            let mut writer = Writer::new();
            if *stream == 0 {
                writer.byte(msg::CHANNEL_DATA).uint32(channel.remote_id);
            } else {
                writer.byte(msg::CHANNEL_EXTENDED_DATA).uint32(channel.remote_id)
                    .uint32(*stream);
            }
            writer.string(&data[..room]);
            packets.push(writer.finish());
            channel.remote_window -= room as u64;
            if room == data.len() {
                channel.pending.pop_front();
            } else {
                data.drain(..room);
            }
        }
        if let Some(status) = channel.exit_status {
            if channel.pending.is_empty() && !channel.close_sent {
                channel.close_sent = true;
                let mut writer = Writer::new();
                writer.byte(msg::CHANNEL_REQUEST).uint32(channel.remote_id)
                    .string(b"exit-status").boolean(false).uint32(status);
                packets.push(writer.finish());
                let mut writer = Writer::new();
                writer.byte(msg::CHANNEL_EOF).uint32(channel.remote_id);
                packets.push(writer.finish());
                let mut writer = Writer::new();
                writer.byte(msg::CHANNEL_CLOSE).uint32(channel.remote_id);
                packets.push(writer.finish());
            }
        }
        for packet in packets {
            self.send(packet)?;
        }
        Ok(())
    }
}

/// RFC 4252 7: whether `signature` is `key`'s, under `algorithm`, over
/// the session identifier and the request as received (`request` is the
/// payload up to the signature, message number included).
fn request_signed(session_id: &[u8], request: &[u8], key: &PublicKey, algorithm: &str,
                  signature: &[u8]) -> bool {
    let mut data = Writer::new();
    data.string(session_id).raw(request);
    matches!(signature::verify(key, &data.finish(), signature),
             Ok(Some(name)) if name == algorithm)
}

/// The MODP group size for a group exchange request: the largest no
/// bigger than `preferred`, or failing that the smallest that fits -
/// within `min` and `max` either way, as RFC 4419 3 asks.
fn choose_group(sizes: &[usize], min: u32, preferred: u32, max: u32) -> Option<usize> {
    let fits = |bits: &&usize| (min as usize..=max as usize).contains(*bits);
    sizes.iter().filter(fits).filter(|&&bits| bits <= preferred as usize).max()
        .or_else(|| sizes.iter().filter(fits).min()).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_choose_group() {
        let all = &MODP_SIZES;
        assert_eq!(choose_group(all, 2048, 8192, 8192), Some(8192));
        assert_eq!(choose_group(all, 2048, 7680, 8192), Some(6144));
        assert_eq!(choose_group(all, 2048, 3072, 8192), Some(3072));
        // Nothing at or below the preference: the smallest that fits.
        assert_eq!(choose_group(all, 1000, 1000, 2048), Some(1024));
        assert_eq!(choose_group(all, 2049, 2049, 3000), None);
        assert_eq!(choose_group(&[2048, 4096], 2048, 8192, 8192), Some(4096));
    }

    /// A signature under one RSA hash, offered in a request naming
    /// another, is refused - though it verifies for the key.
    #[test]
    fn test_the_signature_must_be_under_the_named_algorithm() {
        let key = PrivateKey::generate("rsa", Some(1024)).unwrap();
        let public = key.public();
        let session_id = [9u8; 32];
        let request = b"\x32 the request as received";
        let mut data = Writer::new();
        data.string(&session_id).raw(request);
        let data = data.finish();
        for (signed_as, named) in [("ssh-rsa", "rsa-sha2-512"), ("rsa-sha2-256", "rsa-sha2-512"),
                                   ("rsa-sha2-512", "ssh-rsa")] {
            let signature = signature::sign(&key, &data, Some(signed_as)).unwrap();
            assert!(request_signed(&session_id, request, &public, signed_as, &signature));
            assert!(!request_signed(&session_id, request, &public, named, &signature),
                    "{signed_as} offered as {named}");
        }
        // And the session identifier is part of what is signed.
        let signature = signature::sign(&key, &data, Some("rsa-sha2-512")).unwrap();
        assert!(!request_signed(&[8u8; 32], request, &public, "rsa-sha2-512", &signature));
    }
}
