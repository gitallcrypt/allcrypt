//! WireGuard's cryptography, built from this library's primitives: keys
//! as `wg` writes them, the handshake, cookie replies and transport
//! messages, with the state between steps kept in a file.
//!
//!     cargo run --release --example wireguard -- genkey
//!     cargo run --release --example wireguard -- pubkey < private
//!     cargo run --release --example wireguard -- genpsk
//!     cargo run --release --example wireguard -- initiate --state FILE KEYS [--index N]
//!     cargo run --release --example wireguard -- respond MESSAGE --state FILE KEYS [--index N]
//!     cargo run --release --example wireguard -- complete MESSAGE --state FILE
//!     cargo run --release --example wireguard -- seal HEX --state FILE
//!     cargo run --release --example wireguard -- open MESSAGE --state FILE
//!     cargo run --release --example wireguard -- cookie-reply MESSAGE --private KEY
//!             --secret HEX --source HEX
//!     cargo run --release --example wireguard -- cookie MESSAGE --state FILE
//!     cargo run --release --example wireguard -- check-mac2 MESSAGE --secret HEX --source HEX
//!
//! KEYS is `--private KEY --peer KEY [--psk KEY]`, base64 as `wg` writes
//! them, or `--config FILE`, a `wg` configuration whose `[Interface]`
//! has the private key and whose first `[Peer]` has the peer's public key
//! and any preshared key. A MESSAGE is hex. `initiate` and `respond` write
//! the handshake state to FILE; `complete` and `respond` leave a session
//! there, which `seal` and `open` use and advance. `cookie` takes a
//! cookie reply into an initiator's state, and its next `initiate` carries
//! MAC2. `--ephemeral HEX` and `--timestamp HEX` fix what is otherwise
//! random or the clock. `seal` pads to 16 bytes as WireGuard pads a
//! packet; `open` returns the padding with the packet.
//!
//! What has checked it is in `examples/products/README.md`.

mod noise;

#[path = "../shared/base64.rs"]
mod base64;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use noise::{Key, Pending, ReplayWindow, Session};

// ----------------------------------------------------------------- arguments --

fn positional(args: &[String]) -> Vec<&String> {
    let mut out = Vec::new();
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
        } else if arg.starts_with("--") {
            skip = true;
        } else {
            out.push(arg);
        }
    }
    out
}

fn value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if !text.len().is_multiple_of(2) || !text.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("{text}: not hex."));
    }
    Ok((0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex")).collect())
}

fn fixed<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], String> {
    let len = bytes.len();
    bytes.try_into().map_err(|_| format!("{what} is {N} bytes, not {len}."))
}

/// A key as `wg` writes it: 32 bytes in base64.
fn key_from_base64(text: &str, what: &str) -> Result<Key, String> {
    fixed(base64::decode(text.trim()).ok_or_else(|| format!("{what} is not base64."))?, what)
}

struct Keys {
    private: Key,
    peer: Key,
    psk: Key,
}

/// The `[Interface]` private key and the first `[Peer]`'s public and
/// preshared keys of a `wg` configuration.
fn read_config(path: &str) -> Result<Keys, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let (mut section, mut private, mut peer, mut psk) = (String::new(), None, None, None);
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            section = line.to_ascii_lowercase();
            continue;
        }
        let Some((name, val)) = line.split_once('=') else { continue };
        let (name, val) = (name.trim().to_ascii_lowercase(), val.trim());
        match (section.as_str(), name.as_str()) {
            ("[interface]", "privatekey") => private = Some(key_from_base64(val, "PrivateKey")?),
            ("[peer]", "publickey") if peer.is_none() =>
                peer = Some(key_from_base64(val, "PublicKey")?),
            ("[peer]", "presharedkey") if psk.is_none() =>
                psk = Some(key_from_base64(val, "PresharedKey")?),
            _ => {}
        }
    }
    Ok(Keys { private: private.ok_or(format!("{path}: no [Interface] PrivateKey."))?,
              peer: peer.ok_or(format!("{path}: no [Peer] PublicKey."))?,
              psk: psk.unwrap_or([0; 32]) })
}

fn keys(args: &[String]) -> Result<Keys, String> {
    if let Some(path) = value(args, "--config") {
        return read_config(path);
    }
    Ok(Keys {
        private: key_from_base64(value(args, "--private").ok_or("--private or --config")?,
                                 "The private key")?,
        peer: key_from_base64(value(args, "--peer").ok_or("--peer or --config")?,
                              "The peer's public key")?,
        psk: match value(args, "--psk") {
            Some(text) => key_from_base64(text, "The preshared key")?,
            None => [0; 32],
        },
    })
}

// --------------------------------------------------------------------- state --

/// Everything between steps, as `name = hex` lines.
#[derive(Default)]
struct State {
    fields: Vec<(String, String)>,
}

impl State {
    fn read(path: &str) -> Result<State, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Ok(State { fields: text.lines().filter_map(|l| l.split_once(" = "))
            .map(|(k, v)| (k.to_string(), v.to_string())).collect() })
    }

    fn write(&self, path: &str) -> Result<(), String> {
        let text: String = self.fields.iter().map(|(k, v)| format!("{k} = {v}\n")).collect();
        std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.fields.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    fn set(&mut self, name: &str, value: String) {
        self.fields.retain(|(k, _)| k != name);
        self.fields.push((name.to_string(), value));
    }

    fn remove(&mut self, name: &str) {
        self.fields.retain(|(k, _)| k != name);
    }

    fn key(&self, name: &str) -> Result<Key, String> {
        fixed(unhex(self.get(name).ok_or_else(|| format!("The state has no {name}."))?)?, name)
    }

    fn number(&self, name: &str) -> Result<u64, String> {
        self.get(name).ok_or_else(|| format!("The state has no {name}."))?.parse()
            .map_err(|_| format!("{name} is not a number."))
    }

    fn session(&self) -> Result<Session, String> {
        Ok(Session { send: self.key("send")?, receive: self.key("receive")?,
                     local_index: self.number("local-index")? as u32,
                     remote_index: self.number("remote-index")? as u32 })
    }

    fn put_session(&mut self, session: &Session) {
        for name in ["chaining-key", "hash", "ephemeral"] {
            self.remove(name);
        }
        self.set("send", hex(&session.send));
        self.set("receive", hex(&session.receive));
        self.set("local-index", session.local_index.to_string());
        self.set("remote-index", session.remote_index.to_string());
        self.set("send-counter", "0".to_string());
        self.remove("replay-highest");
        self.remove("replay-seen");
    }

    fn window(&self) -> Result<ReplayWindow, String> {
        let highest = self.get("replay-highest").map(|v| v.parse::<u64>()).transpose()
            .map_err(|_| "replay-highest is not a number.")?;
        let seen = self.get("replay-seen").unwrap_or("").split(',').filter(|s| !s.is_empty())
            .map(|s| s.parse::<u64>().map_err(|_| "replay-seen is not numbers.".to_string()))
            .collect::<Result<_, _>>()?;
        Ok(ReplayWindow { highest, seen })
    }

    fn put_window(&mut self, window: &ReplayWindow) {
        if let Some(h) = window.highest {
            self.set("replay-highest", h.to_string());
        }
        self.set("replay-seen", window.seen.iter().map(u64::to_string)
                                            .collect::<Vec<_>>().join(","));
    }
}

fn index(args: &[String]) -> Result<u32, String> {
    match value(args, "--index") {
        Some(text) => text.parse().map_err(|_| format!("{text}: not an index.")),
        None => Ok(u32::from_le_bytes(allcrypt::api::random_bytes(4)?.try_into()
                                       .expect("four"))),
    }
}

fn ephemeral(args: &[String]) -> Result<Key, String> {
    match value(args, "--ephemeral") {
        Some(text) => fixed(unhex(text)?, "--ephemeral"),
        None => noise::generate_private(),
    }
}

fn message(args: &[String]) -> Result<Vec<u8>, String> {
    unhex(positional(args).get(1).ok_or("Which message?")?)
}

fn state_path(args: &[String]) -> Result<&str, String> {
    value(args, "--state").ok_or_else(|| "--state FILE".to_string())
}

// ----------------------------------------------------------------- commands --

fn initiate(args: &[String]) -> Result<(), String> {
    let path = state_path(args)?;
    // An existing state keeps its cookie and keys for the retry a cookie
    // reply asks for.
    let mut state = State::read(path).unwrap_or_default();
    let keys = if value(args, "--config").is_none() && value(args, "--private").is_none()
        && state.get("private").is_some() {
        Keys { private: state.key("private")?, peer: state.key("peer")?, psk: state.key("psk")? }
    } else {
        keys(args)?
    };
    let timestamp = match value(args, "--timestamp") {
        Some(text) => fixed(unhex(text)?, "--timestamp")?,
        None => noise::now_tai64n(),
    };
    let (mut msg, pending) = noise::create_initiation(&keys.private, &keys.peer,
                                                      &ephemeral(args)?, &timestamp,
                                                      index(args)?)?;
    let cookie: Option<[u8; 16]> = state.get("cookie").map(|c| fixed(unhex(c)?, "cookie"))
        .transpose()?;
    let mac1 = noise::add_macs(&mut msg, &keys.peer, cookie.as_ref());
    state.set("role", "initiator".to_string());
    state.set("private", hex(&keys.private));
    state.set("peer", hex(&keys.peer));
    state.set("psk", hex(&keys.psk));
    state.set("chaining-key", hex(&pending.chaining_key));
    state.set("hash", hex(&pending.hash));
    state.set("ephemeral", hex(&pending.ephemeral_private));
    state.set("local-index", pending.sender.to_string());
    state.set("last-mac1", hex(&mac1));
    state.write(path)?;
    println!("{}", hex(&msg));
    Ok(())
}

fn respond(args: &[String]) -> Result<(), String> {
    let path = state_path(args)?;
    let keys = keys(args)?;
    let msg = message(args)?;
    let our_public = noise::public_key(&keys.private);
    if msg.len() != noise::INITIATION_LEN || !noise::check_mac1(&msg, &our_public) {
        return Err("MAC1 does not check: this initiation was not made for our key.".into());
    }
    let init = noise::consume_initiation(&msg, &keys.private)?;
    if init.peer_public != keys.peer {
        return Err(format!("The initiation is from {}, which is not the peer.",
                           base64::encode(&init.peer_public)));
    }
    // A replayed initiation carries an old timestamp: refused, as wg does,
    // against the last one this state accepted.
    let mut state = State::read(path).unwrap_or_default();
    if let Some(last) = state.get("last-timestamp") {
        if init.timestamp.to_vec() <= unhex(last)? {
            return Err("The initiation's timestamp is not newer than the last one: a \
                        replay.".to_string());
        }
    }
    let (mut resp, session) = noise::create_response(&init, &keys.psk, &ephemeral(args)?,
                                                     index(args)?)?;
    noise::add_macs(&mut resp, &keys.peer, None);
    state.set("role", "responder".to_string());
    state.set("private", hex(&keys.private));
    state.set("peer", hex(&keys.peer));
    state.set("psk", hex(&keys.psk));
    state.set("last-timestamp", hex(&init.timestamp));
    state.put_session(&session);
    state.write(path)?;
    println!("{}", hex(&resp));
    Ok(())
}

fn complete(args: &[String]) -> Result<(), String> {
    let path = state_path(args)?;
    let mut state = State::read(path)?;
    let msg = message(args)?;
    let private = state.key("private")?;
    if msg.len() != noise::RESPONSE_LEN || !noise::check_mac1(&msg, &noise::public_key(&private)) {
        return Err("MAC1 does not check: this response was not made for our key.".into());
    }
    let pending = Pending { chaining_key: state.key("chaining-key")?, hash: state.key("hash")?,
                            ephemeral_private: state.key("ephemeral")?,
                            sender: state.number("local-index")? as u32 };
    let session = noise::consume_response(&msg, &pending, &private, &state.key("psk")?)?;
    state.put_session(&session);
    state.write(path)?;
    println!("session {} {}", session.local_index, session.remote_index);
    Ok(())
}

fn seal(args: &[String]) -> Result<(), String> {
    let path = state_path(args)?;
    let mut state = State::read(path)?;
    let session = state.session()?;
    let counter = state.number("send-counter")?;
    if counter >= noise::REJECT_AFTER_MESSAGES {
        return Err("This session has sent all it may; handshake again.".to_string());
    }
    let plaintext = unhex(positional(args).get(1).map(|s| s.as_str()).unwrap_or(""))?;
    let msg = noise::seal_transport(&session, counter, &noise::pad(&plaintext, 1420));
    state.set("send-counter", (counter + 1).to_string());
    state.write(path)?;
    println!("{}", hex(&msg));
    Ok(())
}

fn open(args: &[String]) -> Result<(), String> {
    let path = state_path(args)?;
    let mut state = State::read(path)?;
    let (counter, plaintext) = noise::open_transport(&state.session()?, &message(args)?)?;
    // The window is updated only after the tag verifies: a forged counter
    // must not move it.
    let mut window = state.window()?;
    window.accept(counter)?;
    state.put_window(&window);
    state.write(path)?;
    println!("{}", hex(&plaintext));
    Ok(())
}

fn cookie_reply(args: &[String]) -> Result<(), String> {
    let msg = message(args)?;
    if msg.len() != noise::INITIATION_LEN && msg.len() != noise::RESPONSE_LEN {
        return Err("A cookie reply answers a handshake message.".to_string());
    }
    let private = key_from_base64(value(args, "--private").ok_or("--private KEY")?,
                                  "The private key")?;
    let secret: [u8; 32] = fixed(unhex(value(args, "--secret").ok_or("--secret HEX")?)?,
                                 "--secret")?;
    let source = unhex(value(args, "--source").ok_or("--source HEX")?)?;
    let our_public = noise::public_key(&private);
    if !noise::check_mac1(&msg, &our_public) {
        return Err("MAC1 does not check, so no cookie: a reply is only for a message that \
                    knew our key.".to_string());
    }
    let nonce: [u8; 24] = match value(args, "--nonce") {
        Some(text) => fixed(unhex(text)?, "--nonce")?,
        None => fixed(allcrypt::api::random_bytes(24)?, "nonce")?,
    };
    println!("{}", hex(&noise::cookie_reply(&msg, &our_public, &secret, &source, &nonce)));
    Ok(())
}

fn take_cookie(args: &[String]) -> Result<(), String> {
    let path = state_path(args)?;
    let mut state = State::read(path)?;
    let last: [u8; 16] = fixed(unhex(state.get("last-mac1").ok_or("No message sent yet.")?)?,
                               "last-mac1")?;
    let cookie = noise::open_cookie_reply(&message(args)?, &state.key("peer")?, &last)?;
    state.set("cookie", hex(&cookie));
    state.write(path)?;
    println!("cookie {}", hex(&cookie));
    Ok(())
}

fn run(args: &[String]) -> Result<bool, String> {
    match positional(args).first().map(|s| s.as_str()) {
        Some("genkey") => println!("{}", base64::encode(&noise::generate_private()?)),
        Some("genpsk") => println!("{}", base64::encode(&allcrypt::api::random_bytes(32)?)),
        Some("pubkey") => {
            let mut text = String::new();
            std::io::stdin().read_line(&mut text).map_err(|e| e.to_string())?;
            println!("{}", base64::encode(&noise::public_key(
                &key_from_base64(&text, "The private key")?)));
        }
        Some("initiate") => initiate(args)?,
        Some("respond") => respond(args)?,
        Some("complete") => complete(args)?,
        Some("seal") => seal(args)?,
        Some("open") => open(args)?,
        Some("cookie-reply") => cookie_reply(args)?,
        Some("cookie") => take_cookie(args)?,
        Some("check-mac2") => {
            let secret: [u8; 32] = fixed(unhex(value(args, "--secret").ok_or("--secret HEX")?)?,
                                         "--secret")?;
            let source = unhex(value(args, "--source").ok_or("--source HEX")?)?;
            let good = noise::check_mac2(&message(args)?, &secret, &source);
            println!("{}", if good { "good" } else { "bad" });
            return Ok(good);
        }
        _ => return Err("Commands: genkey, pubkey, genpsk, initiate, respond, complete, seal, \
                         open, cookie-reply, cookie, check-mac2. See the top of \
                         examples/products/wireguard/main.rs.".to_string()),
    }
    Ok(true)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("wireguard: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests;
