/*!
Whole SSH sessions between OpenSSH's `ssh` and this library's server,
replayed offline.

`tests/transcripts/ssh_server_sessions.txt` was recorded by
`scripts/check_ssh_server.py --record`: OpenSSH 10.0's and 7.4's `ssh`
against `examples/ssh_serve.rs` on loopback, the server's randomness
drawn from a counter so that its side of each session is a function of
what the client sent.

Feeding the client's bytes to a server seeded the same way, the server
must send **exactly** the bytes it sent to `ssh`. Its key exchange
reply carries a signature over the exchange hash, which covers both
KEXINITs, both versions, the host key and the shared secret; every
packet after NEWKEYS is under keys derived from it - so one wrong byte
in the negotiation, the key exchange, the signature, the derivation, the
cipher, the MAC or the packet layer comes out as different bytes. And
`ssh` accepted every one of them: it checked the host key's signature
against a `known_hosts` entry, and authenticated, ran the command and
took its exit status.

What this cannot do is notice a change `ssh` would have tolerated -
replay is exact - so a deliberate change to what the server sends (a
new algorithm in its KEXINIT, say) means recording again, and the
recording needs OpenSSH.

The application side is `examples/ssh_serve.rs`'s built-in commands,
repeated here: `echo`, `stderr` and `exit` joined by `;`, and `cat`.
It acts after every `process`, as there, which is what makes the
server's output depend on nothing but the bytes received.
*/

use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::ssh::server::{Server, ServerConfig, SessionRequest};
use allcrypt::ssh::{cipher, kex, keys, mac, private_key};

const TRANSCRIPTS: &str = include_str!("transcripts/ssh_server_sessions.txt");

/// The generator `examples/ssh_serve.rs` used.
fn counter_stream(seed: u64) -> allcrypt::ssh::server::RandomSource {
    let mut counter = 0u64;
    let mut pool: Vec<u8> = Vec::new();
    Box::new(move |buf: &mut [u8]| {
        for byte in buf.iter_mut() {
            if pool.is_empty() {
                let mut input = seed.to_be_bytes().to_vec();
                input.extend_from_slice(&counter.to_be_bytes());
                counter += 1;
                pool = SHA256::new(&input).digest();
                pool.reverse();
            }
            *byte = pool.pop().unwrap_or(0);
        }
        Ok(())
    })
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

struct Session {
    name: String,
    fields: Vec<(String, String)>,
    /// `(from_client, bytes)` in the order they crossed.
    flow: Vec<(bool, Vec<u8>)>,
}

impl Session {
    fn field(&self, name: &str) -> &str {
        self.fields.iter().find(|(key, _)| key == name).map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("{}: no {name}", self.name))
    }

    /// The server as the recording ran it: this host key, every
    /// algorithm in every table, the user's key and the password.
    fn server(&self) -> Server {
        let key_text = String::from_utf8(
            allcrypt::pem::decode(self.field("host_key")).unwrap()).unwrap();
        let mut config = ServerConfig::new(vec![private_key::read(&key_text, None).unwrap().0]);
        config.kex = kex::METHODS.iter().map(|m| m.name).collect();
        config.ciphers = cipher::CIPHERS.iter().map(|c| c.name)
            .filter(|name| *name != "none").collect();
        config.macs = mac::MACS.iter().map(|m| m.name).collect();
        config.host_key_algorithms = vec![
            "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"];
        config.authorize_key("allcrypt", keys::parse_line(self.field("authorized")).unwrap().key);
        config.authorize_password("allcrypt", self.field("password"));
        let seed: u64 = self.field("seed").parse().unwrap();
        Server::with_random(config, counter_stream(seed)).unwrap()
    }
}

fn sessions() -> Vec<Session> {
    let mut out: Vec<Session> = Vec::new();
    for line in TRANSCRIPTS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(Session { name: name.to_string(), fields: Vec::new(), flow: Vec::new() });
            continue;
        }
        let session = out.last_mut().expect("a field before any session");
        if let Some(bytes) = line.strip_prefix("C ") {
            session.flow.push((true, unhex(bytes)));
        } else if let Some(bytes) = line.strip_prefix("S ") {
            session.flow.push((false, unhex(bytes)));
        } else {
            let (key, value) = line.split_once(" = ").expect("a field");
            session.fields.push((key.to_string(), value.to_string()));
        }
    }
    out
}

/// `examples/ssh_serve.rs`'s built-in commands, as far as the recording
/// uses them.
struct Builtin {
    finished: bool,
}

impl Builtin {
    fn step(&mut self, server: &mut Server) -> Result<(), String> {
        let Some(SessionRequest::Exec(command)) = server.request().cloned() else {
            return Ok(());
        };
        let input = server.take_stdin()?;
        if self.finished {
            return Ok(());
        }
        if command.trim() == "cat" {
            if !input.is_empty() {
                server.write(&input)?;
            }
            if server.stdin_closed() {
                self.finished = true;
                server.finish(0)?;
            }
            return Ok(());
        }
        self.finished = true;
        let mut status = 0;
        for part in command.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (word, rest) = part.split_once(' ').unwrap_or((part, ""));
            match word {
                "echo" => server.write(format!("{rest}\n").as_bytes())?,
                "stderr" => server.write_stderr(format!("{rest}\n").as_bytes())?,
                "exit" => {
                    status = rest.trim().parse().unwrap();
                    break;
                }
                other => panic!("the recording used a command this replay lacks: {other}"),
            }
        }
        server.finish(status)
    }
}

#[test]
fn test_every_recorded_session_replays_byte_for_byte() {
    let all = sessions();
    let declared: usize = TRANSCRIPTS.lines()
        .find_map(|line| line.strip_prefix("# sessions: "))
        .expect("a session count").parse().unwrap();
    assert_eq!(all.len(), declared);
    assert_eq!(all.len(), 15);

    for session in &all {
        let name = &session.name;
        let mut server = session.server();
        let mut app = Builtin { finished: false };
        let mut sent = Vec::new();
        let mut expected = Vec::new();
        for (from_client, bytes) in &session.flow {
            if *from_client {
                sent.extend_from_slice(&server.take_outgoing());
                assert!(sent == expected, "{name}: the server's bytes before this client \
                                           read differ from what ssh saw");
                server.push_incoming(bytes);
                server.process().unwrap_or_else(|e| panic!("{name}: {e}"));
                app.step(&mut server).unwrap_or_else(|e| panic!("{name}: {e}"));
            } else {
                expected.extend_from_slice(bytes);
            }
        }
        sent.extend_from_slice(&server.take_outgoing());
        assert!(sent == expected, "{name}: the server's last bytes");
        assert!(server.closed(), "{name}");
        assert_eq!(server.user(), Some("allcrypt"), "{name}");
        assert_eq!(server.auth_method(), Some(session.field("auth")), "{name}");
        assert_eq!(server.key_exchanges().to_string(), session.field("exchanges"), "{name}");
        assert_eq!(server.request(), Some(&SessionRequest::Exec(
            session.field("command").to_string())), "{name}");
        let client = session.field("client");
        assert_eq!(server.strict_kex(), client.starts_with("OpenSSH_10"), "{name}");
        if name == "terminal-request" {
            assert!(server.terminal().is_some(), "{name}");
        }
    }
}

/// Replay `session` with the last byte of client read `corrupt`
/// flipped; `Err` with the read's index if the server refused a read.
fn replay_corrupted(session: &Session, corrupt: Option<usize>)
                    -> Result<Vec<u32>, (usize, Vec<u8>)> {
    let mut server = session.server();
    let mut app = Builtin { finished: false };
    let mut exchanges_after = Vec::new();
    let reads = session.flow.iter().filter(|(from_client, _)| *from_client);
    for (index, (_, bytes)) in reads.enumerate() {
        let mut bytes = bytes.clone();
        if corrupt == Some(index) {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        server.push_incoming(&bytes);
        if server.process().is_err() {
            return Err((index, server.take_outgoing()));
        }
        app.step(&mut server).unwrap();
        exchanges_after.push(server.key_exchanges());
    }
    Ok(exchanges_after)
}

/// The first client read wholly under the new keys - the one after the
/// read that carried the client's NEWKEYS - with its last byte flipped.
/// That byte is inside a MAC or an authentication tag, so the server
/// must refuse the read, and say why with a DISCONNECT, before acting on
/// anything in it.
#[test]
fn test_a_flipped_byte_in_a_client_packet_is_refused() {
    for session in sessions() {
        let name = &session.name;
        let exchanges = replay_corrupted(&session, None)
            .unwrap_or_else(|(index, _)| panic!("{name}: read {index} refused unaltered"));
        let keyed = exchanges.iter().position(|&n| n == 1).expect("a NEWKEYS") + 1;
        match replay_corrupted(&session, Some(keyed)) {
            Err((index, disconnect)) => {
                assert_eq!(index, keyed, "{name}");
                assert!(!disconnect.is_empty(), "{name}: no DISCONNECT");
            }
            Ok(_) => panic!("{name}: read {keyed}, corrupted, was accepted"),
        }
    }
}
