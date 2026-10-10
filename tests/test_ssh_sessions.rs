/*!
Whole SSH sessions with OpenSSH's sshd, replayed offline.

`tests/transcripts/ssh_sessions.txt` was recorded by
`scripts/check_ssh_client.py --record`: this library's client against
OpenSSH 10.0's sshd on loopback, its randomness drawn from a counter so
that its side of each session is a function of what the server sent.

Replaying the server's bytes at a client seeded the same way, the client
must send **exactly** the bytes it sent to sshd. Every encrypted packet
after NEWKEYS depends on keys derived from the exchange hash, which
depends on the host key, both KEXINITs, both version strings and the
shared secret - so a single wrong byte anywhere in the key exchange, the
key derivation, the cipher, the MAC or the packet layer shows up as a
different ciphertext. And the server's own encrypted packets have to
decrypt and authenticate for the client to get as far as sending its
next one.

**The secret's encoding is covered by construction, not by luck.** For a
32 byte shared secret, an mpint and a string are the same bytes unless
the top bit is set - so a recording where every Curve25519 and hybrid
secret had it clear would pass with the two encodings swapped. This one
was re-recorded until enough had it set - three Curve25519, two
ML-KEM hybrid and one sntrup761 hybrid secret - and swapping the encoding
for any of the three in `ssh::kex` fails the replay (checked when it was
recorded).
`docs/building.md` says how to check a new recording.

What this cannot do is notice a change sshd would have tolerated -
replay is exact - so a deliberate change to what the client sends
(a new algorithm in KEXINIT, say) means recording again, and the
recording needs OpenSSH.
*/

use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::ssh::client::{Auth, Client, ClientConfig, HostKeyCheck};
use allcrypt::ssh::private_key;

const TRANSCRIPTS: &str = include_str!("transcripts/ssh_sessions.txt");

/// The generator `examples/ssh_exec.rs` used: SHA-256 of the seed and a
/// counter, as a stream. Copied there and here rather than shared,
/// because a deterministic "random" source has no business in the
/// library's API.
fn counter_stream(seed: u64) -> allcrypt::ssh::client::RandomSource {
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

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_string().into_boxed_str())
}

struct Session {
    name: String,
    fields: Vec<(String, String)>,
    /// `(from_server, bytes)` in the order they crossed.
    flow: Vec<(bool, Vec<u8>)>,
}

impl Session {
    fn field(&self, name: &str) -> &str {
        self.fields.iter().find(|(key, _)| key == name).map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("{}: no {name}", self.name))
    }

    /// The identification line this side sent when the session was
    /// recorded, without its CRLF. The replay sends the same one: the
    /// line carries the crate version, so a replay under the current
    /// version would differ from the recording at its first byte, and
    /// every byte after it through the exchange hash, on every release.
    fn recorded_version(&self, ours: bool) -> String {
        let first = self.flow.iter().find(|(from_server, _)| *from_server != ours)
            .unwrap_or_else(|| panic!("{}: nothing sent", self.name));
        let end = first.1.windows(2).position(|w| w == b"\r\n")
            .unwrap_or_else(|| panic!("{}: no identification line", self.name));
        let line = String::from_utf8(first.1[..end].to_vec()).unwrap();
        assert!(line.starts_with("SSH-2.0-allcrypt_"), "{}: {line}", self.name);
        line
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
            session.flow.push((false, unhex(bytes)));
        } else if let Some(bytes) = line.strip_prefix("S ") {
            session.flow.push((true, unhex(bytes)));
        } else {
            let (key, value) = line.split_once(" = ").expect("a field");
            session.fields.push((key.to_string(), value.to_string()));
        }
    }
    out
}

#[test]
fn test_every_recorded_session_replays_byte_for_byte() {
    let all = sessions();
    let declared: usize = TRANSCRIPTS.lines()
        .find_map(|line| line.strip_prefix("# sessions: "))
        .expect("a session count").parse().unwrap();
    assert_eq!(all.len(), declared);
    assert_eq!(all.len(), 24);

    for session in &all {
        let name = &session.name;
        let key_text = String::from_utf8(
            allcrypt::pem::decode(session.field("key")).unwrap()).unwrap();
        let (key, _) = private_key::read(&key_text, None).unwrap();
        let mut config = ClientConfig::new(
            "root", HostKeyCheck::Fingerprint(session.field("host_key").to_string()));
        config.auth.push(Auth::PublicKey(key));
        config.version = session.recorded_version(true);
        for option in session.field("options").split_whitespace() {
            let (option, value) = option.split_once('=').unwrap();
            match option {
                "kex" => config.kex = vec![leak(value)],
                "cipher" => config.ciphers = vec![leak(value)],
                "mac" => config.macs = vec![leak(value)],
                "hostkey" => config.host_key_algorithms = vec![leak(value)],
                other => panic!("{name}: option {other}"),
            }
        }
        let seed: u64 = session.field("seed").parse().unwrap();
        let mut client = Client::with_random(config, counter_stream(seed)).unwrap();
        client.exec(session.field("command"));

        let mut sent = Vec::new();
        let mut expected = Vec::new();
        for (from_server, bytes) in &session.flow {
            if *from_server {
                sent.extend_from_slice(&client.take_outgoing());
                assert_eq!(sent, expected, "{name}: the client's bytes before this \
                                            server packet differ from what sshd saw");
                client.push_incoming(bytes);
                client.process().unwrap_or_else(|e| panic!("{name}: {e}"));
            } else {
                expected.extend_from_slice(bytes);
            }
        }
        sent.extend_from_slice(&client.take_outgoing());
        assert_eq!(sent, expected, "{name}: the client's last bytes");
        assert!(client.authenticated(), "{name}");
        assert_eq!(client.take_stdout(), unhex(session.field("stdout")), "{name}");
        assert_eq!(client.take_stderr(), b"stderr too\n", "{name}");
        assert_eq!(client.exit_status().map(|s| s.to_string()).as_deref(),
                   Some(session.field("exit")), "{name}");
        assert!(client.closed(), "{name}");
    }
}

/// The same recording with the last byte of one server read flipped -
/// the read that answers the client's third flight, which is the key
/// exchange reply in a group exchange and the first encrypted packets
/// otherwise. The last byte is always inside a MAC, a tag or a signature,
/// so the client must refuse the read rather than act on it. (A flip in
/// a length field that is sent in clear only makes the client wait for
/// more, which is the right answer and not one this test can tell from
/// success.)
#[test]
fn test_a_flipped_byte_in_a_server_packet_is_refused() {
    for session in sessions() {
        let name = &session.name;
        let key_text = String::from_utf8(
            allcrypt::pem::decode(session.field("key")).unwrap()).unwrap();
        let (key, _) = private_key::read(&key_text, None).unwrap();
        let mut config = ClientConfig::new("root", HostKeyCheck::AcceptAny);
        config.auth.push(Auth::PublicKey(key));
        config.version = session.recorded_version(true);
        for option in session.field("options").split_whitespace() {
            let (option, value) = option.split_once('=').unwrap();
            match option {
                "kex" => config.kex = vec![leak(value)],
                "cipher" => config.ciphers = vec![leak(value)],
                "mac" => config.macs = vec![leak(value)],
                "hostkey" => config.host_key_algorithms = vec![leak(value)],
                _ => {}
            }
        }
        let mut client = Client::with_random(
            config, counter_stream(session.field("seed").parse().unwrap())).unwrap();
        client.exec(session.field("command"));
        let mut client_flights = 0;
        let mut refused = false;
        for (from_server, bytes) in &session.flow {
            if !*from_server {
                client_flights += 1;
                continue;
            }
            client.take_outgoing();
            if client_flights == 3 {
                let mut broken = bytes.clone();
                let last = broken.len() - 1;
                broken[last] ^= 0x01;
                client.push_incoming(&broken);
                refused = client.process().is_err();
                break;
            }
            client.push_incoming(bytes);
            client.process().unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        assert!(refused, "{name}: a flipped byte was accepted");
    }
}
