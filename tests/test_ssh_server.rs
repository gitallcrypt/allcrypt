/*!
The SSH server against this library's own client, in memory.

Both ends are ours, so this settles the wiring: every key exchange,
host key type, cipher and MAC reaches an encrypted session; public key
and password authentication succeed and fail when they should; the
window holds in both directions across a re-exchange the server starts.
It says nothing about whether the bytes are anybody else's. That half
is `tests/test_ssh_server_sessions.rs`, OpenSSH's `ssh` against this
server recorded and replayed, and `scripts/check_ssh_server.py`, the
same live.

The host and user keys are `ssh-keygen`'s, from `vectors/ssh_keys.vec`.
*/

use allcrypt::ssh::client::{Auth, Client, ClientConfig, HostKeyCheck};
use allcrypt::ssh::private_key::{self, PrivateKey};
use allcrypt::ssh::server::{Server, ServerConfig, SessionRequest};
use allcrypt::ssh::{cipher, kex, mac};

const VECTORS: &str = include_str!("../vectors/ssh_keys.vec");

/// A key from the `[key]` section by name.
fn key(name: &str) -> PrivateKey {
    let mut in_keys = false;
    let mut current = "";
    for line in VECTORS.lines() {
        if line.starts_with('[') {
            in_keys = line == "[key]";
            continue;
        }
        if !in_keys {
            continue;
        }
        if let Some(value) = line.strip_prefix("name = ") {
            current = value;
        } else if let Some(value) = line.strip_prefix("private = ") {
            if current == name {
                let text = String::from_utf8(allcrypt::pem::decode(value).unwrap()).unwrap();
                return private_key::read(&text, None).unwrap().0;
            }
        }
    }
    panic!("no key {name}");
}

/// A server with `host` as its key, accepting `alice` with the Ed25519
/// key and `bob` with a password.
fn server_config(host: PrivateKey) -> ServerConfig {
    let mut config = ServerConfig::new(vec![host]);
    config.authorize_key("alice", key("ed25519").public());
    config.authorize_password("bob", "hunter2");
    config
}

fn client_config(user: &str, host: &PrivateKey) -> ClientConfig {
    ClientConfig::new(user, HostKeyCheck::Key(host.public()))
}

/// What the caller of the server does: once the client has asked for a
/// command, `cat` echoes standard input as it arrives and every other
/// command prints its name to standard output, `stderr` to standard
/// error, and exits with its length.
struct App {
    finished: bool,
}

impl App {
    fn new() -> App {
        App { finished: false }
    }

    fn step(&mut self, server: &mut Server) -> Result<(), String> {
        let Some(SessionRequest::Exec(command)) = server.request().cloned() else {
            return Ok(());
        };
        let input = server.take_stdin()?;
        if self.finished {
            return Ok(());
        }
        if command == "cat" {
            if !input.is_empty() {
                server.write(&input)?;
            }
            if server.stdin_closed() {
                self.finished = true;
                server.finish(0)?;
            }
        } else if server.stdin_closed() || command != "wait" {
            self.finished = true;
            server.write(format!("{command}\n").as_bytes())?;
            server.write_stderr(b"stderr\n")?;
            server.finish(command.len() as u32)?;
        }
        Ok(())
    }
}

/// Move bytes both ways until neither side has anything to say.
/// `between` runs in every round after the server has read, before the
/// application acts, for a test to act mid-session.
fn run(client: &mut Client, server: &mut Server, app: &mut App,
       mut between: impl FnMut(&mut Client, &mut Server, usize) -> Result<(), String>)
       -> Result<(), String> {
    for round in 0..10_000 {
        let up = client.take_outgoing();
        if !up.is_empty() {
            server.push_incoming(&up);
            server.process().map_err(|e| format!("server: {e}"))?;
        }
        between(client, server, round)?;
        app.step(server).map_err(|e| format!("app: {e}"))?;
        let down = server.take_outgoing();
        if !down.is_empty() {
            client.push_incoming(&down);
            client.process().map_err(|e| format!("client: {e}"))?;
        }
        if up.is_empty() && down.is_empty() {
            return Ok(());
        }
    }
    Err("no quiet after 10000 rounds".to_string())
}

fn exec(mut client_config: ClientConfig, server_config: ServerConfig, command: &str)
        -> Result<(Client, Server), String> {
    if client_config.auth.is_empty() {
        client_config.auth.push(Auth::PublicKey(key("ed25519")));
    }
    let mut client = Client::new(client_config)?;
    client.exec(command);
    client.send_eof()?;
    let mut server = Server::new(server_config)?;
    run(&mut client, &mut server, &mut App::new(), |_, _, _| Ok(()))?;
    Ok((client, server))
}

fn assert_session(client: &mut Client, server: &Server, command: &str, what: &str) {
    assert!(client.authenticated(), "{what}");
    assert_eq!(client.take_stdout(), format!("{command}\n").as_bytes(), "{what}");
    assert_eq!(client.take_stderr(), b"stderr\n", "{what}");
    assert_eq!(client.exit_status(), Some(command.len() as u32), "{what}");
    assert!(client.closed() && server.closed(), "{what}");
    assert_eq!(server.request(), Some(&SessionRequest::Exec(command.to_string())), "{what}");
}

/// Every host key type and every algorithm each signs under, with the
/// client accepting only that algorithm and only that key.
#[test]
fn test_every_host_key_algorithm() {
    for (name, algorithms) in [
            ("ed25519", &["ssh-ed25519"][..]),
            ("ecdsa256", &["ecdsa-sha2-nistp256"]),
            ("ecdsa384", &["ecdsa-sha2-nistp384"]),
            ("ecdsa521", &["ecdsa-sha2-nistp521"]),
            ("rsa2048", &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]),
            ("dsa1024", &["ssh-dss"])] {
        for algorithm in algorithms {
            let host = key(name);
            let mut client = client_config("alice", &host);
            client.host_key_algorithms = vec![algorithm];
            client.kex = vec!["curve25519-sha256"];
            let mut server = server_config(host);
            server.host_key_algorithms.push("ssh-rsa");
            server.host_key_algorithms.push("ssh-dss");
            let (mut client, server) = exec(client, server, "hostkey")
                .unwrap_or_else(|e| panic!("{algorithm}: {e}"));
            assert_eq!(client.algorithms().host_key, *algorithm);
            assert_session(&mut client, &server, "hostkey", algorithm);
            assert_eq!(server.user(), Some("alice"));
        }
    }
}

/// With several host keys, the negotiated algorithm picks the key.
#[test]
fn test_the_algorithm_picks_among_several_host_keys() {
    let keys = ["ed25519", "ecdsa384", "rsa2048"];
    for (index, algorithm) in ["ssh-ed25519", "ecdsa-sha2-nistp384", "rsa-sha2-256"]
            .iter().enumerate() {
        let mut client = client_config("alice", &key(keys[index]));
        client.host_key_algorithms = vec![algorithm];
        let mut config = ServerConfig::new(keys.iter().map(|name| key(name)).collect());
        config.authorize_key("alice", key("ed25519").public());
        let (client, _) = exec(client, config, "several").unwrap();
        assert_eq!(client.host_key(), Some(&key(keys[index]).public()));
    }
}

fn key_exchange(method: &str, group_exchange_sizes: &[usize]) {
    let host = key("ed25519");
    let mut client = client_config("alice", &host);
    client.kex = vec![leak(method)];
    let mut server = server_config(host);
    server.kex = kex::METHODS.iter().map(|m| m.name).collect();
    server.group_exchange_sizes = group_exchange_sizes.to_vec();
    let (mut client, server) = exec(client, server, "kex")
        .unwrap_or_else(|e| panic!("{method}: {e}"));
    assert_eq!(server.algorithms().kex, method);
    assert_session(&mut client, &server, "kex", method);
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_string().into_boxed_str())
}

/// Every key exchange method, legacy included, but the two largest
/// fixed groups. The group exchange's group is the server's choice: the
/// client asks for 2048 to 8192 bits preferring 4096, and with only
/// 2048 on offer gets that: the 4096 bit exchange takes half a minute
/// in a debug build.
#[test]
fn test_every_key_exchange() {
    for method in kex::METHODS {
        if matches!(method.name, "diffie-hellman-group16-sha512"
                                 | "diffie-hellman-group18-sha512") {
            continue;
        }
        key_exchange(method.name, &[2048]);
    }
}

/// The 4096 and 8192 bit groups, fixed and exchanged: the same code as
/// the 2048 bit group with a bigger number, and a minute and more in a
/// debug build, so only in an optimised one (`cargo test --release`).
#[test]
#[cfg_attr(debug_assertions, ignore = "slow without optimisation; run with --release")]
fn test_the_large_groups() {
    key_exchange("diffie-hellman-group16-sha512", &[]);
    key_exchange("diffie-hellman-group18-sha512", &[]);
    key_exchange("diffie-hellman-group-exchange-sha256", &kex::MODP_SIZES);
}

/// Every cipher, each direction its own; and every MAC, each with a
/// cipher that uses one.
#[test]
fn test_every_cipher_and_mac() {
    let ciphers: Vec<&'static str> = cipher::CIPHERS.iter().map(|c| c.name)
        .filter(|name| *name != "none").collect();
    let macs: Vec<&'static str> = mac::MACS.iter().map(|m| m.name).collect();
    for (i, c2s) in ciphers.iter().enumerate() {
        let s2c = ciphers[(i + 1) % ciphers.len()];
        let host = key("ecdsa256");
        let mut client = client_config("alice", &host);
        client.kex = vec!["ecdh-sha2-nistp256"];
        client.ciphers = vec![c2s, s2c];
        client.macs = vec![macs[i % macs.len()]];
        let mut server = server_config(host);
        server.ciphers = vec![s2c, c2s];
        server.macs = macs.clone();
        // A client offering two ciphers gets its first both ways; the
        // server's order does not matter.
        let (mut client, server) = exec(client, server, "cipher")
            .unwrap_or_else(|e| panic!("{c2s}: {e}"));
        assert_eq!(server.algorithms().cipher_c2s, *c2s);
        assert_eq!(server.algorithms().cipher_s2c, *c2s);
        assert_session(&mut client, &server, "cipher", c2s);
    }
    for mac_name in &macs {
        let host = key("ed25519");
        let mut client = client_config("alice", &host);
        client.kex = vec!["curve25519-sha256"];
        client.ciphers = vec!["aes128-ctr"];
        client.macs = vec![mac_name];
        let mut server = server_config(host);
        server.macs = macs.clone();
        server.ciphers = vec!["aes128-ctr"];
        let (mut client, server) = exec(client, server, "mac")
            .unwrap_or_else(|e| panic!("{mac_name}: {e}"));
        assert_eq!(server.algorithms().mac_s2c.as_deref(), Some(*mac_name));
        assert_session(&mut client, &server, "mac", mac_name);
    }
}

/// Password authentication; a wrong one, then the right key; and a user
/// with nothing that works, told what the server would take.
#[test]
fn test_authentication() {
    let host = key("ed25519");
    let mut client = client_config("bob", &host);
    client.auth = vec![Auth::Password("hunter2".to_string())];
    let (mut client, server) = exec(client, server_config(key("ed25519")), "pw").unwrap();
    assert_session(&mut client, &server, "pw", "password");
    assert_eq!(server.user(), Some("bob"));
    assert_eq!(server.auth_method(), Some("password"));

    let mut client = client_config("alice", &host);
    client.auth = vec![Auth::Password("hunter2".to_string()),
                       Auth::PublicKey(key("ecdsa256")),
                       Auth::PublicKey(key("ed25519"))];
    let (client, server) = exec(client, server_config(key("ed25519")), "third").unwrap();
    assert!(client.authenticated());
    assert_eq!(server.user(), Some("alice"));

    // bob's password is bob's, and alice's key is alice's.
    for (user, auth) in [("alice", Auth::Password("hunter2".to_string())),
                         ("bob", Auth::PublicKey(key("ed25519"))),
                         ("bob", Auth::Password("hunter3".to_string()))] {
        let mut client = client_config(user, &host);
        client.auth = vec![auth];
        let error = exec(client, server_config(key("ed25519")), "no").err()
            .expect("refused");
        assert!(error.ends_with("would take publickey, password."), "{error}");
    }
}

/// An RSA user key signs with SHA-512 because the server's EXT_INFO
/// says it may; and DSA and the three ECDSA curves authenticate.
#[test]
fn test_every_user_key_type() {
    for name in ["rsa2048", "dsa1024", "ecdsa256", "ecdsa384", "ecdsa521"] {
        let host = key("ed25519");
        let mut client = client_config("carol", &host);
        client.auth = vec![Auth::PublicKey(key(name))];
        let mut server = server_config(host);
        server.authorize_key("carol", key(name).public());
        let (mut client, server) = exec(client, server, "user")
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_session(&mut client, &server, "user", name);
        assert_eq!(server.user(), Some("carol"));
        let expected = match name {
            "rsa2048" => "rsa-sha2-512",
            "dsa1024" => "ssh-dss",
            other => key(other).public().algorithm(),
        };
        assert_eq!(server.auth_method(), Some(format!("publickey {expected}").as_str()));
    }
}

/// Three MiB through `cat`: more than either window, so both
/// WINDOW_ADJUSTs are needed - and a key re-exchange the server starts
/// halfway through, just before the application writes what it has
/// read, so that output is held until the server's NEWKEYS.
#[test]
fn test_a_large_echo_across_a_server_rekey() {
    let host = key("ed25519");
    let mut config = client_config("alice", &host);
    config.auth.push(Auth::PublicKey(key("ed25519")));
    config.kex = vec!["curve25519-sha256"];
    let mut client = Client::new(config).unwrap();
    client.exec("cat");
    let input: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i * 7 + i / 251) as u8).collect();
    client.write(&input).unwrap();
    client.send_eof().unwrap();
    let mut server = Server::new(server_config(host)).unwrap();
    let mut rekeyed = false;
    let mut output = Vec::new();
    run(&mut client, &mut server, &mut App::new(), |client, server, _| {
        output.extend_from_slice(&client.take_stdout());
        if !rekeyed && output.len() > input.len() / 2 {
            rekeyed = true;
            server.rekey()?;
        }
        Ok(())
    }).unwrap();
    output.extend_from_slice(&client.take_stdout());
    assert!(rekeyed);
    assert_eq!(server.key_exchanges(), 2);
    assert_eq!(output.len(), input.len());
    assert!(output == input);
    assert_eq!(client.exit_status(), Some(0));
    assert!(client.closed() && server.closed());
}

/// Strict key exchange is in force when both ends advertise it, which
/// both do.
#[test]
fn test_strict_kex_on_both_ends() {
    let host = key("ed25519");
    let (client, server) = exec(client_config("alice", &host), server_config(host), "strict")
        .unwrap();
    assert!(client.strict_kex() && server.strict_kex());
}

/// No algorithm in common is refused by name, with both lists.
#[test]
fn test_nothing_in_common() {
    let host = key("ed25519");
    let mut client = client_config("alice", &host);
    client.ciphers = vec!["3des-cbc"];
    let error = exec(client, server_config(host), "x").err().unwrap();
    assert!(error.contains("no cipher (client to server) in common"), "{error}");
}

/// A server host key the client did not expect stops the client before
/// it authenticates.
#[test]
fn test_the_client_checks_the_servers_key() {
    let client = client_config("alice", &key("ecdsa256"));
    let mut server = server_config(key("ed25519"));
    server.host_key_algorithms = vec!["ssh-ed25519"];
    let mut client_config = client;
    client_config.host_key_algorithms = vec!["ssh-ed25519"];
    let error = exec(client_config, server, "x").err().unwrap();
    assert!(error.contains("not the one expected"), "{error}");
}

/// A flipped byte in the client's first encrypted packet: the server
/// refuses it, and says so with a DISCONNECT.
#[test]
fn test_a_flipped_byte_is_refused_with_a_disconnect() {
    let host = key("ed25519");
    let mut config = client_config("alice", &host);
    config.auth.push(Auth::PublicKey(key("ed25519")));
    let mut client = Client::new(config).unwrap();
    client.exec("x");
    let mut server = Server::new(server_config(host)).unwrap();
    // Version, KEXINIT and the key exchange, then NEWKEYS and the first
    // encrypted packet (the service request) together.
    let mut flights = 0;
    loop {
        let mut up = client.take_outgoing();
        flights += 1;
        if flights == 3 {
            let last = up.len() - 1;
            up[last] ^= 1;
            server.push_incoming(&up);
            let error = server.process().expect_err("a corrupted packet");
            assert!(server.closed(), "{error}");
            let down = server.take_outgoing();
            client.push_incoming(&down);
            let seen = client.process().expect_err("the server's DISCONNECT");
            assert!(seen.contains("disconnected (2)"), "{seen}");
            return;
        }
        server.push_incoming(&up);
        server.process().unwrap();
        client.push_incoming(&server.take_outgoing());
        client.process().unwrap();
    }
}

/// Several keys and a password: the failure lists both methods once
/// each, and a server with only keys lists only publickey.
#[test]
fn test_the_failure_lists_the_methods_offered() {
    let host = key("ed25519");
    let mut config = ServerConfig::new(vec![key("ed25519")]);
    config.authorize_key("alice", key("ecdsa256").public());
    config.authorize_key("alice", key("ecdsa384").public());
    let mut client = client_config("alice", &host);
    client.auth = vec![Auth::Password("x".to_string())];
    let error = exec(client, config, "x").err().unwrap();
    assert!(error.ends_with("would take publickey."), "{error}");
}

/// A signature by another key, presented with alice's public key: the
/// key is authorized, so the server gets as far as the signature, and
/// the signature is what refuses it.
#[test]
fn test_a_signature_by_another_key_is_refused() {
    let PrivateKey::Ed25519 { public, .. } = key("ed25519") else { unreachable!() };
    let PrivateKey::Ed25519 { seed, .. } = key("ed25519-legacy") else { unreachable!() };
    let forged = PrivateKey::Ed25519 { seed, public };
    let host = key("ed25519");
    let mut client = client_config("alice", &host);
    client.auth = vec![Auth::PublicKey(forged)];
    let error = exec(client, server_config(host), "x").err().expect("refused");
    assert!(error.contains("would take publickey, password"), "{error}");
}
