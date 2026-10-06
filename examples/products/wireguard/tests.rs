//! Conversations with wireguard-go, replayed: `scripts/check_wireguard.py`
//! recorded both sides with ours's random parts fixed, so each handshake
//! message ours writes must come out byte for byte, and every transport
//! message wireguard-go sealed must open.

use super::*;

use crate::fixtures;

fn key(record: &[(String, String)], name: &str) -> Key {
    fixed(fixtures::unhex(fixtures::field(record, name)), name).unwrap()
}

fn bytes(record: &[(String, String)], name: &str) -> Vec<u8> {
    match fixtures::field(record, name) {
        "-" => Vec::new(),
        text => fixtures::unhex(text),
    }
}

/// The transport messages each way, after a handshake.
fn check_transport(record: &[(String, String)], ours: &Session, name: &str) {
    for i in 0.. {
        let label = format!("plaintext-{i}");
        if !record.iter().any(|(k, _)| *k == label) {
            assert!(i >= 3, "{name}");
            break;
        }
        let padded = noise::pad(&bytes(record, &label), 1420);
        // Ours sealing with counter i gives what wireguard-go opened.
        assert_eq!(noise::seal_transport(ours, i, &padded), bytes(record, &format!("ours-{i}")),
                   "{name} ours-{i}");
        let (counter, plain) = noise::open_transport(ours, &bytes(record, &format!("theirs-{i}")))
            .unwrap();
        assert_eq!((counter, plain), (i, padded), "{name} theirs-{i}");
    }
}

#[test]
fn test_ours_initiating_replays() {
    let records = fixtures::records("wireguard.vec", "ours-initiating");
    assert!(records.len() >= 6);
    for r in records {
        let name = fixtures::field(&r, "name");
        let (a, b, psk) = (key(&r, "private"), key(&r, "peer-private"), key(&r, "psk"));
        let timestamp: [u8; 12] = fixed(bytes(&r, "timestamp"), "timestamp").unwrap();
        let index: u32 = fixtures::field(&r, "index").parse().unwrap();
        let (mut init, pending) = noise::create_initiation(&a, &noise::public_key(&b),
                                                           &key(&r, "ephemeral"), &timestamp,
                                                           index).unwrap();
        noise::add_macs(&mut init, &noise::public_key(&b), None);
        assert_eq!(init, bytes(&r, "initiation"), "{name}");
        let response = bytes(&r, "response");
        assert!(noise::check_mac1(&response, &noise::public_key(&a)), "{name}");
        let session = noise::consume_response(&response, &pending, &a, &psk).unwrap();
        check_transport(&r, &session, name);
        // A different preshared key does not complete it.
        let mut other = psk;
        other[0] ^= 1;
        assert!(noise::consume_response(&response, &pending, &a, &other).is_err());
    }
}

#[test]
fn test_theirs_initiating_replays() {
    let records = fixtures::records("wireguard.vec", "theirs-initiating");
    assert!(records.len() >= 6);
    for r in records {
        let name = fixtures::field(&r, "name");
        let (b, a, psk) = (key(&r, "private"), key(&r, "peer-private"), key(&r, "psk"));
        let init = bytes(&r, "initiation");
        assert!(noise::check_mac1(&init, &noise::public_key(&b)), "{name}");
        assert!(!noise::check_mac1(&init, &noise::public_key(&a)), "{name}");
        let seen = noise::consume_initiation(&init, &b).unwrap();
        assert_eq!(seen.peer_public, noise::public_key(&a), "{name}");
        let index: u32 = fixtures::field(&r, "index").parse().unwrap();
        let (mut response, session) = noise::create_response(&seen, &psk, &key(&r, "ephemeral"),
                                                             index).unwrap();
        noise::add_macs(&mut response, &noise::public_key(&a), None);
        assert_eq!(response, bytes(&r, "response"), "{name}");
        check_transport(&r, &session, name);

        // One bit of the initiation changed in transit.
        for byte in [10, 50, 100] {
            let mut bad = init.clone();
            bad[byte] ^= 1;
            assert!(noise::consume_initiation(&bad, &b).is_err(), "{name} byte {byte}");
        }
    }
}

#[test]
fn test_cookies_replay() {
    let records = fixtures::records("wireguard.vec", "cookie");
    assert!(records.len() >= 4);
    for r in records {
        let name = fixtures::field(&r, "name");
        let b = key(&r, "private");
        let secret: [u8; 32] = key(&r, "secret");
        let source = bytes(&r, "source");
        let init = bytes(&r, "initiation");
        // Ours's reply, with its recorded nonce, is what wireguard-go took.
        let reply = bytes(&r, "reply");
        let nonce: [u8; 24] = fixed(reply[8..32].to_vec(), "nonce").unwrap();
        assert_eq!(noise::cookie_reply(&init, &noise::public_key(&b), &secret, &source, &nonce),
                   reply, "{name}");
        // wireguard-go's retry carries a MAC2 ours accepts, from that
        // source and that secret only.
        let retry = bytes(&r, "retry");
        assert!(noise::check_mac2(&retry, &secret, &source), "{name}");
        assert!(!noise::check_mac2(&retry, &[0; 32], &source), "{name}");
        assert!(!noise::check_mac2(&init, &secret, &source), "{name}");
        // The reply opens with the initiation's MAC1, and with no other.
        let mac1: [u8; 16] = init[116..132].try_into().unwrap();
        let cookie = noise::open_cookie_reply(&reply, &noise::public_key(&b), &mac1).unwrap();
        assert_eq!(cookie, noise::cookie(&secret, &source), "{name}");
        assert!(noise::open_cookie_reply(&reply, &noise::public_key(&b), &[0; 16]).is_err());
    }
}

#[test]
fn test_a_wg_configuration() {
    let dir = std::env::temp_dir().join(format!("wg-conf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("wg0.conf");
    std::fs::write(&path, "[Interface]\n# a comment\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n\
                           ListenPort = 51820\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\n\
                           PresharedKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
                           AllowedIPs = 10.0.0.2/32\n").unwrap();
    let keys = read_config(path.to_str().unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    // The private key of wg(8)'s example configuration, and its public
    // key as python-cryptography's X25519 computes it.
    assert_eq!(base64::encode(&noise::public_key(&keys.private)),
               "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=");
    assert_eq!(base64::encode(&keys.peer), "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=");
    assert_eq!(keys.psk, [0; 32]);
}

#[test]
fn test_indices_are_checked() {
    let records = fixtures::records("wireguard.vec", "ours-initiating");
    let r = &records[0];
    let (a, b, psk) = (key(r, "private"), key(r, "peer-private"), key(r, "psk"));
    let timestamp: [u8; 12] = fixed(bytes(r, "timestamp"), "timestamp").unwrap();
    let index: u32 = fixtures::field(r, "index").parse().unwrap();
    let (_, pending) = noise::create_initiation(&a, &noise::public_key(&b), &key(r, "ephemeral"),
                                                &timestamp, index).unwrap();
    // A response naming another of our indices is not an answer to this
    // initiation.
    let wrong = Pending { sender: index ^ 1, ..pending.clone() };
    let reason = noise::consume_response(&bytes(r, "response"), &wrong, &a, &psk).unwrap_err();
    assert!(reason.contains("is for index"), "{reason}");

    let session = noise::consume_response(&bytes(r, "response"), &pending, &a, &psk).unwrap();
    let other = Session { local_index: session.local_index ^ 1, ..session.clone() };
    let reason = noise::open_transport(&other, &bytes(r, "theirs-0")).unwrap_err();
    assert!(reason.contains("is for index"), "{reason}");
}

/// `wg genkey` clamps: the low three bits clear, the top bit clear and the
/// next one set.
#[test]
fn test_generated_keys_are_clamped() {
    for _ in 0..32 {
        let key = noise::generate_private().unwrap();
        assert_eq!(key[0] & 7, 0);
        assert_eq!(key[31] & 0xc0, 0x40);
    }
}

fn run_args(args: &[&str]) -> Result<bool, String> {
    run(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

/// The command line end to end through state files, both sides ours:
/// a replayed initiation is refused by the timestamp, and a
/// configuration's first peer is the one used.
#[test]
fn test_the_command_line() {
    let dir = std::env::temp_dir().join(format!("wg-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let (a, b) = (noise::generate_private().unwrap(), noise::generate_private().unwrap());
    let (pa, pb) = (noise::public_key(&a), noise::public_key(&b));
    std::fs::write(path("a.conf"), format!(
        "[Interface]\nPrivateKey = {}\n[Peer]\nPublicKey = {}\n[Peer]\nPublicKey = {}\n",
        base64::encode(&a), base64::encode(&pb), base64::encode(&pa))).unwrap();

    let (sa, sb) = (path("a.state"), path("b.state"));
    let init = noise::create_initiation(&a, &pb, &[9; 32], &noise::tai64n(100, 0), 1).unwrap();
    let mut msg = init.0;
    noise::add_macs(&mut msg, &pb, None);
    let initiation = hex(&msg);
    let responder = ["respond", &initiation, "--state", &sb, "--private", &base64::encode(&b),
                     "--peer", &base64::encode(&pa)];
    assert!(run_args(&responder).unwrap());
    let reason = run_args(&responder).unwrap_err();
    assert!(reason.contains("not newer"), "{reason}");

    // The configuration's first peer is b, so this initiation is to b.
    assert!(run_args(&["initiate", "--state", &sa, "--config", &path("a.conf")]).unwrap());
    let state = State::read(&sa).unwrap();
    assert_eq!(state.key("peer").unwrap(), pb);
    std::fs::remove_dir_all(&dir).ok();
}
