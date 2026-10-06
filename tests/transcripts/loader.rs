// Reads tests/transcripts/handshakes.txt.
//
// Shared by the transcript tests with `include!`, because two integration
// test binaries cannot share a module any other way without a crate. That
// also means no `//!` comments in here: an included file is pasted inside
// a `mod`, and an inner doc comment cannot be.
//
// The file is line-based - "<field> <transcript> <value>" - rather than
// JSON, so this is `split` and not a hand-rolled scanner. The first version
// was JSON with a scanner, and the scanner picked the wrong field for the
// transcript name: every test passed and every failure message would have
// named the wrong handshake.

/// One captured handshake.
#[derive(Default, Clone)]
#[allow(dead_code)]
pub struct Transcript {
    pub name: String,
    pub version: String,
    pub cipher: String,
    pub to_server: Vec<u8>,
    pub to_client: Vec<u8>,
    /// `(label, client_random, secret)` from the key log - for TLS 1.2 the
    /// label is `CLIENT_RANDOM` and the secret is the master secret.
    pub secrets: Vec<(String, String, String)>,
}

#[allow(dead_code)]
fn unhex_bytes(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Read every transcript in the fixture.
#[allow(dead_code)]
pub fn load() -> Vec<Transcript> {
    // Cargo runs integration tests from the package root.
    load_from("tests/transcripts/handshakes.txt",
              "scripts/capture_transcripts.py")
}

/// The GOST captures, which live in their own file because their
/// generator is a different one - it needs OpenSSL's gost-engine, where
/// `capture_transcripts.py` needs only Python's `ssl`. Same format.
#[allow(dead_code)]
pub fn load_gost() -> Vec<Transcript> {
    load_from("tests/transcripts/gost_handshakes.txt",
              "scripts/capture_gost_transcripts.py")
}

/// TLS 1.3 handshakes with ML-DSA certificates, OpenSSL 3.5 at both ends.
/// Their own file for the same reason as the GOST ones.
#[allow(dead_code)]
pub fn load_mldsa() -> Vec<Transcript> {
    load_from("tests/transcripts/mldsa_handshakes.txt", "scripts/capture_mldsa.py")
}

/// Read one fixture file. `generator` is named in the error, because
/// "no such file" is only useful with the command that makes it.
#[allow(dead_code)]
fn load_from(path: &str, generator: &str) -> Vec<Transcript> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!(
        "{}: {} - run {}", path, e, generator));

    let mut transcripts: Vec<Transcript> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ' ');
        let (field, name, value) = match (parts.next(), parts.next(), parts.next()) {
            (Some(field), Some(name), Some(value)) => (field, name, value),
            _ => panic!("{}: malformed line {:?}", path, line),
        };

        if !transcripts.iter().any(|t| t.name == name) {
            transcripts.push(Transcript { name: name.to_string(), ..Default::default() });
        }
        let transcript = transcripts.iter_mut().find(|t| t.name == name).unwrap();
        match field {
            "version" => transcript.version = value.to_string(),
            "cipher" => transcript.cipher = value.to_string(),
            "to_server" => transcript.to_server = unhex_bytes(value),
            "to_client" => transcript.to_client = unhex_bytes(value),
            "secret" => {
                let mut pieces = value.splitn(3, ' ');
                match (pieces.next(), pieces.next(), pieces.next()) {
                    (Some(label), Some(random), Some(secret)) =>
                        transcript.secrets.push((label.to_string(),
                                                 random.to_string(),
                                                 secret.to_string())),
                    _ => panic!("{}: malformed secret line {:?}", path, line),
                }
            }
            other => panic!("{}: unknown field {:?}", path, other),
        }
    }

    assert!(!transcripts.is_empty(), "no transcripts in {}", path);
    for transcript in &transcripts {
        assert!(!transcript.to_server.is_empty() && !transcript.to_client.is_empty(),
                "{}: a direction is empty", transcript.name);
        assert!(!transcript.version.is_empty() && !transcript.cipher.is_empty(),
                "{}: missing version or cipher", transcript.name);
    }
    transcripts
}
