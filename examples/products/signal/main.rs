//! The Signal protocol - X3DH, the Double Ratchet and sender keys, in
//! libsignal's version 3 wire format - built from this library's
//! primitives.
//!
//!     cargo run --release --example signal -- demo
//!     cargo run --release --example signal -- agent SEED REGISTRATION_ID NAME PEER
//!
//! `demo` runs a conversation between two parties in one process and
//! prints what crosses the wire. `agent` reads commands on standard
//! input and answers on standard output, in the line protocol of
//! `scripts/witness/signalwitness`, which is libsignal-protocol-c
//! answering the same commands; `scripts/check_signal.py` puts the two
//! on either side of the same conversations. SEED is hex, and the agent
//! draws every random byte from the stream it names, as the witness
//! does, so the two produce the same bytes from the same seed.
//!
//! What has checked it is in `examples/products/README.md`.

mod agent;
mod group;
mod proto;
mod rng;
mod session;
mod wire;

#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

use std::io::{BufRead, Write};

use agent::{hex, Agent};
use rng::Random;
use session::Party;
use wire::Error;

fn describe(kind: u32) -> &'static str {
    match kind {
        wire::PREKEY_TYPE => "prekey message",
        wire::SIGNAL_TYPE => "message",
        wire::SENDERKEY_TYPE => "group message",
        _ => "unknown",
    }
}

fn demo() -> Result<(), Error> {
    let mut alice = Party::new(Random::system(), 1001)?;
    let mut bob = Party::new(Random::system(), 2002)?;
    println!("alice identity {}", hex(&alice.identity.public.serialize()));
    println!("bob   identity {}", hex(&bob.identity.public.serialize()));

    let bundle = bob.publish(1, 1)?;
    println!("bob publishes prekey 1 and signed prekey 1");
    alice.process_bundle("bob", &bundle)?;
    println!("alice verifies the signed prekey and runs X3DH\n");

    let say = |from: &mut Party, to: &mut Party, names: (&str, &str), text: &str|
                   -> Result<(u32, Vec<u8>), Error> {
        let (kind, bytes) = from.encrypt(names.1, text.as_bytes())?;
        println!("{} -> {}  {}, {} bytes", names.0, names.1, describe(kind), bytes.len());
        let plaintext = to.decrypt(names.0, kind, &bytes)?;
        println!("    {} reads {:?}", names.1, String::from_utf8_lossy(&plaintext));
        Ok((kind, bytes))
    };
    say(&mut alice, &mut bob, ("alice", "bob"), "Hello, Bob.")?;
    println!("    bob's session records alice's registration id, {}",
             bob.remote_registration_id("alice").unwrap_or(0));
    say(&mut alice, &mut bob, ("alice", "bob"), "Are you there?")?;
    say(&mut bob, &mut alice, ("bob", "alice"), "Hi Alice - a new ratchet key with this one.")?;
    say(&mut alice, &mut bob, ("alice", "bob"), "Now plain messages, no prekey header.")?;

    println!("\nbob sends three; they arrive 3, 1, 2");
    let mut sent = Vec::new();
    for text in ["one", "two", "three"] {
        sent.push(bob.encrypt("alice", text.as_bytes())?);
    }
    for at in [2, 0, 1] {
        let (kind, bytes) = &sent[at];
        let plaintext = alice.decrypt("bob", *kind, bytes)?;
        println!("    alice reads {:?}", String::from_utf8_lossy(&plaintext));
    }
    let (kind, bytes) = &sent[0];
    println!("    again: {}", alice.decrypt("bob", *kind, bytes).unwrap_err());

    println!("\na group: alice distributes her sender key to bob");
    let distribution = alice.groups.distribution(&mut alice.random, "friends", "alice")?;
    bob.groups.process("friends", "alice", &distribution)?;
    let message = alice.groups.encrypt(&mut alice.random, "friends", "alice",
                                       b"One ciphertext for everyone.")?;
    println!("alice -> group  {}, {} bytes, signed", describe(wire::SENDERKEY_TYPE),
             message.len());
    let plaintext = bob.groups.decrypt("friends", "alice", &message)?;
    println!("    bob reads {:?}", String::from_utf8_lossy(&plaintext));
    Ok(())
}

fn agent(args: &[String]) -> Result<(), String> {
    let [seed, registration_id, name, peer] = args else {
        return Err("usage: agent SEED REGISTRATION_ID NAME PEER".to_string());
    };
    let seed = (0..seed.len()).step_by(2)
        .map(|i| seed.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .ok_or("SEED is hex")?;
    let registration_id = registration_id.parse().map_err(|_| "REGISTRATION_ID is a number")?;
    let mut agent = Agent::new(Random::seeded(&seed), registration_id, name, peer)
        .map_err(|e| e.to_string())?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        writeln!(out, "{}", agent.run(&line)).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("demo") => demo().map_err(|e| e.to_string()),
        Some("agent") => agent(&args[1..]),
        _ => Err("usage: signal demo | signal agent SEED REGISTRATION_ID NAME PEER".to_string()),
    };
    if let Err(error) = result {
        eprintln!("signal: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Every conversation `scripts/check_signal.py --record` captured
    /// between two copies of libsignal-protocol-c, replayed with this
    /// implementation on both sides: each command must get the reply
    /// libsignal gave, byte for byte - ciphertexts, bundles, signatures
    /// and error codes alike. Both sides are seeded as the witnesses
    /// were, so a single extra or missing random draw anywhere shows as
    /// the first reply that differs.
    #[test]
    fn test_libsignals_conversations_replay_byte_for_byte() {
        let conversations = fixtures::records("signal.vec", "conversation");
        assert_eq!(conversations.len(), 11);
        let mut steps = 0;
        for record in &conversations {
            let title = fixtures::field(record, "name");
            let mut agents: HashMap<String, Agent> = HashMap::new();
            let mut pending: Option<(String, String)> = None;
            for (key, value) in record {
                match key.as_str() {
                    "party" => {
                        let words: Vec<&str> = value.split(' ').collect();
                        let seed = fixtures::unhex(words[1]);
                        let agent = Agent::new(Random::seeded(&seed), words[2].parse().unwrap(),
                                               words[3], words[4]).unwrap();
                        agents.insert(words[0].to_string(), agent);
                    }
                    "send" => {
                        let (who, command) = value.split_once(' ').unwrap();
                        pending = Some((who.to_string(), command.to_string()));
                    }
                    "reply" => {
                        let (who, command) = pending.take().expect("a reply follows a send");
                        let reply = agents.get_mut(&who).unwrap().run(&command);
                        assert_eq!(&reply, value, "{title}: {who} {}",
                                   &command[..command.len().min(60)]);
                        steps += 1;
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(steps, 463);
    }

    /// A conversation with the system's randomness, which the replays
    /// cannot have: nothing about it is fixed in advance.
    #[test]
    fn test_a_conversation_with_fresh_randomness() {
        let mut alice = Party::new(Random::system(), 1).unwrap();
        let mut bob = Party::new(Random::system(), 2).unwrap();
        let bundle = bob.publish(5, 6).unwrap();
        alice.process_bundle("bob", &bundle).unwrap();

        let (kind, first) = alice.encrypt("bob", b"first").unwrap();
        assert_eq!(kind, wire::PREKEY_TYPE);
        let (_, second) = alice.encrypt("bob", b"second").unwrap();
        // Out of order, and the prekey message's session is built once.
        assert_eq!(bob.decrypt("alice", kind, &second).unwrap(), b"second");
        assert_eq!(bob.decrypt("alice", kind, &first).unwrap(), b"first");
        assert_eq!(bob.decrypt("alice", kind, &first).unwrap_err(), Error::DUPLICATE_MESSAGE);

        let (kind, reply) = bob.encrypt("alice", b"reply").unwrap();
        assert_eq!(kind, wire::SIGNAL_TYPE);
        assert_eq!(alice.decrypt("bob", kind, &reply).unwrap(), b"reply");
        // Answered, so Alice stops sending prekey messages.
        assert_eq!(alice.encrypt("bob", b"x").unwrap().0, wire::SIGNAL_TYPE);
    }

    /// A message for one peer does not decrypt as another, and a flipped
    /// bit anywhere in it is refused rather than decrypted to something.
    #[test]
    fn test_tampering_is_refused() {
        let mut alice = Party::new(Random::system(), 1).unwrap();
        let mut bob = Party::new(Random::system(), 2).unwrap();
        let bundle = bob.publish(1, 1).unwrap();
        alice.process_bundle("bob", &bundle).unwrap();
        let (kind, message) = alice.encrypt("bob", b"hello").unwrap();
        bob.decrypt("alice", kind, &message).unwrap();
        let (kind, message) = bob.encrypt("alice", b"tamper with me").unwrap();
        for at in (1..message.len()).step_by(7) {
            let mut bad = message.clone();
            bad[at] ^= 0x10;
            assert!(alice.decrypt("bob", kind, &bad).is_err(), "byte {at}");
        }
        assert_eq!(alice.decrypt("carol", kind, &message).unwrap_err(), Error::NO_SESSION);
        assert_eq!(alice.decrypt("bob", kind, &message).unwrap(), b"tamper with me");
    }

    #[test]
    fn test_a_bundle_with_a_bad_signature_is_refused() {
        let mut alice = Party::new(Random::system(), 1).unwrap();
        let mut bob = Party::new(Random::system(), 2).unwrap();
        let mut bundle = bob.publish(1, 1).unwrap();
        bundle.signature[10] ^= 1;
        assert_eq!(alice.process_bundle("bob", &bundle).unwrap_err(), Error::INVALID_KEY);
        assert_eq!(alice.encrypt("bob", b"x").unwrap_err(), Error::UNKNOWN);
    }
}
