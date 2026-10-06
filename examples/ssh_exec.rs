//! Run one command over SSH with `allcrypt::ssh::client`, over a real
//! socket. A development tool: `scripts/check_ssh_client.py` uses it to
//! put the client in front of OpenSSH's `sshd` on loopback.
//!
//!     cargo run --example ssh_exec -- HOST PORT USER KEYFILE COMMAND \
//!         [kex=NAME] [cipher=NAME] [mac=NAME] [hostkey=NAME]
//!         [password=PW | password-stdin] [seed=N record=FILE]
//!
//! Prints the negotiated algorithms, then the command's output, and
//! exits with the command's exit status.
//!
//! With `seed`, every random byte the client uses comes from a counter
//! generator, so its side of the session is a function of what the server
//! sent; with `record`, both directions are written to FILE in the order
//! they crossed, for `tests/test_ssh_sessions.rs` to replay offline.

#[path = "products/shared/passphrase.rs"]
mod passphrase;

use allcrypt::ssh::client::{Auth, Client, ClientConfig, HostKeyCheck};
use allcrypt::ssh::private_key;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// SHA-256 of the seed and a counter, as a stream. Not a random number
/// generator anyone should use; a reproducible one, which is the point.
fn counter_stream(seed: u64) -> allcrypt::ssh::client::RandomSource {
    use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn leak(text: &str) -> &'static str {
    Box::leak(text.to_string().into_boxed_str())
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        return Err("usage: ssh_exec HOST PORT USER KEYFILE COMMAND [name=value ...]".into());
    }
    let mut config = ClientConfig::new(&args[3], HostKeyCheck::AcceptAny);
    if args[4] != "-" {
        let text = std::fs::read_to_string(&args[4]).map_err(|e| e.to_string())?;
        let (key, _) = private_key::read(&text, None)?;
        config.auth.push(Auth::PublicKey(key));
    }
    let mut seed = None;
    let mut record = None;
    for option in &args[6..] {
        if option == "password-stdin" {
            let password = String::from_utf8(passphrase::read_line("Password: ")?)
                .map_err(|_| "the password is not UTF-8")?;
            config.auth.push(Auth::Password(password));
            continue;
        }
        let (name, value) = option.split_once('=').ok_or("options are name=value")?;
        match name {
            "seed" => seed = Some(value.parse::<u64>().map_err(|e| e.to_string())?),
            "record" => record = Some(value.to_string()),
            "kex" => config.kex = vec![leak(value)],
            "cipher" => config.ciphers = vec![leak(value)],
            "mac" => config.macs = vec![leak(value)],
            "hostkey" => config.host_key_algorithms = vec![leak(value)],
            "password" => config.auth.push(Auth::Password(value.to_string())),
            other => return Err(format!("unknown option {other}")),
        }
    }
    let mut client = match seed {
        Some(seed) => Client::with_random(config, counter_stream(seed))?,
        None => Client::new(config)?,
    };
    client.exec(&args[5]);
    let mut transcript = String::new();

    let mut stream = TcpStream::connect((args[1].as_str(), args[2].parse::<u16>()
        .map_err(|e| e.to_string())?)).map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).map_err(|e| e.to_string())?;
    let mut buffer = vec![0u8; 65536];
    loop {
        let out = client.take_outgoing();
        if !out.is_empty() {
            transcript.push_str(&format!("C {}\n", hex(&out)));
            stream.write_all(&out).map_err(|e| e.to_string())?;
        }
        if client.closed() {
            break;
        }
        let n = stream.read(&mut buffer).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        transcript.push_str(&format!("S {}\n", hex(&buffer[..n])));
        client.push_incoming(&buffer[..n]);
        client.process()?;
        std::io::stdout().write_all(&client.take_stdout()).map_err(|e| e.to_string())?;
        std::io::stderr().write_all(&client.take_stderr()).map_err(|e| e.to_string())?;
    }
    let a = client.algorithms();
    eprintln!("negotiated: kex={} hostkey={} cipher={}/{} mac={:?}/{:?} strict={} hostkey-fp={}",
              a.kex, a.host_key, a.cipher_c2s, a.cipher_s2c, a.mac_c2s, a.mac_s2c,
              client.strict_kex(),
              client.host_key().map(|k| k.fingerprint_sha256()).unwrap_or_default());
    if let Some(path) = record {
        std::fs::write(&path, transcript).map_err(|e| e.to_string())?;
    }
    std::process::exit(client.exit_status().map(|s| s as i32).unwrap_or(255));
}
