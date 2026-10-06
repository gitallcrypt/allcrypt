//! An SSH server on loopback with `allcrypt::ssh::server`. A development
//! tool: `scripts/check_ssh_server.py` puts OpenSSH's `ssh` in front of
//! it.
//!
//!     cargo run --release --example ssh_serve -- PORT HOSTKEY[,HOSTKEY...] \
//!         [authorized=FILE] [user=NAME] [password=PW | password-stdin] \
//!         [kex=LIST] [cipher=LIST] [mac=LIST] [hostkey=LIST] \
//!         [run=builtin|sh] [once] [seed=N record=FILE]
//!
//! `HOSTKEY` files are `openssh-key-v1`, as `ssh-keygen` writes them.
//! `authorized` is an `authorized_keys` file whose keys may log in as
//! `user` (default `allcrypt`); `password` is accepted for that user too.
//! The algorithm options are comma-separated lists, or `all` for every
//! entry of the table, the legacy ones included; without them the
//! server offers the library's defaults.
//!
//! What a command does: with `run=builtin` (the default), a few commands
//! the server answers itself, so that a session's output depends only on
//! what the client sent - `echo ARGS`, `stderr ARGS` (to standard error),
//! `exit N`, joined with `;`; `cat`, which echoes standard input as it
//! arrives; and `sha256sum`, which prints the SHA-256 of standard input
//! the way coreutils does. With `run=sh`, the command goes to `sh -c`
//! once its standard input is complete, and the output goes back when it
//! has finished: no terminal and nothing interactive.
//!
//! With `once`, the server exits after one connection, with 0 if that
//! session ended with both CLOSEs and 1 otherwise. With `seed`, every
//! random byte the server uses comes from a counter generator, so its
//! side of the session is a function of what the client sent; with
//! `record`, both directions are written to FILE in the order they
//! crossed, for `tests/test_ssh_server_sessions.rs` to replay offline.
//!
//! Only 127.0.0.1 is listened on, and only one connection is served at
//! a time.

#[path = "products/shared/passphrase.rs"]
mod passphrase;

use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::ssh::server::{Server, ServerConfig, SessionRequest};
use allcrypt::ssh::{cipher, kex, keys, mac, private_key};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// SHA-256 of the seed and a counter, as a stream - the same generator
/// as `examples/ssh_exec.rs`. Reproducible, which is the point, and not
/// random.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A name list option: `all` for the whole table, else the names given,
/// each looked up so that the `&'static str` the config holds is the
/// table's own.
fn names(value: &str, table: &[&'static str]) -> Result<Vec<&'static str>, String> {
    if value == "all" {
        return Ok(table.to_vec());
    }
    value.split(',').map(|name| table.iter().find(|known| **known == name).copied()
        .ok_or_else(|| format!("unknown algorithm {name}"))).collect()
}

const HOST_KEY_ALGORITHMS: [&str; 8] = [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"];

/// The commands `run=builtin` answers. `finished` once the exit status
/// has been handed over.
struct Builtin {
    finished: bool,
}

impl Builtin {
    /// Act on what the session has asked so far. Called after every
    /// `process`, which is what makes the server's output a function of
    /// the bytes received and nothing else.
    fn step(&mut self, server: &mut Server) -> Result<(), String> {
        let Some(request) = server.request().cloned() else {
            return Ok(());
        };
        let input = server.take_stdin()?;
        if self.finished {
            return Ok(());
        }
        let command = match request {
            SessionRequest::Exec(command) => command,
            SessionRequest::Shell => {
                self.finished = true;
                server.write_stderr(b"ssh_serve: no shell here; give a command\n")?;
                return server.finish(1);
            }
        };
        match command.trim() {
            "cat" => {
                if !input.is_empty() {
                    server.write(&input)?;
                }
                if server.stdin_closed() {
                    self.finished = true;
                    server.finish(0)?;
                }
                Ok(())
            }
            line => {
                self.finished = true;
                let mut status = 0;
                for part in line.split(';').map(str::trim).filter(|p| !p.is_empty()) {
                    let (word, rest) = part.split_once(' ').unwrap_or((part, ""));
                    match word {
                        "echo" => server.write(format!("{rest}\n").as_bytes())?,
                        "stderr" => server.write_stderr(format!("{rest}\n").as_bytes())?,
                        "exit" => {
                            status = rest.trim().parse().unwrap_or(255);
                            break;
                        }
                        other => {
                            server.write_stderr(format!("ssh_serve: unknown command: {other}\n")
                                                .as_bytes())?;
                            status = 127;
                            break;
                        }
                    }
                }
                server.finish(status)
            }
        }
    }
}

/// `sha256sum` and `run=sh`: both need all of standard input first.
struct Buffered {
    input: Vec<u8>,
    finished: bool,
    shell: bool,
}

impl Buffered {
    fn step(&mut self, server: &mut Server) -> Result<(), String> {
        let Some(request) = server.request().cloned() else {
            return Ok(());
        };
        self.input.extend_from_slice(&server.take_stdin()?);
        if self.finished || !server.stdin_closed() {
            return Ok(());
        }
        self.finished = true;
        if !self.shell {
            let digest = SHA256::new(&self.input).digest();
            server.write(format!("{}  -\n", hex(&digest)).as_bytes())?;
            return server.finish(0);
        }
        let mut command = std::process::Command::new("sh");
        if let SessionRequest::Exec(text) = &request {
            command.arg("-c").arg(text);
        }
        let mut child = command.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().map_err(|e| e.to_string())?;
        let mut stdin = child.stdin.take().ok_or("stdin")?;
        let input = std::mem::take(&mut self.input);
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = child.wait_with_output().map_err(|e| e.to_string())?;
        let _ = writer.join();
        server.write(&output.stdout)?;
        server.write_stderr(&output.stderr)?;
        server.finish(output.status.code().unwrap_or(255) as u32)
    }
}

enum App {
    Builtin(Builtin),
    Buffered(Buffered),
}

impl App {
    fn step(&mut self, server: &mut Server, shell: bool) -> Result<(), String> {
        if let App::Builtin(builtin) = self {
            let wants_all_input = shell || matches!(server.request(),
                Some(SessionRequest::Exec(command)) if command.trim() == "sha256sum");
            if wants_all_input {
                *self = App::Buffered(Buffered { input: Vec::new(), finished: false, shell });
            } else {
                return builtin.step(server);
            }
        }
        match self {
            App::Buffered(buffered) => buffered.step(server),
            App::Builtin(_) => Ok(()),
        }
    }
}

struct Options {
    config_args: Vec<(String, String)>,
    shell: bool,
    once: bool,
    seed: Option<u64>,
    record: Option<String>,
}

fn config(host_key_files: &str, options: &Options) -> Result<ServerConfig, String> {
    let mut host_keys = Vec::new();
    for path in host_key_files.split(',') {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        host_keys.push(private_key::read(&text, None)?.0);
    }
    let mut config = ServerConfig::new(host_keys);
    let mut user = "allcrypt".to_string();
    let mut authorized = None;
    let mut password = None;
    let kex_table: Vec<&'static str> = kex::METHODS.iter().map(|m| m.name).collect();
    let cipher_table: Vec<&'static str> = cipher::CIPHERS.iter().map(|c| c.name)
        .filter(|name| *name != "none").collect();
    let mac_table: Vec<&'static str> = mac::MACS.iter().map(|m| m.name).collect();
    for (name, value) in &options.config_args {
        match name.as_str() {
            "user" => user = value.clone(),
            "authorized" => authorized = Some(value.clone()),
            "password" => password = Some(value.clone()),
            "kex" => config.kex = names(value, &kex_table)?,
            "cipher" => config.ciphers = names(value, &cipher_table)?,
            "mac" => config.macs = names(value, &mac_table)?,
            "hostkey" => config.host_key_algorithms = names(value, &HOST_KEY_ALGORITHMS)?,
            other => return Err(format!("unknown option {other}")),
        }
    }
    if let Some(path) = authorized {
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
        for line in text.lines().filter(|l| !l.trim().is_empty() && !l.starts_with('#')) {
            config.authorize_key(&user, keys::parse_line(line)?.key);
        }
    }
    if let Some(password) = password {
        config.authorize_password(&user, &password);
    }
    Ok(config)
}

/// One connection, start to end. Returns whether the session closed
/// properly, and the transcript.
fn serve(stream: &mut TcpStream, mut server: Server, shell: bool)
         -> Result<(bool, String), String> {
    stream.set_read_timeout(Some(Duration::from_secs(60))).map_err(|e| e.to_string())?;
    let mut app = App::Builtin(Builtin { finished: false });
    let mut transcript = String::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        let out = server.take_outgoing();
        if !out.is_empty() {
            transcript.push_str(&format!("S {}\n", hex(&out)));
            if let Err(error) = stream.write_all(&out) {
                eprintln!("ssh_serve: write: {error}");
                break;
            }
        }
        let n = match stream.read(&mut buffer) {
            Ok(n) => n,
            Err(error) => {
                eprintln!("ssh_serve: read: {error}");
                break;
            }
        };
        if n == 0 {
            break;
        }
        transcript.push_str(&format!("C {}\n", hex(&buffer[..n])));
        server.push_incoming(&buffer[..n]);
        let step = server.process().and_then(|()| app.step(&mut server, shell));
        if let Err(error) = step {
            eprintln!("ssh_serve: {error}");
            let out = server.take_outgoing();
            transcript.push_str(&format!("S {}\n", hex(&out)));
            let _ = stream.write_all(&out);
            return Ok((false, transcript));
        }
    }
    let a = server.algorithms();
    eprintln!("ssh_serve: client={} kex={} hostkey={} cipher={}/{} mac={:?}/{:?} strict={} \
               exchanges={} user={:?} auth={:?} terminal={:?} request={:?} closed={}",
              String::from_utf8_lossy(server.client_version()), a.kex, a.host_key,
              a.cipher_c2s, a.cipher_s2c, a.mac_c2s, a.mac_s2c, server.strict_kex(),
              server.key_exchanges(), server.user(), server.auth_method(),
              server.terminal().map(|t| format!("{}:{}x{}", t.term, t.columns, t.rows)),
              server.request(),
              server.closed());
    Ok((server.closed(), transcript))
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        return Err("usage: ssh_serve PORT HOSTKEY[,HOSTKEY...] [name=value ...] [once]".into());
    }
    let mut options = Options { config_args: Vec::new(), shell: false, once: false,
                                seed: None, record: None };
    for option in &args[3..] {
        if option == "once" {
            options.once = true;
            continue;
        }
        if option == "password-stdin" {
            // Read once, before listening: `config` runs per connection.
            let password = String::from_utf8(passphrase::read_line("Password: ")?)
                .map_err(|_| "the password is not UTF-8")?;
            options.config_args.push(("password".to_string(), password));
            continue;
        }
        let (name, value) = option.split_once('=').ok_or("options are name=value")?;
        match name {
            "seed" => options.seed = Some(value.parse().map_err(|e| format!("seed: {e}"))?),
            "record" => options.record = Some(value.to_string()),
            "run" => options.shell = match value {
                "sh" => true,
                "builtin" => false,
                other => return Err(format!("run={other}: builtin or sh")),
            },
            _ => options.config_args.push((name.to_string(), value.to_string())),
        }
    }
    let port: u16 = args[1].parse().map_err(|e| format!("port: {e}"))?;
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    eprintln!("ssh_serve: listening on 127.0.0.1:{port}");
    for stream in listener.incoming() {
        let mut stream = stream.map_err(|e| e.to_string())?;
        let config = config(&args[2], &options)?;
        let server = match options.seed {
            Some(seed) => Server::with_random(config, counter_stream(seed))?,
            None => Server::new(config)?,
        };
        let (closed, transcript) = serve(&mut stream, server, options.shell)?;
        if let Some(path) = &options.record {
            std::fs::write(path, transcript).map_err(|e| e.to_string())?;
        }
        if options.once {
            std::process::exit(if closed { 0 } else { 1 });
        }
    }
    Ok(())
}
