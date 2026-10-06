//! Writes SSH keys, encrypted key files and SSHSIG signatures made by
//! this library into a directory, for `scripts/check_ssh_witness.py` to
//! hand to OpenSSH's `ssh-keygen`. The reverse of
//! `vectors/ssh_keys.vec`, which is OpenSSH's files read by us.
//!
//!     cargo run --example ssh_write_keys -- <directory>

use allcrypt::ssh::cipher::CIPHERS;
use allcrypt::ssh::private_key::{self, Encryption, PrivateKey};
use allcrypt::ssh::signature::sshsig_sign;
use std::fs;
use std::path::Path;

fn main() -> Result<(), String> {
    let directory = std::env::args().nth(1).ok_or("usage: ssh_write_keys <directory>")?;
    let directory = Path::new(&directory);
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;

    let mut keys = Vec::new();
    for (name, kind, bits) in [("ed25519", "ed25519", None), ("ecdsa256", "ecdsa", Some(256)),
                               ("ecdsa384", "ecdsa", Some(384)), ("ecdsa521", "ecdsa", Some(521)),
                               ("rsa1024", "rsa", Some(1024)), ("rsa2048", "rsa", Some(2048)),
                               ("dsa1024", "dsa", None)] {
        keys.push((name.to_string(), PrivateKey::generate(kind, bits)?));
    }

    let write = |name: &str, text: &str| -> Result<(), String> {
        let path = directory.join(name);
        fs::write(&path, text).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    };
    for (name, key) in &keys {
        write(&format!("{name}.pub"), &(key.public().to_openssh(name) + "\n"))?;
        write(&format!("{name}--none"), &private_key::write(key, name, None)?)?;
        for spec in CIPHERS.iter().filter(|spec| spec.name != "none") {
            let encryption = Encryption { cipher: spec.name, passphrase: b"pw", rounds: 4 };
            write(&format!("{name}--{}", spec.name),
                  &private_key::write(key, name, Some(&encryption))?)?;
        }
        for hash in ["sha512", "sha256"] {
            write(&format!("{name}.{hash}.sig"),
                  &sshsig_sign(key, "file", b"allcrypt\n", hash)?)?;
        }
    }
    println!("wrote {} keys into {}", keys.len(), directory.display());
    Ok(())
}
