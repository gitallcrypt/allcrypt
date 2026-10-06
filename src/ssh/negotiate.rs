/*
KEXINIT and what follows from it: the message both sides send, the
algorithms both arrive at, and the six keys of RFC 4253 7.2 once the
key exchange has produced `K` and `H`. Shared by `client` and `server`.

# Pitfalls

**The client's order decides, on both ends.** RFC 4253 7.1: in every
category the algorithm is the first on the *client's* list that is also
on the server's. The server's own preference counts only in what it
lists at all. A server that picks its favourite from the overlap reaches
a different answer than the client computes from the same two messages,
and the connection fails at the first encrypted packet - or, if both
happen to agree for the usual client, at the first unusual one.

**An authenticated cipher takes no MAC.** With `chacha20-poly1305` or
AES-GCM the MAC lists are not consulted at all (OpenSSH's
`choose_enc`/`choose_mac`), so MAC lists with nothing in common do not
fail the exchange. The decision is per direction.

**The markers in the key exchange list are not algorithms.**
`ext-info-c`, `ext-info-s` and `kex-strict-*-v00@openssh.com` ride in
the key exchange name-list of the first KEXINIT. Neither side lists the
other's marker, so none can be chosen - but each side must look for the
other's in the list it received, not in its own.

**`first_kex_packet_follows` is right only if both firsts match.** The
sender guessed the method and the host key algorithm; the guess counts
only if the negotiated pair is the sender's first of each. A wrong guess
is one packet the receiver discards without reading.
*/

use super::cipher::{self, Cipher};
use super::kex::{self, SharedSecret};
use super::mac::{self, Mac};
use super::msg;
use super::transport::Keys;
use super::wire::{Reader, Writer};

pub const STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";
pub const EXT_INFO_CLIENT: &str = "ext-info-c";

/// The host key algorithms offered by default, in preference order:
/// the non-legacy ones. `ssh-rsa` (SHA-1) and `ssh-dss` are reached by
/// naming them.
pub const HOST_KEY_ALGORITHMS: [&str; 6] = [
    "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "rsa-sha2-512", "rsa-sha2-256"];

pub const CIPHERS: [&str; 6] = [
    "chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "aes256-ctr", "aes192-ctr", "aes128-ctr"];

pub const MACS: [&str; 4] = [
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512"];

/// The non-legacy key exchange methods, in `kex::METHODS` order.
pub fn default_kex() -> Vec<&'static str> {
    kex::METHODS.iter().filter(|m| !m.legacy).map(|m| m.name).collect()
}

/// Which end of the connection this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

/// What was negotiated.
#[derive(Clone, Debug, Default)]
pub struct Algorithms {
    pub kex: String,
    pub host_key: String,
    pub cipher_c2s: String,
    pub cipher_s2c: String,
    pub mac_c2s: Option<String>,
    pub mac_s2c: Option<String>,
}

/// A KEXINIT payload, without compression (only `none`) or languages
/// (none), and with no guessed packet following.
pub fn encode(cookie: &[u8; 16], kex: &[&str], host_key: &[&str], ciphers: &[&str],
              macs: &[&str]) -> Result<Vec<u8>, String> {
    let mut writer = Writer::new();
    writer.byte(msg::KEXINIT).raw(cookie);
    writer.name_list(kex)?
        .name_list(host_key)?
        .name_list(ciphers)?
        .name_list(ciphers)?
        .name_list(macs)?
        .name_list(macs)?
        .name_list(&["none"])?
        .name_list(&["none"])?
        .name_list(&[])?
        .name_list(&[])?;
    writer.boolean(false).uint32(0);
    Ok(writer.finish())
}

/// A KEXINIT as received: the name-lists, borrowed from the payload.
pub struct KexInit<'a> {
    pub kex: Vec<&'a str>,
    pub host_key: Vec<&'a str>,
    pub ciphers_c2s: Vec<&'a str>,
    pub ciphers_s2c: Vec<&'a str>,
    pub macs_c2s: Vec<&'a str>,
    pub macs_s2c: Vec<&'a str>,
    pub compression_c2s: Vec<&'a str>,
    pub compression_s2c: Vec<&'a str>,
    pub first_kex_follows: bool,
}

impl<'a> KexInit<'a> {
    /// `payload` starts with the message number.
    pub fn parse(payload: &'a [u8]) -> Result<KexInit<'a>, String> {
        let mut reader = Reader::new(payload.get(1..).ok_or("SSH: an empty KEXINIT.")?);
        let _cookie = reader.bytes(16)?;
        let kex = reader.name_list()?;
        let host_key = reader.name_list()?;
        let ciphers_c2s = reader.name_list()?;
        let ciphers_s2c = reader.name_list()?;
        let macs_c2s = reader.name_list()?;
        let macs_s2c = reader.name_list()?;
        let compression_c2s = reader.name_list()?;
        let compression_s2c = reader.name_list()?;
        let _languages_c2s = reader.name_list()?;
        let _languages_s2c = reader.name_list()?;
        let first_kex_follows = reader.boolean()?;
        let _reserved = reader.uint32()?;
        Ok(KexInit { kex, host_key, ciphers_c2s, ciphers_s2c, macs_c2s, macs_s2c,
                     compression_c2s, compression_s2c, first_kex_follows })
    }

    /// Whether the packet this KEXINIT said would follow is to be read:
    /// the sender's first method and host key algorithm were the ones
    /// negotiated. `false` when no packet follows.
    pub fn guess_is_wrong(&self, chosen: &Algorithms) -> bool {
        self.first_kex_follows
            && (self.kex.first() != Some(&chosen.kex.as_str())
                || self.host_key.first() != Some(&chosen.host_key.as_str()))
    }
}

fn choose<'a>(client: &[&'a str], server: &[&str], what: &str) -> Result<&'a str, String> {
    client.iter().find(|name| server.contains(name)).copied().ok_or_else(|| format!(
        "SSH: no {what} in common. The client offers {}; the server offers {}.",
        client.join(","), server.join(",")))
}

/// RFC 4253 7.1, from the two KEXINITs.
pub fn negotiate(client: &KexInit<'_>, server: &KexInit<'_>) -> Result<Algorithms, String> {
    let kex_name = choose(&client.kex, &server.kex, "key exchange")?;
    let host_key = choose(&client.host_key, &server.host_key, "host key algorithm")?;
    let c2s = choose(&client.ciphers_c2s, &server.ciphers_c2s, "cipher (client to server)")?;
    let s2c = choose(&client.ciphers_s2c, &server.ciphers_s2c, "cipher (server to client)")?;
    let pick_mac = |cipher: &str, ours: &[&str], theirs: &[&str]|
                    -> Result<Option<String>, String> {
        if cipher::lookup(cipher)?.tag_len > 0 {
            Ok(None)
        } else {
            Ok(Some(choose(ours, theirs, "MAC")?.to_string()))
        }
    };
    let mac_c2s = pick_mac(c2s, &client.macs_c2s, &server.macs_c2s)?;
    let mac_s2c = pick_mac(s2c, &client.macs_s2c, &server.macs_s2c)?;
    for (ours, theirs) in [(&client.compression_c2s, &server.compression_c2s),
                           (&client.compression_s2c, &server.compression_s2c)] {
        if choose(ours, theirs, "compression").ok() != Some("none") {
            return Err("SSH: the peer requires compression, which this library does \
                        not do.".to_string());
        }
    }
    // Both ends look the method up before using it; an unknown one here
    // means a list held a name no table has.
    kex::lookup(kex_name)?;
    Ok(Algorithms {
        kex: kex_name.to_string(),
        host_key: host_key.to_string(),
        cipher_c2s: c2s.to_string(),
        cipher_s2c: s2c.to_string(),
        mac_c2s,
        mac_s2c,
    })
}

/// The six keys of RFC 4253 7.2 as this side's protection:
/// `(sending, receiving)`. The client sends with A, C, E and the server
/// with B, D, F.
pub fn derive_keys(hash: &str, shared: &SharedSecret, h: &[u8], session_id: &[u8],
                   algorithms: &Algorithms, side: Side) -> Result<(Keys, Keys), String> {
    let make = |cipher_name: &str, mac_name: &Option<String>, letters: [u8; 3], sending: bool|
               -> Result<Keys, String> {
        let spec = cipher::lookup(cipher_name)?;
        let iv = kex::derive(hash, shared, h, letters[0], session_id, spec.iv_len)?;
        let key = kex::derive(hash, shared, h, letters[1], session_id, spec.key_len)?;
        let mac = match mac_name {
            Some(name) => {
                let mac_spec = mac::lookup(name)?;
                let mac_key = kex::derive(hash, shared, h, letters[2], session_id,
                                          mac_spec.key_len)?;
                Some(Mac::new(name, &mac_key)?)
            }
            None => None,
        };
        Ok(Keys { cipher: Cipher::new(cipher_name, &key, &iv, sending)?, mac })
    };
    let client = side == Side::Client;
    let c2s = make(&algorithms.cipher_c2s, &algorithms.mac_c2s, *b"ACE", client)?;
    let s2c = make(&algorithms.cipher_s2c, &algorithms.mac_s2c, *b"BDF", !client)?;
    Ok(if client { (c2s, s2c) } else { (s2c, c2s) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kexinit(kex: &[&str], ciphers: &[&str], macs: &[&str]) -> Vec<u8> {
        encode(&[0; 16], kex, &["ssh-ed25519"], ciphers, macs).unwrap()
    }

    /// The client's order wins even where the server lists the same two
    /// the other way round.
    #[test]
    fn test_the_clients_order_decides() {
        let client = kexinit(&["curve25519-sha256", "ecdh-sha2-nistp256"],
                             &["aes128-ctr", "aes256-ctr"], &["hmac-sha2-256", "hmac-sha2-512"]);
        let server = kexinit(&["ecdh-sha2-nistp256", "curve25519-sha256"],
                             &["aes256-ctr", "aes128-ctr"], &["hmac-sha2-512", "hmac-sha2-256"]);
        let chosen = negotiate(&KexInit::parse(&client).unwrap(),
                               &KexInit::parse(&server).unwrap()).unwrap();
        assert_eq!(chosen.kex, "curve25519-sha256");
        assert_eq!(chosen.cipher_c2s, "aes128-ctr");
        assert_eq!(chosen.mac_s2c.as_deref(), Some("hmac-sha2-256"));
    }

    /// AES-GCM takes no MAC, so MAC lists with nothing in common do not
    /// matter; with a CTR cipher they do.
    #[test]
    fn test_an_aead_cipher_skips_the_mac() {
        let client = kexinit(&["curve25519-sha256"], &["aes128-gcm@openssh.com"], &["hmac-md5"]);
        let server = kexinit(&["curve25519-sha256"], &["aes128-gcm@openssh.com"],
                             &["hmac-sha2-256"]);
        let chosen = negotiate(&KexInit::parse(&client).unwrap(),
                               &KexInit::parse(&server).unwrap()).unwrap();
        assert_eq!(chosen.mac_c2s, None);

        let client = kexinit(&["curve25519-sha256"], &["aes128-ctr"], &["hmac-md5"]);
        let server = kexinit(&["curve25519-sha256"], &["aes128-ctr"], &["hmac-sha2-256"]);
        let error = negotiate(&KexInit::parse(&client).unwrap(),
                              &KexInit::parse(&server).unwrap()).unwrap_err();
        assert!(error.contains("no MAC in common"), "{error}");
    }

    /// The markers never negotiate, even listed first.
    #[test]
    fn test_markers_are_not_methods() {
        let client = kexinit(&[EXT_INFO_CLIENT, STRICT_CLIENT, "curve25519-sha256"],
                             &["aes128-ctr"], &["hmac-sha2-256"]);
        let server = kexinit(&[STRICT_SERVER, "curve25519-sha256"], &["aes128-ctr"],
                             &["hmac-sha2-256"]);
        let chosen = negotiate(&KexInit::parse(&client).unwrap(),
                               &KexInit::parse(&server).unwrap()).unwrap();
        assert_eq!(chosen.kex, "curve25519-sha256");
    }

    /// Both ends derive the same pair, mirrored.
    #[test]
    fn test_the_two_sides_keys_mirror() {
        let shared = kex::SharedSecret::for_test(&[7; 32]);
        let algorithms = Algorithms {
            kex: "curve25519-sha256".into(), host_key: "ssh-ed25519".into(),
            cipher_c2s: "aes128-ctr".into(), cipher_s2c: "aes256-ctr".into(),
            mac_c2s: Some("hmac-sha2-256".into()), mac_s2c: Some("hmac-sha2-512".into()),
        };
        let (mut client_send, mut client_receive) =
            derive_keys("sha256", &shared, &[1; 32], &[1; 32], &algorithms, Side::Client).unwrap();
        let (mut server_send, mut server_receive) =
            derive_keys("sha256", &shared, &[1; 32], &[1; 32], &algorithms, Side::Server).unwrap();
        assert_eq!(client_send.cipher.spec().name, "aes128-ctr");
        assert_eq!(server_send.cipher.spec().name, "aes256-ctr");
        let up = client_send.cipher.crypt(0, &[0x42; 32], 0).unwrap();
        assert_eq!(server_receive.cipher.crypt(0, &up, 0).unwrap(), vec![0x42; 32]);
        let down = server_send.cipher.crypt(0, &[0x24; 32], 0).unwrap();
        assert_eq!(client_receive.cipher.crypt(0, &down, 0).unwrap(), vec![0x24; 32]);
    }
}
