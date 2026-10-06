/*
Ephemeral (EC)DHE keys, for both sides of both handshakes.

A TLS 1.3 client sends key shares before it knows which group the server
wants; a TLS 1.2 server generates one after it has seen the ClientHello;
a TLS 1.3 server generates one to answer with. All three do the same
thing with the same groups, so they do it here rather than three times.

Two shapes behind one type, because X25519 is not an EC curve in this
library's sense: it has its own scalar clamping, its own encoding, and
its own exchange function, and the only thing it shares with P-256 is
what a caller wants from it.

**The shared secret is not post-processed here**, and that is the trap
this module is placed to avoid. TLS 1.3 uses the value as it comes out -
the x coordinate padded to the field width, leading zeros and all
(RFC 8446 7.4) - while TLS 1.2 *strips* those zeros before using it as
a premaster secret (RFC 5246 8.1.2). The difference shows up about one
exchange in 256, so an implementation that applied one rule to both
interoperates for days. `exchange` returns the raw value and the caller
applies its version's rule.
*/

use crate::bignum::BigUint;
use crate::ec::{curves, x25519, x448};
use crate::tls::handshake::groups;

/// One ephemeral key pair for a named group.
///
/// A TLS 1.3 client keeps several, because it sends its public keys
/// before it knows which group the server wants and the private halves
/// have to survive until the answer names one. A server keeps one.
pub enum EphemeralKey {
    X25519 { private: [u8; 32], public: [u8; 32] },
    /// **A variant of its own, not X25519 with a length field.**
    ///
    /// The two Montgomery curves differ in four ways and three of them
    /// are silent: the clamp is two low bits and bit 447 rather than
    /// three and bit 254, the base point is 5 rather than 9, `a24` is
    /// 39081 rather than 121665, and there is no spare high bit to mask
    /// because the field fills 56 bytes exactly. A shared implementation
    /// parameterised by length would get the fourth one wrong by
    /// carrying over a masking step, and produce something that
    /// round-trips against itself. `src/ec/x448.rs` has the detail.
    X448 { private: [u8; 56], public: [u8; 56] },
    Ec { group: u16, curve: &'static str, private: BigUint, public: Vec<u8> },
    /// A hybrid share (RFC 10024): an ML-KEM key pair and a classical
    /// ephemeral key, with `public` their concatenation in the group's
    /// order. Only a *client* holds one of these - a server answering a
    /// hybrid share does not generate an ML-KEM key, it encapsulates to
    /// the client's, which is why [`EphemeralKey::respond`] exists.
    Hybrid {
        group: u16,
        kem: crate::api::MlKemKey,
        classical: Box<EphemeralKey>,
        kem_first: bool,
        public: Vec<u8>,
    },
}

impl EphemeralKey {
    pub fn generate(group: u16) -> Result<EphemeralKey, String> {
        if let Some((kem_set, classical_group, kem_first)) = groups::hybrid(group) {
            let kem = crate::api::MlKemKey::generate(kem_set)?;
            let classical = Box::new(EphemeralKey::generate(classical_group)?);
            let public = if kem_first {
                [kem.public_bytes(), classical.public()].concat()
            } else {
                [classical.public(), kem.public_bytes()].concat()
            };
            return Ok(EphemeralKey::Hybrid { group, kem, classical, kem_first,
                                             public });
        }
        if group == groups::X25519 {
            let (private, public) = x25519::generate_key_pair()?;
            return Ok(EphemeralKey::X25519 { private, public });
        }
        if group == groups::X448 {
            let (private, public) = x448::generate_key_pair()?;
            return Ok(EphemeralKey::X448 { private, public });
        }
        let curve = groups::curve_name(group).ok_or_else(|| format!(
            "No key share can be generated for group {}.", groups::name(group)))?;
        let handle = curves::by_name(curve)?;
        let (private, point) = handle.generate_key_pair()?;
        // Uncompressed SEC1, and *bare* - a TLS 1.3 key_share entry has
        // its own length prefix, unlike TLS 1.2's ServerKeyExchange where
        // the point carries one of its own.
        let public = handle.encode_point(&point, false)?;
        Ok(EphemeralKey::Ec { group, curve, private, public })
    }

    pub fn group(&self) -> u16 {
        match self {
            EphemeralKey::X25519 { .. } => groups::X25519,
            EphemeralKey::X448 { .. } => groups::X448,
            EphemeralKey::Ec { group, .. } => *group,
            EphemeralKey::Hybrid { group, .. } => *group,
        }
    }

    /// Our public half, borrowed.
    ///
    /// Borrowed rather than returned by value because most callers only
    /// need to write it into a message: `entry()` is the one that has to
    /// own it, and it is the only place that copies.
    pub fn public(&self) -> &[u8] {
        match self {
            EphemeralKey::X25519 { public, .. } => public,
            EphemeralKey::X448 { public, .. } => public,
            EphemeralKey::Ec { public, .. } => public,
            EphemeralKey::Hybrid { public, .. } => public,
        }
    }

    pub fn entry(&self) -> crate::tls::handshake13::KeyShareEntry {
        crate::tls::handshake13::KeyShareEntry {
            group: self.group(),
            key_exchange: self.public().to_vec(),
        }
    }

    /// The (EC)DHE shared secret, from the peer's half.
    ///
    /// TLS 1.3 does **not** strip the leading zeros that TLS 1.2 strips
    /// from a premaster secret (RFC 5246 section 8.1.2 against RFC 8446
    /// section 7.4). For the EC groups the value is the x coordinate
    /// padded to the field's width, zeros and all.
    pub fn complete(&self, peer: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            EphemeralKey::X25519 { private, .. } => {
                if peer.len() != 32 {
                    return Err(format!(
                        "An X25519 key share is 32 bytes; the peer sent {}.",
                        peer.len()));
                }
                let mut point = [0u8; 32];
                point.copy_from_slice(peer);
                let shared = x25519::exchange(private, &point)?;
                Ok(shared.to_vec())
            }
            EphemeralKey::X448 { private, .. } => {
                if peer.len() != 56 {
                    return Err(format!(
                        "An X448 key share is 56 bytes; the peer sent {}.",
                        peer.len()));
                }
                let mut point = [0u8; 56];
                point.copy_from_slice(peer);
                let shared = x448::exchange(private, &point)?;
                Ok(shared.to_vec())
            }
            EphemeralKey::Ec { curve, private, .. } => {
                let handle = curves::by_name(curve)?;
                let point = handle.decode_point(peer)?;
                handle.ecdh(private, &point)
            }
            EphemeralKey::Hybrid { group, kem, classical, kem_first, .. } => {
                // The server's share is the ML-KEM ciphertext and its own
                // classical share. RFC 10024 4.2: the client checks the
                // ciphertext's length against the group, which splitting
                // at a fixed offset and requiring the remainder to be the
                // classical share's exact length does.
                let set = crate::pq::ml_kem::parameters(kem.parameter_set())?;
                let ciphertext_len = set.ciphertext_len();
                let classical_len = classical.public().len();
                if peer.len() != ciphertext_len + classical_len {
                    return Err(format!(
                        "A {} server share is {} bytes - a {} byte ML-KEM \
                         ciphertext and a {} byte {} share - and the peer \
                         sent {}.", groups::name(*group),
                        ciphertext_len + classical_len, ciphertext_len,
                        classical_len, groups::name(classical.group()),
                        peer.len()));
                }
                let (ciphertext, theirs) = if *kem_first {
                    (&peer[..ciphertext_len], &peer[ciphertext_len..])
                } else {
                    (&peer[classical_len..], &peer[..classical_len])
                };
                // An altered ciphertext is not an error here: it gives a
                // different secret, the two sides disagree, and the
                // handshake fails at Finished - as FIPS 203 requires.
                let kem_secret = kem.decapsulate(ciphertext)?;
                let classical_secret = classical.complete(theirs)?;
                Ok(combine(*kem_first, &kem_secret, &classical_secret))
            }
        }
    }

    /// A server's answer to a client's key share: `(our share, the shared
    /// secret)`.
    ///
    /// For a Diffie-Hellman group that is a fresh key pair and an
    /// exchange. For a hybrid group it is not symmetric: the server
    /// **encapsulates** to the client's ML-KEM key - after FIPS 203's
    /// modulus check on it, which RFC 10024 4.2 requires - and answers
    /// with the ciphertext alongside its own classical share.
    pub fn respond(group: u16, theirs: &[u8])
            -> Result<(crate::tls::handshake13::KeyShareEntry, Vec<u8>), String> {
        let Some((kem_set, classical_group, kem_first)) = groups::hybrid(group)
        else {
            let ours = EphemeralKey::generate(group)?;
            let shared = ours.complete(theirs)?;
            return Ok((ours.entry(), shared));
        };
        let set = crate::pq::ml_kem::parameters(kem_set)?;
        let ek_len = set.encapsulation_key_len();
        let classical = EphemeralKey::generate(classical_group)?;
        let classical_len = classical.public().len();
        if theirs.len() != ek_len + classical_len {
            return Err(format!(
                "A {} client share is {} bytes - a {} byte ML-KEM \
                 encapsulation key and a {} byte {} share - and the peer \
                 sent {}.", groups::name(group), ek_len + classical_len,
                ek_len, classical_len, groups::name(classical_group),
                theirs.len()));
        }
        let (ek, their_classical) = if kem_first {
            (&theirs[..ek_len], &theirs[ek_len..])
        } else {
            (&theirs[classical_len..], &theirs[..classical_len])
        };
        let kem = crate::api::MlKemPublicKey::from_public(kem_set, ek)?;
        let (kem_secret, ciphertext) = kem.encapsulate()?;
        let classical_secret = classical.complete(their_classical)?;
        let share = if kem_first {
            [ciphertext.as_slice(), classical.public()].concat()
        } else {
            [classical.public(), ciphertext.as_slice()].concat()
        };
        Ok((crate::tls::handshake13::KeyShareEntry { group, key_exchange: share },
            combine(kem_first, &kem_secret, &classical_secret)))
    }
}

/// A hybrid group's shared secret: the two secrets concatenated, in the
/// group's order - `ML-KEM || X25519` for X25519MLKEM768, `ECDHE ||
/// ML-KEM` for the other two (RFC 10024 4.3). No KDF here: the TLS 1.3
/// key schedule's HKDF-Extract is the combiner.
fn combine(kem_first: bool, kem_secret: &[u8], classical_secret: &[u8]) -> Vec<u8> {
    if kem_first {
        [kem_secret, classical_secret].concat()
    } else {
        [classical_secret, kem_secret].concat()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 10024's size table: client share, server share, shared secret.
    #[test]
    fn test_hybrid_sizes_are_what_rfc_10024_tabulates() {
        let table = [(groups::X25519_MLKEM768, 1216, 1120, 64),
                     (groups::SECP256R1_MLKEM768, 1249, 1153, 64),
                     (groups::SECP384R1_MLKEM1024, 1665, 1665, 80)];
        for (group, client, server, secret) in table {
            let ours = EphemeralKey::generate(group).unwrap();
            assert_eq!(ours.public().len(), client, "{}", groups::name(group));
            assert_eq!(ours.group(), group);
            let (answer, theirs) = EphemeralKey::respond(group, ours.public())
                .unwrap();
            assert_eq!(answer.group, group);
            assert_eq!(answer.key_exchange.len(), server, "{}", groups::name(group));
            assert_eq!(theirs.len(), secret);
            assert_eq!(ours.complete(&answer.key_exchange).unwrap(), theirs,
                       "{}: both sides agree", groups::name(group));
        }
    }

    /// The shared secret is the two secrets concatenated **in the group's
    /// order**, checked by building the server's answer by hand from the
    /// primitives rather than through `respond`.
    #[test]
    fn test_the_secret_is_the_two_secrets_in_the_groups_order() {
        // X25519MLKEM768: ML-KEM first, in the share and in the secret.
        let client = EphemeralKey::generate(groups::X25519_MLKEM768).unwrap();
        let (ek, x25519_public) = client.public().split_at(1184);
        let set = crate::pq::ml_kem::parameters("ML-KEM-768").unwrap();
        let (kem_secret, ciphertext) =
            crate::pq::ml_kem::encapsulate_internal(set, ek, &[9u8; 32]).unwrap();
        let (server_private, server_public) = x25519::generate_key_pair().unwrap();
        let mut peer = [0u8; 32];
        peer.copy_from_slice(x25519_public);
        let dh = x25519::exchange(&server_private, &peer).unwrap();
        let share = [ciphertext.as_slice(), &server_public].concat();
        assert_eq!(client.complete(&share).unwrap(),
                   [kem_secret.as_slice(), &dh].concat());

        // SecP256r1MLKEM768: the ECDHE part first, in both.
        let client = EphemeralKey::generate(groups::SECP256R1_MLKEM768).unwrap();
        let (point, ek) = client.public().split_at(65);
        let (kem_secret, ciphertext) =
            crate::pq::ml_kem::encapsulate_internal(set, ek, &[7u8; 32]).unwrap();
        let server = EphemeralKey::generate(groups::SECP256R1).unwrap();
        let dh = server.complete(point).unwrap();
        let share = [server.public(), ciphertext.as_slice()].concat();
        assert_eq!(client.complete(&share).unwrap(),
                   [dh.as_slice(), &kem_secret].concat());
    }

    /// A server refuses a client share whose ML-KEM key fails FIPS 203's
    /// modulus check, or whose length is wrong (RFC 10024 4.2).
    #[test]
    fn test_a_server_checks_the_clients_share() {
        let client = EphemeralKey::generate(groups::X25519_MLKEM768).unwrap();
        let mut bad = client.public().to_vec();
        bad[0] = 0xff;
        bad[1] |= 0x0f;                 // a twelve bit field of 4095
        assert!(EphemeralKey::respond(groups::X25519_MLKEM768, &bad).unwrap_err()
                    .contains("modulus check"));
        let short = &client.public()[..1215];
        assert!(EphemeralKey::respond(groups::X25519_MLKEM768, short).unwrap_err()
                    .contains("1216 bytes"));
        let long = [client.public(), &[0u8]].concat();
        assert!(EphemeralKey::respond(groups::X25519_MLKEM768, &long).unwrap_err()
                    .contains("1216 bytes"));
    }

    /// A client refuses a server share of the wrong length - and an
    /// altered ciphertext is not an error but a different secret.
    #[test]
    fn test_a_client_checks_the_servers_share() {
        let client = EphemeralKey::generate(groups::X25519_MLKEM768).unwrap();
        let (answer, secret) = EphemeralKey::respond(groups::X25519_MLKEM768,
                                                     client.public()).unwrap();
        assert!(client.complete(&answer.key_exchange[1..]).unwrap_err()
                    .contains("1120 bytes"));
        let longer = [answer.key_exchange.as_slice(), &[0u8]].concat();
        assert!(client.complete(&longer).unwrap_err().contains("1120 bytes"));
        let mut altered = answer.key_exchange.clone();
        altered[0] ^= 1;
        let got = client.complete(&altered).unwrap();
        assert_ne!(got, secret);
        assert_eq!(got[32..], secret[32..], "the X25519 half is untouched");
    }
}
