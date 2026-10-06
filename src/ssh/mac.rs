/*
SSH's MACs by name: RFC 4253 section 6.4, RFC 6668's SHA-2 ones,
OpenSSH's UMAC ones, and OpenSSH's encrypt-then-MAC variants
(`*-etm@openssh.com`).

The MAC of a packet is `HMAC(key, uint32 sequence_number || packet)`,
truncated for the `-96` names. UMAC takes the sequence number as its
nonce instead - eight bytes, big endian - and MACs the packet alone.
What `packet` is depends on the mode:

  * **encrypt-and-MAC** (RFC 4253): the *plaintext* packet, length field
    and all - the MAC is computed before encryption and sent beside the
    ciphertext. A receiver must decrypt before it can check anything.
  * **encrypt-then-MAC** (OpenSSH): the packet length in clear, then the
    *ciphertext*. A receiver checks before it decrypts, which is the
    point: it closes the padding-oracle and plaintext-recovery attacks
    on CBC that encrypt-and-MAC is open to.

# Pitfalls

**The sequence number is not reset by a key exchange** - unless strict
key exchange is on (OpenSSH's Terrapin countermeasure), in which case it
is reset at every NEWKEYS. It wraps at 2^32 either way.

**`-96` keeps the key at the hash's full length** and truncates only the
output to 12 bytes.

**UMAC's nonce is the sequence number, so it repeats when the sequence
number wraps** - after 2^32 packets under one key. RFC 4344 asks for a
rekey long before that, and OpenSSH rekeys by volume; a nonce reused
under one UMAC key leaks the xor of two hashes.

**`umac-128` is not `umac-64` with a longer tag**: the key schedule is
shared, but the tag is four UHASH iterations under a pad of its own,
not two more appended to the 64 bit tag.
*/

use crate::api::AnyHash;
use crate::mac::Hmac;
use crate::mac::umac::Umac;
use crate::Mac as _;

#[derive(Debug, PartialEq, Eq)]
pub struct Spec {
    pub name: &'static str,
    /// The hash for HMAC, or `"umac"`.
    hash: &'static str,
    pub key_len: usize,
    pub mac_len: usize,
    /// Encrypt-then-MAC.
    pub etm: bool,
}

const fn spec(name: &'static str, hash: &'static str, key_len: usize, mac_len: usize,
              etm: bool) -> Spec {
    Spec { name, hash, key_len, mac_len, etm }
}

/// Every MAC this module speaks, in the order a client offers them.
pub const MACS: &[Spec] = &[
    spec("hmac-sha2-256-etm@openssh.com", "sha256", 32, 32, true),
    spec("hmac-sha2-512-etm@openssh.com", "sha512", 64, 64, true),
    spec("hmac-sha1-etm@openssh.com", "sha1", 20, 20, true),
    spec("hmac-sha2-256", "sha256", 32, 32, false),
    spec("hmac-sha2-512", "sha512", 64, 64, false),
    spec("hmac-sha1", "sha1", 20, 20, false),
    spec("hmac-sha1-96-etm@openssh.com", "sha1", 20, 12, true),
    spec("hmac-sha1-96", "sha1", 20, 12, false),
    spec("hmac-md5-etm@openssh.com", "md5", 16, 16, true),
    spec("hmac-md5", "md5", 16, 16, false),
    spec("hmac-md5-96-etm@openssh.com", "md5", 16, 12, true),
    spec("hmac-md5-96", "md5", 16, 12, false),
    // OpenSSH until 7.6. The plain name is RFC 4253's; OpenSSH sent the
    // @openssh.com one too, from a time the plain one's status was unclear.
    spec("hmac-ripemd160-etm@openssh.com", "ripemd160", 20, 20, true),
    spec("hmac-ripemd160", "ripemd160", 20, 20, false),
    spec("hmac-ripemd160@openssh.com", "ripemd160", 20, 20, false),
    // OpenSSH since 4.7 (umac-64) and 6.2 (umac-128), RFC 4418 with an
    // AES-128 key. Offered by name, not by default.
    spec("umac-64-etm@openssh.com", "umac", 16, 8, true),
    spec("umac-128-etm@openssh.com", "umac", 16, 16, true),
    spec("umac-64@openssh.com", "umac", 16, 8, false),
    spec("umac-128@openssh.com", "umac", 16, 16, false),
];

pub fn lookup(name: &str) -> Result<&'static Spec, String> {
    MACS.iter().find(|spec| spec.name == name).ok_or_else(|| {
        let known: Vec<&str> = MACS.iter().map(|spec| spec.name).collect();
        format!("SSH: unknown MAC {name:?}. Known: {}.", known.join(", "))
    })
}

enum Keyed {
    Hmac(Box<Hmac<AnyHash>>),
    Umac(Box<Umac>),
}

/// One direction's MAC, keyed once per key exchange.
pub struct Mac {
    spec: &'static Spec,
    keyed: Keyed,
}

impl Mac {
    pub fn new(name: &str, key: &[u8]) -> Result<Mac, String> {
        let spec = lookup(name)?;
        if key.len() != spec.key_len {
            return Err(format!("SSH: {name} takes a {} byte key, not {}.",
                               spec.key_len, key.len()));
        }
        let keyed = if spec.hash == "umac" {
            Keyed::Umac(Box::new(Umac::new(key, spec.mac_len)?))
        } else {
            Keyed::Hmac(Box::new(Hmac::new(AnyHash::new(spec.hash)?, key)))
        };
        Ok(Mac { spec, keyed })
    }

    pub fn spec(&self) -> &'static Spec {
        self.spec
    }

    /// The MAC of `data` at `sequence`.
    pub fn compute(&mut self, sequence: u32, data: &[u8]) -> Result<Vec<u8>, String> {
        match &mut self.keyed {
            Keyed::Hmac(keyed) => {
                let mut mac = (**keyed).clone();
                mac.update(&sequence.to_be_bytes());
                mac.update(data);
                let mut out = mac.digest();
                out.truncate(self.spec.mac_len);
                Ok(out)
            }
            Keyed::Umac(umac) => umac.tag(data, &u64::from(sequence).to_be_bytes()),
        }
    }

    /// Whether `tag` is the MAC of `data`, compared in constant time.
    pub fn verify(&mut self, sequence: u32, data: &[u8], tag: &[u8]) -> Result<bool, String> {
        let expected = self.compute(sequence, data)?;
        Ok(expected.len() == tag.len()
            && expected.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC-SHA-256 of the sequence number and the data, which is all
    /// the format adds to RFC 2104.
    #[test]
    fn test_the_sequence_number_is_prepended() {
        let mut mac = Mac::new("hmac-sha2-256", &[0x0b; 32]).unwrap();
        let mut message = 7u32.to_be_bytes().to_vec();
        message.extend_from_slice(b"packet");
        let tag = mac.compute(7, b"packet").unwrap();
        assert_eq!(tag, crate::api::hmac("sha256", &[0x0b; 32], &message).unwrap());
        assert!(mac.verify(7, b"packet", &tag).unwrap());
        assert!(!mac.verify(8, b"packet", &tag).unwrap());
        assert_eq!(Mac::new("hmac-sha1-96", &[1; 20]).unwrap().compute(0, b"").unwrap().len(),
                   12);
    }

    /// UMAC's nonce is the sequence number as eight big-endian bytes,
    /// and the packet is MACed without it. OpenSSH's `mac_compute` does
    /// `put_u64(nonce, seqno)`.
    #[test]
    fn test_umac_takes_the_sequence_number_as_its_nonce() {
        for (name, tag_len) in [("umac-64@openssh.com", 8), ("umac-128-etm@openssh.com", 16)] {
            let key = [0x42; 16];
            let mut mac = Mac::new(name, &key).unwrap();
            let mut umac = Umac::new(&key, tag_len).unwrap();
            for sequence in [0u32, 1, 2, 3, 0xffff_ffff] {
                let tag = mac.compute(sequence, b"packet").unwrap();
                assert_eq!(tag, umac.tag(b"packet", &u64::from(sequence).to_be_bytes()).unwrap());
                assert!(mac.verify(sequence, b"packet", &tag).unwrap());
                assert!(!mac.verify(sequence ^ 1, b"packet", &tag).unwrap());
            }
        }
    }
}
