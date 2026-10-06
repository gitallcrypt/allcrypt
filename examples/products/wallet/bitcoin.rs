//! Bitcoin's key and address formats - WIF; P2PKH, P2SH-wrapped P2WPKH
//! (BIP-49), P2WPKH (BIP-84) and BIP-86's key-path P2TR - and signed
//! messages as Bitcoin Core writes them (BIP-137's header byte).

use allcrypt::bignum::BigUint;
use allcrypt::ec::Point;

use crate::encoding::{base58check_decode, base58check_encode, segwit_decode, segwit_encode};
use crate::hash::{hash160, sha256d, tagged_hash};
use crate::keys::{curve, private_bytes, private_from_bytes, recover, sign_recoverable, ser_p,
                  uncompressed};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Network {
    pub testnet: bool,
}

impl Network {
    fn wif_prefix(self) -> u8 {
        if self.testnet { 0xef } else { 0x80 }
    }
    fn p2pkh_prefix(self) -> u8 {
        if self.testnet { 0x6f } else { 0x00 }
    }
    fn p2sh_prefix(self) -> u8 {
        if self.testnet { 0xc4 } else { 0x05 }
    }
    pub fn hrp(self) -> &'static str {
        if self.testnet { "tb" } else { "bc" }
    }
}

/// A private key in Wallet Import Format, with whether its public key is
/// to be used compressed.
pub fn wif_encode(k: &BigUint, compressed: bool, network: Network) -> String {
    let mut data = vec![network.wif_prefix()];
    data.extend(private_bytes(k));
    if compressed {
        data.push(1);
    }
    base58check_encode(&data)
}

pub fn wif_decode(text: &str) -> Result<(BigUint, bool, Network), String> {
    let data = base58check_decode(text)?;
    let network = match data.first() {
        Some(0x80) => Network { testnet: false },
        Some(0xef) => Network { testnet: true },
        _ => return Err("Not a WIF private key (its prefix is neither 0x80 nor 0xef)."
            .to_string()),
    };
    let compressed = match data.len() {
        33 => false,
        34 if data[33] == 1 => true,
        _ => return Err("A WIF key is 32 bytes, with 01 after it if compressed.".to_string()),
    };
    Ok((private_from_bytes(&data[1..33])?, compressed, network))
}

pub fn public_bytes(point: &Point, compressed: bool) -> Vec<u8> {
    if compressed { ser_p(point) } else { uncompressed(point) }
}

pub fn p2pkh(public: &[u8], network: Network) -> String {
    let mut data = vec![network.p2pkh_prefix()];
    data.extend(hash160(public));
    base58check_encode(&data)
}

/// P2WPKH inside P2SH (BIP-49): the script hash of `0 <keyhash>`. A
/// witness key must be compressed.
pub fn p2sh_p2wpkh(compressed: &[u8], network: Network) -> String {
    let mut script = vec![0x00, 0x14];
    script.extend(hash160(compressed));
    let mut data = vec![network.p2sh_prefix()];
    data.extend(hash160(&script));
    base58check_encode(&data)
}

pub fn p2wpkh(compressed: &[u8], network: Network) -> String {
    segwit_encode(network.hrp(), 0, &hash160(compressed)).expect("a 20-byte program")
}

/// BIP-86's key-path-only taproot output key: the internal key with even
/// y, tweaked by its own TapTweak hash and no script tree (BIP-341).
pub fn taproot_output_key(internal: &Point) -> Result<[u8; 32], String> {
    let c = curve();
    let x = ser_p(internal)[1..].to_vec();
    // lift_x: the point with this x and even y.
    let mut even = vec![2u8];
    even.extend_from_slice(&x);
    let p = c.decode_point(&even)?;
    let t = BigUint::from_bytes_be(&tagged_hash("TapTweak", &x));
    if t >= c.n {
        return Err("The tweak is not below n.".to_string());
    }
    let q = c.add(&p, &c.generator_mul(&t));
    if q.is_identity() {
        return Err("The tweaked key is the identity.".to_string());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&ser_p(&q)[1..]);
    Ok(out)
}

pub fn p2tr(internal: &Point, network: Network) -> Result<String, String> {
    segwit_encode(network.hrp(), 1, &taproot_output_key(internal)?)
}

// ---------------------------------------------------------------- messages --

fn varint(n: usize) -> Vec<u8> {
    match n {
        0..=0xfc => vec![n as u8],
        0xfd..=0xffff => {
            let mut v = vec![0xfd];
            v.extend((n as u16).to_le_bytes());
            v
        }
        _ => {
            let mut v = vec![0xfe];
            v.extend((n as u32).to_le_bytes());
            v
        }
    }
}

/// Double SHA-256 of the magic prefix and the message, each with its
/// length as a Bitcoin varint.
pub fn message_hash(message: &[u8]) -> Vec<u8> {
    const MAGIC: &[u8] = b"Bitcoin Signed Message:\n";
    let mut data = varint(MAGIC.len());
    data.extend_from_slice(MAGIC);
    data.extend(varint(message.len()));
    data.extend_from_slice(message);
    sha256d(&data)
}

/// The kind of address a signed message's header byte names (BIP-137):
/// 27 to 30 an uncompressed key's P2PKH, 31 to 34 a compressed key's,
/// 35 to 38 P2SH-P2WPKH and 39 to 42 P2WPKH.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AddressKind {
    P2pkhUncompressed,
    P2pkh,
    P2shP2wpkh,
    P2wpkh,
}

impl AddressKind {
    fn base(self) -> u8 {
        match self {
            AddressKind::P2pkhUncompressed => 27,
            AddressKind::P2pkh => 31,
            AddressKind::P2shP2wpkh => 35,
            AddressKind::P2wpkh => 39,
        }
    }

    pub fn address(self, point: &Point, network: Network) -> String {
        match self {
            AddressKind::P2pkhUncompressed => p2pkh(&uncompressed(point), network),
            AddressKind::P2pkh => p2pkh(&ser_p(point), network),
            AddressKind::P2shP2wpkh => p2sh_p2wpkh(&ser_p(point), network),
            AddressKind::P2wpkh => p2wpkh(&ser_p(point), network),
        }
    }
}

/// The 65-byte compact signature: header, r, s.
pub fn sign_message(k: &BigUint, kind: AddressKind, message: &[u8]) -> Result<Vec<u8>, String> {
    let sig = sign_recoverable(k, &message_hash(message))?;
    let mut out = vec![kind.base() + sig.recid];
    out.extend(sig.r.to_bytes_be_padded(32)?);
    out.extend(sig.s.to_bytes_be_padded(32)?);
    Ok(out)
}

/// Recover the signer and check it is the address's owner. Electrum and
/// Bitcoin Core write a segwit address's signature with the P2PKH
/// compressed header, so the address decides the kind when the header
/// says compressed P2PKH.
pub fn verify_message(address: &str, signature: &[u8], message: &[u8]) -> Result<(), String> {
    if signature.len() != 65 {
        return Err(format!("A signed message's signature is 65 bytes, not {}.",
                           signature.len()));
    }
    let header = signature[0];
    if !(27..=42).contains(&header) {
        return Err(format!("Header byte {header} is not one BIP-137 defines."));
    }
    let kind = [AddressKind::P2pkhUncompressed, AddressKind::P2pkh, AddressKind::P2shP2wpkh,
                AddressKind::P2wpkh][usize::from((header - 27) / 4)];
    let recid = (header - 27) % 4;
    let r = BigUint::from_bytes_be(&signature[1..33]);
    let s = BigUint::from_bytes_be(&signature[33..]);
    let point = recover(&r, &s, recid, &message_hash(message))?;
    let network = Network { testnet: !address.starts_with(['1', '3', 'b']) };
    let candidates: Vec<AddressKind> = match kind {
        AddressKind::P2pkh => vec![AddressKind::P2pkh, AddressKind::P2shP2wpkh,
                                   AddressKind::P2wpkh],
        other => vec![other],
    };
    if candidates.iter().any(|k| k.address(&point, network) == address) {
        Ok(())
    } else {
        Err("The signature is valid for another key, not this address's.".to_string())
    }
}

/// What kind of address this is, and whether it is well formed.
pub fn check_address(address: &str) -> Result<String, String> {
    for (hrp, network) in [("bc", "mainnet"), ("tb", "testnet"), ("bcrt", "regtest")] {
        if address.to_ascii_lowercase().starts_with(&format!("{hrp}1")) {
            let (version, program) = segwit_decode(hrp, address)?;
            let kind = match (version, program.len()) {
                (0, 20) => "P2WPKH".to_string(),
                (0, 32) => "P2WSH".to_string(),
                (1, 32) => "P2TR".to_string(),
                (v, n) => format!("witness version {v}, {n}-byte program"),
            };
            return Ok(format!("{kind} ({network})"));
        }
    }
    let data = base58check_decode(address)?;
    if data.len() != 21 {
        return Err(format!("A Base58 address holds 21 bytes, not {}.", data.len()));
    }
    Ok(match data[0] {
        0x00 => "P2PKH (mainnet)",
        0x05 => "P2SH (mainnet)",
        0x6f => "P2PKH (testnet)",
        0xc4 => "P2SH (testnet)",
        other => return Err(format!("Address version {other:#04x} is not Bitcoin's.")),
    }.to_string())
}
