//! Wi-Fi payload decryption from a capture file (pcap or pcapng), built
//! from this library's primitives: WEP, and WPA, WPA2 and WPA3 once the
//! 4-way handshake in the capture has yielded the pairwise key.
//!
//!     cargo run --release --example wifi -- decrypt CAP --wep-key HEX [--out FILE]
//!     cargo run --release --example wifi -- decrypt CAP --essid NAME --password-stdin
//!         [--bssid AA:BB:..] [--out FILE] [--pmk HEX] [--airdecap] [--frames FILE]
//!
//! The pairwise ciphers TKIP, CCMP-128, CCMP-256, GCMP-128 and GCMP-256;
//! the AKMs PSK and 802.1X in their SHA-1 and SHA-256 forms, SAE and OWE
//! (the last two from `--pmk`, since their PMK comes from a key exchange
//! a capture does not reveal). Message 3 of the 4-way handshake, and the
//! group key handshake, yield the group keys: the GTK decrypts frames to
//! a group address under the group cipher; and with management frame
//! protection (802.11w) a protected unicast management frame - a
//! deauthentication, a disassociation, an action - opens under the
//! pairwise key as a data frame does.
//!
//! It prints a tally and with `--out` writes the decrypted data frames as
//! `airdecap-ng` does: each becomes an Ethernet frame (the 802.11 and
//! LLC/SNAP headers replaced by a 14-byte Ethernet header), in a
//! link-type-1 pcap. `--airdecap` decrypts what `airdecap-ng` does and no
//! more: unicast data frames, a retransmission skipped. `--frames FILE`
//! writes each decrypted frame's number (from 1) and plaintext in hex,
//! one to a line.
//!
//! The pieces are the library's: WEP and TKIP in `stream_ciphers`, the
//! TKIP key mixing and Michael there and in `mac`, AES-CCM in
//! `block_ciphers::ccm`, AES-GCM, AES key wrap (`block_ciphers::keywrap`),
//! AES-CMAC, and the PSK, PRF, KDF, PTK and PMKID in `kdf::ieee80211`. The
//! 802.11 framing - which bytes are the nonce, the additional
//! authenticated data, the sequence counter, the key data - is here.
//!
//! What has checked it is in `examples/products/README.md`.

use std::collections::HashMap;

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{ccm, keywrap};
use allcrypt::hash_functions::md5::MD5;
use allcrypt::hash_functions::sha1::SHA1;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::kdf::ieee80211;
use allcrypt::mac::cmac::cmac;
use allcrypt::mac::Hmac;
use allcrypt::stream_ciphers::rc4::RC4;
use allcrypt::stream_ciphers::{tkip, wep, StreamCipher};

#[path = "pcap.rs"]
mod pcap;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/cli.rs"]
mod cli;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

type Mac = [u8; 6];

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    cli::unhex(text, &[' ', '\t', '\r', '\n', ':', '-'])
}

/// A QoS data frame: type 2 with subtype bit 7.
fn is_qos_data(frame: &[u8]) -> bool {
    frame[0] & 0x8c == 0x88
}

/// A data frame with both DS bits set carries a fourth address.
fn has_a4(frame: &[u8]) -> bool {
    frame[0] & 0x0c == 0x08 && frame[1] & 3 == 3
}

/// The QoS Control field's priority (its TID), or 0 without one. The
/// field follows the third address, or the fourth.
fn priority(frame: &[u8]) -> u8 {
    if is_qos_data(frame) { frame[if has_a4(frame) { 30 } else { 24 }] & 0x0f } else { 0 }
}

/// Where the data begins after an 802.11 header: 24 bytes, 30 with a
/// fourth address, plus 2 for a QoS Control field, plus 4 for an HT
/// Control field, which a QoS data or management frame with the order
/// bit set carries.
fn header_len(frame: &[u8]) -> usize {
    let management = frame[0] & 0x0c == 0;
    let qos = is_qos_data(frame);
    let htc = frame[1] & 0x80 != 0 && (qos || management);
    24 + if has_a4(frame) { 6 } else { 0 } + if qos { 2 } else { 0 } + if htc { 4 } else { 0 }
}

/// A trailing 4-byte FCS (the whole frame's CRC-32) if present, as some
/// captures keep it: recognised by the CRC matching, and removed, the
/// way airdecap-ng does.
fn strip_fcs(frame: &[u8]) -> &[u8] {
    if frame.len() > 4 {
        let (body, fcs) = frame.split_at(frame.len() - 4);
        if allcrypt::checksum::crc32(body).to_le_bytes() == fcs {
            return body;
        }
    }
    frame
}

fn addr(frame: &[u8], at: usize) -> Mac {
    frame[at..at + 6].try_into().unwrap()
}

/// The BSSID and the station's address, from the To-DS/From-DS bits. A
/// frame with both set (WDS, mesh, a four-address station) names only
/// the transmitter and the receiver; this takes the transmitter as the
/// access point, and `Decryptor::data` tries the other way round when
/// only that link has keys.
fn bssid_and_station(frame: &[u8]) -> Option<(Mac, Mac)> {
    match frame[1] & 3 {
        0 => Some((addr(frame, 16), addr(frame, 4))),   // IBSS: BSSID is A3
        1 => Some((addr(frame, 4), addr(frame, 10))),   // to the AP
        2 => Some((addr(frame, 10), addr(frame, 4))),   // from the AP
        _ => Some((addr(frame, 10), addr(frame, 4))),   // four addresses
    }
}

// ------------------------------------------------- what was negotiated ---

/// The cipher and key management suites a station and its access point
/// agreed on, from the RSN element (or WPA's vendor element) the station
/// sends in message 2 of the 4-way handshake. Cipher suite types: 2 TKIP,
/// 4 CCMP-128, 8 GCMP-128, 9 GCMP-256, 10 CCMP-256. AKMs: 1 and 2
/// (802.1X and PSK, PRF-SHA1), 5 and 6 (their SHA-256 forms), 8 (SAE),
/// 18 (OWE).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Suites {
    akm: u8,
    pairwise: u8,
    group: u8,
    /// WPA (2003)'s vendor element rather than RSN.
    wpa1: bool,
}

/// The suites in an RSN element (`30 LEN version group pairwise... akm...`)
/// or WPA's (`DD LEN 00 50 F2 01 version group ...`), the first of each
/// list.
fn parse_suites(element: &[u8]) -> Option<Suites> {
    let (body, oui, wpa1): (&[u8], [u8; 3], bool) = match element.first()? {
        0x30 => (element.get(2..2 + *element.get(1)? as usize)?, [0x00, 0x0f, 0xac], false),
        0xdd if element.get(2..6)? == [0x00, 0x50, 0xf2, 0x01] =>
            (element.get(6..2 + *element.get(1)? as usize)?, [0x00, 0x50, 0xf2], true),
        _ => return None,
    };
    let suite = |at: usize| -> Option<u8> {
        let s = body.get(at..at + 4)?;
        (s[..3] == oui).then_some(s[3])
    };
    let group = suite(2)?;
    let pairwise_count = u16::from_le_bytes(body.get(6..8)?.try_into().ok()?) as usize;
    let pairwise = suite(8)?;
    let akm_at = 8 + 4 * pairwise_count;
    let akm = suite(akm_at + 2)?;
    Some(Suites { akm, pairwise, group, wpa1 })
}

/// The suites in a run of elements, from the first RSN or WPA element.
fn find_suites(mut elements: &[u8]) -> Option<Suites> {
    while elements.len() >= 2 {
        let length = elements[1] as usize + 2;
        let element = elements.get(..length)?;
        if let Some(suites) = parse_suites(element) {
            return Some(suites);
        }
        elements = &elements[length..];
    }
    None
}

/// A temporal key's length for a cipher suite: TKIP's is its 16 byte key
/// and two 8 byte Michael keys.
fn tk_len(cipher: u8) -> Option<usize> {
    match cipher {
        2 | 9 | 10 => Some(32),
        4 | 8 => Some(16),
        _ => None,
    }
}

impl Suites {
    /// The PTK - KCK, KEK and TK - for these suites: PRF-SHA1 for the
    /// first AKMs and WPA, KDF-SHA256 for the SHA-256 ones, SAE and OWE.
    fn ptk(&self, pmk: &[u8], aa: &Mac, spa: &Mac, anonce: &[u8; 32], snonce: &[u8; 32])
           -> Option<Vec<u8>> {
        let bits = (32 + tk_len(self.pairwise)?) * 8;
        match self.akm {
            1 | 2 => ieee80211::try_ptk_sha1(pmk, aa, spa, anonce, snonce, bits).ok(),
            5 | 6 | 8 | 18 => ieee80211::try_ptk_sha256(pmk, aa, spa, anonce, snonce, bits).ok(),
            _ => None,
        }
    }

    /// An EAPOL-Key frame's MIC under the KCK: by the key descriptor
    /// version - 1 HMAC-MD5, 2 HMAC-SHA1, 3 AES-CMAC - or, at version 0,
    /// by the AKM: AES-CMAC for SAE, HMAC-SHA256 for OWE over P-256.
    fn mic(&self, keyver: u8, kck: &[u8], eapol: &[u8]) -> Option<Vec<u8>> {
        let mic = match (keyver, self.akm) {
            (1, _) => Hmac::mac(MD5::new(&[]), kck, eapol),
            (2, _) => Hmac::mac(SHA1::new(&[]), kck, eapol),
            (3, _) | (0, 8) => cmac("aes", kck, eapol).ok()?,
            (0, 18) => Hmac::mac(SHA256::new(&[]), kck, eapol),
            _ => return None,
        };
        Some(mic[..16].to_vec())
    }
}

// ----------------------------------------------------- the handshake ---

/// One station's link with its access point: the 4-way handshake as it
/// goes by, and the pairwise key once a MIC has checked.
#[derive(Default)]
struct Station {
    bssid: Mac,
    station: Mac,
    suites: Option<Suites>,
    anonce: Option<[u8; 32]>,
    snonce: Option<[u8; 32]>,
    eapol: Option<Vec<u8>>,
    key_mic: Option<Vec<u8>>,
    keyver: u8,
    ptk: Option<Vec<u8>>,
    last_crc: [u32; 2],
}

/// The group keys of one access point: GTKs by key index, IGTKs by key
/// index, both learnt from the handshakes.
#[derive(Default)]
struct Group {
    gtk: HashMap<u8, Vec<u8>>,
    igtk: HashMap<u16, Vec<u8>>,
    cipher: u8,
}

/// An EAPOL-Key frame, read: the fields the handshakes use. The key data
/// starts after a 16 byte MIC, the size of every MIC the AKMs here use.
struct EapolKey<'a> {
    whole: &'a [u8],
    descriptor: u8,
    info: u16,
    nonce: [u8; 32],
    key_iv: &'a [u8],
    mic: &'a [u8],
    data: &'a [u8],
}

impl<'a> EapolKey<'a> {
    fn parse(eapol: &'a [u8]) -> Option<EapolKey<'a>> {
        if eapol.get(1) != Some(&3) {
            return None;
        }
        let size = u16::from_be_bytes([*eapol.get(2)?, *eapol.get(3)?]) as usize + 4;
        let whole = eapol.get(..size)?;
        let data_len = u16::from_be_bytes([*whole.get(97)?, *whole.get(98)?]) as usize;
        Some(EapolKey {
            whole,
            descriptor: whole[4],
            info: u16::from_be_bytes([whole[5], whole[6]]),
            nonce: whole[17..49].try_into().ok()?,
            key_iv: &whole[49..65],
            mic: &whole[81..97],
            data: whole.get(99..99 + data_len)?,
        })
    }

    fn keyver(&self) -> u8 { (self.info & 7) as u8 }
    fn pairwise(&self) -> bool { self.info & 0x0008 != 0 }
    fn install(&self) -> bool { self.info & 0x0040 != 0 }
    fn ack(&self) -> bool { self.info & 0x0080 != 0 }
    fn has_mic(&self) -> bool { self.info & 0x0100 != 0 }
    fn encrypted_data(&self) -> bool { self.info & 0x1000 != 0 }
    /// WPA's group key index, in key information bits 4 and 5.
    fn wpa1_key_index(&self) -> u8 { ((self.info >> 4) & 3) as u8 }

    /// The frame with its MIC field zeroed, as the MIC is computed over.
    fn zeroed(&self) -> Vec<u8> {
        let mut copy = self.whole.to_vec();
        copy[81..97].fill(0);
        copy
    }
}

/// Key data encrypted under the KEK: RC4 keyed with the key IV and the
/// KEK, its first 256 bytes of keystream discarded, for descriptor
/// version 1; AES key wrap (RFC 3394) for every other.
fn decrypt_key_data(keyver: u8, kek: &[u8], key_iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if keyver == 1 {
        let mut rc4 = RC4::new(&[key_iv, kek].concat()).ok()?;
        let mut discard = Vec::new();
        rc4.crypt(&[0u8; 256], &mut discard);
        let mut out = Vec::new();
        rc4.crypt(data, &mut out);
        return Some(out);
    }
    let mut aes = AesCrypto::new(kek).ok()?;
    keywrap::unwrap(&mut aes, data).ok()
}

/// The GTK and IGTK key data elements (KDEs) in decrypted key data:
/// `DD LEN 00 0F AC TYPE`, type 1 a GTK (key index, then a reserved
/// byte), type 9 an IGTK (2 byte key index, 6 byte IPN).
fn read_kdes(mut data: &[u8], group: &mut Group) {
    while data.len() >= 2 {
        let length = data[1] as usize + 2;
        let Some(element) = data.get(..length) else { return };
        if element[0] == 0xdd && element.len() >= 6 && element[2..5] == [0x00, 0x0f, 0xac] {
            match element[5] {
                1 if element.len() > 8 => {
                    group.gtk.insert(element[6] & 3, element[8..].to_vec());
                }
                9 if element.len() > 14 => {
                    group.igtk.insert(u16::from_le_bytes([element[6], element[7]]),
                                      element[14..].to_vec());
                }
                _ => {}
            }
        }
        // Padding (DD and then zeros) reads as empty elements.
        data = &data[length..];
    }
}

impl Station {
    fn kck(&self) -> Option<&[u8]> { self.ptk.as_ref().map(|p| &p[..16]) }
    fn kek(&self) -> Option<&[u8]> { self.ptk.as_ref().map(|p| &p[16..32]) }
    fn tk(&self) -> Option<&[u8]> { self.ptk.as_ref().map(|p| &p[32..]) }

    /// An EAPOL-Key frame of either handshake. The 4-way handshake's
    /// nonces and a MIC'd frame give the PTK; message 3's key data, and
    /// the group key handshake's, give the GTK and IGTK.
    fn eapol_key(&mut self, frame: &[u8], z: usize, pmk: &[u8], group: &mut Group) {
        // The LLC/SNAP then the EAPOL header: ethertype 0x888e at z+6.
        if frame.len() < z + 8 + 99 || frame[z + 6] != 0x88 || frame[z + 7] != 0x8e {
            return;
        }
        let Some(key) = EapolKey::parse(&frame[z + 8..]) else { return };
        if !key.pairwise() {
            self.group_key(&key, group);
            return;
        }
        if key.ack() && !key.has_mic() {
            self.anonce = Some(key.nonce);                          // message 1
        } else if !key.ack() && key.has_mic() && key.nonce != [0; 32] {
            self.snonce = Some(key.nonce);                          // message 2
            if let Some(suites) = find_suites(key.data) {
                self.suites = Some(suites);
            }
        } else if key.ack() && key.install() && key.has_mic() && key.nonce != [0; 32] {
            self.anonce = Some(key.nonce);                          // message 3
        }
        if key.has_mic() {
            self.key_mic = Some(key.mic.to_vec());
            self.eapol = Some(key.zeroed());
            self.keyver = key.keyver();
        }
        if key.descriptor == 254 && self.suites.is_none() {
            // WPA's descriptor without a WPA element seen: TKIP and PSK.
            self.suites = Some(Suites { akm: 2, pairwise: 2, group: 2, wpa1: true });
        }
        self.derive(pmk);
        if key.ack() && key.install() && key.encrypted_data() {
            if let (Some(kek), Some(suites)) = (self.kek(), self.suites) {
                if let Some(data) = decrypt_key_data(key.keyver(), kek, key.key_iv, key.data) {
                    read_kdes(&data, group);
                    group.cipher = suites.group;
                }
            }
        }
    }

    /// Message 1 of the group key handshake: the GTK, as a KDE under RSN,
    /// or bare under WPA with its index in the key information.
    fn group_key(&mut self, key: &EapolKey, group: &mut Group) {
        let (Some(kek), Some(kck), Some(suites)) = (self.kek(), self.kck(), self.suites) else {
            return;
        };
        if !key.ack() || !key.has_mic() || suites.mic(key.keyver(), kck, &key.zeroed())
                .as_deref() != Some(key.mic) {
            return;
        }
        let Some(data) = decrypt_key_data(key.keyver(), kek, key.key_iv, key.data) else { return };
        if key.descriptor == 254 {
            group.gtk.insert(key.wpa1_key_index(), data);
        } else {
            read_kdes(&data, group);
        }
        group.cipher = suites.group;
    }

    fn derive(&mut self, pmk: &[u8]) {
        let (Some(anonce), Some(snonce), Some(eapol), Some(key_mic)) =
            (self.anonce, self.snonce, &self.eapol, &self.key_mic) else { return };
        // The suites default to WPA2-PSK with CCMP, which is what a
        // capture without message 2's element most likely holds.
        let suites = self.suites.unwrap_or(Suites { akm: 2, pairwise: 4, group: 4, wpa1: false });
        let Some(ptk) = suites.ptk(pmk, &self.bssid, &self.station, &anonce, &snonce) else {
            return;
        };
        if suites.mic(self.keyver, &ptk[..16], eapol).as_ref() == Some(key_mic) {
            self.suites = Some(suites);
            self.ptk = Some(ptk);
        }
    }
}

// --------------------------------------------------- the data ciphers ---

/// The header CCMP and GCMP share, 8 bytes after the 802.11 header: the
/// packet number's bytes 0 and 1, a reserved byte, the key index and
/// Ext IV bit, then bytes 2 to 5. Returned most significant first.
fn packet_number(frame: &[u8], z: usize) -> [u8; 6] {
    [frame[z + 7], frame[z + 6], frame[z + 5], frame[z + 4], frame[z + 1], frame[z]]
}

/// CCMP's and GCMP's additional authenticated data (IEEE 802.11-2020
/// 12.5.3.3.3): the header with the volatile bits masked off - a data
/// frame's subtype bits, the retry, power management and more-data bits,
/// a QoS data frame's order bit, the sequence number - and the protected
/// bit kept. An HT Control field is left out.
fn aead_aad(frame: &[u8]) -> Vec<u8> {
    let management = frame[0] & 0x0c == 0;
    let a4 = has_a4(frame);
    let qos = is_qos_data(frame);
    let mut aad = Vec::with_capacity(32);
    aad.push(if management { frame[0] } else { frame[0] & 0x8f });
    aad.push(frame[1] & if qos { 0x47 } else { 0xc7 });
    aad.extend_from_slice(&frame[4..22]);           // A1, A2, A3
    aad.push(frame[22] & 0x0f);                     // sequence control
    aad.push(0);
    if a4 {
        aad.extend_from_slice(&frame[24..30]);      // A4
    }
    if qos {
        aad.push(priority(frame));
        aad.push(0);
    }
    aad
}

/// CCMP's nonce (13 bytes): a flags byte - the QoS priority, and bit 4
/// for a management frame (802.11w) - then A2 and the packet number.
fn ccmp_nonce(frame: &[u8], z: usize) -> [u8; 13] {
    let management = frame[0] & 0x0c == 0;
    let mut nonce = [0u8; 13];
    nonce[0] = priority(frame) | if management { 0x10 } else { 0 };
    nonce[1..7].copy_from_slice(&frame[10..16]);
    nonce[7..13].copy_from_slice(&packet_number(frame, z));
    nonce
}

/// The plaintext of a frame protected by a pairwise or group key, or
/// `None` if it does not authenticate. `key` is the TK or the GTK.
fn open_frame(cipher: u8, key: &[u8], frame: &[u8], z: usize) -> Option<Vec<u8>> {
    let body = frame.get(z + 8..)?;
    match cipher {
        2 => {
            let ta = addr(frame, 10);
            let iv16 = u16::from_be_bytes([frame[z], frame[z + 2]]);
            let iv32 = u32::from_le_bytes(frame[z + 4..z + 8].try_into().ok()?);
            let tsc = (u64::from(iv32) << 16) | u64::from(iv16);
            let rc4_key = tkip::rc4_key(key.get(..16)?.try_into().ok()?, &ta, tsc);
            wep::open(&rc4_key, body).ok()
        }
        4 | 10 => {
            let tag_len = if cipher == 4 { 8 } else { 16 };
            let split = body.len().checked_sub(tag_len)?;
            let mut aes = AesCrypto::new(key).ok()?;
            ccm::decrypt(&mut aes, &ccmp_nonce(frame, z), &aead_aad(frame), &body[..split],
                         &body[split..]).ok()
        }
        8 | 9 => {
            // GCMP's nonce is A2 and the packet number, 12 bytes.
            let mut nonce = frame[10..16].to_vec();
            nonce.extend_from_slice(&packet_number(frame, z));
            let split = body.len().checked_sub(16)?;
            allcrypt::api::aead_decrypt("aes-gcm", key, &nonce, &aead_aad(frame),
                                        &body[..split], &body[split..]).ok()
        }
        _ => None,
    }
}

/// The destination and source addresses of a data frame, by its DS bits.
fn da_sa(frame: &[u8]) -> (Mac, Mac) {
    match frame[1] & 3 {
        0 => (addr(frame, 4), addr(frame, 10)),
        1 => (addr(frame, 16), addr(frame, 10)),
        2 => (addr(frame, 4), addr(frame, 16)),
        _ => (addr(frame, 16), addr(frame, 24)),
    }
}

/// TKIP's MSDU integrity check: Michael under `mic_key` over the
/// destination, the source, the priority and the data must equal the
/// eight bytes after the data. An MSDU sent in fragments carries its MIC
/// in the last, so one fragment alone does not check.
fn michael_checks(frame: &[u8], mic_key: &[u8], plaintext: &[u8]) -> bool {
    let Some(split) = plaintext.len().checked_sub(8) else { return false };
    let Ok(key) = <[u8; 8]>::try_from(mic_key) else { return false };
    let (da, sa) = da_sa(frame);
    tkip::msdu_mic(&key, &da, &sa, priority(frame), &plaintext[..split]) == plaintext[split..]
}

/// A WEP frame's plaintext: the 3-byte IV then the shared key, RC4,
/// the ICV checked.
fn open_wep(frame: &[u8], z: usize, key: &[u8]) -> Option<Vec<u8>> {
    let mut rc4_key = frame[z..z + 3].to_vec();
    rc4_key.extend_from_slice(key);
    wep::open(&rc4_key, frame.get(z + 4..)?).ok()
}

/// Convert a decrypted frame to the Ethernet frame `airdecap-ng` writes:
/// destination and source from the addresses (by the DS bits), then the
/// payload from after the LLC's `AA AA 03 00 00 00`, keeping its
/// ethertype.
fn to_ethernet(frame: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let (dst, src) = da_sa(frame);
    // The payload is LLC/SNAP (8 bytes) then the data; the Ethernet
    // frame keeps the last 2 (the ethertype) and drops the rest.
    if payload.len() < 8 {
        return None;
    }
    let mut out = Vec::with_capacity(12 + payload.len() - 6);
    out.extend_from_slice(&dst);
    out.extend_from_slice(&src);
    out.extend_from_slice(&payload[6..]);
    Some(out)
}

#[derive(Default)]
struct Tally {
    stations: usize,
    wep: usize,
    wpa: usize,
    plain: usize,
    unwep: usize,
    unwpa: usize,
    bad_wep: usize,
    bad_wpa: usize,
    group: usize,
    management: usize,
}

/// What kind of frame a plaintext came from.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Wep,
    Pairwise,
    Group,
    Management,
}

/// One frame decrypted.
struct Decrypted {
    /// The frame's number in the capture, from 1.
    number: usize,
    kind: Kind,
    /// A data frame's LLC/SNAP header and what follows it (TKIP's Michael
    /// MIC left off), or a management frame's body.
    plaintext: Vec<u8>,
    /// A data frame as `airdecap-ng` writes it.
    ethernet: Option<Vec<u8>>,
}

/// The state a capture builds up - each station's handshake and keys,
/// each access point's group keys - and the frames it decrypts, one at a
/// time.
struct Decryptor<'k> {
    pmk: Option<&'k [u8]>,
    wep_key: Option<&'k [u8]>,
    want_bssid: Option<Mac>,
    /// `airdecap-ng`'s selection: unicast data frames only, and a frame
    /// retransmitted in the same direction skipped.
    airdecap: bool,
    stations: HashMap<(Mac, Mac), Station>,
    groups: HashMap<Mac, Group>,
    tally: Tally,
}

/// A group address: the low bit of the first byte.
fn is_group(address: &[u8]) -> bool {
    address[0] & 1 == 1
}

impl<'k> Decryptor<'k> {
    fn new(pmk: Option<&'k [u8]>, wep_key: Option<&'k [u8]>, airdecap: bool) -> Decryptor<'k> {
        Decryptor { pmk, wep_key, want_bssid: None, airdecap, stations: HashMap::new(),
                    groups: HashMap::new(), tally: Tally::default() }
    }

    fn frame(&mut self, number: usize, frame: &[u8]) -> Option<Decrypted> {
        let frame = strip_fcs(frame);
        if frame.len() < 24 {
            return None;
        }
        match frame[0] & 0x0c {
            // A data frame without data (null, CF-Ack, CF-Poll) is
            // shorter than any protected frame and goes no further.
            0x08 => self.data(number, frame),
            0x00 if !self.airdecap => self.management(number, frame),
            _ => None,
        }
    }

    fn station(&mut self, bssid: Mac, station: Mac) -> &mut Station {
        let tally = &mut self.tally;
        self.stations.entry((bssid, station)).or_insert_with(|| {
            tally.stations += 1;
            Station { bssid, station, ..Default::default() }
        })
    }

    fn data(&mut self, number: usize, frame: &[u8]) -> Option<Decrypted> {
        let z = header_len(frame);
        if frame.len() < z + 16 {
            return None;
        }
        let (mut bssid, mut station_mac) = bssid_and_station(frame)?;
        if frame[1] & 3 == 3 && !self.stations.contains_key(&(bssid, station_mac))
                && self.stations.contains_key(&(station_mac, bssid)) {
            (bssid, station_mac) = (station_mac, bssid);
        }
        if self.want_bssid.is_some_and(|want| want != bssid) {
            return None;
        }
        let protected = frame[1] & 0x40 != 0;
        let ext_iv = frame[z + 3] & 0x20 != 0;
        // A frame from the access point to a group address is under the
        // group key; airdecap-ng counts it and leaves it.
        // To the access point, A1 is the BSSID and never a group address.
        if !self.airdecap && is_group(&frame[4..10]) && protected && ext_iv {
            self.tally.wpa += 1;
            let group = self.groups.get(&bssid)?;
            let key = group.gtk.get(&(frame[z + 3] >> 6))?;
            let mut plaintext = open_frame(group.cipher, key, frame, z)?;
            if group.cipher == 2 {
                // The access point's transmit MIC key, bytes 16 to 24.
                if !michael_checks(frame, key.get(16..24)?, &plaintext) {
                    return None;
                }
                plaintext.truncate(plaintext.len() - 8);
            }
            self.tally.group += 1;
            return Some(Decrypted { number, kind: Kind::Group,
                                    ethernet: to_ethernet(frame, &plaintext), plaintext });
        }
        let airdecap = self.airdecap;
        let pmk = self.pmk;
        let wep_key = self.wep_key;
        self.groups.entry(bssid).or_default();
        let station = self.station(bssid, station_mac);

        // A retransmitted frame has the same body CRC as the last in its
        // direction; airdecap-ng skips it, so the counts match when we do.
        if airdecap {
            let direction = usize::from(frame[1] & 3 == 2);
            let crc = allcrypt::checksum::crc32(&frame[z..]);
            if station.last_crc[direction] == crc && crc != 0 {
                return None;
            }
            station.last_crc[direction] = crc;
        }

        // Encrypted data starts with neither the LLC's AA AA 03; an
        // unprotected frame is passed through.
        if !protected {
            if frame[z] == 0xaa && frame[z + 1] == 0xaa && frame[z + 2] == 0x03 {
                self.tally.plain += 1;
                if let Some(pmk) = pmk {
                    // The station and the access point's group keys are in
                    // different maps, so both can be borrowed at once.
                    let station = self.stations.get_mut(&(bssid, station_mac))?;
                    let group = self.groups.get_mut(&bssid)?;
                    station.eapol_key(frame, z, pmk, group);
                }
            }
            return None;
        }
        if !ext_iv {
            self.tally.wep += 1;
            let key = wep_key?;
            return match open_wep(frame, z, key) {
                Some(plaintext) => {
                    self.tally.unwep += 1;
                    Some(Decrypted { number, kind: Kind::Wep,
                                     ethernet: to_ethernet(frame, &plaintext), plaintext })
                }
                None => {
                    self.tally.bad_wep += 1;
                    None
                }
            };
        }
        self.tally.wpa += 1;
        let station = self.stations.get(&(bssid, station_mac))?;
        let (Some(tk), Some(suites)) = (station.tk(), station.suites) else { return None };
        let Some(mut plaintext) = open_frame(suites.pairwise, tk, frame, z) else {
            self.tally.bad_wpa += 1;
            return None;
        };
        if suites.pairwise == 2 && plaintext.len() >= 8 {
            // TKIP leaves its 8-byte Michael MIC after the data: under the
            // access point's transmit key (TK bytes 16 to 24) from it, the
            // station's (24 to 32) to it. airdecap-ng does not check it.
            let mic_key = if frame[1] & 3 == 1 { &tk[24..32] } else { &tk[16..24] };
            if !airdecap && !michael_checks(frame, mic_key, &plaintext) {
                self.tally.bad_wpa += 1;
                return None;
            }
            plaintext.truncate(plaintext.len() - 8);
        }
        self.tally.unwpa += 1;
        // A handshake inside the protected link - a group key rekeying -
        // is read as one in the clear is.
        if plaintext.starts_with(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]) {
            if let (Some(pmk), Some(group)) = (pmk, self.groups.get_mut(&bssid)) {
                let mut inner = frame[..z].to_vec();
                inner.extend_from_slice(&plaintext);
                if let Some(station) = self.stations.get_mut(&(bssid, station_mac)) {
                    station.eapol_key(&inner, z, pmk, group);
                }
            }
        }
        Some(Decrypted { number, kind: Kind::Pairwise, ethernet: to_ethernet(frame, &plaintext),
                         plaintext })
    }

    /// A management frame: an association request's RSN element, which
    /// names the suites before the handshake does; and a protected unicast
    /// management frame, which opens under the pairwise key.
    fn management(&mut self, number: usize, frame: &[u8]) -> Option<Decrypted> {
        let (a1, a2, a3) = (addr(frame, 4), addr(frame, 10), addr(frame, 16));
        if self.want_bssid.is_some_and(|want| want != a3) {
            return None;
        }
        let station_mac = if a2 == a3 { a1 } else { a2 };
        let protected = frame[1] & 0x40 != 0;
        let subtype = frame[0] & 0xf0;
        if !protected {
            // Association (0x00) and reassociation (0x20) requests: the
            // capability and listen interval, and a reassociation's
            // current AP, before the elements.
            let fixed = match subtype { 0x00 => 4, 0x20 => 10, _ => return None };
            if let Some(suites) = frame.get(24 + fixed..).and_then(find_suites) {
                self.station(a3, station_mac).suites.get_or_insert(suites);
            }
            return None;
        }
        // A group-addressed management frame is never encrypted: BIP
        // protects it in the clear, which this does not check.
        let z = header_len(frame);
        if frame.len() < z + 8 {
            return None;
        }
        let station = self.stations.get(&(a3, station_mac))?;
        let (Some(tk), Some(suites)) = (station.tk(), station.suites) else { return None };
        let plaintext = open_frame(suites.pairwise, tk, frame, z)?;
        self.tally.management += 1;
        Some(Decrypted { number, kind: Kind::Management, plaintext, ethernet: None })
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("decrypt") || args.len() < 2 {
        return Err("usage: wifi decrypt CAP (--wep-key HEX | --essid NAME \
                    (--password-stdin | --pmk HEX)) [--bssid MAC] [--out FILE] [--airdecap] \
                    [--frames FILE]".to_string());
    }
    let capture = std::fs::read(&args[1]).map_err(|e| format!("{}: {e}", args[1]))?;
    let mut wep_key = None;
    let mut essid = None;
    let mut password = None;
    let mut pmk_hex = None;
    let mut want_bssid: Option<Mac> = None;
    let mut out_path = None;
    let mut frames_path = None;
    let mut airdecap = false;
    let mut rest = args[2..].iter();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--wep-key" => wep_key = Some(unhex(&value()?)?),
            "--essid" => essid = Some(value()?),
            "--pmk" => pmk_hex = Some(unhex(&value()?)?),
            "--password-stdin" => password = Some(passphrase::read_line("Password: ")?),
            "--bssid" => want_bssid = Some(unhex(&value()?)?.try_into()
                .map_err(|_| "A BSSID is six bytes.".to_string())?),
            "--out" => out_path = Some(value()?),
            "--frames" => frames_path = Some(value()?),
            "--airdecap" => airdecap = true,
            other => return Err(format!("unknown option {other}")),
        }
    }

    let pmk = match (&pmk_hex, &essid, &password) {
        (Some(pmk), _, _) => Some(pmk.clone()),
        (None, Some(essid), Some(password)) =>
            Some(ieee80211::psk(password, essid.as_bytes())?.to_vec()),
        _ => None,
    };

    let mut decryptor = Decryptor::new(pmk.as_deref(), wep_key.as_deref(), airdecap);
    decryptor.want_bssid = want_bssid;
    let mut writer = pcap::Writer::new();
    let mut listing = String::new();
    for (index, frame) in pcap::Reader::new(&capture)?.enumerate() {
        let Some(decrypted) = decryptor.frame(index + 1, frame) else { continue };
        if let Some(ethernet) = &decrypted.ethernet {
            writer.write(ethernet);
        }
        listing.push_str(&format!("{} {:?} {}\n", decrypted.number, decrypted.kind,
                                  cli::hex(&decrypted.plaintext)));
    }

    let tally = &decryptor.tally;
    println!("Stations seen:            {}", tally.stations);
    println!("WEP data frames:          {}", tally.wep);
    println!("WPA data frames:          {}", tally.wpa);
    println!("Plaintext data frames:    {}", tally.plain);
    println!("Decrypted WEP frames:     {}", tally.unwep);
    println!("Decrypted WPA frames:     {}", tally.unwpa);
    println!("Bad WEP frames:           {}", tally.bad_wep);
    println!("Bad WPA frames:           {}", tally.bad_wpa);
    if !airdecap {
        println!("Decrypted group frames:   {}", tally.group);
        println!("Decrypted management:     {}", tally.management);
    }
    if let Some(path) = out_path {
        std::fs::write(&path, writer.finish()).map_err(|e| format!("{path}: {e}"))?;
    }
    if let Some(path) = frames_path {
        std::fs::write(&path, listing).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = run(&args) {
        eprintln!("wifi: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::hex;

    /// The capture decrypted as `run` decrypts it: the Ethernet frames
    /// and how many frames decrypted - with `airdecap`, `airdecap-ng`'s
    /// selection.
    fn decrypt_capture(capture: &[u8], pmk: Option<&[u8]>, wep_key: Option<&[u8]>)
                       -> (Vec<Vec<u8>>, usize) {
        let mut decryptor = Decryptor::new(pmk, wep_key, true);
        let decrypted: Vec<Decrypted> = pcap::Reader::new(capture).unwrap().enumerate()
            .filter_map(|(i, frame)| decryptor.frame(i + 1, frame)).collect();
        let count = decrypted.len();
        (decrypted.into_iter().filter_map(|d| d.ethernet).collect(), count)
    }

    fn sha256(data: &[u8]) -> String {
        use allcrypt::hash_functions::HashFunction;
        let mut h = allcrypt::hash_functions::sha2::SHA256::new(&[]);
        h.update(data);
        hex(&h.digest())
    }

    /// Every recorded capture decrypts to the Ethernet payloads whose
    /// SHA-256 equalled `airdecap-ng`'s, and the count matches. The
    /// captures are aircrack-ng's: WPA2-CCMP, WPA-TKIP and WPA-CCMP.
    #[test]
    fn test_aircrack_captures() {
        let records = fixtures::records("wifi.vec", "captures");
        assert!(records.len() >= 3);
        for record in &records {
            let name = fixtures::field(record, "name");
            let capture = std::fs::read(fixtures::dir().join(fixtures::field(record, "capture")))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let essid = fixtures::field(record, "essid");
            let password = fixtures::field(record, "password");
            let pmk = ieee80211::psk(password.as_bytes(), essid.as_bytes()).unwrap();
            let (payloads, decrypted) = decrypt_capture(&capture, Some(&pmk), None);
            assert_eq!(decrypted.to_string(), fixtures::field(record, "decrypted"), "{name}");
            assert_eq!(sha256(&payloads.concat()), fixtures::field(record, "payload_sha256"),
                       "{name}");
            let wrong = ieee80211::psk(b"wrong", essid.as_bytes()).unwrap();
            let (_, none) = decrypt_capture(&capture, Some(&wrong), None);
            assert_eq!(none, 0, "{name}: a wrong passphrase decrypts nothing");
        }
    }

    /// One of the Wireshark captures: its frames, and its PMK.
    fn wireshark_capture(name: &str) -> (Vec<Vec<u8>>, Vec<u8>) {
        let records = fixtures::records("wifi-wireshark.vec", "captures");
        let record = records.iter().find(|r| fixtures::field(r, "name") == name)
            .unwrap_or_else(|| panic!("no capture {name}"));
        let capture = std::fs::read(fixtures::dir().join(fixtures::field(record, "capture")))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let pmk = match fixtures::field(record, "pmk") {
            "-" => ieee80211::psk(fixtures::field(record, "password").as_bytes(),
                                  fixtures::field(record, "essid").as_bytes()).unwrap().to_vec(),
            pmk => unhex(pmk).unwrap(),
        };
        let frames = pcap::Reader::new(&capture).unwrap().map(<[u8]>::to_vec).collect();
        (frames, pmk)
    }

    /// The frames decrypted, numbered by their place in `frames`, those
    /// `keep` refuses left out.
    fn decrypt_frames(frames: &[Vec<u8>], pmk: &[u8], airdecap: bool,
                      keep: impl Fn(&[u8]) -> bool) -> Vec<Decrypted> {
        let mut decryptor = Decryptor::new(Some(pmk), None, airdecap);
        frames.iter().enumerate().filter(|(_, f)| keep(f))
            .filter_map(|(i, frame)| decryptor.frame(i + 1, frame)).collect()
    }

    /// An EAPOL-Key frame's key information, if the frame is one sent in
    /// the clear.
    fn eapol_info(frame: &[u8]) -> Option<u16> {
        let frame = strip_fcs(frame);
        if frame.len() < 24 || frame[0] & 0x0c != 0x08 || frame[1] & 0x40 != 0 {
            return None;
        }
        let z = header_len(frame);
        (frame.get(z + 6..z + 8)? == [0x88, 0x8e]).then(|| {
            u16::from_be_bytes([frame[z + 13], frame[z + 14]])
        })
    }

    fn numbers(decrypted: &[Decrypted]) -> Vec<usize> {
        decrypted.iter().map(|d| d.number).collect()
    }

    /// Wireshark's decryption-test captures decrypt, frame for frame, to
    /// the plaintexts `tshark` decrypted: unicast and group data frames
    /// under CCMP, CCMP-256, GCMP, GCMP-256 and TKIP, protected management
    /// frames, group keys from the 4-way and the group handshakes and their
    /// rekeying, and PSK-SHA256, SAE and OWE keys from their PMKs; three of
    /// them with frames appended that `tshark` opened - QoS priorities,
    /// fragments, HT Control fields, a TKIP group frame's Michael over its
    /// priority - and a handshake made whole, with frames of four addresses
    /// each way. A wrong PMK decrypts nothing, and with `airdecap` only
    /// unicast data frames decrypt.
    #[test]
    fn test_wireshark_captures() {
        let records = fixtures::records("wifi-wireshark.vec", "captures");
        assert_eq!(records.len(), 13);
        let mut kinds = Vec::new();
        for record in &records {
            let name = fixtures::field(record, "name");
            let (frames, pmk) = wireshark_capture(name);
            let decrypted = decrypt_frames(&frames, &pmk, false, |_| true);
            let listed: Vec<String> = numbers(&decrypted).iter().map(usize::to_string).collect();
            assert_eq!(listed.join(","), fixtures::field(record, "frames"), "{name}");
            let plaintexts: Vec<u8> = decrypted.iter().flat_map(|d| d.plaintext.clone())
                .collect();
            assert_eq!(sha256(&plaintexts), fixtures::field(record, "plaintext_sha256"),
                       "{name}");
            kinds.extend(decrypted.iter().map(|d| d.kind));
            let mut wrong = pmk.clone();
            wrong[0] ^= 1;
            assert!(decrypt_frames(&frames, &wrong, false, |_| true).is_empty(),
                    "{name}: a wrong PMK decrypts nothing");
            let selected = decrypt_frames(&frames, &pmk, true, |_| true);
            assert!(selected.iter().all(|d| d.kind == Kind::Pairwise),
                    "{name}: airdecap-ng's selection is unicast data frames");
        }
        for kind in [Kind::Pairwise, Kind::Group, Kind::Management] {
            assert!(kinds.contains(&kind), "no {kind:?} frame among the captures");
        }
    }

    /// The suites come from message 2's RSN element when no association
    /// request was captured, and message 3's ANonce stands in for message
    /// 1's: either missing, the capture decrypts as before. `wpa-gcmp` is
    /// GCMP, which the defaults would not guess.
    #[test]
    fn test_a_handshake_seen_in_part() {
        let (frames, pmk) = wireshark_capture("wpa-gcmp.pcapng");
        let all = numbers(&decrypt_frames(&frames, &pmk, false, |_| true));
        assert!(all.len() > 10);
        let association = |f: &[u8]| f[0] == 0x00 || f[0] == 0x20;
        assert!(frames.iter().any(|f| association(f)));
        assert_eq!(numbers(&decrypt_frames(&frames, &pmk, false, |f| !association(f))), all,
                   "without the association request");
        let message_1 = |f: &[u8]| eapol_info(f).is_some_and(|i| i & 0x0188 == 0x0088);
        assert!(frames.iter().any(|f| message_1(f)));
        assert_eq!(numbers(&decrypt_frames(&frames, &pmk, false, |f| !message_1(f))), all,
                   "without message 1");
    }

    /// The group cipher comes from the suites when message 3 installs the
    /// GTK: `wpa2-psk-ccmp-tkip`'s group key is TKIP's under a CCMP pair.
    #[test]
    fn test_message_3_names_the_group_cipher() {
        let (frames, pmk) = wireshark_capture("wpa2-psk-ccmp-tkip.pcapng");
        let mut decryptor = Decryptor::new(Some(&pmk), None, false);
        for (i, frame) in frames.iter().enumerate() {
            decryptor.frame(i + 1, frame);
            if let Some(group) = decryptor.groups.values().find(|g| !g.gtk.is_empty()) {
                assert_eq!(group.cipher, 2);
                return;
            }
        }
        panic!("no GTK installed");
    }

    /// A trailing FCS is recognised and removed: the capture with one on
    /// every frame decrypts as without.
    #[test]
    fn test_a_trailing_fcs() {
        let (frames, pmk) = wireshark_capture("wpa2-psk-mfp.pcapng");
        let with_fcs: Vec<Vec<u8>> = frames.iter().map(|f| {
            let mut f = f.clone();
            f.extend_from_slice(&allcrypt::checksum::crc32(&f).to_le_bytes());
            f
        }).collect();
        let plain = decrypt_frames(&frames, &pmk, false, |_| true);
        let fcs = decrypt_frames(&with_fcs, &pmk, false, |_| true);
        assert!(!plain.is_empty());
        assert_eq!(numbers(&fcs), numbers(&plain));
        assert!(fcs.iter().zip(&plain).all(|(a, b)| a.plaintext == b.plaintext));
    }

    /// A TKIP frame sealed again under `tk` with `plaintext`: its header
    /// and TSC kept, Michael computed over the plaintext under the MIC key
    /// for the frame's direction, and one bit of it changed when `bend`.
    fn tkip_reseal(tk: &[u8], frame: &[u8], plaintext: &[u8], bend: bool) -> Vec<u8> {
        let z = header_len(frame);
        let mic_key: [u8; 8] = if frame[1] & 3 == 1 { &tk[24..32] } else { &tk[16..24] }
            .try_into().unwrap();
        let (da, sa) = da_sa(frame);
        let mut mic = tkip::msdu_mic(&mic_key, &da, &sa, priority(frame), plaintext);
        if bend {
            mic[3] ^= 0x10;
        }
        let iv16 = u16::from_be_bytes([frame[z], frame[z + 2]]);
        let iv32 = u32::from_le_bytes(frame[z + 4..z + 8].try_into().unwrap());
        let tsc = (u64::from(iv32) << 16) | u64::from(iv16);
        let rc4_key = tkip::rc4_key(tk[..16].try_into().unwrap(), &addr(frame, 10), tsc);
        let mut out = frame[..z + 8].to_vec();
        out.extend(wep::seal(&rc4_key, &[plaintext, &mic[..]].concat()).unwrap());
        out
    }

    /// `wpa1-gtk-rekey`, its pairwise TKIP frames decrypted.
    struct Wpa1Pairwise {
        frames: Vec<Vec<u8>>,
        pmk: Vec<u8>,
        /// Each pairwise frame's index in `frames`, and its plaintext.
        pairwise: Vec<(usize, Vec<u8>)>,
        tk: Vec<u8>,
    }

    fn wpa1_pairwise() -> Wpa1Pairwise {
        let (frames, pmk) = wireshark_capture("wpa1-gtk-rekey.pcapng");
        let mut decryptor = Decryptor::new(Some(&pmk), None, false);
        let mut pairwise = Vec::new();
        let mut tk = None;
        for (i, frame) in frames.iter().enumerate() {
            if let Some(d) = decryptor.frame(i + 1, frame) {
                if d.kind == Kind::Pairwise {
                    let frame = strip_fcs(frame);
                    let (bssid, station) = bssid_and_station(frame).unwrap();
                    tk.get_or_insert_with(|| decryptor.stations[&(bssid, station)].tk()
                        .unwrap().to_vec());
                    pairwise.push((i, d.plaintext));
                }
            }
        }
        Wpa1Pairwise { frames, pmk, pairwise, tk: tk.expect("a pairwise frame") }
    }

    /// TKIP's Michael is checked under the MIC key for the frame's
    /// direction: every pairwise frame of `wpa1-gtk-rekey`, sealed again
    /// under its TK with its MIC right, opens, and with one bit of the MIC
    /// changed - the ICV still right - does not, unless `airdecap`.
    #[test]
    fn test_michael_is_checked() {
        let Wpa1Pairwise { frames, pmk, pairwise, tk } = wpa1_pairwise();
        assert!(pairwise.len() > 5);
        for airdecap in [false, true] {
            for bend in [false, true] {
                let mut resealed = frames.clone();
                for (i, plaintext) in &pairwise {
                    resealed[*i] = tkip_reseal(&tk, strip_fcs(&frames[*i]), plaintext, bend);
                }
                let opened = decrypt_frames(&resealed, &pmk, airdecap, |_| true).iter()
                    .filter(|d| d.kind == Kind::Pairwise).count();
                let expected = decrypt_frames(&frames, &pmk, airdecap, |_| true).iter()
                    .filter(|d| d.kind == Kind::Pairwise).count();
                assert_eq!(opened, if bend && !airdecap { 0 } else { expected },
                           "airdecap {airdecap}, MIC bent {bend}");
            }
        }
    }

    /// A group key handshake whose MIC does not verify installs nothing:
    /// `wpa1-gtk-rekey`'s group messages, which travel inside pairwise
    /// TKIP frames, sealed again with one bit of the EAPOL MIC changed,
    /// leave the group frames under the keys they carried shut.
    #[test]
    fn test_a_group_handshake_is_authenticated() {
        let Wpa1Pairwise { frames, pmk, pairwise, tk } = wpa1_pairwise();
        let groups = |frames: &[Vec<u8>]| decrypt_frames(frames, &pmk, false, |_| true).iter()
            .filter(|d| d.kind == Kind::Group).count();
        let mut bent = frames.clone();
        let mut changed = 0;
        for (i, plaintext) in &pairwise {
            // LLC/SNAP, then EAPOL: the key information at 13, the MIC at
            // 89; not pairwise, with a MIC and the ack.
            let info = u16::from_be_bytes([plaintext[13], plaintext[14]]);
            if plaintext[6..8] == [0x88, 0x8e] && info & 0x0188 == 0x0180 {
                let mut eapol = plaintext.clone();
                eapol[8 + 81] ^= 1;
                bent[*i] = tkip_reseal(&tk, strip_fcs(&frames[*i]), &eapol, false);
                changed += 1;
            }
        }
        assert!(changed >= 2);
        let (before, after) = (groups(&frames), groups(&bent));
        assert!(after < before, "{after} group frames, {before} before");
    }

    /// A frame with four addresses is between the hosts in its third and
    /// fourth: the Ethernet frame written
    /// for each of `wpa2-psk-4addr`'s is from 0b:.. to 0a:.., whichever
    /// end of the link sent it.
    #[test]
    fn test_four_addresses_name_the_hosts() {
        let (frames, pmk) = wireshark_capture("wpa2-psk-4addr.pcap");
        let decrypted = decrypt_frames(&frames, &pmk, false, |_| true);
        assert_eq!(decrypted.len(), 3);
        for d in &decrypted {
            let ethernet = d.ethernet.as_ref().unwrap();
            assert_eq!(ethernet[..12], [[0x0a; 6], [0x0b; 6]].concat());
        }
    }

    /// The suites are the first of each list in an RSN element, the AKM
    /// found after however many pairwise suites there are: here two.
    #[test]
    fn test_an_rsn_element_with_two_pairwise_suites() {
        // Element 48: version 1, group CCMP, two pairwise (TKIP, CCMP),
        // one AKM (PSK), capabilities.
        let element = [0x30, 0x18, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x02, 0x00,
                       0x00, 0x0f, 0xac, 0x02, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
                       0x00, 0x0f, 0xac, 0x02, 0x00, 0x00];
        assert_eq!(parse_suites(&element),
                   Some(Suites { akm: 2, pairwise: 2, group: 4, wpa1: false }));
        // A reassociation request carries one too, after its current AP.
        let (frames, _) = wireshark_capture("wpa-gcmp.pcapng");
        let request = frames.iter().find(|f| f[0] == 0x00).expect("an association request");
        let mut again = request.clone();
        again[0] = 0x20;
        again.splice(28..28, [0x02; 6]);
        let mut decryptor = Decryptor::new(None, None, false);
        decryptor.frame(1, &again);
        let suites: Vec<u8> = decryptor.stations.values().filter_map(|s| s.suites)
            .map(|s| s.pairwise).collect();
        assert_eq!(suites, [8]);
    }

    /// GTK and IGTK key data elements by their key index, and padding
    /// after them.
    #[test]
    fn test_key_data_elements() {
        let mut data = vec![0xdd, 0x16, 0x00, 0x0f, 0xac, 0x01, 0x02, 0x00];
        data.extend([0x11; 16]);
        data.extend([0xdd, 0x1c, 0x00, 0x0f, 0xac, 0x09, 0x04, 0x00, 1, 0, 0, 0, 0, 0]);
        data.extend([0x22; 16]);
        data.extend([0xdd, 0x00, 0x00, 0x00]);
        let mut group = Group::default();
        read_kdes(&data, &mut group);
        assert_eq!(group.gtk.keys().copied().collect::<Vec<_>>(), [2]);
        assert_eq!(group.gtk[&2], [0x11; 16]);
        assert_eq!(group.igtk[&4], [0x22; 16]);
    }

    /// A WEP frame this library sealed opens, and both a wrong key and a
    /// one-bit change are refused by the ICV.
    #[test]
    fn test_wep_round_trip() {
        let key = b"ABCDE";
        let frame = {
            // A minimal data frame: FC, duration, three addresses, SC,
            // the 4-byte WEP IV, then the WEP body.
            let mut f = vec![0x08, 0x41, 0, 0];
            f.extend_from_slice(&[0x11; 6]);        // A1
            f.extend_from_slice(&[0x22; 6]);        // A2
            f.extend_from_slice(&[0x33; 6]);        // A3 (BSSID)
            f.extend_from_slice(&[0, 0]);           // SC
            f.extend_from_slice(&[0x01, 0x02, 0x03, 0x00]);   // IV, keyid 0
            let snap = b"\xaa\xaa\x03\x00\x00\x00\x08\x00payload";
            f.extend(wep::encrypt(key, &[0x01, 0x02, 0x03], snap).unwrap());
            f
        };
        let z = header_len(&frame);
        assert!(open_wep(&frame, z, key).is_some());
        assert!(open_wep(&frame, z, b"WRONG").is_none());
        let mut bent = frame.clone();
        bent[28] ^= 1;
        assert!(open_wep(&bent, z, key).is_none());
    }
}
