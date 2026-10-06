//! Wi-Fi payload decryption from a capture file, built from this
//! library's primitives: WEP, and WPA/WPA2 with TKIP or CCMP once the
//! 4-way handshake in the capture has yielded the pairwise key.
//!
//!     cargo run --release --example wifi -- decrypt CAP --wep-key HEX [--out FILE]
//!     cargo run --release --example wifi -- decrypt CAP --essid NAME --password-stdin
//!         [--bssid AA:BB:..] [--out FILE] [--pmk HEX]
//!
//! It prints a tally - stations, data frames, how many decrypted - and
//! with `--out` writes the decrypted frames as `airdecap-ng` does: each
//! becomes an Ethernet frame (the 802.11 and LLC/SNAP headers replaced
//! by a 14-byte Ethernet header), in a link-type-1 pcap.
//!
//! The pieces are the library's: WEP and TKIP in `stream_ciphers`, the
//! TKIP key mixing and Michael there and in `mac`, AES-CCM in
//! `block_ciphers::ccm`, and the PSK, PRF, PTK and PMKID in
//! `kdf::ieee80211`. The 802.11 framing - which bytes are the nonce, the
//! additional authenticated data, the sequence counter - is here.
//!
//! What has checked it is in `examples/products/README.md`.

use std::collections::HashMap;

use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::ccm;
use allcrypt::hash_functions::sha1::SHA1;
use allcrypt::hash_functions::md5::MD5;
use allcrypt::kdf::ieee80211;
use allcrypt::mac::Hmac;
use allcrypt::stream_ciphers::{tkip, wep};

#[path = "pcap.rs"]
mod pcap;
#[path = "../shared/passphrase.rs"]
mod passphrase;
#[path = "../shared/fixtures.rs"]
#[cfg(test)]
mod fixtures;

type Mac = [u8; 6];

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let text: String = text.split([':', '-']).collect::<String>()
        .split_whitespace().collect();
    if !text.len().is_multiple_of(2) {
        return Err("An odd number of hex digits.".to_string());
    }
    (0..text.len()).step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

/// Where the data begins after an 802.11 header: 24 bytes, 30 with a
/// fourth address, plus 2 for a QoS control field.
fn header_len(frame: &[u8]) -> usize {
    let a4 = frame[1] & 3 == 3;
    let qos = frame[0] & 0x8c == 0x88;
    24 + if a4 { 6 } else { 0 } + if qos { 2 } else { 0 }
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

/// A data frame? type is 2 (`fc0 & 0x0c == 0x08`), and null-data
/// subtypes (0x44, 0x48, 0x4c, 0xc0) carry nothing.
fn is_data(frame: &[u8]) -> bool {
    frame.len() >= 24 && frame[0] & 0x0c == 0x08 && frame[0] & 0x40 == 0
}

fn addr(frame: &[u8], at: usize) -> Mac {
    frame[at..at + 6].try_into().unwrap()
}

/// The BSSID and the station's address, from the To-DS/From-DS bits.
fn bssid_and_station(frame: &[u8]) -> Option<(Mac, Mac)> {
    match frame[1] & 3 {
        0 => Some((addr(frame, 16), addr(frame, 4))),   // IBSS: BSSID is A3
        1 => Some((addr(frame, 4), addr(frame, 10))),   // to the AP
        2 => Some((addr(frame, 10), addr(frame, 4))),   // from the AP
        _ => Some((addr(frame, 10), addr(frame, 4))),   // WDS: TA as BSSID
    }
}

#[derive(Default)]
struct Station {
    bssid: Mac,
    station: Mac,
    anonce: Option<[u8; 32]>,
    snonce: Option<[u8; 32]>,
    eapol: Option<Vec<u8>>,
    key_mic: Option<Vec<u8>>,
    keyver: u8,
    ptk: Option<Vec<u8>>,
    last_crc: [u32; 2],
}

/// Collect the handshake, and derive the PTK once a nonce from each side
/// and an EAPOL frame with its MIC are in hand and the MIC checks.
impl Station {
    fn eapol_key(&mut self, frame: &[u8], z: usize, pmk: &[u8]) {
        // The LLC/SNAP then the EAPOL header: ethertype 0x888e at z+6.
        if frame.len() < z + 8 + 97 || frame[z + 6] != 0x88 || frame[z + 7] != 0x8e {
            return;
        }
        let e = z + 8;                       // the EAPOL frame
        if frame[e + 1] != 3 {               // key frame
            return;
        }
        let info = u16::from_be_bytes([frame[e + 5], frame[e + 6]]);
        let (pairwise, install, ack, mic) =
            (info & 0x08 != 0, info & 0x40 != 0, info & 0x80 != 0, info & 0x100 != 0);
        if !pairwise {
            return;
        }
        let nonce: [u8; 32] = frame[e + 17..e + 49].try_into().unwrap();
        if ack && !mic {
            self.anonce = Some(nonce);                       // message 1
        } else if !ack && mic && nonce != [0; 32] {
            self.snonce = Some(nonce);                       // message 2
        } else if ack && install && mic && nonce != [0; 32] {
            self.anonce = Some(nonce);                       // message 3
        }
        if mic {
            let size = u16::from_be_bytes([frame[e + 2], frame[e + 3]]) as usize + 4;
            if frame.len() >= e + size && size >= 97 {
                self.key_mic = Some(frame[e + 81..e + 97].to_vec());
                let mut eapol = frame[e..e + size].to_vec();
                eapol[81..97].fill(0);
                self.eapol = Some(eapol);
                self.keyver = (info & 7) as u8;
            }
        }
        self.derive(pmk);
    }

    fn derive(&mut self, pmk: &[u8]) {
        let (Some(anonce), Some(snonce), Some(eapol), Some(key_mic)) =
            (self.anonce, self.snonce, &self.eapol, &self.key_mic) else { return };
        // The station address is not stored here; the PTK input sorts the
        // two addresses, so BSSID and either peer give the same key.
        let ptk = ieee80211::ptk_sha1(pmk, &self.bssid, &self.station, &anonce, &snonce, 512);
        let kck = &ptk[..16];
        let computed = if self.keyver == 1 {
            Hmac::mac(MD5::new(&[]), kck, eapol)[..16].to_vec()
        } else {
            Hmac::mac(SHA1::new(&[]), kck, eapol)[..16].to_vec()
        };
        if &computed == key_mic {
            self.ptk = Some(ptk);
        }
    }
}

/// CCMP's nonce (13 bytes) and additional authenticated data, from the
/// frame (IEEE 802.11-2020 12.5.3): the nonce is a flags byte (the QoS
/// priority), A2, and the 48-bit packet number big endian; the AAD is
/// the header with the volatile bits of the frame-control, sequence-
/// control and QoS fields masked off.
fn ccmp_nonce_aad(frame: &[u8], z: usize) -> ([u8; 13], Vec<u8>) {
    let a4 = frame[1] & 3 == 3;
    let qos = frame[0] & 0x8c == 0x88;
    let priority = if qos { frame[z - 2] & 0x0f } else { 0 };
    // The packet number is at the start of the CCMP header, bytes
    // 0,1 then 4,5,6,7, most significant last.
    let pn = [frame[z + 7], frame[z + 6], frame[z + 5], frame[z + 4], frame[z + 1], frame[z]];
    let mut nonce = [0u8; 13];
    nonce[0] = priority;
    nonce[1..7].copy_from_slice(&frame[10..16]);
    nonce[7..13].copy_from_slice(&pn);

    let mut aad = Vec::with_capacity(32);
    aad.push(frame[0] & 0x8f);
    aad.push(frame[1] & 0xc7);
    aad.extend_from_slice(&frame[4..22]);           // A1, A2, A3
    aad.push(frame[22] & 0x0f);                     // sequence control
    aad.push(0);
    if a4 {
        aad.extend_from_slice(&frame[24..30]);      // A4
    }
    if qos {
        aad.push(priority);
        aad.push(0);
    }
    (nonce, aad)
}

/// Decrypt one protected data frame to its plaintext payload (the
/// LLC/SNAP and above), or `None` if it does not authenticate.
fn decrypt(frame: &[u8], station: &Station, wep_key: Option<&[u8]>) -> Option<Vec<u8>> {
    let z = header_len(frame);
    if frame.len() < z + 8 {
        return None;
    }
    let ext_iv = frame[z + 3] & 0x20 != 0;
    if !ext_iv {
        // WEP: the 3-byte IV then the shared key.
        let key = wep_key?;
        let mut rc4_key = frame[z..z + 3].to_vec();
        rc4_key.extend_from_slice(key);
        return wep::open(&rc4_key, &frame[z + 4..]).ok();
    }
    let ptk = station.ptk.as_ref()?;
    let tk = &ptk[32..48];
    match station.keyver {
        1 => {
            let ta = addr(frame, 10);
            let iv16 = u16::from_be_bytes([frame[z], frame[z + 2]]);
            let iv32 = u32::from_le_bytes(frame[z + 4..z + 8].try_into().unwrap());
            let tsc = (u64::from(iv32) << 16) | u64::from(iv16);
            let rc4_key = tkip::rc4_key(tk.try_into().unwrap(), &ta, tsc);
            wep::open(&rc4_key, &frame[z + 8..]).ok()
        }
        2 => {
            let (nonce, aad) = ccmp_nonce_aad(frame, z);
            let body = &frame[z + 8..];
            let mut aes = AesCrypto::new(tk.to_vec()).ok()?;
            ccm::decrypt(&mut aes, &nonce, &aad, &body[..body.len() - 8],
                         &body[body.len() - 8..]).ok()
        }
        _ => None,
    }
}

/// Convert a decrypted frame to the Ethernet frame `airdecap-ng` writes:
/// destination and source from the addresses (by the DS bits), then the
/// payload from after the LLC's `AA AA 03 00 00 00`, keeping its
/// ethertype.
fn to_ethernet(frame: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let (dst, src): (Mac, Mac) = match frame[1] & 3 {
        0 => (addr(frame, 4), addr(frame, 10)),
        1 => (addr(frame, 16), addr(frame, 10)),
        2 => (addr(frame, 4), addr(frame, 16)),
        _ => (addr(frame, 16), addr(frame, 24)),
    };
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
}

fn run(args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) != Some("decrypt") || args.len() < 2 {
        return Err("usage: wifi decrypt CAP (--wep-key HEX | --essid NAME \
                    (--password-stdin | --pmk HEX)) [--bssid MAC] [--out FILE]".to_string());
    }
    let capture = std::fs::read(&args[1]).map_err(|e| format!("{}: {e}", args[1]))?;
    let mut wep_key = None;
    let mut essid = None;
    let mut password = None;
    let mut pmk_hex = None;
    let mut want_bssid: Option<Mac> = None;
    let mut out_path = None;
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
            other => return Err(format!("unknown option {other}")),
        }
    }

    let pmk = match (&pmk_hex, &essid, &password) {
        (Some(pmk), _, _) => Some(pmk.clone()),
        (None, Some(essid), Some(password)) =>
            Some(ieee80211::psk(password, essid.as_bytes())?.to_vec()),
        _ => None,
    };

    let mut stations: HashMap<Mac, Station> = HashMap::new();
    let mut tally = Tally::default();
    let mut writer = pcap::Writer::new();
    let reader = pcap::Reader::new(&capture)?;

    for frame in reader {
        let frame = strip_fcs(frame);
        if !is_data(frame) {
            continue;
        }
        let z = header_len(frame);
        if frame.len() < z + 16 {
            continue;
        }
        let Some((bssid, station_mac)) = bssid_and_station(frame) else { continue };
        if let Some(want) = want_bssid {
            if want != bssid {
                continue;
            }
        }
        let station = stations.entry(station_mac).or_insert_with(|| {
            tally.stations += 1;
            Station { bssid, station: station_mac, ..Default::default() }
        });

        // A retransmitted frame has the same body CRC as the last in its
        // direction; airdecap-ng skips it, so the counts match when we do.
        let direction = usize::from(frame[1] & 3 == 2);
        let crc = allcrypt::checksum::crc32(&frame[z..]);
        if station.last_crc[direction] == crc && crc != 0 {
            continue;
        }
        station.last_crc[direction] = crc;

        // Encrypted data starts with neither the LLC's AA AA 03; an
        // unprotected frame is passed through.
        let protected = frame[1] & 0x40 != 0;
        if !protected {
            if frame[z] == 0xaa && frame[z + 1] == 0xaa && frame[z + 2] == 0x03 {
                tally.plain += 1;
                if let Some(pmk) = &pmk {
                    station.eapol_key(frame, z, pmk);
                }
            }
            continue;
        }

        let ext_iv = frame[z + 3] & 0x20 != 0;
        if !ext_iv {
            tally.wep += 1;
            if wep_key.is_none() {
                continue;
            }
            match decrypt(frame, station, wep_key.as_deref()) {
                Some(payload) => {
                    tally.unwep += 1;
                    emit(&mut writer, frame, &payload);
                }
                None => tally.bad_wep += 1,
            }
        } else {
            tally.wpa += 1;
            if station.ptk.is_none() {
                continue;
            }
            match decrypt(frame, station, None) {
                Some(mut payload) => {
                    tally.unwpa += 1;
                    // TKIP leaves its 8-byte Michael MIC after the data.
                    if station.keyver == 1 && payload.len() >= 8 {
                        payload.truncate(payload.len() - 8);
                    }
                    emit(&mut writer, frame, &payload);
                }
                None => tally.bad_wpa += 1,
            }
        }
    }

    println!("Stations seen:            {}", tally.stations);
    println!("WEP data frames:          {}", tally.wep);
    println!("WPA data frames:          {}", tally.wpa);
    println!("Plaintext data frames:    {}", tally.plain);
    println!("Decrypted WEP frames:     {}", tally.unwep);
    println!("Decrypted WPA frames:     {}", tally.unwpa);
    println!("Bad WEP frames:           {}", tally.bad_wep);
    println!("Bad WPA frames:           {}", tally.bad_wpa);
    if let Some(path) = out_path {
        std::fs::write(&path, writer.finish()).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(())
}

/// Write the decrypted frame out as Ethernet.
fn emit(writer: &mut pcap::Writer, frame: &[u8], payload: &[u8]) {
    if let Some(ethernet) = to_ethernet(frame, payload) {
        writer.write(&ethernet);
    }
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

    /// A helper that mirrors `run`'s decryption, returning the decrypted
    /// Ethernet payloads and the tally, so the fixtures can be checked
    /// without a file on disk.
    fn decrypt_capture(capture: &[u8], pmk: Option<&[u8]>, wep_key: Option<&[u8]>)
                       -> (Vec<Vec<u8>>, usize) {
        let mut stations: HashMap<Mac, Station> = HashMap::new();
        let mut payloads = Vec::new();
        let mut decrypted = 0;
        for frame in pcap::Reader::new(capture).unwrap() {
            let frame = strip_fcs(frame);
            if !is_data(frame) {
                continue;
            }
            let z = header_len(frame);
            if frame.len() < z + 16 {
                continue;
            }
            let Some((bssid, mac)) = bssid_and_station(frame) else { continue };
            let station = stations.entry(mac).or_insert_with(
                || Station { bssid, station: mac, ..Default::default() });
            let direction = usize::from(frame[1] & 3 == 2);
            let crc = allcrypt::checksum::crc32(&frame[z..]);
            if station.last_crc[direction] == crc && crc != 0 {
                continue;
            }
            station.last_crc[direction] = crc;
            let protected = frame[1] & 0x40 != 0;
            if !protected {
                if frame[z] == 0xaa && frame[z + 1] == 0xaa && frame[z + 2] == 0x03 {
                    if let Some(pmk) = pmk {
                        station.eapol_key(frame, z, pmk);
                    }
                }
                continue;
            }
            let ext_iv = frame[z + 3] & 0x20 != 0;
            if !ext_iv && wep_key.is_none() {
                continue;
            }
            if ext_iv && station.ptk.is_none() {
                continue;
            }
            if let Some(mut payload) = decrypt(frame, station, wep_key) {
                decrypted += 1;
                if ext_iv && station.keyver == 1 && payload.len() >= 8 {
                    payload.truncate(payload.len() - 8);
                }
                if let Some(ethernet) = to_ethernet(frame, &payload) {
                    payloads.push(ethernet);
                }
            }
        }
        (payloads, decrypted)
    }

    fn sha256(data: &[u8]) -> String {
        use allcrypt::hash_functions::HashFunction;
        let mut h = allcrypt::hash_functions::sha2::SHA256::new(&[]);
        h.update(data);
        hex(&h.digest())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
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
            f.extend(wep::encrypt(key, &[0x01, 0x02, 0x03], snap));
            f
        };
        let station = Station::default();
        assert!(decrypt(&frame, &station, Some(key)).is_some());
        assert!(decrypt(&frame, &station, Some(b"WRONG")).is_none());
        let mut bent = frame.clone();
        bent[28] ^= 1;
        assert!(decrypt(&bent, &station, Some(key)).is_none());
    }
}
