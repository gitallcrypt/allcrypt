//! The YubiKey OTP application's challenge-response: HMAC-SHA1 under a
//! secret in one of the key's two "slots", which is what KeePassXC,
//! `pam_yubico` and full-disk-encryption unlockers use. Over USB it is
//! usually reached as a keyboard device; this is the same application
//! reached as a smart card (AID `A0 00 00 05 27 20 01`), which is how it
//! answers through PC/SC and over NFC.
//!
//! **Nothing but a YubiKey implements this**, and no YubiKey has checked
//! this file: the virtual card used for the other three applications
//! has no OTP application. What has checked it is in
//! `examples/products/README.md` - the bytes it sends against yubikit,
//! Yubico's own library, and the answers against HMAC computed here.
//!
//! Three things about the format are easy to get wrong, all from yubikit:
//!
//! * **The challenge is padded to 64 bytes**, with a byte different from
//!   its last, and a slot configured with `HMAC_LT64` (which this example
//!   always sets, as yubikit does) strips trailing bytes equal to the
//!   last before computing the HMAC. So the MAC is over the challenge as
//!   given - except that a full 64-byte challenge loses any repeats of
//!   its last byte, which no padding can avoid.
//! * **A 20-byte HMAC key is split across two fields** of the 52-byte
//!   configuration: the first 16 bytes in `key`, the last 4 at the start
//!   of `uid`. A key longer than SHA-1's block is hashed first, as HMAC
//!   would; one between 21 and 64 bytes cannot be stored.
//! * **The configuration ends in a CRC-16** (ISO/IEC 13239, reflected
//!   polynomial `8408`), complemented and little-endian.

use super::card::Card;

pub const AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01];

const INS_CONFIG: u8 = 0x01;
const INS_STATUS: u8 = 0x03;

const CONFIG_1: u8 = 0x01;
const CONFIG_2: u8 = 0x03;
const CHAL_HMAC_1: u8 = 0x30;
const CHAL_HMAC_2: u8 = 0x38;

const FIXED_SIZE: usize = 16;
const UID_SIZE: usize = 6;
const KEY_SIZE: usize = 16;
const ACCESS_CODE_SIZE: usize = 6;
const CHALLENGE_SIZE: usize = 64;

// Ticket, configuration and extended flags (yubikit's TKTFLAG, CFGFLAG
// and EXTFLAG).
const TKT_CHAL_RESP: u8 = 0x40;
const CFG_CHAL_HMAC: u8 = 0x22;
const CFG_HMAC_LT64: u8 = 0x04;
const CFG_CHAL_BTN_TRIG: u8 = 0x08;
const EXT_SERIAL_API_VISIBLE: u8 = 0x04;
const EXT_ALLOW_UPDATE: u8 = 0x20;

/// The status block: firmware version, programming sequence, touch level.
#[derive(Debug, Clone)]
pub struct Status {
    pub version: [u8; 3],
    pub sequence: u8,
}

fn parse_status(data: &[u8]) -> Result<Status, String> {
    if data.len() < 4 {
        return Err("The OTP status is shorter than four bytes.".to_string());
    }
    Ok(Status { version: [data[0], data[1], data[2]], sequence: data[3] })
}

/// ISO/IEC 13239's CRC-16, as the YubiKey checks a configuration: the
/// reflected polynomial 0x8408, starting from 0xFFFF.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            let low = crc & 1;
            crc >>= 1;
            if low == 1 {
                crc ^= 0x8408;
            }
        }
    }
    crc
}

/// The 52-byte configuration for an HMAC-SHA1 challenge-response slot,
/// followed by the six-byte current access code (zeros for none).
pub fn hmac_configuration(key: &[u8], require_touch: bool) -> Result<Vec<u8>, String> {
    let key = if key.len() > 64 {
        allcrypt::api::AnyHash::new("sha1").map(|mut hash| {
            use allcrypt::hash_functions::HashFunction;
            hash.update(key);
            hash.digest()
        })?
    } else if key.len() > 20 {
        return Err("A challenge-response key is at most 20 bytes, or longer than 64 to be \
                    hashed down.".to_string());
    } else {
        key.to_vec()
    };
    let mut padded = key.clone();
    padded.resize(20, 0);

    let mut config = vec![0u8; FIXED_SIZE];
    config.extend_from_slice(&padded[16..20]);
    config.extend_from_slice(&[0, 0]);
    debug_assert_eq!(config.len(), FIXED_SIZE + UID_SIZE);
    config.extend_from_slice(&padded[..KEY_SIZE]);
    config.extend_from_slice(&[0u8; ACCESS_CODE_SIZE]);
    let mut cfg = CFG_CHAL_HMAC | CFG_HMAC_LT64;
    if require_touch {
        cfg |= CFG_CHAL_BTN_TRIG;
    }
    // Length of the fixed part, then the three flag bytes, then two RFU.
    config.extend_from_slice(&[0, EXT_SERIAL_API_VISIBLE | EXT_ALLOW_UPDATE, TKT_CHAL_RESP,
                               cfg, 0, 0]);
    let crc = !crc16(&config);
    config.extend_from_slice(&crc.to_le_bytes());
    debug_assert_eq!(config.len(), 52);
    // The current access code, which this example never sets.
    config.extend_from_slice(&[0u8; ACCESS_CODE_SIZE]);
    Ok(config)
}

/// A challenge as the key wants it: padded to 64 bytes with a byte that
/// differs from its last.
pub fn pad_challenge(challenge: &[u8]) -> Result<Vec<u8>, String> {
    if challenge.len() > CHALLENGE_SIZE {
        return Err("A challenge is at most 64 bytes.".to_string());
    }
    let pad = if challenge.last() == Some(&0) { 1 } else { 0 };
    let mut out = challenge.to_vec();
    out.resize(CHALLENGE_SIZE, pad);
    Ok(out)
}

pub struct Otp<'a> {
    pub card: &'a mut Card,
    pub status: Status,
}

fn slot_command(slot: u8, one: u8, two: u8) -> Result<u8, String> {
    match slot {
        1 => Ok(one),
        2 => Ok(two),
        _ => Err("The OTP application has slots 1 and 2.".to_string()),
    }
}

impl<'a> Otp<'a> {
    pub fn select(card: &'a mut Card) -> Result<Otp<'a>, String> {
        card.get_response = 0xC0;
        let answer = card.select(&AID, "YubiKey OTP")?;
        let status = parse_status(&answer)?;
        Ok(Otp { card, status })
    }

    /// The serial number (configuration slot 0x10). This application's
    /// commands go without `Le`, as yubikit sends them, so that the two
    /// can be compared byte for byte.
    pub fn serial(&mut self) -> Result<u32, String> {
        let data = self.card.call(0, INS_CONFIG, 0x10, 0, &[], "Reading the serial")?;
        let bytes: [u8; 4] = data.as_slice().try_into()
            .map_err(|_| "The serial is not four bytes.".to_string())?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// HMAC-SHA1 of `challenge` under the slot's key.
    pub fn challenge_response(&mut self, slot: u8, challenge: &[u8]) -> Result<Vec<u8>, String> {
        let command = slot_command(slot, CHAL_HMAC_1, CHAL_HMAC_2)?;
        let answer = self.card.call(0, INS_CONFIG, command, 0, &pad_challenge(challenge)?,
                                    &format!("Challenge-response with slot {slot}"))?;
        if answer.len() != 20 {
            return Err(format!("The response is {} bytes, not 20 - is slot {slot} set up \
                                for HMAC-SHA1?", answer.len()));
        }
        Ok(answer)
    }

    /// Program a slot for HMAC-SHA1 challenge-response. Overwrites
    /// whatever the slot held.
    pub fn program_hmac(&mut self, slot: u8, key: &[u8], require_touch: bool)
                        -> Result<(), String> {
        let command = slot_command(slot, CONFIG_1, CONFIG_2)?;
        let config = hmac_configuration(key, require_touch)?;
        let mut answer = self.card.call(0, INS_CONFIG, command, 0, &config,
                                        &format!("Programming slot {slot}"))?;
        if answer.is_empty() {
            // Some keys answer a configuration with nothing; the status
            // instruction says whether it took.
            answer = self.card.call(0, INS_STATUS, 0, 0, &[], "Reading the OTP status")?;
        }
        let status = parse_status(&answer)?;
        if status.sequence == self.status.sequence {
            return Err(format!("Slot {slot} was not written: the programming sequence did \
                                not advance (is the slot protected by an access code?)."));
        }
        self.status = status;
        Ok(())
    }
}
