//! YKOATH: the one-time password application on a YubiKey (and on a
//! CanoKey), which keeps HOTP (RFC 4226) and TOTP (RFC 6238) secrets and
//! computes codes from them. It is what Yubico Authenticator reads.
//!
//! The card holds the secret and computes `HMAC(secret, counter)`; the
//! host supplies the counter - the time step for TOTP - and turns the four
//! bytes the card returns into digits. So the host decides what time it
//! is, and a host with a wrong clock gets wrong codes from a correct card.
//!
//! An optional **access key** locks the application. It is never sent:
//! the card issues a challenge and the host answers with
//! `HMAC-SHA1(key, challenge)`, then challenges the card back so a card
//! that accepted anything is caught. The key is derived from a password
//! with PBKDF2-HMAC-SHA1, 1000 iterations, salted with the card's
//! identifier from SELECT - so the same password makes a different key
//! on every card.
//!
//! Two quirks of the encoding, both from Yubico's protocol description
//! and yubikit, the reference implementation:
//!
//! * the touch property is written `78 02` - a tag and a value with **no
//!   length byte** - where every other field is a TLV;
//! * a secret shorter than 14 bytes is zero-padded to 14, and one longer
//!   than the hash's block is replaced by its hash, as HMAC itself would.
//!   The card's answer is the same either way; the padding is what the
//!   card expects to store.
//!
//! A long answer is continued with SEND REMAINING (`A5`), not GET
//! RESPONSE.

use allcrypt::api;

use super::card::Card;
use super::tlv;

pub const AID: [u8; 7] = [0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

const INS_PUT: u8 = 0x01;
const INS_DELETE: u8 = 0x02;
const INS_SET_CODE: u8 = 0x03;
const INS_RESET: u8 = 0x04;
const INS_LIST: u8 = 0xA1;
const INS_CALCULATE: u8 = 0xA2;
const INS_VALIDATE: u8 = 0xA3;
const INS_CALCULATE_ALL: u8 = 0xA4;
const INS_SEND_REMAINING: u8 = 0xA5;

const TAG_NAME: u32 = 0x71;
const TAG_NAME_LIST: u32 = 0x72;
const TAG_KEY: u32 = 0x73;
const TAG_CHALLENGE: u32 = 0x74;
const TAG_RESPONSE: u32 = 0x75;
const TAG_TRUNCATED: u32 = 0x76;
const TAG_HOTP: u32 = 0x77;
const TAG_PROPERTY: u8 = 0x78;
const TAG_VERSION: u32 = 0x79;
const TAG_IMF: u32 = 0x7A;
const TAG_TOUCH: u32 = 0x7C;

const HOTP: u8 = 0x10;
const TOTP: u8 = 0x20;
const REQUIRE_TOUCH: u8 = 0x02;
const MINIMUM_KEY: usize = 14;

/// HOTP or TOTP, and the hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kind {
    pub totp: bool,
    /// `sha1`, `sha256` or `sha512`.
    pub hash: &'static str,
}

impl Kind {
    fn code(self) -> u8 {
        let algorithm = match self.hash {
            "sha256" => 0x02,
            "sha512" => 0x03,
            _ => 0x01,
        };
        (if self.totp { TOTP } else { HOTP }) | algorithm
    }

    fn from_code(code: u8) -> Result<Kind, String> {
        let hash = match code & 0x0F {
            0x01 => "sha1",
            0x02 => "sha256",
            0x03 => "sha512",
            other => return Err(format!("A credential has hash {other:02x}, which YKOATH \
                                         does not define.")),
        };
        Ok(Kind { totp: code & 0xF0 == TOTP, hash })
    }

    fn block_size(self) -> usize {
        if self.hash == "sha512" { 128 } else { 64 }
    }
}

/// What the card answered to SELECT.
#[derive(Debug, Clone)]
pub struct Selected {
    pub version: Vec<u8>,
    /// The salt for the access key, which is also the card's identifier.
    pub salt: Vec<u8>,
    /// Present when an access key is set: the challenge to answer.
    pub challenge: Option<Vec<u8>>,
}

/// One stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// The stored name: `[period/][issuer:]account`.
    pub name: String,
    pub kind: Kind,
}

impl Credential {
    pub fn period(&self) -> u64 {
        period(&self.name)
    }
}

/// A TOTP credential's period, from its name's prefix; 30 when there is
/// none.
pub fn period(name: &str) -> u64 {
    name.split_once('/').and_then(|(period, _)| period.parse().ok()).unwrap_or(30)
}

/// The stored name for an account, as yubikit writes it: a TOTP
/// period other than 30 seconds goes in front, then the issuer.
pub fn credential_name(issuer: Option<&str>, account: &str, totp: bool, period: u64) -> String {
    let mut name = String::new();
    if totp && period != 30 {
        name.push_str(&format!("{period}/"));
    }
    if let Some(issuer) = issuer {
        name.push_str(issuer);
        name.push(':');
    }
    name.push_str(account);
    name
}

/// The digits for the four bytes after the digit count, as RFC 4226
/// 5.3 truncates: the top bit cleared, reduced mod 10^digits.
pub fn format_code(truncated: &[u8]) -> Result<String, String> {
    let (&digits, value) = truncated.split_first().ok_or("The card's code is empty.")?;
    let value: [u8; 4] = value.try_into().map_err(|_| "The card's code is not four bytes.")?;
    let number = u32::from_be_bytes(value) & 0x7FFF_FFFF;
    let digits = usize::from(digits);
    if !(6..=10).contains(&digits) {
        return Err(format!("The card says {digits} digits."));
    }
    Ok(format!("{:0width$}", u64::from(number) % 10u64.pow(digits as u32), width = digits))
}

/// The code a secret gives for a counter, computed here: RFC 4226's
/// HOTP, which TOTP is with the time step as the counter. What the card
/// is checked against.
pub fn compute_code(secret: &[u8], hash: &str, counter: u64, digits: usize)
                    -> Result<String, String> {
    let mac = api::hmac(hash, secret, &counter.to_be_bytes())?;
    let offset = usize::from(mac[mac.len() - 1] & 0x0F);
    let mut truncated = vec![digits as u8];
    truncated.extend_from_slice(&mac[offset..offset + 4]);
    format_code(&truncated)
}

/// The access key for a password on this card.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Vec<u8>, String> {
    api::pbkdf2("sha1", password.as_bytes(), salt, 1000, 16)
}

pub struct Oath<'a> {
    pub card: &'a mut Card,
    pub selected: Selected,
}

impl<'a> Oath<'a> {
    pub fn select(card: &'a mut Card) -> Result<Oath<'a>, String> {
        card.get_response = INS_SEND_REMAINING;
        let answer = card.select(&AID, "OATH")?;
        let selected = Selected {
            version: tlv::find(&answer, TAG_VERSION)?.to_vec(),
            salt: tlv::find(&answer, TAG_NAME)?.to_vec(),
            challenge: tlv::find_optional(&answer, TAG_CHALLENGE)?.map(<[u8]>::to_vec),
        };
        Ok(Oath { card, selected })
    }

    pub fn locked(&self) -> bool {
        self.selected.challenge.is_some()
    }

    /// Unlock with the access key: answer the card's challenge, and check
    /// its answer to ours.
    pub fn validate(&mut self, key: &[u8]) -> Result<(), String> {
        let challenge = self.selected.challenge.clone()
            .ok_or("The OATH application has no access key set.")?;
        let ours = self.card.random(8)?;
        let mut data = tlv::encode(TAG_RESPONSE, &api::hmac("sha1", key, &challenge)?);
        data.extend_from_slice(&tlv::encode(TAG_CHALLENGE, &ours));
        let response = self.card.send(0, INS_VALIDATE, 0, 0, &data)?;
        if response.sw == 0x6A80 || response.sw == 0x6982 {
            return Err("The OATH password is wrong.".to_string());
        }
        let answer = response.check("Unlocking OATH")?;
        let expected = api::hmac("sha1", key, &ours)?;
        if tlv::find(&answer, TAG_RESPONSE)? != expected.as_slice() {
            return Err("The card accepted the password but could not prove it knows the \
                        key: its answer to our challenge is wrong.".to_string());
        }
        self.selected.challenge = None;
        Ok(())
    }

    /// Set (or with `None` remove) the access key.
    pub fn set_key(&mut self, key: Option<&[u8]>) -> Result<(), String> {
        let data = match key {
            None => tlv::encode(TAG_KEY, &[]),
            Some(key) => {
                let challenge = self.card.random(8)?;
                let mut value = vec![TOTP | 0x01];
                value.extend_from_slice(key);
                let mut data = tlv::encode(TAG_KEY, &value);
                data.extend_from_slice(&tlv::encode(TAG_CHALLENGE, &challenge));
                data.extend_from_slice(&tlv::encode(TAG_RESPONSE,
                                                    &api::hmac("sha1", key, &challenge)?));
                data
            }
        };
        self.card.call(0, INS_SET_CODE, 0, 0, &data, "Setting the OATH password")?;
        Ok(())
    }

    /// Store a credential.
    pub fn put(&mut self, name: &str, kind: Kind, secret: &[u8], digits: u8, touch: bool,
               counter: u32) -> Result<(), String> {
        if !(6..=8).contains(&digits) {
            return Err("OATH codes are 6, 7 or 8 digits.".to_string());
        }
        if name.len() > 64 {
            return Err("A credential name is at most 64 bytes.".to_string());
        }
        let mut key = if secret.len() > kind.block_size() {
            hash(kind.hash, secret)?
        } else {
            secret.to_vec()
        };
        if key.len() < MINIMUM_KEY {
            key.resize(MINIMUM_KEY, 0);
        }
        let mut value = vec![kind.code(), digits];
        value.extend_from_slice(&key);
        let mut data = tlv::encode(TAG_NAME, name.as_bytes());
        data.extend_from_slice(&tlv::encode(TAG_KEY, &value));
        if touch {
            // A tag and a value, with no length byte between them.
            data.extend_from_slice(&[TAG_PROPERTY, REQUIRE_TOUCH]);
        }
        if counter > 0 {
            data.extend_from_slice(&tlv::encode(TAG_IMF, &counter.to_be_bytes()));
        }
        self.card.call(0, INS_PUT, 0, 0, &data, &format!("Storing {name}"))?;
        Ok(())
    }

    pub fn delete(&mut self, name: &str) -> Result<(), String> {
        self.card.call(0, INS_DELETE, 0, 0, &tlv::encode(TAG_NAME, name.as_bytes()),
                       &format!("Deleting {name}"))?;
        Ok(())
    }

    pub fn list(&mut self) -> Result<Vec<Credential>, String> {
        let answer = self.card.get(0, INS_LIST, 0, 0, "Listing the credentials")?;
        let mut out = Vec::new();
        for item in tlv::parse(&answer)? {
            if item.tag != TAG_NAME_LIST {
                continue;
            }
            let (&code, name) = item.value.split_first().ok_or("An empty list entry.")?;
            out.push(Credential { name: String::from_utf8_lossy(name).into_owned(),
                                  kind: Kind::from_code(code)? });
        }
        Ok(out)
    }

    /// One credential's code: for TOTP at the Unix time `now`, for HOTP
    /// at the card's own counter, which this advances.
    pub fn calculate(&mut self, credential: &Credential, now: u64) -> Result<String, String> {
        let step = credential.kind.totp.then(|| now / credential.period());
        self.calculate_named(&credential.name, step)
    }

    /// One credential's code: TOTP with its time step as the challenge,
    /// HOTP with none (the card counts).
    fn calculate_named(&mut self, name: &str, step: Option<u64>) -> Result<String, String> {
        let challenge = step.map(|step| step.to_be_bytes().to_vec()).unwrap_or_default();
        let mut data = tlv::encode(TAG_NAME, name.as_bytes());
        data.extend_from_slice(&tlv::encode(TAG_CHALLENGE, &challenge));
        let response = self.card.send(0, INS_CALCULATE, 0, 0x01, &data)?;
        if response.sw == 0x6985 {
            return Err(format!("{name} needs a touch."));
        }
        let answer = response.check(&format!("Calculating {name}"))?;
        format_code(tlv::find(&answer, TAG_TRUNCATED)?)
    }

    /// Every TOTP credential's code at `now` in one command. HOTP and
    /// touch credentials are listed without one: computing an HOTP code
    /// advances its counter, so the card only does it when asked by name.
    pub fn calculate_all(&mut self, now: u64) -> Result<Vec<(String, Option<String>)>, String> {
        let challenge = (now / 30).to_be_bytes();
        let answer = self.card.call(0, INS_CALCULATE_ALL, 0, 0x01,
                                    &tlv::encode(TAG_CHALLENGE, &challenge),
                                    "Calculating the codes")?;
        let items = tlv::parse(&answer)?;
        let mut out = Vec::new();
        for pair in items.chunks(2) {
            let [name, code] = pair else {
                return Err("The card's list of codes has an odd number of entries.".to_string());
            };
            if name.tag != TAG_NAME {
                return Err("The card's list of codes is out of order.".to_string());
            }
            let name = String::from_utf8_lossy(name.value).into_owned();
            let code = match code.tag {
                TAG_TRUNCATED => Some(format_code(code.value)?),
                TAG_HOTP | TAG_TOUCH => None,
                other => return Err(format!("A code entry has tag {other:x}.")),
            };
            out.push((name, code));
        }
        // The card used one challenge for every credential: the 30-second
        // step. A credential with another period got a code for the wrong
        // time, so it is asked again with its own.
        for (name, code) in out.iter_mut() {
            let period = period(name);
            if code.is_some() && period != 30 {
                *code = Some(self.calculate_named(name, Some(now / period))?);
            }
        }
        Ok(out)
    }

    /// Remove every credential and the access key.
    pub fn reset(&mut self) -> Result<(), String> {
        self.card.call(0, INS_RESET, 0xDE, 0xAD, &[], "Resetting OATH")?;
        Ok(())
    }
}

fn hash(name: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    use allcrypt::hash_functions::HashFunction;
    let mut hash = api::AnyHash::new(name)?;
    hash.update(data);
    Ok(hash.digest())
}

/// A base32 secret as authenticator apps show it (RFC 4648, no padding
/// required, spaces and case ignored).
pub fn base32_decode(text: &str) -> Result<Vec<u8>, String> {
    let mut bits = 0u64;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u64 - 'A' as u64,
            c @ '2'..='7' => c as u64 - '2' as u64 + 26,
            _ => return Err(format!("{c:?} is not base32.")),
        };
        bits = (bits << 5) | value;
        count += 5;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Ok(out)
}
