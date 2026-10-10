//! The line protocol `scripts/witness/signalwitness` speaks, spoken by
//! this implementation, so that `scripts/check_signal.py` can put either
//! one on either side of a conversation and the offline tests can replay
//! a recorded one. The witness's header lists the commands; replies and
//! error codes are the same here, byte for byte.

use allcrypt::ec::xeddsa::{self, Form};

use crate::rng::Random;
use crate::session::{Bundle, Party};
use crate::wire::{Error, PublicKey, SENDERKEY_TYPE};

pub use crate::cli::hex;

pub struct Agent {
    pub party: Party,
    name: String,
    peer: String,
}

fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    crate::cli::unhex(text, &[]).map_err(|_| Error::INVALID_ARGUMENT)
}

fn number(text: &str) -> Result<u32, Error> {
    text.parse().map_err(|_| Error::INVALID_ARGUMENT)
}

fn fixed<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    unhex(text)?.try_into().map_err(|_| Error::INVALID_ARGUMENT)
}

impl Agent {
    pub fn new(random: Random, registration_id: u32, name: &str, peer: &str)
               -> Result<Agent, Error> {
        Ok(Agent { party: Party::new(random, registration_id)?, name: name.to_string(),
                   peer: peer.to_string() })
    }

    /// One command in, one reply out.
    pub fn run(&mut self, line: &str) -> String {
        let words: Vec<&str> = line.split_whitespace().collect();
        match self.command(&words) {
            Ok(reply) => reply,
            Err(error) => format!("error {}", error.0),
        }
    }

    fn command(&mut self, words: &[&str]) -> Result<String, Error> {
        let party = &mut self.party;
        match words {
            ["identity"] => Ok(format!("identity {}", hex(&party.identity.public.serialize()))),
            ["prekeys", pre_key_id, signed_id] => {
                let bundle = party.publish(number(pre_key_id)?, number(signed_id)?)?;
                let (id, key) = bundle.pre_key.ok_or(Error::UNKNOWN)?;
                Ok(format!("bundle {} {} {} {} {} {} {} {}", bundle.registration_id,
                           bundle.device_id, id, hex(&key.serialize()),
                           bundle.signed_pre_key_id, hex(&bundle.signed_pre_key.serialize()),
                           hex(&bundle.signature), hex(&bundle.identity.serialize())))
            }
            ["process", registration_id, device_id, pre_key_id, pre_key, signed_id,
             signed_key, signature, identity] => {
                let raw: Vec<Option<Vec<u8>>> = [pre_key, signed_key, signature, identity]
                    .iter()
                    .map(|field| if **field == "-" { Ok(None) } else { unhex(field).map(Some) })
                    .collect::<Result<_, _>>()?;
                let pre_key = match (*pre_key_id, &raw[0]) {
                    ("-", _) => None,
                    (id, Some(key)) => Some((number(id)?, PublicKey::decode(key)?)),
                    (_, None) => return Err(Error::INVALID_KEY),
                };
                let decode = |field: &Option<Vec<u8>>| {
                    PublicKey::decode(field.as_deref().unwrap_or(&[]))
                };
                let bundle = Bundle {
                    registration_id: number(registration_id)?,
                    device_id: number(device_id)?,
                    pre_key,
                    signed_pre_key_id: number(signed_id)?,
                    signed_pre_key: decode(&raw[1])?,
                    signature: raw[2].clone().unwrap_or_default(),
                    identity: decode(&raw[3])?,
                };
                party.process_bundle(&self.peer, &bundle)?;
                Ok("ok".to_string())
            }
            ["encrypt", plaintext] => {
                let (kind, bytes) = party.encrypt(&self.peer, &unhex(plaintext)?)?;
                Ok(format!("message {} {}", kind, hex(&bytes)))
            }
            ["decrypt", kind, bytes] => {
                let kind = kind.parse().unwrap_or(0);
                let plaintext = party.decrypt(&self.peer, kind, &unhex(bytes)?)?;
                Ok(format!("plaintext {}", hex(&plaintext)))
            }
            ["group-create", group] => {
                let message = party.groups.distribution(&mut party.random, group, &self.name)?;
                Ok(format!("distribution {}", hex(&message)))
            }
            ["group-process", group, bytes] => {
                party.groups.process(group, &self.peer, &unhex(bytes)?)?;
                Ok("ok".to_string())
            }
            ["group-encrypt", group, plaintext] => {
                let message = party.groups.encrypt(&mut party.random, group, &self.name,
                                                   &unhex(plaintext)?)?;
                Ok(format!("message {} {}", SENDERKEY_TYPE, hex(&message)))
            }
            ["group-decrypt", group, bytes] => {
                let plaintext = party.groups.decrypt(group, &self.peer, &unhex(bytes)?)?;
                Ok(format!("plaintext {}", hex(&plaintext)))
            }
            [command @ ("sign" | "xsign"), key, message, random] => {
                let form = if *command == "sign" { Form::Signal } else { Form::Specification };
                let signature = xeddsa::sign(form, &fixed(key)?, &unhex(message)?,
                                             &fixed(random)?)
                    .map_err(|_| Error::UNKNOWN)?;
                Ok(format!("signature {}", hex(&signature)))
            }
            [command @ ("verify" | "xverify"), key, message, signature] => {
                let form = if *command == "verify" { Form::Signal } else { Form::Specification };
                let verified = xeddsa::verify(form, &fixed(key)?, &unhex(message)?,
                                              &fixed(signature)?).is_ok();
                Ok(format!("verified {}", u8::from(verified)))
            }
            _ => Err(Error::INVALID_ARGUMENT),
        }
    }
}
