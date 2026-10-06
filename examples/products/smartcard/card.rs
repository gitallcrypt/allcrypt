//! Talking to a card: APDUs, status words, and the transports that carry
//! them.
//!
//! ISO/IEC 7816-4 is the shared layer under every application here. A
//! command is `CLA INS P1 P2`, optional data, optional expected length; an
//! answer is data and a two-byte status word, `90 00` for success. Three
//! things on top of that are the same for all of them and live here:
//!
//! * **Long commands are chained**: each piece but the last has bit 0x10
//!   of CLA set (7816-4 5.3.3). Every card here accepts it, where
//!   extended-length APDUs are optional.
//! * **Long answers arrive in pieces**: `61 xx` means more is waiting, and
//!   is fetched with GET RESPONSE - except in YubiKey's OATH application,
//!   which uses its own SEND REMAINING instruction for the same thing.
//! * **`6C xx` means "ask again with Le = xx"**, which a T=0 card says
//!   when the expected length was wrong.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;

/// Something that carries one APDU and returns the card's answer: data
/// followed by the two status bytes.
pub trait Transport {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String>;
}

/// The card's answer to one command, pieces joined.
#[derive(Debug, Clone)]
pub struct Response {
    pub data: Vec<u8>,
    pub sw: u16,
}

impl Response {
    pub fn ok(&self) -> bool {
        self.sw == 0x9000
    }

    /// The data, or an error naming the status word and `what` failed.
    pub fn check(self, what: &str) -> Result<Vec<u8>, String> {
        if self.ok() {
            Ok(self.data)
        } else {
            Err(format!("{what}: the card answered {:04X} ({}).", self.sw, describe(self.sw)))
        }
    }
}

/// "1 try" or "N tries".
pub fn tries(count: u16) -> String {
    if count == 1 { "1 try".to_string() } else { format!("{count} tries") }
}

/// What a status word means, in ISO 7816-4's words where it has them.
pub fn describe(sw: u16) -> String {
    match sw {
        0x9000 => "success".to_string(),
        0x6283 => "the application is blocked".to_string(),
        0x6300 => "verification failed".to_string(),
        0x63C0..=0x63CF => format!("wrong, {} left", tries(sw & 0x0F)),
        0x6581 => "memory failure".to_string(),
        0x6700 => "wrong length".to_string(),
        0x6882 => "secure messaging is not supported".to_string(),
        0x6900 => "the command is not allowed".to_string(),
        0x6883 => "the last command of a chain was expected".to_string(),
        0x6884 => "command chaining is not supported".to_string(),
        0x6982 => "security status not satisfied - a PIN or key is needed first".to_string(),
        0x6983 => "blocked: no tries left".to_string(),
        0x6984 => "the reference data is not usable".to_string(),
        0x6985 => "conditions of use not satisfied".to_string(),
        0x6986 => "the command is not allowed here".to_string(),
        0x6A80 => "wrong data".to_string(),
        0x6A81 => "the function is not supported".to_string(),
        0x6A82 => "not found".to_string(),
        0x6A84 => "not enough memory".to_string(),
        0x6A86 => "wrong P1 or P2".to_string(),
        0x6A88 => "the referenced data does not exist".to_string(),
        0x6B00 => "wrong parameters".to_string(),
        0x6D00 => "the instruction is not supported".to_string(),
        0x6E00 => "the class is not supported".to_string(),
        0x6F00 => "the card failed without saying why".to_string(),
        _ => "not a status this example knows".to_string(),
    }
}

/// A card behind a transport, with the chaining and continuation rules.
pub struct Card {
    transport: Box<dyn Transport>,
    /// The instruction that fetches the rest of a `61 xx` answer: GET
    /// RESPONSE (`C0`) everywhere but YubiKey OATH (`A5`).
    pub get_response: u8,
    /// Where the host's random challenges come from: the operating
    /// system, or a fixed sequence in the tests, which replay recorded
    /// conversations byte for byte.
    pub random: Box<dyn FnMut(usize) -> Result<Vec<u8>, String>>,
}

/// The largest data field of a short APDU.
const SHORT: usize = 255;

impl Card {
    pub fn new(transport: Box<dyn Transport>) -> Card {
        Card { transport, get_response: 0xC0, random: Box::new(allcrypt::api::random_bytes) }
    }

    /// `n` random bytes for a challenge.
    pub fn random(&mut self, n: usize) -> Result<Vec<u8>, String> {
        (self.random)(n)
    }

    /// Send one command and gather the whole answer. No `Le` is sent:
    /// ISO 7816-4 case 1 without data, case 3 with.
    pub fn send(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8])
                -> Result<Response, String> {
        self.exchange(cla, ins, p1, p2, data, false)
    }

    /// A command that has no data and expects an answer: case 2, `Le`
    /// = 00, "as much as there is". YubiKeys answer the same command
    /// without `Le` too; CanoKey refuses OATH's LIST without it (6986),
    /// which is what 7816-4 allows a card to do.
    pub fn read(&mut self, cla: u8, ins: u8, p1: u8, p2: u8) -> Result<Response, String> {
        self.exchange(cla, ins, p1, p2, &[], true)
    }

    /// `read`, requiring 90 00.
    pub fn get(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, what: &str)
               -> Result<Vec<u8>, String> {
        self.read(cla, ins, p1, p2)?.check(what)
    }

    fn exchange(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], le: bool)
                -> Result<Response, String> {
        let mut pieces = data.chunks(SHORT).peekable();
        let mut answer = if data.is_empty() {
            let mut apdu = vec![cla, ins, p1, p2];
            if le {
                apdu.push(0);
            }
            self.raw(&apdu)?
        } else {
            let mut last = None;
            while let Some(piece) = pieces.next() {
                let chained = if pieces.peek().is_some() { cla | 0x10 } else { cla };
                let mut apdu = vec![chained, ins, p1, p2, piece.len() as u8];
                apdu.extend_from_slice(piece);
                if le && pieces.peek().is_none() {
                    apdu.push(0);
                }
                let response = self.raw(&apdu)?;
                if pieces.peek().is_some() && response.sw != 0x9000 {
                    return Ok(response);
                }
                last = Some(response);
            }
            last.expect("data is not empty")
        };
        // 6C xx: the same command with the length the card wants.
        if answer.sw >> 8 == 0x6C && data.len() <= SHORT {
            let mut apdu = vec![cla, ins, p1, p2];
            if !data.is_empty() {
                apdu.push(data.len() as u8);
                apdu.extend_from_slice(data);
            }
            apdu.push(answer.sw as u8);
            answer = self.raw(&apdu)?;
        }
        // 61 xx: more data waiting.
        while answer.sw >> 8 == 0x61 {
            let more = self.raw(&[0x00, self.get_response, 0x00, 0x00, answer.sw as u8])?;
            answer.data.extend_from_slice(&more.data);
            answer.sw = more.sw;
        }
        Ok(answer)
    }

    /// `send`, requiring 90 00.
    pub fn call(&mut self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8], what: &str)
                -> Result<Vec<u8>, String> {
        self.send(cla, ins, p1, p2, data)?.check(what)
    }

    /// SELECT an application by its AID; the answer is its FCI or
    /// whatever the application returns.
    pub fn select(&mut self, aid: &[u8], name: &str) -> Result<Vec<u8>, String> {
        let response = self.send(0x00, 0xA4, 0x04, 0x00, aid)?;
        if response.sw == 0x6A82 {
            return Err(format!("The card has no {name} application."));
        }
        response.check(&format!("Selecting {name}"))
    }

    fn raw(&mut self, apdu: &[u8]) -> Result<Response, String> {
        let mut answer = self.transport.transmit(apdu)?;
        if answer.len() < 2 {
            return Err("The card's answer has no status word.".to_string());
        }
        let sw = u16::from_be_bytes([answer[answer.len() - 2], answer[answer.len() - 1]]);
        answer.truncate(answer.len() - 2);
        Ok(Response { data: answer, sw })
    }
}

/// A card simulator on a TCP port speaking canokey-core's `apdu-replay`
/// line protocol: an APDU in hex per line, answered by `RESP ` and the
/// status word followed by the data, in hex. `scripts/witness/cardsim.py`
/// serves one.
pub struct Tcp {
    stream: TcpStream,
    reader: BufReader<TcpStream>,
}

impl Tcp {
    pub fn connect(address: &str) -> Result<Tcp, String> {
        let stream = TcpStream::connect(address)
            .map_err(|e| format!("Connecting to the card simulator at {address}: {e}."))?;
        let reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        Ok(Tcp { stream, reader })
    }
}

impl Transport for Tcp {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let line: String = apdu.iter().map(|b| format!("{b:02X}")).collect();
        writeln!(self.stream, "{line}").map_err(|e| format!("Writing to the simulator: {e}."))?;
        let mut answer = String::new();
        self.reader.read_line(&mut answer).map_err(|e| format!("Reading the simulator: {e}."))?;
        let hex = answer.trim().strip_prefix("RESP ")
            .ok_or_else(|| format!("The simulator answered {:?}.", answer.trim()))?;
        let bytes = super::unhex(hex)?;
        if bytes.len() < 2 {
            return Err("The simulator's answer has no status word.".to_string());
        }
        let mut out = bytes[2..].to_vec();
        out.extend_from_slice(&bytes[..2]);
        Ok(out)
    }
}

/// One command and the card's answer to it, status word included.
pub type Exchange = (Vec<u8>, Vec<u8>);

/// A recording of every exchange, for writing fixtures: wraps another
/// transport and keeps what crossed it.
pub struct Recorder {
    pub inner: Box<dyn Transport>,
    pub exchanges: std::rc::Rc<std::cell::RefCell<Vec<Exchange>>>,
}

impl Transport for Recorder {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let answer = self.inner.transmit(apdu)?;
        self.exchanges.borrow_mut().push((apdu.to_vec(), answer.clone()));
        Ok(answer)
    }
}

/// A card that answers from a recording, and refuses any command that
/// is not the next one recorded: what the offline tests use, so the
/// example must send byte for byte what it sent to the real card.
#[cfg(test)]
#[derive(Clone)]
pub struct Replay {
    exchanges: std::rc::Rc<std::cell::RefCell<std::collections::VecDeque<Exchange>>>,
}

#[cfg(test)]
impl Replay {
    pub fn new(exchanges: Vec<Exchange>) -> Replay {
        Replay { exchanges: std::rc::Rc::new(std::cell::RefCell::new(exchanges.into())) }
    }

    /// Exchanges not yet used: a test asserts none are left, or the
    /// example stopped short of what the recording did.
    pub fn remaining(&self) -> usize {
        self.exchanges.borrow().len()
    }
}

#[cfg(test)]
impl Transport for Replay {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, String> {
        let (expected, answer) = self.exchanges.borrow_mut().pop_front()
            .ok_or("The recording has ended and another command was sent.")?;
        if expected != apdu {
            return Err(format!("Sent {} where the recording has {}.", super::hex(apdu),
                               super::hex(&expected)));
        }
        Ok(answer)
    }
}

/// A deterministic stand-in for the host's randomness: SHA-256 of the
/// seed and a counter. For recordings that must replay byte for byte,
/// and for nothing else - a challenge anyone can predict proves nothing.
pub fn seeded_random(seed: u64) -> Box<dyn FnMut(usize) -> Result<Vec<u8>, String>> {
    let mut counter = 0u64;
    Box::new(move |n| {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            use allcrypt::hash_functions::HashFunction;
            let mut hash = allcrypt::api::AnyHash::new("sha256")?;
            hash.update(&seed.to_be_bytes());
            hash.update(&counter.to_be_bytes());
            counter += 1;
            out.extend_from_slice(&hash.digest());
        }
        out.truncate(n);
        Ok(out)
    })
}

/// A recording as the fixtures store it: `apdu:answer` pairs in hex,
/// separated by spaces.
pub fn encode_recording(exchanges: &[Exchange]) -> String {
    exchanges.iter().map(|(apdu, answer)| format!("{}:{}", super::hex(apdu), super::hex(answer)))
        .collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
pub fn decode_recording(text: &str) -> Result<Vec<Exchange>, String> {
    text.split_whitespace().map(|pair| {
        let (apdu, answer) = pair.split_once(':').ok_or("A recorded exchange has no colon.")?;
        Ok((super::unhex(apdu)?, super::unhex(answer)?))
    }).collect()
}
