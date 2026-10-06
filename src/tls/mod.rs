/*
TLS.

Sans-I/O throughout: nothing in here opens a socket, reads one, or knows
that sockets exist. Bytes come in through `push_incoming`, bytes come out
through `take_outgoing`, and whoever owns the connection does the actual
reading and writing. That is not an aesthetic choice - it is what lets the
whole stack be tested against recorded transcripts, byte for byte, with no
network and no timing, and it is what lets Python own the socket while the
protocol lives in Rust.

The shape of the decision: Python keeps the sockets, this keeps the
protocol.

What is here: SSLv3 to TLS 1.3, client (`client`) and server (`server`,
`server13`), over the record layers (`record`, `record13` and the GOST
ones), with the key schedules in `keys` and `keys13`.

Nothing in this module trusts anything it reads. A record arrives from the
peer before the handshake has finished, so every length is checked against
its limit, every version against what was negotiated, and every failure is
an alert rather than a panic.
*/

pub mod client;
pub mod codec;
pub mod handshake;
pub mod handshake13;
pub mod kex;
pub mod keys;
pub mod keys13;
pub mod record;
pub mod record13;
pub mod gost_kex;
pub mod gost_kex_28147;
pub mod record_cnt_imit;
pub mod resumption;
pub mod record_gost;
pub mod record_mgm;
pub mod server;
pub mod server13;
pub mod suites;
pub mod tickets;

use core::fmt;

// --------------------------------------------------------------- versions ---

/// A protocol version, as the two bytes on the wire.
///
/// Kept as the raw pair rather than an enum of known versions, because an
/// unknown version has to be *reportable* - a server that answers with
/// something we have never heard of should produce a clear error, not a
/// parse failure.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl Version {
    pub const SSL30: Version = Version { major: 3, minor: 0 };
    pub const TLS10: Version = Version { major: 3, minor: 1 };
    pub const TLS11: Version = Version { major: 3, minor: 2 };
    pub const TLS12: Version = Version { major: 3, minor: 3 };
    pub const TLS13: Version = Version { major: 3, minor: 4 };

    pub const fn new(major: u8, minor: u8) -> Version {
        Version { major, minor }
    }

    pub fn from_bytes(bytes: [u8; 2]) -> Version {
        Version { major: bytes[0], minor: bytes[1] }
    }

    pub fn to_bytes(self) -> [u8; 2] {
        [self.major, self.minor]
    }

    /// The name everyone uses, or the raw pair if we do not know it.
    pub fn name(self) -> String {
        match self {
            Version::SSL30 => "SSLv3".to_string(),
            Version::TLS10 => "TLSv1".to_string(),
            Version::TLS11 => "TLSv1.1".to_string(),
            Version::TLS12 => "TLSv1.2".to_string(),
            Version::TLS13 => "TLSv1.3".to_string(),
            other => format!("unknown version {}.{}", other.major, other.minor),
        }
    }

    pub fn is_known(self) -> bool {
        matches!(self, Version::SSL30 | Version::TLS10 | Version::TLS11
                     | Version::TLS12 | Version::TLS13)
    }

    /// Whether this version's CBC mode carries an explicit IV per record.
    ///
    /// TLS 1.1 added it, precisely because chaining the IV from the previous
    /// record is what made BEAST work. SSLv3 and TLS 1.0 do not have it, and
    /// this library implements them anyway - that is the point of it - so
    /// the distinction has to be a property rather than an assumption.
    pub fn has_explicit_iv(self) -> bool {
        self >= Version::TLS11
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ----------------------------------------------------------- content types ---

/// What a record carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContentType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    /// Kept rather than rejected, so an unexpected type produces
    /// `unexpected_message` from the state machine rather than a parse
    /// error from the framer. The two failures mean different things.
    Unknown(u8),
}

impl ContentType {
    pub fn from_byte(byte: u8) -> ContentType {
        match byte {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            other => ContentType::Unknown(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::ApplicationData => 23,
            ContentType::Unknown(other) => other,
        }
    }

    pub fn name(self) -> String {
        match self {
            ContentType::ChangeCipherSpec => "change_cipher_spec".to_string(),
            ContentType::Alert => "alert".to_string(),
            ContentType::Handshake => "handshake".to_string(),
            ContentType::ApplicationData => "application_data".to_string(),
            ContentType::Unknown(byte) => format!("unknown content type {}", byte),
        }
    }
}

// ----------------------------------------------------------------- alerts ---

/// Alert severity. A fatal alert ends the connection; a warning does not,
/// except `close_notify`, which is how a clean shutdown is spelled.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AlertLevel {
    Warning,
    Fatal,
    Unknown(u8),
}

impl AlertLevel {
    pub fn from_byte(byte: u8) -> AlertLevel {
        match byte {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            other => AlertLevel::Unknown(other),
        }
    }

    pub fn to_byte(self) -> u8 {
        match self {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
            AlertLevel::Unknown(other) => other,
        }
    }
}

/// The alert codes from RFC 5246 section 7.2, plus the SSLv3 ones that
/// survived and the later additions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AlertDescription(pub u8);

impl AlertDescription {
    pub const CLOSE_NOTIFY: AlertDescription = AlertDescription(0);
    pub const UNEXPECTED_MESSAGE: AlertDescription = AlertDescription(10);
    pub const BAD_RECORD_MAC: AlertDescription = AlertDescription(20);
    pub const DECRYPTION_FAILED: AlertDescription = AlertDescription(21);
    pub const RECORD_OVERFLOW: AlertDescription = AlertDescription(22);
    pub const DECOMPRESSION_FAILURE: AlertDescription = AlertDescription(30);
    pub const HANDSHAKE_FAILURE: AlertDescription = AlertDescription(40);
    pub const NO_CERTIFICATE: AlertDescription = AlertDescription(41);
    pub const BAD_CERTIFICATE: AlertDescription = AlertDescription(42);
    pub const UNSUPPORTED_CERTIFICATE: AlertDescription = AlertDescription(43);
    pub const CERTIFICATE_REVOKED: AlertDescription = AlertDescription(44);
    pub const CERTIFICATE_EXPIRED: AlertDescription = AlertDescription(45);
    pub const CERTIFICATE_UNKNOWN: AlertDescription = AlertDescription(46);
    pub const ILLEGAL_PARAMETER: AlertDescription = AlertDescription(47);
    pub const UNKNOWN_CA: AlertDescription = AlertDescription(48);
    pub const ACCESS_DENIED: AlertDescription = AlertDescription(49);
    pub const DECODE_ERROR: AlertDescription = AlertDescription(50);
    pub const DECRYPT_ERROR: AlertDescription = AlertDescription(51);
    pub const EXPORT_RESTRICTION: AlertDescription = AlertDescription(60);
    pub const PROTOCOL_VERSION: AlertDescription = AlertDescription(70);
    pub const INSUFFICIENT_SECURITY: AlertDescription = AlertDescription(71);
    pub const INTERNAL_ERROR: AlertDescription = AlertDescription(80);
    pub const INAPPROPRIATE_FALLBACK: AlertDescription = AlertDescription(86);
    pub const USER_CANCELED: AlertDescription = AlertDescription(90);
    pub const NO_RENEGOTIATION: AlertDescription = AlertDescription(100);
    pub const MISSING_EXTENSION: AlertDescription = AlertDescription(109);
    pub const UNSUPPORTED_EXTENSION: AlertDescription = AlertDescription(110);
    pub const UNRECOGNIZED_NAME: AlertDescription = AlertDescription(112);
    /// RFC 8446 6.2, TLS 1.3 only: the peer asked for a certificate and did
    /// not get one. Distinct from `bad_certificate`, which is about the one
    /// that arrived.
    pub const CERTIFICATE_REQUIRED: AlertDescription = AlertDescription(116);
    pub const NO_APPLICATION_PROTOCOL: AlertDescription = AlertDescription(120);

    pub fn name(self) -> String {
        match self.0 {
            0 => "close_notify".to_string(),
            10 => "unexpected_message".to_string(),
            20 => "bad_record_mac".to_string(),
            21 => "decryption_failed".to_string(),
            22 => "record_overflow".to_string(),
            30 => "decompression_failure".to_string(),
            40 => "handshake_failure".to_string(),
            41 => "no_certificate".to_string(),
            42 => "bad_certificate".to_string(),
            43 => "unsupported_certificate".to_string(),
            44 => "certificate_revoked".to_string(),
            45 => "certificate_expired".to_string(),
            46 => "certificate_unknown".to_string(),
            47 => "illegal_parameter".to_string(),
            48 => "unknown_ca".to_string(),
            49 => "access_denied".to_string(),
            50 => "decode_error".to_string(),
            51 => "decrypt_error".to_string(),
            60 => "export_restriction".to_string(),
            70 => "protocol_version".to_string(),
            71 => "insufficient_security".to_string(),
            80 => "internal_error".to_string(),
            86 => "inappropriate_fallback".to_string(),
            90 => "user_canceled".to_string(),
            100 => "no_renegotiation".to_string(),
            109 => "missing_extension".to_string(),
            110 => "unsupported_extension".to_string(),
            112 => "unrecognized_name".to_string(),
            116 => "certificate_required".to_string(),
            120 => "no_application_protocol".to_string(),
            other => format!("alert {}", other),
        }
    }
}

/// One alert, as it appears on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn fatal(description: AlertDescription) -> Alert {
        Alert { level: AlertLevel::Fatal, description }
    }

    pub fn warning(description: AlertDescription) -> Alert {
        Alert { level: AlertLevel::Warning, description }
    }

    pub fn close_notify() -> Alert {
        Alert::warning(AlertDescription::CLOSE_NOTIFY)
    }

    pub fn parse(payload: &[u8]) -> Result<Alert, String> {
        if payload.len() != 2 {
            return Err(format!("An alert is two bytes, got {}.", payload.len()));
        }
        Ok(Alert {
            level: AlertLevel::from_byte(payload[0]),
            description: AlertDescription(payload[1]),
        })
    }

    pub fn to_bytes(self) -> [u8; 2] {
        [self.level.to_byte(), self.description.0]
    }

    /// Whether receiving this alert ends the connection.
    ///
    /// `close_notify` is a warning and still ends it, which is the one case
    /// that catches people out.
    pub fn is_terminal(self) -> bool {
        self.level == AlertLevel::Fatal
            || self.description == AlertDescription::CLOSE_NOTIFY
    }

    pub fn name(self) -> String {
        let level = match self.level {
            AlertLevel::Warning => "warning",
            AlertLevel::Fatal => "fatal",
            AlertLevel::Unknown(byte) => return format!(
                "unknown alert level {} ({})", byte, self.description.name()),
        };
        format!("{} {}", level, self.description.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_round_trip() {
        for version in [Version::SSL30, Version::TLS10, Version::TLS11,
                        Version::TLS12, Version::TLS13] {
            assert_eq!(Version::from_bytes(version.to_bytes()), version);
            assert!(version.is_known());
            assert!(!version.name().contains("unknown"));
        }

        let future = Version::new(3, 9);
        assert!(!future.is_known());
        assert_eq!(future.name(), "unknown version 3.9");
        assert_eq!(Version::from_bytes([3, 9]), future);
    }

    /// Versions must order the way the protocol thinks they do, because
    /// every "at least TLS 1.1" check depends on it.
    #[test]
    fn test_version_ordering() {
        assert!(Version::SSL30 < Version::TLS10);
        assert!(Version::TLS10 < Version::TLS11);
        assert!(Version::TLS11 < Version::TLS12);
        assert!(Version::TLS12 < Version::TLS13);

        // The explicit IV arrived in TLS 1.1, which is the BEAST fix.
        assert!(!Version::SSL30.has_explicit_iv());
        assert!(!Version::TLS10.has_explicit_iv());
        assert!(Version::TLS11.has_explicit_iv());
        assert!(Version::TLS12.has_explicit_iv());
    }

    #[test]
    fn test_content_types() {
        for (byte, expected) in [(20u8, ContentType::ChangeCipherSpec),
                                 (21, ContentType::Alert),
                                 (22, ContentType::Handshake),
                                 (23, ContentType::ApplicationData)] {
            assert_eq!(ContentType::from_byte(byte), expected);
            assert_eq!(expected.to_byte(), byte);
        }
        // Unknown types survive the round trip rather than being lost, so
        // the state machine can answer with unexpected_message.
        assert_eq!(ContentType::from_byte(99), ContentType::Unknown(99));
        assert_eq!(ContentType::Unknown(99).to_byte(), 99);
    }

    #[test]
    fn test_alerts() {
        let alert = Alert::fatal(AlertDescription::BAD_RECORD_MAC);
        assert_eq!(alert.to_bytes(), [2, 20]);
        assert_eq!(Alert::parse(&[2, 20]).unwrap(), alert);
        assert_eq!(alert.name(), "fatal bad_record_mac");
        assert!(alert.is_terminal());

        // close_notify is a *warning* that still ends the connection, which
        // is the case that catches people out.
        let close = Alert::close_notify();
        assert_eq!(close.level, AlertLevel::Warning);
        assert!(close.is_terminal());

        // An ordinary warning does not end it.
        let warning = Alert::warning(AlertDescription::USER_CANCELED);
        assert!(!warning.is_terminal());

        assert!(Alert::parse(&[2]).is_err());
        assert!(Alert::parse(&[2, 20, 0]).is_err());
        assert!(Alert::parse(&[]).is_err());

        // **`scripts/check_live.py` parses this text**, and it has to
        // tell two kinds of alert apart: `handshake_failure` means the
        // peer declined and says nothing about us, while `decode_error`
        // means the peer read what we sent and could not parse it - which
        // is what three CryptoPro servers sent about a ClientKeyExchange
        // of ours. Its pattern is `The peer sent a (?:fatal|warning)
        // (\w+)\.`, so both halves of this format matter to something
        // outside this file.
        //
        // Pinned here because that script guessed the format instead of
        // reading it: it was written to expect `The peer sent a
        // handshake_failure.` with no level, and "verified" against a
        // string typed by hand rather than one this function produced.
        // The assertion three lines above said what the format was the
        // whole time.
        assert_eq!(Alert::fatal(AlertDescription::HANDSHAKE_FAILURE).name(),
                   "fatal handshake_failure");
        assert_eq!(Alert::fatal(AlertDescription::DECODE_ERROR).name(),
                   "fatal decode_error");
        for alert in [Alert::fatal(AlertDescription::HANDSHAKE_FAILURE),
                      Alert::fatal(AlertDescription::DECODE_ERROR),
                      Alert::warning(AlertDescription::USER_CANCELED)] {
            let name = alert.name();
            let (level, description) = name.split_once(' ')
                .expect("check_live.py needs `<level> <description>`");
            assert!(level == "fatal" || level == "warning", "{level}");
            assert!(description.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '_'),
                    "check_live.py matches \\w+: {description:?}");
        }

        // An unknown code is still readable, which matters when a server
        // sends something we have to report to a human.
        assert_eq!(AlertDescription(200).name(), "alert 200");
    }
}
