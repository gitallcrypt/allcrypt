/*
SSH message numbers, RFC 4250 section 4.1, with RFC 8308's EXT_INFO and
RFC 4252's PK_OK. Shared by `client` and `server`.

Numbers 30 to 49 are reused by every key exchange method for its own
messages, and 60 to 79 by every authentication method, so a number in
those ranges means something only with the method in force:
`USERAUTH_PK_OK` and `USERAUTH_PASSWD_CHANGEREQ` are both 60.
*/

pub const DISCONNECT: u8 = 1;
pub const IGNORE: u8 = 2;
pub const UNIMPLEMENTED: u8 = 3;
pub const DEBUG: u8 = 4;
pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const EXT_INFO: u8 = 7;
pub const KEXINIT: u8 = 20;
pub const NEWKEYS: u8 = 21;
pub const KEX_30: u8 = 30;
pub const KEX_31: u8 = 31;
pub const KEX_DH_GEX_INIT: u8 = 32;
pub const KEX_DH_GEX_REPLY: u8 = 33;
pub const KEX_DH_GEX_REQUEST: u8 = 34;
/// RFC 4419's pre-standard request, carrying `n` alone. The same number
/// as `KEX_30`, which the method in use disambiguates.
pub const KEX_DH_GEX_REQUEST_OLD: u8 = 30;
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const USERAUTH_BANNER: u8 = 53;
pub const USERAUTH_PK_OK: u8 = 60;
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_SUCCESS: u8 = 81;
pub const REQUEST_FAILURE: u8 = 82;
pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;

/// DISCONNECT reason codes, RFC 4250 section 4.2.2.
pub mod reason {
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const BY_APPLICATION: u32 = 11;
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
}

/// CHANNEL_OPEN_FAILURE reason codes, RFC 4250 section 4.3.
pub mod open_failure {
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
    pub const RESOURCE_SHORTAGE: u32 = 4;
}
