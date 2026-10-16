// Written by scripts/make_oldcipher_tables.py from the witness sources
// inmcm/simon.py
// cryptopp/simon.cpp
// lwbc/simon32.rs
// lwbc/simon48.rs
// lwbc/simon64.rs
// lwbc/simon96.rs
// which agree on every entry; do not edit.

/// Simon's 62-bit constant sequences z0 to z4, consumed from the low
/// bit, one bit per round key after the key's own words.
pub(crate) const Z: [u64; 5] = [
    0x19c3522fb386a45f, 0x16864fb8ad0c9f71,
    0x3369f885192c0ef5, 0x3c2ce51207a635db,
    0x3dc94c3a046d678b,
];
