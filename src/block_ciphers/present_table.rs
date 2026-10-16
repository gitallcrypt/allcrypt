// Written by scripts/make_oldcipher_tables.py from the witness sources
// presentgo/block.go
// kurtfu/present.c
// opentitan/Present.py
// which agree on every entry; do not edit.

/// PRESENT's 4-bit S-box.
pub(crate) const S: [u8; 16] = [
    0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d, 0x03, 0x0e, 0x0f, 0x08,
    0x04, 0x07, 0x01, 0x02,
];
