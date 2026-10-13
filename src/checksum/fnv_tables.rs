// The FNV primes, 2^TOP + 2^8 + LOW, for each size in bits.
// Written by scripts/make_fnv_tables.py, which finds them by the
// rule that defines them and requires Landon Curt Noll's C, libfnv
// and fnv-es to carry the same; do not edit.

/// (bits, TOP, LOW).
pub(crate) const PRIMES: [(usize, u32, u8); 6] = [
    (32, 24, 0x93),
    (64, 40, 0xb3),
    (128, 88, 0x3b),
    (256, 168, 0x63),
    (512, 344, 0x57),
    (1024, 680, 0x8d),
];
