// LSH's first-step constants; every later step's follow from them.
// Written by scripts/make_lsh_tables.py from KISA's reference and
// Crypto++ 8.9.0, which agree on every step; do not edit.

pub(crate) const SC0_256: [u32; 8] = [
    0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243,
    0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
];

pub(crate) const SC0_512: [u64; 8] = [
    0x97884283c938982a, 0xba1fca93533e2355, 0xc519a2e87aeb1c03, 0x9a0fc95462af17b1,
    0xfc3dda8ab019a82b, 0x02825d079a895407, 0x79f2d0a7ee06a6f7, 0xd76d15eed9fdf5fe,
];
