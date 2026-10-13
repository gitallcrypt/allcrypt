// DSTU 9041:2020's curves E256/1 and E512/1. Written by
// scripts/make_dstu9041_params.py from uacrypt's hazmat/dstu9041 and
// li0ard's dstu9041/curve.ts, which agree on every value; do not edit.

/// One curve, x^2 + a·y^2 = 1 + d·x^2·y^2 over GF(p) with a = 2: the
/// field's bits, the longest message `l_max(p)` and the hash's kept
/// length `l_H` in bits (the standard's Table 1), then `p`, `d`, the
/// base point's order `n` and its coordinates, big-endian hexadecimal.
pub(crate) struct Params {
    pub(crate) bits: usize,
    pub(crate) l_max: usize,
    pub(crate) l_h: usize,
    pub(crate) p: &'static str,
    pub(crate) d: &'static str,
    pub(crate) n: &'static str,
    pub(crate) gx: &'static str,
    pub(crate) gy: &'static str,
}

/// E256/1 and E512/1, the first curves of Tables В.1 and В.3.
pub(crate) const CURVES: [Params; 2] = [
    Params { bits: 256, l_max: 200, l_h: 32,
             p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe4d",
             d: "18",
             n: "4000000000000000000000000000000029e26087789bc2815bdff97093543ccf",
             gx: "91f5d0e7e2d417e3108b13b075cdc7756045f8424479fcfe8f23d27250a0883f",
             gy: "742f27a268641c9d7ddf69892be3df3d8f9cc52260b89a4953c8379c7c0a212b" },
    Params { bits: 512, l_max: 424, l_h: 64,
             p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc95",
             d: "10d",
             n: "400000000000000000000000000000000000000000000000000000000000000028a3ce52209e2bd4952882d5574165192c46c0d0311fea6bf9fece70ee63b59f",
             gx: "5230a1ee747050a072bd7319741586ea520388b6b53094571c821a2fc9a9e83d56665346b5db04c43e75261dbda512728faafac48ae9260a5a184e2933e3a400",
             gy: "53a0d50cc63c9219762f451978aef214dbcfcc3a5cb5ef27124991a86b42b3a1a832724a0e6b930fdd1da2e27a540d6b675e4422c444f529c508f0bae7d0a85" },
];
