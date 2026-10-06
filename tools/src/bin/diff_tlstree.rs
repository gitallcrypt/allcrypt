// The GOST key derivation functions, dumped for comparison against a
// reading of RFC 7836 and RFC 9189. Verified by scripts/diff_check.py.
//
// Nothing on this machine implements either one, so the reference is a
// second reading of the specifications - written in Python from the
// RFCs' prose rather than from this code. That is weaker than OpenSSL
// and it is what there is; the unit tests in `src/kdf/gost.rs` carry the
// RFCs' own vectors, and this corpus covers the space between them.
//
// What the space between them is for. The vectors in Appendix A.1.1
// print a handful of sequence numbers on one root key. Every mistake
// worth worrying about here is a *framing* mistake - the `0x01` counter
// byte, the `0x00` separator, the trailing `STR_2(256)`, the endianness
// of `STR_8` - and framing mistakes hide behind fixed lengths. So the
// rows sweep label and seed lengths across the Streebog block boundary
// (64 bytes) in both directions, where a length field written into the
// wrong place stops being absorbed by the padding.
//
// Two row kinds:
//
//   kdf <key> <label> <seed> <out>
//   tlstree <suite> <root> <sequence> <level1> <level2> <level3>
//
// The tlstree rows print all three levels rather than only the last,
// because a chain that is wrong at the first level and right afterwards
// is not a thing that can happen - but a chain that is right at the
// first two and wrong at the third is exactly what a mistaken C_3
// produces, and only the levels tell those apart.
use allcrypt::kdf::gost::{kdf_gostr3411_2012_256, tlstree_levels, TlsTreeParams};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 31 + seed as u32 * 97 + 5) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    // ------------------------------------------------------------ KDF ---
    //
    // Lengths either side of 64, the Streebog block. The framed input is
    // label + seed + 4, so a label of 60 with a seed of 0 lands exactly
    // on the block and a padding mistake shows there and nowhere else.
    let keys: [Vec<u8>; 3] = [
        pattern(32, 1),
        vec![0u8; 32],
        vec![0xffu8; 32],
    ];
    for (which, key) in keys.iter().enumerate() {
        for label_len in [0usize, 1, 6, 32, 58, 59, 60, 61, 64, 65, 120] {
            for seed_len in [0usize, 1, 8, 32, 63, 64, 65] {
                let label = pattern(label_len, which as u8 + 2);
                let seed = pattern(seed_len, which as u8 + 70);
                let out = kdf_gostr3411_2012_256(key, &label, &seed);
                println!("kdf {} {} {} {}",
                         hex(key), hex(&label), hex(&seed), hex(&out));
                cases += 1;
            }
        }
    }

    // A key longer than Streebog's block, which HMAC hashes down first,
    // and a key shorter than the digest, which it zero-pads. Both are
    // places an HMAC written for a fixed key length quietly differs.
    for key_len in [0usize, 1, 31, 32, 33, 63, 64, 65, 200] {
        let key = pattern(key_len, 7);
        let out = kdf_gostr3411_2012_256(&key, b"level1", &[0u8; 8]);
        println!("kdf {} {} {} {}", hex(&key), hex(b"level1"),
                 hex(&[0u8; 8]), hex(&out));
        cases += 1;
    }

    // -------------------------------------------------------- TLSTREE ---
    //
    // The sequence numbers are chosen to straddle every mask boundary of
    // both suites, and a few that straddle neither. A mask off by one
    // bit changes the level exactly at its boundary and nowhere else, so
    // a sweep that misses the boundaries cannot see it.
    let roots: [Vec<u8>; 3] = [
        pattern(32, 3),
        vec![0u8; 32],
        (0..32u8).map(|i| i.wrapping_mul(17)).collect(),
    ];

    let mut sequences: Vec<u64> = vec![0, 1, 2, 63, 64, 65, 4095, 4096, 4097];
    for shift in [6u32, 12, 19, 25, 32, 38, 63] {
        let boundary = 1u64 << shift;
        sequences.push(boundary - 1);
        sequences.push(boundary);
        sequences.push(boundary + 1);
    }
    // And a scatter that lines up with nothing, so the corpus is not
    // only boundaries.
    for step in 0..12u64 {
        sequences.push(step.wrapping_mul(0x0123_4567_89ab_cdef) ^ 0x5a5a_1234);
    }
    sequences.push(u64::MAX);
    sequences.sort_unstable();
    sequences.dedup();

    for (suite, params) in [("magma", TlsTreeParams::MAGMA),
                            ("kuznyechik", TlsTreeParams::KUZNYECHIK)] {
        for root in &roots {
            for &sequence in &sequences {
                let (one, two, three) = tlstree_levels(root, sequence, params);
                // A level that came out equal to its key would mean the
                // chain collapsed; never emit such a row silently.
                assert_ne!(one, *root, "{} level 1 returned its own key", suite);
                assert_ne!(two, one, "{} level 2 returned its own key", suite);
                assert_ne!(three, two, "{} level 3 returned its own key", suite);

                println!("tlstree {} {} {} {} {} {}", suite, hex(root), sequence,
                         hex(&one), hex(&two), hex(&three));
                cases += 1;
            }
        }
    }

    eprintln!("[diff_tlstree] {} cases", cases);
}
