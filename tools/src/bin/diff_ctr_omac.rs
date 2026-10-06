// The CTR_OMAC record protection, dumped for comparison against a
// reading of RFC 9189 section 4.1.1. Verified by scripts/diff_check.py.
//
// The primitives underneath - Kuznyechik, Magma, OMAC, CTR-ACPKM,
// TLSTREE - each have a corpus of their own. This one is about the
// *composition*, which is where the remaining mistakes live:
//
//   * the MAC input's framing (`seq || type || version || length ||
//     fragment`), which is shared with every other TLS 1.2 suite and so
//     would be easy to get right by habit and wrong by one field;
//   * authenticate-then-encrypt rather than the other way round - the
//     MAC is *inside* the ciphertext, and a record built the other way
//     round has the same length and round-trips against itself;
//   * the IV being *added to* the sequence number and wrapping in its
//     own width;
//   * two levels of re-keying at once, one between records and one
//     inside them.
//
// The record lengths straddle both ACPKM section sizes in both
// directions, so a section size taken from the wrong suite shows. The
// sequence numbers straddle every TLSTREE boundary of both suites, and
// the IVs include ones near their own wrap.
//
//   ctromac <suite> <enckey> <mackey> <iv> <seq> <type> <version> <in> <out>
use allcrypt::tls::record::SequenceNumber;
use allcrypt::tls::record_gost::{encrypt, CtrOmac, CtrOmacSuite};
use allcrypt::tls::{ContentType, Version};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut cases = 0usize;

    let enc_key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
    let mac_key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(29).wrapping_add(11)).collect();

    // Every TLSTREE boundary of both suites, and some that are boundaries
    // for neither.
    let sequences = [0u64, 1, 5, 63, 64, 65, 4095, 4096, 4097,
                     524_287, 524_288, 33_554_431, 33_554_432,
                     0xFFFF_FFFE, 0xFFFF_FFFF];
    // Either side of both suites' ACPKM sections (1 KB and 4 KB), of a
    // block in both, and of nothing in particular.
    let lengths = [0usize, 1, 7, 8, 9, 15, 16, 17, 63, 64, 255,
                   1023, 1024, 1025, 2047, 2048,
                   4095, 4096, 4097, 5000, 8192];

    // Three slices rather than the cross product of all three axes. The
    // reference on the other side is Kuznyechik and Magma in Python, at
    // something under a megabyte a second, and the full product is tens
    // of megabytes of record - so the choice is between sweeping one
    // axis at a time and sweeping nothing properly.
    for (name, suite) in [("magma", CtrOmacSuite::MAGMA),
                          ("kuznyechik", CtrOmacSuite::KUZNYECHIK)] {
        // A zero IV, a patterned one, and one close enough to its own
        // wrap that the larger sequence numbers carry past it - which is
        // the case a 64 bit add gets wrong.
        let ivs: Vec<Vec<u8>> = vec![
            vec![0u8; suite.iv_len()],
            (0..suite.iv_len()).map(|i| (i as u8) * 17 + 1).collect(),
            vec![0xffu8; suite.iv_len()],
        ];

        let mut rows: Vec<(usize, u64, usize)> = Vec::new();   // iv, sequence, len
        // Every sequence number, at lengths short enough to be cheap.
        for &sequence in &sequences {
            for &len in &[0usize, 17, 255] {
                rows.push((1, sequence, len));
            }
        }
        // Every length, at two sequence numbers - one either side of a
        // boundary, so the long records are not all under one key.
        for &len in &lengths {
            rows.push((1, 1, len));
            rows.push((1, 4096, len));
        }
        // Every IV, including the one that wraps, at the sequence
        // numbers large enough to carry into it.
        for iv in 0..3 {
            for &sequence in &[0u64, 1, 0xFFFF_FFFE, 0xFFFF_FFFF] {
                for &len in &[16usize, 1025] {
                    rows.push((iv, sequence, len));
                }
            }
        }
        rows.sort_unstable();
        rows.dedup();

        for (iv_index, sequence, len) in rows {
            if sequence > suite.snmax {
                continue;   // refused by construction; see the unit tests
            }
            let iv = &ivs[iv_index];

            // Vary the content type and version too: both are in the MAC
            // input and neither changes the length, so a frame that omits
            // one is invisible without them.
            let content_type = match sequence % 3 {
                0 => ContentType::ApplicationData,
                1 => ContentType::Handshake,
                _ => ContentType::Alert,
            };
            let version = if len % 2 == 0 { Version::TLS12 } else { Version::TLS11 };

            let plaintext: Vec<u8> =
                (0..len).map(|i| ((i * 7 + len) % 251) as u8).collect();

            let mut state = CtrOmac::new(suite, &enc_key, &mac_key, iv).unwrap();
            let out = encrypt(&mut state, SequenceNumber::at(sequence),
                              content_type, version, &plaintext).unwrap();
            assert_eq!(out.len(), len + suite.block);
            // A record whose ciphertext still begins with its plaintext
            // would mean the keystream never ran.
            if len > 0 {
                assert_ne!(out[..len], plaintext[..],
                           "{} left the plaintext in the clear", name);
            }

            println!("ctromac {} {} {} {} {} {} {} {} {}", name,
                     hex(&enc_key), hex(&mac_key), hex(iv), sequence,
                     content_type.to_byte(), hex(&version.to_bytes()),
                     hex(&plaintext), hex(&out));
            cases += 1;
        }
    }

    eprintln!("[diff_ctr_omac] {} cases", cases);
}
