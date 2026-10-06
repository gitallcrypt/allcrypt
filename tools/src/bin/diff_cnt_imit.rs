// RFC 9189's CNT_IMIT suite, dumped for comparison against a reading of
// RFC 5830, RFC 4357 and RFC 9189. Verified by scripts/diff_check.py.
//
// The unit tests reproduce RFC 9189 Appendix A.2 byte for byte - both
// records and the whole key exchange - which is one connection with one
// key. This is the rest of the space, and the reason it needs covering
// separately is that **every re-keying mistake here is right for the
// first 1024 octets and wrong afterwards**:
//
//   * CryptoPro meshing's `IVn` is the counter that produced the *last*
//     gamma block, and the meshed IV is *stepped* before use;
//   * the MAC meshes its key and **keeps its chaining state**, which
//     the cipher half does not;
//   * both count their own bytes, because they cover different streams.
//
// So the record rows straddle the 1024 octet boundary from both sides
// and at several offsets, and they run several records per connection -
// a boundary that falls inside a record and a boundary that falls
// between two are different cases, and only a multi-record row has the
// second.
//
// Three row kinds:
//
//   imit <key> <iv> <message> <tag>
//   divers <ukm> <key> <out>
//   cntimit <enckey> <mackey> <iv> <lengths...> <records...>
//   vko2001 <curve> <private> <peer_x> <peer_y> <ukm> <kek>
//   keg2001 <curve> <private> <peer_x> <peer_y> <ukm> <k_exp>
//   wrap2001 <curve> <private> <peer_x> <peer_y> <ukm> <secret> <blob>
//
// The `cntimit` rows carry a whole connection: the lengths of every
// record and then every record's ciphertext, because a row with one
// record could not show that the state carries.
use allcrypt::ec::curves;
use allcrypt::tls::gost_kex_28147::{cp_divers, keg_2001, kexp28147};
use allcrypt::tls::record_cnt_imit::SBOX_2001;
use allcrypt::tls::record::SequenceNumber;
use allcrypt::tls::record_cnt_imit::{encrypt, gost28147imit, CntImit, SBOX};
use allcrypt::tls::{ContentType, Version};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 53 + seed as u32 * 29 + 17) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    // ------------------------------------------------ gostIMIT28147 ---
    //
    // Lengths either side of the 8 byte block and of the 1024 octet
    // meshing boundary - the one-shot does not mesh, so the rows past
    // 1024 are what would catch it starting to.
    for key_seed in 0..3u8 {
        let key = pattern(32, key_seed + 1);
        for iv_seed in 0..2u8 {
            let iv = if iv_seed == 0 { vec![0u8; 8] } else { pattern(8, iv_seed + 40) };
            for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 63, 64, 255,
                        1023, 1024, 1025, 2048] {
                let message = pattern(len, key_seed + iv_seed + 7);
                let tag = gost28147imit(&iv, &key, &message, SBOX).unwrap();
                println!("imit {} {} {} {}", hex(&key), hex(&iv), hex(&message),
                         hex(&tag));
                cases += 1;
            }
        }
    }

    // ----------------------------------------------------- CPDivers ---
    //
    // RFC 4357 gives it no vector at all, so every row here is checked
    // against a second reading. A UKM of all zeros and one of all ones
    // are the degenerate cases: every bit clear puts every word in one
    // sum and none in the other.
    for key_seed in 0..4u8 {
        let key = pattern(32, key_seed + 11);
        for ukm in [vec![0u8; 8], vec![0xffu8; 8], pattern(8, key_seed + 60),
                    vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
                    vec![0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]] {
            let out = cp_divers(&ukm, &key, SBOX).unwrap();
            assert_ne!(out, key, "CPDivers returned its input");
            println!("divers {} {} {}", hex(&ukm), hex(&key), hex(&out));
            cases += 1;
        }
    }

    // ------------------------------------------- the record protection ---
    //
    // Each row is a whole connection. The length lists are chosen so
    // that the 1024 octet boundary falls inside a record, between two
    // records, and at several different offsets within a record - the
    // MAC's count runs ahead of the cipher's by thirteen bytes a record,
    // so the two boundaries are never in the same place and a row that
    // crossed only one would not see the other.
    let connections: [&[usize]; 6] = [
        &[7],
        &[7, 2048],
        &[0, 1, 1, 1],
        &[1000, 1000, 1000],
        &[1019, 5, 1024, 3],
        &[2048, 1, 4096],
    ];

    for key_seed in 0..2u8 {
        let enc_key = pattern(32, key_seed + 21);
        let mac_key = pattern(32, key_seed + 31);
        for iv_seed in 0..2u8 {
            let iv = if iv_seed == 0 { vec![0u8; 8] } else { pattern(8, iv_seed + 70) };
            for lengths in connections {
                let mut state = CntImit::new(&enc_key, &mac_key, &iv).unwrap();
                let mut records = Vec::new();
                for (sequence, &len) in lengths.iter().enumerate() {
                    // Vary the type and version too: both are in the MAC
                    // input and neither changes any length.
                    let content_type = match sequence % 3 {
                        0 => ContentType::ApplicationData,
                        1 => ContentType::Handshake,
                        _ => ContentType::Alert,
                    };
                    let version = if len % 2 == 0 { Version::TLS12 } else { Version::TLS11 };
                    // The plaintext is a function of the sequence
                    // number alone, so the checker can regenerate it
                    // rather than the row carrying it - these records
                    // run to 4 KB and a corpus that spelled them out
                    // would be megabytes. What varies per connection is
                    // the keys and the IV, which the row does carry.
                    let plaintext = pattern(len, sequence as u8);
                    let out = encrypt(&mut state, SequenceNumber::at(sequence as u64),
                                      content_type, version, &plaintext).unwrap();
                    assert_eq!(out.len(), len + 4);
                    records.push(hex(&out));
                }
                println!("cntimit {} {} {} {} {}",
                         hex(&enc_key), hex(&mac_key), hex(&iv),
                         lengths.iter().map(|n| n.to_string())
                                .collect::<Vec<_>>().join(","),
                         records.join(" "));
                cases += 1;
            }
        }
    }

    // ------------------------------- the 2001 suite's key exchange ---
    //
    // VKO GOST R 34.10-2001 has **no published test vector anywhere**:
    // RFC 4357 states the algorithm in four lines and prints no
    // example, and the CryptoPro TLS draft prints none either. Our own
    // round trip proves only that both ends of one implementation
    // agree, which is exactly what a symmetric key agreement proves
    // for free. So these rows are the only outside check there is: the
    // reference recomputes `((UKM*d) mod q) . Q` from the curve
    // parameters and hashes it with its own GOST R 34.11-94.
    for name in ["gost256-a", "gost256-b", "gost256-c"] {
        let curve = curves::by_name(name).unwrap();
        for seed in 0..4u8 {
            let private = allcrypt::bignum::BigUint::from_bytes_be(
                &pattern(31, seed + 3));
            let peer_secret = allcrypt::bignum::BigUint::from_bytes_be(
                &pattern(31, seed + 40));
            let peer = curve.scalar_mul(&curve.g, &peer_secret);
            let ukm = pattern(8, seed + 11);

            let kek = curve.vko_2001(&private, &peer, &ukm).unwrap();
            println!("vko2001 {} {} {} {} {} {}", name,
                     hex(&private.to_bytes_be()),
                     hex(&peer.x().unwrap().to_bytes_be()),
                     hex(&peer.y().unwrap().to_bytes_be()),
                     hex(&ukm), hex(&kek));
            cases += 1;

            let k_exp = keg_2001(&curve, &private, &peer, &ukm).unwrap();
            println!("keg2001 {} {} {} {} {} {}", name,
                     hex(&private.to_bytes_be()),
                     hex(&peer.x().unwrap().to_bytes_be()),
                     hex(&peer.y().unwrap().to_bytes_be()),
                     hex(&ukm), hex(&k_exp));
            cases += 1;

            let secret = pattern(32, seed + 77);
            let wrapped = kexp28147(&secret, &k_exp, &ukm, SBOX_2001).unwrap();
            println!("wrap2001 {} {} {} {} {} {} {}", name,
                     hex(&private.to_bytes_be()),
                     hex(&peer.x().unwrap().to_bytes_be()),
                     hex(&peer.y().unwrap().to_bytes_be()),
                     hex(&ukm), hex(&secret), hex(&wrapped));
            cases += 1;
        }
    }

    eprintln!("[diff_cnt_imit] {} cases", cases);
}
