// The TLS 1.3 key schedule, dumped for comparison against a reference
// written from RFC 8446 section 7.1. Verified by scripts/diff_check.py.
//
// Two independent references are available for this one, and the corpus
// uses both:
//
//   * **`cryptography`'s HKDF**, which is OpenSSL's, for HKDF-Extract and
//     HKDF-Expand. That covers the primitive but says nothing about the
//     structure built on it.
//   * **the RFC's own text**, transcribed in Python, for the HkdfLabel
//     encoding, the three Extract stages, and the labels. This is where
//     the mistakes actually live: `"tls13 "` with the space, the length
//     byte counting the prefix, `Hash("")` for an empty message list, and
//     the derived secret rather than the stage secret as the next salt.
//
// Every one of those produces a schedule that works perfectly against
// itself, which is why a round trip proves nothing here.
//
// What is dumped:
//
//   earlysecret  <hash> <psk|->                        <secret>
//   derived      <hash> <secret>                       <derived>
//   handshake    <hash> <early> <shared>               <secret>
//   master       <hash> <handshake>                    <secret>
//   traffic      <hash> <secret> <label> <transcript>  <derived>
//   keys         <hash> <secret> <keylen>              <key> <iv> <fin>
//   update       <hash> <secret> <keylen>              <next secret>
//   label        <hash> <secret> <label> <context> <n> <output>
//   finished     <hash> <finished key> <transcript>    <verify data>
use allcrypt::tls::keys13::{derive_secret, empty_hash, expand_label, finished,
                            Schedule, TrafficKeys};
use allcrypt::tls::suites::MacAlgorithm;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 131 + seed as u32 * 37 + 11) & 0xff) as u8).collect()
}

fn main() {
    let mut cases = 0usize;

    for (prf, hash_name, hash_len) in [(MacAlgorithm::Sha256, "sha256", 32usize),
                                       (MacAlgorithm::Sha384, "sha384", 48)] {
        // --- the label encoding on its own, including the edges ---
        //
        // Label lengths across the range the protocol uses and past it,
        // context lengths including 0 and the full 255, and output
        // lengths that are not multiples of the hash so the last HKDF
        // block is truncated.
        for (index, label) in [&b"key"[..], b"iv", b"finished", b"c hs traffic",
                               b"res master", b"traffic upd", b"exporter",
                               b"quic key"].iter().enumerate() {
            let seed = index as u8 + 1;
            let secret = filler(hash_len, seed);
            for context_len in [0usize, 1, 31, 32, 48, 255] {
                let context = filler(context_len, seed.wrapping_add(50));
                for out in [1usize, 16, 17, 32, 48, 64, hash_len * 3 + 1] {
                    let value = expand_label(hash_name, &secret, label,
                                             &context, out).unwrap();
                    println!("label {} {} {} {} {} {}",
                             hash_name, hex(&secret),
                             String::from_utf8_lossy(label),
                             hex(&context), out, hex(&value));
                    cases += 1;
                }
            }
        }

        // --- the schedule, end to end, over several shared secrets ---
        //
        // X25519 gives 32 bytes, P-256 gives 32, P-384 gives 48, and a
        // finite-field group gives whatever its modulus is - so the
        // shared secret's length is not the hash's and must not be
        // assumed to be.
        for (index, shared_len) in [32usize, 48, 66, 128, 256, 384].iter().enumerate() {
            let shared = filler(*shared_len, index as u8 + 60);

            let early = Schedule::early(prf, None).unwrap();
            println!("earlysecret {} - {}", hash_name, hex(early.secret()));
            cases += 1;

            let derived = derive_secret(hash_name, early.secret(), b"derived",
                                        &empty_hash(hash_name).unwrap()).unwrap();
            println!("derived {} {} {}", hash_name, hex(early.secret()), hex(&derived));
            cases += 1;

            let handshake = early.handshake(&shared).unwrap();
            println!("handshake {} {} {} {}", hash_name, hex(early.secret()),
                     hex(&shared), hex(handshake.secret()));
            cases += 1;

            let master = handshake.master().unwrap();
            println!("master {} {} {}", hash_name, hex(handshake.secret()),
                     hex(master.secret()));
            cases += 1;

            // Transcript hashes are the hash's own length, always - they
            // are a digest, whatever the messages were.
            let transcript = filler(hash_len, index as u8 + 90);

            for (stage, labels) in [(&handshake, &["c hs traffic", "s hs traffic"][..]),
                                    (&master, &["c ap traffic", "s ap traffic",
                                                "exp master", "res master"][..])] {
                for label in labels {
                    let value = stage.traffic_secret(label.as_bytes(), &transcript).unwrap();
                    println!("traffic {} {} {} {} {}", hash_name,
                             hex(stage.secret()), label, hex(&transcript), hex(&value));
                    cases += 1;
                }
            }

            // --- traffic keys, for every key and IV length ---
            //
            // The key is 16 for AES-128-GCM and 32 for AES-256-GCM and
            // ChaCha20-Poly1305. **The IV is 12 for those three and is
            // not 12 for everything**: RFC 9367 section 4.1.1 makes it
            // the cipher's block, so Kuznyechik's is 16 and Magma's is
            // 8. Both lengths are swept against both key lengths,
            // because the two are independent and deriving one from the
            // other is a mistake that only shows on the wire.
            for key_len in [16usize, 32] {
              for iv_len in [8usize, 12, 16] {
                let secret = master.traffic_secret(b"c ap traffic", &transcript).unwrap();
                let keys = TrafficKeys::derive(hash_name, &secret, key_len, iv_len)
                    .unwrap();
                assert_eq!(keys.iv.len(), iv_len);
                println!("keys {} {} {} {} {} {} {}", hash_name, hex(&secret),
                         key_len, iv_len,
                         hex(&keys.key), hex(&keys.iv), hex(&keys.finished_key));
                cases += 1;

                let next = keys.update(hash_name).unwrap();
                // The IV keeps its length across an update, which is
                // the one place it could silently revert to twelve.
                assert_eq!(next.iv.len(), iv_len);
                println!("update {} {} {} {}", hash_name, hex(&secret), key_len,
                         hex(&next.secret));
                cases += 1;

                let verify = finished(hash_name, &keys.finished_key, &transcript).unwrap();
                println!("finished {} {} {} {}", hash_name, hex(&keys.finished_key),
                         hex(&transcript), hex(&verify));
                cases += 1;
              }
            }
        }

        // --- resumption, which is the only path with a real PSK ---
        //
        // The early secret stops being the well known constant as soon as
        // there is one, and a schedule that ignored the PSK would keep
        // producing the constant and look fine.
        for (index, psk_len) in [1usize, 16, 32, 48, 64].iter().enumerate() {
            let psk = filler(*psk_len, index as u8 + 120);
            let early = Schedule::early(prf, Some(&psk)).unwrap();
            println!("earlysecret {} {} {}", hash_name, hex(&psk), hex(early.secret()));
            cases += 1;
        }
    }

    eprintln!("[diff_tls13_keys] {} cases", cases);
}
