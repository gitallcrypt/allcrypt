// TLS 1.3 protected records, dumped for comparison against OpenSSL through
// python-cryptography. Verified by scripts/diff_check.py.
//
// The AEAD underneath is OpenSSL's, so this is a real independent
// implementation - but the AEAD is the part least likely to be wrong. What
// this corpus is actually for is the three things wrapped around it, each
// of which the checker computes from RFC 8446's text rather than from our
// code:
//
//   * **the inner plaintext**: content, then the *real* content type, then
//     zero padding. The type goes before the padding, so it is found by
//     scanning back past the zeros - and a record that is all padding has
//     no type at all;
//   * **the nonce**: the static IV XOR the sequence number, left-padded to
//     twelve bytes. Padding it on the other side is self-consistent and
//     interoperates with nothing, and nothing travels on the wire that
//     would reveal the mistake;
//   * **the additional data**: the five byte record header as sent, whose
//     length field counts the ciphertext *plus the tag*. TLS 1.2's AAD was
//     the sequence number, the type, the version and the plaintext length,
//     and not one of those fields survives.
//
// Sequence numbers are swept up to the point where the counter reaches
// past the ninth byte from the end of the nonce, because that is where a
// wrongly padded XOR stops being wrong in a way that happens to work.
//
//   record <aead> <key> <iv> <seq> <type> <padding> <plaintext> <fragment>
use allcrypt::tls::keys13::TrafficKeys;
use allcrypt::tls::record::SequenceNumber;
use allcrypt::tls::record13::Aead13;
use allcrypt::tls::ContentType;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| ((i as u32 * 97 + seed as u32 * 41 + 3) & 0xff) as u8).collect()
}

/// A fresh `Aead13` wound forward to `sequence`, since the counter is
/// internal and a record is only reproducible with the number that
/// produced it.
fn at(aead: &str, key: &[u8], iv: &[u8], tag_len: usize, sequence: u64) -> Aead13 {
    // The secret and finished key are not used by the record layer, only
    // by the schedule above it.
    let keys = TrafficKeys {
        secret: vec![0; 32],
        key: key.to_vec(),
        iv: iv.to_vec(),
        finished_key: vec![0; 32],
    };
    Aead13::starting_at(aead, "sha256", keys, tag_len,
                        SequenceNumber::at(sequence)).unwrap()
}

fn main() {
    let mut cases = 0usize;

    // Every AEAD TLS 1.3 uses, at both key lengths, plus the short-tag
    // CCM suite - because a record layer that assumed a sixteen byte tag
    // would read eight bytes of ciphertext as tag and only fail on CCM_8.
    let suites: &[(&str, usize, usize)] = &[
        ("aes-gcm", 16, 16),
        ("aes-gcm", 32, 16),
        ("chacha20-poly1305", 32, 16),
        ("aes-ccm", 16, 16),
        ("aes-ccm-8", 16, 8),
    ];

    for (index, (aead, key_len, tag_len)) in suites.iter().enumerate() {
        let key = filler(*key_len, index as u8 + 1);
        let iv = filler(12, index as u8 + 40);

        // 0 and 1 are the ordinary ones; 255 and 256 cross a byte
        // boundary; the last two reach into the high half of the counter,
        // where a nonce XORed at the wrong offset stops agreeing by
        // accident.
        for sequence in [0u64, 1, 2, 255, 256, 65535, 1 << 32, u64::MAX - 1] {
            for content_type in [ContentType::Handshake, ContentType::Alert,
                                 ContentType::ApplicationData] {
                for length in [0usize, 1, 15, 16, 17, 64, 1000] {
                    let plaintext = filler(length, sequence as u8);
                    for padding in [0usize, 1, 16] {
                        let mut state = at(aead, &key, &iv, *tag_len, sequence);
                        let fragment = state.encrypt(content_type, &plaintext, padding)
                            .unwrap();

                        // And read it straight back with a second state at
                        // the same counter, so the corpus never carries a
                        // record we cannot decrypt ourselves.
                        let mut back = at(aead, &key, &iv, *tag_len, sequence);
                        let (got_type, got) = back.decrypt(&fragment).unwrap();
                        assert_eq!(got_type, content_type);
                        assert_eq!(got, plaintext);

                        println!("record {} {} {} {} {} {} {} {}",
                                 aead, hex(&key), hex(&iv), sequence,
                                 content_type.to_byte(), padding,
                                 hex(&plaintext), hex(&fragment));
                        cases += 1;
                    }
                }
            }
        }
    }

    eprintln!("[diff_tls13_record] {} cases", cases);
}
