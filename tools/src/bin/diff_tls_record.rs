// TLS records produced by our record layer, dumped for comparison against
// an independent implementation. Verified by scripts/diff_check.py.
//
// The reference on the other side is written straight from RFC 5246 section
// 6.2.3.2 using python-cryptography's AES and Python's hmac - not from our
// code. That is the point: MAC-then-encrypt with TLS's N+1 padding has
// several details that are easy to get consistently wrong, and a round trip
// against ourselves would not notice any of them.
//
// The explicit IV is random per record, so the checker cannot predict the
// bytes. It takes the IV out of the record we produced and recomputes the
// rest, which still pins the MAC input, the padding construction and the
// encryption.
use allcrypt::tls::record::{CbcHmac, Protection, RecordWriter, StreamHmac};
use allcrypt::tls::{ContentType, Version};

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let lengths = [0usize, 1, 5, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 100, 255, 1000];

    // SSLv3 is in the list for a reason that has nothing to do with
    // completeness: its MAC is not HMAC and does not cover the record
    // version, so a straight port of the TLS construction is wrong in a
    // way both ends of a handshake would agree on. OpenSSL cannot check
    // it - this build has SSLv3 compiled out entirely - so the Python
    // side implements RFC 6101 section 5.2.3.1 from the text, and this
    // corpus is the only thing that says our version is right.
    for version in [Version::SSL30, Version::TLS10, Version::TLS11,
                    Version::TLS12] {
        // 3DES and single DES alongside AES. OpenSSL has removed both from
        // TLS entirely - this build offers 158 suites and not one of them
        // uses either - so the handshake cannot be tested against it. The
        // raw ciphers are still in `cryptography`'s decrepit module, so
        // the *record construction* can be, which is where the TLS-specific
        // parts live: the MAC input, the N+1 padding, the 8 byte block.
        //
        // An 8 byte block is not a smaller 16 byte block. The padding and
        // the explicit IV are both block-sized, so every length in the
        // corpus lands differently here than it does for AES.
        for (cipher, key_len) in [("aes", 16usize), ("aes", 32),
                                  ("3des", 24), ("des", 8)] {
            for hash in ["sha1", "sha256", "md5"] {
                if version == Version::SSL30 && hash == "sha256" {
                    continue;
                }
                let key: Vec<u8> = (0..key_len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect();
                let mac_key: Vec<u8> = (0..32).map(|i| ((i * 53 + 7) & 0xff) as u8).collect();
                let block_size = if cipher == "aes" { 16 } else { 8 };
                let iv: Vec<u8> =
                    (0..block_size).map(|i| ((i * 91 + 3) & 0xff) as u8).collect();

                for etm in [false, true] {
                let state = CbcHmac::new(cipher, hash, &key, &mac_key, &iv, version).unwrap();
                let state = if etm { state.with_encrypt_then_mac() } else { state };
                let mut writer = RecordWriter::new(version);
                writer.change_cipher_spec(Protection::CbcHmac(state));

                let label = format!("{}-{}-{}-{}{}", version.name(), cipher, key_len,
                                    hash, if etm { "-etm" } else { "" });
                println!("suite {} {} {} {} {} {}", label, version.name(), cipher,
                         hex(&key), hex(&mac_key), hex(&iv));
                println!("hash {} {}", label, hash);
                println!("etm {} {}", label, etm);

                // Several records in a row, so the sequence number advances
                // and - for TLS 1.0 - the IV chains. Both are things the
                // reference has to reproduce independently.
                for (index, length) in lengths.iter().enumerate() {
                    let payload: Vec<u8> =
                        (0..*length).map(|i| ((i * 167 + 13) & 0xff) as u8).collect();
                    let content_type = if index % 3 == 0 {
                        ContentType::ApplicationData
                    } else if index % 3 == 1 {
                        ContentType::Handshake
                    } else {
                        ContentType::Alert
                    };
                    let bytes = writer.write(content_type, &payload).unwrap();
                    println!("record {} {} {} {} {}", label, index,
                             content_type.to_byte(), hex(&payload), hex(&bytes));
                }
                }
            }
        }
    }

    // The stream-cipher path: RC4 and the NULL ciphers. Separate from the
    // loop above because the construction is different - no padding, no IV,
    // and the keystream runs across records rather than restarting.
    //
    // This is the corpus that matters most in this file, because OpenSSL
    // has deleted RC4 and cannot be used as the reference. The Python side
    // implements RFC 5246 section 6.2.3.1 and RC4 itself from scratch; if
    // the two agree over hundreds of records, the construction is right.
    for version in [Version::SSL30, Version::TLS10, Version::TLS11,
                    Version::TLS12] {
        for cipher in ["rc4", "null"] {
            for hash in ["sha1", "md5", "sha256"] {
                let key: Vec<u8> = (0..16).map(|i| ((i * 29 + 5) & 0xff) as u8).collect();
                let mac_key: Vec<u8> = (0..32).map(|i| ((i * 43 + 17) & 0xff) as u8).collect();

                // SSLv3's MAC is defined for MD5 and SHA-1 only, so
                // SHA-256 has no pad length and is refused rather than
                // improvised.
                if version == Version::SSL30 && hash == "sha256" {
                    continue;
                }
                let state = StreamHmac::new(cipher, hash, &key, &mac_key,
                                            version).unwrap();
                let mut writer = RecordWriter::new(version);
                writer.change_cipher_spec(Protection::StreamHmac(state));

                let label = format!("stream-{}-{}-{}", version.name(), cipher, hash);
                println!("streamsuite {} {} {} {} {}", label, version.name(),
                         cipher, hex(&key), hex(&mac_key));
                println!("streamhash {} {}", label, hash);

                // Many records in a row. For RC4 this is the whole point:
                // record N continues record N-1's keystream, so a reference
                // that restarts the cipher agrees on the first record and
                // on nothing after it.
                for (index, length) in lengths.iter().enumerate() {
                    let payload: Vec<u8> =
                        (0..*length).map(|i| ((i * 211 + 7) & 0xff) as u8).collect();
                    let content_type = if index % 3 == 0 {
                        ContentType::ApplicationData
                    } else if index % 3 == 1 {
                        ContentType::Handshake
                    } else {
                        ContentType::Alert
                    };
                    let bytes = writer.write(content_type, &payload).unwrap();
                    println!("streamrecord {} {} {} {} {}", label, index,
                             content_type.to_byte(), hex(&payload), hex(&bytes));
                }
            }
        }
    }

    // And the plaintext path, where the record is just a header and a body.
    let mut writer = RecordWriter::new(Version::TLS12);
    for (index, length) in [0usize, 1, 100, 16384, 16385, 40000].iter().enumerate() {
        let payload: Vec<u8> = (0..*length).map(|i| ((i * 167 + 13) & 0xff) as u8).collect();
        let bytes = writer.write(ContentType::Handshake, &payload).unwrap();
        println!("plain {} {} {}", index, hex(&payload), hex(&bytes));
    }

    eprintln!("records written");
}
