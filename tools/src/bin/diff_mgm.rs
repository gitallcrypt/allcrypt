// MGM, dumped for comparison against a reading of RFC 9058.
// Verified by scripts/diff_check.py.
//
// Nothing on a normal machine implements MGM - OpenSSL has it only
// through the GOST engine, `python-cryptography` has never offered it -
// so the reference is a second reading of the standard rather than
// another library. That makes the sweep below the important part: the
// four worked examples in RFC 9058's appendix are already checked byte
// for byte in `src/block_ciphers/mgm.rs`, and what they cannot reach is
// what this corpus is for.
//
// What the appendix does not cover, and every row here does:
//
//   * **lengths across two block boundaries in both inputs.** The
//     examples have one ragged tail each; a padding rule that is right
//     for `n-1` bytes and wrong for `1` is invisible in them.
//   * **an empty input on either side.** `h = 0` and `q = 0` are
//     separate branches in the tag loop, and the examples have one
//     each - so a mistake affecting both would still show in one.
//   * **both block sizes for every cipher**, because MGM's field
//     polynomial depends on the block size: `w^64 + w^4 + w^3 + w + 1`
//     against `w^128 + w^7 + w^2 + w + 1`. The two are different modes
//     sharing a name, and a 64 bit one built by copying the 128 bit
//     path produces a tag that agrees with itself.
//   * **a counter that wraps.** `incr_r` steps the right half modulo
//     2^{n/2} and `incr_l` the left half, and neither carries into the
//     other. Every example is far too short to reach a wrap; the rows
//     with an ICN whose halves are near their own maximum are not.
//   * **truncated tags**, which RFC 9058 section 4 permits down to 32
//     bits and the appendix never uses.
//
//   mgm <cipher> <taglen> <key> <icn> <aad> <plaintext>  <ciphertext> <tag>
use allcrypt::block_ciphers::mgm::Mgm;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// A deterministic filler, so a row is reproducible from its own fields.
fn filler(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed).wrapping_add(1))
        .collect()
}

fn main() {
    let mut cases = 0usize;
    let mut wrapped = 0usize;

    // One cipher of each block size the standard is written for, plus
    // two more of each so a block size that was hard-coded somewhere
    // shows up as more than one failure.
    for (cipher, block, key_len) in [("kuznyechik", 16usize, 32usize),
                                     ("magma", 8, 32),
                                     ("aes", 16, 16),
                                     ("des", 8, 8)] {
        let key = filler(key_len, 0x11);

        // ICNs: an ordinary one, then two whose halves sit one step
        // below their own wrap, so a message of a few blocks carries
        // each counter over the boundary the standard puts there.
        let mut icns: Vec<Vec<u8>> = vec![filler(block, 0x40)];
        for (left, right) in [(0x00u8, 0xffu8), (0xff, 0x00), (0xff, 0xff)] {
            let mut icn = vec![0u8; block];
            icn[..block / 2].fill(left);
            icn[block / 2..].fill(right);
            // The top bit is the domain separator and is not part of
            // the nonce; masking it here is what the caller must do.
            icn[0] &= 0x7f;
            icns.push(icn);
        }

        for (index, icn) in icns.iter().enumerate() {
            if icn[block / 2..].iter().all(|&b| b == 0xff) {
                wrapped += 1;
            }
            // Lengths either side of both block boundaries, plus zero.
            let lengths: Vec<usize> = vec![0, 1, block - 1, block, block + 1,
                                           2 * block - 1, 2 * block,
                                           2 * block + 1, 5 * block + 3];
            for &aad_len in &lengths {
                for &text_len in &lengths {
                    // The mode refuses both empty, and so does the
                    // reference - a row for it would be a row about an
                    // error message, which `test_api.rs` already has.
                    if aad_len == 0 && text_len == 0 {
                        continue;
                    }
                    let aad = filler(aad_len, 0x60 + index as u8);
                    let plaintext = filler(text_len, 0x90 + index as u8);

                    // The full tag, and the two shortest the standard
                    // allows: 32 bits, and half the block.
                    for tag_len in [block, block / 2, 4] {
                        let mgm = Mgm::with_tag_len(cipher, &key, tag_len).unwrap();
                        let (ciphertext, tag) =
                            mgm.encrypt(icn, &aad, &plaintext).unwrap();
                        assert_eq!(ciphertext.len(), plaintext.len());
                        assert_eq!(tag.len(), tag_len);
                        // Never emit a row we cannot open ourselves.
                        assert_eq!(mgm.decrypt(icn, &aad, &ciphertext, &tag).unwrap(),
                                   plaintext, "{cipher} did not round trip");

                        println!("mgm {} {} {} {} {} {} {} {}",
                                 cipher, tag_len, hex(&key), hex(icn),
                                 hex(&aad), hex(&plaintext),
                                 hex(&ciphertext), hex(&tag));
                        cases += 1;
                    }
                }
            }
        }
    }

    assert!(wrapped >= 4, "no row makes a counter wrap, which is most of \
                           the reason this corpus exists");
    eprintln!("[diff_mgm] {} cases, {} with a counter at its wrap", cases, wrapped);
}
