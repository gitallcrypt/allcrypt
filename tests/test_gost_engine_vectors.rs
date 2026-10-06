/*!
GOST checked against OpenSSL's gost-engine.

For as long as there has been GOST code here it has carried a caveat:
its constant tables were not typed from memory, but **nothing on this
machine implemented any of the GOST algorithms, so the differential
reference was a second reading of the spec.**

That was the honest description and it was a weak position. Every other
algorithm in this repository is compared against somebody else's code -
`hashlib`, OpenSSL through python-cryptography, Python's own integers -
over hundreds of lengths. GOST was compared against a second reading of
the same standards by the same reader, and two readings agree about the
same mistakes.

`vectors/gost_engine.vec` is what closes that. It holds the answers
**OpenSSL's gost-engine** gives - a separate project, written by other
people, and the code actually running on the servers this library
exists to reach - and this file reads them back with no network, no
engine and no OpenSSL. `scripts/make_gost_vectors.py` regenerates it
and `scripts/gost_engine_probe.c` reaches the parts the `openssl`
command line cannot; both are development tools and neither is in the
gate.

## What each section is the only thing to settle

  * **`kuznyechik-*` and `magma-*`** put the two block functions and
    the five modes in front of another implementation for the first
    time. The S-boxes were checked against RustCrypto and `gostcrypto`
    when they were written; the *ciphers built from them* were not.
  * **`gost89*`** covers GOST 28147-89 under two parameter sets, in
    CFB, CBC and the counter mode of RFC 5830 - whose `mod 2^32-1`
    addition is one of the entries in `docs/pitfalls.md` and had no
    witness before this.
  * **`*-ctr-acpkm`** is the one that could not be checked at all.
    ACPKM's counter **runs across the section boundary** rather than
    restarting, every vector published anywhere is far too short to
    reach a boundary, and an implementation that restarts encrypts,
    decrypts and round-trips against itself perfectly. The rows here
    run to three sections and a bit.
  * **`*-mgm`** goes far past RFC 9058's vectors, which stop long
    before either counter chain wraps or even reaches its second byte.
  * **`*-mac`** is OMAC over both ciphers, and `gost-mac*` is GOST
    28147-89's own MAC transform - which writes its halves in the
    opposite order to the 32 round cipher, from a loop that differs
    only in its count.
  * **`*-kexp15`** settles something no document states plainly: which
    half of a 64 byte KExp15 key is the MAC key. Ours and the engine's
    agree, and if they had not, nothing else here would have noticed -
    both ends of every KExp15 test in this repository are ours.

## Reading the file

One `[section]` per algorithm, then records of `Name = hex` separated
by blank lines. `Section` is a decimal byte count rather than hex,
which is why `number()` exists.

**Every test here asserts how many records it found**, and
`test_the_header_agrees_with_the_body` checks those counts against the
comment block the generator wrote. A parser that silently finds nothing
turns every loop into a pass, which has happened in this repository
three times in three different documents.
*/

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::hash_functions::HashFunction;

const VECTORS: &str = include_str!("../vectors/gost_engine.vec");

/// One record: the fields in the order the file states them.
struct Record {
    fields: Vec<(String, String)>,
}

impl Record {
    fn raw(&self, name: &str) -> Option<&str> {
        self.fields.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// A hex field. Absent is an error rather than empty: a row that
    /// forgot its key would otherwise be tested with no key at all.
    fn bytes(&self, name: &str) -> Vec<u8> {
        let value = self.raw(name)
            .unwrap_or_else(|| panic!("no {name} in this record"));
        assert!(value.len().is_multiple_of(2), "odd hex run in {name}: {value:?}");
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16)
                 .unwrap_or_else(|_| panic!("{name} is not hex: {value:?}")))
            .collect()
    }

    fn number(&self, name: &str) -> usize {
        self.raw(name)
            .unwrap_or_else(|| panic!("no {name} in this record"))
            .parse()
            .unwrap_or_else(|_| panic!("{name} is not a number"))
    }
}

/// Every record in one section.
fn section(name: &str) -> Vec<Record> {
    let heading = format!("[{name}]");
    let mut inside = false;
    let mut records = Vec::new();
    let mut fields: Vec<(String, String)> = Vec::new();

    for line in VECTORS.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // A new heading ends this one, or the file's twenty-five
            // sections would run together into one.
            if !fields.is_empty() {
                records.push(Record { fields: std::mem::take(&mut fields) });
            }
            inside = line == heading;
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            if !fields.is_empty() {
                records.push(Record { fields: std::mem::take(&mut fields) });
            }
            continue;
        }
        if !inside {
            continue;
        }
        let (key, value) = line.split_once('=').expect("every line is Name = value");
        fields.push((key.trim().to_string(), value.trim().to_string()));
    }
    if !fields.is_empty() {
        records.push(Record { fields });
    }
    records
}

/// `(name, count)` for every section the generator's header declares.
fn declared_counts() -> Vec<(String, usize)> {
    let mut counts = Vec::new();
    let mut started = false;
    for line in VECTORS.lines() {
        if line.contains("Counts, asserted by the test that reads this") {
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        let Some(rest) = line.strip_prefix('#') else { break };
        let mut parts = rest.split_whitespace();
        let (Some(name), Some(count)) = (parts.next(), parts.next()) else { break };
        let Ok(count) = count.parse() else { break };
        counts.push((name.to_string(), count));
    }
    counts
}

// ------------------------------------------------------- the modes ---

/// Which of our (cipher, parameter set, mode) each section is.
///
/// The four `gost89*` rows were **measured, not read off the names**,
/// and every one of them would have been guessed wrong:
///
///   * `gost89` is **CFB**, not ECB. The engine reports a block size
///     of one for it, which is how a stream-shaped mode announces
///     itself, and `openssl enc` has no route to GOST 28147-89 ECB at
///     all.
///   * `gost89` and `gost89-cbc` use **id-tc26-gost-28147-param-Z**,
///     the 2012 table - so the plain, un-suffixed names are the *new*
///     parameter set.
///   * `gost89-cnt` uses **CryptoPro-A**, the old one, and
///     `gost89-cnt-12` uses TC26-Z. So the `-12` suffix means
///     something on the counter mode and nothing anywhere else.
///
/// A parameter set is the whole of a GOST cipher, so getting one of
/// these wrong is not a near miss: it is a different cipher, and the
/// rows simply never match. They were found by sweeping all nine
/// parameter sets against all six modes and seeing which pair landed.
const MODE_SECTIONS: &[(&str, &str, Option<&str>, Mode)] = &[
    ("kuznyechik-ecb", "kuznyechik", None, Mode::Ecb),
    ("kuznyechik-cbc", "kuznyechik", None, Mode::Cbc),
    ("kuznyechik-cfb", "kuznyechik", None, Mode::Cfb),
    ("kuznyechik-ofb", "kuznyechik", None, Mode::Ofb),
    ("kuznyechik-ctr", "kuznyechik", None, Mode::Ctr),
    ("magma-ecb", "magma", None, Mode::Ecb),
    ("magma-cbc", "magma", None, Mode::Cbc),
    ("magma-ctr", "magma", None, Mode::Ctr),
    ("gost89", "gost", Some("id-tc26-gost-28147-param-Z"), Mode::Cfb),
    ("gost89-cbc", "gost", Some("id-tc26-gost-28147-param-Z"), Mode::Cbc),
    ("gost89-cnt", "gost", Some("id-Gost28147-89-CryptoPro-A-ParamSet"), Mode::Ctr),
    ("gost89-cnt-12", "gost", Some("id-tc26-gost-28147-param-Z"), Mode::Ctr),
];

fn run_mode(cipher: &str, param: Option<&str>, mode: Mode, key: &[u8],
            iv: &[u8], data: &[u8], decrypting: bool) -> Vec<u8> {
    let block = AnyBlockCipher::new(cipher, key, param).expect("the cipher");
    let mut stream = CipherStream::new(block, mode, iv, decrypting)
        .expect("the mode");
    let mut out = stream.update(data).expect("update");
    out.extend_from_slice(&stream.finish().expect("finish"));
    out
}

#[test]
fn test_every_mode_matches_the_engine() {
    let mut checked = 0;
    for &(name, cipher, param, mode) in MODE_SECTIONS {
        let records = section(name);
        assert!(!records.is_empty(), "no records in [{name}]");
        for record in &records {
            let key = record.bytes("Key");
            // ECB has no IV and the file writes none, which is the
            // difference between "no IV" and "an IV of zero bytes".
            let iv = if mode == Mode::Ecb { Vec::new() } else { record.bytes("IV") };
            let input = record.bytes("In");
            let expected = record.bytes("Out");
            let ours = run_mode(cipher, param, mode, &key, &iv, &input, false);
            assert_eq!(ours, expected,
                       "[{name}] disagrees on a {} byte input", input.len());
            checked += 1;
        }
    }
    assert!(checked >= 180,
            "only {checked} mode vectors were read; the file has shrunk or \
             the parser stopped finding records");
}

#[test]
fn test_every_mode_decrypts_back() {
    // The engine only ever encrypts here, so decryption is checked by
    // running our own the other way. That is weaker than the row
    // above - it can only catch an asymmetry - but an asymmetric mode
    // is exactly what a shared bug in encrypt-and-decrypt is not, so
    // the two checks miss different things.
    for &(name, cipher, param, mode) in MODE_SECTIONS {
        for record in &section(name) {
            let key = record.bytes("Key");
            let iv = if mode == Mode::Ecb { Vec::new() } else { record.bytes("IV") };
            let back = run_mode(cipher, param, mode, &key, &iv,
                                &record.bytes("Out"), true);
            assert_eq!(back, record.bytes("In"),
                       "[{name}] does not decrypt its own ciphertext back");
        }
    }
}

#[test]
fn test_the_two_gost_parameter_sets_disagree() {
    // A parameter set *is* the GOST cipher, so a build that quietly
    // fell back to one table would pass every `gost89-cnt` row and
    // fail none of `gost89-cnt-12` - except that it would produce the
    // same bytes for both, and the engine does not. Anchored here
    // rather than left to the rows, because a fallback is a silent
    // change and this is the only thing that speaks up.
    let a = section("gost89-cnt");
    let z = section("gost89-cnt-12");
    let mut compared = 0;
    for (left, right) in a.iter().zip(z.iter()) {
        if left.bytes("In").is_empty() {
            continue;
        }
        assert_eq!(left.bytes("Key"), right.bytes("Key"));
        assert_eq!(left.bytes("IV"), right.bytes("IV"));
        assert_eq!(left.bytes("In"), right.bytes("In"));
        assert_ne!(left.bytes("Out"), right.bytes("Out"),
                   "CryptoPro-A and TC26-Z produced the same ciphertext");
        compared += 1;
    }
    assert!(compared >= 15, "only {compared} pairs compared");
}

// ------------------------------------------------------- CTR-ACPKM ---

#[test]
fn test_ctr_acpkm_matches_the_engine_across_section_boundaries() {
    use allcrypt::block_ciphers::acpkm::ctr_acpkm;

    let mut crossed = 0;
    for (name, cipher) in [("kuznyechik-ctr-acpkm", "kuznyechik"),
                           ("magma-ctr-acpkm", "magma")] {
        let records = section(name);
        assert!(records.len() >= 5, "[{name}] has only {} records", records.len());
        for record in &records {
            let key = record.bytes("Key");
            let nonce = record.bytes("IV");
            let size = record.number("Section");
            let input = record.bytes("In");
            let ours = ctr_acpkm(cipher, &key, &nonce, size, &input)
                .expect("CTR-ACPKM");
            assert_eq!(ours, record.bytes("Out"),
                       "[{name}] disagrees on {} bytes at section size {size}",
                       input.len());
            if input.len() > size {
                crossed += 1;
            }
        }
    }
    // The whole reason this section exists. Without a row past the
    // boundary this test is a slower `test_every_mode_matches_the_
    // engine` for CTR, and the re-keying it is named for is untouched.
    assert!(crossed >= 6,
            "only {crossed} rows are longer than their section, so almost \
             nothing here tested re-keying at all");
}

#[test]
fn test_a_restarted_counter_would_have_been_caught() {
    // ACPKM's counter runs across the boundary; it does not restart
    // when the key changes. Both readings agree on everything shorter
    // than one section and an implementation that restarts round-trips
    // against itself perfectly, so this asserts the vectors can tell
    // the difference rather than trusting that they can.
    use allcrypt::block_ciphers::acpkm::{acpkm_next, ctr_acpkm};

    let record = section("magma-ctr-acpkm").into_iter()
        .find(|r| r.bytes("In").len() > 2 * r.number("Section"))
        .expect("a row at least two sections long");
    let key = record.bytes("Key");
    let nonce = record.bytes("IV");
    let size = record.number("Section");
    let input = record.bytes("In");

    // The wrong implementation, built here: encrypt each section under
    // its own key with the counter starting over every time.
    let mut wrong = Vec::with_capacity(input.len());
    let mut section_key = key.clone();
    for piece in input.chunks(size) {
        wrong.extend_from_slice(
            &ctr_acpkm("magma", &section_key, &nonce, size, piece)
                .expect("one section"));
        section_key = acpkm_next("magma", &section_key).expect("the next key");
    }
    assert_eq!(wrong.len(), input.len());
    assert_ne!(wrong, record.bytes("Out"),
               "a counter that restarts each section produced the engine's \
                answer, so these rows cannot tell the two apart");
}

// --------------------------------------------------------- digests ---

#[test]
fn test_the_digests_match_the_engine() {
    use allcrypt::api::AnyHash;

    // `md_gost94` is GOST R 34.11-94 under the CryptoPro parameter
    // set, which is what the engine's `md_gost94` is and what
    // `AnyHash::new("gost94")` builds. `gost94_test` is the other one
    // and is deliberately not here: the engine does not offer it.
    for (name, ours) in [("md_gost94", "gost94"),
                         ("md_gost12_256", "streebog256"),
                         ("md_gost12_512", "streebog512")] {
        let records = section(name);
        assert!(records.len() >= 30, "[{name}] has only {} records", records.len());
        for record in &records {
            let input = record.bytes("In");
            let mut hash = AnyHash::new(ours).expect("the hash");
            hash.update(&input);
            assert_eq!(hash.digest(), record.bytes("Out"),
                       "[{name}] disagrees on a {} byte message", input.len());
        }
    }
}

#[test]
fn test_the_digests_match_when_fed_in_irregular_pieces() {
    use allcrypt::api::AnyHash;

    // Three of this repository's bugs have been in the fifteen lines
    // of a block buffer, and a known-answer test is one call, so it
    // sees none of them. The pieces are deliberately uneven and cross
    // the 64 byte block at every offset.
    for (name, ours) in [("md_gost94", "gost94"),
                         ("md_gost12_256", "streebog256"),
                         ("md_gost12_512", "streebog512")] {
        for record in &section(name) {
            let input = record.bytes("In");
            if input.len() < 64 {
                continue;
            }
            for step in [1usize, 7, 31, 63, 64, 65] {
                let mut hash = AnyHash::new(ours).expect("the hash");
                for piece in input.chunks(step) {
                    hash.update(piece);
                }
                assert_eq!(hash.digest(), record.bytes("Out"),
                           "[{name}] disagrees on {} bytes fed {step} at a time",
                           input.len());
            }
        }
    }
}

// ------------------------------------------------------------- MGM ---

#[test]
fn test_mgm_matches_the_engine() {
    use allcrypt::api::{aead_decrypt, aead_encrypt};

    let mut long_rows = 0;
    for name in ["kuznyechik-mgm", "magma-mgm"] {
        let records = section(name);
        assert_eq!(records.len(), 10, "[{name}] should have ten records");
        for record in &records {
            let key = record.bytes("Key");
            let nonce = record.bytes("Nonce");
            let ad = record.bytes("AD");
            let input = record.bytes("In");
            let (sealed, tag) = aead_encrypt(name, &key, &nonce, &ad, &input)
                .expect("encrypt");
            assert_eq!(sealed, record.bytes("Out"),
                       "[{name}] disagrees with {} bytes of associated data \
                        and {} of message", ad.len(), input.len());
            assert_eq!(tag, record.bytes("Tag"),
                       "[{name}]'s tag disagrees with {} bytes of associated \
                        data and {} of message", ad.len(), input.len());

            let opened = aead_decrypt(name, &key, &nonce, &ad, &sealed, &tag)
                .expect("decrypt");
            assert_eq!(opened, input, "[{name}] does not open what it sealed");

            if input.len() >= 255 {
                long_rows += 1;
            }
        }
    }
    // RFC 9058's own vectors stop well short of a second byte of
    // either counter. These rows are the only thing here that steps
    // `incr_l` and `incr_r` enough times to tell them apart.
    assert!(long_rows >= 6, "only {long_rows} rows are long enough to matter");
}

#[test]
fn test_mgm_refuses_a_tag_that_was_moved() {
    use allcrypt::api::aead_decrypt;

    // The tag covers the associated data *and* the length of each
    // part. A row's tag offered against the next row's associated
    // data must fail, or the two are not bound together at all - and
    // nothing in a matching vector would say so.
    for name in ["kuznyechik-mgm", "magma-mgm"] {
        let records = section(name);
        let mut tried = 0;
        for pair in records.windows(2) {
            let (first, second) = (&pair[0], &pair[1]);
            let ad = second.bytes("AD");
            if ad == first.bytes("AD") {
                continue;
            }
            assert!(aead_decrypt(name, &first.bytes("Key"),
                                 &first.bytes("Nonce"), &ad,
                                 &first.bytes("Out"), &first.bytes("Tag"))
                    .is_err(),
                    "[{name}] opened a message under somebody else's \
                     associated data");
            tried += 1;
        }
        assert!(tried >= 5, "[{name}] only had {tried} usable pairs");
    }
}

// ------------------------------------------------------------ OMAC ---

#[test]
fn test_omac_matches_the_engine() {
    use allcrypt::mac::cmac::cmac;

    for (name, cipher, tag_len) in [("kuznyechik-mac", "kuznyechik", 16),
                                    ("magma-mac", "magma", 8)] {
        let records = section(name);
        assert_eq!(records.len(), 16, "[{name}] should have sixteen records");
        let mut empty_seen = false;
        let mut exact_block_seen = false;
        for record in &records {
            let key = record.bytes("Key");
            let message = record.bytes("In");
            let expected = record.bytes("Out");
            assert_eq!(expected.len(), tag_len,
                       "[{name}]'s MAC is one block, so {tag_len} bytes - a \
                        shorter one here means the file was generated \
                        through `openssl dgst -mac`, which dispatches both \
                        of these to Magma's method");
            assert_eq!(cmac(cipher, &key, &message).expect("CMAC"), expected,
                       "[{name}] disagrees on a {} byte message", message.len());
            empty_seen |= message.is_empty();
            exact_block_seen |= !message.is_empty()
                && message.len().is_multiple_of(tag_len);
        }
        // CMAC pads the empty message, so it uses K2 where an exact
        // block uses K1. Both mistakes give a MAC that is
        // self-consistent, so a file without both is half a test.
        assert!(empty_seen, "[{name}] has no empty message, which is the K2 case");
        assert!(exact_block_seen, "[{name}] has no whole-block message, which \
                                   is the K1 case");
    }
}

#[test]
fn test_the_two_omacs_are_different_ciphers() {
    // `openssl dgst -mac kuznyechik-mac` and `-mac magma-mac` print
    // the same bytes on this OpenSSL, because the name resolves to
    // Magma's method either way. If a future regeneration ever went
    // back through that route, every Kuznyechik row would be Magma's
    // answer truncated - and each row would still be internally
    // consistent. This is what would say so.
    let kuznyechik = section("kuznyechik-mac");
    let magma = section("magma-mac");
    assert_eq!(kuznyechik.len(), magma.len());
    let mut compared = 0;
    for (left, right) in kuznyechik.iter().zip(magma.iter()) {
        assert_eq!(left.bytes("In"), right.bytes("In"),
                   "the two sections are not over the same messages");
        let short = right.bytes("Out");
        assert_ne!(left.bytes("Out")[..short.len()], short[..],
                   "Kuznyechik's OMAC begins with Magma's, so both rows came \
                    from one cipher");
        compared += 1;
    }
    assert!(compared >= 16);
}

#[test]
fn test_the_gost_28147_mac_matches_the_engine() {
    use allcrypt::tls::record_cnt_imit::gost28147imit;

    // The engine's `gost-mac` is CryptoPro-A and `gost-mac-12` is
    // TC26-Z, both with a zero IV and a four byte tag - the MAC of
    // GOST 28147-89 itself, whose sixteen round transform swaps its
    // halves on the last step where the thirty-two round cipher does
    // not. Copying one loop from the other gives something entirely
    // self-consistent, and these are the only rows that would notice.
    for (name, sbox) in [("gost-mac", "id-Gost28147-89-CryptoPro-A-ParamSet"),
                         ("gost-mac-12", "id-tc26-gost-28147-param-Z")] {
        let records = section(name);
        assert_eq!(records.len(), 16, "[{name}] should have sixteen records");
        for record in &records {
            let message = record.bytes("In");
            let expected = record.bytes("Out");
            assert_eq!(expected.len(), 4, "[{name}]'s tag is four bytes");
            let ours = gost28147imit(&[0u8; 8], &record.bytes("Key"),
                                     &message, sbox).expect("the MAC");
            assert_eq!(ours, expected,
                       "[{name}] disagrees on a {} byte message", message.len());
        }
    }
}

// ---------------------------------------------------------- KExp15 ---

#[test]
fn test_kexp15_matches_the_engine() {
    use allcrypt::tls::gost_kex::kexp15;
    use allcrypt::tls::record_gost::CtrOmacSuite;

    // **Which half of the key is the MAC key** is the thing this
    // settles. R 1323565.1.017-2018 names `K_MAC` and `K_ENC`, and
    // the engine takes one 64 byte key; nothing in either document
    // says which end is which, and every other KExp15 test here has
    // our code at both ends, so it would agree with itself whichever
    // way round it was. The engine's answer is that the MAC key comes
    // first, and that is what this row pins.
    for (name, suite) in [("kuznyechik-kexp15", CtrOmacSuite::KUZNYECHIK),
                          ("magma-kexp15", CtrOmacSuite::MAGMA)] {
        let records = section(name);
        assert_eq!(records.len(), 2, "[{name}] should have two records");
        for record in &records {
            let key = record.bytes("Key");
            assert_eq!(key.len(), 64, "KExp15's key is two keys");
            let (mac_key, enc_key) = key.split_at(32);
            let ours = kexp15(suite, &record.bytes("In"), mac_key, enc_key,
                              &record.bytes("IV")).expect("KExp15");
            assert_eq!(ours, record.bytes("Out"),
                       "[{name}] disagrees on a {} byte secret",
                       record.bytes("In").len());
        }
    }
}

#[test]
fn test_kexp15_unwraps_what_the_engine_wrapped() {
    use allcrypt::tls::gost_kex::kimp15;
    use allcrypt::tls::record_gost::CtrOmacSuite;

    // Unwrapping the *engine's* bytes, not our own. A wrap and an
    // unwrap that share a mistake agree perfectly; only somebody
    // else's ciphertext can say otherwise. The corrupted case is here
    // too, because a `kimp15` that never checked its MAC would pass
    // the row above and this one's first half.
    for (name, suite) in [("kuznyechik-kexp15", CtrOmacSuite::KUZNYECHIK),
                          ("magma-kexp15", CtrOmacSuite::MAGMA)] {
        for record in &section(name) {
            let key = record.bytes("Key");
            let (mac_key, enc_key) = key.split_at(32);
            let iv = record.bytes("IV");
            let wrapped = record.bytes("Out");
            assert_eq!(kimp15(suite, &wrapped, mac_key, enc_key, &iv)
                       .expect("KImp15"), record.bytes("In"),
                       "[{name}] could not unwrap what the engine wrapped");

            let mut damaged = wrapped.clone();
            let last = damaged.len() - 1;
            damaged[last] ^= 1;
            assert!(kimp15(suite, &damaged, mac_key, enc_key, &iv).is_err(),
                    "[{name}] accepted a wrapped secret with a flipped bit");
        }
    }
}

// ------------------------------------------------------------- VKO ---

/// The parameter-set sections, in the order the generator writes them.
///
/// Two of these name the **same curve**: RFC 4357's XchA is CryptoPro-A
/// and XchB is CryptoPro-C, which `ec::curves` asserts from the
/// documents. Deriving under the engine's `XA` and our `gost256-a` is
/// that claim checked by somebody else, which is why the aliases are
/// here rather than deduplicated away.
const CURVE_SECTIONS: &[&str] = &[
    "a-256", "b-256", "c-256", "tca-256", "xa-256", "xb-256",
    "a-512", "b-512", "c-512",
];

#[test]
fn test_vko_matches_the_engine() {
    use allcrypt::bignum::BigUint;
    use allcrypt::ec::curves;
    use allcrypt::ec::vko::Cofactor;
    use allcrypt::ec::Point;

    let mut checked = 0;
    for suffix in CURVE_SECTIONS {
        let name = format!("vko-{suffix}");
        let records = section(&name);
        assert_eq!(records.len(), 2, "[{name}] should have two records");
        for record in &records {
            let curve = curves::by_name(record.raw("Curve").expect("Curve"))
                .expect("the curve");
            let private = BigUint::from_bytes_be(&record.bytes("Private"));
            let peer = Point::new(
                BigUint::from_bytes_be(&record.bytes("PeerX")),
                BigUint::from_bytes_be(&record.bytes("PeerY")));
            assert!(curve.is_on_curve(&peer), "the peer point is not on the curve");
            let bits = record.number("DigestBits");
            let ukm = record.bytes("UKM");

            // `AsSpecified` - RFC 7836's `m/q` term included - which
            // is what the engine turns out to compute. These rows are
            // what established that; see the cofactor test below for
            // what they overturned.
            let ours = curve.vko_using(&private, &peer, &ukm, bits,
                                       Cofactor::AsSpecified)
                .expect("VKO");
            assert_eq!(ours, record.bytes("Out"),
                       "[{name}] disagrees at {bits} bits");
            assert_eq!(ours.len() * 8, bits,
                       "[{name}] derived the wrong length, so the hash is not \
                        the one the row asked for");
            checked += 1;
        }
    }
    assert_eq!(checked, CURVE_SECTIONS.len() * 2);
}

#[test]
fn test_the_engine_settles_vko_s_cofactor() {
    use allcrypt::bignum::BigUint;
    use allcrypt::ec::curves;
    use allcrypt::ec::vko::Cofactor;
    use allcrypt::ec::Point;

    // **These two rows overturned a wrong conclusion**, which is the
    // strongest thing a vector has ever done in this repository.
    //
    // RFC 7836 writes `K = (m/q * UKM * x mod q) * (y*P)`.
    // gost-engine's `VKO_compute_key` reads
    // `BN_mod_mul(scalar, scalar, priv, order)` with no `m/q` in sight,
    // and that was taken as the engine omitting the term - so a
    // `Cofactor::AsDeployed` variant was added and the TLS key exchange
    // was pointed at it, on the argument that its job is to reach a box
    // and the box runs gost-engine.
    //
    // Three lines below that `BN_mod_mul` is a `#if 0` block naming
    // these exact two curves and a comment saying the cofactor clearing
    // is done by `gost_ec_point_mul` instead. The engine applies it.
    // The argument was right and the premise was wrong, and the code
    // would have derived a key no peer shares on either of the two
    // curves that matter.
    //
    // So this asserts both halves: that the engine's answer is
    // `AsSpecified`, and that `WithoutCofactor` gives something *else*
    // on this curve. Without the second half the row would pass on an
    // implementation where the two readings had collapsed into one, and
    // then `Cofactor` would be a distinction with no content.
    let records = section("vko-tca-256");
    assert_eq!(records.len(), 2);
    let mut differed = 0;
    for record in &records {
        let curve = curves::by_name("gost256-tc26-a").expect("the curve");
        assert_eq!(curve.h, BigUint::from_u64(4),
                   "this test is about a cofactor of four");
        let private = BigUint::from_bytes_be(&record.bytes("Private"));
        let peer = Point::new(
            BigUint::from_bytes_be(&record.bytes("PeerX")),
            BigUint::from_bytes_be(&record.bytes("PeerY")));
        let bits = record.number("DigestBits");
        let ukm = record.bytes("UKM");

        let without = curve.vko_using(&private, &peer, &ukm, bits,
                                      Cofactor::WithoutCofactor).expect("VKO");
        let specified = curve.vko_using(&private, &peer, &ukm, bits,
                                        Cofactor::AsSpecified).expect("VKO");
        assert_eq!(specified, record.bytes("Out"),
                   "gost-engine is not RFC 7836's reading after all");
        assert_ne!(without, record.bytes("Out"),
                   "dropping the cofactor also matches, so this row cannot \
                    tell the two apart and Cofactor is untested here");
        differed += 1;
    }
    assert_eq!(differed, 2);
}

#[test]
fn test_the_exchange_parameter_sets_are_aliases_to_the_engine_too() {
    // `ec::curves` asserts from RFC 4357 that XchA is CryptoPro-A and
    // XchB is CryptoPro-C. The engine agrees: the rows it generated
    // under `XA` name `gost256-a`, and they verify under it. That is a
    // reading of one document checked against somebody else's reading
    // of the same one.
    for (alias, real) in [("vko-xa-256", "gost256-a"),
                          ("vko-xb-256", "gost256-c")] {
        let records = section(alias);
        assert!(!records.is_empty(), "[{alias}] is empty");
        for record in &records {
            assert_eq!(record.raw("Curve"), Some(real),
                       "[{alias}] is not on {real}");
        }
    }
}

// ------------------------------------------------- GOST signatures ---

#[test]
fn test_the_engine_s_signatures_verify() {
    use allcrypt::api::AnyHash;
    use allcrypt::bignum::BigUint;
    use allcrypt::ec::curves;
    use allcrypt::ec::Point;
    use allcrypt::hash_functions::HashFunction;

    // **Somebody else's signatures.** GOST R 34.10-2012 is not ECDSA
    // with different curves: the digest is read *little endian*, the
    // signing equation has no inversion, and the wire order is
    // `s || r`. All three are silent when wrong, and our signer and
    // verifier agree by construction - so until these rows existed the
    // only thing checking them was a second reading of the standard.
    let mut checked = 0;
    for suffix in CURVE_SECTIONS {
        let name = format!("sign-{suffix}");
        let records = section(&name);
        assert_eq!(records.len(), 3, "[{name}] should have three records");
        for record in &records {
            let curve = curves::by_name(record.raw("Curve").expect("Curve"))
                .expect("the curve");
            let public = Point::new(
                BigUint::from_bytes_be(&record.bytes("PublicX")),
                BigUint::from_bytes_be(&record.bytes("PublicY")));
            let hash_name = match record.raw("Digest").expect("Digest") {
                "md_gost12_256" => "streebog256",
                "md_gost12_512" => "streebog512",
                other => panic!("unexpected digest {other}"),
            };
            let mut hash = AnyHash::new(hash_name).expect("the hash");
            hash.update(&record.bytes("In"));
            let digest = hash.digest();

            let signature = curve
                .gost_signature_from_bytes(&record.bytes("Sig"))
                .expect("the signature decodes");
            assert!(curve.gost_verify(&public, &digest, &signature)
                    .expect("verify"),
                    "[{name}] rejected a signature the engine made and \
                     verified");
            checked += 1;
        }
    }
    assert_eq!(checked, CURVE_SECTIONS.len() * 3);
}

#[test]
fn test_the_wire_order_and_the_digest_reading_are_both_load_bearing() {
    use allcrypt::api::AnyHash;
    use allcrypt::bignum::BigUint;
    use allcrypt::ec::curves;
    use allcrypt::ec::ecdsa::Signature;
    use allcrypt::ec::Point;
    use allcrypt::hash_functions::HashFunction;

    // Two ways to be wrong that a matching row cannot see, because a
    // signature built the other way round is still the right length and
    // still parses:
    //
    //   * `r || s` instead of `s || r` - ECDSA's order.
    //   * the digest read big endian instead of little.
    //
    // Both must make verification *fail* on the engine's own
    // signatures, or these rows are not evidence about either.
    let mut tried = 0;
    for suffix in CURVE_SECTIONS {
        for record in &section(&format!("sign-{suffix}")) {
            let curve = curves::by_name(record.raw("Curve").expect("Curve"))
                .expect("the curve");
            let public = Point::new(
                BigUint::from_bytes_be(&record.bytes("PublicX")),
                BigUint::from_bytes_be(&record.bytes("PublicY")));
            let hash_name = match record.raw("Digest").expect("Digest") {
                "md_gost12_256" => "streebog256",
                _ => "streebog512",
            };
            let mut hash = AnyHash::new(hash_name).expect("the hash");
            hash.update(&record.bytes("In"));
            let digest = hash.digest();
            let correct = curve
                .gost_signature_from_bytes(&record.bytes("Sig"))
                .expect("the signature decodes");

            let swapped = Signature { r: correct.s.clone(),
                                      s: correct.r.clone() };
            assert!(!curve.gost_verify(&public, &digest, &swapped)
                    .expect("verify"),
                    "the components swapped also verified, so the wire order \
                     is not being tested");

            let mut reversed = digest.clone();
            reversed.reverse();
            assert!(!curve.gost_verify(&public, &reversed, &correct)
                    .expect("verify"),
                    "the digest read the other way round also verified, so \
                     its endianness is not being tested");
            tried += 1;
        }
    }
    assert_eq!(tried, CURVE_SECTIONS.len() * 3);
}

// ----------------------------------------------------------- TLSTREE ---

#[test]
fn test_tlstree_matches_the_engine() {
    use allcrypt::kdf::gost::{tlstree, TlsTreeParams};

    // **Two of the six constant sets.** These are RFC 9189's TLS 1.2
    // pair; `gost_tlstree` has no entry for RFC 9367's four TLS 1.3 sets
    // and refuses them, so those stay on the documents' own tables,
    // which `kdf::gost::document_tests` parses.
    //
    // The interesting part is that the engine reaches the same answer by
    // the opposite route. It reads the eight wire bytes into a `uint64_t`
    // **little endian** and masks with byte-reversed constants -
    // `0x00000000FFFFFFFF` where this library has
    // `0xFFFF_FFFF_0000_0000` - and the masked seed comes out the same
    // byte string either way. Two implementations agreeing through
    // opposite conventions is worth more than two agreeing through the
    // same one.
    let mut past_a_boundary = 0;
    for (name, params) in [("tlstree-kuznyechik", TlsTreeParams::KUZNYECHIK),
                           ("tlstree-magma", TlsTreeParams::MAGMA)] {
        let records = section(name);
        assert_eq!(records.len(), 17, "[{name}] should have seventeen records");
        for record in &records {
            let root = record.bytes("Key");
            let wire = record.bytes("Seq");
            assert_eq!(wire.len(), 8, "a sequence number is eight bytes");
            let sequence = u64::from_be_bytes(wire.clone().try_into()
                                              .expect("eight bytes"));
            assert_eq!(tlstree(&root, sequence, params), record.bytes("Out"),
                       "[{name}] disagrees at sequence {sequence}");
            if sequence >= 64 {
                past_a_boundary += 1;
            }
        }
    }
    // Every mask is all ones at sequence zero, so a row there passes
    // whatever the constants are. Without rows past a boundary this test
    // would hold on a mistyped set.
    assert!(past_a_boundary >= 24,
            "only {past_a_boundary} rows are past the first level boundary");
}

#[test]
fn test_where_the_two_tlstree_suites_agree_is_a_property_of_the_constants() {
    use allcrypt::kdf::gost::{tlstree, TlsTreeParams};

    // At sequence zero **every mask is all ones**, so both suites mask
    // to the same three seeds and the same root gives the same key. That
    // is the hazard this pins: a mistyped constant interoperates on the
    // first record of a connection and diverges later.
    //
    // Where they part company is decided entirely by the constants, so
    // it is asserted as a set rather than as a count. Kuznyechik re-keys
    // level 3 every 2^6 records and Magma every 2^12, so the two agree
    // below 64, differ from 64 up to Magma's boundary, and coincide
    // again wherever a sequence number is masked identically by both -
    // which happens at Magma's level boundaries, because Kuznyechik's
    // masks are coarser at every level.
    //
    // A count would have been a property of the build. Twice already
    // this repository has written down a count and had to replace it
    // with a name; this is the same lesson applied before the fact.
    let expected_to_differ: &[u64] = &[
        64, 65, 4095,
        (1 << 19) - 1, 1 << 19,
        (1 << 25) - 1,
        (1u64 << 32) - 1, 1u64 << 32,
        (1u64 << 38) - 1,
        0x0123_4567_89ab_cdef,
    ];

    let records = section("tlstree-kuznyechik");
    let root = records[0].bytes("Key");
    let mut differed = Vec::new();
    for record in &records {
        let sequence = u64::from_be_bytes(record.bytes("Seq").try_into()
                                         .expect("eight bytes"));
        if tlstree(&root, sequence, TlsTreeParams::KUZNYECHIK)
            != tlstree(&root, sequence, TlsTreeParams::MAGMA) {
            differed.push(sequence);
        }
    }
    assert_eq!(differed, expected_to_differ,
               "the two constant sets part company at different sequence \
                numbers than they should - one of them has changed");
    assert!(!differed.contains(&0),
             "the suites must agree at sequence zero, where every mask is \
              all ones");
}

// ------------------------------------------------------ the file ---

#[test]
fn test_the_header_agrees_with_the_body() {
    // The generator writes the count of every command-line section
    // into the header. If the parser here and the generator there ever
    // stop agreeing about what a record is, this is what says so -
    // and it needs no number typed into this file, which is the only
    // kind of count worth having.
    let declared = declared_counts();
    assert!(declared.len() >= 17,
            "the header declared only {} sections", declared.len());
    for (name, count) in &declared {
        assert_eq!(section(name).len(), *count,
                   "[{name}]: the header says {count} records");
    }
}

#[test]
fn test_every_section_in_the_file_is_read_by_something() {
    // A section nobody reads is a section that silently stops being
    // checked - the file would keep growing and the suite would keep
    // passing. Every heading has to appear in this list, so adding one
    // to the generator fails here until a test for it exists.
    let read_by_a_test = [
        "kuznyechik-ecb", "kuznyechik-cbc", "kuznyechik-cfb",
        "kuznyechik-ofb", "kuznyechik-ctr", "kuznyechik-ctr-acpkm",
        "magma-ecb", "magma-cbc", "magma-ctr", "magma-ctr-acpkm",
        "gost89", "gost89-cbc", "gost89-cnt", "gost89-cnt-12",
        "md_gost94", "md_gost12_256", "md_gost12_512",
        "kuznyechik-mgm", "magma-mgm",
        "kuznyechik-mac", "magma-mac", "gost-mac", "gost-mac-12",
        "kuznyechik-kexp15", "magma-kexp15",
        "vko-a-256", "vko-b-256", "vko-c-256", "vko-tca-256",
        "vko-xa-256", "vko-xb-256",
        "vko-a-512", "vko-b-512", "vko-c-512",
        "sign-a-256", "sign-b-256", "sign-c-256", "sign-tca-256",
        "sign-xa-256", "sign-xb-256",
        "sign-a-512", "sign-b-512", "sign-c-512",
        "tlstree-kuznyechik", "tlstree-magma",
    ];
    let headings: Vec<&str> = VECTORS.lines()
        .map(str::trim)
        .filter(|line| line.starts_with('['))
        .map(|line| &line[1..line.len() - 1])
        .collect();
    assert_eq!(headings.len(), read_by_a_test.len(),
               "the file has {} sections and {} are listed here",
               headings.len(), read_by_a_test.len());
    for heading in &headings {
        assert!(read_by_a_test.contains(heading),
                "[{heading}] is in the file and no test reads it");
    }
    for name in read_by_a_test {
        assert!(!section(name).is_empty(), "[{name}] is listed and empty");
    }
}
