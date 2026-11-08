//! Grain-128AEADv2 against `vectors/grain128aead.vec`, written by
//! `scripts/make_grain128aead_vectors.py`: the NIST final round's 1,089
//! known answers, and random inputs across the DER length forms of the
//! associated data, on which lwc-finalists, the grain-128aeadv2 crate and
//! (where its length encoding is DER's) Bouncy Castle 1.77 agree. And
//! Grain-128AEAD v1 against `vectors/grain128aead_v1.vec`, written by
//! `scripts/make_grain128aead_v1_vectors.py`: the designers' 1,089 known
//! answers and the same shape of random inputs, on which the designers'
//! reference and optimised implementations and lightweight-crypto agree.
//! Every row both ways, through the catalogue, with a forged tag refused.
//! Offline.

use std::collections::HashMap;

use allcrypt::api::{aead_decrypt, aead_encrypt, aead_tag_len, AeadStream};

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Row {
    key: Vec<u8>,
    nonce: Vec<u8>,
    ad: Vec<u8>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    tag: Vec<u8>,
    source: String,
}

fn rows() -> Vec<Row> {
    rows_of(include_str!("../vectors/grain128aead.vec"), "grain128aeadv2 ")
}

fn rows_v1() -> Vec<Row> {
    rows_of(include_str!("../vectors/grain128aead_v1.vec"), "grain128aeadv1 ")
}

fn rows_of(text: &str, kind: &str) -> Vec<Row> {
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| l.starts_with(kind))
        .map(|line| {
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { key: unhex(f["key"]), nonce: unhex(f["nonce"]), ad: unhex(f["ad"]),
                  pt: unhex(f["pt"]), ct: unhex(f["ct"]), tag: unhex(f["tag"]),
                  source: f["source"].to_string() }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

#[test]
fn test_grain128aead_vectors() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in rows() {
        let (ct, tag) = aead_encrypt("grain128aeadv2", &r.key, &r.nonce, &r.ad, &r.pt).unwrap();
        assert_eq!((&ct, &tag), (&r.ct, &r.tag), "{} {}", r.ad.len(), r.pt.len());
        assert_eq!(aead_decrypt("grain128aeadv2", &r.key, &r.nonce, &r.ad, &r.ct, &r.tag)
                       .unwrap(), r.pt);
        let mut forged = r.tag.clone();
        forged[r.pt.len() % 8] ^= 1 << (r.ad.len() % 8);
        assert!(aead_decrypt("grain128aeadv2", &r.key, &r.nonce, &r.ad, &r.ct, &forged)
                    .is_err());
        *counts.entry(r.source).or_default() += 1;
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(counts["nist"], 1089);
    assert_eq!(counts["random"], 158);
}

#[test]
fn test_grain128aead_v1_vectors() {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in rows_v1() {
        let (ct, tag) = aead_encrypt("grain128aeadv1", &r.key, &r.nonce, &r.ad, &r.pt).unwrap();
        assert_eq!((&ct, &tag), (&r.ct, &r.tag), "{} {}", r.ad.len(), r.pt.len());
        assert_eq!(aead_decrypt("grain128aeadv1", &r.key, &r.nonce, &r.ad, &r.ct, &r.tag)
                       .unwrap(), r.pt);
        let mut forged = r.tag.clone();
        forged[r.pt.len() % 8] ^= 1 << (r.ad.len() % 8);
        assert!(aead_decrypt("grain128aeadv1", &r.key, &r.nonce, &r.ad, &r.ct, &forged)
                    .is_err());
        // The other version does not open it.
        assert!(aead_decrypt("grain128aeadv2", &r.key, &r.nonce, &r.ad, &r.ct, &r.tag)
                    .is_err());
        *counts.entry(r.source).or_default() += 1;
    }
    assert_eq!(counts["designers"], 1089);
    assert_eq!(counts["random"], 158);
}

/// The two known-answer files have the same 1,089 inputs and no answer
/// in common.
#[test]
fn test_the_two_versions_known_answers_differ_everywhere() {
    let (v1, v2) = (rows_v1(), rows());
    for (a, b) in v1.iter().zip(&v2).take(1089) {
        assert_eq!((&a.key, &a.nonce, &a.ad, &a.pt), (&b.key, &b.nonce, &b.ad, &b.pt));
        assert_ne!(a.tag, b.tag);
        if !a.pt.is_empty() {
            assert_ne!(a.ct, b.ct);
        }
    }
}

/// A changed ciphertext bit, nonce or associated data byte is refused;
/// the plaintext is authenticated, so a flipped ciphertext bit changes
/// the tag.
#[test]
fn test_grain128aead_refuses_changes() {
    let r = rows().into_iter().find(|r| r.source == "random" && r.pt.len() == 33
                                    && r.ad.len() == 17).unwrap();
    for bit in 0..r.ct.len() * 8 {
        let mut ct = r.ct.clone();
        ct[bit / 8] ^= 1 << (bit % 8);
        assert!(aead_decrypt("grain128aeadv2", &r.key, &r.nonce, &r.ad, &ct, &r.tag).is_err(),
                "bit {bit}");
    }
    let mut nonce = r.nonce.clone();
    nonce[11] ^= 0x80;
    assert!(aead_decrypt("grain128aeadv2", &r.key, &nonce, &r.ad, &r.ct, &r.tag).is_err());
    let mut ad = r.ad.clone();
    ad.push(0);
    assert!(aead_decrypt("grain128aeadv2", &r.key, &r.nonce, &ad, &r.ct, &r.tag).is_err());
}

/// The stream object takes its input in pieces and gives the one-shot
/// answer; it buffers, and says so.
#[test]
fn test_grain128aead_through_the_stream() {
    let r = rows().into_iter().find(|r| r.source == "random" && r.pt.len() == 1000).unwrap();
    let mut s = AeadStream::new("grain-128aeadv2", &r.key, &r.nonce, &r.ad, false).unwrap();
    assert!(s.buffers_everything());
    assert_eq!(s.tag_len(), 8);
    let mut out = Vec::new();
    for chunk in r.pt.chunks(7) {
        s.update(chunk, &mut out).unwrap();
    }
    assert_eq!(s.finish(&mut out).unwrap(), r.tag);
    assert_eq!(out, r.ct);
    assert_eq!(aead_tag_len("grain128aeadv2", &r.key).unwrap(), 8);

    let r = rows_v1().into_iter().find(|r| r.source == "random" && r.pt.len() == 1000).unwrap();
    let mut s = AeadStream::new("grain-128aeadv1", &r.key, &r.nonce, &r.ad, true).unwrap();
    assert!(s.buffers_everything());
    let mut out = Vec::new();
    for chunk in r.ct.chunks(7) {
        s.update(chunk, &mut out).unwrap();
    }
    s.open(&r.tag, &mut out).unwrap();
    assert_eq!(out, r.pt);
}

#[test]
fn test_grain128aead_refusals() {
    let (k, n) = ([0u8; 16], [0u8; 12]);
    assert!(aead_encrypt("grain128aeadv2", &k[..15], &n, b"", b"").is_err());
    assert!(aead_encrypt("grain128aeadv2", &k, &n[..8], b"", b"").is_err());
    // There is no truncated form: the name with a tag length is unknown.
    assert!(aead_encrypt("grain128aeadv2-4", &k, &n, b"", b"").is_err());
    assert!(aead_decrypt("grain128aeadv2", &k, &n, b"", b"", &[0; 16]).is_err());
    assert!(aead_encrypt("grain128aeadv1", &k[..15], &n, b"", b"").is_err());
    // The bare name is both versions, and is refused with both names -
    // by its own refusal, not the unknown-name one, which lists the whole
    // catalogue and so names both as well.
    let err = aead_encrypt("grain128aead", &k, &n, b"", b"").unwrap_err();
    assert!(err.contains("names two ciphers") && err.contains("\"grain128aeadv1\"")
            && err.contains("\"grain128aeadv2\""), "{err}");
    // An error says which version refused.
    for (name, other) in [("grain128aeadv1", "v2"), ("grain128aeadv2", "v1")] {
        let err = aead_decrypt(name, &k, &n, b"", b"", &[0; 8]).unwrap_err();
        let own = format!("Grain-128AEAD{}", &name[12..]);
        assert!(err.starts_with(&own) && !err.contains(other), "{err}");
    }
}
