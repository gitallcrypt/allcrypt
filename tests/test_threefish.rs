//! Threefish-256, -512 and -1024 against `vectors/threefish.vec`, written
//! by `scripts/make_threefish_vectors.py`: rows on which Crypto++ 8.9.0,
//! Bouncy Castle 1.77 and Skein3Fish's C all agree - Crypto++'s published
//! tests, single bits through the key, the tweak and the block, repeated
//! bytes, random blocks with and without a tweak, and blocks iterated 100
//! and 1,000 times. Offline.

use std::collections::HashMap;

use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};
use allcrypt::block_ciphers::threefish::Threefish;
use allcrypt::block_ciphers::BlockCipher;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Row {
    kind: String,
    key: Vec<u8>,
    tweak: Option<[u8; 16]>,
    pt: Vec<u8>,
    ct: Vec<u8>,
    n: usize,
    published: bool,
}

fn rows() -> Vec<Row> {
    let text = include_str!("../vectors/threefish.vec");
    let declared: usize = text.lines().find_map(|l| l.strip_prefix("# rows: "))
        .expect("the header's row count").parse().unwrap();
    let rows: Vec<Row> = text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let kind = line.split(' ').next().unwrap().to_string();
            let f: HashMap<&str, &str> = line.split(' ').skip(1)
                .map(|w| w.split_once('=').unwrap()).collect();
            Row { kind, key: unhex(f["key"]),
                  tweak: f.get("tweak").map(|t| unhex(t).try_into().unwrap()),
                  pt: unhex(f["pt"]), ct: unhex(f["ct"]),
                  n: f.get("n").map_or(1, |n| n.parse().unwrap()),
                  published: f.get("src") == Some(&"published") }
        })
        .collect();
    assert_eq!(rows.len(), declared);
    rows
}

/// The ways to key a cipher with the row's key and tweak: the key alone
/// (only without a tweak), the key followed by the tweak (a zero tweak
/// when there is none), `with_tweak`, and `set_tweak` after the key
/// alone. Each must give the row.
fn ciphers<const N: usize>(r: &Row) -> Vec<(&'static str, Threefish<N>)> {
    let tweak = r.tweak.unwrap_or([0; 16]);
    let mut ways = vec![
        ("key and tweak", Threefish::<N>::new(&[r.key.as_slice(), &tweak].concat()).unwrap()),
        ("with_tweak", Threefish::<N>::with_tweak(&r.key, &tweak).unwrap()),
    ];
    let mut set = Threefish::<N>::new(&r.key).unwrap();
    set.set_tweak(&tweak);
    ways.push(("set_tweak", set));
    if r.tweak.is_none() {
        ways.push(("key alone", Threefish::<N>::new(&r.key).unwrap()));
    }
    ways
}

fn check_rows<const N: usize>(kind: &str, want_published: usize) {
    let rows = rows();
    let (mut single, mut published, mut tweaked) = (0, 0, 0);
    for r in rows.iter().filter(|r| r.kind == kind) {
        for (way, mut c) in ciphers::<N>(r) {
            let mut out = Vec::new();
            c.block_encrypt(&r.pt, &mut out);
            assert_eq!(out, r.ct, "{kind} {way} encrypt {:02x?} {:02x?}", r.key, r.pt);
            let mut back = Vec::new();
            c.block_decrypt(&r.ct, &mut back);
            assert_eq!(back, r.pt, "{kind} {way} decrypt {:02x?}", r.key);
        }
        single += 1;
        published += usize::from(r.published);
        tweaked += usize::from(r.tweak.is_some_and(|t| t != [0; 16]));
    }
    // A parser that found nothing would pass every assertion above.
    assert_eq!(published, want_published, "{kind}");
    assert!(single >= 250, "{kind}: {single}");
    assert!(tweaked >= 150, "{kind}: {tweaked} rows with a tweak");
}

#[test]
fn test_threefish256_vectors() {
    check_rows::<4>("threefish256", PUBLISHED[0]);
}

#[test]
fn test_threefish512_vectors() {
    check_rows::<8>("threefish512", PUBLISHED[1]);
}

#[test]
fn test_threefish1024_vectors() {
    check_rows::<16>("threefish1024", PUBLISHED[2]);
}

/// Crypto++'s published blocks at each size: the Skein team's known
/// answers with and without a tweak, and at 512 bits Botan's four tests
/// too - five blocks, the last test's first block the third test again.
const PUBLISHED: [usize; 3] = [2, 6, 2];

fn check_iterated<const N: usize>(r: &Row) {
    let mut c = Threefish::<N>::new(&[r.key.as_slice(), &r.tweak.unwrap_or([0; 16])].concat())
        .unwrap();
    let mut block = r.pt.clone();
    for _ in 0..r.n {
        let mut out = Vec::new();
        c.block_encrypt(&block, &mut out);
        block = out;
    }
    assert_eq!(block, r.ct, "{} {:02x?} {}", r.kind, r.key, r.n);
    for _ in 0..r.n {
        let mut out = Vec::new();
        c.block_decrypt(&block, &mut out);
        block = out;
    }
    assert_eq!(block, r.pt, "{} {:02x?} {}", r.kind, r.key, r.n);
}

/// A block encrypted `n` times over, and decrypted as many times back.
#[test]
fn test_threefish_iterated() {
    let mut checked = 0;
    for r in rows().iter().filter(|r| r.kind.ends_with("-iter")) {
        match r.kind.as_str() {
            "threefish256-iter" => check_iterated::<4>(r),
            "threefish512-iter" => check_iterated::<8>(r),
            "threefish1024-iter" => check_iterated::<16>(r),
            other => panic!("{other}"),
        }
        checked += 1;
    }
    assert_eq!(checked, 3 * 7);
}

/// Through the catalogue, with the key alone and with the tweak after it,
/// in every mode and at lengths around the block: encrypting in irregular
/// pieces must equal one call and decrypting must give the message back;
/// ECB through the catalogue is the recorded rows.
#[test]
fn test_threefish_through_the_catalogue_in_every_mode() {
    let rows = rows();
    let mut checked = 0;
    for (kind, block) in [("threefish256", 32), ("threefish512", 64), ("threefish1024", 128)] {
        for r in [rows.iter().find(|r| r.kind == kind && r.tweak.is_none()).unwrap(),
                  rows.iter().find(|r| r.kind == kind && r.tweak.is_some() && !r.published)
                      .unwrap()] {
            let key = [r.key.as_slice(), r.tweak.as_ref().map_or(&[][..], |t| &t[..])].concat();
            let mut ecb = CipherStream::new(AnyBlockCipher::new(kind, &key, None).unwrap(),
                                            Mode::from_name("ecb").unwrap(), &[], false).unwrap();
            let mut out = ecb.update(&r.pt).unwrap();
            out.extend(ecb.finish().unwrap());
            assert_eq!(out[..block], r.ct[..], "{kind}");
            assert_eq!(AnyBlockCipher::new(kind, &key, None).unwrap().name(), kind);
        }

        for key_len in [block, block + 16] {
            let key: Vec<u8> = (0..key_len as u32).map(|i| (i * 5 + 1) as u8).collect();
            for mode_name in allcrypt::api::MODES {
                let mode = Mode::from_name(mode_name).unwrap();
                for len in [0usize, 1, block - 1, block, block + 1, 2 * block + 1, 300] {
                    let message: Vec<u8> = (0..len as u32).map(|i| (i * 7 + 3) as u8).collect();
                    let iv = if *mode_name == "ecb" { vec![] } else { vec![9u8; block] };
                    let one = {
                        let mut s = match CipherStream::new(
                            AnyBlockCipher::new(kind, &key, None).unwrap(), mode, &iv, false) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        let mut out = s.update(&message).unwrap();
                        match s.finish() {
                            Ok(tail) => out.extend(tail),
                            // A mode that cannot take this length says so;
                            // that is checked for every cipher elsewhere.
                            Err(_) => continue,
                        }
                        out
                    };
                    let mut s = CipherStream::new(AnyBlockCipher::new(kind, &key, None).unwrap(),
                                                  mode, &iv, false).unwrap();
                    let mut pieces = Vec::new();
                    for chunk in message.chunks(5) {
                        pieces.extend(s.update(chunk).unwrap());
                    }
                    pieces.extend(s.finish().unwrap());
                    assert_eq!(pieces, one, "{kind} {mode_name} {len}");
                    let mut d = CipherStream::new(AnyBlockCipher::new(kind, &key, None).unwrap(),
                                                  mode, &iv, true).unwrap();
                    let mut back = d.update(&one).unwrap();
                    back.extend(d.finish().unwrap());
                    assert_eq!(back, message, "{kind} {mode_name} {len}");
                    checked += 1;
                }
            }
        }
    }
    // The `continue`s skip lengths a mode cannot take; most must remain.
    assert!(checked >= 200, "only {checked} cipher, key, mode and length combinations ran");
}

/// The tweak's two words are both read, in their order: exchanging them,
/// or zeroing either, changes every tweaked row's block.
#[test]
fn test_both_tweak_words_count() {
    let rows = rows();
    let mut checked = 0;
    for r in rows.iter().filter(|r| r.kind == "threefish512" && r.tweak.is_some()) {
        let t = r.tweak.unwrap();
        if t[..8] == t[8..] || t[..8] == [0; 8] || t[8..] == [0; 8] {
            continue;
        }
        for other in [[&t[8..], &t[..8]].concat(), [&t[..8], &[0; 8][..]].concat(),
                      [&[0; 8][..], &t[8..]].concat()] {
            let mut c = Threefish::<8>::with_tweak(&r.key, &other.try_into().unwrap()).unwrap();
            let mut out = Vec::new();
            c.block_encrypt(&r.pt, &mut out);
            assert_ne!(out, r.ct, "{:02x?}", r.key);
        }
        checked += 1;
    }
    assert!(checked >= 32, "{checked}");
}
