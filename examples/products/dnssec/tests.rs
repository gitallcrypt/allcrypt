//! The examples of the DNSSEC RFCs, read out of the documents in `rfcs/`,
//! and the records `scripts/check_dnssec.py` recorded from dnspython.

use super::*;

use allcrypt::hash_functions::HashFunction;
use crate::fixtures;
use rr::{Nsec3, Rrsig};
use sign::Options;


/// An RFC's text with the page breaks taken out: the footer, the form
/// feed and the running header, so an example split across a page reads
/// as one.
fn rfc(number: u32) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("rfcs").join(format!("rfc{number}.txt"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    let header = format!("RFC {number} ");
    text.lines()
        .filter(|l| !l.trim_end().ends_with(']') || !l.contains("[Page "))
        .filter(|l| !l.starts_with(&header) && !l.starts_with('\u{c}'))
        .collect::<Vec<_>>().join("\n")
}

/// The text from the first line containing `start`, outside the table of
/// contents, up to (not including)
/// the next line containing `end`, dedented by the first line's indent.
fn between(text: &str, start: &str, end: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    // A heading starts its line; a table of contents entry for it is
    // indented, and in older RFCs dotted. Either is not the section.
    let from = lines.iter().position(|l| l.starts_with(start))
        .or_else(|| lines.iter().position(|l| l.contains(start) && !l.contains(". . .")))
        .unwrap_or_else(|| panic!("no line with {start:?}"));
    let to = lines[from + 1..].iter().position(|l| l.contains(end))
        .map(|i| from + 1 + i).unwrap_or_else(|| panic!("no line with {end:?} after {start:?}"));
    let indent = lines[from].len() - lines[from].trim_start().len();
    lines[from..to].iter()
        .map(|l| if l.len() >= indent && l[..indent].trim().is_empty() { &l[indent..] }
                 else { l.trim_start() })
        .collect::<Vec<_>>().join("\n")
}

fn records(text: &str) -> Vec<Record> {
    zone::parse(&format!("$TTL 3600\n{text}"), &Name::root()).unwrap()
}

fn of_type(records: &[Record], rtype: u16) -> Vec<Record> {
    records.iter().filter(|r| r.rtype == rtype).cloned().collect()
}

/// One example of the form the algorithm RFCs share: a private key, its
/// DNSKEY, perhaps a DS, an RRset and an RRSIG over it. Checks the public
/// key, the key tag, the DS, and the signature; and, where the algorithm
/// is deterministic, that signing again gives the document's bytes.
fn check_example(private: &str, zone_text: &str, deterministic: bool) {
    let key = Key::from_private_file(private).unwrap();
    let all = records(zone_text);
    let dnskey_record = &of_type(&all, rr::DNSKEY)[0];
    let dnskey = Dnskey::parse(&dnskey_record.rdata).unwrap();
    assert_eq!(key.public_key().unwrap(), dnskey.public_key, "public key");

    let tag = keys::key_tag(&dnskey_record.rdata);
    for ds in of_type(&all, rr::DS) {
        assert_eq!(u16::from_be_bytes([ds.rdata[0], ds.rdata[1]]), tag, "DS key tag");
        let digest = keys::ds_digest(&ds.owner, &dnskey_record.rdata, ds.rdata[3]).unwrap();
        assert_eq!(digest, ds.rdata[4..], "DS digest type {}", ds.rdata[3]);
    }

    let sigs = of_type(&all, rr::RRSIG);
    assert!(!sigs.is_empty());
    for sig_record in sigs {
        let sig = rr::Rrsig::parse(&sig_record.rdata).unwrap();
        assert_eq!(sig.key_tag, tag, "RRSIG key tag");
        let set: Vec<Record> = all.iter()
            .filter(|r| r.rtype == sig.type_covered && r.owner.eq_ignore_case(&sig_record.owner))
            .cloned().collect();
        let data = sign::signed_data(&sig, &set).unwrap();
        assert!(keys::verify(key.algorithm, &dnskey.public_key, &data, &sig.signature).unwrap(),
                "{} RRSIG {}", key.algorithm.mnemonic, rr::type_name(sig.type_covered));
        if deterministic {
            assert_eq!(key.sign(&data).unwrap(), sig.signature, "signing again");
        }
        let mut wrong = data.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(!keys::verify(key.algorithm, &dnskey.public_key, &wrong, &sig.signature)
            .unwrap());
    }
}

/// The private key block of an example (from `Private-key-format` to
/// the first blank line) and its records: lines that start a record,
/// and the lines of a record whose parentheses are still open. Prose is
/// dropped.
fn split_example(section: &str) -> (String, String) {
    let lines: Vec<&str> = section.lines().collect();
    let start = lines.iter().position(|l| l.trim_start().starts_with("Private-key-format"))
        .expect("a private key");
    let indent = lines[start].len() - lines[start].trim_start().len();
    let end = lines[start..].iter().position(|l| l.trim().is_empty())
        .map(|i| start + i).unwrap_or(lines.len());
    let private: Vec<&str> = lines[start..end].iter()
        .map(|l| if l.len() >= indent { &l[indent..] } else { l.trim_start() }).collect();

    let mut kept = Vec::new();
    let mut depth = 0i32;
    for line in &lines[end..] {
        let body = line.split(';').next().unwrap_or("");
        let tokens: Vec<&str> = body.split_whitespace().collect();
        let starts = tokens.len() >= 3 && tokens[0].ends_with('.')
            && tokens[0].chars().any(|c| c.is_ascii_alphabetic())
            && tokens[1..4.min(tokens.len())].iter()
                .any(|t| rr::type_from_name(t.trim_start_matches('(')).is_some());
        if starts || depth > 0 {
            kept.push(line.trim().to_string());
            depth += body.matches('(').count() as i32 - body.matches(')').count() as i32;
        }
    }
    (private.join("\n"), kept.join("\n"))
}

#[test]
fn test_rfc_8080_ed25519_and_ed448() {
    let text = rfc(8080);
    let section = between(&text, "6.1.  Ed25519 Examples", "7.  IANA Considerations");
    let blocks: Vec<&str> = section.split("Private-key-format").skip(1).collect();
    assert_eq!(blocks.len(), 4);
    for block in blocks {
        // The published RRSIGs read "RRSIG MX 3 3600 ( ... example.com. (",
        // which leaves out the algorithm field and opens a second
        // parenthesis it never closes. The signatures are over
        // "MX 15 3 3600" (16 for Ed448): the algorithm restored and a
        // label count of 3, though example.com. has two labels. So a
        // validator would refuse these RRSIGs for their label count; the
        // signature arithmetic is what is checked here.
        let algorithm = if block.contains("Algorithm: 15") { 15 } else { 16 };
        let fixed = block.replace("RRSIG MX 3 3600 (", &format!("RRSIG MX {algorithm} 3 3600 ("))
            .replace("3613 example.com. (", "3613 example.com.")
            .replace("35217 example.com. (", "35217 example.com.")
            .replace("9713 example.com. (", "9713 example.com.")
            .replace("38353 example.com. (", "38353 example.com.");
        assert_ne!(fixed, block, "the erratum is no longer in the document");
        let (private, zone_text) = split_example(&format!("Private-key-format{fixed}"));
        check_example(&private, &zone_text, true);
    }
}

#[test]
fn test_rfc_5702_rsa_sha256_and_sha512() {
    let text = rfc(5702);
    for (start, end) in [("6.1.  RSA/SHA-256", "6.2.  RSA/SHA-512"),
                         ("6.2.  RSA/SHA-512", "7.  IANA Considerations")] {
        let (private, zone_text) = split_example(&between(&text, start, end));
        check_example(&private, &zone_text, true);
    }
}

#[test]
fn test_rfc_6605_ecdsa() {
    let text = rfc(6605);
    for (start, end) in [("6.1.  P-256 Example", "6.2.  P-384 Example"),
                         ("6.2.  P-384 Example", "7.  IANA Considerations")] {
        let (private, zone_text) = split_example(&between(&text, start, end));
        check_example(&private, &zone_text, false);
    }
}

/// Records from the lines of `text` that hold them, the way
/// `split_example` finds them, for a section with no private key.
fn example_records(text: &str) -> Vec<Record> {
    let (_, zone_text) = split_example(&format!("Private-key-format: none\n\n{text}"));
    records(&zone_text)
}

fn check_signature(dnskey: &Record, sig_record: &Record, set: &[Record]) -> Rrsig {
    let dnskey = Dnskey::parse(&dnskey.rdata).unwrap();
    let sig = Rrsig::parse(&sig_record.rdata).unwrap();
    let algorithm = keys::algorithm(sig.algorithm).unwrap();
    let data = sign::signed_data(&sig, set).unwrap();
    assert!(keys::verify(algorithm, &dnskey.public_key, &data, &sig.signature).unwrap(),
            "{} over {}", algorithm.mnemonic, rr::type_name(sig.type_covered));
    sig
}

#[test]
fn test_rfc_5933_gost_r_34_10_2001() {
    let text = rfc(5933);
    let section = between(&text, "2.2.  GOST DNSKEY RR Example", "3.  RRSIG Resource Records");
    let private = between(&section, "Private-key-format", "The following DNSKEY RR");
    let private = private.replace("\n          ", "");
    let key = Key::from_private_file(&private).unwrap();
    let dnskey = &example_records(&section)[0];
    assert_eq!(key.public_key().unwrap(), Dnskey::parse(&dnskey.rdata).unwrap().public_key);
    assert_eq!(keys::key_tag(&dnskey.rdata), 59732);

    let signed = example_records(&between(&text, "3.1.  RRSIG RR Example", "Note: The ECC-GOST"));
    let sig = check_signature(dnskey, &signed[1], &signed[..1]);
    assert_eq!(sig.key_tag, 59732);

    let ds_section = example_records(&between(&text, "4.1.  DS RR Example", "5.  Deployment"));
    let (ksk, ds) = (&ds_section[0], &ds_section[1]);
    assert_eq!(keys::key_tag(&ksk.rdata), 40692);
    assert_eq!(keys::ds_digest(&ksk.owner, &ksk.rdata, 3).unwrap(), ds.rdata[4..]);
}

/// GOST R 34.10-2012 with the nonce the document gives, which makes the
/// signature reproducible: `s = r*d + k*e mod q` with `r` the x of `kG`
/// and `e` the digest read little endian (RFC 7091 section 6.1).
fn gost_sign_with_nonce(curve_name: &str, d: &[u8], digest: &[u8], k: &[u8]) -> Vec<u8> {
    use allcrypt::bignum::BigUint;
    let curve = allcrypt::ec::curves::by_name(curve_name).unwrap();
    let k = BigUint::from_bytes_be(k);
    let d = BigUint::from_bytes_be(d);
    let mut le = digest.to_vec();
    le.reverse();
    let e = BigUint::from_bytes_be(&le).rem(&curve.n).unwrap();
    let r = curve.scalar_mul(&curve.g, &k).x().unwrap().rem(&curve.n).unwrap();
    let s = r.mod_mul(&d, &curve.n).unwrap().mod_add(&k.mod_mul(&e, &curve.n).unwrap(), &curve.n)
        .unwrap();
    let mut out = s.to_bytes_be_padded(32).unwrap();
    out.extend(r.to_bytes_be_padded(32).unwrap());
    out
}

#[test]
fn test_rfc_9558_gost_r_34_10_2012() {
    let text = rfc(9558);
    let section = between(&text, "2.2.  GOST DNSKEY RR Example", "3.  RRSIG Resource Records");
    let private = between(&section, "Private-key-format", "The following DNSKEY RR");
    let private = private.replace("\n            ", "");
    let key = Key::from_private_file(&private).unwrap();
    let dnskey = &example_records(&section)[0];
    assert_eq!(key.public_key().unwrap(), Dnskey::parse(&dnskey.rdata).unwrap().public_key);
    assert_eq!(keys::key_tag(&dnskey.rdata), 47355);

    let rrsig_section = between(&text, "3.1.  RRSIG RR Example", "4.  DS Resource Records");
    let signed = example_records(&rrsig_section);
    let sig = check_signature(dnskey, &signed[1], &signed[..1]);

    // The document's k, and signing again with it gives its bytes.
    let k_line = rrsig_section.lines().find(|l| l.trim_start().starts_with("k = ")).unwrap();
    let k = rr::unhex(&format!("0{}", k_line.trim_start()[4..].trim())).unwrap();
    let data = sign::signed_data(&sig, &signed[..1]).unwrap();
    let mut hash = allcrypt::api::AnyHash::new("streebog256").unwrap();
    hash.update(&data);
    let digest = hash.digest();
    let keys::PrivateKey::Ec { key: ec, .. } = &key.private else { panic!("an EC key") };
    assert_eq!(gost_sign_with_nonce("gost256-tc26-a", &ec.private_bytes().unwrap(), &digest, &k),
               sig.signature);

    let ds_section = example_records(&between(&text, "4.1.  DS RR Example", "5.  Operational"));
    let (ksk, ds) = (&ds_section[0], &ds_section[1]);
    assert_eq!(keys::key_tag(&ksk.rdata), 29468);
    assert_eq!(keys::ds_digest(&ksk.owner, &ksk.rdata, 5).unwrap(), ds.rdata[4..]);
}

#[test]
fn test_rfc_9563_sm2() {
    let text = rfc(9563);
    // Two records are broken over lines before their parenthesis opens,
    // which no master file reader accepts; they are joined here.
    let section = between(&text, "6.  Example", "7.  IANA Considerations")
        .replace("NSEC3  1 1 10\n       AABBCCDD (", "NSEC3  1 1 10 AABBCCDD (")
        .replace("NSEC3 17 2\n       3600 (", "NSEC3 17 2 3600 (");
    let (private, zone_text) = split_example(&section);
    let key = Key::from_private_file(&private).unwrap();
    let all = records(&zone_text);
    let dnskey = &of_type(&all, rr::DNSKEY)[0];
    assert_eq!(keys::key_tag(&dnskey.rdata), 65042);

    // The private key is not the DNSKEY's: it is the key-signing key the
    // DS names, tag 27215, whose DNSKEY the example leaves out. Built from
    // the private key with the SEP flag, it has the DS's tag. The DS's
    // digest is not SM3 (nor SHA-256) of that key's owner and RDATA,
    // so only the tag is checked; RFC 4509's construction is pinned by
    // the SHA-256 and SHA-384 examples, and SM3 by its own vectors.
    let ksk = Dnskey { flags: rr::ZONE_KEY | rr::SEP, protocol: 3, algorithm: 17,
                       public_key: key.public_key().unwrap() }.to_rdata();
    let ds = &of_type(&all, rr::DS)[0];
    assert_eq!(keys::key_tag(&ksk), 27215);
    assert_eq!(u16::from_be_bytes([ds.rdata[0], ds.rdata[1]]), 27215);
    assert_ne!(keys::ds_digest(&ds.owner, &ksk, 6).unwrap(), ds.rdata[4..]);

    // Of the three RRSIGs, the NSEC3 one is checkable: the DNSKEY RRset it
    // would cover includes the key-signing key the example omits, and the
    // NSEC3PARAM one is 27 bytes where SM2's is 64. The NSEC3 RRSIG
    // verifies with GB/T 32918's default identity.
    let sigs = of_type(&all, rr::RRSIG);
    let nsec3_sig = sigs.iter().find(|r| r.rdata[..2] == rr::NSEC3.to_be_bytes()).unwrap();
    check_signature(dnskey, nsec3_sig, &of_type(&all, rr::NSEC3));
    let truncated = sigs.iter().find(|r| r.rdata[..2] == rr::NSEC3PARAM.to_be_bytes()).unwrap();
    assert_eq!(Rrsig::parse(&truncated.rdata).unwrap().signature.len(), 27);
}

/// A zone printed in an appendix, from its SOA line to `end`.
fn appendix_zone(number: u32, soa: &str, end: &str) -> Vec<Record> {
    let text = rfc(number);
    let zone_text = between(&text, soa, end);
    zone::parse(&zone_text, &Name::parse("example.", None).unwrap()).unwrap()
}

fn assert_good(report: &sign::Report) {
    assert!(report.problems.is_empty(), "{:#?}", report.problems);
    assert_eq!(report.signatures, report.valid);
}

/// RFC 4035 appendix A: a whole zone signed with RSASHA1 and NSEC, with a
/// secure and an insecure delegation, glue, and a wildcard.
#[test]
fn test_rfc_4035_appendix_a() {
    let records = appendix_zone(4035, "example.       3600 IN SOA", "The apex DNSKEY set");
    let report = sign::verify_zone(records.clone(), rr::parse_time("20040420000000").unwrap())
        .unwrap();
    assert_good(&report);
    assert_eq!(report.denial, "NSEC");
    assert!(report.valid > 20, "{report:?}");

    // Outside the window, every signature is refused for it.
    let late = sign::verify_zone(records, rr::parse_time("20040601000000").unwrap()).unwrap();
    assert!(late.problems.iter().all(|p| p.contains("expired") || p.contains("no valid")));
    assert_eq!(late.valid, 0);
}

/// RFC 5155 appendix A: the same shape of zone under NSEC3 with opt-out,
/// and the hashes of its owner names, which the appendix gives as test
/// vectors.
#[test]
fn test_rfc_5155_appendix_a() {
    let text = rfc(5155);
    let listed = between(&text, "; H(example)", "example. 3600  IN SOA");
    let mut checked = 0;
    // One entry is too long for a line and continues on the next.
    let mut joined = String::new();
    for line in listed.lines() {
        let line = line.trim();
        match line.strip_prefix(';').map(str::trim_start) {
            Some(rest) if rest.starts_with('=') => joined.push_str(rest),
            _ => {
                joined.push('\n');
                joined.push_str(line);
            }
        }
    }
    for line in joined.lines() {
        let Some(rest) = line.trim().strip_prefix("; H(") else { continue };
        let (name, hash) = rest.split_once(')').unwrap();
        let hash = hash.trim().trim_start_matches('=').trim();
        let name = Name::parse(&format!("{name}."), None).unwrap();
        let ours = keys::nsec3_hash(&name, 1, &rr::unhex("aabbccdd").unwrap(), 12).unwrap();
        assert_eq!(rr::base32hex(&ours).to_ascii_lowercase(), hash, "H({name})");
        checked += 1;
    }
    assert_eq!(checked, 12);

    let records = appendix_zone(5155, "example. 3600  IN SOA", "Appendix B.");
    let report = sign::verify_zone(records, rr::parse_time("20100101000000").unwrap()).unwrap();
    assert_good(&report);
    assert_eq!(report.denial, "NSEC3");
}

/// RFC 4034 section 5.4 and RFC 4509 section 2.3: one DNSKEY, its key tag,
/// and its DS under SHA-1 and SHA-256.
#[test]
fn test_rfc_4034_and_4509_ds() {
    for (number, start, end) in [(4034, "5.4.  DS RR Example", "The first four text fields"),
                                 (4509, "2.3.  Example DS Record", "3.  Implementation")] {
        let text = rfc(number);
        let all = example_records(&between(&text, start, end));
        let (dnskey, ds) = (&of_type(&all, rr::DNSKEY)[0], &of_type(&all, rr::DS)[0]);
        assert_eq!(keys::key_tag(&dnskey.rdata), 60485);
        assert_eq!(u16::from_be_bytes([ds.rdata[0], ds.rdata[1]]), 60485);
        assert_eq!(keys::ds_digest(&ds.owner, &dnskey.rdata, ds.rdata[3]).unwrap(),
                   ds.rdata[4..], "RFC {number}");
    }
}

/// A zone with a secure and an insecure delegation, glue, a wildcard
/// and an empty non-terminal.
const SHAPES: &str = "$TTL 3600\n\
    @ SOA ns1 hostmaster 1 7200 3600 1209600 300\n\
    @ NS ns1\n\
    @ MX 10 mail\n\
    ns1 A 192.0.2.1\n\
    mail AAAA 2001:db8::25\n\
    *.wild TXT \"any\"\n\
    deep.below.empty A 192.0.2.7\n\
    sub NS ns.sub\n\
    ns.sub A 192.0.2.53\n\
    secure NS ns.secure\n\
    secure DS 12345 13 2 0102030405060708091011121314151617181920212223242526272829303132\n";

const SMALL: &str = "$TTL 3600\n@ SOA ns1 hostmaster 1 7200 3600 1209600 300\n\
                     @ NS ns1\nns1 A 192.0.2.1\n";

/// RSA and DSA keys python-cryptography made, with the algorithm line
/// rewritten: generating them in a debug build takes most of a minute,
/// and `test_generated_rsa_and_dsa_keys` covers generation.
fn recorded_key(algorithm: keys::Algorithm, n: u32) -> Key {
    let label = if algorithm.family == keys::Family::Rsa { "rsa" } else { "dsa" };
    let path = fixtures::dir().join("dnssec").join(format!("{label}-{n}.private"));
    let text = std::fs::read_to_string(path).unwrap();
    let line = text.lines().find(|l| l.starts_with("Algorithm:")).unwrap();
    Key::from_private_file(&text.replace(line, &format!("Algorithm: {} ({})", algorithm.number,
                                                       algorithm.mnemonic))).unwrap()
}

/// Sign, check, check again with one record changed, and read the text
/// form back.
fn round_trip(text: &str, keys: &[(Key, u16)], nsec3: Option<Nsec3Param>, label: &str) {
    let origin = Name::parse("example.", None).unwrap();
    let inception = rr::parse_time("20260101000000").unwrap();
    let options = Options { inception, expiration: inception + 86400 * 30, nsec3 };
    let denial = if options.nsec3.is_some() { "NSEC3" } else { "NSEC" };
    let signed = sign::sign_zone(zone::parse(text, &origin).unwrap(), keys, &options).unwrap();
    let report = sign::verify_zone(signed.clone(), inception + 60).unwrap();
    assert_good(&report);
    assert_eq!(report.denial, denial, "{label}");

    let mut tampered = signed.clone();
    let i = tampered.iter().position(|r| r.rtype == rr::A).unwrap();
    tampered[i].rdata[3] ^= 1;
    let report = sign::verify_zone(tampered, inception + 60).unwrap();
    assert!(report.problems.iter().any(|p| p.contains("does not verify")),
            "{label} {:?}", report.problems);

    let text: String = signed.iter().map(|r| r.to_text() + "\n").collect();
    assert_eq!(zone::parse(&text, &origin).unwrap(), signed, "{label}");
}

/// Every algorithm: keys made (RSA and DSA, read), written to BIND's
/// file and read back, and a small zone signed and checked.
#[test]
fn test_sign_and_verify_every_algorithm() {
    for algorithm in keys::ALGORITHMS {
        let (ksk, zsk) = match algorithm.family {
            keys::Family::Rsa | keys::Family::Dsa =>
                (recorded_key(algorithm, 1), recorded_key(algorithm, 2)),
            _ => (Key::generate(algorithm, 0).unwrap(), Key::generate(algorithm, 0).unwrap()),
        };
        let reread = Key::from_private_file(&ksk.to_private_file().unwrap()).unwrap();
        assert_eq!(reread.public_key().unwrap(), ksk.public_key().unwrap(),
                   "{} private key file", algorithm.mnemonic);
        round_trip(SMALL, &[(reread, rr::ZONE_KEY | rr::SEP), (zsk, rr::ZONE_KEY)], None,
                   algorithm.mnemonic);
    }
}

/// Every shape of zone, under NSEC and under NSEC3 with and without a
/// salt and iterations.
#[test]
fn test_sign_and_verify_every_shape() {
    let algorithm = keys::algorithm(8).unwrap();
    let keys = [(recorded_key(algorithm, 1), rr::ZONE_KEY | rr::SEP),
                (recorded_key(algorithm, 2), rr::ZONE_KEY)];
    round_trip(SHAPES, &keys, None, "NSEC");
    for (salt, iterations) in [(vec![], 0), (vec![0xab, 0xcd], 5)] {
        round_trip(SHAPES, &keys, Some(Nsec3Param { hash_algorithm: 1, flags: 0, iterations,
                                                    salt }), "NSEC3");
    }
    // One key signs everything.
    round_trip(SHAPES, &keys[1..], None, "one key");
}

// ------------------------------------------------- dnspython, replayed --

const RECORDED_NOW: u32 = 1767225600 + 3600;

/// Zones dnspython's `sign_zone` signed, one per algorithm it has.
#[test]
fn test_zones_dnspython_signed() {
    let dir = fixtures::dir().join("dnssec");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("zone") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let records = zone::parse(&text, &Name::parse("example.", None).unwrap()).unwrap();
        let report = sign::verify_zone(records.clone(), RECORDED_NOW).unwrap();
        assert!(report.problems.is_empty(), "{path:?}: {:#?}", report.problems);
        assert_eq!(report.valid, 21, "{path:?}");

        // One bit of one signature changed is caught.
        let mut tampered = records;
        let i = tampered.iter().position(|r| r.rtype == rr::RRSIG).unwrap();
        *tampered[i].rdata.last_mut().unwrap() ^= 1;
        assert!(!sign::verify_zone(tampered, RECORDED_NOW).unwrap().problems.is_empty());
        seen += 1;
    }
    assert_eq!(seen, 11);
}

#[test]
fn test_ds_and_key_tags_dnspython_computed() {
    let records = fixtures::records("dnssec/dnssec.vec", "ds");
    assert_eq!(records.len(), 66);
    for record in records {
        let f = |k| fixtures::field(&record, k);
        let owner = Name::parse(f("owner"), None).unwrap();
        let dnskey = base64::decode(f("dnskey")).unwrap();
        assert_eq!(keys::key_tag(&dnskey).to_string(), f("tag"), "{}", f("name"));
        let digest = keys::ds_digest(&owner, &dnskey, f("digest-type").parse().unwrap()).unwrap();
        assert_eq!(fixtures::hex(&digest), f("digest"), "{}", f("name"));
    }
}

#[test]
fn test_nsec3_hashes_dnspython_computed() {
    let records = fixtures::records("dnssec/dnssec.vec", "nsec3");
    assert_eq!(records.len(), 40);
    for record in records {
        let f = |k| fixtures::field(&record, k);
        let name = Name::parse(f("name"), None).unwrap();
        let salt = if f("salt") == "-" { Vec::new() } else { fixtures::unhex(f("salt")) };
        let hash = keys::nsec3_hash(&name, 1, &salt, f("iterations").parse().unwrap()).unwrap();
        assert_eq!(rr::base32hex(&hash), f("hash"), "{}", f("name"));
    }
}

/// Generating RSA and DSA keys and signing with them: ignored, because a
/// debug build takes about 50 seconds (release, under 2). Run with
/// `cargo test --release --example dnssec -- --ignored`.
#[test]
#[ignore]
fn test_generated_rsa_and_dsa_keys() {
    for number in [1, 3, 5, 6, 7, 8, 10] {
        let algorithm = keys::algorithm(number).unwrap();
        let key = Key::generate(algorithm, 1024).unwrap();
        let reread = Key::from_private_file(&key.to_private_file().unwrap()).unwrap();
        assert_eq!(reread.public_key().unwrap(), key.public_key().unwrap());
        let signature = reread.sign(b"data").unwrap();
        assert!(keys::verify(algorithm, &key.public_key().unwrap(), b"data", &signature)
            .unwrap());
    }
}

// ------------------------------------------------------ what verify refuses --

/// A zone signed with the recorded RSASHA256 keys, KSK and ZSK, and the
/// problems `verify_zone` reports for it at `now`.
fn signed_shapes(nsec3: Option<Nsec3Param>) -> (Vec<Record>, u32) {
    let algorithm = keys::algorithm(8).unwrap();
    let keys = [(recorded_key(algorithm, 1), rr::ZONE_KEY | rr::SEP),
                (recorded_key(algorithm, 2), rr::ZONE_KEY)];
    let inception = rr::parse_time("20260101000000").unwrap();
    let options = Options { inception, expiration: inception + 86400 * 30, nsec3 };
    let records = zone::parse(SHAPES, &Name::parse("example.", None).unwrap()).unwrap();
    (sign::sign_zone(records, &keys, &options).unwrap(), inception + 60)
}

fn problems(records: Vec<Record>, now: u32) -> Vec<String> {
    sign::verify_zone(records, now).unwrap().problems
}

fn has(problems: &[String], text: &str) -> bool {
    problems.iter().any(|p| p.contains(text))
}

fn rrsig_mut<'a>(zone: &'a mut [Record], owner: &str, covered: u16) -> &'a mut Record {
    zone.iter_mut().find(|r| r.rtype == rr::RRSIG && r.owner.to_string() == owner
                         && r.rdata[..2] == covered.to_be_bytes()).unwrap()
}

fn edit_rrsig(record: &mut Record, change: impl FnOnce(&mut Rrsig)) {
    let mut sig = Rrsig::parse(&record.rdata).unwrap();
    change(&mut sig);
    record.rdata = sig.to_rdata();
}

#[test]
fn test_the_signing_roles() {
    let (zone, _) = signed_shapes(None);
    let tag = |n: u32| keys::key_tag(&Dnskey { flags: if n == 1 { 257 } else { 256 },
        protocol: 3, algorithm: 8,
        public_key: recorded_key(keys::algorithm(8).unwrap(), n).public_key().unwrap(),
    }.to_rdata());
    for sig in zone.iter().filter(|r| r.rtype == rr::RRSIG) {
        let rrsig = Rrsig::parse(&sig.rdata).unwrap();
        let expected = if rrsig.type_covered == rr::DNSKEY { tag(1) } else { tag(2) };
        assert_eq!(rrsig.key_tag, expected, "{}", sig.to_text());
    }
    // RFC 9077: the lesser of the SOA's minimum (300) and its TTL.
    let low_soa = SHAPES.replace("@ SOA", "@ 120 SOA");
    let keys = [(recorded_key(keys::algorithm(8).unwrap(), 2), rr::ZONE_KEY)];
    let options = Options { inception: 0, expiration: u32::MAX / 2, nsec3: None };
    let signed = sign::sign_zone(zone::parse(&low_soa, &Name::parse("example.", None).unwrap())
                                     .unwrap(), &keys, &options).unwrap();
    assert!(signed.iter().filter(|r| r.rtype == rr::NSEC).all(|r| r.ttl == 120));
}

#[test]
fn test_what_verify_refuses_in_signatures() {
    let (zone, now) = signed_shapes(None);
    assert!(problems(zone.clone(), now).is_empty());

    // Before the inception, after the expiration.
    assert!(has(&problems(zone.clone(), now - 120), "not yet valid"));
    assert!(has(&problems(zone.clone(), now + 86400 * 31), "expired"));

    // A record whose TTL fell after signing still verifies, under the
    // Original TTL; one that rose does not.
    let mut lower = zone.clone();
    for r in lower.iter_mut().filter(|r| r.rtype == rr::MX) {
        r.ttl = 60;
    }
    assert!(problems(lower, now).is_empty());
    let mut higher = zone.clone();
    for r in higher.iter_mut().filter(|r| r.rtype == rr::MX) {
        r.ttl = 7200;
    }
    assert!(has(&problems(higher, now), "above the original"));

    // A label count beyond the owner's, a signer that is not the zone.
    let mut labels = zone.clone();
    edit_rrsig(rrsig_mut(&mut labels, "ns1.example.", rr::A), |s| s.labels = 3);
    assert!(has(&problems(labels, now), "more labels than the owner has"));
    let mut signer = zone.clone();
    edit_rrsig(rrsig_mut(&mut signer, "ns1.example.", rr::A),
               |s| s.signer = Name::parse("other.", None).unwrap());
    assert!(has(&problems(signer, now), "signed by other."));

    // The signer written in capitals is the same name: the signed data
    // lowercases it.
    let mut capitals = zone.clone();
    for r in capitals.iter_mut().filter(|r| r.rtype == rr::RRSIG) {
        edit_rrsig(r, |s| s.signer = Name::parse("EXAMPLE.", None).unwrap());
    }
    assert!(problems(capitals, now).is_empty());

    // An RRset left with no signature by an algorithm the keys have.
    let mut unsigned = zone.clone();
    let i = unsigned.iter().position(|r| r.rtype == rr::RRSIG && r.owner.to_string()
                                     == "mail.example." && r.rdata[..2] == rr::AAAA.to_be_bytes())
        .unwrap();
    unsigned.remove(i);
    assert!(has(&problems(unsigned, now), "no valid signature by algorithm 8"));
}

#[test]
fn test_what_verify_refuses_in_an_nsec_chain() {
    let (zone, now) = signed_shapes(None);
    let origin = Name::parse("example.", None).unwrap();
    let nsec_at = |zone: &mut Vec<Record>, owner: &str| -> usize {
        zone.iter().position(|r| r.rtype == rr::NSEC && r.owner.to_string() == owner).unwrap()
    };
    let mut next = zone.clone();
    let i = nsec_at(&mut next, "ns1.example.");
    let (_, types) = rr::parse_nsec(&next[i].rdata).unwrap();
    next[i].rdata = rr::nsec_rdata(&Name::parse("zz", Some(&origin)).unwrap(), &types);
    assert!(has(&problems(next, now), "NSEC names zz.example. next"));

    let mut bits = zone.clone();
    let i = nsec_at(&mut bits, "ns1.example.");
    let (next_name, mut types) = rr::parse_nsec(&bits[i].rdata).unwrap();
    types.push(rr::MX);
    bits[i].rdata = rr::nsec_rdata(&next_name, &types);
    assert!(has(&problems(bits, now), "ns1.example.: NSEC lists"));
}

#[test]
fn test_what_verify_refuses_in_an_nsec3_chain() {
    let param = Nsec3Param { hash_algorithm: 1, flags: 0, iterations: 2, salt: vec![1, 2] };
    let (zone, now) = signed_shapes(Some(param));
    assert!(problems(zone.clone(), now).is_empty());
    let first = zone.iter().position(|r| r.rtype == rr::NSEC3).unwrap();

    let mut next = zone.clone();
    let mut record = Nsec3::parse(&next[first].rdata).unwrap();
    record.next_hashed[0] ^= 1;
    next[first].rdata = record.to_rdata();
    assert!(has(&problems(next, now), "the next hash is not the next owner"));

    let mut bits = zone.clone();
    let mut record = Nsec3::parse(&bits[first].rdata).unwrap();
    record.types.push(rr::SRV);
    bits[first].rdata = record.to_rdata();
    assert!(has(&problems(bits, now), "lists"));

    // A name's NSEC3 removed: the name has none, and the chain no longer
    // closes over it.
    let mut missing = zone.clone();
    missing.remove(first);
    let found = problems(missing, now);
    assert!(has(&found, ": no NSEC3 ("), "{found:?}");

    // The unsigned delegation is in the chain, as it must be without
    // opt-out; with its NSEC3 gone and opt-out off, that is a problem.
    let insecure = keys::nsec3_hash(&Name::parse("sub.example.", None).unwrap(), 1, &[1, 2], 2)
        .unwrap();
    let label = rr::base32hex(&insecure).to_ascii_lowercase();
    let mut gone = zone.clone();
    gone.retain(|r| !(r.rtype == rr::NSEC3 && r.owner.to_string().starts_with(&label)));
    assert!(has(&problems(gone, now), "sub.example.: no NSEC3"));
}

#[test]
fn test_malformed_keys_and_signatures() {
    for number in [8, 3, 13, 12, 17] {
        let algorithm = keys::algorithm(number).unwrap();
        let key = if matches!(number, 8 | 3) { recorded_key(algorithm, 1) }
                  else { Key::generate(algorithm, 0).unwrap() };
        let public = key.public_key().unwrap();
        let signature = key.sign(b"data").unwrap();
        assert!(keys::verify(algorithm, &public, b"data", &signature).unwrap());
        // A signature of the wrong length is a signature that does not
        // verify, not an error.
        for wrong in [&signature[1..], &[signature.as_slice(), &[0]].concat()[..]] {
            assert!(!keys::verify(algorithm, &public, b"data", wrong).unwrap(),
                    "{}", algorithm.mnemonic);
        }
    }
    // A DSA key whose length is not what its T says.
    let dsa = keys::algorithm(3).unwrap();
    let public = recorded_key(dsa, 1).public_key().unwrap();
    for len in [public.len() - 1, 30] {
        let reason = keys::verify(dsa, &public[..len], b"", &[0; 41]).unwrap_err();
        assert!(reason.contains("for T ="), "{reason}");
    }
}

/// RFC 4034 section 5.1.4: the DS digest is over the owner in canonical
/// form, so the case it is written in does not change it.
#[test]
fn test_ds_owner_case() {
    let text = rfc(4034);
    let all = example_records(&between(&text, "5.4.  DS RR Example", "The first four text"));
    let dnskey = &of_type(&all, rr::DNSKEY)[0];
    let upper = Name::parse("DSKEY.Example.COM.", None).unwrap();
    assert_eq!(keys::ds_digest(&upper, &dnskey.rdata, 1).unwrap(),
               keys::ds_digest(&dnskey.owner, &dnskey.rdata, 1).unwrap());
}

#[test]
fn test_a_type_bit_map_out_of_order_is_refused() {
    // Window 4 (type 1234) before window 0 (A): each window is well
    // formed, and RFC 4034 section 4.1.2 requires increasing order.
    let bits = [rr::write_bitmap(&[1234]), rr::write_bitmap(&[rr::A])].concat();
    assert!(rr::read_bitmap(&bits).unwrap_err().contains("out of order"));
    let bits = [rr::write_bitmap(&[rr::A]), rr::write_bitmap(&[rr::MX])].concat();
    assert!(rr::read_bitmap(&bits).unwrap_err().contains("out of order"));
}
