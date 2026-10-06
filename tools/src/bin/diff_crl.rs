// CRLs built by this library, with its verdict on each, for comparison
// against `openssl verify -crl_check`. Verified by scripts/diff_check.py.
//
// Two things get checked at once and neither is enough alone:
//
//   * **our encoder against their parser.** A CRL nobody else can read is
//     not a CRL, and our writer and reader were written together, so a
//     round trip through both agrees with itself whatever it got wrong.
//   * **our verdict against theirs.** `crl::check` has a three-valued
//     answer with a dozen ways to reach each value, and every wrong one
//     fails in the same direction - a revoked certificate looking clean.
//     OpenSSL is a second opinion written by somebody else from the same
//     RFC.
//
// ## One CRL per row, and why
//
// `openssl verify -CRLfile` uses only the **first** CRL it finds for an
// issuer. Two complete CRLs where the second revokes gives "OK"; swap
// them and it gives "certificate revoked". So any row supplying more
// than one CRL would be compared against a verdict formed from half the
// input, and would agree or disagree for reasons that have nothing to do
// with whether we are right.
//
// Every row here therefore carries exactly one CRL, or none. What that
// leaves out is covered in `src/x509/crl.rs`'s own tests and nowhere
// else, which `docs/pitfalls.md` records:
//
//   * combining a delta CRL with its base, including `removeFromCRL`;
//   * a complete CRL alongside a partitioned one;
//   * `onlySomeReasons`, which the version of python-cryptography here
//     cannot even encode;
//   * indirect CRLs and the `certificateIssuer` entry extension, whose
//     carry-forward rule OpenSSL implements but which needs two entries
//     in one list and a second issuer to be worth testing.
//
// A delta CRL supplied *alone* is in the corpus, because that is the
// dangerous case and both sides refuse it.
//
// Row format:
//
//   row <revoked|clean|unknown> <root> <leaf> <crl|->
//
// all three hex DER. The checker maps OpenSSL's exit codes onto the same
// three words and fails on any code it has not been taught, rather than
// folding an unexpected one into "unknown" - which is where a row that
// proves nothing would come from.
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve};
use allcrypt::asn1::encode_oid;
use allcrypt::x509::builder::{key_usage, CertificateBuilder, CrlBuilder,
                              IssuingDistributionPointFields, RevocationEntry,
                              SanEntry, SigningKey, SubjectKey};
use allcrypt::x509::crl::{check, CertificateList, Status};
use allcrypt::x509::verify::Policy;
use allcrypt::x509::{oids, Certificate};

/// The instant every row is judged at, on both sides.
const NOW: i64 = 1_700_000_000;         // 2023-11-14

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_string(); }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct Key { curve: Curve, private: BigUint, point: Vec<u8> }

impl Key {
    fn new() -> Key {
        let curve = curves::p256();
        let (private, public) = curve.generate_key_pair().unwrap();
        let point = curve.encode_point(&public, false).unwrap();
        Key { curve, private, point }
    }
    fn signing(&self) -> SigningKey<'_> {
        SigningKey::Ec { curve: &self.curve, private: &self.private }
    }
    fn subject(&self) -> SubjectKey<'_> {
        SubjectKey::Ec { curve: &self.curve, point: &self.point }
    }
}

fn root_certificate(key: &Key, common_name: &str) -> Vec<u8> {
    let mut builder = CertificateBuilder::new(common_name, key.subject());
    builder.serial = vec![1];
    builder.issuer = vec![(oids::COMMON_NAME, common_name.to_string())];
    builder.subject = vec![(oids::COMMON_NAME, common_name.to_string())];
    builder.not_before = "20200101000000Z";
    builder.not_after = "20400101000000Z";
    builder.is_ca = Some((true, None));
    builder.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
    builder.sign(&key.signing()).unwrap()
}

fn leaf_certificate(key: &Key, signer: &Key, issuer: &str, serial: &[u8]) -> Vec<u8> {
    let mut builder = CertificateBuilder::new("leaf.test", key.subject());
    builder.serial = serial.to_vec();
    builder.issuer = vec![(oids::COMMON_NAME, issuer.to_string())];
    builder.subject = vec![(oids::COMMON_NAME, "leaf.test".to_string())];
    builder.not_before = "20200101000000Z";
    builder.not_after = "20400101000000Z";
    builder.is_ca = Some((false, None));
    builder.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
    builder.sans = vec![SanEntry::Dns("leaf.test".to_string())];
    builder.sign(&signer.signing()).unwrap()
}

/// Our verdict, in the corpus's three words.
fn verdict(root: &[u8], leaf: &[u8], crl: Option<&[u8]>) -> &'static str {
    let root_certificate = Certificate::parse(root).unwrap();
    let leaf_certificate = Certificate::parse(leaf).unwrap();
    // A CRL that will not even parse is no evidence at all, which is
    // `Unknown` - the same as one that parses and cannot be used.
    let parsed: Vec<CertificateList<'_>> = match crl {
        Some(der) => match CertificateList::parse(der) {
            Ok(list) => vec![list],
            Err(_) => vec![],
        },
        None => vec![],
    };
    match check(&leaf_certificate, &root_certificate, &parsed,
                &Policy::at(NOW), NOW) {
        Status::Revoked { .. } => "revoked",
        Status::NotRevoked => "clean",
        Status::Unknown(_) => "unknown",
    }
}

fn emit(root: &[u8], leaf: &[u8], crl: Option<&[u8]>) {
    println!("row {} {} {} {}", verdict(root, leaf, crl),
             hex(root), hex(leaf), crl.map_or("-".to_string(), hex));
}

fn main() {
    let ca_key = Key::new();
    let leaf_key = Key::new();
    let other_key = Key::new();

    let root = root_certificate(&ca_key, "Diff CA");
    let leaf = leaf_certificate(&leaf_key, &ca_key, "Diff CA", &[0x2a]);

    let mut rows = 0usize;
    let sign = |configure: &dyn Fn(&mut CrlBuilder<'_>)| -> Vec<u8> {
        let mut builder = CrlBuilder::new("Diff CA");
        configure(&mut builder);
        builder.sign(&ca_key.signing()).unwrap()
    };

    // ------------------------------------------------------ the basics ---
    //
    // Clean, revoked, and revoked-but-somebody-else. The third is what
    // separates "the serial matched" from "the list was not empty".
    emit(&root, &leaf, Some(&sign(&|_| {})));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.revoked = vec![RevocationEntry::new(&[0x2a])];
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.revoked = vec![RevocationEntry::new(&[0x2b]),
                         RevocationEntry::new(&[0x01]),
                         RevocationEntry::new(&[0x7f])];
    })));
    // No CRL at all, which must not read as clean on either side.
    emit(&root, &leaf, None);
    rows += 4;

    // ------------------------------------------------- every reason code ---
    //
    // A reason is not supposed to change the verdict, only the
    // explanation - so these rows are a check that neither side has a
    // reason it treats specially. `removeFromCRL` is deliberately
    // included: it is only legal in a delta, and in a complete CRL both
    // sides should still see a revocation.
    for reason in [0u32, 1, 2, 3, 4, 5, 6, 8, 9, 10] {
        emit(&root, &leaf, Some(&sign(&|b| {
            let mut entry = RevocationEntry::new(&[0x2a]);
            entry.reason = Some(reason);
            b.revoked = vec![entry];
        })));
        rows += 1;
    }

    // --------------------------------------------------------- serials ---
    //
    // Serial numbers are arbitrary length and compared as the INTEGER's
    // content octets. These bracket the cases where an implementation
    // that read them as a machine integer, or that normalised leading
    // bytes, would go wrong: a serial needing a leading zero to stay
    // positive, one longer than 64 bits, and the minimum.
    for serial in [vec![0x01u8],
                   vec![0x00, 0x80],
                   vec![0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                   vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22]] {
        let this_leaf = leaf_certificate(&leaf_key, &ca_key, "Diff CA", &serial);
        // On the list.
        emit(&root, &this_leaf, Some(&sign(&|b| {
            b.revoked = vec![RevocationEntry::new(&serial)];
        })));
        // And a neighbouring serial, which must not match it. One byte
        // different in the last place is the case a truncating
        // comparison gets wrong.
        let mut neighbour = serial.clone();
        let last = neighbour.len() - 1;
        neighbour[last] ^= 0x01;
        emit(&root, &this_leaf, Some(&sign(&|b| {
            b.revoked = vec![RevocationEntry::new(&neighbour)];
        })));
        rows += 2;
    }

    // Serials that **share their trailing bytes** and are different
    // numbers. Without these the corpus cannot see a comparison that
    // truncates: every pair above differs in its last byte, so matching
    // on the last byte alone would agree with every row.
    //
    // Found by breaking `entry_for` on purpose to compare only the last
    // byte and watching all forty rows still pass.
    for (ours, theirs) in [(vec![0x01u8, 0x2a], vec![0x2au8]),
                           (vec![0x2au8], vec![0x01u8, 0x2a]),
                           (vec![0x00u8, 0xff, 0x2a], vec![0x7fu8, 0x2a]),
                           (vec![0x11u8, 0x22, 0x33], vec![0x44u8, 0x22, 0x33])] {
        let this_leaf = leaf_certificate(&leaf_key, &ca_key, "Diff CA", &ours);
        emit(&root, &this_leaf, Some(&sign(&|b| {
            b.revoked = vec![RevocationEntry::new(&theirs)];
        })));
        // And the same certificate against its own serial, so the row
        // above is not passing because nothing ever matches.
        emit(&root, &this_leaf, Some(&sign(&|b| {
            b.revoked = vec![RevocationEntry::new(&ours)];
        })));
        rows += 2;
    }

    // ---------------------------------------------------------- freshness ---
    //
    // Expired, not yet valid, and no nextUpdate at all. The third is the
    // interesting one: RFC 5280 requires conforming issuers to set it,
    // and a CRL without one never expires.
    emit(&root, &leaf, Some(&sign(&|b| {
        b.this_update = "20190101000000Z";
        b.next_update = Some("20210101000000Z");
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.this_update = "20190101000000Z";
        b.next_update = Some("20210101000000Z");
        b.revoked = vec![RevocationEntry::new(&[0x2a])];
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.this_update = "20380101000000Z";
        b.next_update = Some("20390101000000Z");
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.this_update = "20200101000000Z";
        b.next_update = None;
    })));
    rows += 4;

    // ------------------------------------------------------- the signer ---
    //
    // The right issuer name and the wrong key, which is what an attacker
    // has; and the wrong issuer name entirely. Neither may clear a
    // certificate and neither may revoke one.
    {
        let mut builder = CrlBuilder::new("Diff CA");
        builder.revoked = vec![RevocationEntry::new(&[0x2a])];
        let forged = builder.sign(&other_key.signing()).unwrap();
        emit(&root, &leaf, Some(&forged));

        let mut builder = CrlBuilder::new("Diff CA");
        let forged_empty = builder_signed(&mut builder, &other_key);
        emit(&root, &leaf, Some(&forged_empty));

        let mut builder = CrlBuilder::new("Some Other CA");
        builder.revoked = vec![RevocationEntry::new(&[0x2a])];
        let elsewhere = builder.sign(&ca_key.signing()).unwrap();
        emit(&root, &leaf, Some(&elsewhere));
        rows += 3;
    }

    // ------------------------------------------- issuingDistributionPoint ---
    //
    // A CRL scoped to end-entity certificates covers this leaf; one
    // scoped to CA certificates does not, and "does not cover you" is
    // not "you are fine". OpenSSL calls the second "different CRL
    // scope".
    emit(&root, &leaf, Some(&sign(&|b| {
        b.issuing_distribution_point = Some(IssuingDistributionPointFields {
            only_user_certs: true, ..Default::default()
        });
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.issuing_distribution_point = Some(IssuingDistributionPointFields {
            only_ca_certs: true, ..Default::default()
        });
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.issuing_distribution_point = Some(IssuingDistributionPointFields {
            only_user_certs: true, ..Default::default()
        });
        b.revoked = vec![RevocationEntry::new(&[0x2a])];
    })));
    rows += 3;

    // ------------------------------------------------- a delta CRL alone ---
    //
    // The dangerous one. A delta lists only what changed since its base,
    // so on its own it cannot show that anything is unrevoked, and an
    // implementation that read it as a complete list would call this
    // clean.
    //
    // Only the *absence* case is here. A delta that lists our serial is
    // a deliberate divergence: OpenSSL ignores a standalone delta
    // entirely and reports "unable to get certificate CRL" even when
    // the delta revokes the certificate, and we honour the revocation.
    // `src/x509/crl.rs` argues why at length. A row where we knowingly
    // differ would have to be either a permanent expected failure or a
    // reason to weaken the code, and neither belongs in a corpus -
    // `test_a_delta_alone_revokes_what_it_lists` covers it instead.
    emit(&root, &leaf, Some(&sign(&|b| {
        b.crl_number = Some(vec![5]);
        b.delta_from = Some(vec![3]);
        b.revoked = vec![RevocationEntry::new(&[0x99])];
    })));
    // An empty delta, which is the same question with nothing in the
    // list at all.
    emit(&root, &leaf, Some(&sign(&|b| {
        b.crl_number = Some(vec![5]);
        b.delta_from = Some(vec![3]);
    })));
    rows += 2;

    // ------------------------------- an unrecognised critical extension ---
    //
    // Critical means "if you do not understand this, do not use this".
    // A CRL carrying one has a scope neither side can establish.
    emit(&root, &leaf, Some(&sign(&|b| {
        b.extra_extensions = vec![
            (encode_oid("1.3.6.1.4.1.99999.7").unwrap(), true, vec![0x05, 0x00])];
    })));
    // And the same extension non-critical is ignorable, so the row above
    // is about the criticality and not about the extension.
    emit(&root, &leaf, Some(&sign(&|b| {
        b.extra_extensions = vec![
            (encode_oid("1.3.6.1.4.1.99999.7").unwrap(), false, vec![0x05, 0x00])];
    })));
    rows += 2;

    // -------------------------------------------------- an empty v1 CRL ---
    //
    // No extensions at all, so no version field: a v1 CRL, which still
    // exists and which both sides must read.
    emit(&root, &leaf, Some(&sign(&|b| {
        b.crl_number = None;
    })));
    emit(&root, &leaf, Some(&sign(&|b| {
        b.crl_number = None;
        b.revoked = vec![RevocationEntry::new(&[0x2a])];
    })));
    rows += 2;

    // ------------------------------------------ a long list of entries ---
    //
    // Enough entries that a search bug shows up, with ours in the middle
    // rather than at either end.
    {
        let mut serials: Vec<Vec<u8>> = (1u8..=60).map(|n| vec![n]).collect();
        serials.retain(|s| s != &vec![0x2a]);
        let present = serials.clone();
        emit(&root, &leaf, Some(&sign(&|b| {
            b.revoked = present.iter().map(|s| RevocationEntry::new(s)).collect();
        })));
        let mut with_ours = serials.clone();
        with_ours.insert(30, vec![0x2a]);
        emit(&root, &leaf, Some(&sign(&|b| {
            b.revoked = with_ours.iter().map(|s| RevocationEntry::new(s)).collect();
        })));
        rows += 2;
    }

    eprintln!("[diff_crl] {} rows", rows);
}

/// `CrlBuilder::sign` through a `&mut`, so the closure-free call sites
/// above read the same as the closure ones.
fn builder_signed(builder: &mut CrlBuilder<'_>, key: &Key) -> Vec<u8> {
    builder.sign(&key.signing()).unwrap()
}
