// OCSP responses built by this library, with its verdict on each, for
// comparison against `openssl ocsp`. Verified by scripts/diff_check.py.
//
// Two things at once, as with `diff_crl.rs`. Our **encoder** is checked
// by somebody else's parser - a response nobody else can read is not a
// response, and our writer and reader were written together so a round
// trip agrees with itself whatever it got wrong. And our **verdict** is
// checked against theirs, because almost every way of getting OCSP
// wrong is a way of accepting an answer about something else.
//
// ## The clock
//
// `openssl ocsp` checks thisUpdate and nextUpdate against the *current*
// time and has no flag to fix it, while our verdict is computed at a
// fixed instant so the corpus is reproducible. So every row's times are
// chosen to give the same answer at both: a fresh response runs from
// 2023 to 2033, a stale one from 2019 to 2021, and a premature one from
// 2038. Anything with a boundary between the two clocks would disagree
// for a reason that is not a bug on either side.
//
// ## What is not here
//
// **Nonces.** `openssl ocsp -respin` with no request has nothing to
// compare a nonce against and is run with `-no_nonce`, so a row about
// one would agree however we behaved. The nonce is covered by
// `src/x509/ocsp.rs`'s own tests.
//
// Row format:
//
//   row <revoked|clean|unknown> <root> <leaf> <response>
//
// all hex DER.
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve};
use allcrypt::x509::builder::{key_usage, CertificateBuilder, OcspResponseBuilder,
                              OcspSingleResponse, OcspStatus, SanEntry,
                              SigningKey, SubjectKey};
use allcrypt::x509::ocsp::{build_request, check};
use allcrypt::x509::crl::Status;
use allcrypt::x509::verify::Policy;
use allcrypt::x509::{oids, Certificate};

/// The instant our side judges at. See the note on the clock above.
const NOW: i64 = 1_700_000_000;         // 2023-11-14

fn hex(bytes: &[u8]) -> String {
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

fn root_certificate(key: &Key) -> Vec<u8> {
    let mut builder = CertificateBuilder::new("OCSP Diff CA", key.subject());
    builder.serial = vec![1];
    builder.issuer = vec![(oids::COMMON_NAME, "OCSP Diff CA".to_string())];
    builder.subject = vec![(oids::COMMON_NAME, "OCSP Diff CA".to_string())];
    builder.not_before = "20200101000000Z";
    builder.not_after = "20400101000000Z";
    builder.is_ca = Some((true, None));
    builder.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
    builder.sign(&key.signing()).unwrap()
}

fn leaf_certificate(key: &Key, signer: &Key, serial: &[u8]) -> Vec<u8> {
    let mut builder = CertificateBuilder::new("leaf.test", key.subject());
    builder.serial = serial.to_vec();
    builder.issuer = vec![(oids::COMMON_NAME, "OCSP Diff CA".to_string())];
    builder.subject = vec![(oids::COMMON_NAME, "leaf.test".to_string())];
    builder.not_before = "20200101000000Z";
    builder.not_after = "20400101000000Z";
    builder.is_ca = Some((false, None));
    builder.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
    builder.sans = vec![SanEntry::Dns("leaf.test".to_string())];
    builder.sign(&signer.signing()).unwrap()
}

/// A responder certificate the CA issues, with whichever EKUs are given.
fn responder_certificate(key: &Key, signer: &Key,
                         eku: Vec<&'static [u8]>) -> Vec<u8> {
    let mut builder = CertificateBuilder::new("OCSP Diff Responder",
                                              key.subject());
    builder.serial = vec![9];
    builder.issuer = vec![(oids::COMMON_NAME, "OCSP Diff CA".to_string())];
    builder.subject = vec![(oids::COMMON_NAME,
                            "OCSP Diff Responder".to_string())];
    builder.not_before = "20200101000000Z";
    builder.not_after = "20400101000000Z";
    builder.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
    builder.extended_key_usage = eku;
    builder.sign(&signer.signing()).unwrap()
}

fn verdict(root: &[u8], leaf: &[u8], response: &[u8]) -> &'static str {
    let issuer = Certificate::parse(root).unwrap();
    let certificate = Certificate::parse(leaf).unwrap();
    match check(&certificate, &issuer, response, None, &Policy::at(NOW), NOW) {
        Status::Revoked { .. } => "revoked",
        Status::NotRevoked => "clean",
        Status::Unknown(_) => "unknown",
    }
}

fn emit(root: &[u8], leaf: &[u8], response: &[u8]) {
    println!("row {} {} {} {}", verdict(root, leaf, response),
             hex(root), hex(leaf), hex(response));
}

fn main() {
    let ca_key = Key::new();
    let leaf_key = Key::new();
    let responder_key = Key::new();
    let stranger_key = Key::new();

    let root = root_certificate(&ca_key);
    let leaf = leaf_certificate(&leaf_key, &ca_key, &[0x2a]);

    let issuer = Certificate::parse(&root).unwrap();
    let certificate = Certificate::parse(&leaf).unwrap();

    let mut rows = 0usize;

    /// A response about `leaf`, configured then signed.
    macro_rules! response {
        ($key:expr, $status:expr, $configure:expr) => {{
            let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
            builder.responses = vec![
                OcspSingleResponse::about(&certificate, &issuer, "sha1",
                                          $status).unwrap()];
            #[allow(clippy::redundant_closure_call)]
            ($configure)(&mut builder);
            builder.sign(&($key).signing()).unwrap()
        }};
    }

    // ------------------------------------------------ the three answers ---
    emit(&root, &leaf, &response!(ca_key, OcspStatus::Good, |_: &mut _| {}));
    emit(&root, &leaf, &response!(
        ca_key, OcspStatus::Revoked("20230601000000Z", Some(1)),
        |_: &mut _| {}));
    // **unknown is not good.** A responder saying it cannot speak for
    // this certificate is not saying the certificate is fine.
    emit(&root, &leaf, &response!(ca_key, OcspStatus::Unknown,
                                  |_: &mut _| {}));
    rows += 3;

    // ------------------------------------------------ every reason code ---
    //
    // A reason changes the explanation and not the verdict, so these
    // check that neither side treats one specially.
    for reason in [0u32, 1, 2, 3, 4, 5, 6, 9, 10] {
        emit(&root, &leaf, &response!(
            ca_key, OcspStatus::Revoked("20230601000000Z", Some(reason)),
            |_: &mut _| {}));
        rows += 1;
    }
    // And a revocation with no reason at all.
    emit(&root, &leaf, &response!(
        ca_key, OcspStatus::Revoked("20230601000000Z", None), |_: &mut _| {}));
    rows += 1;

    // ------------------------------------------------ every CertID hash ---
    //
    // The responder chooses this, so all four have to work. The row
    // carries the matching **request** as well, because `openssl ocsp
    // -cert` builds its own CertID with SHA-1 and finds no answer
    // otherwise - and passing the request checks our request encoder
    // against their parser at the same time.
    for hash in ["sha1", "sha256", "sha384", "sha512"] {
        let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
        builder.responses = vec![
            OcspSingleResponse::about(&certificate, &issuer, hash,
                                      OcspStatus::Good).unwrap()];
        let response = builder.sign(&ca_key.signing()).unwrap();
        let request = build_request(&certificate, &issuer, hash, None).unwrap();
        println!("req {} {} {} {} {}", verdict(&root, &leaf, &response),
                 hex(&root), hex(&leaf), hex(&response), hex(&request));
        rows += 1;
    }

    // -------------------------------------------- every signature hash ---
    for hash in ["sha256", "sha384", "sha512"] {
        let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
        builder.hash = hash;
        builder.responses = vec![
            OcspSingleResponse::about(&certificate, &issuer, "sha1",
                                      OcspStatus::Good).unwrap()];
        emit(&root, &leaf, &builder.sign(&ca_key.signing()).unwrap());
        rows += 1;
    }

    // ---------------------------------------------------- who signed it ---
    //
    // A key the CA never delegated to, in both directions: it must not
    // clear a certificate and it must not revoke one.
    emit(&root, &leaf, &response!(stranger_key, OcspStatus::Good,
                                  |_: &mut _| {}));
    emit(&root, &leaf, &response!(
        stranger_key, OcspStatus::Revoked("20230601000000Z", Some(1)),
        |_: &mut _| {}));
    rows += 2;

    // ------------------------------------------- a delegated responder ---
    {
        let with_eku = responder_certificate(&responder_key, &ca_key,
                                             vec![oids::EKU_OCSP_SIGNING]);
        let without_eku = responder_certificate(&responder_key, &ca_key,
                                                vec![oids::EKU_SERVER_AUTH]);

        let delegated = |certificate_der: &Vec<u8>, status| {
            let mut builder = OcspResponseBuilder::new("OCSP Diff Responder");
            builder.responses = vec![
                OcspSingleResponse::about(&certificate, &issuer, "sha1",
                                          status).unwrap()];
            builder.certs = vec![certificate_der.clone()];
            builder.sign(&responder_key.signing()).unwrap()
        };

        // Properly delegated: accepted.
        emit(&root, &leaf, &delegated(&with_eku, OcspStatus::Good));
        emit(&root, &leaf, &delegated(&with_eku,
                                      OcspStatus::Revoked("20230601000000Z",
                                                          Some(1))));
        // **Without id-kp-OCSPSigning it is not a responder**, however
        // real the certificate is. This is what stops every customer of
        // a CA from answering for every other one.
        emit(&root, &leaf, &delegated(&without_eku, OcspStatus::Good));
        emit(&root, &leaf, &delegated(&without_eku,
                                      OcspStatus::Revoked("20230601000000Z",
                                                          Some(1))));
        // And a responder certificate that is not supplied at all: the
        // signature cannot be checked against anything.
        let mut builder = OcspResponseBuilder::new("OCSP Diff Responder");
        builder.responses = vec![
            OcspSingleResponse::about(&certificate, &issuer, "sha1",
                                      OcspStatus::Good).unwrap()];
        emit(&root, &leaf, &builder.sign(&responder_key.signing()).unwrap());
        rows += 5;
    }

    // ----------------------------------------- about a different certificate ---
    //
    // Signed by the real CA, and about somebody else. The serial is
    // ours and the issuer hashes are not, which is the case a check
    // comparing serials alone would get wrong.
    {
        let other_ca_key = Key::new();
        let other_root = root_certificate(&other_ca_key);
        let other_issuer = Certificate::parse(&other_root).unwrap();
        let other_leaf_der = leaf_certificate(&leaf_key, &other_ca_key, &[0x2a]);
        let other_leaf = Certificate::parse(&other_leaf_der).unwrap();

        let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
        builder.responses = vec![
            OcspSingleResponse::about(&other_leaf, &other_issuer, "sha1",
                                      OcspStatus::Good).unwrap()];
        emit(&root, &leaf, &builder.sign(&ca_key.signing()).unwrap());

        // And a plain serial mismatch under the right issuer, which is
        // the same question from the other side.
        let wrong_serial = leaf_certificate(&leaf_key, &ca_key, &[0x2b]);
        let wrong = Certificate::parse(&wrong_serial).unwrap();
        let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
        builder.responses = vec![
            OcspSingleResponse::about(&wrong, &issuer, "sha1",
                                      OcspStatus::Good).unwrap()];
        emit(&root, &leaf, &builder.sign(&ca_key.signing()).unwrap());
        rows += 2;
    }

    // ---------------------------------------- several answers in one ---
    //
    // Ours has to be picked out rather than the first one taken.
    {
        let other_serial = leaf_certificate(&leaf_key, &ca_key, &[0x7f]);
        let other = Certificate::parse(&other_serial).unwrap();

        let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
        builder.responses = vec![
            OcspSingleResponse::about(&other, &issuer, "sha1",
                                      OcspStatus::Good).unwrap(),
            OcspSingleResponse::about(
                &certificate, &issuer, "sha1",
                OcspStatus::Revoked("20230601000000Z", Some(4))).unwrap(),
        ];
        emit(&root, &leaf, &builder.sign(&ca_key.signing()).unwrap());

        // And the reverse order, so the answer is not position.
        let mut builder = OcspResponseBuilder::new("OCSP Diff CA");
        builder.responses = vec![
            OcspSingleResponse::about(
                &certificate, &issuer, "sha1",
                OcspStatus::Revoked("20230601000000Z", Some(4))).unwrap(),
            OcspSingleResponse::about(&other, &issuer, "sha1",
                                      OcspStatus::Good).unwrap(),
        ];
        emit(&root, &leaf, &builder.sign(&ca_key.signing()).unwrap());
        rows += 2;
    }

    // --------------------------------------------------------- the clock ---
    //
    // Stale and premature, both chosen to read the same way at our
    // fixed instant and at whatever the clock says when the checker
    // runs. A stale response **revokes and cannot clear**.
    for (this_update, next_update) in [("20190101000000Z", "20210101000000Z"),
                                       ("20380101000000Z", "20390101000000Z")] {
        emit(&root, &leaf, &response!(ca_key, OcspStatus::Good,
            |b: &mut OcspResponseBuilder<'_>| {
                b.responses[0].this_update = this_update;
                b.responses[0].next_update = Some(next_update);
            }));
        rows += 1;
    }
    // A *stale* response that revokes is **not** in the corpus, and
    // that is a deliberate divergence. We honour the revocation - the
    // same asymmetry as a stale CRL, and a revocation does not become
    // untrue because the answer carrying it is old - while `openssl
    // ocsp` refuses the whole response with "status expired" and finds
    // no status at all. OpenSSL's own *CRL* path reports the
    // revocation in that situation, so the inconsistency is theirs
    // rather than ours. `test_a_stale_response_revokes_but_cannot_
    // clear` covers it.

    // A response with no nextUpdate: newer information is always
    // available, and the response is usable now.
    emit(&root, &leaf, &response!(ca_key, OcspStatus::Good,
        |b: &mut OcspResponseBuilder<'_>| {
            b.responses[0].next_update = None;
        }));
    rows += 1;

    // ----------------------------------------------- the responder's id ---
    //
    // byKey rather than byName, with the real hash of the CA's key -
    // which is what a responder sends, and which OpenSSL uses to *find*
    // the signing certificate. Nothing here checks the id, because the
    // signature is what decides who signed; a row with a made-up hash
    // would therefore disagree, and it would be about OpenSSL's lookup
    // rather than about either side's correctness.
    {
        let hash = allcrypt::x509::ocsp::key_hash(&issuer, "sha1").unwrap();
        emit(&root, &leaf, &response!(ca_key, OcspStatus::Good,
            |b: &mut OcspResponseBuilder<'_>| {
                b.responder_key_hash = Some(hash.clone());
            }));
        rows += 1;
    }

    // ----------------------------------------- the unsigned error statuses ---
    //
    // Outside the signature, carrying nothing. None of them is news
    // about a certificate, and `unauthorized` in particular must not
    // read as anything.
    for status in [1u8, 2, 3, 5, 6] {
        emit(&root, &leaf, &response!(ca_key, OcspStatus::Good,
            |b: &mut OcspResponseBuilder<'_>| {
                b.response_status = status;
            }));
        rows += 1;
    }

    eprintln!("[diff_ocsp] {} rows", rows);
}
