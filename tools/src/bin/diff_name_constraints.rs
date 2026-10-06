// Name-constrained chains, with this library's verdict on each, for
// comparison against python-cryptography's path verifier. Verified by
// scripts/diff_check.py.
//
// Why this corpus exists when `src/x509/name_constraints.rs` already
// reproduces RFC 5280 4.2.1.10's worked examples: those examples and the
// implementation were both read off the same page by the same reader on
// the same afternoon. A matcher can satisfy every sentence in the RFC and
// still disagree with everything that ships, and for this extension the
// disagreement is silent in the dangerous direction - a subtree read one
// label too wide admits certificates and says nothing.
//
// python-cryptography 42 and later carry a path verifier that enforces
// name constraints (it is webpki's logic, not OpenSSL's), and it is a
// second opinion written by somebody else from the same document.
//
// ## What it can and cannot check
//
// That verifier handles **dNSName and iPAddress constraints only**. It
// ignores constraints on directoryName, rfc822Name and
// uniformResourceIdentifier - it accepts a chain carrying them whatever
// the names are. So rows for those forms would agree with us no matter
// what we did, and a row nothing can check is worse than no row: this
// corpus does not contain any. Those three matchers are pinned by the
// RFC's own examples in the module's unit tests, and by nothing else,
// which `docs/pitfalls.md` records.
//
// Every scenario appears as a **pair** - one leaf inside the subtree and
// one outside, identical in every other respect - so the checker can
// require the reference to *distinguish* them. A reference that rejected
// both (for an unrelated policy reason, of which it has several) would
// otherwise agree with our rejection and prove nothing.
//
// Row format:
//
//   chain <accept|reject> <subject> <root> <intermediate> <leaf>
//
// where <subject> is the name to verify the leaf for - a DNS name, or
// `ip:<dotted quad>` - and the three certificates are hex DER.
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, Curve};
use allcrypt::asn1::{Tag, Writer};
use allcrypt::x509::builder::{key_usage, CertificateBuilder, SanEntry,
                              SigningKey, SubjectKey};
use allcrypt::x509::{oids, Certificate};
use allcrypt::x509::verify::{verify_chain, Policy, Purpose};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

struct Key {
    curve: Curve,
    private: BigUint,
    point: Vec<u8>,
}

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

// The key identifiers used to be computed here, by hand, because the
// builder could not write them - and the reference refuses a chain
// without an authorityKeyIdentifier outright, so they had to be right.
// `CertificateBuilder::key_identifiers` does it now: a second copy of
// "the SHA-1 of the subjectPublicKey BIT STRING's contents" is a second
// chance to pick one of the three plausible readings.

/// A nameConstraints extension. `(tag number, bytes)` pairs.
fn constraints(permitted: &[(u32, Vec<u8>)], excluded: &[(u32, Vec<u8>)])
               -> (Vec<u8>, bool, Vec<u8>) {
    fn subtrees(w: &mut Writer, number: u32, list: &[(u32, Vec<u8>)]) {
        w.write_constructed(Tag::context(number, true), |w| {
            for (tag, bytes) in list {
                w.write_sequence(|w| {
                    w.write_tlv(Tag::context(*tag, *tag == 4), bytes);
                });
            }
        });
    }
    let mut writer = Writer::new();
    writer.write_sequence(|w| {
        if !permitted.is_empty() { subtrees(w, 0, permitted); }
        if !excluded.is_empty() { subtrees(w, 1, excluded); }
    });
    // Critical, which is what a conforming CA must do.
    (oids::NAME_CONSTRAINTS.to_vec(), true, writer.finish())
}

fn dns(text: &str) -> (u32, Vec<u8>) { (2, text.as_bytes().to_vec()) }
fn ip(bytes: &[u8]) -> (u32, Vec<u8>) { (7, bytes.to_vec()) }

struct Chain {
    root: Vec<u8>,
    intermediate: Vec<u8>,
    leaf: Vec<u8>,
}

/// A root, an intermediate carrying `extra`, and a leaf with `sans`.
fn build(root_key: &Key, intermediate_key: &Key, leaf_key: &Key,
         root_extra: Vec<(Vec<u8>, bool, Vec<u8>)>,
         intermediate_extra: Vec<(Vec<u8>, bool, Vec<u8>)>,
         leaf_cn: &str, sans: Vec<SanEntry>) -> Chain {
    let mut root = CertificateBuilder::new("Diff Root", root_key.subject());
    root.serial = vec![1];
    root.issuer = vec![(oids::COMMON_NAME, "Diff Root".to_string())];
    root.subject = vec![(oids::COMMON_NAME, "Diff Root".to_string())];
    root.not_before = "20200101000000Z";
    root.not_after = "20400101000000Z";
    root.is_ca = Some((true, None));
    root.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
    root.extra_extensions = root_extra;
    root.key_identifiers = true;
    let root_der = root.sign(&root_key.signing()).unwrap();

    let mut intermediate = CertificateBuilder::new("Diff Intermediate",
                                                   intermediate_key.subject());
    intermediate.serial = vec![2];
    intermediate.issuer = vec![(oids::COMMON_NAME, "Diff Root".to_string())];
    intermediate.subject = vec![(oids::COMMON_NAME,
                                 "Diff Intermediate".to_string())];
    intermediate.not_before = "20200101000000Z";
    intermediate.not_after = "20400101000000Z";
    intermediate.is_ca = Some((true, Some(0)));
    intermediate.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
    intermediate.extra_extensions = intermediate_extra;
    intermediate.key_identifiers = true;
    let intermediate_der = intermediate.sign(&root_key.signing()).unwrap();

    let mut leaf = CertificateBuilder::new(leaf_cn, leaf_key.subject());
    leaf.serial = vec![3];
    leaf.issuer = vec![(oids::COMMON_NAME, "Diff Intermediate".to_string())];
    leaf.subject = vec![(oids::COMMON_NAME, leaf_cn.to_string())];
    leaf.not_before = "20200101000000Z";
    leaf.not_after = "20400101000000Z";
    leaf.key_usage = Some(key_usage::DIGITAL_SIGNATURE);
    leaf.extended_key_usage = vec![oids::EKU_SERVER_AUTH];
    leaf.sans = sans;
    leaf.key_identifiers = true;
    let leaf_der = leaf.sign(&intermediate_key.signing()).unwrap();

    Chain { root: root_der, intermediate: intermediate_der, leaf: leaf_der }
}

/// Our verdict on a chain, which is what the reference is compared with.
fn verdict(chain: &Chain) -> &'static str {
    let leaf = Certificate::parse(&chain.leaf).unwrap();
    let intermediate = Certificate::parse(&chain.intermediate).unwrap();
    let root = Certificate::parse(&chain.root).unwrap();
    let policy = Policy::at(1_700_000_000);     // 2023-11-14
    match verify_chain(&[leaf, intermediate], &[root], &policy,
                       Purpose::ServerAuth) {
        Ok(()) => "accept",
        Err(_) => "reject",
    }
}

fn emit(chain: &Chain, subject: &str) {
    println!("chain {} {} {} {} {}", verdict(chain), subject,
             hex(&chain.root), hex(&chain.intermediate), hex(&chain.leaf));
}

fn main() {
    // One key set for the whole run: key generation is the slow part and
    // nothing here depends on the keys differing between rows.
    let root_key = Key::new();
    let intermediate_key = Key::new();
    let leaf_key = Key::new();

    let mut rows = 0usize;
    let mut emit_pair = |root_extra: Vec<(Vec<u8>, bool, Vec<u8>)>,
                         intermediate_extra: Vec<(Vec<u8>, bool, Vec<u8>)>,
                         inside: (&str, SanEntry, &str),
                         outside: (&str, SanEntry, &str)| {
        for (cn, san, subject) in [inside, outside] {
            let chain = build(&root_key, &intermediate_key, &leaf_key,
                              root_extra.clone(), intermediate_extra.clone(),
                              cn, vec![san]);
            emit(&chain, subject);
            rows += 1;
        }
    };

    let d = |text: &str| SanEntry::Dns(text.to_string());
    let a = |bytes: &[u8]| SanEntry::Ip(bytes.to_vec());

    // ------------------------------------------------ dNSName, permitted ---
    //
    // The pairs straddle every boundary the matcher has: the subtree's
    // own name, a label below it, the suffix-without-a-dot case that a
    // bare `ends_with` gets wrong, and a name one label short.
    for (base, inside, outside) in [
        ("example.test",        "example.test",           "other.test"),
        ("example.test",        "www.example.test",       "evilexample.test"),
        ("example.test",        "a.b.c.example.test",     "example.test.evil"),
        ("a.example.test",      "a.example.test",         "b.example.test"),
        ("a.example.test",      "x.a.example.test",       "xa.example.test"),
        // Case folding, both directions, and the root label.
        ("Example.TEST",        "WWW.example.test",       "www.example.test.x"),
        // A single label as a subtree.
        ("test",                "example.test",           "example.other"),
    ] {
        emit_pair(vec![],
                  vec![constraints(&[dns(base)], &[])],
                  (inside, d(inside), inside),
                  (outside, d(outside), outside));
    }

    // ------------------------------------------------- dNSName, excluded ---
    for (base, allowed, refused) in [
        ("bad.example.test", "good.example.test", "bad.example.test"),
        ("bad.example.test", "good.example.test", "x.bad.example.test"),
        ("example.test",     "example.other",     "anything.example.test"),
    ] {
        emit_pair(vec![],
                  vec![constraints(&[], &[dns(base)])],
                  (allowed, d(allowed), allowed),
                  (refused, d(refused), refused));
    }

    // -------------------------------------- both lists on one extension ---
    //
    // Excluded beats permitted, so the refused name here is inside the
    // permitted subtree and inside the excluded one.
    emit_pair(vec![],
              vec![constraints(&[dns("example.test")],
                               &[dns("bad.example.test")])],
              ("good.example.test", d("good.example.test"), "good.example.test"),
              ("x.bad.example.test", d("x.bad.example.test"), "x.bad.example.test"));

    // ------------------------------------------- the constraint on the root ---
    //
    // A root's constraints reach the leaf through an unconstrained
    // intermediate. This is the case a per-link check misses.
    emit_pair(vec![constraints(&[dns("example.test")], &[])],
              vec![],
              ("in.example.test", d("in.example.test"), "in.example.test"),
              ("out.other.test", d("out.other.test"), "out.other.test"));

    // ------------------------------------------------ two levels at once ---
    //
    // Root permits example.test, intermediate permits a.example.test.
    // The refused name satisfies the root and not the intermediate.
    emit_pair(vec![constraints(&[dns("example.test")], &[])],
              vec![constraints(&[dns("a.example.test")], &[])],
              ("w.a.example.test", d("w.a.example.test"), "w.a.example.test"),
              ("w.b.example.test", d("w.b.example.test"), "w.b.example.test"));

    // And the other way round, which an implementation keeping only the
    // narrowest list would get wrong: the refused name satisfies the
    // intermediate and not the root.
    emit_pair(vec![constraints(&[dns("a.example.test")], &[])],
              vec![constraints(&[dns("other.test")], &[])],
              ("w.a.example.test", d("w.a.example.test"), "w.a.example.test"),
              ("w.other.test", d("w.other.test"), "w.other.test"));

    // ------------------------------------------------ several subtrees ---
    //
    // A permitted list of more than one: a name need only be in one of
    // them, which is the opposite of the rule across CAs.
    emit_pair(vec![],
              vec![constraints(&[dns("one.test"), dns("two.test")], &[])],
              ("a.two.test", d("a.two.test"), "a.two.test"),
              ("a.three.test", d("a.three.test"), "a.three.test"));

    // ----------------------------------------------------------- iPAddress ---
    //
    // The mask boundary at a byte edge, inside a byte, and the two
    // degenerate masks.
    for (base, mask, inside, outside) in [
        ([192u8, 0, 2, 0],   [255u8, 255, 255, 0],   [192u8, 0, 2, 7],   [192u8, 0, 3, 7]),
        ([192, 0, 2, 0],     [255, 255, 255, 128],   [192, 0, 2, 127],   [192, 0, 2, 128]),
        ([10, 0, 0, 0],      [255, 0, 0, 0],         [10, 9, 8, 7],      [11, 9, 8, 7]),
        // /32: a single host.
        ([203, 0, 113, 7],   [255, 255, 255, 255],   [203, 0, 113, 7],   [203, 0, 113, 8]),
    ] {
        let mut subtree = base.to_vec();
        subtree.extend_from_slice(&mask);
        let dotted = |v: [u8; 4]| format!("ip:{}.{}.{}.{}", v[0], v[1], v[2], v[3]);
        let chain_in = build(&root_key, &intermediate_key, &leaf_key, vec![],
                             vec![constraints(&[ip(&subtree)], &[])],
                             "Host", vec![a(&inside)]);
        emit(&chain_in, &dotted(inside));
        let chain_out = build(&root_key, &intermediate_key, &leaf_key, vec![],
                              vec![constraints(&[ip(&subtree)], &[])],
                              "Host", vec![a(&outside)]);
        emit(&chain_out, &dotted(outside));
        rows += 2;
    }

    // An excluded address range.
    {
        let subtree = vec![192u8, 0, 2, 0, 255, 255, 255, 0];
        let chain_in = build(&root_key, &intermediate_key, &leaf_key, vec![],
                             vec![constraints(&[], &[ip(&subtree)])],
                             "Host", vec![a(&[198, 51, 100, 7])]);
        emit(&chain_in, "ip:198.51.100.7");
        let chain_out = build(&root_key, &intermediate_key, &leaf_key, vec![],
                              vec![constraints(&[], &[ip(&subtree)])],
                              "Host", vec![a(&[192, 0, 2, 7])]);
        emit(&chain_out, "ip:192.0.2.7");
        rows += 2;
    }

    // ------------------------------------------------ a mixed-form leaf ---
    //
    // A DNS constraint and a leaf holding an address as well: the
    // address is of an unconstrained form, so it must not be what
    // decides the verdict.
    {
        let chain = build(&root_key, &intermediate_key, &leaf_key, vec![],
                          vec![constraints(&[dns("example.test")], &[])],
                          "in.example.test",
                          vec![d("in.example.test"), a(&[198, 51, 100, 7])]);
        emit(&chain, "in.example.test");
        let chain = build(&root_key, &intermediate_key, &leaf_key, vec![],
                          vec![constraints(&[dns("example.test")], &[])],
                          "out.other.test",
                          vec![d("out.other.test"), a(&[198, 51, 100, 7])]);
        emit(&chain, "out.other.test");
        rows += 2;
    }

    // ----------------------------------------------- no constraints at all ---
    //
    // The control. If this row is not accepted, every rejection above
    // may be for a reason that has nothing to do with name constraints,
    // and the whole corpus proves nothing.
    {
        let chain = build(&root_key, &intermediate_key, &leaf_key, vec![], vec![],
                          "anything.test", vec![d("anything.test")]);
        emit(&chain, "anything.test");
        rows += 1;
    }

    eprintln!("[diff_name_constraints] {} chains", rows);
}
