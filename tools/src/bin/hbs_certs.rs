// Self-signed HSS, XMSS and XMSS^MT certificates (RFC 9802) issued by
// this library, for scripts/make_hbs_x509_vectors.py to hand to Bouncy
// Castle, which must verify every one.
//
//     cargo run --release -p allcrypt-tools --bin hbs_certs < SPECS
//
// One spec per line on standard input, the fields of a vectors/hbs_x509.vec
// `ours` row without its certificate:
//
//     ours scheme=hss levels=LMS_../LMOTS_..,... seed= id= count=
//     ours scheme=xmss set= sk_seed= sk_prf= seed= idx=
//
// and the certificate's DER in hex out, a line each - with `--state`, followed
// by a space and the key's state after signing it (`HssPrivateKey::to_bytes`,
// `XmssPrivateKey::to_bytes`), for scripts/make_hbs_cms_vectors.py to hand to
// the CMS example's `sign`. With `--types` it
// prints each LMS and LM-OTS parameter set's name and RFC 8554 type code
// instead, from the library's table, which the LMS tests hold to RFC
// 8554 and RFC 9858. The certificate is
// what tests/test_hbs_x509.rs makes again: CN "allcrypt " and the
// parameter set, serial 1, the builder's default validity, a CA with
// keyCertSign and cRLSign (RFC 9802 section 6) and key identifiers,
// signed by the key at its index - deterministic, as HSS and XMSS are.
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::BufRead;

use allcrypt::pq::lms::{HssPrivateKey, LmotsParams, LmsParams};
use allcrypt::pq::xmss::{XmssParams, XmssPrivateKey};
use allcrypt::x509::builder::{key_usage, CertificateBuilder, SigningKey, SubjectKey};
use allcrypt::x509::HashSig;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn certificate(name: &str, scheme: HashSig, public: &[u8], key: &SigningKey<'_>) -> Vec<u8> {
    let common_name = format!("allcrypt {name}");
    let mut builder = CertificateBuilder::new(&common_name, SubjectKey::HashSig { scheme,
                                                                              key: public });
    builder.is_ca = Some((true, None));
    builder.key_usage = Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
    builder.key_identifiers = true;
    builder.sign(key).expect("a certificate")
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--types") {
        for p in allcrypt::pq::lms::LMS_PARAMETER_SETS.iter() {
            println!("{} {}", p.name, p.id);
        }
        for p in allcrypt::pq::lms::LMOTS_PARAMETER_SETS.iter() {
            println!("{} {}", p.name, p.id);
        }
        return;
    }
    let with_state = std::env::args().nth(1).as_deref() == Some("--state");
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        let f: HashMap<&str, &str> = line.split(' ').skip(1)
            .map(|w| w.split_once('=').unwrap()).collect();
        let (der, state) = match f["scheme"] {
            "hss" => {
                let levels: Vec<(&'static LmsParams, &'static LmotsParams)> = f["levels"]
                    .split(',').map(|l| {
                        let (lms, ots) = l.split_once('/').unwrap();
                        (LmsParams::named(lms).unwrap(), LmotsParams::named(ots).unwrap())
                    }).collect();
                let id: [u8; 16] = unhex(f["id"]).try_into().unwrap();
                let key = HssPrivateKey::from_seed(&levels, &unhex(f["seed"]), &id,
                                                   f["count"].parse().unwrap()).unwrap();
                let public = key.public_key();
                let key = RefCell::new(key);
                let der = certificate(f["levels"].split(',').next().unwrap(), HashSig::Hss,
                                      &public, &SigningKey::Hss(&key));
                let state = key.borrow().to_bytes();
                (der, state)
            }
            _ => {
                let p = XmssParams::named(f["set"]).unwrap();
                let key = XmssPrivateKey::from_seeds(p, &unhex(f["sk_seed"]), &unhex(f["sk_prf"]),
                                                     &unhex(f["seed"]),
                                                     f["idx"].parse().unwrap()).unwrap();
                let public = key.public_key();
                let scheme = if p.multi_tree { HashSig::XmssMt } else { HashSig::Xmss };
                let key = RefCell::new(key);
                let der = certificate(p.name, scheme, &public, &SigningKey::Xmss(&key));
                let state = key.borrow().to_bytes();
                (der, state)
            }
        };
        let hex = |b: &[u8]| b.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if with_state {
            println!("{} {}", hex(&der), hex(&state));
        } else {
            println!("{}", hex(&der));
        }
    }
}
