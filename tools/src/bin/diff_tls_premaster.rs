// The TLS premaster secret, for the two Diffie-Hellman families whose
// rules are opposites.
//
// This corpus exists because of a bug nothing else here could see. The
// server applied the finite-field rule to ECDHE: RFC 5246 section 8.1.2
// strips the leading zero bytes of a finite-field shared secret, and
// RFC 4492 section 5.10 says of the elliptic-curve x coordinate that
// "leading zeros found in this octet string MUST NOT be truncated".
//
// Every other check was blind to it:
//
//   - our client against our server agreed, because a shared value with
//     a leading zero turns up about once in 256 and neither side ever
//     drew one;
//   - the OpenSSL handshake tests agreed for the same reason;
//   - `tools/src/bin/diff_ec.rs` checks `curve.ecdh`, which is the layer
//     *below* the rule, and was correct all along;
//   - and the deliberate-breakage sweep reported the line as unprotected
//     while in fact removing it was the fix.
//
// So the rows here are premasters, not shared secrets, and every one of
// them has a leading zero byte in the raw value - found by searching,
// because waiting for them is what let the bug live. The checker applies
// each RFC's rule from its own reading and requires our answer to match
// one and *differ from the other*, so a row cannot agree with both.
use allcrypt::bignum::BigUint;
use allcrypt::ec::curves;
use allcrypt::publickey_ciphers::dh::{modp_group, MODP_1024};
use allcrypt::tls::keys::premaster_from_shared;
use allcrypt::tls::suites::KeyExchange;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn scalar(&mut self, n: &BigUint) -> BigUint {
        let bytes: Vec<u8> =
            (0..n.bit_len().div_ceil(8)).map(|_| (self.next() >> 24) as u8).collect();
        let mut value = BigUint::from_bytes_be(&bytes);
        while value >= *n || value.is_zero() {
            value = value.shr(1).add(&BigUint::one());
        }
        value
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut rng = Rng(0x13198A2E03707344);
    let mut ec_rows = 0;
    let mut dh_rows = 0;

    // ---- elliptic curve: the premaster keeps its leading zeros --------
    // **Named, not `curves::all()`.** This corpus only says something
    // where the checker can do ECDH independently, and
    // python-cryptography can do it on exactly these four: it has no
    // GOST curves at all, and it refuses sm2p256v1 ("Curve
    // 1.2.156.10197.1.301 is not supported") even though this OpenSSL
    // has it. A row nothing can check is worse than no row - the same
    // reasoning `diff_ecdsa.rs` gives for naming its curves, and a
    // filter by name prefix silently absorbed the next curve that
    // arrived.
    // On P-521 the top byte holds one bit, so a leading zero byte is
    // every other secret rather than one in 256 - which is the case a
    // `bits / 8` width gets wrong.
    for curve in [curves::p256(), curves::p384(), curves::p521(), curves::secp256k1()] {
        let db = rng.scalar(&curve.n);
        let qb = curve.generator_mul(&db);
        let mut found = 0;
        let mut da = rng.scalar(&curve.n);
        for _ in 0..4000 {
            da = da.add(&BigUint::one());
            if da >= curve.n {
                da = BigUint::from_u64(2);
            }
            let shared = curve.ecdh(&da, &qb).unwrap();
            if shared[0] != 0 {
                continue;
            }
            // The whole point: the premaster is the shared value
            // unchanged, zeros and all.
            let premaster =
                premaster_from_shared(KeyExchange::EcdheRsa, shared.clone());
            println!("ecdhe {} {} {} {}", curve.name, da.to_hex(), db.to_hex(),
                     hex(&premaster));
            found += 1;
            ec_rows += 1;
            if found == 3 {
                break;
            }
        }
        assert!(found > 0,
                "{}: no shared secret with a leading zero byte in 4000 tries, \
                 which cannot happen by chance - the search or the padding \
                 is broken",
                curve.name);
    }

    // ---- finite field: the premaster loses them -----------------------
    //
    // MODP-1024 rather than something smaller: python-cryptography will
    // not perform an exchange on a tiny modulus, and this arm exists to
    // be checked by somebody else. The search costs a modular
    // exponentiation per try and about 256 tries, which is seconds.
    let group = modp_group(MODP_1024).unwrap();
    let p_hex = group.p().to_hex();
    let g_hex = group.g().to_hex();
    let b = rng.scalar(group.p());
    let yb = group.public_key(&b).unwrap();
    let mut a = rng.scalar(group.p());
    while dh_rows < 3 {
        a = a.add(&BigUint::one());
        let shared = group.shared_secret(&a, &yb).unwrap();
        assert_eq!(shared.len(), group.modulus_bytes(),
                   "the shared secret came back unpadded, so there is \
                    nothing here to strip and the rows below prove nothing");
        if shared[0] != 0 {
            continue;
        }
        let premaster = premaster_from_shared(KeyExchange::DheRsa, shared.clone());
        assert!(premaster.len() < shared.len(),
                "a secret with a leading zero came through the stripping rule \
                 unchanged");
        println!("dhe {} {} {} {} {}", p_hex, g_hex, a.to_hex(), b.to_hex(),
                 hex(&premaster));
        dh_rows += 1;
    }

    eprintln!("[diff_tls_premaster] {} elliptic-curve and {} finite-field rows, \
               every one with a leading zero in the raw shared value",
              ec_rows, dh_rows);
}
