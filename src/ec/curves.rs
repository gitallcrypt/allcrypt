/*
Named curve parameters.

These are copied constants, and a typo in one of them produces a curve that
mostly works — arithmetic still closes, points still look like points — while
being a different and possibly weak group. So they are not trusted on sight.
`tests::test_curve_parameters_are_self_consistent` checks, for every curve
here, that G is on the curve and that n*G is the identity. Those two facts
pin down every parameter: get p, a, b, Gx, Gy or n wrong and one of them
fails.

The differential tests in tools/src/bin/diff_ec.rs go further and compare scalar
multiplication against OpenSSL through python-cryptography.
*/

use super::{Curve, Point};
use crate::bignum::BigUint;

fn hex(s: &str) -> BigUint {
    BigUint::from_hex(s).expect("curve constants are valid hex")
}

/// NIST P-256, also called secp256r1 and prime256v1. The default curve for
/// TLS ECDHE and for most certificates.
pub fn p256() -> Curve {
    let p = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
    Curve {
        name: "P-256",
        a: hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"), // p - 3
        b: hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        g: Point::new(
            hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        ),
        n: hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        h: BigUint::one(),
        p,
    }
}

/// NIST P-384, also called secp384r1.
pub fn p384() -> Curve {
    let p = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                 ffffffff0000000000000000ffffffff");
    Curve {
        name: "P-384",
        a: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                ffffffff0000000000000000fffffffc"), // p - 3
        b: hex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
                c656398d8a2ed19d2a85c8edd3ec2aef"),
        g: Point::new(
            hex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                 5502f25dbf55296c3a545e3872760ab7"),
            hex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
                 0a60b1ce1d7e819d7a431d7c90ea0e5f"),
        ),
        n: hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
                581a0db248b0a77aecec196accc52973"),
        h: BigUint::one(),
        p,
    }
}

/// NIST P-521, also called secp521r1: `p = 2^521 - 1`. Its field
/// elements are 66 bytes, not a whole number of 64 bit limbs nor of
/// bytes' worth of bits - the top byte carries one bit - which is where
/// encoders that assume `bits / 8` go wrong. Copied from RFC 5903 section
/// 3.3 by script, and read back out of it by `rfc5903_tests`.
pub fn p521() -> Curve {
    let p = hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 ffff");
    Curve {
        name: "P-521",
        a: hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                fffc"), // p - 3
        b: hex("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
                09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
                3f00"),
        g: Point::new(
            hex("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
                 3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
                 bd66"),
            hex("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
                 662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
                 6650"),
        ),
        n: hex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
                6409"),
        h: BigUint::one(),
        p,
    }
}

/// secp256k1, the Bitcoin curve. `a = 0`, which exercises a different branch
/// of the doubling formula than the NIST curves' `a = p - 3`.
pub fn secp256k1() -> Curve {
    let p = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    Curve {
        name: "secp256k1",
        a: BigUint::zero(),
        b: BigUint::from_u64(7),
        g: Point::new(
            hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        ),
        n: hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
        h: BigUint::one(),
        p,
    }
}


// --------------------------------------------------------------- GOST ---
//
// The curves GOST R 34.10-2012 uses, from RFC 4357 and RFC 7836. Short
// Weierstrass like the NIST ones, so the same arithmetic works. What
// differs is that `a` is not `p - 3`, which exercises the general
// doubling formula rather than the NIST shortcut, and that one of them
// has a generator with `x = 0` - a perfectly ordinary point and an
// unusual one to meet.
//
// Taken from the gost-engine project's `gost_params.c` and then checked
// arithmetically, which is the check that matters here:
// `tests::test_curve_parameters_are_self_consistent` verifies for every
// curve that G is on it and that n*G is the identity, and those two facts
// together pin down every one of p, a, b, Gx, Gy and n. A single wrong
// hex digit in any of them breaks one or the other.

/// `id-GostR3410-2001-CryptoPro-A-ParamSet`, also
/// `id-tc26-gost-3410-2012-256-paramSetB`. The 256 bit curve nearly
/// everything uses, and the one RFC 9189's suites are keyed on.
pub fn gost256_a() -> Curve {
    let p = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97");
    Curve {
        name: "gost256-a",
        a: hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"),
        b: BigUint::from_u64(0xa6),
        g: Point::new(BigUint::one(), hex("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14")),
        n: hex("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"),
        h: BigUint::one(),
        p,
    }
}

/// `id-GostR3410-2001-CryptoPro-B-ParamSet`, also 256-paramSetC.
pub fn gost256_b() -> Curve {
    let p = hex("8000000000000000000000000000000000000000000000000000000000000c99");
    Curve {
        name: "gost256-b",
        a: hex("8000000000000000000000000000000000000000000000000000000000000c96"),
        b: hex("3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b"),
        g: Point::new(BigUint::one(), hex("3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc")),
        n: hex("800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f"),
        h: BigUint::one(),
        p,
    }
}

/// `id-GostR3410-2001-CryptoPro-C-ParamSet`, also 256-paramSetD.
///
/// Its generator has `x = 0`. An implementation that treats a zero
/// coordinate as "no point" fails here and nowhere else.
pub fn gost256_c() -> Curve {
    let p = hex("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b");
    Curve {
        name: "gost256-c",
        a: hex("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598"),
        b: BigUint::from_u64(0x805a),
        g: Point::new(BigUint::zero(), hex("41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67")),
        n: hex("9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9"),
        h: BigUint::one(),
        p,
    }
}

/// `id-tc26-gost-3410-2012-512-paramSetA`.
pub fn gost512_a() -> Curve {
    let p = hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7");
    Curve {
        name: "gost512-a",
        a: hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4"),
        b: hex("e8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265\
                 ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760"),
        g: Point::new(BigUint::from_u64(3), hex("7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921\
                 df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4")),
        n: hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275"),
        h: BigUint::one(),
        p,
    }
}

/// `id-tc26-gost-3410-2012-512-paramSetB`.
pub fn gost512_b() -> Curve {
    let p = hex("8000000000000000000000000000000000000000000000000000000000000000\
                 000000000000000000000000000000000000000000000000000000000000006f");
    Curve {
        name: "gost512-b",
        a: hex("8000000000000000000000000000000000000000000000000000000000000000\
                 000000000000000000000000000000000000000000000000000000000000006c"),
        b: hex("687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f\
                 3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116"),
        g: Point::new(BigUint::from_u64(2), hex("1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335\
                 dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd")),
        n: hex("8000000000000000000000000000000000000000000000000000000000000001\
                 49a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd"),
        h: BigUint::one(),
        p,
    }
}

/// `id-tc26-gost-3410-2012-256-paramSetA`, RFC 7836 appendix A.2.
///
/// **The first curve here with a cofactor other than one**, and the
/// reason `Curve::validate`'s subgroup branch is live code rather than
/// a guard. `m = 4q`, so a point can be on the curve, not be the
/// identity, and still sit in a subgroup of order 2 or 4 - which is
/// the small-subgroup attack that branch exists for.
///
/// It is stated in RFC 7836 twice over, as a twisted Edwards curve
/// `(e, d, u, v)` and as the short Weierstrass curve `(a, b, x, y)`
/// below. This library had neither, and said in a comment that it
/// could not do the arithmetic because the curve was Edwards - which
/// was wrong, and cost a refused certificate: the document gives the
/// Weierstrass form of the same curve, and that is the form every
/// function here already speaks.
pub fn gost256_tc26_a() -> Curve {
    let p = hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97");
    Curve {
        name: "gost256-tc26-a",
        a: hex("c2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335"),
        b: hex("295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513"),
        g: Point::new(
            hex("91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28"),
            hex("32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c"),
        ),
        n: hex("400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67"),
        h: BigUint::from_u64(4),
        p,
    }
}

/// `id-tc26-gost-3410-2012-512-paramSetC`, RFC 7836 appendix A.2.
///
/// The curve RFC 9189's own worked example is on: the server
/// certificate in appendix A.1.3.2 carries a key on it, and a client
/// without this curve refuses that handshake at the Certificate
/// message. Cofactor four, like its 256 bit neighbour above, and the
/// same story about the Edwards form.
pub fn gost512_c() -> Curve {
    let p = hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7");
    Curve {
        name: "gost512-c",
        a: hex("dc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e1430645\
                 46e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3"),
        b: hex("b4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade0\
                 38cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1"),
        g: Point::new(
            hex("e2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043a\
                 a27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148"),
            hex("f5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9b\
                 e18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f"),
        ),
        n: hex("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                 c98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed"),
        h: BigUint::from_u64(4),
        p,
    }
}

/// sm2p256v1, GB/T 32918.5-2017. `a = p - 3` as on the NIST
/// curves, so it shares their doubling path; what differs is
/// everything built on top - see `src/ec/sm2.rs`.
///
/// These constants were printed by `scripts/make_sm2_curve.py`
/// out of OpenSSL and were not typed.
pub fn sm2() -> Curve {
    let p = hex("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff");
    Curve {
        name: "sm2p256v1",
        a: hex("fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"), // p - 3
        b: hex("28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"),
        g: Point::new(
            hex("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"),
            hex("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"),
        ),
        n: hex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"),
        h: BigUint::one(),
        p,
    }
}

/// Every curve, for the tests that must hold on all of them.
pub fn all() -> Vec<Curve> {
    vec![p256(), p384(), p521(), secp256k1(), sm2(),
         gost256_a(), gost256_b(), gost256_c(), gost256_tc26_a(),
         gost512_a(), gost512_b(), gost512_c()]
}

/// Look one up by name: the curves compiled in, and then any a caller
/// has registered.
///
/// **Built-ins first**, which is the same order `registry` uses for every
/// other kind of meaning and for the same reason: nothing a caller
/// registers can change what `P-256` means for anybody else in the
/// process. `from_parameters` refuses a name that is already built in, so
/// the two sets cannot overlap.
pub fn by_name(name: &str) -> Result<Curve, String> {
    match builtin_by_name(name) {
        Ok(curve) => Ok(curve),
        Err(unknown) => match crate::registry::curve_parameters_named(name) {
            // Not re-validated. `registry::register` ran every check in
            // `from_parameters` before it stored these, and the registry
            // is the only way they get in, so re-running 64 rounds of
            // Miller-Rabin on every lookup would buy nothing.
            Some(parameters) => Ok(parameters.assemble()),
            None => Err(unknown),
        },
    }
}

/// How a curve name is compared: case-folded, with underscores and
/// spaces read as hyphens.
///
/// **Applied to registered curves as well as built-in ones**, which it was
/// not at first, and the bug that exposed it is worth recording.
/// `api::ca_key` lowercases its `key_type` before looking the curve up -
/// harmless for every built-in name, because this same folding happens
/// inside. A registered curve was compared exactly, so
/// `CertificateAuthority(..., "brainpoolP256r1")` failed with `Unknown
/// curve "brainpoolp256r1"` while `EcKey.generate("brainpoolP256r1")`
/// worked, and the lowercase spelling in the error was the only clue that
/// anything had folded it.
///
/// A registered curve should behave like a built-in one everywhere or the
/// registry is a second class of curve with its own rules, so there is one
/// function and both sides call it.
pub fn normalise_name(name: &str) -> String {
    name.to_ascii_lowercase().replace(['_', ' '], "-")
}

/// The curves this file carries, and nothing a caller has added.
///
/// Separate from `by_name` because `from_parameters` needs to ask "is
/// this name already built in" without the registry answering "yes,
/// because you registered it a moment ago" - which would make
/// re-registering a curve under the same name impossible, where every
/// other registration replaces the older meaning.
pub fn builtin_by_name(name: &str) -> Result<Curve, String> {
    match normalise_name(name).as_str() {
        "p-256" | "secp256r1" | "prime256v1" => Ok(p256()),
        "p-384" | "secp384r1" => Ok(p384()),
        "p-521" | "secp521r1" => Ok(p521()),
        "secp256k1" => Ok(secp256k1()),
        // Both spellings are in use: GB/T 32918.5 calls the curve
        // `sm2p256v1` and OpenSSL calls it `SM2`.
        "sm2" | "sm2p256v1" | "curvesm2" => Ok(sm2()),
        // Both naming schemes reach the same place: the CryptoPro
        // names are what certificates carry and the tc26 names are
        // what RFC 7836 calls the same curves. A caller should not
        // have to know that paramSetB and CryptoPro-A are one curve.
        "gost256-a" | "gostr3410-2001-cryptopro-a" | "tc26-256-b" => Ok(gost256_a()),
        "gost256-b" | "gostr3410-2001-cryptopro-b" | "tc26-256-c" => Ok(gost256_b()),
        "gost256-c" | "gostr3410-2001-cryptopro-c" | "tc26-256-d" => Ok(gost256_c()),
        // The two with no CryptoPro name, because CryptoPro never
        // named them: they arrived with TC 26 in 2012.
        "gost256-tc26-a" | "tc26-256-a" => Ok(gost256_tc26_a()),
        "gost512-a" | "tc26-512-a" => Ok(gost512_a()),
        "gost512-b" | "tc26-512-b" => Ok(gost512_b()),
        "gost512-c" | "tc26-512-c" => Ok(gost512_c()),
        other => Err(format!("Unknown curve {:?}. Known: {}.", other, NAMES.join(", "))),
    }
}

pub const NAMES: &[&str] = &["P-256", "P-384", "P-521", "secp256k1", "sm2p256v1",
                             "gost256-a", "gost256-b", "gost256-c",
                             "gost256-tc26-a",
                             "gost512-a", "gost512-b", "gost512-c"];

/// Domain parameters for a curve this library does not carry.
///
/// Every field is required, including the cofactor: a caller who does
/// not know it does not know the curve, and guessing 1 turns the
/// cofactor checks in `vko` and `validate` into checks of the guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurveParameters {
    pub name: String,
    pub p: BigUint,
    pub a: BigUint,
    pub b: BigUint,
    pub gx: BigUint,
    pub gy: BigUint,
    /// Order of the base point, which must be prime - see the checks.
    pub n: BigUint,
    /// Cofactor: the curve's order divided by `n`.
    pub h: BigUint,
}

impl CurveParameters {
    /// The `Curve` these describe, **without re-checking them**.
    ///
    /// Only sound because `registry::register` calls `from_parameters`,
    /// which runs every check, before any of these reach a table. Do not
    /// call this on parameters that have not been through that.
    pub(crate) fn assemble(&self) -> Curve {
        Curve {
            name: intern(&self.name),
            p: self.p.clone(),
            a: self.a.clone(),
            b: self.b.clone(),
            g: Point::new(self.gx.clone(), self.gy.clone()),
            n: self.n.clone(),
            h: self.h.clone(),
        }
    }
}

/// Names handed to `from_parameters`, kept alive for the process.
///
/// `Curve::name` is `&'static str`, because every curve in this file is
/// a constant and nothing else needed a name with a lifetime. A curve
/// built at run time needs one too, so the string is leaked - once per
/// distinct name, which is what this table is for. Registering the same
/// curve in a loop would otherwise leak on every call.
static INTERNED: std::sync::OnceLock<std::sync::Mutex<Vec<&'static str>>> =
    std::sync::OnceLock::new();

fn intern(name: &str) -> &'static str {
    let table = INTERNED.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut names = table.lock().expect("the interning table is not poisoned");
    if let Some(existing) = names.iter().find(|held| **held == name) {
        return existing;
    }
    let leaked: &'static str = Box::leak(name.to_string().into_boxed_str());
    names.push(leaked);
    leaked
}

/// The `&'static str` a registered curve's name was interned as, if it
/// has been.
///
/// For the callers that must hand back a `&'static str` - `x509::oids`
/// maps an OID to one - so that a registered curve is reachable there
/// without leaking a fresh string on every certificate parsed.
pub fn interned_name(name: &str) -> Option<&'static str> {
    let table = INTERNED.get()?;
    let names = table.lock().ok()?;
    let wanted = normalise_name(name);
    names.iter().find(|held| normalise_name(held) == wanted).copied()
}

/// Build a curve from its domain parameters, checking that they are a
/// curve.
///
/// **This is the one place in this library where a caller supplies
/// cryptography rather than a name**, alongside a GOST S-box, and for
/// the same reason: a short Weierstrass curve *is* its seven numbers,
/// distributed as a parameter set rather than as code. Meeting a box on
/// a curve nobody vendored is ordinary in the corners this library
/// exists for.
///
/// So the numbers are checked, and every check below is one that a
/// plausible-looking mistake passes without:
///
///   * **p prime.** Over a composite modulus the inverse in the point
///     addition formula does not always exist, so most additions still
///     work and a few produce nonsense. Nothing else here would notice:
///     `is_on_curve` is an equation, and it holds in a ring.
///   * **p odd and at least 5.** `y^2 = x^3 + ax + b` is not the general
///     form in characteristic 2 or 3, and the arithmetic in this file
///     assumes it is.
///   * **non-singular**, `4a^3 + 27b^2 != 0`. A singular curve's points
///     do not form a group at all - there is a point where the tangent
///     is undefined - and the discrete log on one is easy. Every other
///     check here passes on a singular curve: G is on it, and the
///     scalar multiplication will happily run.
///   * **G on the curve, and not the identity.** The cheap one, and the
///     one that catches a mistyped coordinate.
///   * **n prime, and n*G the identity.** Together these are what make
///     `n` mean "the order of G": `n*G = 0` alone holds for any multiple
///     of the true order, so a caller who passed `2*ord(G)` would pass
///     that check and then have a cofactor wrong by two, quietly. With
///     `n` prime and `G` not the identity, the order is exactly `n`.
///   * **the cofactor fits Hasse's bound**: `#E = n*h` must be within
///     `2*sqrt(p)` of `p+1`. This is what catches an `h` that was
///     guessed rather than known, and it is written as a squared
///     comparison so no square root is needed.
///   * **n != p.** An anomalous curve, where the group order equals the
///     field characteristic, has an efficiently computable discrete
///     logarithm (Semaev, Smart, Satoh-Araki). It is cheap to check and
///     catastrophic to miss.
///
/// **What it does not check**, said out loud rather than left as a gap:
/// the embedding degree. A curve with small embedding degree is broken
/// by the MOV/Frey-Rück reduction, and establishing a lower bound on it
/// means factoring `n-1`-sized quantities and testing `p^k mod n` for
/// many `k`. A caller supplying their own curve is trusting its
/// provenance for that property, and this cannot supply it for them.
/// Neither is the twist's security, which matters for the
/// x-coordinate-only protocols this library does not use here.
pub fn from_parameters(spec: CurveParameters) -> Result<Curve, String> {
    let one = BigUint::one();
    let two = BigUint::from_u64(2);
    let four = BigUint::from_u64(4);

    if spec.name.trim().is_empty() {
        return Err("A curve needs a name.".to_string());
    }
    // **Refused rather than shadowed.** A registered meaning is
    // consulted after the compiled-in tables everywhere else in this
    // library, so a curve registered under a built-in name would be
    // silently unreachable - the caller would believe their parameters
    // were in use and be running P-256.
    // `builtin_by_name` folds the name, so "P_256" and "p-256" are both
    // caught here rather than only the exact spelling.
    if builtin_by_name(&spec.name).is_ok() {
        return Err(format!(
            "{:?} is already a curve in this library, and a registered one \
                would never be reached: the built-in tables are consulted \
                first. Give it a different name.", spec.name));
    }

    if spec.p < BigUint::from_u64(5) {
        return Err("The field characteristic must be at least 5: y^2 = x^3 + ax + b is \
            not the general form of a curve in characteristic 2 or 3.".to_string());
    }
    if !spec.p.rem(&two)?.is_one() {
        return Err("The field characteristic must be odd.".to_string());
    }
    for (what, value) in [("a", &spec.a), ("b", &spec.b),
                          ("the base point's x", &spec.gx),
                          ("the base point's y", &spec.gy)] {
        if *value >= spec.p {
            return Err(format!("{} must be less than p.", what));
        }
    }
    if spec.h.is_zero() {
        return Err("The cofactor must be at least 1.".to_string());
    }
    if spec.n < two {
        return Err("The order of the base point must be at least 2."
                   .to_string());
    }
    if spec.n == spec.p {
        return Err("This is an anomalous curve - the order of the base point equals \
            the field characteristic - and the discrete logarithm on one is \
            efficiently computable."
                   .to_string());
    }

    // 4a^3 + 27b^2, mod p. Before the primality test, because it is
    // microseconds and catches the commoner mistake.
    let a3 = spec.a.mod_mul(&spec.a, &spec.p)?.mod_mul(&spec.a, &spec.p)?;
    let b2 = spec.b.mod_mul(&spec.b, &spec.p)?;
    let discriminant = four.mod_mul(&a3, &spec.p)?
        .mod_add(&BigUint::from_u64(27).mod_mul(&b2, &spec.p)?, &spec.p)?;
    if discriminant.is_zero() {
        return Err("4a^3 + 27b^2 is zero, so this curve is singular: its points are \
            not a group and the discrete logarithm on it is easy.".to_string());
    }

    // 64 rounds of Miller-Rabin, the same count `dh` uses for a modulus
    // it did not generate. This is a one-off cost at registration.
    if !crate::publickey_ciphers::rsa::is_probably_prime(&spec.p, 64)? {
        return Err("The field characteristic is not prime. Over a composite modulus \
            the inverse in the point addition formula does not always exist, \
            so most of the arithmetic works and some of it silently does not.".to_string());
    }
    if !crate::publickey_ciphers::rsa::is_probably_prime(&spec.n, 64)? {
        return Err("The order of the base point is not prime. This library requires it \
            to be, because `n*G = 0` alone does not pin the order down - any \
            multiple of it satisfies that - and a caller who passed a multiple \
            would get a cofactor wrong by that factor with nothing to show it."
                   .to_string());
    }

    let curve = spec.assemble();

    // **There is deliberately no "G is the identity" check.** The
    // identity is `Point` with no coordinates, and this function takes
    // `gx` and `gy` as numbers, so `Point::new` always produces a point
    // that has them: the identity cannot be expressed through this
    // interface at all. A check for it was written here and removed
    // after the test for it failed with "not on the curve" - which is
    // the honest answer for all-zero coordinates, and is the shape a
    // zeroed struct arrives in.
    //
    // It matters because the order argument below needs `G` to be
    // something other than the identity: with `n` prime, `n*G = 0` and
    // `G != 0`, the order of `G` is exactly `n`. That premise holds
    // structurally here rather than by checking it.
    if !curve.is_on_curve(&curve.g) {
        return Err("The base point is not on the curve.".to_string());
    }
    if !curve.scalar_mul(&curve.g, &curve.n).is_identity() {
        return Err("n*G is not the identity, so n is not the order of the base point."
                   .to_string());
    }

    // Hasse: |#E - (p + 1)| <= 2*sqrt(p), with #E = n*h. Squared, so no
    // square root: (n*h - p - 1)^2 <= 4p.
    let order = spec.n.mul(&spec.h);
    let p_plus_one = spec.p.add(&one);
    let gap = if order > p_plus_one {
        order.sub(&p_plus_one)?
    } else {
        p_plus_one.sub(&order)?
    };
    if gap.mul(&gap) > four.mul(&spec.p) {
        return Err(format!(
            "The cofactor {} does not fit this curve: n*h would put the \
                number of points more than 2*sqrt(p) away from p+1, which \
                Hasse's theorem forbids. The cofactor has to be known rather \
                than guessed.", spec.h.to_hex()));
    }

    Ok(curve)
}

/// The GOST curves, by name.
///
/// There were six copies of this list - in `vko.rs`, `gost3410.rs`,
/// `x509/verify.rs`, both `gost_kex` files and here - each written out
/// by hand, and adding a curve meant finding all six. The two that
/// were missed would have gone on being untested while looking
/// covered, which is the failure this repository keeps meeting.
pub fn gost_names() -> Vec<&'static str> {
    NAMES.iter().copied().filter(|name| name.starts_with("gost")).collect()
}

#[cfg(test)]
mod document_tests {
    /*
    Every GOST curve here, checked against the document that defines it.

    These constants were copied - from gost-engine, originally - and
    `ec::tests::test_curve_parameters_are_self_consistent` already
    checks that they form a consistent curve: G on it, n*G the
    identity. That is a strong check and it is not the same as being
    the *right* curve. A consistent curve with one digit changed is
    still a consistent curve; it is simply somebody else's, with an
    unknown order and no relation to what a peer is using.

    So the parameters are read back out of the standards, at test time,
    and compared. This is the rule in docs/extending.md ("Where test
    vectors come from") applied to something bigger than a test vector:
    the document is the authority, and a value that was typed is a value
    that was typed.

    Two documents, two formats:

      * **RFC 4357 section 11.4** prints the 2001 parameter sets as an
        annotated ASN.1 dump, `SEQUENCE { a, b, p, q, x, y }`, with
        short values as decimal (`INTEGER 166`) and long ones as hex
        rows. It runs across a page break, so the running header has
        to be stepped over.

      * **RFC 7836 appendix A.2** prints two more as plain ASN.1, in a
        different field order - `p, a, b, ...` - and with the twisted
        Edwards parameters interleaved. Reading them positionally
        against 4357's order would silently swap `a` and `p`, which is
        why each parser states its own order.

    What this catches that nothing else does: the aliasing. XchA is
    CryptoPro-A and XchB is CryptoPro-C, and `oids::gost_curve_for`
    says so. That claim is only as good as somebody's memory until
    the two sets of parameters are compared, which is what
    `test_the_exchange_sets_are_the_curves_we_map_them_to` does.
    */

    use super::*;

    /// P-256's own parameters, as a caller would supply them.
    ///
    /// **A real curve, under a name this library does not know.** Using
    /// a toy curve would leave the primality tests and Hasse's bound
    /// untested at any realistic size, and using a built-in name would
    /// be refused - which is itself checked below.
    fn a_spec() -> CurveParameters {
        let real = p256();
        CurveParameters {
            name: "p-256-under-another-name".to_string(),
            p: real.p.clone(),
            a: real.a.clone(),
            b: real.b.clone(),
            gx: real.g.x().expect("a base point is never the identity").clone(),
            gy: real.g.y().expect("a base point is never the identity").clone(),
            n: real.n.clone(),
            h: real.h.clone(),
        }
    }

    #[test]
    fn test_a_curve_can_be_built_from_its_parameters() {
        let curve = from_parameters(a_spec()).unwrap();
        assert_eq!(curve.name, "p-256-under-another-name");

        // It is the same group, so it agrees with the built-in on a
        // scalar multiplication - which is the only check that the
        // parameters were used rather than quietly replaced.
        let k = BigUint::from_u64(0x9e3779b9);
        let ours = curve.scalar_mul(&curve.g, &k);
        let theirs = p256().scalar_mul(&p256().g, &k);
        assert_eq!(ours.x(), theirs.x());
        assert_eq!(ours.y(), theirs.y());
    }

    #[test]
    fn test_the_name_is_interned_rather_than_leaked_per_call() {
        // Ten registrations of the same name must not leak ten strings.
        // Checked by pointer identity, which is the property that
        // matters and the only one observable from here.
        let first = from_parameters(a_spec()).unwrap().name;
        for _ in 0..9 {
            let again = from_parameters(a_spec()).unwrap().name;
            assert!(std::ptr::eq(first, again),
                    "the name was leaked again rather than interned");
        }
    }

    /// `(what it is, how to break the spec, what the message must say)`.
    ///
    /// A named type because clippy is right that the bare tuple is hard
    /// to read, and because the middle field is a closure - which is what
    /// lets each case say how to break a *valid* spec rather than
    /// hand-writing twelve broken ones, where a typo would test the typo.
    type BreakageCase = (&'static str, Box<dyn Fn(&mut CurveParameters)>,
                         &'static str);

    /// **Every check, shown to fire.** A validation nobody has watched
    /// reject anything is a validation that might be testing `true`.
    #[test]
    fn test_each_parameter_check_rejects_what_it_is_for() {
        let cases: Vec<BreakageCase> = vec![
            ("a built-in name", Box::new(|s: &mut CurveParameters| {
                s.name = "secp256k1".to_string();
            }), "already a curve"),
            ("an empty name", Box::new(|s: &mut CurveParameters| {
                s.name = "   ".to_string();
            }), "needs a name"),
            ("an even p", Box::new(|s: &mut CurveParameters| {
                s.p = s.p.add(&BigUint::one());
            }), "must be odd"),
            ("a tiny p", Box::new(|s: &mut CurveParameters| {
                s.p = BigUint::from_u64(3);
            }), "at least 5"),
            ("a out of range", Box::new(|s: &mut CurveParameters| {
                s.a = s.p.clone();
            }), "must be less than p"),
            ("a zero cofactor", Box::new(|s: &mut CurveParameters| {
                s.h = BigUint::zero();
            }), "at least 1"),
            // p stays prime and G stays on the curve here: only b moves,
            // to the value that makes 4a^3 + 27b^2 vanish. With a = -3,
            // 4a^3 = -108, so b^2 = 4 and b = 2 is singular.
            ("a singular curve", Box::new(|s: &mut CurveParameters| {
                s.a = s.p.sub(&BigUint::from_u64(3)).unwrap();
                s.b = BigUint::from_u64(2);
            }), "singular"),
            ("a composite p", Box::new(|s: &mut CurveParameters| {
                // p - 2 is odd and, for P-256's p, composite.
                s.p = s.p.sub(&BigUint::from_u64(2)).unwrap();
            }), "not prime"),
            ("a composite n", Box::new(|s: &mut CurveParameters| {
                s.n = s.n.mul(&BigUint::from_u64(2));
            }), "not prime"),
            ("a point off the curve", Box::new(|s: &mut CurveParameters| {
                s.gy = s.gy.add(&BigUint::one());
            }), "not on the curve"),
            // All-zero coordinates: the shape a zeroed struct arrives
            // in, and **not** the identity - which this interface cannot
            // express, since it takes the coordinates as numbers. The
            // first version of this case expected a message about the
            // identity and got "not on the curve", which is the correct
            // answer and is why there is no identity check to fire.
            ("all-zero coordinates", Box::new(|s: &mut CurveParameters| {
                s.gx = BigUint::zero();
                s.gy = BigUint::zero();
            }), "not on the curve"),
            ("a guessed cofactor", Box::new(|s: &mut CurveParameters| {
                s.h = BigUint::from_u64(7);
            }), "cofactor"),
        ];

        let mut fired = 0;
        for (what, break_it, expected) in &cases {
            let mut spec = a_spec();
            break_it(&mut spec);
            let error = from_parameters(spec).unwrap_err();
            assert!(error.contains(expected),
                    "{}: expected a message about {:?}, got {:?}",
                    what, expected, error);
            fired += 1;
        }
        assert_eq!(fired, cases.len());
        // The count is asserted so that a case deleted from the list
        // above shows up here rather than shrinking the loop in silence.
        assert_eq!(cases.len(), 12);
    }

    /// The anomalous-curve check, which needs its own curve.
    ///
    /// P-256's `n` cannot be made to equal its `p` without breaking
    /// something else first, so this is the one case built from a real
    /// anomalous curve: p = 17, and the curve y^2 = x^3 + 2x + 2 over
    /// F_17 has 17 points, so n = p = 17 with G a generator.
    #[test]
    fn test_an_anomalous_curve_is_refused() {
        let spec = CurveParameters {
            name: "anomalous-17".to_string(),
            p: BigUint::from_u64(17),
            a: BigUint::from_u64(2),
            b: BigUint::from_u64(2),
            gx: BigUint::from_u64(5),
            gy: BigUint::from_u64(1),
            n: BigUint::from_u64(17),
            h: BigUint::one(),
        };
        let error = from_parameters(spec).unwrap_err();
        assert!(error.contains("anomalous"), "{}", error);
    }

    const RFC4357: &str = include_str!("../../rfcs/rfc4357.txt");
    const RFC7836: &str = include_str!("../../rfcs/rfc7836.txt");

    /// A page header, a footer, or a blank line - none of which is
    /// part of a value and all of which sit in the middle of one.
    fn furniture(line: &str, footer: &str, header: &str) -> bool {
        let trimmed = line.trim();
        trimmed.is_empty() || trimmed.starts_with(footer)
            || trimmed.starts_with(header)
    }

    /// The six integers of a 2001 parameter set, in RFC 4357's order:
    /// `a, b, p, q, x, y`.
    fn rfc4357_parameters(set: &str) -> Vec<BigUint> {
        let marker = format!("id-GostR3410-2001-CryptoPro-{}-ParamSet", set);
        let lines: Vec<&str> = RFC4357.lines().collect();
        // The name appears in the ASN.1 module definitions as well as
        // in the dump; the dump's copy is the one printed as a
        // continuation line, starting with a colon.
        let start = lines.iter().rposition(|line| {
            let trimmed = line.trim();
            trimmed.starts_with(':') && trimmed.ends_with(&marker)
        }).unwrap_or_else(|| panic!("{} is not in RFC 4357's dump", marker));

        let mut values: Vec<BigUint> = Vec::new();
        let mut pending: Option<String> = None;
        for line in &lines[start + 1..] {
            if values.len() == 6 {
                break;
            }
            if furniture(line, "Popov,", "RFC 4357") {
                continue;
            }
            let trimmed = line.trim();
            if let Some(at) = trimmed.find("INTEGER") {
                if let Some(hex) = pending.take() {
                    values.push(BigUint::from_hex(&hex).expect("hex"));
                }
                let tail = trimmed[at + "INTEGER".len()..].trim();
                if tail.is_empty() {
                    pending = Some(String::new());
                } else {
                    values.push(BigUint::from_u64(
                        tail.parse().expect("a decimal INTEGER")));
                }
                continue;
            }
            if let Some(hex) = pending.as_mut() {
                let rest = trimmed.trim_start_matches(':').trim();
                let bytes: Vec<&str> = rest.split_whitespace().collect();
                if !bytes.is_empty()
                    && bytes.iter().all(|word| word.len() == 2
                                        && word.chars().all(|c| c.is_ascii_hexdigit())) {
                    for word in bytes {
                        hex.push_str(word);
                    }
                    continue;
                }
                let finished = pending.take().expect("pending");
                values.push(BigUint::from_hex(&finished).expect("hex"));
            }
        }
        if let Some(hex) = pending {
            if values.len() < 6 && !hex.is_empty() {
                values.push(BigUint::from_hex(&hex).expect("hex"));
            }
        }
        assert_eq!(values.len(), 6,
                   "{}: RFC 4357 prints a, b, p, q, x and y", marker);
        values
    }

    /// The integers of one RFC 7836 appendix A.2 parameter set, in the
    /// document's order.
    ///
    /// Seven for the plain sets (`p, a, b, m, q, x, y`) and eleven for
    /// the ones also given in Edwards form (`p, a, b, e, d, m, q, x,
    /// y, u, v`). **The count decides which order applies**, so it is
    /// returned rather than assumed: reading a seven-value set as an
    /// eleven-value one puts `m` where `e` should be and produces a
    /// curve that is wrong in a way the arithmetic would not catch,
    /// because it would never be built.
    fn rfc7836_parameters(set: &str) -> Vec<BigUint> {
        let marker = format!("Parameter set: {}", set);
        let lines: Vec<&str> = RFC7836.lines().collect();
        let start = lines.iter().rposition(|line| line.trim() == marker)
            .unwrap_or_else(|| panic!("{} is not in RFC 7836", marker));

        let mut values = Vec::new();
        let mut pending: Option<String> = None;
        for line in &lines[start + 1..] {
            if furniture(line, "Smyshlyaev,", "RFC 7836") {
                continue;
            }
            let trimmed = line.trim();
            if trimmed.starts_with("Parameter set:") {
                break;
            }
            if trimmed == "INTEGER" {
                if let Some(hex) = pending.take() {
                    values.push(BigUint::from_hex(&hex).expect("hex"));
                }
                pending = Some(String::new());
                continue;
            }
            if let Some(hex) = pending.as_mut() {
                let words: Vec<&str> = trimmed.split_whitespace().collect();
                if !words.is_empty()
                    && words.iter().all(|word| word.len() == 2
                                        && word.chars().all(|c| c.is_ascii_hexdigit())) {
                    for word in words {
                        hex.push_str(word);
                    }
                    continue;
                }
                let finished = pending.take().expect("pending");
                if !finished.is_empty() {
                    values.push(BigUint::from_hex(&finished).expect("hex"));
                }
                if trimmed == "}" {
                    break;
                }
            }
        }
        if let Some(hex) = pending {
            if !hex.is_empty() {
                values.push(BigUint::from_hex(&hex).expect("hex"));
            }
        }
        assert!(values.len() == 7 || values.len() == 11,
                "{}: RFC 7836 prints seven values, or eleven when the \
                 twisted Edwards form is given too; this found {}",
                marker, values.len());
        values
    }

    fn same(curve: &Curve, a: &BigUint, b: &BigUint, p: &BigUint, q: &BigUint,
            x: &BigUint, y: &BigUint) {
        assert_eq!(&curve.p, p, "{}: p", curve.name);
        assert_eq!(&curve.a, a, "{}: a", curve.name);
        assert_eq!(&curve.b, b, "{}: b", curve.name);
        assert_eq!(&curve.n, q, "{}: the subgroup order", curve.name);
        assert_eq!(curve.g.x().expect("G is not the identity"), x,
                   "{}: G.x", curve.name);
        assert_eq!(curve.g.y().expect("G is not the identity"), y,
                   "{}: G.y", curve.name);
    }

    #[test]
    fn test_the_2001_curves_are_rfc_4357s() {
        for (set, curve) in [("A", gost256_a()), ("B", gost256_b()),
                             ("C", gost256_c())] {
            let v = rfc4357_parameters(set);
            same(&curve, &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]);
        }
    }

    /// XchA and XchB are two of the curves above under other names,
    /// which is what `oids::gost_curve_for` claims when it maps them.
    /// Compared parameter by parameter, because the claim is otherwise
    /// only as good as somebody's memory of RFC 4357.
    #[test]
    fn test_the_exchange_sets_are_the_curves_we_map_them_to() {
        assert_eq!(rfc4357_parameters("XchA"), rfc4357_parameters("A"),
                   "XchA is not CryptoPro-A after all");
        assert_eq!(rfc4357_parameters("XchB"), rfc4357_parameters("C"),
                   "XchB is not CryptoPro-C after all");

        // And that the mapping says so.
        use crate::x509::oids;
        assert_eq!(oids::gost_curve_for(oids::GOST_2001_CRYPTOPRO_XCHA),
                   Some("gost256-a"));
        assert_eq!(oids::gost_curve_for(oids::GOST_2001_CRYPTOPRO_XCHB),
                   Some("gost256-c"));
    }

    #[test]
    fn test_the_2012_curves_are_rfc_7836s() {
        // The 512 bit sets A and B, in the seven value form:
        // p, a, b, m, q, x, y.
        for (set, curve) in [("id-tc26-gost-3410-12-512-paramSetA", gost512_a()),
                             ("id-tc26-gost-3410-12-512-paramSetB", gost512_b())] {
            let v = rfc7836_parameters(set);
            assert_eq!(v.len(), 7, "{}", set);
            same(&curve, &v[1], &v[2], &v[0], &v[4], &v[5], &v[6]);
            // `m` is the order of the whole group and `q` the
            // subgroup's; these two curves have cofactor one, which is
            // the claim `h` makes.
            assert_eq!(v[3], v[4], "{}: m should equal q here", set);
            assert!(curve.h.is_one(), "{}: cofactor", set);
        }

        // And the two given in both forms, in the eleven value order:
        // p, a, b, e, d, m, q, x, y, u, v.
        for (set, curve) in [("id-tc26-gost-3410-2012-256-paramSetA",
                              gost256_tc26_a()),
                             ("id-tc26-gost-3410-2012-512-paramSetC",
                              gost512_c())] {
            let v = rfc7836_parameters(set);
            assert_eq!(v.len(), 11, "{}", set);
            same(&curve, &v[1], &v[2], &v[0], &v[6], &v[7], &v[8]);
            // The cofactor is `m / q`, and it is four on both. The
            // check is written as a multiplication so it cannot pass
            // on a truncating division.
            assert_eq!(curve.h.mul(&curve.n), v[5],
                       "{}: h * q is not m, so the cofactor is wrong", set);
            assert_eq!(curve.h, BigUint::from_u64(4), "{}: cofactor", set);
        }
    }
}

#[cfg(test)]
mod rfc5903_tests {
    /*
    The three NIST curves against RFC 5903, which prints each in full
    (section 3) and gives an exchange on each (section 8). P-256 and
    P-384 were typed long ago and have only been checked for
    consistency and against OpenSSL by differential test; P-521 was
    copied out of this document by script. Either way, the document is
    read back here and compared, so a digit that drifts fails a test
    that names the document.
    */

    use super::*;

    const RFC: &str = include_str!("../../rfcs/rfc5903.txt");

    /// The text from `heading` to the next numbered section.
    fn section(heading: &str, next: &str) -> &'static str {
        // The table of contents carries the same titles with one space
        // after the number; the body has two.
        let start = RFC.find(heading).expect(heading);
        let end = start + RFC[start..].find(next).expect(next);
        &RFC[start..end]
    }

    /// The hex rows under a line that is exactly `label`, up to the next
    /// blank line, as one number.
    fn value(section: &str, label: &str) -> BigUint {
        let mut lines = section.lines()
            .skip_while(|line| line.trim_end() != label);
        assert!(lines.next().is_some(), "{label} not found");
        let hex: String = lines.take_while(|line| !line.trim().is_empty())
            .flat_map(|line| line.split_whitespace()).collect();
        BigUint::from_hex(&hex).unwrap()
    }

    /// A curve, the headings around its section 3 parameters, and the
    /// headings around its section 8 exchange.
    type Row = (fn() -> Curve, &'static str, &'static str, &'static str, &'static str);

    const CURVES: [Row; 3] = [
        (p256, "3.1.  256-Bit", "3.2.  384-Bit", "8.1.  256-Bit", "8.2.  384-Bit"),
        (p384, "3.2.  384-Bit", "3.3.  521-Bit", "8.2.  384-Bit", "8.3.  521-Bit"),
        (p521, "3.3.  521-Bit", "4.  Security", "8.3.  521-Bit", "9.  Changes from"),
    ];

    #[test]
    fn test_the_nist_curves_are_the_ones_rfc_5903_prints() {
        for (curve, heading, next, _, _) in CURVES {
            let curve = curve();
            let text = section(heading, next);
            let p = value(text, "Group Prime/Irreducible Polynomial:");
            assert_eq!(curve.p, p, "{}: p", curve.name);
            assert_eq!(curve.a, p.sub(&BigUint::from_u64(3)).unwrap(),
                       "{}: a is -3", curve.name);
            assert_eq!(curve.b, value(text, "Group Curve b:"), "{}: b", curve.name);
            assert_eq!(curve.n, value(text, "Group Order:"), "{}: n", curve.name);
            assert_eq!(curve.g.x(), Some(&value(text, "gx:")), "{}: gx", curve.name);
            assert_eq!(curve.g.y(), Some(&value(text, "gy:")), "{}: gy", curve.name);
            assert_eq!(curve.h, BigUint::one(), "{}: h", curve.name);
        }
    }

    /// Section 8's exchanges: both public keys from their private keys,
    /// and the shared value from each side.
    #[test]
    fn test_the_rfc_5903_exchanges() {
        for (curve, _, _, heading, next) in CURVES {
            let curve = curve();
            let text = section(heading, next);
            let i = value(text, "i:");
            let r = value(text, "r:");
            let gi = Point::new(value(text, "gix:"), value(text, "giy:"));
            let gr = Point::new(value(text, "grx:"), value(text, "gry:"));
            let shared = value(text, "girx:")
                .to_bytes_be_padded(curve.field_bytes()).unwrap();

            let ours = curve.generator_mul(&i);
            assert_eq!((ours.x(), ours.y()), (gi.x(), gi.y()), "{}: g^i", curve.name);
            let ours = curve.generator_mul(&r);
            assert_eq!((ours.x(), ours.y()), (gr.x(), gr.y()), "{}: g^r", curve.name);
            assert_eq!(curve.ecdh(&i, &gr).unwrap(), shared, "{}: initiator", curve.name);
            assert_eq!(curve.ecdh(&r, &gi).unwrap(), shared, "{}: responder", curve.name);
        }
    }
}
