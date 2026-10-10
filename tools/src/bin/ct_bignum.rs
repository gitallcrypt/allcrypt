/*
ctgrind: find the places where `bignum` branches on a secret.

The idea is Adam Langley's. Valgrind's memcheck already tracks, bit by bit,
which values are "undefined" and complains when an undefined value reaches a
conditional jump or a memory address. That is exactly the property we want
from constant-time code, with "undefined" renamed "secret". So we tell
valgrind that a secret's bytes are undefined, run the operation, and every
complaint is a place where the secret reached a branch or an index.

What it catches: data dependent branches, table lookups indexed by a secret,
and early exits. What it does NOT catch: variable latency instructions
(division on some cores), compiler transformations applied after the
measurement, and anything the optimiser folded away before valgrind ever saw
it. It is a lower bound on the problems, not a proof of their absence.

**The trap this file is written against.** The first version of this harness
used a literal array as its secret. LLVM constant folded the branch, valgrind
saw nothing, and the harness reported a clean bill of health for code that
was plainly variable time. So every secret here is built at run time from
`std::env::args`, which the compiler cannot see through, and every case is
declared in the table below as `Constant` or `Variable`. A `Variable` case
that reports nothing fails the run just as loudly as a `Constant` case that
reports something - those are the positive controls, and without them a
harness that silently stopped working would read as success.

Run it through `scripts/ct_check.py`, which knows the expectations. By hand:

    cargo build --release -p allcrypt-tools --bin ct_bignum
    valgrind -q ./target/release/tools/src/bin/ct_bignum mod_inverse
*/

use allcrypt::api::{self, AnyBlockCipher, CipherStream, Mode};
use allcrypt::bignum::{BigUint, Montgomery, Secret};
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::ghash::Ghash;
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::ec::{curves, eddsa, sm2, x25519, x448, xeddsa};
use allcrypt::nacl;
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::hash_functions::streebog::Streebog;
use allcrypt::pq::{ml_dsa, ml_kem};
use allcrypt::publickey_ciphers::dh;
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};

// ------------------------------------------------------------ valgrind ---

/// Memcheck's client request numbers. `VG_USERREQ_TOOL_BASE('M','C')` is
/// 0x4d430000 and the requests follow it in the order memcheck.h declares
/// them: NOACCESS, UNDEFINED, DEFINED. Only the last two are used here.
const MAKE_MEM_UNDEFINED: u64 = 0x4D43_0001;
const MAKE_MEM_DEFINED: u64 = 0x4D43_0002;

/// The x86-64 client request sequence from valgrind.h: four rotations of
/// `rdi` that add up to 64 bits - so `rdi` comes out unchanged and the
/// sequence is a no-op on a real CPU - followed by `xchg rbx, rbx`, which
/// valgrind recognises. `rax` points at the argument block and the result
/// comes back in `rdx`.
///
/// Returns -1 when running under valgrind and the default (0) otherwise,
/// which is how `under_valgrind` below can tell.
#[cfg(target_arch = "x86_64")]
fn request(code: u64, ptr: *const u8, len: usize) -> i64 {
    let args: [u64; 6] = [code, ptr as u64, len as u64, 0, 0, 0];
    let mut result: u64 = 0;
    unsafe {
        core::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("dx") result,
            in("ax") args.as_ptr() as u64,
            options(nostack),
        );
    }
    // `args` must outlive the instruction; valgrind read it through rax.
    core::hint::black_box(&args);
    result as i64
}

#[cfg(not(target_arch = "x86_64"))]
fn request(_code: u64, _ptr: *const u8, _len: usize) -> i64 {
    0
}

fn under_valgrind() -> bool {
    let probe = [0u8; 1];
    request(MAKE_MEM_DEFINED, probe.as_ptr(), 1) == -1
}

/// Mark a slice secret. Everything computed from it stays secret until it is
/// declassified, and any branch on it is reported.
fn classify<T>(values: &[T]) {
    request(MAKE_MEM_UNDEFINED, values.as_ptr() as *const u8, core::mem::size_of_val(values));
}

/// Mark a slice public again - for a result we are about to print, or for a
/// value whose leakage is deliberate and argued.
fn declassify<T>(values: &[T]) {
    request(MAKE_MEM_DEFINED, values.as_ptr() as *const u8, core::mem::size_of_val(values));
}

// -------------------------------------------------------------- secrets ---

/// A secret the compiler cannot see through.
///
/// `scripts/ct_check.py` passes nothing extra, so the value is the fallback -
/// but it arrives via `args()`, so LLVM has to assume it could be anything.
/// Do not replace this with a literal: see the header.
fn secret_hex(fallback: &str) -> BigUint {
    let from_argv = std::env::args().nth(2);
    let text = from_argv.unwrap_or_else(|| fallback.to_string());
    let value = BigUint::from_hex(&text).expect("secret must be hex");
    classify(value.limbs());
    value
}

/// The same, widened to the fixed width the constant-time path uses.
fn secret_width(fallback: &str, k: usize) -> Secret {
    let from_argv = std::env::args().nth(2);
    let text = from_argv.unwrap_or_else(|| fallback.to_string());
    let value = BigUint::from_hex(&text).expect("secret must be hex");
    let wide = Secret::from_biguint(&value, k).expect("secret must fit the width");
    classify(wide.limbs());
    wide
}

/// A secret as raw bytes rather than a number, for the algorithms whose
/// key is a byte string: EdDSA's private key is 32 (or 57) bytes that
/// are hashed and clamped, never interpreted as an integer.
fn secret_bytes32(fallback: &str) -> Vec<u8> {
    let from_argv = std::env::args().nth(2);
    let text = from_argv.unwrap_or_else(|| fallback.to_string());
    let bytes: Vec<u8> = (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    // The valgrind client request takes u64s; a byte slice is marked
    // through its own address range just the same.
    request(MAKE_MEM_UNDEFINED, bytes.as_ptr(), bytes.len());
    bytes
}

/// Bytes from hex, unmarked: the public counterpart of `secret_bytes32`.
fn public_bytes(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// A public value, built the same way so the two differ only in the marking.
fn public_hex(fallback: &str) -> BigUint {
    let from_argv = std::env::args().nth(3);
    BigUint::from_hex(&from_argv.unwrap_or_else(|| fallback.to_string())).expect("hex")
}

/// 2048 bit RSA-shaped odd modulus. Public in every use here.
const MODULUS: &str = "c7b5b1c4f6e3a9d2b8f1e07c5a4936d8e2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a09\
f8e7d6c5b4a3928170615f4e3d2c1b0a9988776655443322110ffeeddccbbaa99887766554433221\
100fedcba9876543210f0e1d2c3b4a596879a8b7c6d5e4f30215243546576879a8b9c8d7e6f5041\
32231405f6e7d8c9bab9a8978695a4b3c2d1e0f00f1e2d3c4b5a69788796a5b4c3d2e1f00112233\
44556677889900aabbccddeeff102132435465768798a9bacbdcedfe0f1e2d3c4b5a697887766554\
433221100ffeeddccbbaa998877665544332211f0e1d2c3b4a5968778695a4b3c2d1e0fd9c8b7a6\
95847362514039281706f5e4d3c2b1a0918273645546372819aabbccddeeff00112233445566778\
899aabbccddeeff01";

/// A 256 bit prime - the P-256 field characteristic - for the cases that need
/// one. Fermat inversion is only an inversion modulo a prime.
const PRIME: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// Two 512 bit primes making a 1024 bit RSA modulus. Fixed rather than
/// generated: a prime search under valgrind would be the whole run, and the
/// point is the private operation, not how the key was made.
const RSA_P: &str = "e8dc9779087d3f4c7f8ebcbcf69108d2ab390849171d3473f98bbf44e9a6fe76\
8ec68c9dde26aa6221b499e2443ebd536f8ceb482755c1b124ed6bf4ffe2aab3";
const RSA_Q: &str = "d9c81dd66038e61f5bf258a4f3eeca4b6f0f07c16563976ab496d28e80da02d4\
1bae3754aafeba4d16851e08cb89d74a241e0233f9230f09503bc96f123895b1";

/// Mark everything a private key holds that must not reach a branch: the
/// primes, both CRT exponents, the coefficient and `d`.
fn classify_key(key: &RsaPrivateKey) {
    let (p, q) = key.primes();
    let (dp, dq, qinv) = key.crt_parameters();
    for value in [p, q, dp, dq, qinv, key.private_exponent()] {
        classify(value.limbs());
    }
}

/// A secret exponent of the shape an RSA private key has: a full width value
/// with no special structure.
const EXPONENT: &str = "9e3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a8b7c6d\
5e4f302152435465768798a9babcdcedfe0f1e2d3c4b5a6978877665544332211a0b1c2d3e4f506\
17283940516273849506172839405a6b7c8d9eaf0b1c2d3e4f50617283940516273849506172839\
40516273849506172839405b6c7d8e9fa0b1c2d3e4f5061728394051627384950617283940a1b2c\
3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9001122334455667788990\
0aabbccddeeff102132435465768798a9bacbdcedfe0f1e2d3c4b5a69788776655443322110fedc\
ba9876543210f0e1d2c3b4a596879a8b7c6d5e4f3021524354657687981b2c3d4e5f60718293a4b\
5c6d7e8f9a0b1c2d3";

// ---------------------------------------------------------------- cases ---

fn run(case: &str) {
    match case {
        // -- the constant-time path, which must come back clean ----------

        "pow_ct" => {
            let m = public_hex(MODULUS);
            let mont = Montgomery::new(&m).unwrap();
            let exp = secret_width(EXPONENT, mont.limbs());
            let base = Secret::from_biguint(&BigUint::from_hex("03").unwrap(), mont.limbs()).unwrap();
            let out = mont.pow_ct(&base, &exp, mont.modulus_bits());
            emit(&out);
        }

        "pow_ct_short" => {
            // The same call with a secret that happens to be small. The
            // iteration count is the modulus's width either way, so this
            // must be as clean as the case above - if it is not, the loop
            // bound has gone back to measuring the exponent.
            let m = public_hex(MODULUS);
            let mont = Montgomery::new(&m).unwrap();
            let exp = secret_width("0d3f7b21c5d80a46", mont.limbs());
            let base = Secret::from_biguint(&BigUint::from_hex("03").unwrap(), mont.limbs()).unwrap();
            let out = mont.pow_ct(&base, &exp, mont.modulus_bits());
            emit(&out);
        }

        "montgomery_mul" => {
            let m = public_hex(MODULUS);
            let mont = Montgomery::new(&m).unwrap();
            let a = secret_width(EXPONENT, mont.limbs());
            let wide = mont.to_domain(&a);
            emit(&mont.mul(&wide, &wide));
        }

        "montgomery_add_sub" => {
            let m = public_hex(MODULUS);
            let mont = Montgomery::new(&m).unwrap();
            let a = secret_width(EXPONENT, mont.limbs());
            let b = secret_width("0d3f7b21c5d80a46", mont.limbs());
            emit(&mont.add_mod(&a, &b));
            emit(&mont.sub_mod(&a, &b));
        }

        "inverse_prime" => {
            // A prime modulus, which is what Fermat inversion needs.
            let m = public_hex(PRIME);
            let mont = Montgomery::new(&m).unwrap();
            let a = secret_width("0d3f7b21c5d80a46f2e19b3c7d5a8064", mont.limbs());
            emit(&mont.inverse_prime(&a, mont.modulus_bits()));
        }

        "secret_compare" => {
            let m = public_hex(MODULUS);
            let k = m.limbs().len();
            let a = secret_width(EXPONENT, k);
            let b = secret_width("0d3f7b21c5d80a46", k);
            // Masks, not bools: none of these may reach a branch.
            let folded = a.ct_lt(&b) ^ a.ct_eq(&b) ^ a.ct_is_zero() ^ a.bit(17);
            let mut out = Secret::zero(k);
            out.limbs_mut()[0] = folded;
            emit(&out);
        }

        "secret_bytes" => {
            let m = public_hex(MODULUS);
            let k = m.limbs().len();
            let a = secret_width(EXPONENT, k);
            let bytes = a.to_bytes_be();
            declassify(&bytes);
            println!("{}", bytes.len());
        }

        // -- the call sites, which are what any of this was for -----------

        "rsa_private" => {
            // A 1024 bit key from fixed primes: generating one would spend
            // the whole run in Miller-Rabin, and the primes are the secret
            // whether they were generated or typed.
            let key = RsaPrivateKey::from_primes(
                BigUint::from_hex(RSA_P).unwrap(),
                BigUint::from_hex(RSA_Q).unwrap(),
                BigUint::from_u64(65537),
            ).unwrap();
            // Marked *after* construction: `from_primes` derives the CRT
            // parameters with ordinary arithmetic and is a key generation
            // step, not a per-operation one.
            classify_key(&key);
            let ciphertext = BigUint::from_hex("deadbeefcafebabe0123456789abcdef").unwrap();
            let plaintext = key.raw(&ciphertext).unwrap();
            publish(&plaintext);
        }

        "rsa_oaep_decode" => {
            // The padding check alone, on an encoded message made by the
            // private operation before anything is marked: the row above
            // measures that operation. What is marked is the whole block,
            // which is the secret the check must not branch on.
            let key = RsaPrivateKey::from_primes(
                BigUint::from_hex(RSA_P).unwrap(),
                BigUint::from_hex(RSA_Q).unwrap(),
                BigUint::from_u64(65537),
            ).unwrap();
            let size = key.size();
            let ciphertext = rsa::encrypt_oaep(&key.public, "sha256", "sha256", b"label",
                                               b"sixteen byte msg").unwrap();
            let mut em = key.raw(&BigUint::from_bytes_be(&ciphertext)).unwrap()
                .to_bytes_be_padded(size).unwrap();
            classify(&em);
            let length = oaep_output(rsa::eme_oaep_decode(&em, "sha256", "sha256", b"label"));
            assert_eq!(length, 16, "the block decodes");
            println!("{}", length);
            // And a block that fails, at the leading byte: Manger's oracle.
            em[0] = 1;
            classify(&em);
            let refused = oaep_output(rsa::eme_oaep_decode(&em, "sha256", "sha256", b"label"))
                == usize::MAX;
            println!("{}", refused);
        }

        "ecdsa_sign" => {
            let curve = curves::p256();
            let private = secret_hex("0d3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a");
            let digest = [0x5au8; 32];
            let signature = curve.sign(&private, &digest, SHA256::new(&[])).unwrap();
            publish(&signature.r);
            publish(&signature.s);
        }

        "gost_sign" => {
            // GOST R 34.10's `s = r d + k e` gives `d` from `k` by one
            // subtraction and one division, so the nonce and the key are
            // as secret as ECDSA's. Same shape as the row above: the
            // nonce stays bytes into a Secret, k*G runs on ec::fixed,
            // and the equation runs in the Montgomery domain over n.
            // The digest is Streebog's and the curve a GOST one; the
            // private key is the same secret as ecdsa_sign's.
            let curve = curves::by_name("gost256-a").unwrap();
            let private = secret_hex("0d3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a");
            let digest = [0x5au8; 32];
            let signature = curve.gost_sign(&private, &digest, Streebog::new_256(&[])).unwrap();
            publish(&signature.r);
            publish(&signature.s);
        }

        "eddsa_sign" => {
            // The long-term scalar is the *hash* of the private key,
            // clamped - so what reaches the multiplication is derived
            // from the secret rather than being it, and leaking it is
            // just as bad: `S = r + k*s` with a known `r` gives `s`.
            let private = secret_bytes32(
                "0d3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a");
            let signature = eddsa::sign(eddsa::Variant::Ed25519, &private,
                                        b"message digest", &[]).unwrap();
            println!("{}", signature.len());
        }

        "sm2_sign" => {
            // SM2's nonce reaches `scalar_mul_secret`, so the ladder
            // runs on a Secret exactly as ECDSA's does. What is left is
            // the arithmetic around it, which is still BigUint: the
            // inverse of (1 + d) and the product r*d both normalise.
            // See the note in ct_check.py's table.
            let curve = curves::sm2();
            let private = secret_hex(
                "0d3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a");
            let signature = sm2::sign(&curve, &private, sm2::DEFAULT_ID,
                                      b"message digest").unwrap();
            publish(&signature.r);
            publish(&signature.s);
        }

        "sm2_decrypt" => {
            // The private key multiplies an attacker-chosen point, which
            // is the shape that most wants the ladder.
            let curve = curves::sm2();
            let private = secret_hex(
                "0d3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a");
            let public = curve.generator_mul(&private);
            let ciphertext = sm2::encrypt(&curve, &public, b"sixteen byte msg").unwrap();
            let plaintext = sm2::decrypt(&curve, &private, &ciphertext).unwrap();
            println!("{}", plaintext.len());
        }

        "dh_shared" => {
            let group = dh::modp_group(dh::MODP_1024).unwrap();
            let private = secret_hex(
                "0d3f7b21c5d80a46f2e19b3c7d5a8064e1f2c3b4a5968778695a4b3c2d1e0f9a");
            let peer = BigUint::from_hex("04").unwrap();
            let shared = group.shared_secret(&private, &peer).unwrap();
            declassify(&shared);
            println!("{}", shared.len());
        }

        // -- ML-KEM ---------------------------------------------------------
        //
        // The key is made before anything is marked: key generation is
        // its own question. What is marked is everything in `dk` that is
        // secret - `dk_pke` and `z` - and for encapsulation, `m`. The
        // shared secret is declassified only to print it.

        "ml_kem_decaps" | "ml_kem_decaps_reject" => {
            let (set, _ek, dk, mut ciphertext) = ml_kem_fixture();
            if case == "ml_kem_decaps_reject" {
                // The implicit-rejection path must look the same as the
                // other one, so it gets a row of its own.
                ciphertext[0] ^= 1;
            }
            classify_ml_kem_dk(set, &dk);
            let shared = ml_kem::decapsulate_internal(set, &dk, &ciphertext)
                .unwrap();
            declassify(&shared);
            println!("{}", shared.len());
        }

        "ml_dsa_sign" => {
            // The key is made in the open, then everything in it that is
            // secret is marked: K (bytes 32..64), and s1, s2 and t0 (from
            // 128 on). rho and tr are public - tr is H(pk). mu is public
            // too; rnd is zero, the deterministic variant.
            let set = ml_dsa::parameters("ML-DSA-44").unwrap();
            let (_pk, sk) = ml_dsa::key_gen_internal(set, &runtime_bytes(32, 0x51))
                .unwrap();
            let mu = runtime_bytes(64, 0x52);
            classify(&sk[32..64]);
            classify(&sk[128..]);
            let signature = ml_dsa::sign_mu(set, &sk, &mu, &[0u8; 32]).unwrap();
            declassify(&signature);
            println!("{}", signature.len());
        }

        "ml_kem_compress_checked" => {
            // The positive control for the three rows around it: the
            // public, checked `Poly::compress` on a secret polynomial. Its
            // range check is a branch per coefficient, which is why
            // ML-KEM's own algorithms call the unchecked one - and if
            // this ever comes back clean, the ML-KEM rows' clean results
            // mean nothing.
            let mut poly = ml_kem::ring::Poly::zero();
            for (at, byte) in runtime_bytes(256, 0x44).iter().enumerate() {
                poly.coefficients[at] = *byte as u16 * 13;
            }
            classify(&poly.coefficients);
            let out = poly.compress(4).unwrap();
            declassify(&out.coefficients);
            println!("{}", out.coefficients[0]);
        }

        "ml_kem_encaps" => {
            let (set, ek, _dk, _ciphertext) = ml_kem_fixture();
            let m = runtime_bytes(32, 0x5a);
            classify(&m);
            let (shared, ciphertext) =
                ml_kem::encapsulate_internal(set, &ek, &m).unwrap();
            // The ciphertext is sent, so it is public from here on; the
            // shared secret is printed.
            declassify(&ciphertext);
            declassify(&shared);
            println!("{} {}", shared.len(), ciphertext.len());
        }

        // -- the variable-time path: positive controls -------------------

        "mod_inverse" => {
            // Extended Euclid, which cannot be made constant time in place.
            // The same prime `inverse_prime` uses, so the two rows differ in
            // the algorithm and nothing else.
            let a = secret_hex(EXPONENT);
            let m = public_hex(PRIME);
            let out = a.mod_inverse(&m).unwrap();
            publish(&out);
        }

        "mod_pow_ct_biguint" => {
            // The `BigUint` convenience wrapper. The exponentiation itself
            // is clean; the final `declassify` normalises the result, which
            // is a branch on it. Documented at `Secret::declassify`, and a
            // positive control here so the day it stops reporting is the day
            // somebody has to explain why.
            let exp = secret_hex(EXPONENT);
            let m = public_hex(MODULUS);
            let base = BigUint::from_hex("03").unwrap();
            let out = base.mod_pow_ct(&exp, &m).unwrap();
            publish(&out);
        }

        // -- the primitives everything is built from ---------------------

        "add" => {
            let a = secret_hex(EXPONENT);
            let b = public_hex(MODULUS);
            publish(&a.add(&b));
        }

        "mul" => {
            let a = secret_hex(EXPONENT);
            let b = public_hex(MODULUS);
            publish(&a.mul(&b));
        }

        "cmp" => {
            let a = secret_hex(EXPONENT);
            let b = public_hex(MODULUS);
            let bigger = a > b;
            println!("{}", bigger);
        }

        "rem" => {
            let a = secret_hex(EXPONENT);
            let m = public_hex(MODULUS);
            publish(&a.rem(&m).unwrap());
        }

        "mod_pow_public" => {
            // The variable-time path, run on a secret exponent on purpose.
            // This is the positive control: if this case ever comes back
            // clean, the harness has stopped working.
            let exp = secret_hex(EXPONENT);
            let m = public_hex(MODULUS);
            let base = BigUint::from_hex("03").unwrap();
            publish(&base.mod_pow(&exp, &m).unwrap());
        }

        "to_bytes" => {
            let a = secret_hex(EXPONENT);
            let bytes = a.to_bytes_be();
            declassify(&bytes);
            println!("{}", bytes.len());
        }

        // -- AES and GHASH ---------------------------------------------
        //
        // The key and the data are both secret: the table path leaks
        // through either. A key schedule is part of every case, since
        // setting the key is where a table-indexed SubWord would leak.

        "ed448_sign" => {
            let private = secret_bytes32(concat!(
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3",
                "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"));
            let signature = eddsa::sign(eddsa::Variant::Ed448, &private,
                                        b"message digest", b"context").unwrap();
            println!("{}", signature.len());
        }

        "xeddsa_sign" => {
            // The specification form: whether the key or its negation
            // signs depends on the sign of the secret point's x, and is
            // taken by a mask rather than a branch. The Signal form runs
            // too; it publishes that bit in S by design.
            let private: [u8; 32] = secret_bytes32(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .try_into().unwrap();
            for form in [xeddsa::Form::Specification, xeddsa::Form::Signal] {
                let signature = xeddsa::sign(form, &private, b"message", &[7u8; 64]).unwrap();
                publish_bytes(&signature);
            }
        }

        "x25519" => {
            // The raw primitive rather than `exchange`: the all-zero
            // refusal is a branch on the output, which is the verdict the
            // caller acts on, and would be reported as such.
            let scalar: [u8; 32] = secret_bytes32(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .try_into().unwrap();
            let point = x25519::public_key(&[0x42; 32]).unwrap();
            publish_bytes(&x25519::x25519(&scalar, &point).unwrap());
        }

        "x25519_exchange" => {
            let private: [u8; 32] = secret_bytes32(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
                .try_into().unwrap();
            let peer = x25519::public_key(&[0x42; 32]).unwrap();
            publish_bytes(&x25519::exchange(&private, &peer).unwrap());
        }

        "x448_exchange" => {
            let private: [u8; 56] = secret_bytes32(concat!(
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121",
                "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"))
                .try_into().unwrap();
            let peer = x448::public_key(&[0x42; 56]).unwrap();
            publish_bytes(&x448::exchange(&private, &peer).unwrap());
        }

        "x448" => {
            let scalar: [u8; 56] = secret_bytes32(concat!(
                "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121",
                "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"))
                .try_into().unwrap();
            let point = x448::public_key(&[0x42; 56]).unwrap();
            publish_bytes(&x448::x448(&scalar, &point).unwrap());
        }

        "aes_blocks" => {
            let key = secret_bytes32(AES_KEY);
            let mut data = secret_bytes32(AES_DATA);
            let mut aes = AesCrypto::new(&key).unwrap();
            // 21 blocks: one sixteen-block batch, one of four, and a
            // padded tail of one.
            aes.encrypt_blocks(&mut data[..21 * 16]).unwrap();
            aes.decrypt_blocks(&mut data[..21 * 16]).unwrap();
            publish_bytes(&data);
        }

        "aes_block_table" => {
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let mut aes = AesCrypto::new(&key).unwrap();
            let mut out = Vec::new();
            aes.block_encrypt(&data[..16], &mut out);
            publish_bytes(&out);
        }

        "aes_gcm_seal" => {
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let (ciphertext, tag) = api::aead_encrypt("aes-gcm", &key, &[7u8; 12], b"header",
                                                      &data[..333]).unwrap();
            publish_bytes(&ciphertext);
            publish_bytes(&tag);
        }

        "aes_xts" => {
            let key = secret_bytes32(AES_XTS_KEY);
            let data = secret_bytes32(AES_DATA);
            // Not a whole number of blocks, so ciphertext stealing runs too.
            let sealed = api::xts_encrypt("aes", &key, 5, &data[..20 * 16 + 5]).unwrap();
            let opened = api::xts_decrypt("aes", &key, 5, &sealed).unwrap();
            publish_bytes(&opened);
        }

        "aes_ctr_cbc_decrypt" => {
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let iv = [3u8; 16];
            let cipher = AnyBlockCipher::new("aes", &key, None).unwrap();
            let mut ctr = CipherStream::new(cipher, Mode::Ctr, &iv, false).unwrap();
            let mut out = ctr.update(&data[..333]).unwrap();
            let cipher = AnyBlockCipher::new("aes", &key, None).unwrap();
            let mut cbc = CipherStream::new(cipher, Mode::Cbc, &iv, true).unwrap();
            out.extend(cbc.update(&data[..21 * 16]).unwrap());
            publish_bytes(&out);
        }

        "ghash" => {
            let h = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let mut ghash = Ghash::new(&h[..16]).unwrap();
            ghash.update(&data[..333]);
            publish_bytes(&ghash.digest());
        }

        "poly1305" => {
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let mut mac = allcrypt::mac::poly1305::Poly1305::new(&key[..32]).unwrap();
            // 333 bytes: five four-block groups, one single block and a
            // short final one, so every path is reached.
            allcrypt::Mac::update(&mut mac, &data[..333]);
            publish_bytes(&mac.tag());
        }

        "chacha20_poly1305_seal" => {
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let (ciphertext, tag) = api::aead_encrypt("chacha20-poly1305", &key[..32], &[7u8; 12],
                                                      b"header", &data[..333]).unwrap();
            publish_bytes(&ciphertext);
            publish_bytes(&tag);
        }

        "secretbox_seal" => {
            // Both constructions: HSalsa20 or HChaCha20 for the subkey,
            // the stream from byte 32, and Poly1305 over the ciphertext.
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            for construction in [nacl::Construction::XSalsa20Poly1305,
                                 nacl::Construction::XChaCha20Poly1305] {
                let boxed = nacl::secretbox_encrypt(construction, &key[..32], &[7u8; 24],
                                                    &data[..333]).unwrap();
                publish_bytes(&boxed);
            }
        }

        "secretbox_open" => {
            // A box sealed under a public key, opened under the same key
            // marked secret: everything up to the verdict.
            let boxed = nacl::secretbox_encrypt(nacl::Construction::XSalsa20Poly1305,
                                                &public_bytes(AES_KEY)[..32], &[7u8; 24],
                                                &public_bytes(AES_DATA)[..333]).unwrap();
            let key = secret_bytes32(AES_KEY);
            let opened = nacl::secretbox_decrypt(nacl::Construction::XSalsa20Poly1305,
                                                 &key[..32], &[7u8; 24], &boxed).unwrap();
            publish_bytes(&opened);
        }

        "box_beforenm" => {
            let private = secret_bytes32(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
            let peer = x25519::public_key(&[0x42; 32]).unwrap();
            for construction in [nacl::Construction::XSalsa20Poly1305,
                                 nacl::Construction::XChaCha20Poly1305] {
                publish_bytes(&nacl::box_beforenm(construction, &peer, &private).unwrap());
            }
        }

        // -- the modes the review moved onto the batch path -------------

        "aes_ocb_open" => {
            // Sealed under the key as public, opened with it marked secret:
            // the offsets, the batched blocks, the checksum and the tag
            // comparison, up to the verdict.
            let (ciphertext, tag) = api::aead_encrypt("aes-ocb", &public_bytes(AES_KEY)[..16],
                                                      &[7u8; 12], b"header",
                                                      &public_bytes(AES_DATA)[..333]).unwrap();
            let key = secret_bytes32(AES_KEY);
            let opened = api::aead_decrypt("aes-ocb", &key[..16], &[7u8; 12], b"header",
                                           &ciphertext, &tag).unwrap();
            publish_bytes(&opened);
        }

        "aes_mgm_open" => {
            let (ciphertext, tag) = api::aead_encrypt("aes-mgm", &public_bytes(AES_KEY),
                                                      &[7u8; 16], b"header",
                                                      &public_bytes(AES_DATA)[..333]).unwrap();
            let key = secret_bytes32(AES_KEY);
            let opened = api::aead_decrypt("aes-mgm", &key, &[7u8; 16], b"header",
                                           &ciphertext, &tag).unwrap();
            publish_bytes(&opened);
        }

        "aes_lrw" => {
            // A secret cipher key and a secret tweak key: the tweak
            // multiplication and the batched blocks, both directions.
            let key = secret_bytes32(AES_KEY);
            let tweak: [u8; 16] = secret_bytes32(AES_XTS_KEY)[..16].try_into().unwrap();
            let data = secret_bytes32(AES_DATA);
            let mut aes = AesCrypto::new(&key[..16]).unwrap();
            let index = [0u8; 16];
            let sealed = allcrypt::block_ciphers::lrw::encrypt(&mut aes, &tweak, &index,
                                                               &data[..21 * 16]).unwrap();
            let opened = allcrypt::block_ciphers::lrw::decrypt(&mut aes, &tweak, &index,
                                                               &sealed).unwrap();
            publish_bytes(&opened);
        }

        "aes_ctr_acpkm" => {
            // Sections of two blocks, so the key changes several times.
            let key = secret_bytes32(AES_KEY);
            let data = secret_bytes32(AES_DATA);
            let out = allcrypt::block_ciphers::acpkm::ctr_acpkm("aes", &key, &[3u8; 8], 32,
                                                                &data[..333]).unwrap();
            publish_bytes(&out);
        }

        "tls_mte_open" => {
            // A TLS 1.2 AES-CBC-HMAC-SHA256 record, MAC-then-encrypt,
            // written under keys taken as public and read under the same
            // keys marked secret - so everything decrypted from it is
            // secret too: the padding, its length, and the MAC position
            // the padding implies, which is Lucky 13's whole subject.
            use allcrypt::tls::record::{CbcHmac, Protection, RecordReader, RecordWriter};
            use allcrypt::tls::{ContentType, Version};
            let protection = |key: &[u8], mac_key: &[u8]| Protection::CbcHmac(
                CbcHmac::new("aes", "sha256", &key[..16], &mac_key[..32], &[0u8; 16],
                             Version::TLS12).unwrap());
            let mut writer = RecordWriter::new(Version::TLS12);
            writer.change_cipher_spec(protection(&public_bytes(AES_KEY),
                                                 &public_bytes(AES_XTS_KEY)));
            let wire = writer.write(ContentType::ApplicationData,
                                    &public_bytes(AES_DATA)[..333]).unwrap();
            let mut reader = RecordReader::new();
            reader.expect_version(Version::TLS12);
            reader.change_cipher_spec(protection(&secret_bytes32(AES_KEY),
                                                 &secret_bytes32(AES_XTS_KEY)));
            reader.push_incoming(&wire);
            let record = reader.read().unwrap().expect("one record");
            publish_bytes(&record.payload);
        }

        other => {
            eprintln!("unknown case {:?}", other);
            std::process::exit(2);
        }
    }
}

const AES_KEY: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const AES_XTS_KEY: &str = "27182818284590452353602874713526624977572470936999595749669676273141592653589793238462643383279502884197169399375105820974944592";
/// 336 bytes: 21 blocks.
const AES_DATA: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\
6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\
6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\
6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\
6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710\
6bc1bee22e409f96e93d7e117393172a";

/// Print bytes, lifting the marking at the boundary as `publish` does.
fn publish_bytes(bytes: &[u8]) {
    request(MAKE_MEM_DEFINED, bytes.as_ptr(), bytes.len());
    println!("{}", bytes.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>());
}

/// The caller's side of an OAEP decode: whether it succeeded, and the
/// message, whose length is the separator's position. Both are the
/// output, so branching on them and freeing the message are the
/// caller's business and the rsa_oaep_decode row accepts them under this
/// name. Never inlined, because a valgrind that attributes an inlined
/// frame to its enclosing function - 3.18 does, for the `unwrap` and the
/// `Vec`'s free here - would otherwise name all of `run`, behind which
/// any leak in the harness could hide. What it returns is declassified,
/// so `run` never branches on anything secret: the length, or
/// `usize::MAX` for a refusal.
#[inline(never)]
fn oaep_output(result: Result<Vec<u8>, String>) -> usize {
    let mut length = [usize::MAX];
    if let Ok(message) = result {
        length[0] = message.len();
        declassify(&message);
    }
    declassify(&length);
    length[0]
}

/// The control for `ct_check.py`'s division scan: a function that does
/// nothing but divide two run-time values, so the scan is known to be able
/// to see a `div` before it is believed about ML-KEM having none.
#[inline(never)]
fn division_control(a: u32, b: u32) -> u32 {
    a / b
}

/// Bytes the compiler cannot see through: argv's third argument if there
/// is one, else `fill` - which still arrives through `std::env::args`
/// being consulted, so nothing here is a literal LLVM can fold.
fn runtime_bytes(len: usize, fill: u8) -> Vec<u8> {
    let seed = std::env::args().nth(3).map(|text| text.len() as u8)
        .unwrap_or(fill);
    (0..len).map(|at| seed.wrapping_add(at as u8)).collect()
}

/// An ML-KEM-768 key pair and an honest ciphertext for it, all public at
/// this point.
fn ml_kem_fixture() -> (&'static ml_kem::Parameters, Vec<u8>, Vec<u8>, Vec<u8>) {
    let set = ml_kem::parameters("ML-KEM-768").unwrap();
    let (ek, dk) = ml_kem::key_gen_internal(
        set, &runtime_bytes(32, 0x11), &runtime_bytes(32, 0x22)).unwrap();
    let (_shared, ciphertext) =
        ml_kem::encapsulate_internal(set, &ek, &runtime_bytes(32, 0x33))
            .unwrap();
    (set, ek, dk, ciphertext)
}

/// Mark the secret parts of a decapsulation key: `dk_pke`, the first
/// `384k` bytes, and `z`, the last 32. The `ek` and `H(ek)` between them
/// are public, and marking them would report the hash check's comparison
/// - a branch on public data.
fn classify_ml_kem_dk(set: &ml_kem::Parameters, dk: &[u8]) {
    classify(&dk[..384 * set.k]);
    classify(&dk[dk.len() - 32..]);
}

/// Print a result. Declassifying first is not a cheat: the caller is about to
/// hand the value to somebody, and `to_hex` would otherwise report a branch
/// on every secret in the program regardless of the operation under test.
fn publish(value: &BigUint) {
    declassify(value.limbs());
    let text = value.to_hex();
    println!("{}", &text[..text.len().min(16)]);
}

/// The same for a `Secret`. Printing it is what a caller would do with the
/// answer; the marking is lifted at exactly that point and not before, so
/// everything the operation itself did is still under scrutiny.
fn emit(value: &Secret) {
    declassify(value.limbs());
    println!("{:016x}", value.limbs()[0]);
}

fn main() {
    let case = std::env::args().nth(1).unwrap_or_default();
    if case == "--list" {
        for name in CASES {
            println!("{}", name);
        }
        return;
    }
    if case == "--self-test" {
        // Proves the marking reaches valgrind at all, independently of any
        // expectation about bignum. Under valgrind this must report; run
        // without it, it prints "not under valgrind" and exits 3.
        if !under_valgrind() {
            println!("not under valgrind");
            std::process::exit(3);
        }
        let secret = secret_hex("ff");
        let branched = !secret.is_zero() && secret.limbs()[0] > 3;
        println!("{}", branched);
        return;
    }
    if case == "--division-control" {
        // Never run by the harness - it only needs the function to exist
        // in the binary - but called from here so it is not dropped.
        let n = std::env::args().count() as u32;
        println!("{}", division_control(1000, n));
        return;
    }
    if case.is_empty() {
        eprintln!("usage: ct_bignum <case>|--list|--self-test");
        std::process::exit(2);
    }
    run(&case);
}

/// Every case, in the order `scripts/ct_check.py` reports them. The verdict
/// each one is expected to produce lives in that script, beside the reason.
const CASES: &[&str] = &[
    "pow_ct",
    "pow_ct_short",
    "montgomery_mul",
    "montgomery_add_sub",
    "inverse_prime",
    "secret_compare",
    "secret_bytes",
    "rsa_private",
    "rsa_oaep_decode",
    "ecdsa_sign",
    "gost_sign",
    "eddsa_sign",
    "ed448_sign",
    "xeddsa_sign",
    "x25519",
    "x448",
    "x25519_exchange",
    "x448_exchange",
    "sm2_sign",
    "sm2_decrypt",
    "dh_shared",
    "ml_kem_decaps",
    "ml_kem_decaps_reject",
    "ml_kem_encaps",
    "ml_kem_compress_checked",
    "ml_dsa_sign",
    "mod_inverse",
    "mod_pow_ct_biguint",
    "add",
    "mul",
    "cmp",
    "rem",
    "mod_pow_public",
    "to_bytes",
    "aes_blocks",
    "aes_block_table",
    "aes_gcm_seal",
    "aes_xts",
    "aes_ctr_cbc_decrypt",
    "ghash",
    "poly1305",
    "chacha20_poly1305_seal",
    "secretbox_seal",
    "secretbox_open",
    "box_beforenm",
    "aes_ocb_open",
    "aes_mgm_open",
    "aes_lrw",
    "aes_ctr_acpkm",
    "tls_mte_open",
];
