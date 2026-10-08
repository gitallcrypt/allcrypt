//! Timing measured on the machine itself: dudect (Reparaz, Balasch and
//! Verbauwhede, "Dude, is my code constant time?", DATE 2017).
//!
//! `ct_check.py` asks valgrind whether a secret reaches a branch or an
//! address, which is a property of the compiled code. This asks the
//! processor. Each target runs on two classes of input - one fixed
//! secret, and fresh random secrets - interleaved at random, and every
//! run is timed. If the code's time does not depend on the secret, the
//! two distributions of times are the same; Welch's t-test says how
//! confidently they differ. It sees what valgrind cannot: an instruction
//! whose latency depends on its operands, a microcode quirk, a compiler
//! output that valgrind's model treats as constant and the silicon does
//! not.
//!
//! What it does not do is prove anything. A small |t| over a million
//! runs is evidence, not a guarantee; a difference smaller than the
//! noise is not seen. So the table has controls, as `ct_check.py`'s
//! does:
//!
//!   * `control_memcmp` and `control_biguint_pow` are variable time on
//!     purpose and **must** show a large |t|. If they do not, the
//!     machine is too noisy, or the measurement has stopped working, and
//!     no clean row means anything.
//!   * `control_xor` does the same work whatever its input; a large |t|
//!     there means the two classes differ for a reason that is not the
//!     code - the environment - and the run says so instead of blaming
//!     a target.
//!
//! Run it on the machine whose behaviour matters, after building with
//! the toolchain that matters:
//!
//!     cargo run --release -p allcrypt-tools --bin dudect            # 10 s a row
//!     cargo run --release -p allcrypt-tools --bin dudect -- --seconds 60
//!     cargo run --release -p allcrypt-tools --bin dudect -- x25519 poly1305
//!
//! `docs/building.md` ("Checking constant time") has how to read it.
//!
//! The statistics follow dudect's reference code: the measurements are
//! tested whole and also cropped at a series of percentiles, because a
//! leak can be a small shift in the body of the distribution that the
//! long tail of interrupts would otherwise swamp; the largest |t| of the
//! tests is reported. |t| above 10 is "definitely not constant time" in
//! the paper's terms; 4.5 to 10 is worth a longer run.

use std::hint::black_box;
use std::time::{Duration, Instant};

use allcrypt::api;
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, eddsa, x25519};
use allcrypt::hash_functions::sha2::SHA256;
use allcrypt::nacl;
use allcrypt::pq::ml_kem;

/// |t| above this, and the distributions differ: the paper's threshold.
const LEAK: f64 = 10.0;
/// |t| above this and below `LEAK`: inconclusive, run longer.
const SUSPECT: f64 = 4.5;
/// Measurements discarded at the start of each row, while caches and the
/// frequency settle, and used to place the cropping percentiles.
const WARM_UP: usize = 10_000;
/// Inputs prepared at a time, outside the timed region.
const BATCH: usize = 1_000;
/// The number of cropped tests, as in dudect.
const CROPS: usize = 20;

/// A timestamp: the cycle counter between fences on x86-64, a monotonic
/// clock elsewhere. Only differences matter.
#[inline(always)]
fn now() -> u64 {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: lfence and rdtsc have no memory operands and are available
    // on every x86-64 processor.
    unsafe {
        use core::arch::x86_64::{_mm_lfence, _rdtsc};
        _mm_lfence();
        let t = _rdtsc();
        _mm_lfence();
        t
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use std::sync::OnceLock;
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}

/// xorshift64*, for the class choices and the random inputs. Seeded from
/// the operating system, so two runs do not see the same sequence.
struct Rng(u64);

impl Rng {
    fn new() -> Rng {
        let mut seed = [0u8; 8];
        allcrypt::random::fill(&mut seed).expect("the system random source");
        Rng(u64::from_le_bytes(seed) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 56) as u8).collect()
    }
}

/// Welch's t over two classes, accumulated online (Welford).
#[derive(Clone, Copy, Default)]
struct Welch {
    n: [f64; 2],
    mean: [f64; 2],
    m2: [f64; 2],
}

impl Welch {
    fn push(&mut self, class: usize, x: f64) {
        self.n[class] += 1.0;
        let delta = x - self.mean[class];
        self.mean[class] += delta / self.n[class];
        self.m2[class] += delta * (x - self.mean[class]);
    }

    fn t(&self) -> f64 {
        if self.n[0] < 2.0 || self.n[1] < 2.0 {
            return 0.0;
        }
        let var0 = self.m2[0] / (self.n[0] - 1.0);
        let var1 = self.m2[1] / (self.n[1] - 1.0);
        let denominator = (var0 / self.n[0] + var1 / self.n[1]).sqrt();
        if denominator == 0.0 {
            return 0.0;
        }
        (self.mean[0] - self.mean[1]) / denominator
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Claimed constant time: |t| must stay under `LEAK`.
    Constant,
    /// A control that is variable time on purpose: |t| must exceed `LEAK`.
    Leaks,
    /// The environment check: no code difference between the classes.
    Sanity,
}

struct Outcome {
    measurements: usize,
    max_t: f64,
    mean_cycles: f64,
}

/// Measure one target for `budget`. `prepare(rng, fixed)` builds an
/// input of the fixed class or a random one, outside the timed region;
/// `run` is the operation, timed.
fn measure<I>(budget: Duration, mut prepare: impl FnMut(&mut Rng, bool) -> I,
              run: impl Fn(&I)) -> Outcome {
    let mut rng = Rng::new();
    let mut warm: Vec<u64> = Vec::with_capacity(WARM_UP);
    let mut tests = [Welch::default(); CROPS + 1];
    let mut thresholds = [u64::MAX; CROPS];
    let mut measurements = 0usize;
    let mut total = 0f64;
    let start = Instant::now();
    while start.elapsed() < budget || warm.len() < WARM_UP {
        let classes: Vec<usize> = (0..BATCH).map(|_| (rng.next() >> 63) as usize).collect();
        let inputs: Vec<I> = classes.iter().map(|&c| prepare(&mut rng, c == 0)).collect();
        for (input, &class) in inputs.iter().zip(&classes) {
            let before = now();
            run(input);
            let elapsed = now().wrapping_sub(before);
            if warm.len() < WARM_UP {
                warm.push(elapsed);
                if warm.len() == WARM_UP {
                    // dudect's percentiles: 1 - 0.5^(10 (i + 1) / CROPS),
                    // denser towards the top, where the noise is.
                    let mut sorted = warm.clone();
                    sorted.sort_unstable();
                    for (i, threshold) in thresholds.iter_mut().enumerate() {
                        let p = 1.0 - 0.5f64.powf(10.0 * (i + 1) as f64 / CROPS as f64);
                        *threshold = sorted[((p * WARM_UP as f64) as usize).min(WARM_UP - 1)];
                    }
                }
                continue;
            }
            let x = elapsed as f64;
            measurements += 1;
            total += x;
            tests[0].push(class, x);
            for (test, threshold) in tests[1..].iter_mut().zip(&thresholds) {
                if elapsed < *threshold {
                    test.push(class, x);
                }
            }
        }
    }
    let max_t = tests.iter().map(|t| t.t().abs()).fold(0.0, f64::max);
    Outcome { measurements, max_t, mean_cycles: total / measurements.max(1) as f64 }
}

type Target = (&'static str, Expect, &'static str, fn(Duration) -> Outcome);

fn targets() -> Vec<Target> {
    vec![
        ("control_xor", Expect::Sanity,
         "XOR of 64 bytes: no difference between the classes but the data",
         |budget| measure(budget, |rng, fixed| if fixed { vec![0x5a; 64] } else { rng.bytes(64) },
                          |input: &Vec<u8>| {
                              let mut acc = [0u8; 64];
                              for (a, b) in acc.iter_mut().zip(input) {
                                  *a ^= b;
                              }
                              black_box(acc);
                          })),
        ("control_memcmp", Expect::Leaks,
         "slice == over 4096 bytes: the fixed class differs only in the last byte, \
          the random one in the first",
         |budget| {
             let reference = vec![0x33u8; 4096];
             measure(budget, |rng, fixed| {
                 let mut candidate = if fixed { reference.clone() } else { rng.bytes(4096) };
                 if fixed {
                     candidate[4095] ^= 1;
                 } else {
                     candidate[0] = 0x34;
                 }
                 candidate
             }, |candidate: &Vec<u8>| { black_box(black_box(&reference[..]) == &candidate[..]); })
         }),
        ("control_biguint_pow", Expect::Leaks,
         "BigUint::mod_pow, square and multiply on the exponent's bits: a fixed \
          exponent of weight one against random 256 bit ones",
         |budget| {
             let modulus = curves::p256().p.clone();
             let base = BigUint::from_u64(0x1234_5678_9abc_def1);
             measure(budget, |rng, fixed| {
                 if fixed {
                     BigUint::one().shl(255)
                 } else {
                     BigUint::from_bytes_be(&rng.bytes(32))
                 }
             }, |exponent: &BigUint| { let _ = black_box(base.mod_pow(exponent, &modulus)); })
         }),
        ("x25519", Expect::Constant, "the ladder, secret scalar, public point",
         |budget| {
             let point = x25519::public_key(&[0x42; 32]).unwrap();
             measure(budget, |rng, fixed| {
                 let scalar: [u8; 32] = if fixed { [0x11; 32] } else {
                     rng.bytes(32).try_into().unwrap()
                 };
                 scalar
             }, |scalar: &[u8; 32]| { black_box(x25519::x25519(scalar, &point).unwrap()); })
         }),
        ("ed25519_sign", Expect::Constant, "signing, secret seed, fixed message",
         |budget| measure(budget, |rng, fixed| if fixed { vec![0x22; 32] } else { rng.bytes(32) },
                          |seed: &Vec<u8>| {
                              black_box(eddsa::sign(eddsa::Variant::Ed25519, seed, b"message",
                                                    &[]).unwrap());
                          })),
        ("ecdsa_p256_sign", Expect::Constant,
         "signing with RFC 6979 nonces, secret key, fixed digest",
         |budget| {
             let curve = curves::p256();
             measure(budget, |rng, fixed| {
                 let mut bytes = if fixed { vec![0x33; 32] } else { rng.bytes(32) };
                 bytes[0] &= 0x7f; // below the group order
                 BigUint::from_bytes_be(&bytes)
             }, |private: &BigUint| {
                 black_box(curve.sign(private, &[0x5a; 32], SHA256::new(&[])).unwrap());
             })
         }),
        ("ml_kem_768_decaps", Expect::Constant,
         "decapsulation of the valid ciphertext against random ones: the implicit \
          rejection must take as long as acceptance",
         |budget| {
             let set = ml_kem::parameters("ML-KEM-768").unwrap();
             let (ek, dk) = ml_kem::key_gen_internal(set, &[1; 32], &[2; 32]).unwrap();
             let (_, valid) = ml_kem::encapsulate_internal(set, &ek, &[3; 32]).unwrap();
             let length = valid.len();
             measure(budget, |rng, fixed| if fixed { valid.clone() } else { rng.bytes(length) },
                     |ciphertext: &Vec<u8>| {
                         black_box(ml_kem::decapsulate_internal(set, &dk, ciphertext).unwrap());
                     })
         }),
        ("aes_ecb_bitsliced", Expect::Constant,
         "eight AES-256 blocks through the bitsliced path, fixed key, secret data",
         |budget| measure(budget, |rng, fixed| if fixed { vec![0x44; 128] } else { rng.bytes(128) },
                          |data: &Vec<u8>| {
                              let cipher = api::AnyBlockCipher::new("aes", &[7; 32], None).unwrap();
                              let mut stream = api::CipherStream::new(cipher, api::Mode::Ecb,
                                                                      &[], false).unwrap();
                              black_box(stream.update(data).unwrap());
                          })),
        ("poly1305", Expect::Constant, "a 333 byte message under a secret key",
         |budget| measure(budget, |rng, fixed| if fixed { vec![0x55; 32] } else { rng.bytes(32) },
                          |key: &Vec<u8>| {
                              let mut mac = allcrypt::mac::Poly1305::new(key).unwrap();
                              allcrypt::Mac::update(&mut mac, &[0x66; 333]);
                              black_box(mac.tag());
                          })),
        ("chacha20_poly1305_seal", Expect::Constant, "333 bytes sealed under a secret key",
         |budget| measure(budget, |rng, fixed| if fixed { vec![0x77; 32] } else { rng.bytes(32) },
                          |key: &Vec<u8>| {
                              black_box(api::aead_encrypt("chacha20-poly1305", key, &[1; 12],
                                                          b"header", &[0x88; 333]).unwrap());
                          })),
        ("secretbox_tag_check", Expect::Constant,
         "a forged tag differing from the right one in its last byte against random \
          tags: both are refused, and the comparison must not stop early",
         |budget| {
             let construction = nacl::Construction::XSalsa20Poly1305;
             let (ciphertext, tag) = nacl::secretbox_encrypt_detached(
                 construction, &[9; 32], &[1; 24], &[0x99; 333]).unwrap();
             measure(budget, |rng, fixed| {
                 let mut forged = if fixed { tag.to_vec() } else { rng.bytes(16) };
                 if fixed {
                     forged[15] ^= 1;
                 } else {
                     forged[0] = tag[0] ^ 1;
                 }
                 forged
             }, |forged: &Vec<u8>| {
                 black_box(nacl::secretbox_decrypt_detached(construction, &[9; 32], &[1; 24],
                                                            &ciphertext, forged).is_err());
             })
         }),
        ("box_beforenm", Expect::Constant, "the box key from a secret X25519 key",
         |budget| {
             let peer = x25519::public_key(&[0x42; 32]).unwrap();
             measure(budget, |rng, fixed| if fixed { vec![0xaa; 32] } else { rng.bytes(32) },
                     |private: &Vec<u8>| {
                         black_box(nacl::box_beforenm(nacl::Construction::XSalsa20Poly1305,
                                                      &peer, private).unwrap());
                     })
         }),
    ]
}

fn cpu() -> String {
    std::fs::read_to_string("/proc/cpuinfo").ok()
        .and_then(|text| text.lines().find(|l| l.starts_with("model name"))
                  .and_then(|l| l.split(':').nth(1)).map(|s| s.trim().to_string()))
        .unwrap_or_else(|| std::env::consts::ARCH.to_string())
}

fn main() {
    let mut seconds = 10u64;
    let mut wanted = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seconds" => {
                seconds = args.next().and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| { eprintln!("--seconds takes a number"); std::process::exit(2) });
            }
            "--list" => {
                for (name, _, why, _) in targets() {
                    println!("{name:24} {why}");
                }
                return;
            }
            other if other.starts_with('-') => {
                eprintln!("usage: dudect [--seconds N] [--list] [target...]");
                std::process::exit(2);
            }
            other => wanted.push(other.to_string()),
        }
    }
    let table: Vec<Target> = targets().into_iter()
        .filter(|t| wanted.is_empty() || wanted.iter().any(|w| w == t.0)).collect();
    if table.is_empty() {
        eprintln!("no such target; --list names them");
        std::process::exit(2);
    }
    if cfg!(debug_assertions) {
        eprintln!("dudect: a debug build measures the debug build. Use --release.");
    }
    println!("dudect on {}, {} s a row; |t| > {LEAK} differs, {SUSPECT} to {LEAK} \
              inconclusive", cpu(), seconds);
    let mut environment_noisy = false;
    let mut failures = Vec::new();
    for (name, expect, why, run) in table {
        let outcome = run(Duration::from_secs(seconds));
        let verdict = match expect {
            Expect::Sanity if outcome.max_t > LEAK => {
                environment_noisy = true;
                "NOISY"
            }
            Expect::Sanity => "ok",
            Expect::Leaks if outcome.max_t > LEAK => "ok (leaks, as it must)",
            Expect::Leaks => {
                failures.push(name);
                "FAIL: the control did not show"
            }
            Expect::Constant if outcome.max_t > LEAK => {
                failures.push(name);
                "FAIL"
            }
            Expect::Constant if outcome.max_t > SUSPECT => "inconclusive; run longer",
            Expect::Constant => "ok",
        };
        println!("{name:24} {:>10} runs {:>10.0} cycles  max |t| {:>8.2}  {verdict}",
                 outcome.measurements, outcome.mean_cycles, outcome.max_t);
        if verdict.starts_with("FAIL") {
            println!("    {why}");
        }
    }
    if environment_noisy {
        println!("\nThe sanity row differs between its classes, which no code can explain. \
                  Pin the run to one core (taskset -c 2), stop other work, and run again \
                  before reading anything else in this table.");
        std::process::exit(1);
    }
    if !failures.is_empty() {
        println!("\nNot as expected: {}. A target that fails twice on a quiet machine is \
                  a finding; a control that does not show means the measurement is not \
                  working here.", failures.join(", "));
        std::process::exit(1);
    }
}
