//! The named linear congruential generators against `vectors/lcg.vec`:
//! the outputs of the libraries that shipped them (libstdc++, musl,
//! newlib, Wine's msvcrt, PCG, glibc, the JDK), recorded by
//! `scripts/make_lcg_vectors.py`. Offline.

use std::collections::HashMap;

use allcrypt::prng::lcg::{JavaRandom, NamedLcg, Rand48, LCG, NAMED};

fn fields(line: &str) -> (&str, HashMap<&str, &str>) {
    let mut words = line.split(' ');
    let kind = words.next().unwrap();
    let f = words.map(|w| w.split_once('=').unwrap()).collect();
    (kind, f)
}

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn test_lcg_vectors() {
    let text = include_str!("../vectors/lcg.vec");
    let mut counts: HashMap<String, usize> = HashMap::new();
    for line in text.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (kind, f) = fields(line);
        let outputs: Vec<&str> = f["outputs"].split(',').collect();
        match kind {
            "lcg" => {
                let seed: u64 = f["seed"].parse().unwrap();
                let mut g = LCG::named(f["name"], seed).unwrap();
                for _ in 0..f["skip"].parse::<usize>().unwrap() {
                    g.next_output();
                }
                for (i, want) in outputs.iter().enumerate() {
                    assert_eq!(g.next_output(), want.parse::<i128>().unwrap(),
                               "output {i}: {line}");
                }
                *counts.entry(f["name"].to_string()).or_default() += 1;
            }
            "java" => {
                let mut r = JavaRandom::new(f["seed"].parse().unwrap());
                let arg: i32 = f["arg"].parse().unwrap();
                for (i, want) in outputs.iter().enumerate() {
                    let got = match f["method"] {
                        "nextInt" => r.next_int().to_string() == *want,
                        "nextIntBounded" => r.next_int_bounded(arg).unwrap().to_string() == *want,
                        "nextLong" => r.next_long().to_string() == *want,
                        "nextBoolean" => r.next_boolean().to_string() == *want,
                        "nextFloat" => r.next_float() == want.parse::<f32>().unwrap(),
                        "nextDouble" => r.next_double() == want.parse::<f64>().unwrap(),
                        "nextBytes" => r.next_bytes(arg as usize) == unhex(want),
                        other => panic!("unknown method {other}"),
                    };
                    assert!(got, "call {i}: {line}");
                }
                *counts.entry(format!("java.{}", f["method"])).or_default() += 1;
            }
            "rand48" => {
                let mut r = Rand48::default();
                for step in f["setup"].split(';') {
                    let (how, arg) = step.split_once(':').unwrap_or((step, ""));
                    let words = || -> Vec<u16> { arg.split(',').map(|w| w.parse().unwrap()).collect() };
                    match how {
                        "none" => {}
                        "srand48" => r.srand48(arg.parse().unwrap()),
                        "seed48" => { r.seed48(words().try_into().unwrap()); }
                        "lcong48" => r.lcong48(words().try_into().unwrap()),
                        other => panic!("unknown setup {other}"),
                    }
                }
                let calls = f["calls"].chars();
                assert_eq!(f["calls"].len(), outputs.len(), "{line}");
                for (i, (call, want)) in calls.zip(&outputs).enumerate() {
                    let ok = match call {
                        'l' => r.lrand48().to_string() == *want,
                        'm' => r.mrand48().to_string() == *want,
                        'd' => r.drand48() == want.parse::<f64>().unwrap(),
                        other => panic!("unknown call {other}"),
                    };
                    assert!(ok, "call {i} ({call}): {line}");
                }
                *counts.entry("rand48".to_string()).or_default() += 1;
            }
            other => panic!("unknown row kind {other}"),
        }
    }
    // A parser that found nothing would pass every assertion above.
    for g in NAMED.iter().filter(|g| g.name != "randu") {
        assert!(counts.get(g.name).copied().unwrap_or(0) >= 17,
                "too few {} rows: {:?}", g.name, counts.get(g.name));
    }
    for method in ["nextInt", "nextIntBounded", "nextLong", "nextBoolean", "nextFloat",
                   "nextDouble", "nextBytes"] {
        assert!(counts.get(&format!("java.{method}")).copied().unwrap_or(0) >= 8,
                "too few java.{method} rows");
    }
    assert!(counts.get("rand48").copied().unwrap_or(0) >= 16, "too few rand48 rows");
}

/// RANDU has no implementation left to record, so it is checked by the
/// property that made it notorious: with `a = 2^16 + 3`, `a^2 = 6a - 9`
/// mod 2^31, so `x[k+2] = 6 x[k+1] - 9 x[k]`. A different multiplier
/// fails this on the first triple, and the first output is the
/// definition, `65539 * seed mod 2^31`.
#[test]
fn test_randu_is_determined_by_its_previous_two_outputs() {
    let g = NamedLcg::by_name("randu").unwrap();
    assert_eq!((g.a * g.a) % g.m, (6 * g.a + g.m - 9) % g.m);
    for seed in [1u64, 3, 12345, (1 << 31) - 1, 0xdead_beef] {
        let mut r = LCG::named("randu", seed).unwrap();
        let mut x: Vec<i128> = (0..10_000).map(|_| r.next_output()).collect();
        assert_eq!(x[0], (65539 * (seed as i128)) % (1 << 31), "seed {seed}");
        x.insert(0, (seed as i128) % (1 << 31));
        for k in 0..x.len() - 2 {
            assert_eq!(x[k + 2], (6 * x[k + 1] - 9 * x[k]).rem_euclid(1 << 31),
                       "seed {seed}, k {k}");
        }
    }
}

/// The generic constructor still takes any parameters: here `glibc_type0`
/// written out by hand, which must agree with the named one.
#[test]
fn test_the_generic_constructor_matches_a_named_one() {
    let mut generic = LCG::new(42, 1_103_515_245, 12345, 1 << 31, (1 << 31) - 1);
    let mut named = LCG::named("glibc_type0", 42).unwrap();
    for _ in 0..1000 {
        assert_eq!(generic.next_output(), named.next_output());
    }
}
