/*!
Linear congruential generators: `x' = (a*x + c) mod m`.

The generic generator takes any `a`, `c` and `m` below 2^128, and a mask
saying which bits of the state are the output. The named ones are the
parameter sets real software shipped, seeded the way that software seeds
them and reporting the bits it reports, so that a sequence reproduced here
is the sequence the original program saw:

| name | a | c | m | output | from |
|---|---|---|---|---|---|
| `minstd_rand0` | 16807 | 0 | 2^31-1 | the state | Park and Miller (1988), C++11 `std::minstd_rand0` |
| `minstd_rand` | 48271 | 0 | 2^31-1 | the state | Park, Miller and Stockmeyer (1993), C++11 `std::minstd_rand` |
| `glibc_type0` | 1103515245 | 12345 | 2^31 | the state | glibc `random()`/`rand()` with an 8 byte `initstate` buffer |
| `lrand48` | 0x5DEECE66D | 11 | 2^48 | bits 47..17 | POSIX `lrand48` |
| `mrand48` | 0x5DEECE66D | 11 | 2^48 | bits 47..16, signed | POSIX `mrand48` |
| `java` | 0x5DEECE66D | 11 | 2^48 | bits 47..16, signed | `java.util.Random.nextInt()` |
| `msvc` | 214013 | 2531011 | 2^32 | bits 30..16 | Microsoft C runtime `rand()` |
| `musl` | 6364136223846793005 | 1 | 2^64 | bits 63..33 | musl `rand()` |
| `newlib` | 6364136223846793005 | 1 | 2^64 | bits 62..32 | newlib `rand()` |
| `mmix` | 6364136223846793005 | 1442695040888963407 | 2^64 | the state | Knuth's MMIX; the LCG under PCG |
| `randu` | 65539 | 0 | 2^31 | the state | IBM System/360 SSP `RANDU` |

**None of these is fit for anything that needs to be unpredictable.**
An LCG's state is its output, or most of it: `minstd`, `glibc_type0`,
`randu` and `mmix` print the whole state, so one output predicts every
later one; the truncated ones fall to a lattice reduction over a few
consecutive outputs. Their low bits are worse than their high ones: with
a power-of-two modulus, bit `k` of the state has period `2^(k+1)`, so the
lowest bit of `glibc_type0` simply alternates. That is why the C
libraries above report high bits - and why `rand() % 2` was a coin that
always alternated on systems that did not.

**RANDU** is the canonical bad one. With `a = 2^16 + 3`,
`a^2 = 6a - 9 (mod 2^31)`, so every output is determined by the two
before it: `x[k+2] = 6 x[k+1] - 9 x[k] (mod 2^31)`. Consecutive triples
therefore lie on 15 planes in the unit cube, which a three-dimensional
Monte Carlo integration sees immediately. It was the scientific
subroutine package's generator for System/360 and was widely copied.
`tests/test_lcg.rs` checks the relation.

The seeding rules differ and are part of the generator:

- `minstd_*` reduce the seed mod `m` and use 1 if that is zero, since 0
  is a fixed point of a multiplicative generator (C++ [rand.eng.lcong]).
- `glibc_type0` replaces a zero seed by 1 *before* reducing, so a seed of
  2^31 gives state 0 there and is not corrected (glibc `srandom_r`).
- `lrand48`/`mrand48` use the low 32 bits of the seed as the state's
  high 32 bits under a fixed `0x330E` (`srand48`).
- `java` XORs the seed with the multiplier and keeps 48 bits.
- `musl` stores `seed - 1`, computed as an `unsigned int`, so a seed of
  0 starts the 64 bit state at 2^32 - 1.
- The C library ones take an `unsigned int` seed, and a wider seed is
  truncated to 32 bits here as the C call would truncate it.

`JavaRandom` and `Rand48` carry the rest of those two interfaces -
`nextInt(bound)`, `nextDouble`, `nextBytes`; `drand48`, `seed48`,
`lcong48` - because their non-integer outputs are part of what a program
using them saw.
*/

use super::Prng;

/// How a named generator turns the seed its library function takes into
/// the first state. See the module documentation for which uses which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seeding {
    /// `seed mod m`.
    Direct,
    /// `seed mod m`, then 1 if that is 0 (C++ `linear_congruential_engine`).
    ModNonZero,
    /// 1 if the seed is 0, then `seed mod m` (glibc `srandom` at TYPE_0).
    ZeroToOne,
    /// `(seed & 0xffffffff) << 16 | 0x330E` (`srand48`).
    Rand48,
    /// `(seed ^ 0x5DEECE66D) mod 2^48` (`java.util.Random`).
    Java,
    /// `seed - 1`, computed in the seed's own width (musl's `srand`, where
    /// it is `unsigned int` arithmetic: a seed of 0 gives `2^32 - 1`, not
    /// `2^64 - 1`, in the 64 bit state).
    MinusOne,
}

/// A parameter set that shipped. `NAMED` is the list.
#[derive(Clone, Copy, Debug)]
pub struct NamedLcg {
    pub name: &'static str,
    pub a: u128,
    pub c: u128,
    pub m: u128,
    /// The width of the seed argument the original function takes; a
    /// wider seed is truncated to it.
    pub seed_bits: u32,
    pub seeding: Seeding,
    /// The output is `bits` bits of the state starting at bit `shift`.
    pub shift: u32,
    pub bits: u32,
    /// Whether the original function returns those bits as a signed
    /// integer of width `bits` (`mrand48`, Java's `nextInt`).
    pub signed: bool,
    /// Where the parameter set comes from, in a few words.
    pub origin: &'static str,
}

const RAND48_A: u128 = 0x5_DEEC_E66D;

/// The named parameter sets, in the order of the table in the module
/// documentation.
pub const NAMED: &[NamedLcg] = &[
    NamedLcg { name: "minstd_rand0", a: 16807, c: 0, m: (1 << 31) - 1, seed_bits: 64,
               seeding: Seeding::ModNonZero, shift: 0, bits: 31, signed: false,
               origin: "Park and Miller 1988; C++11 std::minstd_rand0" },
    NamedLcg { name: "minstd_rand", a: 48271, c: 0, m: (1 << 31) - 1, seed_bits: 64,
               seeding: Seeding::ModNonZero, shift: 0, bits: 31, signed: false,
               origin: "Park, Miller and Stockmeyer 1993; C++11 std::minstd_rand" },
    NamedLcg { name: "glibc_type0", a: 1_103_515_245, c: 12345, m: 1 << 31, seed_bits: 32,
               seeding: Seeding::ZeroToOne, shift: 0, bits: 31, signed: false,
               origin: "glibc random() with an 8 byte initstate buffer (TYPE_0)" },
    NamedLcg { name: "lrand48", a: RAND48_A, c: 11, m: 1 << 48, seed_bits: 32,
               seeding: Seeding::Rand48, shift: 17, bits: 31, signed: false,
               origin: "POSIX lrand48 after srand48" },
    NamedLcg { name: "mrand48", a: RAND48_A, c: 11, m: 1 << 48, seed_bits: 32,
               seeding: Seeding::Rand48, shift: 16, bits: 32, signed: true,
               origin: "POSIX mrand48 after srand48" },
    NamedLcg { name: "java", a: RAND48_A, c: 11, m: 1 << 48, seed_bits: 64,
               seeding: Seeding::Java, shift: 16, bits: 32, signed: true,
               origin: "java.util.Random.nextInt()" },
    NamedLcg { name: "msvc", a: 214_013, c: 2_531_011, m: 1 << 32, seed_bits: 32,
               seeding: Seeding::Direct, shift: 16, bits: 15, signed: false,
               origin: "Microsoft C runtime rand()" },
    NamedLcg { name: "musl", a: 6_364_136_223_846_793_005, c: 1, m: 1 << 64, seed_bits: 32,
               seeding: Seeding::MinusOne, shift: 33, bits: 31, signed: false,
               origin: "musl rand()" },
    NamedLcg { name: "newlib", a: 6_364_136_223_846_793_005, c: 1, m: 1 << 64, seed_bits: 32,
               seeding: Seeding::Direct, shift: 32, bits: 31, signed: false,
               origin: "newlib rand()" },
    NamedLcg { name: "mmix", a: 6_364_136_223_846_793_005, c: 1_442_695_040_888_963_407,
               m: 1 << 64, seed_bits: 64, seeding: Seeding::Direct, shift: 0, bits: 64,
               signed: false, origin: "Knuth's MMIX; the state update of PCG" },
    NamedLcg { name: "randu", a: 65539, c: 0, m: 1 << 31, seed_bits: 64,
               seeding: Seeding::Direct, shift: 0, bits: 31, signed: false,
               origin: "IBM System/360 Scientific Subroutine Package RANDU" },
];

impl NamedLcg {
    /// The parameter set called `name`.
    ///
    /// # Errors
    /// A name not in `NAMED`; the message lists the ones that are.
    pub fn by_name(name: &str) -> Result<&'static NamedLcg, String> {
        NAMED.iter().find(|g| g.name == name).ok_or_else(|| {
            let names: Vec<&str> = NAMED.iter().map(|g| g.name).collect();
            format!("unknown LCG {name:?}; the named ones are {}", names.join(", "))
        })
    }

    /// The first state for `seed`, by this generator's own rule.
    pub fn initial_state(&self, seed: u64) -> u128 {
        let seed = if self.seed_bits >= 64 { seed } else { seed & ((1u64 << self.seed_bits) - 1) };
        let seed = seed as u128;
        match self.seeding {
            Seeding::Direct => seed % self.m,
            Seeding::ModNonZero => match seed % self.m { 0 => 1, s => s },
            Seeding::ZeroToOne => if seed == 0 { 1 } else { seed % self.m },
            // The mask repeats seed_bits for the two generators that use
            // this rule, so that the rule is srand48's on its own.
            Seeding::Rand48 => ((seed & 0xffff_ffff) << 16) | 0x330e,
            Seeding::Java => (seed ^ RAND48_A) & ((1 << 48) - 1),
            Seeding::MinusOne => {
                let width = if self.seed_bits >= 64 { u64::MAX as u128 } else { (1 << self.seed_bits) - 1 };
                (seed.wrapping_sub(1) & width) % self.m
            }
        }
    }
}

/// `(x * y) mod m` for `x, y < m`, with no overflow whatever `m` is.
fn mul_mod(x: u128, y: u128, m: u128) -> u128 {
    if let Some(p) = x.checked_mul(y) {
        return p % m;
    }
    if m.is_power_of_two() {
        return x.wrapping_mul(y) & (m - 1);
    }
    double_and_add(x, y, m)
}

/// `(x * y) mod m` one bit of `y` at a time, every intermediate below `m`.
fn double_and_add(mut x: u128, mut y: u128, m: u128) -> u128 {
    let mut result = 0u128;
    while y != 0 {
        if y & 1 == 1 {
            result = add_mod(result, x, m);
        }
        x = add_mod(x, x, m);
        y >>= 1;
    }
    result
}

/// `(x + y) mod m` for `x, y < m`.
fn add_mod(x: u128, y: u128, m: u128) -> u128 {
    let (sum, carried) = x.overflowing_add(y);
    if carried || sum >= m { sum.wrapping_sub(m) } else { sum }
}

pub struct LCG {
    state: u128,
    a: u128,
    c: u128,
    m: u128,
    mask: u128,
    mask_shift: u32,
    signed: bool,
    named: Option<&'static NamedLcg>,
}


impl LCG {
    /// A generator with any parameters. The output is `(state & mask) >>
    /// mask.trailing_zeros()`, and `get_bytes` takes the low byte of each
    /// output.
    ///
    /// # Panics
    /// The parameters `try_new` refuses: `m < 2` or `mask == 0`. A
    /// parameter from outside goes through `try_new`, which is what
    /// `api::lcg_custom` does.
    pub fn new(state: u128, a: u128, c: u128, m: u128, mask: u128) -> LCG {
        match LCG::try_new(state, a, c, m, mask) {
            Ok(lcg) => lcg,
            Err(reason) => panic!("{reason}"),
        }
    }

    /// `new`, with the parameters checked here rather than one layer
    /// out: `m == 0` made `step` divide by zero, and `mask == 0` made
    /// `mask.trailing_zeros()` 128 and the output shift by that - both
    /// panics on first use rather than at construction.
    ///
    /// # Errors
    /// `m < 2` (a modulus of 1 has one state) or `mask == 0` (an output
    /// of no bits).
    pub fn try_new(state: u128, a: u128, c: u128, m: u128, mask: u128)
                   -> Result<LCG, String> {
        if m < 2 {
            return Err(format!("An LCG's modulus is at least 2, not {m}."));
        }
        if mask == 0 {
            return Err("An LCG's output mask selects no bits.".to_string());
        }
        Ok(LCG {
            state,
            a,
            c,
            m,
            mask,
            mask_shift: mask.trailing_zeros(),
            signed: false,
            named: None,
        })
    }

    /// One of `NAMED`, seeded by its own rule.
    ///
    /// # Errors
    /// A name not in `NAMED`.
    pub fn named(name: &str, seed: u64) -> Result<LCG, String> {
        let g = NamedLcg::by_name(name)?;
        Ok(LCG::from_named(g, seed))
    }

    /// One of `NAMED`, seeded by its own rule.
    pub fn from_named(g: &'static NamedLcg, seed: u64) -> LCG {
        let mask = if g.bits >= 128 { u128::MAX } else { ((1u128 << g.bits) - 1) << g.shift };
        LCG {
            state: g.initial_state(seed),
            a: g.a,
            c: g.c,
            m: g.m,
            mask,
            mask_shift: g.shift,
            signed: g.signed,
            named: Some(g),
        }
    }

    /// Advance once and return the new state.
    pub fn step(&mut self) -> u128 {
        let a = self.a % self.m;
        let c = self.c % self.m;
        let x = self.state % self.m;
        self.state = add_mod(mul_mod(a, x, self.m), c, self.m);
        self.state
    }

    /// Advance once and return the output: the masked bits, as the
    /// original function returns them - sign-extended for the signed
    /// ones (`mrand48`, `java`).
    pub fn next_output(&mut self) -> i128 {
        let bits = (self.step() & self.mask) >> self.mask_shift;
        if self.signed {
            let width = 128 - (self.mask >> self.mask_shift).leading_zeros();
            let shift = 128 - width;
            ((bits << shift) as i128) >> shift
        } else {
            bits as i128
        }
    }

    /// The current state.
    pub fn state(&self) -> u128 {
        self.state
    }

    /// The parameter set this generator was built from, if it was.
    pub fn parameters(&self) -> Option<&'static NamedLcg> {
        self.named
    }

    pub fn get_byte(&mut self) -> u8 {
        self.step();
        ((self.state & self.mask) >> self.mask_shift) as u8
    }
}

impl Prng for LCG {
    /// The low byte of each output, which is how a C program filling a
    /// buffer with `rand() & 0xff` used one.
    fn get_bytes(&mut self, output: &mut Vec<u8>, count: usize) {
        for _i in 0..count {
            output.push(self.get_byte());
        }
    }
    fn name(&self) -> String {
        match self.named {
            Some(g) => g.name.to_string(),
            None => format!("LCG {}*x + {} % {}", self.a, self.c, self.m),
        }
    }
    /// One step's whole new state - the raw value, before the output's
    /// mask - truncated to 64 bits when `m` exceeds 2^64.
    fn get_raw_output(&mut self, output: &mut Vec<u64>) {
        output.push(self.step() as u64);
    }
    /// The named generator's own seeding rule; for one built by `new`,
    /// the seed is the state.
    fn set_seed(&mut self, seed: u64) {
        self.state = match self.named {
            Some(g) => g.initial_state(seed),
            None => seed as u128,
        };
    }
}

const JAVA_MASK: u64 = (1 << 48) - 1;

/// `java.util.Random`: the 48 bit LCG and the methods that read it.
/// Every method matches the JDK's for the same seed and call sequence;
/// `vectors/lcg.vec` holds JDK 21's answers.
pub struct JavaRandom {
    seed: u64,
}

impl JavaRandom {
    /// `new Random(seed)`.
    pub fn new(seed: i64) -> JavaRandom {
        let mut r = JavaRandom { seed: 0 };
        r.set_seed(seed);
        r
    }

    /// `setSeed(seed)`.
    pub fn set_seed(&mut self, seed: i64) {
        self.seed = (seed as u64 ^ RAND48_A as u64) & JAVA_MASK;
    }

    /// `next(bits)`, the protected method every other one calls: the top
    /// `bits` of the new 48 bit state, as an `int`.
    ///
    /// # Panics
    /// `bits` above 32, which Java's contract excludes and which would
    /// not fit the `int`.
    pub fn next(&mut self, bits: u32) -> i32 {
        assert!(bits <= 32, "next({bits}): at most 32 bits fit an int");
        self.seed = self.seed.wrapping_mul(RAND48_A as u64).wrapping_add(0xb) & JAVA_MASK;
        (self.seed >> (48 - bits)) as i32
    }

    /// `nextInt()`.
    pub fn next_int(&mut self) -> i32 {
        self.next(32)
    }

    /// `nextInt(bound)`: uniform in `0..bound` by rejection, or by the top
    /// bits for a power of two.
    ///
    /// # Errors
    /// A bound that is not positive, as the JDK throws.
    pub fn next_int_bounded(&mut self, bound: i32) -> Result<i32, String> {
        if bound <= 0 {
            return Err(format!("bound must be positive, not {bound}"));
        }
        let mut r = self.next(31);
        let m = bound - 1;
        if bound & m == 0 {
            return Ok(((bound as i64 * r as i64) >> 31) as i32);
        }
        // The JDK's loop condition overflows an int on purpose: it is
        // negative exactly when `u` falls in the final, partial copy of
        // 0..bound.
        let mut u = r;
        loop {
            r = u % bound;
            if u.wrapping_sub(r).wrapping_add(m) >= 0 {
                return Ok(r);
            }
            u = self.next(31);
        }
    }

    /// `nextLong()`: two `next(32)`, the second added as a *signed* int,
    /// so the high word is one less whenever the low one's top bit is set.
    pub fn next_long(&mut self) -> i64 {
        let high = (self.next(32) as i64) << 32;
        high.wrapping_add(self.next(32) as i64)
    }

    /// `nextBoolean()`.
    pub fn next_boolean(&mut self) -> bool {
        self.next(1) != 0
    }

    /// `nextFloat()`: 24 bits over 2^24.
    pub fn next_float(&mut self) -> f32 {
        self.next(24) as f32 / (1u32 << 24) as f32
    }

    /// `nextDouble()`: 26 bits and then 27, over 2^53.
    pub fn next_double(&mut self) -> f64 {
        let high = (self.next(26) as i64) << 27;
        (high + self.next(27) as i64) as f64 / (1u64 << 53) as f64
    }

    /// `nextBytes(new byte[n])`: one `nextInt()` per four bytes, least
    /// significant byte first, the last int's unused bytes discarded.
    pub fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let r = self.next_int().to_le_bytes();
            let take = (n - out.len()).min(4);
            out.extend_from_slice(&r[..take]);
        }
        out
    }
}

/// The POSIX `drand48` family over one shared state, as the C library
/// keeps it: `srand48`, `seed48` and `lcong48` set it, and `lrand48`,
/// `mrand48` and `drand48` read it.
pub struct Rand48 {
    x: u64,
    a: u64,
    c: u64,
}

impl Default for Rand48 {
    /// The state before any seeding call: zero, with the standard
    /// multiplier and addend, which is where glibc starts.
    fn default() -> Rand48 {
        Rand48 { x: 0, a: RAND48_A as u64, c: 0xb }
    }
}

const RAND48_MASK: u64 = (1 << 48) - 1;

impl Rand48 {
    /// The state `srand48(seed)` leaves.
    pub fn new(seed: i64) -> Rand48 {
        let mut r = Rand48::default();
        r.srand48(seed);
        r
    }

    /// `srand48`: the low 32 bits of `seed` become the state's high 32
    /// bits over `0x330E`, and the multiplier and addend are reset.
    pub fn srand48(&mut self, seed: i64) {
        self.x = ((seed as u64 & 0xffff_ffff) << 16) | 0x330e;
        self.a = RAND48_A as u64;
        self.c = 0xb;
    }

    /// `seed48`: the state from three 16 bit words, least significant
    /// first, resetting the multiplier and addend. Returns the previous
    /// state in the same form.
    pub fn seed48(&mut self, xsubi: [u16; 3]) -> [u16; 3] {
        let old = Rand48::words(self.x);
        self.x = Rand48::from_words(xsubi);
        self.a = RAND48_A as u64;
        self.c = 0xb;
        old
    }

    /// `lcong48`: the state from `param[0..3]`, the multiplier from
    /// `param[3..6]` and the addend from `param[6]`.
    pub fn lcong48(&mut self, param: [u16; 7]) {
        self.x = Rand48::from_words([param[0], param[1], param[2]]);
        self.a = Rand48::from_words([param[3], param[4], param[5]]);
        self.c = param[6] as u64;
    }

    fn words(x: u64) -> [u16; 3] {
        [x as u16, (x >> 16) as u16, (x >> 32) as u16]
    }

    fn from_words(w: [u16; 3]) -> u64 {
        w[0] as u64 | (w[1] as u64) << 16 | (w[2] as u64) << 32
    }

    fn step(&mut self) -> u64 {
        self.x = self.x.wrapping_mul(self.a).wrapping_add(self.c) & RAND48_MASK;
        self.x
    }

    /// `lrand48`: the top 31 bits, non-negative.
    pub fn lrand48(&mut self) -> i64 {
        (self.step() >> 17) as i64
    }

    /// `mrand48`: the top 32 bits, as a signed 32 bit value.
    pub fn mrand48(&mut self) -> i64 {
        (self.step() >> 16) as u32 as i32 as i64
    }

    /// `drand48`: the whole state over 2^48, which a double holds exactly.
    pub fn drand48(&mut self) -> f64 {
        self.step() as f64 / (1u64 << 48) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_double_and_add_agrees_with_the_native_product() {
        // Where the product fits, the slow path must give what `%` gives.
        let mut x = 0x0123_4567_89ab_cdefu128;
        for m in [7u128, 1 << 31, (1 << 31) - 1, 1 << 48, u64::MAX as u128, (1 << 64) + 13] {
            for _ in 0..200 {
                x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1) >> 64;
                let a = x % m;
                let b = (x >> 7) % m;
                assert_eq!(double_and_add(a, b, m), a * b % m, "{a} {b} {m}");
            }
        }
    }

    #[test]
    fn test_mul_mod_above_2_to_the_64() {
        // No native product to compare with, so the ring's own laws:
        // commutativity, identity, and distributivity over add_mod.
        let m = (1u128 << 100) + 277;
        let x = (1u128 << 99) + 12345;
        let y = (1u128 << 98) + 999;
        let z = (1u128 << 97) + 5;
        assert_eq!(mul_mod(x, y, m), mul_mod(y, x, m));
        assert_eq!(mul_mod(x, 1, m), x);
        assert_eq!(mul_mod(x, add_mod(y, z, m), m),
                   add_mod(mul_mod(x, y, m), mul_mod(x, z, m), m));
        // A power-of-two modulus takes the wrapping path.
        let p = 1u128 << 127;
        assert_eq!(mul_mod(p - 1, p - 1, p), 1);
    }

    #[test]
    fn test_add_mod_near_the_top_of_the_range() {
        let m = u128::MAX - 10;
        assert_eq!(add_mod(m - 1, m - 1, m), m - 2);
        assert_eq!(add_mod(m - 1, 1, m), 0);
    }

    #[test]
    fn test_every_name_is_found_and_unknown_ones_are_listed() {
        for g in NAMED {
            assert_eq!(NamedLcg::by_name(g.name).unwrap().name, g.name);
            assert!(g.a < g.m && g.c < g.m, "{}", g.name);
        }
        let e = NamedLcg::by_name("rand").unwrap_err();
        assert!(e.contains("minstd_rand0") && e.contains("randu"), "{e}");
    }

    #[test]
    fn test_seeding_rules_differ_where_they_should() {
        let minstd = NamedLcg::by_name("minstd_rand0").unwrap();
        let glibc = NamedLcg::by_name("glibc_type0").unwrap();
        // C++ reduces first: a seed equal to m is corrected to 1.
        assert_eq!(minstd.initial_state((1 << 31) - 1), 1);
        // glibc corrects first: 2^31 reduces to 0 and stays there.
        assert_eq!(glibc.initial_state(1 << 31), 0);
        assert_eq!(glibc.initial_state(0), 1);
        // A 32 bit seed argument drops the high half.
        assert_eq!(glibc.initial_state((1 << 32) + 5), 5);
        // musl subtracts in unsigned int, before widening: seed 0 is
        // 2^32 - 1, which `vectors/lcg.vec` confirms and 2^64 - 1 is not.
        let musl = NamedLcg::by_name("musl").unwrap();
        assert_eq!(musl.initial_state(0), u32::MAX as u128);
        assert_eq!(musl.initial_state(1), 0);
    }

    #[test]
    fn test_set_seed_uses_the_named_rule() {
        let mut a = LCG::named("java", 42).unwrap();
        let mut b = LCG::named("java", 0).unwrap();
        b.set_seed(42);
        assert_eq!(a.next_output(), b.next_output());
        assert_eq!(a.name(), "java");
    }

    #[test]
    fn test_the_named_java_stream_is_next_int() {
        let mut lcg = LCG::named("java", 12345).unwrap();
        let mut java = JavaRandom::new(12345);
        for _ in 0..100 {
            assert_eq!(lcg.next_output(), java.next_int() as i128);
        }
    }

    #[test]
    fn test_the_named_rand48_streams_are_the_family_functions() {
        for seed in [0i64, 1, -1, 1 << 40] {
            let mut l = LCG::named("lrand48", seed as u64).unwrap();
            let mut m = LCG::named("mrand48", seed as u64).unwrap();
            let mut r = Rand48::new(seed);
            let mut s = Rand48::new(seed);
            for _ in 0..50 {
                assert_eq!(l.next_output(), r.lrand48() as i128);
                assert_eq!(m.next_output(), s.mrand48() as i128);
            }
        }
    }

    #[test]
    fn test_get_bytes_is_the_low_byte_of_each_output() {
        let mut a = LCG::named("msvc", 1).unwrap();
        let mut b = LCG::named("msvc", 1).unwrap();
        let mut bytes = Vec::new();
        a.get_bytes(&mut bytes, 16);
        let expected: Vec<u8> = (0..16).map(|_| b.next_output() as u8).collect();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_seed48_returns_the_previous_state() {
        let mut r = Rand48::new(7);
        let before = r.seed48([1, 2, 3]);
        assert_eq!(before, [0x330e, 7, 0]);
        assert_eq!(r.seed48([4, 5, 6]), [1, 2, 3]);
    }

    #[test]
    fn test_a_bad_bound_is_refused() {
        let mut j = JavaRandom::new(0);
        assert!(j.next_int_bounded(0).is_err());
        assert!(j.next_int_bounded(-5).is_err());
    }

    /// `LCG::new` accepted `m == 0` and `mask == 0`, each a panic on
    /// the first output (a division by zero, a shift by 128), and the
    /// guard lived only in `api::lcg_custom`. The tests built
    /// generators with valid parameters only.
    #[test]
    fn test_a_degenerate_modulus_or_mask_is_refused_at_construction() {
        assert!(LCG::try_new(1, 3, 5, 0, 0xff).is_err(), "m = 0");
        assert!(LCG::try_new(1, 3, 5, 1, 0xff).is_err(), "m = 1");
        assert!(LCG::try_new(1, 3, 5, 7, 0).is_err(), "mask = 0");
        let mut lcg = LCG::try_new(1, 3, 5, 7, 0xff).unwrap();
        let mut out = Vec::new();
        lcg.get_raw_output(&mut out);
        assert_eq!(out, vec![(3 + 5) % 7], "a * 1 + c mod m");
    }
}
