// ML-KEM (FIPS 203), dumped for comparison against the second ML-KEM in
// `scripts/diff_check.py`.
//
// Nothing on this machine implements ML-KEM - not python-cryptography,
// not OpenSSL 3.0 - so the reference is one written in that script from
// FIPS 203, by different routes wherever the standard leaves room: its
// NTT is the definition (residues modulo 128 quadratics) rather than a
// butterfly network, its rounding is exact rational arithmetic, and its
// hashes are hashlib's. NIST's 195 vectors pin both implementations to
// the standard; this corpus is what compares them over inputs nobody
// chose.
//
// Rows, one per line, every value hex:
//
//   kem   <set> d z m ek dk k c k_dec   key generation from (d, z),
//                                       encapsulation with m, and our
//                                       decapsulation of our own c
//   rej   <set> dk c k                  decapsulation of an altered or
//                                       random ciphertext: the implicit
//                                       rejection path
//   ekchk <set> ek verdict              the modulus check on an ek with
//                                       one coefficient field overwritten
//   dkchk <set> dk verdict              the hash check on a dk with one
//                                       byte changed somewhere
//
// The overwritten field in `ekchk` is drawn from all of 0..4096, so
// roughly a fifth of those rows are above q and must be refused and the
// rest must not: a check that refused everything fails as surely as one
// that accepted everything.

use allcrypt::pq::ml_kem;

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
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Overwrite the twelve bit field `index` of a packed vector.
fn set_field(packed: &mut [u8], index: usize, value: u16) {
    // Two fields per three bytes, little-endian: the even field is the
    // first byte and the low nibble of the second, the odd field is the
    // high nibble of the second and the third byte.
    let at = 3 * (index / 2);
    if index.is_multiple_of(2) {
        packed[at] = value as u8;
        packed[at + 1] = (packed[at + 1] & 0xf0) | (value >> 8) as u8;
    } else {
        packed[at + 1] = (packed[at + 1] & 0x0f) | ((value & 0x0f) << 4) as u8;
        packed[at + 2] = (value >> 4) as u8;
    }
}

fn main() -> Result<(), String> {
    let mut rng = Rng(0x6d6c_6b65_6d20_3230);
    for name in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"] {
        let set = ml_kem::parameters(name)?;
        for _ in 0..40 {
            let (d, z, m) = (rng.bytes(32), rng.bytes(32), rng.bytes(32));
            let (ek, dk) = ml_kem::key_gen_internal(set, &d, &z)?;
            let (k, c) = ml_kem::encapsulate_internal(set, &ek, &m)?;
            let k_dec = ml_kem::decapsulate_internal(set, &dk, &c)?;
            println!("kem {name} {} {} {} {} {} {} {} {}", hex(&d), hex(&z),
                     hex(&m), hex(&ek), hex(&dk), hex(&k), hex(&c),
                     hex(&k_dec));

            // An altered ciphertext - one to three bytes, anywhere - and
            // a wholly random one.
            let mut altered = c;
            for _ in 0..1 + rng.below(3) {
                let at = rng.below(altered.len());
                altered[at] ^= 1 << rng.below(8);
            }
            let k_rej = ml_kem::decapsulate_internal(set, &dk, &altered)?;
            println!("rej {name} {} {} {}", hex(&dk), hex(&altered),
                     hex(&k_rej));
            let random = rng.bytes(set.ciphertext_len());
            let k_rand = ml_kem::decapsulate_internal(set, &dk, &random)?;
            println!("rej {name} {} {} {}", hex(&dk), hex(&random),
                     hex(&k_rand));

            let mut bad_ek = ek;
            let field = rng.below(256 * set.k);
            set_field(&mut bad_ek, field, rng.below(4096) as u16);
            let verdict = ml_kem::modulus_check(set, &bad_ek)?;
            println!("ekchk {name} {} {verdict}", hex(&bad_ek));

            let mut bad_dk = dk;
            let at = rng.below(bad_dk.len());
            bad_dk[at] ^= 1 << rng.below(8);
            let verdict = ml_kem::hash_check(set, &bad_dk)?;
            println!("dkchk {name} {} {verdict}", hex(&bad_dk));
        }
    }
    Ok(())
}
