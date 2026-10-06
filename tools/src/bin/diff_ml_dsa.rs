// ML-DSA (FIPS 204), dumped for comparison against the second ML-DSA in
// `scripts/diff_check.py`.
//
// Nothing on this machine implements ML-DSA, so the reference is one
// written in that script from FIPS 204 - and it multiplies by Kronecker
// substitution in the ring rather than in the NTT domain, and brings `A`
// out of the transformed domain by interpolation, so the arithmetic this
// file's numbers came through has no counterpart there to share a mistake
// with.
//
// Rows, every value hex:
//
//   key <set> seed pk sk               key generation
//   sig <set> sk mu rnd signature      signing from mu, rnd zero or random
//   ver <set> pk mu signature verdict  verification of an honest signature,
//                                      an altered one, or one for another mu
//
// `mu` is drawn at random rather than computed from a message: the
// message wrapping is checked by NIST's vectors across all twelve
// pre-hash functions, and what this corpus adds is breadth over keys and
// rejection-loop paths.

use allcrypt::pq::ml_dsa;

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

fn main() -> Result<(), String> {
    let mut rng = Rng(0x6d6c_6473_6120_3230);
    for name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
        let set = ml_dsa::parameters(name)?;
        for round in 0..6 {
            let seed = rng.bytes(32);
            let (pk, sk) = ml_dsa::key_gen_internal(set, &seed)?;
            println!("key {name} {} {} {}", hex(&seed), hex(&pk), hex(&sk));

            for hedged in [false, true] {
                let mu = rng.bytes(64);
                let rnd = if hedged { rng.bytes(32) } else { vec![0u8; 32] };
                let signature = ml_dsa::sign_mu(set, &sk, &mu, &rnd)?;
                println!("sig {name} {} {} {} {}", hex(&sk), hex(&mu), hex(&rnd),
                         hex(&signature));

                let verdict = ml_dsa::verify_mu(set, &pk, &mu, &signature)?;
                println!("ver {name} {} {} {} {verdict}", hex(&pk), hex(&mu),
                         hex(&signature));

                // Altered somewhere - c-tilde, z or the hint - or checked
                // against another mu, alternating.
                if round % 2 == 0 {
                    let mut altered = signature;
                    let at = rng.below(altered.len());
                    altered[at] ^= 1 << rng.below(8);
                    let verdict = ml_dsa::verify_mu(set, &pk, &mu, &altered)?;
                    println!("ver {name} {} {} {} {verdict}", hex(&pk), hex(&mu),
                             hex(&altered));
                } else {
                    let other = rng.bytes(64);
                    let verdict = ml_dsa::verify_mu(set, &pk, &other, &signature)?;
                    println!("ver {name} {} {} {} {verdict}", hex(&pk),
                             hex(&other), hex(&signature));
                }
            }
        }
    }
    Ok(())
}
