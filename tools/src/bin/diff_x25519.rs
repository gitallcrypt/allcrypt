// X25519, dumped for comparison against OpenSSL through
// python-cryptography.
//
// The unit tests pin the RFC 7748 vectors, which is what says the
// arithmetic is right. This is the other half: hundreds of random inputs,
// which is what says it is right *everywhere* rather than at the four
// points somebody wrote down. The two failures this shape catches that a
// vector does not are a carry that only appears for some inputs, and a
// non-canonical encoding handled differently from the way OpenSSL handles
// it.
use allcrypt::ec::x25519;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for byte in out.iter_mut() {
            *byte = (self.next() >> 24) as u8;
        }
        out
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn main() {
    let mut rng = Rng(0xB7E151628AED2A6A);

    // Random scalars against the base point: the public key half.
    for _ in 0..150 {
        let scalar = rng.bytes32();
        let public = x25519::public_key(&scalar).unwrap();
        println!("pub {} {}", hex(&scalar), hex(&public));
    }

    // Random scalars against random *public keys*, which is the actual
    // key exchange, and both sides must agree.
    for _ in 0..150 {
        let a = rng.bytes32();
        let b = rng.bytes32();
        let a_public = x25519::public_key(&a).unwrap();
        let b_public = x25519::public_key(&b).unwrap();
        let one_way = x25519::x25519(&a, &b_public).unwrap();
        let other_way = x25519::x25519(&b, &a_public).unwrap();
        assert_eq!(one_way, other_way, "the two sides disagreed");
        println!("dh {} {} {}", hex(&a), hex(&b_public), hex(&one_way));
    }

    // Random scalars against arbitrary 32 byte strings. Most of these are
    // not public keys at all - they land on the twist, or encode a value
    // at or above p. RFC 7748 says all of them are legal input, and this
    // is where an implementation that "validates" the u coordinate stops
    // agreeing with everyone else.
    for _ in 0..100 {
        let scalar = rng.bytes32();
        let mut point = rng.bytes32();
        // Every fourth one gets the spare high bit set, which the RFC says
        // to ignore rather than reject.
        if rng.next().is_multiple_of(4) {
            point[31] |= 0x80;
        }
        println!("raw {} {} {}", hex(&scalar), hex(&point),
                 hex(&x25519::x25519(&scalar, &point).unwrap()));
    }

    // Clamping, stated as a fact about the output rather than about the
    // function: a scalar and its clamped form must give the same answer.
    for _ in 0..20 {
        let scalar = rng.bytes32();
        let clamped = x25519::clamp(&scalar);
        assert_eq!(x25519::public_key(&scalar).unwrap(),
                   x25519::public_key(&clamped).unwrap(),
                   "clamping is not idempotent");
        println!("clamp {} {}", hex(&scalar), hex(&clamped));
    }

    eprintln!("diff_x25519: every exchange agreed with itself, and clamping \
               was idempotent on every scalar");
}
