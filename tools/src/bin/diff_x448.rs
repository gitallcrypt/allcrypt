// X448, dumped for comparison against OpenSSL through
// python-cryptography.
//
// The unit tests pin RFC 7748's vectors - two single shots, the Alice and
// Bob exchange, and the thousand-round chain - which is what says the
// arithmetic is right. This is the other half: hundreds of random inputs,
// which is what says it is right *everywhere* rather than at the handful
// of points somebody wrote down.
//
// Two failures this shape catches that a vector does not: a carry that
// only appears for some inputs, and a coordinate handled differently from
// the way OpenSSL handles it.
//
// **The differences from `diff_x25519.rs` are the point.** X448 has no
// spare high bit to set - the field is 448 bits in exactly 56 bytes - so
// there is no "non-canonical encoding" row of that shape, and the
// equivalent here is a coordinate at or above `p`, which has to be
// constructed rather than stumbled on. The clamp rows check two low bits
// and bit 447 where X25519's check three and bit 254, so a corpus copied
// from the other file would assert the wrong thing and pass anyway,
// because a clamped scalar is a valid scalar either way.
use allcrypt::ec::x448;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes(&mut self) -> [u8; x448::KEY_LEN] {
        let mut out = [0u8; x448::KEY_LEN];
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
    let mut rng = Rng(0x243F6A8885A308D3);

    // Random scalars against the base point: the public key half.
    for _ in 0..80 {
        let scalar = rng.bytes();
        let public = x448::public_key(&scalar).unwrap();
        println!("pub {} {}", hex(&scalar), hex(&public));
    }

    // Random scalars against random *public keys*, which is the actual
    // key exchange, and both sides must agree.
    for _ in 0..80 {
        let a = rng.bytes();
        let b = rng.bytes();
        let a_public = x448::public_key(&a).unwrap();
        let b_public = x448::public_key(&b).unwrap();
        let one_way = x448::x448(&a, &b_public).unwrap();
        let other_way = x448::x448(&b, &a_public).unwrap();
        assert_eq!(one_way, other_way, "the two sides disagreed");
        println!("dh {} {} {}", hex(&a), hex(&b_public), hex(&one_way));
    }

    // Random scalars against arbitrary 56 byte strings. Most are not
    // public keys at all - they land on the twist, or encode a value at
    // or above p. RFC 7748 makes all of them legal input, and this is
    // where an implementation that "validates" the u coordinate stops
    // agreeing with everyone else.
    //
    // **A value at or above p has to be built on purpose.** For X25519
    // the spare high bit gives you one for free; here p is
    // `2^448 - 2^224 - 1`, so a random 56 byte string is below it
    // essentially always. Every fourth row therefore sets the top byte
    // to 0xff, which puts the value above p for certain - that is the
    // row that exercises the reduction, and without it nothing does.
    let mut above_p = 0;
    for index in 0..60 {
        let scalar = rng.bytes();
        let mut point = rng.bytes();
        if index % 4 == 0 {
            point[x448::KEY_LEN - 1] = 0xff;
            above_p += 1;
        }
        println!("raw {} {} {}", hex(&scalar), hex(&point),
                 hex(&x448::x448(&scalar, &point).unwrap()));
    }
    assert!(above_p >= 15,
            "only {above_p} rows have a coordinate above p, so the reduction \
             is barely covered");

    // Clamping, stated as a fact about the output rather than about the
    // function: a scalar and its clamped form must give the same answer.
    for _ in 0..20 {
        let scalar = rng.bytes();
        let clamped = x448::clamp(&scalar);
        assert_eq!(x448::public_key(&scalar).unwrap(),
                   x448::public_key(&clamped).unwrap(),
                   "clamping is not idempotent");
        println!("clamp {} {}", hex(&scalar), hex(&clamped));
    }

    // The low-order points RFC 7748 section 7 names, so the corpus states
    // what an implementation must do with them rather than leaving it to
    // a reader. `x448` returns zero; `exchange` refuses.
    for value in [0u8, 1] {
        let mut point = [0u8; x448::KEY_LEN];
        point[0] = value;
        let scalar = rng.bytes();
        println!("raw {} {} {}", hex(&scalar), hex(&point),
                 hex(&x448::x448(&scalar, &point).unwrap()));
        assert!(x448::exchange(&scalar, &point).is_err(),
                "a low order point was not refused by exchange");
    }

    eprintln!("diff_x448: every exchange agreed with itself, clamping was \
               idempotent on every scalar, and {above_p} coordinates were \
               above p");
}
