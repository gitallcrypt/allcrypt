/*
Finite-field Diffie-Hellman (PKCS#3, and the DHE key exchange of TLS).

Both sides agree on a prime `p` and a generator `g`. Each picks a secret
exponent, sends `g^x mod p`, and raises what arrives to its own exponent.
Both land on `g^(xy) mod p`, and an eavesdropper who saw both public values
has to solve a discrete logarithm to follow.

That is the whole algorithm. Everything below it is defence, because
*plain* Diffie-Hellman authenticates nobody and validates nothing, and
almost every way it has failed in practice is a missing check rather than
broken arithmetic:

  * **The peer's public value is not a number, it is a claim.** `y = 0`,
    `y = 1` and `y = p-1` generate tiny subgroups, so the "shared secret"
    is 0, 1, or one of two values - known to anybody watching. A server
    that sends `y = 1` makes every connection share the same key. Checked
    in `validate_peer`.

  * **The group is chosen by the server** in TLS 1.2 DHE, and nothing in
    the protocol proves `p` is prime or that its order has no small
    factors. A composite `p`, or a prime with a smooth `p-1`, turns the
    discrete log into something feasible and the key into something
    guessable. `check_prime` exists for this; the size floor is a separate
    policy question, because *small* and *fake* are different failures.

  * **Small groups are not an academic worry.** Logjam broke 512 bit
    export DH in real time, and precomputation against a single common
    1024 bit group is within reach of a state. The size floor lives in the
    caller's policy rather than here, because this library's purpose is to
    still be able to talk to the thing - deliberately, not by accident.

  * **The secret exponent is secret.** `mod_pow_ct` is used for anything
    involving it. See the note on exponent length in `generate_key_pair`.

This module does not authenticate anything. In TLS the ServerKeyExchange
signature is what binds `p`, `g` and `y` to a certificate; without it, an
active attacker simply runs Diffie-Hellman with each side separately.
*/

use crate::bignum::{montgomery, BigUint, Montgomery, Secret};
use crate::random;

/// A prime `p` and a generator `g`, validated as far as they can be
/// cheaply.
///
/// Holding the pair in one place is what makes it possible to say that a
/// public value was validated *against the group it belongs to* - the
/// range check is `2 <= y <= p-2`, which is meaningless without `p`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DhGroup {
    p: BigUint,
    g: BigUint,
}

impl DhGroup {
    /// A group from its two numbers.
    ///
    /// Refuses only what is structurally impossible: an even or tiny
    /// modulus, and a generator outside `[2, p-2]`. It deliberately does
    /// **not** refuse a small `p`: a 512 bit export group is a real group
    /// that a real server will offer, and refusing to represent it would
    /// mean this library could not even describe what it was rejecting.
    /// Strength is the caller's policy - see `check_size`.
    pub fn new(p: BigUint, g: BigUint) -> Result<DhGroup, String> {
        // The structural floor is exactly where the group stops having a
        // usable element: `validate_peer` accepts [2, p-2], which is empty
        // below p = 5. Anything above that is a real group, however
        // useless - the *strength* floor is `check_size`, deliberately
        // somewhere else.
        if p < BigUint::from_u64(5) {
            return Err(format!("The DH modulus is {}, and a group needs p >= 5 \
                                for [2, p-2] to contain anything.", p.to_hex()));
        }
        if p.is_even() {
            // Every even number above 2 is composite, so this is not a
            // sloppy prime but a wrong one - and the Montgomery path
            // needs an odd modulus regardless.
            return Err("The DH modulus is even, so it is not prime.".to_string());
        }
        let two = BigUint::from_u64(2);
        let p_minus_1 = p.sub(&BigUint::one())?;
        let p_minus_2 = p_minus_1.sub(&BigUint::one())?;
        if g < two || g > p_minus_2 {
            return Err(format!("The DH generator must be in [2, p-2]; this \
                                one is {} bits and p is {} bits.",
                               g.bit_len(), p.bit_len()));
        }
        Ok(DhGroup { p, g })
    }

    /// A group from big-endian bytes, as they arrive on the wire.
    pub fn from_bytes(p: &[u8], g: &[u8]) -> Result<DhGroup, String> {
        DhGroup::new(BigUint::from_bytes_be(p), BigUint::from_bytes_be(g))
    }

    pub fn p(&self) -> &BigUint {
        &self.p
    }

    pub fn g(&self) -> &BigUint {
        &self.g
    }

    /// The size of the modulus in bits, which is what a strength policy is
    /// written in terms of.
    pub fn bits(&self) -> usize {
        self.p.bit_len()
    }

    /// The width every value in this group encodes to on the wire.
    pub fn modulus_bytes(&self) -> usize {
        self.p.bit_len().div_ceil(8)
    }

    /// Refuse a group smaller than `min_bits`.
    ///
    /// Separate from `new` because size is a decision, not a fact about
    /// the numbers: 512 bits is broken for a secret that matters and
    /// perfectly adequate for reaching a 1998 load balancer that has
    /// nothing on it. The caller says which situation it is in.
    pub fn check_size(&self, min_bits: usize) -> Result<(), String> {
        if self.bits() < min_bits {
            return Err(format!(
                "The server offered a {} bit Diffie-Hellman group and the \
                 minimum is {}. Logjam showed 512 bit groups falling in \
                 real time and 1024 bit ones within reach of precomputation; \
                 lower the minimum deliberately if you have to talk to this \
                 anyway.", self.bits(), min_bits));
        }
        Ok(())
    }

    /// Check that `p` is probably prime.
    ///
    /// Not done by default, and the reason is cost rather than doubt: this
    /// is `rounds` full-width modular exponentiations, several times the
    /// work of the key exchange itself, on every connection.
    ///
    /// What it defends against is a server that sends a *composite*
    /// modulus. If `p = q*r` the discrete log splits by the Chinese
    /// remainder theorem into two much smaller ones, and the shared secret
    /// becomes computable by whoever chose `p`. Nothing else in the
    /// handshake notices: the arithmetic works, the signature over the
    /// parameters verifies (the server signed them, and the server is the
    /// attacker or has been given the parameters by one), and both sides
    /// derive the same key - which the attacker also derives.
    ///
    /// Miller-Rabin with random bases is the right test here rather than
    /// fixed bases, because this number was chosen by somebody who may
    /// want it to pass.
    pub fn check_prime(&self, rounds: usize) -> Result<(), String> {
        if crate::publickey_ciphers::rsa::is_probably_prime(&self.p, rounds)? {
            Ok(())
        } else {
            Err("The server's Diffie-Hellman modulus is composite. That is \
                 not a mistake anybody makes by accident: a composite \
                 modulus makes the shared secret computable by whoever \
                 chose it.".to_string())
        }
    }

    /// A fresh key pair: a secret exponent and `g^x mod p`.
    ///
    /// The exponent is drawn from the whole range `[2, p-2]` rather than
    /// the short one that would be enough if the subgroup order were
    /// known. That costs a full-width exponentiation, and it is the
    /// conservative choice on purpose: short exponents are safe only when
    /// the group has no small subgroups, `p` comes from the server here,
    /// and van Oorschot-Wiener recovers a short exponent when `p-1` is
    /// smooth. A group we cannot check is a group we do not take shortcuts
    /// in.
    ///
    /// `mod_pow_ct` because the exponent is the secret. See
    /// docs/pitfalls.md - the iteration count still follows the exponent's
    /// bit length, which is why the draw is from a fixed-width range.
    pub fn generate_key_pair(&self) -> Result<(BigUint, BigUint), String> {
        let one = BigUint::one();
        let p_minus_2 = self.p.sub(&BigUint::from_u64(2))?;
        // `below` returns [1, p-3]; shifting up by one gives [2, p-2],
        // which excludes the exponents 0 and 1 - both of which would send
        // a public value that announces itself.
        let private = random::below(&p_minus_2)?.add(&one);
        let public = self.public_key(&private)?;
        Ok((private, public))
    }

    /// `g^x mod p` for a private exponent we already have.
    pub fn public_key(&self, private: &BigUint) -> Result<BigUint, String> {
        self.g.mod_pow_ct(private, &self.p)
    }

    /// Refuse a peer public value that cannot be a real one.
    ///
    /// `y` must be in `[2, p-2]`. The three excluded values are not
    /// arbitrary:
    ///
    ///   * `y = 0` makes every shared secret 0;
    ///   * `y = 1` makes every shared secret 1;
    ///   * `y = p-1` has order 2, so the shared secret is 1 or `p-1`
    ///     depending on the parity of our exponent - which leaks that
    ///     parity, one bit of the private key per handshake.
    ///
    /// This is the check whose absence makes a "working" implementation
    /// silently insecure, because all three cases complete the handshake.
    pub fn validate_peer(&self, peer: &BigUint) -> Result<(), String> {
        let two = BigUint::from_u64(2);
        let p_minus_2 = self.p.sub(&two)?;
        if *peer < two || *peer > p_minus_2 {
            return Err(format!(
                "The peer's Diffie-Hellman public value is not in [2, p-2] \
                 (it is {}), so it generates a subgroup with one or two \
                 elements and the shared secret would be a constant.",
                if peer.is_zero() { "0".to_string() }
                else if peer.is_one() { "1".to_string() }
                else if *peer == self.p.sub(&BigUint::one())? { "p-1".to_string() }
                else { format!("{} bits", peer.bit_len()) }));
        }
        Ok(())
    }

    /// The shared secret `peer^x mod p`, big-endian and left-padded to the
    /// width of `p`.
    ///
    /// Padded because a shared secret is a fixed-width field element, and
    /// a bare `to_bytes_be` would silently hand back a shorter buffer
    /// roughly one time in 256 - which is a key derivation that works
    /// until it does not. TLS 1.2 then *strips* those zeros again for its
    /// own premaster; see `strip_leading_zeros`, and note that TLS 1.3 and
    /// RFC 7919 keep them. Both conventions exist and they disagree, which
    /// is why neither is applied here.
    pub fn shared_secret(&self, private: &BigUint, peer: &BigUint)
                         -> Result<Vec<u8>, String> {
        self.validate_peer(peer)?;

        // The whole computation stays fixed width. Going through
        // `BigUint::mod_pow_ct` would normalise the result, and
        // `to_bytes_be_padded` would then scan it for its first non-zero
        // byte - two branches on the shared secret, at the exact moment it
        // is most worth protecting.
        let group = Montgomery::new(&self.p)?;
        let width = group.limbs();
        let base = Secret::from_biguint(peer, width)?;
        let exponent = Secret::from_biguint(private, width)?;
        let shared = group.pow_ct(&base, &exponent, group.modulus_bits());

        // A degenerate result after a valid-looking input means the group
        // itself is wrong - `p` is composite, or `g` has tiny order. The
        // arithmetic did not fail, so nothing else would notice.
        //
        // The three comparisons fold into one mask before anything branches.
        // Branching on the *result* is fine and unavoidable: if it is set we
        // are about to abort the handshake, which tells the peer anyway. What
        // must not happen is three separate decisions, each timed.
        let one = Secret::one(width);
        let (p_minus_1, _) = group.modulus().sub(&one);
        let degenerate =
            shared.ct_is_zero() | shared.ct_eq(&one) | shared.ct_eq(&p_minus_1);
        if montgomery::unmask(degenerate) {
            return Err("The Diffie-Hellman shared secret is degenerate, so \
                        the group has a small subgroup the peer steered us \
                        into.".to_string());
        }

        // Fixed width by construction, so the one-in-256 short buffer this
        // function's doc comment warns about cannot happen here at all.
        let mut bytes = shared.to_bytes_be();
        let want = self.modulus_bytes();
        if bytes.len() < want {
            return Err(format!("Shared secret is {} bytes, group needs {}.",
                               bytes.len(), want));
        }
        // `to_bytes_be` pads to whole limbs, which may be wider than the
        // modulus when `p` is not a multiple of 64 bits. The extra bytes are
        // leading zeros of a value below `p`, so dropping a fixed, public
        // number of them is not a measurement of anything.
        bytes.drain(..bytes.len() - want);
        Ok(bytes)
    }

    /// A public value encoded for the wire: big-endian, left-padded to the
    /// width of `p`.
    ///
    /// RFC 7919 requires the padding, most TLS 1.2 servers accept either,
    /// and sending the padded form is the one that is right under both
    /// readings.
    pub fn encode(&self, value: &BigUint) -> Result<Vec<u8>, String> {
        value.to_bytes_be_padded(self.modulus_bytes())
    }
}

/// Drop leading zero bytes, for the TLS 1.0-1.2 premaster secret.
///
/// RFC 5246 section 8.1.2 says the premaster is the shared secret with
/// "leading bytes ... that contain all zero bits" stripped. It is a real
/// trap rather than a formality: it only differs about one handshake in
/// 256, so an implementation that forgets it interoperates perfectly for
/// days and then fails one connection in a way nobody can reproduce.
///
/// TLS 1.3 and RFC 7919 reversed this and keep the zeros. Applying the
/// wrong one of the two rules is the same bug in the other direction.
pub fn strip_leading_zeros(secret: &[u8]) -> &[u8] {
    let start = secret.iter().take_while(|byte| **byte == 0).count();
    &secret[start..]
}

/// The 1024 bit MODP group from RFC 2409 section 6.2 (Oakley group 2).
///
/// Here to be *reachable*, not to be recommended: it is below any sane
/// modern floor, and it is one of the handful of groups Logjam's
/// precomputation argument was written about. Old equipment offers it and
/// often nothing else.
pub const MODP_1024: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE65381FFFFFFFFFFFFFFFF", "02");

/// The 2048 bit MODP group from RFC 3526 section 3 (group 14).
///
/// These and the RFC 3526 groups below are checked by
/// `rfc_modp_tests` twice over: against the hex the documents print, and
/// against the formula they print beside it, which builds each prime
/// from the binary digits of pi - computed in that test with this
/// library's bignum. Those added for SSH were copied from RFC 3526 by
/// script.
///
/// The usual default when a server has to pick one, and the smallest of
/// these groups that is still defensible.
pub const MODP_2048: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
     FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
     670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
     180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
     3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF\
     FFFFFFFF", "02");

/// The 1536 bit MODP group, RFC 3526 section 2 (IKE group 5).
pub const MODP_1536: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
     FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
     670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", "02");

/// The 3072 bit MODP group, RFC 3526 section 4 (group 15).
pub const MODP_3072: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
     FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
     670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
     180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
     3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
     04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
     B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
     1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
     BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
     E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", "02");

/// The 4096 bit MODP group, RFC 3526 section 5 (group 16): SSH's
/// `diffie-hellman-group16-sha512`.
pub const MODP_4096: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
     FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
     670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
     180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
     3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
     04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
     B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
     1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
     BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
     E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
     99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
     04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
     233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
     D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199\
     FFFFFFFFFFFFFFFF", "02");

/// The 6144 bit MODP group, RFC 3526 section 6 (group 17).
pub const MODP_6144: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
     FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
     670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
     180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
     3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
     04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
     B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
     1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
     BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
     E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
     99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
     04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
     233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
     D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492\
     36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406\
     AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918\
     DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151\
     2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03\
     F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F\
     BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA\
     CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B\
     B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632\
     387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E\
     6DCC4024FFFFFFFFFFFFFFFF", "02");

/// The 8192 bit MODP group, RFC 3526 section 7 (group 18): SSH's
/// `diffie-hellman-group18-sha512`.
pub const MODP_8192: (&str, &str) = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
     8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
     302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
     A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
     49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
     FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
     670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
     180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
     3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
     04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
     B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
     1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
     BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
     E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
     99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
     04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
     233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
     D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492\
     36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406\
     AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918\
     DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151\
     2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03\
     F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F\
     BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA\
     CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B\
     B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632\
     387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E\
     6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA\
     3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C\
     5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9\
     22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886\
     2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6\
     6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5\
     0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268\
     359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6\
     FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71\
     60C980DD98EDD3DFFFFFFFFFFFFFFFFF", "02");

/// Build one of the constants above.
pub fn modp_group(group: (&str, &str)) -> Result<DhGroup, String> {
    DhGroup::new(BigUint::from_hex(&group.0.replace(['\n', ' '], ""))?,
                 BigUint::from_hex(group.1)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The textbook example, small enough to check by hand: p = 23, g = 5.
    /// Alice picks 6 and sends 8; Bob picks 15 and sends 19; both reach 2.
    ///
    /// Worth having as well as the big groups precisely because it can be
    /// verified without running the code.
    #[test]
    fn test_the_textbook_example_by_hand() {
        let group = DhGroup::new(BigUint::from_u64(23), BigUint::from_u64(5)).unwrap();

        let alice_private = BigUint::from_u64(6);
        let bob_private = BigUint::from_u64(15);
        let alice_public = group.public_key(&alice_private).unwrap();
        let bob_public = group.public_key(&bob_private).unwrap();
        assert_eq!(alice_public, BigUint::from_u64(8));
        assert_eq!(bob_public, BigUint::from_u64(19));

        let one_way = group.shared_secret(&alice_private, &bob_public).unwrap();
        let other_way = group.shared_secret(&bob_private, &alice_public).unwrap();
        assert_eq!(one_way, other_way);
        assert_eq!(one_way, vec![2]);
    }

    #[test]
    fn test_a_generated_pair_agrees_both_ways() {
        // 1024 bits with a short explicit exponent would be faster, but
        // generate_key_pair draws a full-width one and that is the path
        // worth testing. One group, both directions.
        let group = modp_group(MODP_1024).unwrap();
        assert_eq!(group.bits(), 1024);

        let (alice_private, alice_public) = group.generate_key_pair().unwrap();
        let (bob_private, bob_public) = group.generate_key_pair().unwrap();
        assert_ne!(alice_public, bob_public, "two key pairs came out identical");

        let one_way = group.shared_secret(&alice_private, &bob_public).unwrap();
        let other_way = group.shared_secret(&bob_private, &alice_public).unwrap();
        assert_eq!(one_way, other_way);
        assert_eq!(one_way.len(), 128, "the secret must be padded to the modulus");
    }

    /// The three degenerate public values. Every one of them completes a
    /// handshake in an implementation that does not check, which is what
    /// makes them worth a test of their own.
    #[test]
    fn test_degenerate_peer_values_are_refused() {
        let group = modp_group(MODP_1024).unwrap();
        let (private, _) = group.generate_key_pair().unwrap();
        let p_minus_1 = group.p().sub(&BigUint::one()).unwrap();

        for (label, value) in [("0", BigUint::zero()),
                               ("1", BigUint::one()),
                               ("p-1", p_minus_1.clone()),
                               ("p", group.p().clone()),
                               ("p+1", group.p().add(&BigUint::one()))] {
            assert!(group.validate_peer(&value).is_err(),
                    "y = {} was accepted", label);
            assert!(group.shared_secret(&private, &value).is_err(),
                    "y = {} produced a shared secret", label);
        }

        // And the smallest legitimate value either side of the range is
        // accepted, so this is a range check and not a blanket refusal.
        assert!(group.validate_peer(&BigUint::from_u64(2)).is_ok());
        assert!(group.validate_peer(&p_minus_1.sub(&BigUint::one()).unwrap()).is_ok());
    }

    #[test]
    fn test_a_group_that_is_not_one_is_refused() {
        let p = modp_group(MODP_1024).unwrap().p().clone();
        // An even modulus is composite by inspection.
        assert!(DhGroup::new(p.add(&BigUint::one()), BigUint::from_u64(2)).is_err());
        // g must be in [2, p-2]: 0, 1 and p-1 generate nothing useful.
        for bad in [BigUint::zero(), BigUint::one(), p.sub(&BigUint::one()).unwrap()] {
            assert!(DhGroup::new(p.clone(), bad).is_err(), "generator accepted");
        }
    }

    #[test]
    fn test_the_size_floor_is_a_policy_not_a_fact() {
        let small = modp_group(MODP_1024).unwrap();
        assert!(small.check_size(2048).is_err());
        assert!(small.check_size(1024).is_ok(), "the floor must be reachable");
        assert!(modp_group(MODP_2048).unwrap().check_size(2048).is_ok());
    }

    /// A composite modulus is the attack `check_prime` exists for, and the
    /// point of this test is that *nothing else* catches it: the key
    /// exchange below runs to completion and both sides agree on a key.
    #[test]
    fn test_a_composite_modulus_is_caught_only_by_the_prime_check() {
        // p = q * r with two primes of similar size, so it looks right.
        let q = BigUint::from_hex("f7d1a5c3b98f4e2d0c6b8a3f5e1d9c7b").unwrap();
        let r = BigUint::from_hex("e3b5c9d7f1a3856942c7e8b1d5f39ca7").unwrap();
        let composite = q.mul(&r);
        let group = DhGroup::new(composite, BigUint::from_u64(2)).unwrap();

        // It behaves perfectly. That is the problem.
        let (alice_private, alice_public) = group.generate_key_pair().unwrap();
        let (bob_private, bob_public) = group.generate_key_pair().unwrap();
        assert_eq!(group.shared_secret(&alice_private, &bob_public).unwrap(),
                   group.shared_secret(&bob_private, &alice_public).unwrap());

        assert!(group.check_prime(16).is_err(), "a composite modulus passed");
        assert!(modp_group(MODP_1024).unwrap().check_prime(16).is_ok());
    }

    /// The two refusals do not compose the way you would hope, and a real
    /// server made that concrete.
    ///
    /// `dh-composite.badssl.com` serves a composite modulus of **2047**
    /// bits. With the default floor of 2048 it is refused on size, and
    /// the primality check never runs - so a live-test row written to
    /// exercise that check passed, green, having tested nothing. The size
    /// check is first because it is free and the prime check costs two
    /// dozen full-width exponentiations; that ordering is right, and its
    /// consequence is that a caller who wants the primality answer has to
    /// lower the floor far enough to reach it.
    ///
    /// Pinned here so the interaction is a documented property rather
    /// than something rediscovered from a live run.
    #[test]
    fn test_a_composite_modulus_below_the_floor_is_refused_for_size_first() {
        // Two primes whose product is one bit below a round size, like
        // badssl's. 2^127 - 1 and 2^121 - 1 are Mersenne primes, so the
        // product is 248 bits - just under a 249 bit "floor".
        let p1 = BigUint::one().shl(127).sub(&BigUint::one()).unwrap();
        let p2 = BigUint::one().shl(121).sub(&BigUint::one()).unwrap();
        let composite = p1.mul(&p2);
        let bits = composite.bit_len();
        let group = DhGroup::new(composite, BigUint::from_u64(2)).unwrap();

        // At a floor above it, the size is the answer and the modulus is
        // never examined.
        let size_error = group.check_size(bits + 1).unwrap_err();
        assert!(size_error.contains("bit Diffie-Hellman group"), "{}", size_error);
        assert!(!size_error.contains("composite"),
                "the size refusal should not claim to know about primality");

        // Lower the floor to reach it, and the real answer appears.
        assert!(group.check_size(bits).is_ok());
        let prime_error = group.check_prime(24).unwrap_err();
        assert!(prime_error.contains("composite"), "{}", prime_error);
    }

    #[test]
    fn test_stripping_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2]), &[1, 2]);
        assert_eq!(strip_leading_zeros(&[1, 0, 2]), &[1, 0, 2]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0]), &[] as &[u8]);
        assert_eq!(strip_leading_zeros(&[]), &[] as &[u8]);
    }

    /// The encoding is fixed width, which is the half of the
    /// padded/stripped pair that lives on the wire.
    #[test]
    fn test_encoding_is_padded_to_the_modulus() {
        let group = modp_group(MODP_1024).unwrap();
        assert_eq!(group.encode(&BigUint::from_u64(2)).unwrap().len(), 128);
        assert_eq!(group.encode(&BigUint::from_u64(2)).unwrap()[127], 2);
    }
}

#[cfg(test)]
mod rfc_modp_tests {
    /*
    Every MODP prime here against the two documents that define them,
    in both of the forms the documents give.

    RFC 2409 and RFC 3526 print each prime twice: as hex, and as the
    formula it was made from, `2^n - 2^(n-64) - 1 + 2^64 * ([2^e pi] + k)`.
    The hex is compared with the constant; the formula is evaluated with
    a pi computed here and compared with the hex. Two independent
    readings of one number, and a constant that drifted from either
    fails.
    */

    use super::*;

    const RFC2409: &str = include_str!("../../rfcs/rfc2409.txt");
    const RFC3526: &str = include_str!("../../rfcs/rfc3526.txt");

    /// From `heading` - a whole line, because the table of contents
    /// carries the same words - the formula's (n, m, e, k) and the printed hex,
    /// skipping the page headers and footers a long prime runs across.
    fn printed(text: &str, heading: &str) -> ((usize, usize, usize, u64), String) {
        let at = text.find(heading).expect(heading);
        let section = &text[at..];
        let formula_at = section.find("prime is").expect("formula");
        let formula: String = section[formula_at..].lines().next().unwrap()
            .chars().filter(|c| !c.is_whitespace()).collect();
        // "primeis:2^4096-2^4032-1+2^64*{[2^3966pi]+240904}"
        let numbers: Vec<u64> = formula.split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty()).map(|part| part.parse().unwrap()).collect();
        // 2, n, 2, m, 1, 2, 64, 2, e, k
        assert_eq!(numbers.len(), 10, "{formula}");
        let parameters = (numbers[1] as usize, numbers[3] as usize, numbers[8] as usize,
                          numbers[9]);
        let hex_at = section.find("hexadecimal value is").expect("hex");
        let end = section[hex_at..].find("enerator is").unwrap() + hex_at;
        let hex: String = section[hex_at..end].lines().skip(1)
            .filter(|line| {
                let words: Vec<&str> = line.split_whitespace().collect();
                !words.is_empty() && words.iter().all(|word| word.len() == 8
                    && word.chars().all(|c| c.is_ascii_hexdigit()))
            })
            .flat_map(|line| line.split_whitespace()).collect();
        (parameters, hex)
    }

    fn constant_hex(group: (&str, &str)) -> String {
        group.0.chars().filter(|c| c.is_ascii_hexdigit()).collect()
    }

    #[test]
    fn test_every_modp_prime_is_the_printed_one_and_the_formula() {
        let groups = [
            (RFC2409, "\n6.2 Second Oakley Group\n", MODP_1024),
            (RFC3526, "\n2.  1536-bit MODP Group\n", MODP_1536),
            (RFC3526, "\n3.  2048-bit MODP Group\n", MODP_2048),
            (RFC3526, "\n4.  3072-bit MODP Group\n", MODP_3072),
            (RFC3526, "\n5.  4096-bit MODP Group\n", MODP_4096),
            (RFC3526, "\n6.  6144-bit MODP Group\n", MODP_6144),
            (RFC3526, "\n7.  8192-bit MODP Group\n", MODP_8192),
        ];
        let pi = crate::bignum::test_support::pi_scaled(8192);
        for (text, heading, group) in groups {
            let ((n, m, e, k), hex) = printed(text, heading);
            assert_eq!(constant_hex(group), hex, "{heading}: the constant");
            assert_eq!(group.1, "02", "{heading}: the generator");
            // 2^n - 2^m - 1 + 2^64 * ([2^e pi] + k)
            let floor = pi.shr(8192 - e).add(&BigUint::from_u64(k));
            let prime = BigUint::one().shl(n).sub(&BigUint::one().shl(m)).unwrap()
                .sub(&BigUint::one()).unwrap()
                .add(&floor.shl(64));
            assert_eq!(prime.to_hex().to_uppercase(), hex, "{heading}: the formula");
            assert_eq!(modp_group(group).unwrap().bits(), n, "{heading}");
        }
    }
}
