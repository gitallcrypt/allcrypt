/*
SLH-DSA, the stateless hash-based signature scheme of FIPS 205.

Formerly SPHINCS+, which is what the literature and most library APIs
still call it. Signatures are enormous - 7,856 bytes at the smallest
parameter set and 49,856 at the largest - and signing is slow. In
exchange it rests on nothing but a hash function. There is no number
theory in it at all: no factoring, no discrete logarithm, no lattice. If
SHA-256 and SHAKE256 hold, this holds, which is a much shorter list of
assumptions than anything else in this library makes.

This file has key generation, signing and verification, through both
the internal and the external interface; `docs/post-quantum.md` has the
status and what checks each part.

## The shape of it, briefly

Four constructions stacked, each one fixing the previous one's limit.

1. **WOTS+** signs one `n`-byte value, once, with a set of hash chains.
   `len` chains of `w-1` steps; the message digits say how far down each
   chain to reveal. Signing twice with one key leaks the key.
2. **XMSS** turns `2^h'` WOTS+ keys into one key by putting their public
   keys in a Merkle tree and publishing the root. Now `2^h'` signatures,
   but the signer has to remember which leaves are spent - it is
   *stateful*.
3. **The hypertree** stacks `d` XMSS trees, each layer signing the root
   of the layer below, giving `2^h` leaves for `h = d * h'`.
4. **FORS** removes the state: the message picks the leaf
   pseudo-randomly instead of counting, and a few-time signature scheme
   tolerates the collisions that follows from picking at random. This is
   the "SL" in SLH-DSA - stateless.

Key generation only needs the first three, and only the *root* of the
top tree: the public key is `PK.seed ‖ PK.root`, and the private key is
`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`. So generating a key means
generating `2^h'` WOTS+ public keys and hashing them into a tree - 512
of them at the `s` parameter sets, each one `len` chains of 15 hash
calls. That is why key generation here costs a quarter of a million hash
calls and takes visible time. It is not a bug and there is no shortcut:
the root is a commitment to every leaf.

# Pitfalls

**The address structure is the whole danger.** Every hash call in
SLH-DSA is keyed by a 32 byte `ADRS` saying which part of which tree it
belongs to, and that is what stops one subtree's hashes being replayed
into another. Get a field offset wrong, or leave a field stale from a
previous call, and the result is a *self-consistent* scheme: it signs,
it verifies against itself, and it matches no other implementation and
has lost its security proof. Two specific traps:

* `setTypeAndClear` zeroes the last twelve bytes as well as setting the
  type. Code that sets the type without clearing keeps whatever the
  previous type left in those bytes. **There is therefore no way to set
  a type on its own in this implementation**: [`Adrs`] exposes one
  method per type - [`Adrs::set_wots`], [`Adrs::set_wots_public_key`],
  [`Adrs::set_tree`], [`Adrs::set_fors_tree`], [`Adrs::set_fors_secret`],
  [`Adrs::set_fors_roots`] - each of which takes every word that type
  uses and writes all of them. A stale field is not something to be
  careful about here; it is unrepresentable.
* The same two words have different names depending on the type: bytes
  24..28 are the *chain address* under `WOTS_HASH` and the *tree height*
  under `TREE`. They are one slot. The accessors here are named after
  the spec's names and documented as aliases rather than hidden behind
  one neutral name, because the spec's pseudocode uses both and a reader
  checking this against FIPS 205 needs to see the same words.

**The SHA-2 family compresses the address and the SHAKE family does
not.** SHAKE hashes the full 32 bytes; SHA-2 hashes a 22 byte form that
drops the high bytes of the layer, tree and type fields. That is safe
only because those bytes are always zero, which is an assumption this
code enforces rather than trusts: see
[`Adrs::compressed`].

**The SHA-2 family uses two different hash functions, and which one
depends on both `n` and which operation it is.** At `n = 16` everything
is SHA-256. At `n = 24` and `n = 32`, `PRF` and `F` stay SHA-256 while
`H` and `T_l` become SHA-512 - and the zero padding changes with it,
from `64 - n` bytes to `128 - n`. An implementation that uses one hash
throughout is wrong at two of the three security levels and right at the
one that is usually tested first.

**A WOTS+ key signs once.** This is not a constant-time footnote, it is
a total break: two signatures under one WOTS+ key let anyone forge a
third message. SLH-DSA's whole design exists to make that impossible to
do by accident, and the part of the design that does it is the
randomised leaf choice. Any future "optimisation" here that makes leaf
choice depend on a counter reintroduces the statefulness that FORS was
added to remove.

**These functions are not constant time and the secret they touch is the
seed.** `chain` runs a data-dependent number of steps when signing, and
that is in the standard - FIPS 205 signing leaks the message digits
through timing, which is fine because the digits are public. `PRF` over
`SK.seed` is a fixed-length hash and so has no data-dependent path. Key
generation as implemented here has no secret-dependent branch at all.

## Where the numbers come from

`vectors/slh_dsa.vec`, which is NIST's own ACVP validation data, fetched
by `scripts/make_slh_dsa_vectors.py`. **No second implementation is used
as a check** - python-cryptography has no such thing, and OpenSSL 3.5,
which has it, is not used as a witness for it - so there is no second
opinion to differ against. The vectors
are the entire independent check, which is why
`tests/test_slh_dsa.rs` asserts the case count before it uses anything:
a parser that silently finds nothing would turn the whole test into an
empty loop that passes.
*/

use crate::hash_functions::HashFunction;
use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::sha2::{SHA256, SHA512};
use crate::mac::hmac::Hmac;

/// `lg(w)`: the Winternitz parameter's logarithm. **Fixed at 4 for every
/// parameter set in FIPS 205.** The standard defines the algorithms for
/// other values and then approves none of them, so `w` is a constant
/// here rather than a field - a `w` that varied per parameter set would
/// be a dozen untested code paths.
pub const LG_W: usize = 4;

/// The Winternitz parameter: `2^LG_W`. A chain is `W - 1` steps long.
pub const W: usize = 1 << LG_W;

/// Which hash family a parameter set is built from.
///
/// Not a cosmetic choice: the two families differ in the address
/// encoding they hash, in how many hash functions they use, and - for
/// SHA-2 - in which one depending on `n`. See the pitfalls at the top.
#[derive(Debug, PartialEq, Eq)]
pub enum Family {
    /// SHA-256, and SHA-512 as well above `n = 16`. Hashes the
    /// compressed 22 byte address.
    Sha2,
    /// SHAKE256 at every security level - *not* SHAKE128 at the 128 bit
    /// sets. Hashes the full 32 byte address.
    Shake,
}

/// One of the twelve approved parameter sets.
///
/// The fields are the spec's own names. `len1`, `len2` and `len` are
/// derived rather than stored, because they are functions of `n` and
/// `LG_W` and storing them would be a thirteenth number to get wrong.
#[derive(Debug)]
pub struct Parameters {
    /// The ACVP and FIPS 205 name, e.g. `SLH-DSA-SHA2-128s`.
    pub name: &'static str,
    /// Security parameter in bytes: the width of every hash output, of
    /// both seeds, and of every tree node. 16, 24 or 32.
    pub n: usize,
    /// Total hypertree height. `d * h_prime`.
    pub h: usize,
    /// Number of hypertree layers.
    pub d: usize,
    /// Height of one XMSS tree, so `2^h_prime` WOTS+ keys per tree.
    /// This is the number that decides what key generation costs.
    pub h_prime: usize,
    /// Height of a FORS tree. Used by signing and verification only.
    pub a: usize,
    /// Number of FORS trees. Used by signing and verification only.
    pub k: usize,
    /// Length in bytes of the message digest `H_msg` produces, which
    /// splits into the FORS indices, the tree index and the leaf index.
    /// Used by signing and verification only.
    pub m: usize,
    /// Which hash family.
    pub family: Family,
}

/// The twelve approved sets, in the order ACVP lists them.
///
/// `s` is "small signature, slow signing", `f` is "fast signing, larger
/// signature" - and the difference is entirely in the tree shape: `s`
/// has few tall trees, `f` has many short ones. The `f` sets are
/// *cheaper to generate a key for* despite being the ones called fast
/// for signing, because a key costs `2^h_prime` WOTS+ keys and `h_prime`
/// is 3 or 4 there against 8 or 9 for `s`.
pub const PARAMETER_SETS: [Parameters; 12] = [
    Parameters { name: "SLH-DSA-SHA2-128s",  n: 16, h: 63, d: 7,  h_prime: 9, a: 12, k: 14, m: 30, family: Family::Sha2 },
    Parameters { name: "SLH-DSA-SHAKE-128s", n: 16, h: 63, d: 7,  h_prime: 9, a: 12, k: 14, m: 30, family: Family::Shake },
    Parameters { name: "SLH-DSA-SHA2-128f",  n: 16, h: 66, d: 22, h_prime: 3, a: 6,  k: 33, m: 34, family: Family::Sha2 },
    Parameters { name: "SLH-DSA-SHAKE-128f", n: 16, h: 66, d: 22, h_prime: 3, a: 6,  k: 33, m: 34, family: Family::Shake },
    Parameters { name: "SLH-DSA-SHA2-192s",  n: 24, h: 63, d: 7,  h_prime: 9, a: 14, k: 17, m: 39, family: Family::Sha2 },
    Parameters { name: "SLH-DSA-SHAKE-192s", n: 24, h: 63, d: 7,  h_prime: 9, a: 14, k: 17, m: 39, family: Family::Shake },
    Parameters { name: "SLH-DSA-SHA2-192f",  n: 24, h: 66, d: 22, h_prime: 3, a: 8,  k: 33, m: 42, family: Family::Sha2 },
    Parameters { name: "SLH-DSA-SHAKE-192f", n: 24, h: 66, d: 22, h_prime: 3, a: 8,  k: 33, m: 42, family: Family::Shake },
    Parameters { name: "SLH-DSA-SHA2-256s",  n: 32, h: 64, d: 8,  h_prime: 8, a: 14, k: 22, m: 47, family: Family::Sha2 },
    Parameters { name: "SLH-DSA-SHAKE-256s", n: 32, h: 64, d: 8,  h_prime: 8, a: 14, k: 22, m: 47, family: Family::Shake },
    Parameters { name: "SLH-DSA-SHA2-256f",  n: 32, h: 68, d: 17, h_prime: 4, a: 9,  k: 35, m: 49, family: Family::Sha2 },
    Parameters { name: "SLH-DSA-SHAKE-256f", n: 32, h: 68, d: 17, h_prime: 4, a: 9,  k: 35, m: 49, family: Family::Shake },
];

/// Look a parameter set up by its FIPS 205 name.
///
/// The name is matched exactly, including case. Nothing here folds case
/// the way the curve registry does: these names are fixed strings in a
/// standard rather than identifiers users type, and a near miss should
/// be a refusal rather than a guess.
pub fn parameters(name: &str) -> Result<&'static Parameters, String> {
    PARAMETER_SETS.iter().find(|set| set.name == name).ok_or_else(|| {
        format!("Unknown SLH-DSA parameter set {:?}. FIPS 205 approves \
                 twelve: {}.", name,
                PARAMETER_SETS.iter().map(|s| s.name)
                    .collect::<Vec<_>>().join(", "))
    })
}

// `len` here is FIPS 205's name for the number of hash chains in a WOTS+
// key, not a container's length, so clippy's suggestion of an `is_empty`
// alongside it does not apply: there is nothing to be empty, and every
// approved parameter set makes it 35, 51 or 67. Renaming it to satisfy
// the lint would cost a reader checking this file against the standard
// more than the lint is worth.
#[allow(clippy::len_without_is_empty)]
impl Parameters {
    /// Number of `LG_W` bit digits in an `n` byte message: `8n / lg(w)`.
    ///
    /// At `lg(w) = 4` this is `2n`, but it is written as the division so
    /// that it stays right if `W` ever changes.
    pub fn len1(&self) -> usize { 8 * self.n / LG_W }

    /// Length of the checksum, in digits:
    /// `floor(lg(len1 * (w - 1)) / lg(w)) + 1`.
    ///
    /// Three for every approved set. Derived rather than written as 3,
    /// and `test_the_derived_lengths_are_the_documented_ones` checks
    /// that the derivation agrees with the standard's table - which is
    /// the point of deriving it.
    pub fn len2(&self) -> usize {
        let maximum = self.len1() * (W - 1);
        // `bits` ends as floor(lg(maximum)) + 1.
        let mut bits = 0;
        let mut remaining = maximum;
        while remaining > 0 {
            bits += 1;
            remaining >>= 1;
        }
        (bits - 1) / LG_W + 1
    }

    /// Number of hash chains in a WOTS+ key: `len1 + len2`.
    ///
    /// 35, 51 or 67 depending on `n`. This is the count that multiplies
    /// into everything: a WOTS+ public key is `len` chains, and a WOTS+
    /// signature is `len * n` bytes.
    pub fn len(&self) -> usize { self.len1() + self.len2() }

    /// `PK.seed ‖ PK.root`, so `2n`.
    pub fn public_key_len(&self) -> usize { 2 * self.n }

    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`, so `4n`.
    ///
    /// The public key is *inside* the private key, which is worth
    /// knowing before writing a parser: a 64 byte SLH-DSA-128s private
    /// key ends with the 32 bytes that are its public key.
    pub fn secret_key_len(&self) -> usize { 4 * self.n }


    /// `(1 + k * (1 + a) + h + d * len) * n`: `R`, the FORS signature,
    /// and one XMSS signature per hypertree layer.
    ///
    /// 7,856 bytes at `SLH-DSA-SHA2-128s` and 49,856 at
    /// `SLH-DSA-SHAKE-256f`. This was deliberately absent until signing
    /// existed, because `a`, `k` and `m` are the three fields of
    /// [`Parameters`] that key generation never reads - a mistake in any
    /// of them would have sat here unchecked. The `sigGen` vectors state
    /// each signature's length, so it is checked now.
    pub fn signature_len(&self) -> usize {
        (1 + self.k * (1 + self.a) + self.h + self.d * self.len()) * self.n
    }
}

// The seven address types. The value goes in bytes 16..20 of an address,
// big-endian, and only the last byte is ever non-zero - which is what
// lets the SHA-2 form keep one byte of it.
const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// Which of the two WOTS+ address types is wanted.
///
/// `WOTS_HASH` and `WOTS_PRF` carry the same three fields and differ
/// only in the type word, so they share one setter. An enum rather than
/// the raw constants because the two are one keystroke apart in effect
/// and a mixed-up pair would give a working scheme with the wrong
/// secrets in it.
#[derive(Debug, PartialEq, Eq)]
pub enum WotsAddress {
    /// `WOTS_HASH`: a step of a hash chain.
    Chain,
    /// `WOTS_PRF`: the secret value a chain starts from.
    Secret,
}

/// A 32 byte hash address: which hash call, in which tree, at which
/// layer.
///
/// ```text
///   0..4    layer address        (which hypertree layer)
///   4..16   tree address         (which XMSS tree in that layer)
///  16..20   type
///  20..24   key pair address  |  padding (zero) under TREE
///  24..28   chain address     |  tree height
///  28..32   hash address      |  tree index
/// ```
///
/// Every field is big-endian. The three words from 20 are re-used with
/// different meanings per type, which is the source of the staleness
/// trap described at the top of this file.
///
/// Deliberately **not** `Copy`, and cloned nowhere in this file. The
/// spec's pseudocode makes a fresh copy of the address whenever it
/// switches type; this implementation keeps one address and rewrites it,
/// which is only safe because there is no way to change the type without
/// also writing every word that type uses. That is why the setters below
/// are one-per-type and take all the words at once, instead of there
/// being a `set_type` and three independent word setters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adrs {
    bytes: [u8; 32],
}

impl Default for Adrs {
    fn default() -> Adrs { Adrs::new() }
}

impl Adrs {
    /// All zeros: layer 0, tree 0, type `WOTS_HASH`.
    pub fn new() -> Adrs { Adrs { bytes: [0u8; 32] } }

    fn word(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// Which hypertree layer, counting from 0 at the bottom.
    pub fn set_layer_address(&mut self, layer: u32) { self.word(0, layer) }

    /// Which XMSS tree within the layer.
    ///
    /// The field is twelve bytes and this takes eight, writing zeros
    /// into 4..8. That is not a shortcut: the tree index is at most
    /// `2^(h - h')` and `h` is 68 at the largest parameter set, so the
    /// top four bytes are always zero - and the SHA-2 compressed form
    /// *drops* them, so a value that needed them would be silently
    /// truncated there. Taking a `u64` makes that unrepresentable.
    pub fn set_tree_address(&mut self, tree: u64) {
        self.bytes[4..8].fill(0);
        self.bytes[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    /// FIPS 205's `ADRS.setTypeAndClear`: set the type, zero the rest.
    ///
    /// Private, and the only caller is a per-type setter below. Exposing
    /// it would put back exactly the mistake the per-type setters exist
    /// to prevent - a type change that leaves the following words
    /// holding another type's values.
    fn set_type_and_clear(&mut self, which: u32) {
        self.word(16, which);
        self.bytes[20..32].fill(0);
    }

    /// A WOTS+ address: `WOTS_HASH` for a chain step or `WOTS_PRF` for
    /// the secret value a chain starts from.
    ///
    /// Takes the key pair, chain and hash addresses together because all
    /// three are meaningful under both types, so all three must be set.
    pub fn set_wots(&mut self, which: WotsAddress, key_pair: u32,
                    chain: u32, hash: u32) {
        self.set_type_and_clear(match which {
            WotsAddress::Chain => WOTS_HASH,
            WotsAddress::Secret => WOTS_PRF,
        });
        self.word(20, key_pair);
        self.word(24, chain);
        self.word(28, hash);
    }

    /// A `WOTS_PK` address: the one that compresses a WOTS+ public key.
    ///
    /// The key pair is the only field it uses; the other two stay zero,
    /// and this setter's existence is what makes that explicit rather
    /// than left over.
    pub fn set_wots_public_key(&mut self, key_pair: u32) {
        self.set_type_and_clear(WOTS_PK);
        self.word(20, key_pair);
    }

    /// A `TREE` address: an interior Merkle node.
    ///
    /// Bytes 20..24 are padding under this type and stay zero. Bytes
    /// 24..28 and 28..32 are the *tree height* and *tree index* - the
    /// same two words the WOTS+ types call chain and hash addresses.
    pub fn set_tree(&mut self, height: u32, index: u32) {
        self.set_type_and_clear(TREE);
        self.word(24, height);
        self.word(28, index);
    }

    /// A `FORS_TREE` address: a node of one FORS tree.
    ///
    /// Same three words as a WOTS+ address under different names, and a
    /// separate method rather than a flag on `set_wots` because mixing
    /// the two types up is the mistake that would be hardest to see: the
    /// values are interchangeable, only the type word differs, and the
    /// result would be a scheme whose FORS trees were keyed like WOTS+
    /// chains.
    pub fn set_fors_tree(&mut self, key_pair: u32, height: u32, index: u32) {
        self.set_type_and_clear(FORS_TREE);
        self.word(20, key_pair);
        self.word(24, height);
        self.word(28, index);
    }

    /// A `FORS_PRF` address: the secret under one FORS leaf.
    ///
    /// The tree height is always zero under this type - a secret belongs
    /// to a leaf and leaves are at height zero - so it is not a
    /// parameter, and `set_type_and_clear` has already made it zero.
    pub fn set_fors_secret(&mut self, key_pair: u32, index: u32) {
        self.set_type_and_clear(FORS_PRF);
        self.word(20, key_pair);
        self.word(28, index);
    }

    /// A `FORS_ROOTS` address: the one that compresses the `k` roots.
    pub fn set_fors_roots(&mut self, key_pair: u32) {
        self.set_type_and_clear(FORS_ROOTS);
        self.word(20, key_pair);
    }

    /// Bytes 20..24, whatever the current type calls them.
    pub fn key_pair_address(&self) -> u32 {
        u32::from_be_bytes(self.bytes[20..24].try_into().unwrap())
    }

    /// Bytes 28..32: the hash address under `WOTS_HASH`.
    ///
    /// The one word that changes *within* a type, as `chain` walks a
    /// hash chain, which is why it is here rather than on [`Cleared`].
    pub fn set_hash_address(&mut self, hash: u32) { self.word(28, hash) }

    /// The full 32 byte address, which is what the SHAKE family hashes.
    pub fn as_bytes(&self) -> &[u8; 32] { &self.bytes }

    /// The 22 byte compressed address, which is what the SHA-2 family
    /// hashes: `ADRS[3] ‖ ADRS[8..16] ‖ ADRS[19] ‖ ADRS[20..32]`.
    ///
    /// One byte of the layer, eight of the tree, one of the type, and
    /// the last twelve whole. The bytes it drops are the high bytes of
    /// three fields whose values never reach them - `d` is at most 22,
    /// the type is at most 6, and the tree index is bounded by `2^68` -
    /// so dropping them loses nothing. **That is an invariant, not an
    /// observation**, so it is checked: if a caller has somehow put a
    /// value in those bytes, compressing would quietly map two distinct
    /// addresses to one, and two addresses that collide is precisely
    /// what the address structure exists to prevent.
    pub fn compressed(&self) -> Result<[u8; 22], String> {
        for (offset, what) in [(0usize, "layer address"),
                               (4, "tree address"),
                               (16, "type")] {
            if self.bytes[offset..offset + 3].iter().any(|&b| b != 0) {
                return Err(format!(
                    "SLH-DSA address: the {} has a value that does not fit \
                     the compressed form the SHA-2 family hashes. Two \
                     distinct addresses would compress to the same 22 bytes, \
                     which defeats the point of having addresses.", what));
            }
        }
        let mut out = [0u8; 22];
        out[0] = self.bytes[3];
        out[1..9].copy_from_slice(&self.bytes[8..16]);
        out[9] = self.bytes[19];
        out[10..22].copy_from_slice(&self.bytes[20..32]);
        Ok(out)
    }
}

/// The four keyed hash functions of a parameter set, bound to one
/// `PK.seed`.
///
/// `PRF`, `F`, `H` and `T_l`. Not `H_msg` or `PRF_msg`: those two are
/// only reachable from signing, they need MGF1 and HMAC rather than a
/// bare hash, and adding them now would mean adding two untested
/// functions to a file whose whole claim is that every line in it is
/// checked against NIST's answers.
///
/// The `Debug` here prints the parameter set's name and the public seed,
/// both of which are public by definition. Nothing secret is reachable
/// from a `Hasher`: `SK.seed` is an argument to [`Hasher::prf`] and is
/// not held.
#[derive(Debug)]
pub struct Hasher<'a> {
    parameters: &'static Parameters,
    pk_seed: &'a [u8],
}

impl<'a> Hasher<'a> {
    /// Bind a parameter set to a public seed.
    ///
    /// The seed's length is checked here rather than trusted, because
    /// `PK.seed` is prefixed to every hash input in the scheme and a
    /// short one would shift every subsequent byte.
    pub fn new(parameters: &'static Parameters, pk_seed: &'a [u8])
            -> Result<Hasher<'a>, String> {
        if pk_seed.len() != parameters.n {
            return Err(format!(
                "{}: PK.seed is {} bytes and should be {}.",
                parameters.name, pk_seed.len(), parameters.n));
        }
        Ok(Hasher { parameters, pk_seed })
    }

    /// The parameter set this hasher belongs to.
    pub fn parameters(&self) -> &'static Parameters { self.parameters }

    /// `SHAKE256(PK.seed ‖ ADRS ‖ tail, 8n)`.
    ///
    /// One function for all four of PRF, F, H and T_l, which in the
    /// SHAKE family really are the same construction - the address is
    /// what separates them.
    fn shake(&self, adrs: &Adrs, tail: &[&[u8]]) -> Result<Vec<u8>, String> {
        let mut sponge = Keccak::shake(256, self.parameters.n)?;
        sponge.update(self.pk_seed);
        sponge.update(adrs.as_bytes());
        for part in tail {
            sponge.update(part);
        }
        Ok(sponge.squeeze(self.parameters.n))
    }

    /// `Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64-n) ‖ ADRS^c ‖ tail))`.
    fn sha256(&self, adrs: &Adrs, tail: &[&[u8]]) -> Result<Vec<u8>, String> {
        let mut hash = SHA256::new(self.pk_seed);
        hash.update(&[0u8; 64][..64 - self.parameters.n]);
        hash.update(&adrs.compressed()?);
        for part in tail {
            hash.update(part);
        }
        let mut digest = hash.digest();
        digest.truncate(self.parameters.n);
        Ok(digest)
    }

    /// `Trunc_n(SHA-512(PK.seed ‖ toByte(0, 128-n) ‖ ADRS^c ‖ tail))`.
    ///
    /// **Only `H` and `T_l`, and only above `n = 16`.** The padding
    /// grows with the block size, from `64 - n` to `128 - n`, which is a
    /// second thing to get wrong in the same place.
    fn sha512(&self, adrs: &Adrs, tail: &[&[u8]]) -> Result<Vec<u8>, String> {
        let mut hash = SHA512::new(self.pk_seed, 512);
        hash.update(&[0u8; 128][..128 - self.parameters.n]);
        hash.update(&adrs.compressed()?);
        for part in tail {
            hash.update(part);
        }
        let mut digest = hash.digest();
        digest.truncate(self.parameters.n);
        Ok(digest)
    }

    /// Whether this set's `H` and `T_l` use SHA-512.
    ///
    /// True for the SHA-2 sets above `n = 16` and nothing else. Written
    /// once, here, rather than inline at both call sites.
    fn wide(&self) -> bool {
        self.parameters.family == Family::Sha2 && self.parameters.n > 16
    }

    /// `PRF(PK.seed, SK.seed, ADRS)`: the secret value at one address.
    ///
    /// Always the narrow hash in the SHA-2 family, whatever `n` is.
    pub fn prf(&self, sk_seed: &[u8], adrs: &Adrs) -> Result<Vec<u8>, String> {
        match self.parameters.family {
            Family::Shake => self.shake(adrs, &[sk_seed]),
            Family::Sha2 => self.sha256(adrs, &[sk_seed]),
        }
    }

    /// `F(PK.seed, ADRS, M1)`: one step of a hash chain.
    ///
    /// Always the narrow hash in the SHA-2 family, whatever `n` is,
    /// which is what makes `F` and `H` differ above `n = 16` despite
    /// looking identical in the pseudocode.
    pub fn f(&self, adrs: &Adrs, message: &[u8]) -> Result<Vec<u8>, String> {
        match self.parameters.family {
            Family::Shake => self.shake(adrs, &[message]),
            Family::Sha2 => self.sha256(adrs, &[message]),
        }
    }

    /// `H(PK.seed, ADRS, M2)`: one interior Merkle node from its two
    /// children.
    ///
    /// Takes the children separately rather than concatenated. The spec
    /// writes `H(..., left ‖ right)`; the joining happens inside the
    /// hash's `update` here, which saves building a temporary and, more
    /// usefully, makes it impossible to pass a single buffer whose split
    /// point is wrong.
    pub fn h(&self, adrs: &Adrs, left: &[u8], right: &[u8])
            -> Result<Vec<u8>, String> {
        match self.parameters.family {
            Family::Shake => self.shake(adrs, &[left, right]),
            Family::Sha2 if self.wide() => self.sha512(adrs, &[left, right]),
            Family::Sha2 => self.sha256(adrs, &[left, right]),
        }
    }

    /// `PRF_msg(SK.prf, opt_rand, M)`: the signature's randomiser `R`.
    ///
    /// **Not keyed by `PK.seed` and not addressed**, unlike the four
    /// above: it takes a secret key of its own and no `ADRS`, because it
    /// is called once per signature rather than once per tree node. So it
    /// is HMAC in the SHA-2 family where the others are a bare hash - a
    /// bare `SHA-256(SK.prf ‖ ...)` would be length-extendable in a
    /// construction whose whole first argument is secret.
    pub fn prf_msg(&self, sk_prf: &[u8], opt_rand: &[u8], message: &[u8])
            -> Result<Vec<u8>, String> {
        if sk_prf.len() != self.parameters.n {
            return Err(format!("{}: SK.prf is {} bytes and should be {}.",
                               self.parameters.name, sk_prf.len(),
                               self.parameters.n));
        }
        match self.parameters.family {
            Family::Shake => {
                let mut sponge = Keccak::shake(256, self.parameters.n)?;
                sponge.update(sk_prf);
                sponge.update(opt_rand);
                sponge.update(message);
                Ok(sponge.squeeze(self.parameters.n))
            }
            Family::Sha2 => {
                // `opt_rand ‖ M` is the HMAC message and `SK.prf` the key.
                let mut input = Vec::with_capacity(opt_rand.len()
                                                   + message.len());
                input.extend_from_slice(opt_rand);
                input.extend_from_slice(message);
                let mut tag = if self.wide() {
                    Hmac::mac(SHA512::new(&[], 512), sk_prf, &input)
                } else {
                    Hmac::mac(SHA256::new(&[]), sk_prf, &input)
                };
                tag.truncate(self.parameters.n);
                Ok(tag)
            }
        }
    }

    /// `H_msg(R, PK.seed, PK.root, M)`: the `m` byte digest that chooses
    /// which leaf signs this message.
    ///
    /// The SHA-2 family's form is the odd one in this file: a hash of
    /// everything, then **MGF1 over `R ‖ PK.seed ‖ that hash`** to reach
    /// `m` bytes, because `m` is 30 to 49 bytes and no SHA-2 output is
    /// that length. MGF1 is the same function RSA-OAEP and PSS use, so
    /// this calls `rsa`'s rather than carrying a second copy.
    ///
    /// Note what MGF1's seed is and is not: `R ‖ PK.seed ‖ H(...)`, with
    /// `R` and `PK.seed` appearing **twice** in the construction, once
    /// inside the inner hash and once in the seed. Dropping the outer
    /// copy looks like removing a redundancy and gives a different digest
    /// for every message.
    pub fn h_msg(&self, randomiser: &[u8], pk_root: &[u8], message: &[u8])
            -> Result<Vec<u8>, String> {
        let m = self.parameters.m;
        if randomiser.len() != self.parameters.n
                || pk_root.len() != self.parameters.n {
            return Err(format!(
                "{}: H_msg takes an {} byte R and PK.root, not {} and {}.",
                self.parameters.name, self.parameters.n, randomiser.len(),
                pk_root.len()));
        }

        if self.parameters.family == Family::Shake {
            let mut sponge = Keccak::shake(256, m)?;
            sponge.update(randomiser);
            sponge.update(self.pk_seed);
            sponge.update(pk_root);
            sponge.update(message);
            return Ok(sponge.squeeze(m));
        }

        let (inner, name): (Vec<u8>, &str) = if self.wide() {
            let mut hash = SHA512::new(randomiser, 512);
            hash.update(self.pk_seed);
            hash.update(pk_root);
            hash.update(message);
            (hash.digest(), "sha512")
        } else {
            let mut hash = SHA256::new(randomiser);
            hash.update(self.pk_seed);
            hash.update(pk_root);
            hash.update(message);
            (hash.digest(), "sha256")
        };

        let mut seed = Vec::with_capacity(2 * self.parameters.n + inner.len());
        seed.extend_from_slice(randomiser);
        seed.extend_from_slice(self.pk_seed);
        seed.extend_from_slice(&inner);
        crate::publickey_ciphers::rsa::mgf1(name, &seed, m)
    }

    /// `T_l(PK.seed, ADRS, M_l)`: compress `l` values into one.
    ///
    /// Used with `l = len` over a WOTS+ public key and, once signing
    /// exists, with `l = k` over the FORS roots. The `l` is implicit in
    /// how much data is passed: the function is the same for every `l`,
    /// which is why the spec gives it a subscript and no argument.
    pub fn t(&self, adrs: &Adrs, message: &[u8]) -> Result<Vec<u8>, String> {
        match self.parameters.family {
            Family::Shake => self.shake(adrs, &[message]),
            Family::Sha2 if self.wide() => self.sha512(adrs, &[message]),
            Family::Sha2 => self.sha256(adrs, &[message]),
        }
    }
}

/// FIPS 205 algorithm 5, `chain`: walk `steps` links of a hash chain
/// from position `start`.
///
/// The address's hash field is set to the position *before* each step,
/// so a chain from 0 by `W - 1` steps uses hash addresses 0 through
/// `W - 2`. Off by one here produces a scheme that works and matches
/// nothing.
fn chain(hasher: &Hasher, adrs: &mut Adrs, start: usize, steps: usize,
         value: &[u8]) -> Result<Vec<u8>, String> {
    let mut current = value.to_vec();
    for step in start..start + steps {
        adrs.set_hash_address(step as u32);
        current = hasher.f(adrs, &current)?;
    }
    Ok(current)
}

/// FIPS 205 algorithm 6, `wots_pkGen`: the public key of one WOTS+ key
/// pair.
///
/// `len` chains, each walked its full `W - 1` steps from a secret value
/// derived at its own address, then all of them compressed with `T_len`.
///
/// The address arrives carrying the layer, tree and key pair this WOTS+
/// key belongs to, and leaves rewritten: the caller must set everything
/// from byte 16 on afterwards, which the per-type setters on [`Adrs`]
/// make unavoidable.
fn wots_public_key(hasher: &Hasher, adrs: &mut Adrs, sk_seed: &[u8])
        -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let key_pair = adrs.key_pair_address();

    // The concatenation `T_len` will consume, built once.
    let mut chains = Vec::with_capacity(parameters.len() * parameters.n);

    for index in 0..parameters.len() as u32 {
        // Two addresses in the spec: `skADRS` under WOTS_PRF for the
        // secret, and `ADRS` under WOTS_HASH for the chain. One address
        // here, switched between them - and switching writes all three
        // of the words that follow the type, so nothing can be stale.
        adrs.set_wots(WotsAddress::Secret, key_pair, index, 0);
        let secret = hasher.prf(sk_seed, adrs)?;

        adrs.set_wots(WotsAddress::Chain, key_pair, index, 0);
        chains.extend_from_slice(&chain(hasher, adrs, 0, W - 1, &secret)?);
    }

    // `wotspkADRS`: same key pair, type WOTS_PK, everything else zero.
    adrs.set_wots_public_key(key_pair);
    hasher.t(adrs, &chains)
}

/// FIPS 205 algorithm 9, `xmss_node`: the Merkle node at height `height`
/// and index `index` of one XMSS tree.
///
/// Recursive, as the standard writes it. At height 0 a node is a WOTS+
/// public key; above that it is `H` of its two children. The whole cost
/// of key generation is here: computing the root at height `h'` visits
/// all `2^h'` leaves, and each leaf is `len * (W - 1)` hash calls.
fn xmss_node(hasher: &Hasher, adrs: &mut Adrs, sk_seed: &[u8], index: u32,
             height: usize) -> Result<Vec<u8>, String> {
    if height == 0 {
        adrs.set_wots(WotsAddress::Chain, index, 0, 0);
        return wots_public_key(hasher, adrs, sk_seed);
    }

    let left = xmss_node(hasher, adrs, sk_seed, 2 * index, height - 1)?;
    let right = xmss_node(hasher, adrs, sk_seed, 2 * index + 1, height - 1)?;

    // The children rewrote the address; every field from 16 on is set
    // again here, which `set_tree` does not let this forget.
    adrs.set_tree(height as u32, index);
    hasher.h(adrs, &left, &right)
}

/// FIPS 205 algorithm 18, `slh_keygen_internal`: a key pair from three
/// seeds.
///
/// Returns `(secret_key, public_key)` as the byte strings FIPS 205
/// defines: `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` and
/// `PK.seed ‖ PK.root`.
///
/// The seeds are inputs rather than generated here on purpose: that is
/// what makes the function testable against NIST's vectors, which state
/// the seeds. A wrapper that draws them from the system generator is the
/// right public API and belongs on top of this, not instead of it.
///
/// **This is slow at the `s` parameter sets**, and the cost is
/// structural: `2^h'` WOTS+ public keys, which is 512 of them at
/// `h' = 9`, each `len` chains of 15 `F` calls. A quarter of a million
/// hash calls for one key. There is no way to produce the root without
/// producing every leaf.
pub fn key_gen_internal(parameters: &'static Parameters, sk_seed: &[u8],
                        sk_prf: &[u8], pk_seed: &[u8])
        -> Result<(Vec<u8>, Vec<u8>), String> {
    for (what, seed) in [("SK.seed", sk_seed), ("SK.prf", sk_prf),
                         ("PK.seed", pk_seed)] {
        if seed.len() != parameters.n {
            return Err(format!("{}: {} is {} bytes and should be {}.",
                               parameters.name, what, seed.len(),
                               parameters.n));
        }
    }

    let hasher = Hasher::new(parameters, pk_seed)?;

    // The top layer of the hypertree, tree 0.
    let mut adrs = Adrs::new();
    adrs.set_layer_address((parameters.d - 1) as u32);
    adrs.set_tree_address(0);

    let root = xmss_node(&hasher, &mut adrs, sk_seed, 0, parameters.h_prime)?;

    let mut public = Vec::with_capacity(parameters.public_key_len());
    public.extend_from_slice(pk_seed);
    public.extend_from_slice(&root);

    let mut secret = Vec::with_capacity(parameters.secret_key_len());
    secret.extend_from_slice(sk_seed);
    secret.extend_from_slice(sk_prf);
    secret.extend_from_slice(&public);

    Ok((secret, public))
}

// ---------------------------------------------------------------- signing ---
//
// Everything above is reachable from key generation and is checked by
// NIST's 120 keyGen vectors. Everything below is signing, checked by the
// sigGen vectors in the same file.

/// FIPS 205 algorithm 4, `base_2b`: read `out_len` integers of `b` bits
/// out of a byte string, most significant bit first.
///
/// Used twice with different widths and it is not the same job either
/// time: with `b = LG_W` it cuts a message into WOTS+ digits, and with
/// `b = a` it cuts the message digest into FORS tree indices. The bit
/// order is the thing to get right - this consumes bits from the top of
/// each byte, so a reader that assumed little-endian digits would produce
/// a valid-looking signature under a different message.
fn base_2b(input: &[u8], b: usize, out_len: usize) -> Result<Vec<u32>, String> {
    if b == 0 || b > 24 {
        return Err(format!("base_2b: {b} bits per digit is out of range."));
    }
    let needed = (out_len * b).div_ceil(8);
    if input.len() < needed {
        return Err(format!(
            "base_2b: {} digits of {} bits need {} bytes and only {} were \
             given.", out_len, b, needed, input.len()));
    }

    let mut out = Vec::with_capacity(out_len);
    let mut at = 0usize;
    let mut total: u64 = 0;
    let mut bits = 0usize;
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | input[at] as u64;
            at += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) & ((1u64 << b) - 1)) as u32);
    }
    Ok(out)
}

/// The `len` digits a WOTS+ key signs: `len1` message digits then `len2`
/// checksum digits.
///
/// Shared by signing and by recovering a public key from a signature,
/// which matters more than saving the duplication: the checksum is what
/// stops an attacker raising a digit, and a signer and verifier that
/// computed it differently would simply fail to interoperate, with the
/// checksum having protected nothing. One function, both callers.
///
/// The left shift is the part that looks wrong and is not. `len2 * LG_W`
/// is 12 bits of checksum, which does not fill the 2 bytes it is written
/// into, so FIPS 205 shifts it up by `(8 - (len2 * lg_w) mod 8) mod 8` -
/// four bits here - so that the checksum digits land at the top of the
/// two bytes rather than the bottom.
fn wots_digits(parameters: &Parameters, message: &[u8])
        -> Result<Vec<u32>, String> {
    if message.len() != parameters.n {
        return Err(format!(
            "{}: a WOTS+ key signs exactly {} bytes, not {}.",
            parameters.name, parameters.n, message.len()));
    }
    let mut digits = base_2b(message, LG_W, parameters.len1())?;

    let checksum: u32 = digits.iter().map(|d| (W - 1) as u32 - d).sum();
    let checksum_bits = parameters.len2() * LG_W;
    let shifted = (checksum as u64) << ((8 - (checksum_bits % 8)) % 8);
    let width = checksum_bits.div_ceil(8);
    // `toByte(shifted, width)`: big-endian, the low `width` bytes.
    let full = shifted.to_be_bytes();
    let bytes = &full[full.len() - width..];

    digits.extend(base_2b(bytes, LG_W, parameters.len2())?);
    Ok(digits)
}

/// FIPS 205 algorithm 7, `wots_sign`: reveal each chain at the depth its
/// digit names.
///
/// **A WOTS+ key signs once.** Two signatures under one key reveal enough
/// of the chains to forge a third message; the whole of SLH-DSA's design
/// above this function exists to make signing twice with one key
/// unreachable. Nothing in this function can enforce that, which is why
/// it is not public.
fn wots_sign(hasher: &Hasher, adrs: &mut Adrs, message: &[u8], sk_seed: &[u8])
        -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let key_pair = adrs.key_pair_address();
    let digits = wots_digits(parameters, message)?;

    let mut signature = Vec::with_capacity(parameters.len() * parameters.n);
    for (index, digit) in digits.iter().enumerate() {
        let index = index as u32;
        adrs.set_wots(WotsAddress::Secret, key_pair, index, 0);
        let secret = hasher.prf(sk_seed, adrs)?;

        adrs.set_wots(WotsAddress::Chain, key_pair, index, 0);
        signature.extend_from_slice(
            &chain(hasher, adrs, 0, *digit as usize, &secret)?);
    }
    Ok(signature)
}

/// FIPS 205 algorithm 8, `wots_pkFromSig`: finish each chain from where
/// the signature stopped.
///
/// The verifier's half of `wots_sign`, and the two must agree on where
/// each chain starts: the signature holds the value at depth `digit`, so
/// the verifier walks the remaining `w - 1 - digit` steps *beginning at*
/// `digit`. Starting at zero instead would hash the right number of times
/// from the wrong offset and reject every valid signature.
fn wots_public_key_from_signature(hasher: &Hasher, adrs: &mut Adrs,
                                  signature: &[u8], message: &[u8])
        -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let key_pair = adrs.key_pair_address();
    let n = parameters.n;
    if signature.len() != parameters.len() * n {
        return Err(format!(
            "{}: a WOTS+ signature is {} bytes, not {}.", parameters.name,
            parameters.len() * n, signature.len()));
    }
    let digits = wots_digits(parameters, message)?;

    let mut chains = Vec::with_capacity(parameters.len() * n);
    for (index, digit) in digits.iter().enumerate() {
        adrs.set_wots(WotsAddress::Chain, key_pair, index as u32, 0);
        let start = *digit as usize;
        chains.extend_from_slice(&chain(hasher, adrs, start, W - 1 - start,
                                        &signature[index * n..(index + 1) * n])?);
    }

    adrs.set_wots_public_key(key_pair);
    hasher.t(adrs, &chains)
}

/// FIPS 205 algorithm 10, `xmss_sign`: a WOTS+ signature plus the
/// authentication path to the tree's root.
///
/// The path is the sibling at each height, and the sibling of node `i` at
/// height `j` is `(idx >> j) ^ 1` - an XOR, not a `+ 1`. With `+ 1` the
/// path would be right for every even index and wrong for every odd one,
/// so half of all signatures would verify.
fn xmss_sign(hasher: &Hasher, adrs: &mut Adrs, message: &[u8], sk_seed: &[u8],
             leaf: u32) -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let mut authentication = Vec::with_capacity(parameters.h_prime
                                                * parameters.n);
    for height in 0..parameters.h_prime {
        let sibling = (leaf >> height) ^ 1;
        authentication.extend_from_slice(
            &xmss_node(hasher, adrs, sk_seed, sibling, height)?);
    }

    adrs.set_wots(WotsAddress::Chain, leaf, 0, 0);
    let mut signature = wots_sign(hasher, adrs, message, sk_seed)?;
    signature.extend_from_slice(&authentication);
    Ok(signature)
}

/// FIPS 205 algorithm 11, `xmss_pkFromSig`: fold the authentication path
/// back up to a root.
///
/// Which side each sibling goes on is decided by a bit of the leaf index,
/// and it is the *`k`th* bit at step `k` rather than the lowest bit
/// throughout. Getting that wrong gives a verifier that accepts leaf 0 and
/// rejects the rest.
fn xmss_public_key_from_signature(hasher: &Hasher, adrs: &mut Adrs, leaf: u32,
                                  signature: &[u8], message: &[u8])
        -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let n = parameters.n;
    let wots_len = parameters.len() * n;
    if signature.len() != wots_len + parameters.h_prime * n {
        return Err(format!(
            "{}: an XMSS signature is {} bytes, not {}.", parameters.name,
            wots_len + parameters.h_prime * n, signature.len()));
    }

    adrs.set_wots(WotsAddress::Chain, leaf, 0, 0);
    let mut node = wots_public_key_from_signature(
        hasher, adrs, &signature[..wots_len], message)?;

    // The tree index halves at every step, which is the same as
    // `leaf >> (height + 1)` - the spec's two branches divide by two
    // either side of subtracting one, and both land here.
    let mut index = leaf;
    for height in 0..parameters.h_prime {
        let sibling = &signature[wots_len + height * n
                                 ..wots_len + (height + 1) * n];
        // Bit `height` of the leaf index, which is what decides
        // whether this node is its parent's left or right child.
        let left = (leaf >> height) & 1 == 0;
        index >>= 1;
        adrs.set_tree((height + 1) as u32, index);
        node = if left {
            hasher.h(adrs, &node, sibling)?
        } else {
            hasher.h(adrs, sibling, &node)?
        };
    }
    Ok(node)
}

/// FIPS 205 algorithm 16, `fors_skGen`: the secret value under one FORS
/// leaf.
fn fors_secret(hasher: &Hasher, adrs: &mut Adrs, sk_seed: &[u8],
               key_pair: u32, index: u32) -> Result<Vec<u8>, String> {
    adrs.set_fors_secret(key_pair, index);
    hasher.prf(sk_seed, adrs)
}

/// FIPS 205 algorithm 17, `fors_node`: a node of one FORS tree.
///
/// The same shape as [`xmss_node`] over different addresses, and
/// deliberately not merged with it: the leaf of an XMSS tree is a whole
/// WOTS+ public key while the leaf of a FORS tree is `F` of one secret,
/// and the address types differ at every level. A shared "Merkle tree"
/// helper would have to be told which of those it was doing at each step,
/// which is the same decision written less clearly.
fn fors_node(hasher: &Hasher, adrs: &mut Adrs, sk_seed: &[u8], key_pair: u32,
             index: u32, height: usize) -> Result<Vec<u8>, String> {
    if height == 0 {
        let secret = fors_secret(hasher, adrs, sk_seed, key_pair, index)?;
        adrs.set_fors_tree(key_pair, 0, index);
        return hasher.f(adrs, &secret);
    }
    let left = fors_node(hasher, adrs, sk_seed, key_pair, 2 * index,
                         height - 1)?;
    let right = fors_node(hasher, adrs, sk_seed, key_pair, 2 * index + 1,
                          height - 1)?;
    adrs.set_fors_tree(key_pair, height as u32, index);
    hasher.h(adrs, &left, &right)
}

/// FIPS 205 algorithm 18, `fors_sign`: `k` revealed leaves with their
/// authentication paths.
///
/// FORS is a *few*-time scheme, which is the point of it: the message
/// digest picks one leaf out of `2^a` in each of `k` trees, and signing
/// two messages that pick overlapping leaves leaks a little. SLH-DSA's
/// parameters are chosen so that the leak stays below the security level
/// for the number of signatures a key is allowed. Nothing here enforces
/// that count.
///
/// Note `i * 2^a + indices[i]`: leaf indices are global across the `k`
/// trees rather than per tree, so tree 1's leaf 0 is index `2^a`. Using a
/// per-tree index would make every tree derive the same secrets.
fn fors_sign(hasher: &Hasher, adrs: &mut Adrs, digest: &[u8], sk_seed: &[u8],
             key_pair: u32) -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let (a, k) = (parameters.a, parameters.k);
    let indices = base_2b(digest, a, k)?;

    let mut signature = Vec::with_capacity(k * (1 + a) * parameters.n);
    for (tree, chosen) in indices.iter().enumerate() {
        let tree = tree as u32;
        let base = tree << a;
        signature.extend_from_slice(
            &fors_secret(hasher, adrs, sk_seed, key_pair, base + chosen)?);

        for height in 0..a {
            let sibling = (chosen >> height) ^ 1;
            signature.extend_from_slice(&fors_node(
                hasher, adrs, sk_seed, key_pair,
                (tree << (a - height)) + sibling, height)?);
        }
    }
    Ok(signature)
}

/// FIPS 205 algorithm 19, `fors_pkFromSig`: the FORS public key a
/// signature implies.
///
/// Used by the verifier and also by the *signer*, which is worth knowing:
/// `slh_sign_internal` calls this to find the value the hypertree has to
/// sign, rather than recomputing the roots a second way. So a fault here
/// breaks signing and verification together rather than making them
/// disagree - which is why the sigGen vectors catch it at all.
fn fors_public_key_from_signature(hasher: &Hasher, adrs: &mut Adrs,
                                  signature: &[u8], digest: &[u8],
                                  key_pair: u32) -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let (a, k, n) = (parameters.a, parameters.k, parameters.n);
    if signature.len() != k * (1 + a) * n {
        return Err(format!(
            "{}: a FORS signature is {} bytes, not {}.", parameters.name,
            k * (1 + a) * n, signature.len()));
    }
    let indices = base_2b(digest, a, k)?;

    let mut roots = Vec::with_capacity(k * n);
    for (tree, chosen) in indices.iter().enumerate() {
        let tree = tree as u32;
        let at = tree as usize * (1 + a) * n;
        let secret = &signature[at..at + n];

        adrs.set_fors_tree(key_pair, 0, (tree << a) + chosen);
        let mut node = hasher.f(adrs, secret)?;

        let mut index = (tree << a) + chosen;
        for height in 0..a {
            let sibling = &signature[at + (1 + height) * n
                                     ..at + (2 + height) * n];
            let left = (chosen >> height) & 1 == 0;
            index >>= 1;
            adrs.set_fors_tree(key_pair, (height + 1) as u32, index);
            node = if left {
                hasher.h(adrs, &node, sibling)?
            } else {
                hasher.h(adrs, sibling, &node)?
            };
        }
        roots.extend_from_slice(&node);
    }

    adrs.set_fors_roots(key_pair);
    hasher.t(adrs, &roots)
}

/// FIPS 205 algorithm 12, `ht_sign`: one XMSS signature per hypertree
/// layer, each signing the root below it.
///
/// This is where the other `d - 1` layers finally do something - key
/// generation only ever builds the top one. The index walk is the part to
/// watch: after signing at a layer, the leaf for the next layer up is the
/// low `h'` bits of the current tree index, and the tree index shifts
/// right by `h'`.
fn ht_sign(hasher: &Hasher, sk_seed: &[u8], message: &[u8], tree: u64,
           leaf: u32) -> Result<Vec<u8>, String> {
    let parameters = hasher.parameters();
    let mut adrs = Adrs::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);

    let mut signature = xmss_sign(hasher, &mut adrs, message, sk_seed, leaf)?;
    let mut root = xmss_public_key_from_signature(
        hasher, &mut adrs, leaf, &signature, message)?;

    // The leaf for the layer above is the low `h'` bits of *this* layer's
    // tree index, and the tree index then shifts by the same amount.
    // Declared inside the loop because the value from layer 0 has already
    // been used and must not be carried in.
    let mut tree = tree;
    for layer in 1..parameters.d {
        let leaf = (tree & ((1u64 << parameters.h_prime) - 1)) as u32;
        tree >>= parameters.h_prime;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(tree);

        let above = xmss_sign(hasher, &mut adrs, &root, sk_seed, leaf)?;
        if layer < parameters.d - 1 {
            root = xmss_public_key_from_signature(hasher, &mut adrs, leaf,
                                                  &above, &root)?;
        }
        signature.extend_from_slice(&above);
    }
    Ok(signature)
}

/// FIPS 205 algorithm 13, `ht_verify`: walk the layers back up and
/// compare with `PK.root`.
fn ht_verify(hasher: &Hasher, message: &[u8], signature: &[u8], tree: u64,
             leaf: u32, root: &[u8]) -> Result<bool, String> {
    let parameters = hasher.parameters();
    let per_layer = (parameters.h_prime + parameters.len()) * parameters.n;
    if signature.len() != parameters.d * per_layer {
        return Err(format!(
            "{}: a hypertree signature is {} bytes, not {}.", parameters.name,
            parameters.d * per_layer, signature.len()));
    }

    let mut adrs = Adrs::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);

    let mut node = xmss_public_key_from_signature(
        hasher, &mut adrs, leaf, &signature[..per_layer], message)?;

    let mut tree = tree;
    for layer in 1..parameters.d {
        let leaf = (tree & ((1u64 << parameters.h_prime) - 1)) as u32;
        tree >>= parameters.h_prime;

        adrs.set_layer_address(layer as u32);
        adrs.set_tree_address(tree);

        node = xmss_public_key_from_signature(
            hasher, &mut adrs, leaf,
            &signature[layer * per_layer..(layer + 1) * per_layer], &node)?;
    }
    Ok(node == root)
}

/// Where the message digest splits into a FORS index, a tree index and a
/// leaf index.
///
/// `(md_bytes, tree_bytes, leaf_bytes)`, and they sum to `m`. That sum is
/// not a coincidence to be relied on quietly - `m` is a field of the
/// parameter table that key generation never reads, so
/// `test_the_digest_splits_exactly_into_m_bytes` checks it for all twelve
/// sets. A wrong `m` would otherwise show up only as a signature that
/// does not match.
fn digest_split(parameters: &Parameters) -> (usize, usize, usize) {
    let md = (parameters.k * parameters.a).div_ceil(8);
    let tree = (parameters.h - parameters.h_prime).div_ceil(8);
    let leaf = parameters.h_prime.div_ceil(8);
    (md, tree, leaf)
}

/// `toInt` of up to eight bytes, then reduced to `bits` bits.
///
/// The reduction is written as a branch because `1u64 << 64` is undefined
/// and `h - h'` reaches 64 at `SLH-DSA-SHAKE-256f`, where the mask is the
/// whole word and there is nothing to mask.
fn index_from(bytes: &[u8], bits: usize) -> Result<u64, String> {
    if bytes.len() > 8 {
        return Err(format!("SLH-DSA: an index field of {} bytes does not fit \
                            a u64; the parameter table is wrong.",
                           bytes.len()));
    }
    let mut value: u64 = 0;
    for byte in bytes {
        value = (value << 8) | *byte as u64;
    }
    Ok(if bits >= 64 { value } else { value & ((1u64 << bits) - 1) })
}

/// FIPS 205 algorithm 19, `slh_sign_internal`.
///
/// `opt_rand` is what makes this deterministic or hedged, and both are
/// standard: passing `PK.seed` gives the deterministic signature, passing
/// `n` fresh random bytes gives a hedged one. **They differ**, and both
/// verify - so a test that asserted signing was deterministic would be
/// asserting the wrong thing for the hedged mode, unlike EdDSA where
/// determinism is the specification.
///
/// `sk` is `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`, the byte string FIPS
/// 205 defines and the one [`key_gen_internal`] returns.
pub fn sign_internal(parameters: &'static Parameters, sk: &[u8],
                     message: &[u8], opt_rand: &[u8])
        -> Result<Vec<u8>, String> {
    let n = parameters.n;
    if sk.len() != parameters.secret_key_len() {
        return Err(format!("{}: a private key is {} bytes, not {}.",
                           parameters.name, parameters.secret_key_len(),
                           sk.len()));
    }
    if opt_rand.len() != n {
        return Err(format!(
            "{}: opt_rand is {} bytes and should be {}. Pass PK.seed for a \
             deterministic signature or {} random bytes for a hedged one.",
            parameters.name, opt_rand.len(), n, n));
    }
    let (sk_seed, sk_prf) = (&sk[..n], &sk[n..2 * n]);
    let (pk_seed, pk_root) = (&sk[2 * n..3 * n], &sk[3 * n..]);

    let hasher = Hasher::new(parameters, pk_seed)?;

    let randomiser = hasher.prf_msg(sk_prf, opt_rand, message)?;
    let digest = hasher.h_msg(&randomiser, pk_root, message)?;

    let (md_bytes, tree_bytes, leaf_bytes) = digest_split(parameters);
    let md = &digest[..md_bytes];
    let tree = index_from(&digest[md_bytes..md_bytes + tree_bytes],
                          parameters.h - parameters.h_prime)?;
    let leaf = index_from(
        &digest[md_bytes + tree_bytes..md_bytes + tree_bytes + leaf_bytes],
        parameters.h_prime)? as u32;

    // FORS lives at layer 0 of the tree the digest chose, under the key
    // pair the leaf index chose.
    let mut adrs = Adrs::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);

    let fors = fors_sign(&hasher, &mut adrs, md, sk_seed, leaf)?;
    let fors_key = fors_public_key_from_signature(&hasher, &mut adrs, &fors,
                                                  md, leaf)?;
    let hypertree = ht_sign(&hasher, sk_seed, &fors_key, tree, leaf)?;

    let mut signature = Vec::with_capacity(randomiser.len() + fors.len()
                                           + hypertree.len());
    signature.extend_from_slice(&randomiser);
    signature.extend_from_slice(&fors);
    signature.extend_from_slice(&hypertree);
    Ok(signature)
}

/// FIPS 205 algorithm 20, `slh_verify_internal`.
///
/// Returns `Ok(false)` for a signature that is wrong - including one of
/// the wrong length, which ACVP's `sigVer` cases expect refused rather
/// than reported - and `Err` only when the inputs cannot be interpreted
/// at all: a public key of the wrong length. The distinction matters for
/// the caller: a `false` is a verification failure to be reported as
/// such, while an `Err` means the caller passed something that was never
/// a key.
///
/// `pk` is `PK.seed ‖ PK.root`.
pub fn verify_internal(parameters: &'static Parameters, pk: &[u8],
                       message: &[u8], signature: &[u8])
        -> Result<bool, String> {
    let n = parameters.n;
    if pk.len() != parameters.public_key_len() {
        return Err(format!("{}: a public key is {} bytes, not {}.",
                           parameters.name, parameters.public_key_len(),
                           pk.len()));
    }
    let fors_len = parameters.k * (1 + parameters.a) * n;
    let hypertree_len = parameters.d
        * (parameters.h_prime + parameters.len()) * n;
    if signature.len() != n + fors_len + hypertree_len {
        // Not an error: a signature of the wrong length is a signature
        // that does not verify, and saying so as `Ok(false)` keeps a
        // caller from having to treat "too short" differently from
        // "wrong".
        return Ok(false);
    }
    let (pk_seed, pk_root) = (&pk[..n], &pk[n..]);
    let hasher = Hasher::new(parameters, pk_seed)?;

    let randomiser = &signature[..n];
    let fors = &signature[n..n + fors_len];
    let hypertree = &signature[n + fors_len..];

    let digest = hasher.h_msg(randomiser, pk_root, message)?;
    let (md_bytes, tree_bytes, leaf_bytes) = digest_split(parameters);
    let md = &digest[..md_bytes];
    let tree = index_from(&digest[md_bytes..md_bytes + tree_bytes],
                          parameters.h - parameters.h_prime)?;
    let leaf = index_from(
        &digest[md_bytes + tree_bytes..md_bytes + tree_bytes + leaf_bytes],
        parameters.h_prime)? as u32;

    let mut adrs = Adrs::new();
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);

    let fors_key = fors_public_key_from_signature(&hasher, &mut adrs, fors,
                                                  md, leaf)?;
    ht_verify(&hasher, &fors_key, hypertree, tree, leaf, pk_root)
}

// ------------------------------------------------- the external interface ---
//
// Everything above is `slh_sign_internal` and `slh_verify_internal`, which
// sign a message as it is given. FIPS 205's *external* interface - the one
// its section 10 calls `slh_sign` and the one another implementation's
// default API uses - signs a message that has been wrapped first, and the
// wrapping is a domain separator.

// `PreHash`, `PRE_HASHES`, `MAX_CONTEXT` and `wrap` are in `pq::prehash`,
// shared with ML-DSA, whose external interface is the same construction.
pub use super::prehash::{PreHash, MAX_CONTEXT, PRE_HASHES};
use super::prehash::wrap;

/// FIPS 205 algorithm 22, `slh_sign`: the external interface.
///
/// What a caller should reach for. `context` is a domain separator - an
/// empty one is normal and is what a protocol that has no opinion should
/// pass - and `pre_hash` picks between the pure form and hashing the
/// message first.
///
/// `opt_rand` chooses deterministic (`PK.seed`) or hedged (`n` random
/// bytes), exactly as in [`sign_internal`].
///
/// **A signature made here is not interchangeable with one made by
/// [`sign_internal`]** on the same message, and that is deliberate: they
/// sign different byte strings. Nothing but a protocol that specifies the
/// internal interface should use that one.
pub fn sign(parameters: &'static Parameters, sk: &[u8], message: &[u8],
            context: &[u8], pre_hash: Option<PreHash>, opt_rand: &[u8])
        -> Result<Vec<u8>, String> {
    let wrapped = wrap(message, context, pre_hash)?;
    sign_internal(parameters, sk, &wrapped, opt_rand)
}

/// FIPS 205 algorithm 24, `slh_verify`: the external interface.
///
/// The context and pre-hash must be the same ones the signer used. A
/// mismatch is a verification failure rather than an error, because from
/// the verifier's side it is indistinguishable from a wrong signature -
/// which is precisely what the domain separation is for.
pub fn verify(parameters: &'static Parameters, pk: &[u8], message: &[u8],
              context: &[u8], pre_hash: Option<PreHash>, signature: &[u8])
        -> Result<bool, String> {
    let wrapped = wrap(message, context, pre_hash)?;
    verify_internal(parameters, pk, &wrapped, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `h = d * h'` for all twelve, which ties the one field key
    /// generation never reads to the two it does.
    ///
    /// `h` is the total hypertree height and it is not free: it is the
    /// product of the number of layers and the height of one layer. A
    /// typo in any of the three shows up here, and `d` and `h_prime` are
    /// both checked against NIST's answers by the vectors, so this pins
    /// `h` to numbers that are known good.
    #[test]
    fn test_the_tree_shape_is_internally_consistent() {
        for set in &PARAMETER_SETS {
            assert_eq!(set.h, set.d * set.h_prime,
                       "{}: h should be d * h'", set.name);
        }
        assert_eq!(PARAMETER_SETS.len(), 12);
    }

    /// The table covers each combination once: three security levels,
    /// two hash families, two tree shapes.
    ///
    /// A duplicated or missing row would otherwise be invisible - the
    /// vectors iterate the file, not the table, so a parameter set this
    /// library simply lacks would look like a shorter test rather than a
    /// failure.
    #[test]
    fn test_every_approved_combination_is_present_exactly_once() {
        let mut seen = std::collections::HashSet::new();
        for set in &PARAMETER_SETS {
            assert!(seen.insert(set.name), "{} appears twice", set.name);
            assert!(matches!(set.n, 16 | 24 | 32), "{}: odd n", set.name);
        }
        for level in ["128", "192", "256"] {
            for family in ["SHA2", "SHAKE"] {
                for shape in ["s", "f"] {
                    let name = format!("SLH-DSA-{family}-{level}{shape}");
                    assert!(seen.contains(name.as_str()),
                            "{name} is missing from the table");
                }
            }
        }
        assert_eq!(seen.len(), 12);
    }

    /// The derived lengths agree with FIPS 205's table.
    ///
    /// `len` is 35, 51 and 67 at the three security levels, and it is
    /// derived here rather than stated. If the derivation were wrong the
    /// vectors would catch it - a WOTS+ key with the wrong number of
    /// chains gives the wrong root - but this says which of the three
    /// steps went wrong instead of only that the root differs.
    #[test]
    fn test_the_derived_lengths_are_the_documented_ones() {
        for set in &PARAMETER_SETS {
            assert_eq!(set.len1(), 2 * set.n, "{}: len1", set.name);
            assert_eq!(set.len2(), 3, "{}: len2 is 3 for every \
                                       approved set", set.name);
            let expected = match set.n { 16 => 35, 24 => 51, _ => 67 };
            assert_eq!(set.len(), expected, "{}: len", set.name);
            assert_eq!(set.public_key_len(), 2 * set.n);
            assert_eq!(set.secret_key_len(), 4 * set.n);
        }
    }

    #[test]
    fn test_an_unknown_parameter_set_is_refused_by_name() {
        // A near miss, because a near miss is what happens in practice:
        // SPHINCS+ spelt its sets with a plus and a lower case s.
        let error = parameters("sphincs+-sha2-128s").unwrap_err();
        assert!(error.contains("Unknown SLH-DSA parameter set"), "{error}");
        assert!(error.contains("SLH-DSA-SHA2-128s"),
                "the refusal should list what is available: {error}");
        assert!(parameters("SLH-DSA-SHA2-128S").is_err(),
                "the names are fixed strings in a standard, not \
                 identifiers, so case is not folded");
    }

    /// The address's byte layout, field by field.
    ///
    /// Written as "set one field, see exactly those bytes change",
    /// because the layout is the thing this file says is most dangerous
    /// to get wrong and the vectors would only report a wrong root.
    #[test]
    fn test_the_address_fields_land_where_the_standard_puts_them() {
        let mut adrs = Adrs::new();
        assert_eq!(adrs.as_bytes(), &[0u8; 32]);

        adrs.set_layer_address(0x07);
        assert_eq!(&adrs.as_bytes()[0..4], &[0, 0, 0, 7]);

        adrs.set_tree_address(0x0102_0304_0506_0708);
        assert_eq!(&adrs.as_bytes()[4..8], &[0, 0, 0, 0],
                   "the top four bytes of the tree field stay zero");
        assert_eq!(&adrs.as_bytes()[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);

        adrs.set_wots(WotsAddress::Chain, 0x0a, 0x0b, 0x0c);
        assert_eq!(&adrs.as_bytes()[16..20], &[0, 0, 0, 0], "WOTS_HASH is 0");
        assert_eq!(&adrs.as_bytes()[20..24], &[0, 0, 0, 0x0a]);
        assert_eq!(&adrs.as_bytes()[24..28], &[0, 0, 0, 0x0b]);
        assert_eq!(&adrs.as_bytes()[28..32], &[0, 0, 0, 0x0c]);
        assert_eq!(adrs.key_pair_address(), 0x0a);

        adrs.set_wots(WotsAddress::Secret, 0x0a, 0x0b, 0);
        assert_eq!(&adrs.as_bytes()[16..20], &[0, 0, 0, 5], "WOTS_PRF is 5");

        // And the layer and tree survived all of it: nothing below byte
        // 16 is touched by a type change.
        assert_eq!(&adrs.as_bytes()[0..16],
                   &[0, 0, 0, 7, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// Changing type clears the words the old type left behind.
    ///
    /// This is the staleness trap from the top of the file, tested from
    /// the outside: after a `WOTS_HASH` address with all three words
    /// full, a `TREE` address must show padding in 20..24 whatever was
    /// there before.
    #[test]
    fn test_a_type_change_cannot_leave_another_type_s_values_behind() {
        let mut adrs = Adrs::new();
        adrs.set_wots(WotsAddress::Chain, 0xffff_ffff, 0xffff_ffff,
                      0xffff_ffff);

        adrs.set_tree(3, 9);
        assert_eq!(&adrs.as_bytes()[20..24], &[0, 0, 0, 0],
                   "bytes 20..24 are padding under TREE and must be zero, \
                    not the previous key pair address");
        assert_eq!(&adrs.as_bytes()[24..28], &[0, 0, 0, 3], "tree height");
        assert_eq!(&adrs.as_bytes()[28..32], &[0, 0, 0, 9], "tree index");

        adrs.set_wots_public_key(4);
        assert_eq!(&adrs.as_bytes()[20..24], &[0, 0, 0, 4]);
        assert_eq!(&adrs.as_bytes()[24..32], &[0u8; 8],
                   "WOTS_PK uses only the key pair address; the tree \
                    height and index must not survive into it");
    }

    /// The tree height and the chain address are one slot under two
    /// names, and so are the tree index and the hash address.
    ///
    /// Stated as a test because the two pairs of names appear in the
    /// spec's pseudocode as if they were different fields, and a reader
    /// who believes they are will look for four words where there are
    /// two.
    #[test]
    fn test_the_two_reused_words_really_are_the_same_bytes() {
        let mut chain_form = Adrs::new();
        chain_form.set_wots(WotsAddress::Chain, 0, 5, 6);

        let mut tree_form = Adrs::new();
        tree_form.set_tree(5, 6);

        assert_eq!(&chain_form.as_bytes()[24..32], &tree_form.as_bytes()[24..32],
                   "chain/hash and height/index are the same two words");
        assert_ne!(chain_form, tree_form,
                   "...and only the type and the key pair word differ");
    }

    /// The compressed form keeps exactly the bytes FIPS 205 says.
    #[test]
    fn test_the_compressed_address_is_the_documented_twenty_two_bytes() {
        let mut adrs = Adrs::new();
        adrs.set_layer_address(6);
        adrs.set_tree_address(0x1122_3344_5566_7788);
        adrs.set_wots(WotsAddress::Secret, 1, 2, 3);

        let compressed = adrs.compressed().unwrap();
        assert_eq!(compressed.len(), 22);
        assert_eq!(compressed[0], 6, "one byte of layer");
        assert_eq!(&compressed[1..9],
                   &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        assert_eq!(compressed[9], 5, "one byte of type, WOTS_PRF");
        assert_eq!(&compressed[10..22], &adrs.as_bytes()[20..32]);
    }

    /// Compressing refuses an address whose high bytes are in use.
    ///
    /// They never are, for the reasons in `compressed`'s own
    /// documentation - but "never" there is an invariant that this
    /// checks rather than a fact to be trusted, because the consequence
    /// of being wrong is two different addresses hashing as one.
    #[test]
    fn test_compressing_refuses_an_address_that_would_not_fit() {
        let mut adrs = Adrs::new();
        adrs.set_layer_address(0x0100);
        let error = adrs.compressed().unwrap_err();
        assert!(error.contains("layer address"), "{error}");

        let mut adrs = Adrs::new();
        // A tree index needing more than eight bytes cannot be set
        // through `set_tree_address`, which is the point of it taking a
        // `u64`; reaching the field another way is what this guards.
        adrs.bytes[4] = 1;
        assert!(adrs.compressed().unwrap_err().contains("tree address"));
    }

    /// A seed of the wrong length is refused rather than padded.
    #[test]
    fn test_the_seed_lengths_are_checked() {
        let set = parameters("SLH-DSA-SHA2-128s").unwrap();
        let short = [0u8; 15];
        let right = [0u8; 16];

        assert!(Hasher::new(set, &short).unwrap_err().contains("PK.seed"));

        let error = key_gen_internal(set, &short, &right, &right).unwrap_err();
        assert!(error.contains("SK.seed") && error.contains("15"), "{error}");
        let error = key_gen_internal(set, &right, &short, &right).unwrap_err();
        assert!(error.contains("SK.prf"), "{error}");
    }

    /// The two hash families differ at the same address and seed.
    ///
    /// Trivially true if the code is right, and the reason to state it is
    /// the failure it excludes: a `family` field that were ignored
    /// somewhere would give two parameter sets that produce identical
    /// keys, which the vectors would report as "the SHAKE sets are all
    /// wrong" without saying why.
    #[test]
    fn test_the_families_do_not_agree() {
        let seed = [0x5au8; 16];
        let adrs = Adrs::new();
        let sha2 = Hasher::new(parameters("SLH-DSA-SHA2-128s").unwrap(),
                               &seed).unwrap();
        let shake = Hasher::new(parameters("SLH-DSA-SHAKE-128s").unwrap(),
                                &seed).unwrap();
        assert_ne!(sha2.f(&adrs, &seed).unwrap(),
                   shake.f(&adrs, &seed).unwrap());
    }

    /// Above `n = 16` the SHA-2 family's `F` and `H` are different hash
    /// functions, and `T_l` follows `H`.
    ///
    /// The single most likely way to be self-consistently wrong in this
    /// file: one hash everywhere passes at 128 bits and fails at 192 and
    /// 256. Checked by construction rather than by a vector, so that the
    /// vectors' verdict has something to point at.
    #[test]
    fn test_f_and_h_part_company_above_the_smallest_parameter_set() {
        let adrs = Adrs::new();

        // At n = 16 everything is SHA-256, so F over a doubled block
        // agrees with H over its two halves.
        let seed = [0x11u8; 16];
        let hasher = Hasher::new(parameters("SLH-DSA-SHA2-128s").unwrap(),
                                 &seed).unwrap();
        let mut doubled = seed.to_vec();
        doubled.extend_from_slice(&seed);
        assert_eq!(hasher.f(&adrs, &doubled).unwrap(),
                   hasher.h(&adrs, &seed, &seed).unwrap(),
                   "at n = 16 F and H are the same construction");
        assert_eq!(hasher.t(&adrs, &doubled).unwrap(),
                   hasher.h(&adrs, &seed, &seed).unwrap());

        // At n = 24 and 32 they are not: H and T move to SHA-512 with a
        // different amount of padding, and F stays on SHA-256.
        for name in ["SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-256f"] {
            let set = parameters(name).unwrap();
            let seed = vec![0x11u8; set.n];
            let hasher = Hasher::new(set, &seed).unwrap();
            let mut doubled = seed.clone();
            doubled.extend_from_slice(&seed);
            assert_ne!(hasher.f(&adrs, &doubled).unwrap(),
                       hasher.h(&adrs, &seed, &seed).unwrap(),
                       "{name}: F is SHA-256 and H is SHA-512");
            assert_eq!(hasher.t(&adrs, &doubled).unwrap(),
                       hasher.h(&adrs, &seed, &seed).unwrap(),
                       "{name}: T_l follows H, not F");
        }

        // The SHAKE family uses one function throughout, at every n.
        for name in ["SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256f"] {
            let set = parameters(name).unwrap();
            let seed = vec![0x11u8; set.n];
            let hasher = Hasher::new(set, &seed).unwrap();
            let mut doubled = seed.clone();
            doubled.extend_from_slice(&seed);
            assert_eq!(hasher.f(&adrs, &doubled).unwrap(),
                       hasher.h(&adrs, &seed, &seed).unwrap(),
                       "{name}: SHAKE256 is the whole family");
        }
    }

    /// The digest splits exactly into `m` bytes, for all twelve sets.
    ///
    /// `m` is one of the three parameter fields key generation never
    /// reads, and it is not free: it must be exactly the FORS index plus
    /// the tree index plus the leaf index. A wrong `m` would show up
    /// otherwise only as a signature that does not match, at whichever
    /// parameter set was wrong.
    #[test]
    fn test_the_digest_splits_exactly_into_m_bytes() {
        for set in &PARAMETER_SETS {
            let (md, tree, leaf) = digest_split(set);
            assert_eq!(md + tree + leaf, set.m,
                       "{}: the digest split does not use all of m", set.name);
            assert!(tree <= 8,
                    "{}: a {} byte tree index does not fit a u64", set.name,
                    tree);
            assert!(leaf <= 4, "{}: leaf index", set.name);
        }
    }

    /// The leaf index is **two bytes at `h' = 9` and one everywhere
    /// else**, which is the only structural difference the slow parameter
    /// sets have in the signing path.
    ///
    /// Stated here rather than left to `tests/test_slh_dsa.rs`, whose
    /// small-set signing cases are behind `--ignored` because they cost
    /// minutes: this is the thing those cases would have caught, and it
    /// costs nothing to check directly.
    #[test]
    fn test_the_leaf_index_is_two_bytes_only_where_h_prime_is_nine() {
        let mut wide = Vec::new();
        for set in &PARAMETER_SETS {
            let (_, _, leaf) = digest_split(set);
            assert_eq!(leaf, set.h_prime.div_ceil(8), "{}", set.name);
            if leaf > 1 {
                wide.push(set.name);
            }
        }
        assert_eq!(wide, ["SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",
                          "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s"],
                   "exactly the h' = 9 sets have a two byte leaf index");
    }

    /// `index_from` is big-endian and masks to the right width.
    ///
    /// The width reaches 64 at `SLH-DSA-SHAKE-256f`, where `1u64 << 64`
    /// would be undefined - so the all-bits case is checked explicitly
    /// rather than trusted to a shift.
    #[test]
    fn test_the_index_arithmetic_masks_without_overflowing() {
        assert_eq!(index_from(&[0x01, 0x02], 16).unwrap(), 0x0102,
                   "big endian");
        // Nine bits, which is what h' = 9 needs out of two bytes.
        assert_eq!(index_from(&[0x01, 0xff], 9).unwrap(), 0x1ff);
        assert_eq!(index_from(&[0xff, 0xff], 9).unwrap(), 0x1ff,
                   "the high bits are dropped, not saturated");
        assert_eq!(index_from(&[0x00], 3).unwrap(), 0);
        assert_eq!(index_from(&[0x0f], 3).unwrap(), 7);

        // 64 bits: the whole word, and nothing to mask.
        let all = [0xffu8; 8];
        assert_eq!(index_from(&all, 64).unwrap(), u64::MAX);
        assert_eq!(index_from(&all, 63).unwrap(), u64::MAX >> 1);

        assert!(index_from(&[0u8; 9], 64).unwrap_err().contains("u64"));

        // And every parameter set's own fields are within range, which is
        // what makes the u64 sound rather than merely convenient.
        for set in &PARAMETER_SETS {
            let (_, tree, leaf) = digest_split(set);
            assert!(index_from(&vec![0xff; tree], set.h - set.h_prime).is_ok(),
                    "{}", set.name);
            assert!(index_from(&vec![0xff; leaf], set.h_prime).is_ok(),
                    "{}", set.name);
        }
    }

    /// `base_2b` reads digits from the top of each byte.
    ///
    /// The bit order is the thing that would be self-consistently wrong:
    /// a little-endian reading gives a perfectly good set of digits and a
    /// signature over a different message. Checked against a hand-worked
    /// example whose two readings differ, and against the boundary case
    /// where a digit straddles two bytes.
    #[test]
    fn test_base_2b_reads_the_high_bits_first() {
        // 0xAB = 1010 1011, so four-bit digits are 0xA then 0xB.
        assert_eq!(base_2b(&[0xAB], 4, 2).unwrap(), vec![0xA, 0xB]);
        assert_ne!(base_2b(&[0xAB], 4, 2).unwrap(), vec![0xB, 0xA],
                   "a low-bits-first reading would give this instead");

        // Twelve bits from two bytes: 0x123 out of 0x12 0x3x.
        assert_eq!(base_2b(&[0x12, 0x34], 12, 1).unwrap(), vec![0x123]);
        // And a digit that straddles the byte boundary: six bit digits of
        // 0b100100_01 0b0011_0100 are 0b100100, 0b010011, 0b0100xx.
        assert_eq!(base_2b(&[0x91, 0x34], 6, 2).unwrap(), vec![0b100100,
                                                               0b010011]);

        // Too few bytes is refused rather than read short, because a
        // short read would silently produce digits from nothing.
        let error = base_2b(&[0x12], 12, 2).unwrap_err();
        assert!(error.contains("need 3 bytes"), "{error}");
    }

    /// The WOTS+ checksum digits, against a worked example.
    ///
    /// The shift is what makes this worth stating: `len2 * lg_w` is twelve
    /// bits written into two bytes, so the checksum is shifted up by four
    /// before being cut into digits. Without the shift the digits come out
    /// as `0, high, low` instead of `high, mid, low`, which is a valid
    /// checksum that no verifier agrees with.
    #[test]
    fn test_the_wots_checksum_is_shifted_before_it_is_split() {
        let set = parameters("SLH-DSA-SHA2-128s").unwrap();
        // An all-zero message: every digit is 0, so the checksum is
        // len1 * (w - 1) = 32 * 15 = 480 = 0x1E0.
        let digits = wots_digits(set, &[0u8; 16]).unwrap();
        assert_eq!(digits.len(), set.len());
        assert!(digits[..set.len1()].iter().all(|d| *d == 0));

        // 0x1E0 << 4 = 0x1E00, so the three digits are 1, E, 0.
        assert_eq!(&digits[set.len1()..], &[0x1, 0xE, 0x0],
                   "the checksum is shifted left by four before splitting");

        // An all-ones message: every digit is 15, so the checksum is 0.
        let digits = wots_digits(set, &[0xffu8; 16]).unwrap();
        assert!(digits[..set.len1()].iter().all(|d| *d == 15));
        assert_eq!(&digits[set.len1()..], &[0, 0, 0]);

        // The checksum is what stops a digit being raised: lowering any
        // message digit must raise the checksum.
        let mut message = [0x77u8; 16];
        let before = wots_digits(set, &message).unwrap();
        message[0] = 0x67;
        let after = wots_digits(set, &message).unwrap();
        assert!(after[set.len1()..] > before[set.len1()..],
                "lowering a digit must raise the checksum, or WOTS+ is \
                 forgeable by raising digits");
    }

    /// A chain of `s` steps from position `i` is a chain of one step
    /// repeated, and it depends on where it starts.
    ///
    /// The off-by-one in `chain` - using hash addresses `i..i+s` rather
    /// than `i+1..=i+s` - is invisible in a self-check, so what is
    /// checked here is the property that makes WOTS+ work at all:
    /// walking `a` then `b` steps must equal walking `a + b`, which is
    /// what lets a verifier finish a chain the signer stopped partway
    /// along.
    #[test]
    fn test_walking_a_chain_in_two_parts_matches_walking_it_at_once() {
        let seed = [0x22u8; 16];
        let hasher = Hasher::new(parameters("SLH-DSA-SHAKE-128f").unwrap(),
                                 &seed).unwrap();
        let mut adrs = Adrs::new();
        adrs.set_wots(WotsAddress::Chain, 3, 4, 0);

        let whole = chain(&hasher, &mut adrs, 0, W - 1, &seed).unwrap();
        let part = chain(&hasher, &mut adrs, 0, 6, &seed).unwrap();
        let rest = chain(&hasher, &mut adrs, 6, W - 1 - 6, &part).unwrap();
        assert_eq!(whole, rest, "a chain must be splittable at any point");

        // Zero steps is the identity, which is the case a verifier hits
        // for a digit of 15.
        assert_eq!(chain(&hasher, &mut adrs, 0, 0, &seed).unwrap(),
                   seed.to_vec());
    }
}
