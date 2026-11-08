/*!
LMS and HSS: the Leighton-Micali hash-based signatures (RFC 8554), with
the SHA-256/192, SHAKE256/256 and SHAKE256/192 parameter sets of RFC 9858
and NIST SP 800-208.

**Stateful.** An LMS key is a Merkle tree of `2^h` one-time keys, and
each signature spends the next one: signing the same leaf twice gives
away enough of that one-time key to forge. The private key is therefore
a counter as much as a secret, and a copy of it - a backup restored, a
virtual machine snapshot, two processes holding one file - signs twice
with the same leaves without anything noticing. [`LmsPrivateKey::sign`]
and [`HssPrivateKey::sign`] advance the counter before returning; the
caller has to store the advanced key before the signature leaves.

## The one-time signature, LM-OTS

A private key is `p` strings of `n` bytes; each is the start of a chain
of `2^w - 1` hashes, and the public key is the hash of all the chain
ends. A signature reveals each chain at the position given by `w` bits
of the message's hash or of its checksum, which is what stops a
signature for one message being walked forward into another. Every hash
is prefixed with `I` (the tree's 16 byte identifier), `q` (the leaf), the
chain and the step, so no two hashes anywhere in any key share an input.

## The tree, LMS, and the hierarchy, HSS

Leaf `r` of the tree is the hash of one-time public key `r - 2^h`, and
the root `T[1]` is the LMS public key. HSS stacks `L` trees: each signs
the public key of the one below, and the lowest signs messages. Every
HSS signature carries the whole chain, so it is `L` LMS signatures and
`L - 1` public keys long.

## Keys from seeds

RFC 8554 leaves private keys to the implementation and suggests, in its
Appendix A, deriving each one-time key from a seed:
`x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`. Keys
here are made that way, so a key is `(SEED, I)` and a leaf number. The
signature's randomiser `C` is derived alike with `i = 0xfffd`, as the
RFC authors' implementation (Cisco's hash-sigs) does and RFC 9858's
worked examples show. Below the top of a hierarchy, each tree's SEED and
I are derived from its parent's at the leaf that signs it, with
`i = 0xfffe` and `0xffff` - hash-sigs' rule again, which no standard
fixes: a hierarchy made here signs exactly as hash-sigs' does from the
same top SEED and I, and any implementation verifies it.

The LMS and LM-OTS parameter sets of one tree must share a hash
function and length; SP 800-208 requires it, and neither RFC defines
what a mixed pair would mean.
*/

use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::sha2::SHA256;
use crate::hash_functions::HashFunction;

/// The four hash functions: SHA-256 and SHAKE256, at 32 or 24 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LmsHash {
    /// SHA-256, its first `n` bytes.
    Sha256,
    /// SHAKE256 with `n` bytes of output.
    Shake256,
}

/// An LM-OTS parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmotsParams {
    /// The name the RFCs give it: `LMOTS_SHA256_N32_W8`.
    pub name: &'static str,
    /// The type code in keys and signatures.
    pub id: u32,
    /// The hash function.
    pub hash: LmsHash,
    /// Bytes of hash output.
    pub n: usize,
    /// Bits of the message's hash per chain: 1, 2, 4 or 8.
    pub w: usize,
    /// Chains, and so `n`-byte strings in a signature.
    pub p: usize,
    /// The checksum's left shift.
    pub ls: u32,
}

/// An LMS parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LmsParams {
    /// The name the RFCs give it: `LMS_SHA256_M32_H10`.
    pub name: &'static str,
    /// The type code in keys and signatures.
    pub id: u32,
    /// The hash function.
    pub hash: LmsHash,
    /// Bytes of hash output.
    pub m: usize,
    /// The tree's height: `2^h` signatures.
    pub h: u32,
}

/// `p` and `ls` from `n` and `w`, RFC 8554 Appendix B.
const fn p_and_ls(n: usize, w: usize) -> (usize, u32) {
    let u = (8 * n).div_ceil(w);
    let checksum_max = ((1usize << w) - 1) * u;
    let bits = usize::BITS - checksum_max.leading_zeros();
    let v = (bits as usize).div_ceil(w);
    (u + v, 16 - (v * w) as u32)
}

const fn lmots(name: &'static str, id: u32, hash: LmsHash, n: usize, w: usize) -> LmotsParams {
    let (p, ls) = p_and_ls(n, w);
    LmotsParams { name, id, hash, n, w, p, ls }
}

const fn lms(name: &'static str, id: u32, hash: LmsHash, m: usize, h: u32) -> LmsParams {
    LmsParams { name, id, hash, m, h }
}

use LmsHash::{Sha256 as S, Shake256 as K};

/// The LM-OTS parameter sets: RFC 8554 Table 1 and RFC 9858 Table 1.
pub const LMOTS_PARAMETER_SETS: [LmotsParams; 16] = [
    lmots("LMOTS_SHA256_N32_W1", 1, S, 32, 1), lmots("LMOTS_SHA256_N32_W2", 2, S, 32, 2),
    lmots("LMOTS_SHA256_N32_W4", 3, S, 32, 4), lmots("LMOTS_SHA256_N32_W8", 4, S, 32, 8),
    lmots("LMOTS_SHA256_N24_W1", 5, S, 24, 1), lmots("LMOTS_SHA256_N24_W2", 6, S, 24, 2),
    lmots("LMOTS_SHA256_N24_W4", 7, S, 24, 4), lmots("LMOTS_SHA256_N24_W8", 8, S, 24, 8),
    lmots("LMOTS_SHAKE_N32_W1", 9, K, 32, 1), lmots("LMOTS_SHAKE_N32_W2", 10, K, 32, 2),
    lmots("LMOTS_SHAKE_N32_W4", 11, K, 32, 4), lmots("LMOTS_SHAKE_N32_W8", 12, K, 32, 8),
    lmots("LMOTS_SHAKE_N24_W1", 13, K, 24, 1), lmots("LMOTS_SHAKE_N24_W2", 14, K, 24, 2),
    lmots("LMOTS_SHAKE_N24_W4", 15, K, 24, 4), lmots("LMOTS_SHAKE_N24_W8", 16, K, 24, 8),
];

/// The LMS parameter sets: RFC 8554 Table 2 and RFC 9858 Table 2.
pub const LMS_PARAMETER_SETS: [LmsParams; 20] = [
    lms("LMS_SHA256_M32_H5", 5, S, 32, 5), lms("LMS_SHA256_M32_H10", 6, S, 32, 10),
    lms("LMS_SHA256_M32_H15", 7, S, 32, 15), lms("LMS_SHA256_M32_H20", 8, S, 32, 20),
    lms("LMS_SHA256_M32_H25", 9, S, 32, 25),
    lms("LMS_SHA256_M24_H5", 10, S, 24, 5), lms("LMS_SHA256_M24_H10", 11, S, 24, 10),
    lms("LMS_SHA256_M24_H15", 12, S, 24, 15), lms("LMS_SHA256_M24_H20", 13, S, 24, 20),
    lms("LMS_SHA256_M24_H25", 14, S, 24, 25),
    lms("LMS_SHAKE_M32_H5", 15, K, 32, 5), lms("LMS_SHAKE_M32_H10", 16, K, 32, 10),
    lms("LMS_SHAKE_M32_H15", 17, K, 32, 15), lms("LMS_SHAKE_M32_H20", 18, K, 32, 20),
    lms("LMS_SHAKE_M32_H25", 19, K, 32, 25),
    lms("LMS_SHAKE_M24_H5", 20, K, 24, 5), lms("LMS_SHAKE_M24_H10", 21, K, 24, 10),
    lms("LMS_SHAKE_M24_H15", 22, K, 24, 15), lms("LMS_SHAKE_M24_H20", 23, K, 24, 20),
    lms("LMS_SHAKE_M24_H25", 24, K, 24, 25),
];

const D_PBLC: u16 = 0x8080;
const D_MESG: u16 = 0x8181;
const D_LEAF: u16 = 0x8282;
const D_INTR: u16 = 0x8383;
/// Appendix A's `i` for the randomiser and a child tree's SEED and I.
const J_RANDOMISER: u16 = 0xfffd;
const J_CHILD_SEED: u16 = 0xfffe;
const J_CHILD_I: u16 = 0xffff;

impl LmotsParams {
    /// A parameter set by its name, in any case, or its type code in
    /// decimal or as `0x...`.
    pub fn named(name: &str) -> Result<&'static LmotsParams, String> {
        find(&LMOTS_PARAMETER_SETS, name, |p| (p.name, p.id))
            .ok_or_else(|| format!("No LM-OTS parameter set {name:?}. Known: {}.",
                                   LMOTS_PARAMETER_SETS.map(|p| p.name).join(", ")))
    }

    /// By type code.
    pub fn by_id(id: u32) -> Option<&'static LmotsParams> {
        LMOTS_PARAMETER_SETS.iter().find(|p| p.id == id)
    }

    /// A signature's length: the type, `C` and `p` strings.
    pub fn signature_len(&self) -> usize {
        4 + self.n * (self.p + 1)
    }
}

impl LmsParams {
    /// A parameter set by its name, in any case, or its type code in
    /// decimal or as `0x...`.
    pub fn named(name: &str) -> Result<&'static LmsParams, String> {
        find(&LMS_PARAMETER_SETS, name, |p| (p.name, p.id))
            .ok_or_else(|| format!("No LMS parameter set {name:?}. Known: {}.",
                                   LMS_PARAMETER_SETS.map(|p| p.name).join(", ")))
    }

    /// By type code.
    pub fn by_id(id: u32) -> Option<&'static LmsParams> {
        LMS_PARAMETER_SETS.iter().find(|p| p.id == id)
    }

    /// A public key's length: two types, `I` and the root.
    pub fn public_key_len(&self) -> usize {
        24 + self.m
    }

    /// A signature's length with `ots`: the leaf, the one-time signature,
    /// the type and the path.
    pub fn signature_len(&self, ots: &LmotsParams) -> usize {
        8 + ots.signature_len() + self.h as usize * self.m
    }
}

fn find<T>(table: &'static [T], name: &str, key: impl Fn(&T) -> (&'static str, u32))
           -> Option<&'static T> {
    let id = match name.strip_prefix("0x").or_else(|| name.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => name.parse().ok(),
    };
    table.iter().find(|t| {
        let (n, i) = key(t);
        n.eq_ignore_ascii_case(name) || Some(i) == id
    })
}

/// Refuses an LMS and LM-OTS pair that do not share a hash and length.
fn check_pair(lms: &LmsParams, ots: &LmotsParams) -> Result<(), String> {
    if lms.hash != ots.hash || lms.m != ots.n {
        return Err(format!("{} and {} use different hash functions; one tree takes one.",
                           lms.name, ots.name));
    }
    Ok(())
}

/// `H(parts...)`, the first `n` bytes.
fn hash(kind: LmsHash, n: usize, parts: &[&[u8]]) -> Vec<u8> {
    match kind {
        LmsHash::Sha256 => {
            let mut h = SHA256::new(&[]);
            for part in parts {
                h.update(part);
            }
            let mut out = h.digest();
            out.truncate(n);
            out
        }
        LmsHash::Shake256 => {
            let mut h = Keccak::shake(256, n).expect("256 is a SHAKE security level");
            for part in parts {
                h.update(part);
            }
            h.squeeze(n)
        }
    }
}

/// Appendix A: `H(I || u32str(q) || u16str(j) || u8str(0xff) || SEED)`.
fn derive(kind: LmsHash, n: usize, i: &[u8; 16], q: u32, j: u16, seed: &[u8]) -> Vec<u8> {
    hash(kind, n, &[i, &q.to_be_bytes(), &j.to_be_bytes(), &[0xff], seed])
}

/// `coef(S, i, w)`: the `i`th `w`-bit digit of `S`, most significant first.
fn coef(s: &[u8], i: usize, w: usize) -> usize {
    let digits_per_byte = 8 / w;
    let byte = s[i / digits_per_byte] as usize;
    let shift = 8 - w * (i % digits_per_byte + 1);
    (byte >> shift) & ((1 << w) - 1)
}

/// `Q || Cksm(Q)`.
fn with_checksum(ots: &LmotsParams, q_hash: &[u8]) -> Vec<u8> {
    let max = (1usize << ots.w) - 1;
    let sum: usize = (0..8 * ots.n / ots.w).map(|i| max - coef(q_hash, i, ots.w)).sum();
    let mut out = q_hash.to_vec();
    out.extend_from_slice(&((sum as u16) << ots.ls).to_be_bytes());
    out
}

/// Chain `i` from step `from` to step `to`.
fn chain(ots: &LmotsParams, id: &[u8; 16], q: u32, i: usize, start: &[u8], from: usize,
         to: usize) -> Vec<u8> {
    let mut tmp = start.to_vec();
    for j in from..to {
        tmp = hash(ots.hash, ots.n, &[id, &q.to_be_bytes(), &(i as u16).to_be_bytes(),
                                      &[j as u8], &tmp]);
    }
    tmp
}

/// The hash of the chain ends: the one-time public key `K`.
fn ots_key_hash(ots: &LmotsParams, id: &[u8; 16], q: u32, ends: &[Vec<u8>]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(ends.len() + 3);
    let q_bytes = q.to_be_bytes();
    let d = D_PBLC.to_be_bytes();
    parts.push(id);
    parts.push(&q_bytes);
    parts.push(&d);
    parts.extend(ends.iter().map(|e| e.as_slice()));
    hash(ots.hash, ots.n, &parts)
}

/// One-time public key `q` of the tree `(SEED, I)`.
fn ots_public(ots: &LmotsParams, id: &[u8; 16], seed: &[u8], q: u32) -> Vec<u8> {
    let top = (1 << ots.w) - 1;
    let ends: Vec<Vec<u8>> = (0..ots.p).map(|i| {
        let x = derive(ots.hash, ots.n, id, q, i as u16, seed);
        chain(ots, id, q, i, &x, 0, top)
    }).collect();
    ots_key_hash(ots, id, q, &ends)
}

/// One-time signature `q` of the tree `(SEED, I)` over `message`.
fn ots_sign(ots: &LmotsParams, id: &[u8; 16], seed: &[u8], q: u32, message: &[u8]) -> Vec<u8> {
    let c = derive(ots.hash, ots.n, id, q, J_RANDOMISER, seed);
    let q_hash = hash(ots.hash, ots.n,
                      &[id, &q.to_be_bytes(), &D_MESG.to_be_bytes(), &c, message]);
    let digits = with_checksum(ots, &q_hash);
    let mut out = Vec::with_capacity(ots.signature_len());
    out.extend_from_slice(&ots.id.to_be_bytes());
    out.extend_from_slice(&c);
    for i in 0..ots.p {
        let x = derive(ots.hash, ots.n, id, q, i as u16, seed);
        out.extend_from_slice(&chain(ots, id, q, i, &x, 0, coef(&digits, i, ots.w)));
    }
    out
}

/// The public key a one-time signature implies, RFC 8554 Algorithm 4b;
/// `None` if it is not one under `ots`.
fn ots_candidate(ots: &LmotsParams, id: &[u8; 16], q: u32, message: &[u8], sig: &[u8])
                 -> Option<Vec<u8>> {
    if sig.len() != ots.signature_len() || sig[..4] != ots.id.to_be_bytes() {
        return None;
    }
    let c = &sig[4..4 + ots.n];
    let q_hash = hash(ots.hash, ots.n,
                      &[id, &q.to_be_bytes(), &D_MESG.to_be_bytes(), c, message]);
    let digits = with_checksum(ots, &q_hash);
    let top = (1 << ots.w) - 1;
    let ends: Vec<Vec<u8>> = (0..ots.p).map(|i| {
        let y = &sig[4 + ots.n * (i + 1)..4 + ots.n * (i + 2)];
        chain(ots, id, q, i, y, coef(&digits, i, ots.w), top)
    }).collect();
    Some(ots_key_hash(ots, id, q, &ends))
}

/// An LM-OTS public key on its own, RFC 8554 section 4.3:
/// `u32str(type) || I || u32str(q) || K`, one-time key `q` of the tree
/// `(seed, id)`.
pub fn lmots_public_key(ots: &'static LmotsParams, seed: &[u8], id: &[u8; 16], q: u32)
                        -> Result<Vec<u8>, String> {
    if seed.len() != ots.n {
        return Err(format!("{}'s SEED is {} bytes, not {}.", ots.name, ots.n, seed.len()));
    }
    let mut out = ots.id.to_be_bytes().to_vec();
    out.extend_from_slice(id);
    out.extend_from_slice(&q.to_be_bytes());
    out.extend_from_slice(&ots_public(ots, id, seed, q));
    Ok(out)
}

/// An LM-OTS signature with one-time key `q` of the tree `(seed, id)`:
/// `u32str(type) || C || y[0] .. y[p-1]`. That key must sign nothing
/// else; this keeps no state to see that it does not.
pub fn lmots_sign(ots: &'static LmotsParams, seed: &[u8], id: &[u8; 16], q: u32,
                  message: &[u8]) -> Result<Vec<u8>, String> {
    if seed.len() != ots.n {
        return Err(format!("{}'s SEED is {} bytes, not {}.", ots.name, ots.n, seed.len()));
    }
    Ok(ots_sign(ots, id, seed, q, message))
}

/// Whether `signature` is an LM-OTS signature of `message` under the
/// LM-OTS public key `public_key`. Anything malformed is `false`.
pub fn lmots_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Some(ots) = public_key.get(..4).and_then(|t| LmotsParams::by_id(
        u32::from_be_bytes(t.try_into().expect("four bytes")))) else { return false };
    if public_key.len() != 24 + ots.n {
        return false;
    }
    let id: [u8; 16] = public_key[4..20].try_into().expect("16 bytes");
    let q = u32::from_be_bytes(public_key[20..24].try_into().expect("four bytes"));
    ots_candidate(ots, &id, q, message, signature).is_some_and(|k| k == public_key[24..])
}

/// Trees this high or lower keep every node; higher ones recompute.
const CACHED_HEIGHT: u32 = 15;

/// An LMS private key: a tree from `(SEED, I)` and the next leaf.
#[derive(Clone)]
pub struct LmsPrivateKey {
    lms: &'static LmsParams,
    ots: &'static LmotsParams,
    id: [u8; 16],
    seed: Vec<u8>,
    q: u32,
    /// Node `r` at `[r * m..]`, for a tree no higher than `CACHED_HEIGHT`.
    nodes: Option<Vec<u8>>,
}

impl LmsPrivateKey {
    /// The tree of `(seed, id)` from leaf `q`: `seed` is `m` bytes.
    pub fn from_seed(lms: &'static LmsParams, ots: &'static LmotsParams, seed: &[u8],
                     id: &[u8; 16], q: u32) -> Result<LmsPrivateKey, String> {
        check_pair(lms, ots)?;
        if seed.len() != lms.m {
            return Err(format!("{}'s SEED is {} bytes, not {}.", lms.name, lms.m, seed.len()));
        }
        if u64::from(q) > 1u64 << lms.h {
            return Err(format!("{} has {} leaves; {q} is past them.", lms.name, 1u64 << lms.h));
        }
        Ok(LmsPrivateKey { lms, ots, id: *id, seed: seed.to_vec(), q, nodes: None })
    }

    /// The parameter sets.
    pub fn params(&self) -> (&'static LmsParams, &'static LmotsParams) {
        (self.lms, self.ots)
    }

    /// The next leaf to sign with.
    pub fn next_leaf(&self) -> u32 {
        self.q
    }

    /// Signatures left.
    pub fn remaining(&self) -> u64 {
        (1u64 << self.lms.h) - u64::from(self.q)
    }

    fn leaf(&self, r: u32) -> Vec<u8> {
        let k = ots_public(self.ots, &self.id, &self.seed, r - (1 << self.lms.h));
        hash(self.lms.hash, self.lms.m, &[&self.id, &r.to_be_bytes(), &D_LEAF.to_be_bytes(), &k])
    }

    fn interior(&self, r: u32, left: &[u8], right: &[u8]) -> Vec<u8> {
        hash(self.lms.hash, self.lms.m,
             &[&self.id, &r.to_be_bytes(), &D_INTR.to_be_bytes(), left, right])
    }

    /// Node `r` computed from its leaves.
    fn subtree(&self, r: u32) -> Vec<u8> {
        if r >= 1 << self.lms.h {
            return self.leaf(r);
        }
        let (left, right) = (self.subtree(2 * r), self.subtree(2 * r + 1));
        self.interior(r, &left, &right)
    }

    fn node(&mut self, r: u32) -> Vec<u8> {
        let m = self.lms.m;
        if self.lms.h > CACHED_HEIGHT {
            return self.subtree(r);
        }
        if self.nodes.is_none() {
            let count = 2usize << self.lms.h;
            let mut nodes = vec![0u8; count * m];
            for r in (1..count).rev() {
                let value = if r >= count / 2 {
                    self.leaf(r as u32)
                } else {
                    let (l, rest) = nodes[2 * r * m..].split_at(m);
                    self.interior(r as u32, l, &rest[..m])
                };
                nodes[r * m..(r + 1) * m].copy_from_slice(&value);
            }
            self.nodes = Some(nodes);
        }
        let nodes = self.nodes.as_ref().expect("filled above");
        nodes[r as usize * m..(r as usize + 1) * m].to_vec()
    }

    /// The public key: `u32str(type) || u32str(otstype) || I || T[1]`.
    pub fn public_key(&mut self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.lms.public_key_len());
        out.extend_from_slice(&self.lms.id.to_be_bytes());
        out.extend_from_slice(&self.ots.id.to_be_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.node(1));
        out
    }

    /// Signs with the next leaf and moves past it; an error once every
    /// leaf is spent.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        if self.remaining() == 0 {
            return Err(format!("This {} key has signed with all {} of its leaves.",
                               self.lms.name, 1u64 << self.lms.h));
        }
        let q = self.q;
        self.q += 1;
        let mut out = Vec::with_capacity(self.lms.signature_len(self.ots));
        out.extend_from_slice(&q.to_be_bytes());
        out.extend_from_slice(&ots_sign(self.ots, &self.id, &self.seed, q, message));
        out.extend_from_slice(&self.lms.id.to_be_bytes());
        let mut r = (1u32 << self.lms.h) + q;
        while r > 1 {
            let sibling = self.node(r ^ 1);
            out.extend_from_slice(&sibling);
            r /= 2;
        }
        Ok(out)
    }

    /// The tree a child of this one has, at the leaf that will sign it.
    fn child(&self, lms: &'static LmsParams, ots: &'static LmotsParams)
             -> Result<LmsPrivateKey, String> {
        let mut seed = derive(self.lms.hash, self.lms.m, &self.id, self.q, J_CHILD_SEED,
                              &self.seed);
        seed.resize(lms.m, 0);
        let i = derive(self.lms.hash, self.lms.m, &self.id, self.q, J_CHILD_I, &self.seed);
        LmsPrivateKey::from_seed(lms, ots, &seed, &i[..16].try_into().expect("16 bytes"), 0)
    }
}

/// The length of the LMS public key at the start of `bytes`, from its
/// type; `None` for an unknown type or too few bytes.
fn public_key_len_at(bytes: &[u8]) -> Option<usize> {
    let lms = LmsParams::by_id(u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?))?;
    Some(lms.public_key_len()).filter(|&n| bytes.len() >= n)
}

/// The length of the LMS signature at the start of `bytes`, from its two
/// types; `None` for an unknown type or too few bytes.
fn signature_len_at(bytes: &[u8]) -> Option<usize> {
    let ots = LmotsParams::by_id(u32::from_be_bytes(bytes.get(4..8)?.try_into().ok()?))?;
    let at = 4 + ots.signature_len();
    let lms = LmsParams::by_id(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))?;
    Some(lms.signature_len(ots)).filter(|&n| bytes.len() >= n)
}

/// Whether `signature` is an LMS signature of `message` under
/// `public_key`, RFC 8554 Algorithm 6a. Anything malformed is `false`.
pub fn lms_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    lms_verify_inner(public_key, message, signature).unwrap_or(false)
}

fn lms_verify_inner(public_key: &[u8], message: &[u8], signature: &[u8]) -> Option<bool> {
    let lms = LmsParams::by_id(u32::from_be_bytes(public_key.get(..4)?.try_into().ok()?))?;
    let ots = LmotsParams::by_id(u32::from_be_bytes(public_key.get(4..8)?.try_into().ok()?))?;
    if public_key.len() != lms.public_key_len() || check_pair(lms, ots).is_err()
        || signature.len() != lms.signature_len(ots) {
        return Some(false);
    }
    let id: [u8; 16] = public_key[8..24].try_into().ok()?;
    let q = u32::from_be_bytes(signature[..4].try_into().ok()?);
    let ots_sig = &signature[4..4 + ots.signature_len()];
    let rest = &signature[4 + ots.signature_len()..];
    if rest[..4] != lms.id.to_be_bytes() || u64::from(q) >= 1u64 << lms.h {
        return Some(false);
    }
    let k = ots_candidate(ots, &id, q, message, ots_sig)?;
    let mut r = (1u32 << lms.h) + q;
    let mut tmp = hash(lms.hash, lms.m, &[&id, &r.to_be_bytes(), &D_LEAF.to_be_bytes(), &k]);
    for sibling in rest[4..].chunks(lms.m) {
        let parent = (r / 2).to_be_bytes();
        let d = D_INTR.to_be_bytes();
        tmp = if r % 2 == 1 {
            hash(lms.hash, lms.m, &[&id, &parent, &d, sibling, &tmp])
        } else {
            hash(lms.hash, lms.m, &[&id, &parent, &d, &tmp, sibling])
        };
        r /= 2;
    }
    Some(tmp == public_key[24..])
}

/// An HSS private key: `L` trees from one SEED and I, and how many
/// signatures it has made.
#[derive(Clone)]
pub struct HssPrivateKey {
    levels: Vec<LmsPrivateKey>,
    /// `signed[i]` is level `i`'s signature of level `i + 1`'s public key.
    signed: Vec<Vec<u8>>,
    public: Vec<Vec<u8>>,
    seed: Vec<u8>,
    id: [u8; 16],
    count: u64,
}

/// The most levels HSS has.
pub const HSS_MAX_LEVELS: usize = 8;

impl HssPrivateKey {
    /// The hierarchy of `levels` - (LMS, LM-OTS) pairs from the top -
    /// whose top tree is `(seed, id)`, after `count` signatures.
    pub fn from_seed(levels: &[(&'static LmsParams, &'static LmotsParams)], seed: &[u8],
                     id: &[u8; 16], count: u64) -> Result<HssPrivateKey, String> {
        if levels.is_empty() || levels.len() > HSS_MAX_LEVELS {
            return Err(format!("HSS has 1 to {HSS_MAX_LEVELS} levels, not {}.", levels.len()));
        }
        let total: u32 = levels.iter().map(|(l, _)| l.h).sum();
        if total < 64 && count > 1u64 << total {
            return Err(format!("This hierarchy makes {} signatures; {count} is past them.",
                               1u64 << total));
        }
        // The leaf of each level: `count` in the mixed radix of the heights,
        // the top level most significant. A spent hierarchy is the last
        // leaf of every level, made unusable below.
        let mut digits = vec![0u32; levels.len()];
        let mut rest = count;
        let spent = total < 64 && count == 1u64 << total;
        for (d, (l, _)) in digits.iter_mut().zip(levels).rev() {
            *d = (rest & ((1u64 << l.h) - 1)) as u32;
            rest >>= l.h;
        }
        if spent {
            for (d, (l, _)) in digits.iter_mut().zip(levels) {
                *d = (1u32 << l.h) - 1;
            }
        }
        let mut key = HssPrivateKey { levels: Vec::new(), signed: Vec::new(), public: Vec::new(),
                                      seed: seed.to_vec(), id: *id, count };
        let (lms, ots) = levels[0];
        key.levels.push(LmsPrivateKey::from_seed(lms, ots, seed, id, digits[0])?);
        key.public.push(key.levels[0].public_key());
        for (i, &(lms, ots)) in levels.iter().enumerate().skip(1) {
            let mut child = key.levels[i - 1].child(lms, ots)?;
            let child_public = child.public_key();
            key.signed.push(key.levels[i - 1].sign(&child_public)?);
            child.q = digits[i];
            key.levels.push(child);
            key.public.push(child_public);
        }
        if spent {
            key.levels.last_mut().expect("one level at least").q += 1;
        }
        Ok(key)
    }

    /// The (LMS, LM-OTS) pairs, from the top.
    pub fn params(&self) -> Vec<(&'static LmsParams, &'static LmotsParams)> {
        self.levels.iter().map(|l| l.params()).collect()
    }

    /// Signatures made so far.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Signatures left, saturating at `u64::MAX`.
    pub fn remaining(&self) -> u64 {
        let total: u32 = self.levels.iter().map(|l| l.lms.h).sum();
        if total >= 64 { u64::MAX - self.count } else { (1u64 << total) - self.count }
    }

    /// The public key: `u32str(L) || ` the top tree's.
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = (self.levels.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&self.public[0]);
        out
    }

    /// Signs with the next leaf of the lowest tree and moves past it,
    /// replacing spent trees below the top; an error once the hierarchy
    /// is spent.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        if self.remaining() == 0 {
            return Err("This HSS key has made every signature it can.".to_string());
        }
        // The lowest level that has a leaf left; everything below it is
        // replaced.
        let last = self.levels.len() - 1;
        let mut level = last;
        while self.levels[level].remaining() == 0 {
            level -= 1;
        }
        for i in level..last {
            let (lms, ots) = self.levels[i + 1].params();
            let mut child = self.levels[i].child(lms, ots)?;
            let child_public = child.public_key();
            self.signed[i] = self.levels[i].sign(&child_public)?;
            self.public[i + 1] = child_public;
            self.levels[i + 1] = child;
        }
        let bottom = self.levels[last].sign(message)?;
        self.count += 1;
        let mut out = (last as u32).to_be_bytes().to_vec();
        for i in 0..last {
            out.extend_from_slice(&self.signed[i]);
            out.extend_from_slice(&self.public[i + 1]);
        }
        out.extend_from_slice(&bottom);
        Ok(out)
    }

    /// The key as bytes: `u32str(L)`, each level's two types, the count
    /// of signatures made as eight bytes, then the top SEED and I - all
    /// big endian. This is this library's own form; RFC 8554 defines
    /// none.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = (self.levels.len() as u32).to_be_bytes().to_vec();
        for l in &self.levels {
            out.extend_from_slice(&l.lms.id.to_be_bytes());
            out.extend_from_slice(&l.ots.id.to_be_bytes());
        }
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.id);
        out
    }

    /// Reads [`to_bytes`](HssPrivateKey::to_bytes) back.
    pub fn from_bytes(bytes: &[u8]) -> Result<HssPrivateKey, String> {
        let bad = || "Not an HSS private key in this library's form.".to_string();
        let levels = u32::from_be_bytes(bytes.get(..4).ok_or_else(bad)?.try_into()
                                        .map_err(|_| bad())?) as usize;
        if levels == 0 || levels > HSS_MAX_LEVELS {
            return Err(bad());
        }
        let mut params = Vec::new();
        for i in 0..levels {
            let at = 4 + 8 * i;
            let word = |o: usize| -> Result<u32, String> {
                Ok(u32::from_be_bytes(bytes.get(o..o + 4).ok_or_else(bad)?.try_into()
                                      .map_err(|_| bad())?))
            };
            let lms = LmsParams::by_id(word(at)?).ok_or_else(bad)?;
            let ots = LmotsParams::by_id(word(at + 4)?).ok_or_else(bad)?;
            params.push((lms, ots));
        }
        let at = 4 + 8 * levels;
        let m = params[0].0.m;
        if bytes.len() != at + 8 + m + 16 {
            return Err(bad());
        }
        let count = u64::from_be_bytes(bytes[at..at + 8].try_into().map_err(|_| bad())?);
        let seed = &bytes[at + 8..at + 8 + m];
        let id: [u8; 16] = bytes[at + 8 + m..].try_into().map_err(|_| bad())?;
        HssPrivateKey::from_seed(&params, seed, &id, count)
    }
}

/// Whether `signature` is an HSS signature of `message` under
/// `public_key`, RFC 8554 Algorithm 6. Anything malformed is `false`.
pub fn hss_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    hss_verify_inner(public_key, message, signature).unwrap_or(false)
}

fn hss_verify_inner(public_key: &[u8], message: &[u8], signature: &[u8]) -> Option<bool> {
    let levels = u32::from_be_bytes(public_key.get(..4)?.try_into().ok()?) as usize;
    let nspk = u32::from_be_bytes(signature.get(..4)?.try_into().ok()?) as usize;
    if levels == 0 || levels > HSS_MAX_LEVELS || nspk + 1 != levels {
        return Some(false);
    }
    let mut key = &public_key[4..];
    let mut rest = &signature[4..];
    for _ in 0..nspk {
        let sig_len = signature_len_at(rest)?;
        let (sig, after) = rest.split_at(sig_len);
        let pub_len = public_key_len_at(after)?;
        let (next, after) = after.split_at(pub_len);
        if !lms_verify(key, next, sig) {
            return Some(false);
        }
        key = next;
        rest = after;
    }
    Some(lms_verify(key, message, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coef_reads_digits_from_the_top() {
        let s = [0x12, 0x34];
        assert_eq!((0..4).map(|i| coef(&s, i, 4)).collect::<Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!((0..8).map(|i| coef(&s, i, 2)).collect::<Vec<_>>(),
                   [0, 1, 0, 2, 0, 3, 1, 0]);
        assert_eq!(coef(&s, 0, 8), 0x12);
        assert_eq!((0..8).map(|i| coef(&s[..1], i, 1)).collect::<Vec<_>>(),
                   [0, 0, 0, 1, 0, 0, 1, 0]);
    }

    #[test]
    fn test_names_and_codes() {
        assert_eq!(LmsParams::named("lms_sha256_m32_h10").unwrap().id, 6);
        assert_eq!(LmsParams::named("0x14").unwrap().name, "LMS_SHAKE_M24_H5");
        assert_eq!(LmotsParams::named("16").unwrap().name, "LMOTS_SHAKE_N24_W8");
        assert!(LmsParams::named("LMS_SHA256_M32_H30").is_err());
        assert!(LmsParams::named("4").is_err());
        assert!(LmotsParams::named("0").is_err());
    }

    #[test]
    fn test_a_mixed_pair_is_refused() {
        let lms = LmsParams::named("LMS_SHA256_M32_H5").unwrap();
        for other in ["LMOTS_SHA256_N24_W8", "LMOTS_SHAKE_N32_W8"] {
            let ots = LmotsParams::named(other).unwrap();
            assert!(LmsPrivateKey::from_seed(lms, ots, &[0; 32], &[0; 16], 0).is_err());
        }
    }

    #[test]
    fn test_a_tree_signs_every_leaf_once_and_then_refuses() {
        let lms = LmsParams::named("LMS_SHA256_M24_H5").unwrap();
        let ots = LmotsParams::named("LMOTS_SHA256_N24_W2").unwrap();
        let mut key = LmsPrivateKey::from_seed(lms, ots, &[7; 24], &[9; 16], 0).unwrap();
        let public = key.public_key();
        for q in 0..32u32 {
            let message = q.to_be_bytes();
            let sig = key.sign(&message).unwrap();
            assert_eq!(sig[..4], q.to_be_bytes());
            assert!(lms_verify(&public, &message, &sig));
            assert!(!lms_verify(&public, b"other", &sig));
        }
        assert!(key.sign(b"one more").is_err());
    }

    #[test]
    fn test_a_leaf_number_past_the_tree_is_refused_without_overflowing() {
        // RFC 8554 Algorithm 6a refuses q >= 2^h. A path walked from such
        // a q ends at the wrong node and could not verify, but the node
        // number 2^h + q is a u32: at q near 2^32 it overflows.
        let lms = LmsParams::named("LMS_SHA256_M24_H25").unwrap();
        let ots = LmotsParams::named("LMOTS_SHA256_N24_W8").unwrap();
        let public = [&lms.id.to_be_bytes()[..], &ots.id.to_be_bytes(), &[0; 16], &[0; 24]]
            .concat();
        for q in [1u32 << 25, u32::MAX] {
            let mut sig = q.to_be_bytes().to_vec();
            sig.extend_from_slice(&ots.id.to_be_bytes());
            sig.resize(4 + ots.signature_len(), 0);
            sig.extend_from_slice(&lms.id.to_be_bytes());
            sig.resize(lms.signature_len(ots), 0);
            assert!(!lms_verify(&public, b"m", &sig), "q {q}");
        }
    }

    #[test]
    fn test_a_mixed_pair_is_refused_even_when_its_signature_is_consistent() {
        // A tree whose one-time keys use a shorter hash than its nodes,
        // built by hand past the check that refuses to make one: its
        // signature hangs together, and the verifier must still refuse it.
        let lms = LmsParams::named("LMS_SHA256_M32_H5").unwrap();
        let ots = LmotsParams::named("LMOTS_SHA256_N24_W8").unwrap();
        let mut key = LmsPrivateKey { lms, ots, id: [3; 16], seed: vec![4; 24], q: 0,
                                      nodes: None };
        let public = key.public_key();
        let sig = key.sign(b"m").unwrap();
        assert!(!lms_verify(&public, b"m", &sig));
    }

    #[test]
    fn test_levels_of_different_hash_lengths_make_a_hierarchy() {
        // A lower tree's SEED is as long as its own hash, the parent's
        // derivation cut or padded with zeros, as hash-sigs makes it.
        let long = (LmsParams::named("LMS_SHA256_M32_H5").unwrap(),
                    LmotsParams::named("LMOTS_SHA256_N32_W4").unwrap());
        let short = (LmsParams::named("LMS_SHAKE_M24_H5").unwrap(),
                     LmotsParams::named("LMOTS_SHAKE_N24_W4").unwrap());
        for levels in [[long, short], [short, long]] {
            let seed = vec![5; levels[0].0.m];
            let mut key = HssPrivateKey::from_seed(&levels, &seed, &[6; 16], 31).unwrap();
            for message in [&b"before"[..], b"after the lower tree is replaced"] {
                let sig = key.sign(message).unwrap();
                assert!(hss_verify(&key.public_key(), message, &sig));
            }
            assert_eq!(key.levels[1].seed.len(), levels[1].0.m);
        }
    }

    #[test]
    fn test_a_tall_tree_recomputes_what_a_short_one_caches() {
        // The path through recomputed subtrees must equal the cached one;
        // both at a height that is cheap, by lowering the cut for one key.
        let lms = LmsParams::named("LMS_SHA256_M24_H5").unwrap();
        let ots = LmotsParams::named("LMOTS_SHA256_N24_W8").unwrap();
        let mut cached = LmsPrivateKey::from_seed(lms, ots, &[1; 24], &[2; 16], 13).unwrap();
        let fresh = cached.clone();
        let sig = cached.sign(b"m").unwrap();
        let mut path = Vec::new();
        let mut r = 32 + 13u32;
        while r > 1 {
            path.extend_from_slice(&fresh.subtree(r ^ 1));
            r /= 2;
        }
        assert_eq!(sig[sig.len() - path.len()..], path[..]);
        assert_eq!(fresh.subtree(1), cached.node(1));
    }
}
