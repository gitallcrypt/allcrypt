/*!
XMSS and XMSS^MT: the eXtended Merkle Signature Scheme (RFC 8391), with
the SHA-256/192, SHAKE256/256 and SHAKE256/192 parameter sets of NIST SP
800-208.

**Stateful**, as LMS is (`pq::lms`): each signature spends one WOTS+
one-time key, the private key's index says which is next, and signing
moves it on before returning. A copy of the key signs with the same
leaves twice; the caller stores the moved key before the signature
leaves.

## What differs from LMS

The one-time signature is WOTS+ with `w = 16`, and every hash in it and in
the trees is keyed and masked: the key and the bitmask are each a PRF of
the public `SEED` and a 32 byte address naming the hash's place - layer,
tree, leaf, chain, step - so no two hashes in a key share an input. A
leaf is the WOTS+ public key compressed by an L-tree, an unbalanced tree
over its `len` chain ends. XMSS^MT stacks `d` layers of trees of height
`h / d`, as HSS stacks LMS trees, but derives every tree from the one
`SK_SEED` and signs with one index across all of them.

## Keys from seeds

A key is three `n`-byte seeds, `SK_SEED`, `SK_PRF` and `SEED`, and the
index of the next leaf. Each WOTS+ private key element is derived as SP
800-208 section 7.2.1 requires:
`PRF_keygen(SK_SEED, SEED || ADRS)`, with the address of its chain. RFC
8391's own suggestion, a PRF of `SK_SEED` and the leaf's address expanded
per chain, is open to a multi-target attack and gives different keys from
the same seeds: Botan 2 and Bouncy Castle 1.77 derive that way, Botan 3
and the XMSS reference implementation this way. The private key bytes are
the reference's: `OID || idx || SK_SEED || SK_PRF || root || SEED`.
*/

use crate::hash_functions::keccak::Keccak;
use crate::hash_functions::sha2::{SHA256, SHA512};
use crate::hash_functions::HashFunction;

/// The hash under a parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmssHash {
    /// SHA-256 at `n = 32`, its first 24 bytes at `n = 24`, and SHA-512 at
    /// `n = 64`.
    Sha2,
    /// SHAKE128 with `n` bytes of output: RFC 8391's `SHAKE` sets at 256 bits.
    Shake128,
    /// SHAKE256 with `n` bytes of output: RFC 8391's `SHAKE` sets at 512
    /// bits and SP 800-208's `SHAKE256` sets.
    Shake256,
}

/// An XMSS or XMSS^MT parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XmssParams {
    /// The name RFC 8391 or SP 800-208 gives it: `XMSS-SHA2_10_256`,
    /// `XMSSMT-SHAKE256_40/4_192`.
    pub name: &'static str,
    /// The OID in keys - the XMSS and XMSS^MT registries number apart.
    pub oid: u32,
    /// Whether this is XMSS^MT.
    pub multi_tree: bool,
    /// The hash.
    pub hash: XmssHash,
    /// Bytes of hash output.
    pub n: usize,
    /// The whole height: `2^h` signatures.
    pub h: u32,
    /// Layers: 1 for XMSS.
    pub d: u32,
}

/// RFC 8391 and SP 800-208's families, in the order the registries number
/// them: (name part, hash, n).
const FAMILIES: [(&str, XmssHash, usize); 7] = [
    ("SHA2", XmssHash::Sha2, 32), ("SHA2", XmssHash::Sha2, 64),
    ("SHAKE", XmssHash::Shake128, 32), ("SHAKE", XmssHash::Shake256, 64),
    ("SHA2", XmssHash::Sha2, 24), ("SHAKE256", XmssHash::Shake256, 32),
    ("SHAKE256", XmssHash::Shake256, 24),
];
const XMSS_HEIGHTS: [u32; 3] = [10, 16, 20];
const XMSSMT_SHAPES: [(u32, u32); 8] =
    [(20, 2), (20, 4), (40, 2), (40, 4), (40, 8), (60, 3), (60, 6), (60, 12)];

/// Every parameter set: the 21 XMSS ones, then the 56 XMSS^MT ones.
pub fn parameter_sets() -> &'static [XmssParams] {
    use std::sync::OnceLock;
    static SETS: OnceLock<Vec<XmssParams>> = OnceLock::new();
    SETS.get_or_init(|| {
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        let mut out = Vec::new();
        for (f, &(part, hash, n)) in FAMILIES.iter().enumerate() {
            for (i, &h) in XMSS_HEIGHTS.iter().enumerate() {
                out.push(XmssParams { name: leak(format!("XMSS-{part}_{h}_{}", 8 * n)),
                                      oid: (3 * f + i + 1) as u32, multi_tree: false, hash, n,
                                      h, d: 1 });
            }
        }
        for (f, &(part, hash, n)) in FAMILIES.iter().enumerate() {
            for (i, &(h, d)) in XMSSMT_SHAPES.iter().enumerate() {
                out.push(XmssParams { name: leak(format!("XMSSMT-{part}_{h}/{d}_{}", 8 * n)),
                                      oid: (8 * f + i + 1) as u32, multi_tree: true, hash, n,
                                      h, d });
            }
        }
        out
    })
}

const W: usize = 16;
const PAD_F: u64 = 0;
const PAD_H: u64 = 1;
const PAD_HASH_MSG: u64 = 2;
const PAD_PRF: u64 = 3;
const PAD_PRF_KEYGEN: u64 = 4;

impl XmssParams {
    /// A parameter set by its name, in any case.
    pub fn named(name: &str) -> Result<&'static XmssParams, String> {
        parameter_sets().iter().find(|p| p.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| format!("No XMSS or XMSS^MT parameter set {name:?}; \
                                    xmss_parameter_sets() lists them."))
    }

    /// An XMSS parameter set by OID, or an XMSS^MT one.
    pub fn by_oid(oid: u32, multi_tree: bool) -> Option<&'static XmssParams> {
        parameter_sets().iter().find(|p| p.oid == oid && p.multi_tree == multi_tree)
    }

    /// One tree's height, `h / d`.
    pub fn tree_height(&self) -> u32 {
        self.h / self.d
    }

    /// WOTS+ chains: `len1 = 8n / 4` for the message and three for the
    /// checksum, which at `w = 16` is three digits for every `n` here.
    pub fn wots_len(&self) -> usize {
        2 * self.n + 3
    }

    /// The index's bytes in a signature and a private key: four for XMSS,
    /// `ceil(h / 8)` for XMSS^MT.
    pub fn index_len(&self) -> usize {
        if self.multi_tree { self.h.div_ceil(8) as usize } else { 4 }
    }

    /// The prefix that separates the hash functions: 32 bytes at `n = 32`,
    /// 64 at `n = 64`, and 4 for SP 800-208's `n = 24`.
    fn padding_len(&self) -> usize {
        if self.n == 24 { 4 } else { self.n }
    }

    /// `OID || root || SEED`.
    pub fn public_key_len(&self) -> usize {
        4 + 2 * self.n
    }

    /// `OID || idx || SK_SEED || SK_PRF || root || SEED`.
    pub fn private_key_len(&self) -> usize {
        4 + self.index_len() + 4 * self.n
    }

    /// `idx || r || ` and per layer a WOTS+ signature and an authentication
    /// path.
    pub fn signature_len(&self) -> usize {
        self.index_len() + self.n
            + self.d as usize * (self.wots_len() + self.tree_height() as usize) * self.n
    }

    /// A hash with `toByte(which, padding_len)` already in it.
    fn start(&self, which: u64) -> Hasher {
        let mut h = match (self.hash, self.n) {
            (XmssHash::Sha2, 64) => Hasher::Sha512(SHA512::new(&[], 512)),
            (XmssHash::Sha2, _) => Hasher::Sha256(SHA256::new(&[])),
            (XmssHash::Shake128, n) => Hasher::Shake(Keccak::shake(128, n)
                                                     .expect("a SHAKE security level")),
            (XmssHash::Shake256, n) => Hasher::Shake(Keccak::shake(256, n)
                                                     .expect("a SHAKE security level")),
        };
        // `which` is below 256 for every function here, so the prefix is
        // zeros and one byte.
        const ZEROS: [u8; 64] = [0; 64];
        h.update(&ZEROS[..self.padding_len() - 1]);
        h.update(&[which as u8]);
        h
    }

    /// `H(toByte(which, padding_len) || key || parts...)`.
    fn keyed(&self, which: u64, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut h = self.start(which);
        h.update(key);
        for part in parts {
            h.update(part);
        }
        h.finish(self.n)
    }
}

/// The hash under a parameter set, part way through its input.
#[derive(Clone)]
enum Hasher {
    Sha256(SHA256),
    Sha512(SHA512),
    Shake(Keccak),
}

impl Hasher {
    fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
            Hasher::Shake(h) => h.update(data),
        }
    }

    /// The first `n` bytes of the output.
    fn finish(self, n: usize) -> Vec<u8> {
        let mut out = match self {
            Hasher::Sha256(mut h) => h.digest(),
            Hasher::Sha512(mut h) => h.digest(),
            Hasher::Shake(h) => return h.squeeze(n),
        };
        out.truncate(n);
        out
    }
}

/// A hash address: eight big-endian words.
#[derive(Clone, Copy, Default)]
struct Adrs([u32; 8]);

impl Adrs {
    fn new(layer: u32, tree: u64, kind: u32) -> Adrs {
        Adrs([layer, (tree >> 32) as u32, tree as u32, kind, 0, 0, 0, 0])
    }

    fn with(mut self, word: usize, value: u32) -> Adrs {
        self.0[word] = value;
        self
    }

    fn bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_mut(4).zip(self.0) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

const OTS: u32 = 0;
const LTREE: u32 = 1;
const HASH_TREE: u32 = 2;
/// The word that selects the key or a bitmask.
const KEY_AND_MASK: usize = 7;

/// The key a tree's hashes need: the parameters and the two seeds.
struct Keys<'a> {
    p: &'static XmssParams,
    sk_seed: &'a [u8],
    seed: &'a [u8],
    /// `PRF(SEED, ·)` with its prefix and `SEED` already in: two thirds of
    /// a tree's hash calls are this PRF, and where the two fill whole
    /// SHA-2 blocks - `n = 32` and `n = 64` - this halves their cost.
    prf_start: Hasher,
}

impl<'a> Keys<'a> {
    fn new(p: &'static XmssParams, sk_seed: &'a [u8], seed: &'a [u8]) -> Keys<'a> {
        let mut prf_start = p.start(PAD_PRF);
        prf_start.update(seed);
        Keys { p, sk_seed, seed, prf_start }
    }

    fn prf(&self, adrs: Adrs) -> Vec<u8> {
        let mut h = self.prf_start.clone();
        h.update(&adrs.bytes());
        h.finish(self.p.n)
    }

    /// Algorithm 2: `steps` steps of chain `adrs` from step `start`.
    fn chain(&self, x: &[u8], start: usize, steps: usize, adrs: Adrs) -> Vec<u8> {
        let mut tmp = x.to_vec();
        for j in start..start + steps {
            let at = adrs.with(6, j as u32);
            let key = self.prf(at.with(KEY_AND_MASK, 0));
            let mask = self.prf(at.with(KEY_AND_MASK, 1));
            for (t, m) in tmp.iter_mut().zip(&mask) {
                *t ^= m;
            }
            let mut h = self.p.start(PAD_F);
            h.update(&key);
            h.update(&tmp);
            tmp = h.finish(self.p.n);
        }
        tmp
    }

    /// Algorithm 7: `H` keyed and masked by the address.
    fn rand_hash(&self, left: &[u8], right: &[u8], adrs: Adrs) -> Vec<u8> {
        let key = self.prf(adrs.with(KEY_AND_MASK, 0));
        let m0 = self.prf(adrs.with(KEY_AND_MASK, 1));
        let m1 = self.prf(adrs.with(KEY_AND_MASK, 2));
        let mut h = self.p.start(PAD_H);
        h.update(&key);
        let mut masked = [0u8; 64];
        for (side, mask) in [(left, &m0), (right, &m1)] {
            for ((out, a), b) in masked.iter_mut().zip(side).zip(mask) {
                *out = a ^ b;
            }
            h.update(&masked[..side.len()]);
        }
        h.finish(self.p.n)
    }

    /// WOTS+ private key element `chain` of leaf `leaf`, SP 800-208 7.2.1.
    fn wots_secret(&self, layer: u32, tree: u64, leaf: u32, chain: u32) -> Vec<u8> {
        let adrs = Adrs::new(layer, tree, OTS).with(4, leaf).with(5, chain);
        self.p.keyed(PAD_PRF_KEYGEN, self.sk_seed, &[self.seed, &adrs.bytes()])
    }

    /// Algorithm 8: the L-tree over a WOTS+ public key.
    fn ltree(&self, mut pk: Vec<Vec<u8>>, layer: u32, tree: u64, leaf: u32) -> Vec<u8> {
        let base = Adrs::new(layer, tree, LTREE).with(4, leaf);
        let mut height = 0;
        while pk.len() > 1 {
            let half = pk.len() / 2;
            let mut next: Vec<Vec<u8>> = (0..half).map(|i| {
                self.rand_hash(&pk[2 * i], &pk[2 * i + 1],
                               base.with(5, height).with(6, i as u32))
            }).collect();
            if !pk.len().is_multiple_of(2) {
                next.push(pk.pop().expect("odd, so not empty"));
            }
            pk = next;
            height += 1;
        }
        pk.pop().expect("len is never zero")
    }

    /// A leaf: the L-tree over WOTS+ public key `leaf` of one tree.
    fn leaf(&self, layer: u32, tree: u64, leaf: u32) -> Vec<u8> {
        let ots = Adrs::new(layer, tree, OTS).with(4, leaf);
        let pk = (0..self.p.wots_len() as u32).map(|i| {
            let x = self.wots_secret(layer, tree, leaf, i);
            self.chain(&x, 0, W - 1, ots.with(5, i))
        }).collect();
        self.ltree(pk, layer, tree, leaf)
    }

    /// Node `index` at `height` of one tree, from its leaves.
    fn node(&self, layer: u32, tree: u64, height: u32, index: u32) -> Vec<u8> {
        if height == 0 {
            return self.leaf(layer, tree, index);
        }
        let left = self.node(layer, tree, height - 1, 2 * index);
        let right = self.node(layer, tree, height - 1, 2 * index + 1);
        self.rand_hash(&left, &right,
                       Adrs::new(layer, tree, HASH_TREE).with(5, height - 1).with(6, index))
    }

    /// Algorithm 5 and the checksum: the digits a message signs.
    fn digits(&self, message: &[u8]) -> Vec<usize> {
        let mut out: Vec<usize> = message.iter().flat_map(|b| [(b >> 4) as usize,
                                                               (b & 15) as usize]).collect();
        let checksum: usize = out.iter().map(|d| W - 1 - d).sum::<usize>() << 4;
        out.extend([(checksum >> 12) & 15, (checksum >> 8) & 15, (checksum >> 4) & 15]);
        out
    }

    /// A WOTS+ signature of `message` with leaf `leaf` of one tree.
    fn wots_sign(&self, message: &[u8], layer: u32, tree: u64, leaf: u32) -> Vec<u8> {
        let ots = Adrs::new(layer, tree, OTS).with(4, leaf);
        self.digits(message).into_iter().enumerate().flat_map(|(i, d)| {
            let x = self.wots_secret(layer, tree, leaf, i as u32);
            self.chain(&x, 0, d, ots.with(5, i as u32))
        }).collect()
    }
}

/// The root a WOTS+ signature and authentication path lead to, Algorithm
/// 14 for one tree; `seed` is the public SEED.
fn root_from_signature(p: &'static XmssParams, seed: &[u8], message: &[u8], sig: &[u8],
                       auth: &[u8], (layer, tree, leaf): (u32, u64, u32)) -> Vec<u8> {
    let keys = Keys::new(p, &[], seed);
    let ots = Adrs::new(layer, tree, OTS).with(4, leaf);
    let pk = keys.digits(message).into_iter().enumerate().map(|(i, d)| {
        keys.chain(&sig[i * p.n..(i + 1) * p.n], d, W - 1 - d, ots.with(5, i as u32))
    }).collect();
    let mut node = keys.ltree(pk, layer, tree, leaf);
    let mut index = leaf;
    for (k, sibling) in auth.chunks(p.n).enumerate() {
        let adrs = Adrs::new(layer, tree, HASH_TREE).with(5, k as u32).with(6, index / 2);
        node = if index.is_multiple_of(2) {
            keys.rand_hash(&node, sibling, adrs)
        } else {
            keys.rand_hash(sibling, &node, adrs)
        };
        index /= 2;
    }
    node
}

/// `H_msg(r || root || toByte(idx, n), message)`.
fn message_hash(p: &'static XmssParams, r: &[u8], root: &[u8], idx: u64, message: &[u8])
                -> Vec<u8> {
    let mut idx_bytes = vec![0u8; p.n];
    let at = p.n - 8;
    idx_bytes[at..].copy_from_slice(&idx.to_be_bytes());
    let key = [r, root, &idx_bytes].concat();
    p.keyed(PAD_HASH_MSG, &key, &[message])
}

/// Trees this high or lower keep every node once built; higher ones are
/// computed again for each signature.
const CACHED_HEIGHT: u32 = 16;

/// An XMSS or XMSS^MT private key.
#[derive(Clone)]
pub struct XmssPrivateKey {
    p: &'static XmssParams,
    idx: u64,
    sk_seed: Vec<u8>,
    sk_prf: Vec<u8>,
    root: Vec<u8>,
    seed: Vec<u8>,
    /// Built trees, at most one per layer, by (layer, tree).
    cache: Vec<((u32, u64), Levels)>,
}

/// One tree's nodes, level by level from the leaves: `levels[height][index]`.
type Levels = Vec<Vec<Vec<u8>>>;

impl XmssPrivateKey {
    /// The key of `p` from `SK_SEED`, `SK_PRF` and `SEED`, `n` bytes each,
    /// whose next leaf is `idx`. Computes the root: the top tree, every
    /// leaf.
    pub fn from_seeds(p: &'static XmssParams, sk_seed: &[u8], sk_prf: &[u8], seed: &[u8],
                      idx: u64) -> Result<XmssPrivateKey, String> {
        for (what, s) in [("SK_SEED", sk_seed), ("SK_PRF", sk_prf), ("SEED", seed)] {
            if s.len() != p.n {
                return Err(format!("{}'s {what} is {} bytes, not {}.", p.name, p.n, s.len()));
            }
        }
        if p.h < 64 && idx > 1u64 << p.h {
            return Err(format!("{} signs {} times; {idx} is past them.", p.name, 1u64 << p.h));
        }
        let mut key = XmssPrivateKey { p, idx, sk_seed: sk_seed.to_vec(),
                                       sk_prf: sk_prf.to_vec(), root: Vec::new(),
                                       seed: seed.to_vec(), cache: Vec::new() };
        let top = p.tree_height();
        key.root = key.tree_node(p.d - 1, 0, top, 0);
        Ok(key)
    }

    /// Node `(height, index)` of tree `tree` at `layer`, from the cache
    /// when the tree is low enough to keep.
    fn tree_node(&mut self, layer: u32, tree: u64, height: u32, index: u32) -> Vec<u8> {
        let keys = Keys::new(self.p, &self.sk_seed, &self.seed);
        let top = self.p.tree_height();
        if top > CACHED_HEIGHT {
            return keys.node(layer, tree, height, index);
        }
        if let Some((_, levels)) = self.cache.iter().find(|(at, _)| *at == (layer, tree)) {
            return levels[height as usize][index as usize].clone();
        }
        let mut levels: Levels =
            vec![(0..1u32 << top).map(|i| keys.leaf(layer, tree, i)).collect()];
        for k in 0..top {
            let below = &levels[k as usize];
            let next = (0..below.len() / 2).map(|j| {
                keys.rand_hash(&below[2 * j], &below[2 * j + 1],
                               Adrs::new(layer, tree, HASH_TREE).with(5, k).with(6, j as u32))
            }).collect();
            levels.push(next);
        }
        let value = levels[height as usize][index as usize].clone();
        // One tree per layer is in use at a time; keep those.
        self.cache.retain(|(at, _)| at.0 != layer);
        self.cache.push(((layer, tree), levels));
        value
    }

    /// The parameter set.
    pub fn params(&self) -> &'static XmssParams {
        self.p
    }

    /// The next leaf: the number of signatures made, if the key began at 0.
    pub fn index(&self) -> u64 {
        self.idx
    }

    /// Signatures left.
    pub fn remaining(&self) -> u64 {
        if self.p.h >= 64 { u64::MAX - self.idx } else { (1u64 << self.p.h) - self.idx }
    }

    /// `OID || root || SEED`.
    pub fn public_key(&self) -> Vec<u8> {
        [&self.p.oid.to_be_bytes()[..], &self.root, &self.seed].concat()
    }

    /// `OID || idx || SK_SEED || SK_PRF || root || SEED`, the XMSS
    /// reference implementation's form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let idx = &self.idx.to_be_bytes()[8 - self.p.index_len()..];
        [&self.p.oid.to_be_bytes()[..], idx, &self.sk_seed, &self.sk_prf, &self.root,
         &self.seed].concat()
    }

    /// Reads [`to_bytes`](XmssPrivateKey::to_bytes) back, an XMSS key or,
    /// with `multi_tree`, an XMSS^MT one - the two registries share OIDs.
    /// The root is computed again and must be the one stored.
    pub fn from_bytes(bytes: &[u8], multi_tree: bool) -> Result<XmssPrivateKey, String> {
        let kind = if multi_tree { "XMSS^MT" } else { "XMSS" };
        let bad = || format!("Not an {kind} private key in the reference's form.");
        let oid = u32::from_be_bytes(bytes.get(..4).ok_or_else(bad)?.try_into()
                                     .map_err(|_| bad())?);
        let p = XmssParams::by_oid(oid, multi_tree).ok_or_else(bad)?;
        if bytes.len() != p.private_key_len() {
            return Err(bad());
        }
        let (n, i) = (p.n, p.index_len());
        let idx = bytes[4..4 + i].iter().fold(0u64, |a, &b| a << 8 | u64::from(b));
        let at = 4 + i;
        let key = XmssPrivateKey::from_seeds(p, &bytes[at..at + n], &bytes[at + n..at + 2 * n],
                                             &bytes[at + 3 * n..], idx)?;
        if key.root != bytes[at + 2 * n..at + 3 * n] {
            return Err(format!("This {kind} private key's root is not the one its seeds make."));
        }
        Ok(key)
    }

    /// Signs with the next leaf and moves past it; an error once every
    /// leaf is spent.
    pub fn sign(&mut self, message: &[u8]) -> Result<Vec<u8>, String> {
        if self.remaining() == 0 {
            return Err(format!("This {} key has made all {} of its signatures.",
                               self.p.name, 1u64 << self.p.h));
        }
        let p = self.p;
        let idx = self.idx;
        self.idx += 1;
        let mut idx32 = [0u8; 32];
        idx32[24..].copy_from_slice(&idx.to_be_bytes());
        let r = p.keyed(PAD_PRF, &self.sk_prf, &[&idx32]);
        let mut out = idx.to_be_bytes()[8 - p.index_len()..].to_vec();
        out.extend_from_slice(&r);
        let top = p.tree_height();
        let mask = (1u64 << top) - 1;
        let mut signed = message_hash(p, &r, &self.root, idx, message);
        let mut tree = idx >> top;
        let mut leaf = (idx & mask) as u32;
        for layer in 0..p.d {
            let keys = Keys::new(p, &self.sk_seed, &self.seed);
            out.extend_from_slice(&keys.wots_sign(&signed, layer, tree, leaf));
            let mut index = leaf;
            for k in 0..top {
                let sibling = self.tree_node(layer, tree, k, index ^ 1);
                out.extend_from_slice(&sibling);
                index /= 2;
            }
            signed = self.tree_node(layer, tree, top, 0);
            leaf = (tree & mask) as u32;
            tree >>= top;
        }
        Ok(out)
    }
}

/// Whether `signature` is an XMSS signature of `message` under
/// `public_key` - or, with `multi_tree`, an XMSS^MT one. Anything
/// malformed is `false`.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8], multi_tree: bool) -> bool {
    let Some(oid) = public_key.get(..4) else { return false };
    let Some(p) = XmssParams::by_oid(u32::from_be_bytes(oid.try_into().expect("four bytes")),
                                     multi_tree) else { return false };
    if public_key.len() != p.public_key_len() || signature.len() != p.signature_len() {
        return false;
    }
    let (root, seed) = (&public_key[4..4 + p.n], &public_key[4 + p.n..]);
    let i = p.index_len();
    let idx = signature[..i].iter().fold(0u64, |a, &b| a << 8 | u64::from(b));
    if p.h < 64 && idx >> p.h != 0 {
        return false;
    }
    let r = &signature[i..i + p.n];
    let top = p.tree_height();
    let mask = (1u64 << top) - 1;
    let mut node = message_hash(p, r, root, idx, message);
    let mut tree = idx >> top;
    let mut leaf = (idx & mask) as u32;
    let per_layer = (p.wots_len() + top as usize) * p.n;
    for (layer, part) in signature[i + p.n..].chunks(per_layer).enumerate() {
        let (sig, auth) = part.split_at(p.wots_len() * p.n);
        node = root_from_signature(p, seed, &node, sig, auth, (layer as u32, tree, leaf));
        leaf = (tree & mask) as u32;
        tree >>= top;
    }
    node == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_registries() {
        let sets = parameter_sets();
        assert_eq!(sets.len(), 21 + 56);
        assert_eq!(XmssParams::named("XMSS-SHA2_10_256").unwrap().oid, 1);
        assert_eq!(XmssParams::named("xmss-shake256_20_192").unwrap().oid, 0x15);
        assert_eq!(XmssParams::named("XMSSMT-SHA2_20/2_256").unwrap().oid, 1);
        assert_eq!(XmssParams::named("XMSSMT-SHAKE256_60/12_192").unwrap().oid, 0x38);
        assert_eq!(XmssParams::by_oid(7, false).unwrap().hash, XmssHash::Shake128);
        assert_eq!(XmssParams::by_oid(10, false).unwrap().hash, XmssHash::Shake256);
        assert!(XmssParams::by_oid(0x16, false).is_none());
        assert!(XmssParams::by_oid(0x39, true).is_none());
    }

    #[test]
    fn test_the_padding_prefix() {
        let p = XmssParams::named("XMSS-SHA2_10_192").unwrap();
        let q = XmssParams::named("XMSS-SHA2_10_256").unwrap();
        // toByte(3, 4) and toByte(3, 32): the value in the last byte.
        let a = p.keyed(PAD_PRF, &[1; 24], &[&[2; 32]]);
        let mut manual = SHA256::new(&[0, 0, 0, 3]);
        manual.update(&[1; 24]);
        manual.update(&[2; 32]);
        assert_eq!(a, manual.digest()[..24]);
        let b = q.keyed(PAD_PRF, &[1; 32], &[&[2; 32]]);
        let mut manual = SHA256::new(&[0; 31]);
        manual.update(&[3]);
        manual.update(&[1; 32]);
        manual.update(&[2; 32]);
        assert_eq!(b, manual.digest());
    }

    #[test]
    fn test_the_absorbed_prf_is_the_prf() {
        for name in ["XMSS-SHA2_10_256", "XMSS-SHA2_10_512", "XMSS-SHA2_10_192",
                     "XMSS-SHAKE_10_256"] {
            let p = XmssParams::named(name).unwrap();
            let seed = vec![9u8; p.n];
            let keys = Keys::new(p, &[], &seed);
            let adrs = Adrs::new(1, 2, OTS).with(4, 3).with(5, 4).with(6, 5).with(7, 1);
            assert_eq!(keys.prf(adrs), p.keyed(PAD_PRF, &seed, &[&adrs.bytes()]), "{name}");
        }
    }

    #[test]
    fn test_tall_trees_compute_what_low_ones_cache() {
        // Trees above CACHED_HEIGHT are computed node by node: the same
        // nodes, at every height, as the cached levels of a low tree.
        let p = XmssParams::named("XMSSMT-SHA2_20/4_192").unwrap();
        let mut key = XmssPrivateKey::from_seeds(p, &[4; 24], &[5; 24], &[6; 24], 0).unwrap();
        let (sk_seed, seed) = (key.sk_seed.clone(), key.seed.clone());
        let keys = Keys::new(p, &sk_seed, &seed);
        for (height, index) in [(0, 7), (1, 3), (2, 6), (4, 1), (5, 0)] {
            assert_eq!(keys.node(1, 9, height, index), key.tree_node(1, 9, height, index),
                       "height {height}");
        }
    }

    #[test]
    fn test_a_small_multi_tree_key_signs_across_trees() {
        // XMSSMT-SHA2_20/4_192: trees of height 5. Across the end of the
        // lowest tree, every signature verifies and a changed one does not.
        let p = XmssParams::named("XMSSMT-SHA2_20/4_192").unwrap();
        let mut key = XmssPrivateKey::from_seeds(p, &[1; 24], &[2; 24], &[3; 24], 30).unwrap();
        let public = key.public_key();
        for i in 30..34u64 {
            let message = i.to_be_bytes();
            let sig = key.sign(&message).unwrap();
            assert_eq!(sig.len(), p.signature_len());
            assert!(verify(&public, &message, &sig, true), "{i}");
            assert!(!verify(&public, &message, &sig, false));
            assert!(!verify(&public, b"other", &sig, true));
        }
        let bytes = key.to_bytes();
        let back = XmssPrivateKey::from_bytes(&bytes, true).unwrap();
        assert_eq!(back.index(), 34);
        let mut wrong = bytes.clone();
        wrong[4 + p.index_len() + 2 * p.n] ^= 1;
        assert!(XmssPrivateKey::from_bytes(&wrong, true).is_err());
    }
}
