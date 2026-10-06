//! Bitsliced, fixsliced AES: the constant-time path behind
//! `AesCrypto::encrypt_blocks` and `decrypt_blocks`.
//!
//! ## Representation
//!
//! Four blocks are held as eight `u64`s, one per bit position of a byte
//! (BearSSL's `aes_ct64` layout): word `k` holds bit `k` of all 64 bytes.
//! Within a word, bits `16r..16r+16` are row `r`, and inside a row the
//! nibble at `4c` is column `c`, one bit per block. A row rotation of the
//! state is a 16-bit rotation of each word and a column rotation is a
//! nibble rotation inside each 16-bit quarter.
//!
//! The S-box is Boyar and Peralta's 113-gate circuit over the eight words;
//! the inverse S-box is the forward one between two applications of the
//! inverse affine map. No step indexes memory with key or data, and no
//! step branches on them.
//!
//! ## Fixslicing
//!
//! ShiftRows is not applied each round (Adomnicai and Peyrin, "Fixslicing
//! AES-like ciphers", TCHES 2021). The state after round `t` is kept as
//! `SR^-t` of the real one, which turns round `t`'s MixColumns into
//! `SR^-s . MC . SR^s` for `s = t mod 4`: the same formula with the row
//! rotations replaced by "one row down and `s` columns across". Round keys
//! `1..Nr-1` are stored pre-permuted by `SR^-t`, and the last round applies
//! the outstanding `SR^(Nr mod 4)` once - `SR^2` for AES-128 and AES-256,
//! nothing for AES-192.
//!
//! ## Groups
//!
//! The round functions take eight words, four blocks. `encrypt_n` runs `N`
//! such groups through every stage in a plain loop over the groups, which
//! the compiler's loop vectoriser widens into SSE2 registers on x86-64; no
//! intrinsics are involved. Sixteen blocks (`N = 4`) is the batch size
//! used, and a shorter tail goes four blocks at a time, zero padded.

/// Eight bit planes of four blocks.
type Planes = [u64; 8];

/// The S-box: Boyar and Peralta's circuit, in the variable names of their
/// paper (and of BearSSL's transcription).
#[inline(always)]
fn sbox(q: &mut Planes) {
    let x0 = q[7];
    let x1 = q[6];
    let x2 = q[5];
    let x3 = q[4];
    let x4 = q[3];
    let x5 = q[2];
    let x6 = q[1];
    let x7 = q[0];

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section: inversion in GF(2^8) via GF(2^4).
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation, with the affine constant 0x63.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// `A^-1(x ^ 0x63)`: the inverse of the S-box's affine step. The S-box is
/// `A(inv(x)) ^ 0x63`, so `inv_affine . sbox . inv_affine` is the inverse
/// S-box.
#[inline(always)]
fn inv_affine(q: &mut Planes) {
    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

#[inline(always)]
fn inv_sbox(q: &mut Planes) {
    inv_affine(q);
    sbox(q);
    inv_affine(q);
}

#[inline(always)]
fn swap_bits(q: &mut Planes, low: u64, shift: u32, x: usize, y: usize) {
    let high = !low;
    let a = q[x];
    let b = q[y];
    q[x] = (a & low) | ((b & low) << shift);
    q[y] = ((a & high) >> shift) | (b & high);
}

/// The 8x8 bit transpose between bytes and bit planes. Its own inverse.
#[inline(always)]
fn ortho(q: &mut Planes) {
    for (x, y) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        swap_bits(q, 0x5555_5555_5555_5555, 1, x, y);
    }
    for (x, y) in [(0, 2), (1, 3), (4, 6), (5, 7)] {
        swap_bits(q, 0x3333_3333_3333_3333, 2, x, y);
    }
    for (x, y) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
        swap_bits(q, 0x0F0F_0F0F_0F0F_0F0F, 4, x, y);
    }
}

/// One block's four little-endian words spread over two words so that,
/// with three other blocks and `ortho`, each byte lands in its row and
/// column.
#[inline(always)]
fn interleave_in(w: [u32; 4]) -> (u64, u64) {
    let mut x = w.map(u64::from);
    for v in x.iter_mut() {
        *v |= *v << 16;
        *v &= 0x0000_FFFF_0000_FFFF;
        *v |= *v << 8;
        *v &= 0x00FF_00FF_00FF_00FF;
    }
    (x[0] | (x[2] << 8), x[1] | (x[3] << 8))
}

#[inline(always)]
fn interleave_out(q0: u64, q1: u64) -> [u32; 4] {
    let mut x = [q0 & 0x00FF_00FF_00FF_00FF, q1 & 0x00FF_00FF_00FF_00FF,
                 (q0 >> 8) & 0x00FF_00FF_00FF_00FF, (q1 >> 8) & 0x00FF_00FF_00FF_00FF];
    for v in x.iter_mut() {
        *v |= *v >> 8;
        *v &= 0x0000_FFFF_0000_FFFF;
    }
    x.map(|v| v as u32 | (v >> 16) as u32)
}

/// Row `r + k`, column `c + s` into row `r`, column `c`.
#[inline(always)]
fn rotate(x: u64, k: u32, s: u32) -> u64 {
    if s == 0 {
        return x.rotate_right(16 * k);
    }
    // The columns that do not wrap within their row come from one rotation,
    // the ones that do from a rotation 16 bits shorter.
    let stay = ((1u64 << (16 - 4 * s)) - 1) * 0x0001_0001_0001_0001;
    (x.rotate_right(16 * k + 4 * s) & stay) | (x.rotate_right(16 * k + 4 * s - 16) & !stay)
}

/// MixColumns conjugated by `SR^S`. With `S = 0` it is MixColumns.
///
/// Per column, `2a ^ 3b ^ c ^ d` for rows `a..d` is `2(a^b) ^ b ^ (c^d)`,
/// and `c^d` is `a^b` two rows down; multiplication by 2 moves plane `i`
/// to `i+1` and folds plane 7 into planes 0, 1, 3 and 4.
#[inline(always)]
fn mix_columns<const S: u32>(q: &mut Planes) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let [r0, r1, r2, r3, r4, r5, r6, r7] = q.map(|x| rotate(x, 1, S));
    let s2 = (2 * S) % 4;
    q[0] = q7 ^ r7 ^ r0 ^ rotate(q0 ^ r0, 2, s2);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotate(q1 ^ r1, 2, s2);
    q[2] = q1 ^ r1 ^ r2 ^ rotate(q2 ^ r2, 2, s2);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotate(q3 ^ r3, 2, s2);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotate(q4 ^ r4, 2, s2);
    q[5] = q4 ^ r4 ^ r5 ^ rotate(q5 ^ r5, 2, s2);
    q[6] = q5 ^ r5 ^ r6 ^ rotate(q6 ^ r6, 2, s2);
    q[7] = q6 ^ r6 ^ r7 ^ rotate(q7 ^ r7, 2, s2);
}

/// InvMixColumns conjugated by `SR^S` (multiplication by 0e, 0b, 0d, 09).
#[inline(always)]
fn inv_mix_columns<const S: u32>(q: &mut Planes) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let [r0, r1, r2, r3, r4, r5, r6, r7] = q.map(|x| rotate(x, 1, S));
    let s2 = (2 * S) % 4;
    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ rotate(q0 ^ q5 ^ q6 ^ r0 ^ r5, 2, s2);
    q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ rotate(q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6, 2, s2);
    q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ rotate(q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7, 2, s2);
    q[3] = q0 ^ q1 ^ q2 ^ q5 ^ q6 ^ r0 ^ r2 ^ r3 ^ r5
        ^ rotate(q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7, 2, s2);
    q[4] = q1 ^ q2 ^ q3 ^ q5 ^ r1 ^ r3 ^ r4 ^ r5 ^ r6 ^ r7
        ^ rotate(q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6, 2, s2);
    q[5] = q2 ^ q3 ^ q4 ^ q6 ^ r2 ^ r4 ^ r5 ^ r6 ^ r7
        ^ rotate(q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7, 2, s2);
    q[6] = q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7
        ^ rotate(q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7, 2, s2);
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ rotate(q4 ^ q5 ^ q7 ^ r4 ^ r7, 2, s2);
}

/// ShiftRows: row `r` rotated left by `r` columns.
#[inline(always)]
fn shift_rows(q: &mut Planes) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_0000_0000_FFFF)
            | ((v & 0x0000_0000_FFF0_0000) >> 4)
            | ((v & 0x0000_0000_000F_0000) << 12)
            | ((v & 0x0000_FF00_0000_0000) >> 8)
            | ((v & 0x0000_00FF_0000_0000) << 8)
            | ((v & 0xF000_0000_0000_0000) >> 12)
            | ((v & 0x0FFF_0000_0000_0000) << 4);
    }
}

/// `SR^2`: rows 1 and 3 by two columns, rows 0 and 2 untouched. Its own
/// inverse.
#[inline(always)]
fn shift_rows_2(q: &mut Planes) {
    for x in q.iter_mut() {
        let v = *x;
        *x = (v & 0x0000_FFFF_0000_FFFF)
            | ((v & 0xFF00_0000_FF00_0000) >> 8)
            | ((v & 0x00FF_0000_00FF_0000) << 8);
    }
}

#[inline(always)]
fn add_round_key(q: &mut Planes, key: &Planes) {
    for (x, k) in q.iter_mut().zip(key) {
        *x ^= k;
    }
}

/// Run `$body` on each group's eight words, `$s` bound to them. A macro so
/// the body is inlined into the loop body the vectoriser sees; a closure
/// was outlined and called once per group, which kept it scalar.
macro_rules! each_group {
    ($q:expr, $n:expr, |$s:ident| $body:expr) => {
        for g in 0..$n {
            let q = &mut *$q;
            let mut $s = [q[0][g], q[1][g], q[2][g], q[3][g], q[4][g], q[5][g], q[6][g], q[7][g]];
            {
                let $s = &mut $s;
                $body;
            }
            for k in 0..8 {
                q[k][g] = $s[k];
            }
        }
    };
}

/// `SubWord` on one little-endian word, through the bitsliced S-box so the
/// key schedule does not index a table with key bytes.
pub(crate) fn sub_word(x: u32) -> u32 {
    let mut q = [0u64; 8];
    q[0] = u64::from(x);
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    q[0] as u32
}

/// The expanded key, every round key broadcast to four blocks and
/// pre-permuted for fixslicing.
pub(crate) struct Keys {
    rounds: usize,
    planes: [Planes; 15],
}

impl Keys {
    /// From the FIPS 197 key schedule as little-endian words, `4 * (rounds
    /// + 1)` of them.
    pub(crate) fn new(words: &[u32], rounds: usize) -> Keys {
        let mut planes = [[0u64; 8]; 15];
        for (t, plane) in planes.iter_mut().enumerate().take(rounds + 1) {
            let (a, b) = interleave_in(words[4 * t..4 * t + 4].try_into().unwrap());
            let mut q = [a, a, a, a, b, b, b, b];
            ortho(&mut q);
            // SR^-t, as SR^(4 - t mod 4), for the keys between the first
            // and the last.
            if t != 0 && t != rounds {
                for _ in 0..(4 - t % 4) % 4 {
                    shift_rows(&mut q);
                }
            }
            *plane = q;
        }
        Keys { rounds, planes }
    }

    #[inline(always)]
    fn load<const N: usize>(blocks: &[u8]) -> [[u64; N]; 8] {
        let mut q = [[0u64; N]; 8];
        for (g, group) in blocks.chunks_exact(64).take(N).enumerate() {
            for (i, block) in group.chunks_exact(16).enumerate() {
                let lo = u64::from_le_bytes(block[..8].try_into().unwrap());
                let hi = u64::from_le_bytes(block[8..].try_into().unwrap());
                let (a, b) = interleave_in([lo as u32, (lo >> 32) as u32, hi as u32,
                                            (hi >> 32) as u32]);
                q[i][g] = a;
                q[i + 4][g] = b;
            }
        }
        each_group!(&mut q, N, |s| ortho(s));
        q
    }

    #[inline(always)]
    fn store<const N: usize>(mut q: [[u64; N]; 8], blocks: &mut [u8]) {
        each_group!(&mut q, N, |s| ortho(s));
        for (g, group) in blocks.chunks_exact_mut(64).take(N).enumerate() {
            for (i, block) in group.chunks_exact_mut(16).enumerate() {
                let w = interleave_out(q[i][g], q[i + 4][g]);
                let lo = u64::from(w[0]) | (u64::from(w[1]) << 32);
                let hi = u64::from(w[2]) | (u64::from(w[3]) << 32);
                block[..8].copy_from_slice(&lo.to_le_bytes());
                block[8..].copy_from_slice(&hi.to_le_bytes());
            }
        }
    }

    #[inline(always)]
    fn round<const N: usize, const S: u32>(&self, q: &mut [[u64; N]; 8], t: usize) {
        let key = &self.planes[t];
        each_group!(q, N, |s| {
            sbox(s);
            mix_columns::<S>(s);
            add_round_key(s, key);
        });
    }

    /// Encrypt `4 * N` blocks in place; `blocks` is exactly that long.
    #[inline(always)]
    fn encrypt_n<const N: usize>(&self, blocks: &mut [u8]) {
        let mut q = Self::load::<N>(blocks);
        let first = &self.planes[0];
        each_group!(&mut q, N, |s| add_round_key(s, first));
        // Rounds 1..Nr-1 in the order of their S = t mod 4: 1, 2, 3, 0.
        let mut t = 1;
        loop {
            self.round::<N, 1>(&mut q, t);
            if t + 1 == self.rounds {
                break;
            }
            self.round::<N, 2>(&mut q, t + 1);
            if t + 2 == self.rounds {
                break;
            }
            self.round::<N, 3>(&mut q, t + 2);
            if t + 3 == self.rounds {
                break;
            }
            self.round::<N, 0>(&mut q, t + 3);
            t += 4;
            if t == self.rounds {
                break;
            }
        }
        let last = &self.planes[self.rounds];
        let pending_sr2 = self.rounds % 4 == 2;
        each_group!(&mut q, N, |s| {
            sbox(s);
            if pending_sr2 {
                shift_rows_2(s);
            }
            add_round_key(s, last);
        });
        Self::store(q, blocks);
    }

    #[inline(always)]
    fn decrypt_n<const N: usize>(&self, blocks: &mut [u8]) {
        let mut q = Self::load::<N>(blocks);
        let last = &self.planes[self.rounds];
        let pending_sr2 = self.rounds % 4 == 2;
        each_group!(&mut q, N, |s| {
            add_round_key(s, last);
            if pending_sr2 {
                shift_rows_2(s);
            }
            inv_sbox(s);
        });
        for t in (1..self.rounds).rev() {
            let key = &self.planes[t];
            match t % 4 {
                0 => each_group!(&mut q, N, |s| {
                    add_round_key(s, key);
                    inv_mix_columns::<0>(s);
                    inv_sbox(s);
                }),
                1 => each_group!(&mut q, N, |s| {
                    add_round_key(s, key);
                    inv_mix_columns::<1>(s);
                    inv_sbox(s);
                }),
                2 => each_group!(&mut q, N, |s| {
                    add_round_key(s, key);
                    inv_mix_columns::<2>(s);
                    inv_sbox(s);
                }),
                _ => each_group!(&mut q, N, |s| {
                    add_round_key(s, key);
                    inv_mix_columns::<3>(s);
                    inv_sbox(s);
                }),
            }
        }
        let first = &self.planes[0];
        each_group!(&mut q, N, |s| add_round_key(s, first));
        Self::store(q, blocks);
    }

    /// Encrypt whole blocks in place: sixteen at a time, then four at a
    /// time, the last group zero padded. `blocks.len()` is a multiple of 16.
    pub(crate) fn encrypt(&self, blocks: &mut [u8]) {
        self.batches(blocks, Keys::encrypt_n::<4>, Keys::encrypt_n::<1>);
    }

    pub(crate) fn decrypt(&self, blocks: &mut [u8]) {
        self.batches(blocks, Keys::decrypt_n::<4>, Keys::decrypt_n::<1>);
    }

    #[inline(always)]
    fn batches(&self, blocks: &mut [u8], sixteen: fn(&Keys, &mut [u8]),
               four: fn(&Keys, &mut [u8])) {
        debug_assert!(blocks.len().is_multiple_of(16));
        let mut big = blocks.chunks_exact_mut(256);
        for chunk in &mut big {
            sixteen(self, chunk);
        }
        for chunk in big.into_remainder().chunks_mut(64) {
            if chunk.len() == 64 {
                four(self, chunk);
            } else {
                let mut padded = [0u8; 64];
                padded[..chunk.len()].copy_from_slice(chunk);
                four(self, &mut padded);
                chunk.copy_from_slice(&padded[..chunk.len()]);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The S-box table by its definition: the inverse in GF(2^8) (zero to
    /// zero), then the affine map.
    fn reference_sbox(x: u8) -> u8 {
        fn mul(mut a: u8, mut b: u8) -> u8 {
            let mut p = 0;
            while b != 0 {
                if b & 1 != 0 {
                    p ^= a;
                }
                a = (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 };
                b >>= 1;
            }
            p
        }
        let inverse = (1..=255u8).find(|&y| mul(x, y) == 1).unwrap_or(0);
        inverse ^ inverse.rotate_left(1) ^ inverse.rotate_left(2) ^ inverse.rotate_left(3)
            ^ inverse.rotate_left(4) ^ 0x63
    }

    /// The circuit against the definition for all 256 inputs, through
    /// `sub_word` (which is `ortho`, `sbox`, `ortho`), and the inverse
    /// circuit back.
    #[test]
    fn test_sbox_circuit_is_the_sbox() {
        for x in 0..=255u8 {
            let word = u32::from_le_bytes([x, x.wrapping_add(1), x.wrapping_mul(7), !x]);
            let want = u32::from_le_bytes(word.to_le_bytes().map(reference_sbox));
            assert_eq!(sub_word(word), want, "{x:02x}");

            let mut q = [0u64; 8];
            q[0] = u64::from(want);
            ortho(&mut q);
            inv_sbox(&mut q);
            ortho(&mut q);
            assert_eq!(q[0] as u32, word, "inverse at {x:02x}");
        }
    }

    /// `ortho` is an involution, and `interleave_out` undoes
    /// `interleave_in`.
    #[test]
    fn test_layout_round_trips() {
        let mut q: Planes = core::array::from_fn(|i| 0x0123_4567_89ab_cdefu64.rotate_left(7 * i as u32));
        let before = q;
        ortho(&mut q);
        assert_ne!(q, before);
        ortho(&mut q);
        assert_eq!(q, before);
        let w = [0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c];
        let (a, b) = interleave_in(w);
        assert_eq!(interleave_out(a, b), w);
    }

    /// The conjugated MixColumns are what their definition says:
    /// `SR^-s . MC . SR^s`, built from the plain functions.
    #[test]
    fn test_mix_columns_conjugates() {
        fn inv_shift_rows(q: &mut Planes) {
            for _ in 0..3 {
                shift_rows(q);
            }
        }
        let start: Planes = core::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15u64.rotate_left(11 * i as u32));
        for s in 0..4 {
            let mut want = start;
            for _ in 0..s {
                shift_rows(&mut want);
            }
            mix_columns::<0>(&mut want);
            for _ in 0..s {
                inv_shift_rows(&mut want);
            }
            let mut got = start;
            match s {
                0 => mix_columns::<0>(&mut got),
                1 => mix_columns::<1>(&mut got),
                2 => mix_columns::<2>(&mut got),
                _ => mix_columns::<3>(&mut got),
            }
            assert_eq!(got, want, "s = {s}");
            match s {
                0 => inv_mix_columns::<0>(&mut got),
                1 => inv_mix_columns::<1>(&mut got),
                2 => inv_mix_columns::<2>(&mut got),
                _ => inv_mix_columns::<3>(&mut got),
            }
            assert_eq!(got, start, "inverse, s = {s}");
        }
        let mut twice = start;
        shift_rows(&mut twice);
        shift_rows(&mut twice);
        let mut direct = start;
        shift_rows_2(&mut direct);
        assert_eq!(direct, twice);
    }
}
