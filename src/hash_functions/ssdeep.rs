/*!
Context triggered piecewise hashes: ssdeep, and the CTPH of ctph.js.

## ssdeep

Jesse Kornblum's ssdeep (2006), after Andrew Tridgell's spamsum: a
rolling hash over the last seven bytes cuts the input into pieces
wherever it is `-1` modulo a block size, and each piece contributes one
base64 character, the low six bits of its FNV-1 hash. The digest is
`blocksize:pieces:pieces at twice the block size`, the block size chosen
so that the first string has between 32 and 64 characters where the
input allows. Two inputs that share long runs of bytes share runs of
characters, and `compare` scores the pair from 0 to 100.

This is libfuzzy 2.14.1's streaming form (`fuzzy.c`), which hashes at
every block size at once rather than going over the input again at each
smaller one, and gives the same digest as the classic form, as ppdeep's
multi-pass implementation computes it. The digest is libfuzzy's default:
no sequence elimination and the second string cut to 32 characters.

## CTPH

What CyberChef calls CTPH is ctph.js 0.0.5, a different and simpler
scheme in the same spirit: an FNV-1 hash from `0x28021967`, a rolling
hash without the modular arithmetic, the block size chosen from a
logarithm and written as one base64 digit of its exponent, every piece
emitted with no limit on the string's length, and the input's last
byte always closing a piece. ctph.js computes the FNV product in
JavaScript's doubles, which round it once it passes 2^53, so the six
bits it keeps are those of the rounded product; `ctph` rounds the same
way, and takes the logarithm in doubles as ctph.js does.
*/

const ROLLING_WINDOW: usize = 7;
const MIN_BLOCKSIZE: u32 = 3;
const SPAMSUM_LENGTH: usize = 64;
const NUM_BLOCKHASHES: usize = 31;
/// FNV-1's 32 bit offset basis, `0x28021967`, of which only the low six
/// bits survive into ssdeep's characters.
const HASH_INIT: u8 = 0x27;
const FNV_PRIME: u32 = 0x0100_0193;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// The most input a digest describes: the largest block size times the
/// string length.
const TOTAL_SIZE_MAX: u64 = ((MIN_BLOCKSIZE as u64) << (NUM_BLOCKHASHES - 1)) * SPAMSUM_LENGTH as u64;

/// The rolling hash over the last seven bytes, in 32 bit arithmetic.
#[derive(Clone, Default)]
struct Roll {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl Roll {
    fn update(&mut self, c: u8) {
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add(ROLLING_WINDOW as u32 * u32::from(c));
        self.h1 = self.h1.wrapping_add(u32::from(c)).wrapping_sub(u32::from(self.window[self.n]));
        self.window[self.n] = c;
        self.n = (self.n + 1) % ROLLING_WINDOW;
        self.h3 = (self.h3 << 5) ^ u32::from(c);
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// One step of FNV-1 kept to its low six bits, which depend only on the
/// low six bits of the state.
fn sum_hash(c: u8, h: u8) -> u8 {
    ((u32::from(h).wrapping_mul(FNV_PRIME) ^ u32::from(c)) & 63) as u8
}

#[derive(Clone, Copy)]
struct BlockHash {
    dindex: usize,
    /// The characters so far, written in order over zeros, so the place
    /// after the last is zero - except that a full string's last place
    /// holds the character its last piece would have had.
    digest: [u8; SPAMSUM_LENGTH],
    halfdigest: u8,
    h: u8,
    halfh: u8,
}

const EMPTY: BlockHash = BlockHash { dindex: 0, digest: [0; SPAMSUM_LENGTH], halfdigest: 0,
                                     h: HASH_INIT, halfh: HASH_INIT };

/// An ssdeep digest in progress.
#[derive(Clone)]
pub struct Ssdeep {
    total_size: u64,
    reduce_border: u64,
    bhstart: usize,
    bhend: usize,
    need_lasthash: bool,
    rollmask: u32,
    bh: [BlockHash; NUM_BLOCKHASHES],
    roll: Roll,
    lasth: u8,
}

impl Default for Ssdeep {
    fn default() -> Self {
        Ssdeep::new()
    }
}

impl Ssdeep {
    pub fn new() -> Ssdeep {
        Ssdeep {
            total_size: 0,
            reduce_border: u64::from(MIN_BLOCKSIZE) * SPAMSUM_LENGTH as u64,
            bhstart: 0,
            bhend: 1,
            need_lasthash: false,
            rollmask: 0,
            bh: [EMPTY; NUM_BLOCKHASHES],
            roll: Roll::default(),
            lasth: 0,
        }
    }

    /// The block size the `index`th string runs at: 3, 6, 12 and so on.
    fn block_size(index: usize) -> u64 {
        u64::from(MIN_BLOCKSIZE) << index
    }

    /// Start the next block size off where the last one is, the first
    /// time the last one emits a character.
    fn try_fork(&mut self) {
        let last = self.bh[self.bhend - 1];
        if self.bhend < NUM_BLOCKHASHES {
            self.bh[self.bhend] = BlockHash { h: last.h, halfh: last.halfh, ..EMPTY };
            self.bhend += 1;
        } else if !self.need_lasthash {
            self.need_lasthash = true;
            self.lasth = last.h;
        }
    }

    /// Stop hashing at the smallest block size once the input is too long
    /// for it to be the one the digest uses.
    fn try_reduce(&mut self) {
        if self.bhend - self.bhstart < 2 || self.reduce_border >= self.total_size
            || self.bh[self.bhstart + 1].dindex < SPAMSUM_LENGTH / 2 {
            return;
        }
        self.bhstart += 1;
        self.reduce_border *= 2;
        self.rollmask = self.rollmask * 2 + 1;
    }

    fn step(&mut self, c: u8) {
        self.roll.update(c);
        let horg = self.roll.sum().wrapping_add(1);
        let mut h = horg / MIN_BLOCKSIZE;
        for bh in &mut self.bh[self.bhstart..self.bhend] {
            bh.h = sum_hash(c, bh.h);
            bh.halfh = sum_hash(c, bh.halfh);
        }
        if self.need_lasthash {
            self.lasth = sum_hash(c, self.lasth);
        }
        // A piece ends where the rolling hash is -1 modulo the block size,
        // that is where horg is 0 modulo it - except at horg = 0 itself,
        // since 2^32 is not a multiple of 3.
        if horg == 0 || h & self.rollmask != 0 || !horg.is_multiple_of(MIN_BLOCKSIZE) {
            return;
        }
        h >>= self.bhstart;
        let mut i = self.bhstart;
        loop {
            if self.bh[i].dindex == 0 {
                self.try_fork();
            }
            let bh = &mut self.bh[i];
            bh.digest[bh.dindex] = B64[usize::from(bh.h)];
            bh.halfdigest = B64[usize::from(bh.halfh)];
            if bh.dindex < SPAMSUM_LENGTH - 1 {
                // A full string keeps hashing into its last character,
                // so the input's tail is one piece.
                bh.dindex += 1;
                bh.h = HASH_INIT;
                if bh.dindex < SPAMSUM_LENGTH / 2 {
                    bh.halfh = HASH_INIT;
                    bh.halfdigest = 0;
                }
            } else {
                self.try_reduce();
            }
            if h & 1 != 0 {
                break;
            }
            h >>= 1;
            i += 1;
            if i >= self.bhend {
                break;
            }
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_size = self.total_size.saturating_add(data.len() as u64);
        for &c in data {
            self.step(c);
        }
    }

    /// The digest of everything so far, `blocksize:string:string`. The
    /// state is untouched, so more can follow.
    ///
    /// # Errors
    /// More input than the largest block size describes, about 206 GB.
    pub fn digest(&self) -> Result<String, String> {
        if self.total_size > TOTAL_SIZE_MAX {
            return Err(format!("ssdeep describes at most {TOTAL_SIZE_MAX} bytes."));
        }
        let h = self.roll.sum();
        // The first guess from the length, then down to the largest
        // block size whose string is at least half full.
        let mut bi = self.bhstart;
        while Ssdeep::block_size(bi) * (SPAMSUM_LENGTH as u64) < self.total_size {
            bi += 1;
        }
        bi = bi.min(self.bhend - 1);
        while bi > self.bhstart && self.bh[bi].dindex < SPAMSUM_LENGTH / 2 {
            bi -= 1;
        }
        let mut out = format!("{}:", Ssdeep::block_size(bi)).into_bytes();
        let bh = &self.bh[bi];
        out.extend_from_slice(&bh.digest[..bh.dindex]);
        if h != 0 {
            out.push(B64[usize::from(bh.h)]);
        } else if bh.digest[bh.dindex] != 0 {
            out.push(bh.digest[bh.dindex]);
        }
        out.push(b':');
        if bi < self.bhend - 1 {
            let bh = &self.bh[bi + 1];
            out.extend_from_slice(&bh.digest[..bh.dindex.min(SPAMSUM_LENGTH / 2 - 1)]);
            if h != 0 {
                out.push(B64[usize::from(bh.halfh)]);
            } else if bh.halfdigest != 0 {
                out.push(bh.halfdigest);
            }
        } else if h != 0 {
            out.push(B64[usize::from(if bi == 0 { bh.h } else { self.lasth })]);
        }
        Ok(String::from_utf8(out).expect("base64 and digits"))
    }
}

/// The ssdeep digest of `data`.
pub fn ssdeep(data: &[u8]) -> Result<String, String> {
    let mut state = Ssdeep::new();
    state.update(data);
    state.digest()
}

/// Copy a digest string, dropping each character that repeats the three
/// before it: such runs carry little information and would bias a score.
/// `None` for a string longer than a digest's.
fn eliminate_sequences(part: &[u8]) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(SPAMSUM_LENGTH);
    let mut run = 0;
    for (i, &c) in part.iter().enumerate() {
        if i > 0 && c == part[i - 1] {
            run += 1;
            if run >= 3 {
                continue;
            }
        } else {
            run = 0;
        }
        if out.len() == SPAMSUM_LENGTH {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

/// Whether two strings share a run of seven characters.
fn has_common_substring(a: &[u8], b: &[u8]) -> bool {
    a.len() >= ROLLING_WINDOW && b.len() >= ROLLING_WINDOW
        && a.windows(ROLLING_WINDOW).any(|w| b.windows(ROLLING_WINDOW).any(|v| v == w))
}

/// The edit distance with insertions and deletions costing one and a
/// substitution two.
fn edit_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut row: Vec<u32> = (0..=b.len() as u32).collect();
    for (i, &x) in a.iter().enumerate() {
        let mut next = vec![i as u32 + 1];
        for (j, &y) in b.iter().enumerate() {
            let cost = (row[j + 1] + 1).min(next[j] + 1).min(row[j] + if x == y { 0 } else { 2 });
            next.push(cost);
        }
        row = next;
    }
    row[b.len()]
}

fn score_strings(a: &[u8], b: &[u8], block_size: u64) -> u32 {
    if !has_common_substring(a, b) {
        return 0;
    }
    let lengths = (a.len() + b.len()) as u32;
    let mut score = edit_distance(a, b) * SPAMSUM_LENGTH as u32 / lengths;
    score = 100 * score / SPAMSUM_LENGTH as u32;
    score = 100 - score;
    // A small block size does not get to claim a large match.
    if block_size >= u64::from((99 + ROLLING_WINDOW as u32) / ROLLING_WINDOW as u32 * MIN_BLOCKSIZE) {
        return score;
    }
    let cap = block_size / u64::from(MIN_BLOCKSIZE) * a.len().min(b.len()) as u64;
    score.min(u32::try_from(cap).unwrap_or(u32::MAX))
}

/// A digest's block size: the decimal number before its first colon,
/// digits alone - where libfuzzy's `sscanf` also takes leading spaces and
/// a sign, which no digest has.
fn parse_size(digest: &str) -> Result<u64, String> {
    let size = digest.split_once(':').map(|(size, _)| size).unwrap_or("");
    if size.is_empty() || !size.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("{digest:?} is not an ssdeep digest."));
    }
    size.parse().map_err(|_| format!("{digest:?} is not an ssdeep digest."))
}

/// A digest's two strings, read as libfuzzy reads them: after the block
/// size, the first up to a colon and the second up to the end or a comma
/// (a file name follows one), runs of more than three repeated characters
/// cut to three.
fn parse_strings(digest: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let malformed = || format!("{digest:?} is not an ssdeep digest.");
    let rest = digest.split_once(':').ok_or_else(malformed)?.1;
    let (first, second) = rest.split_once(':').ok_or_else(malformed)?;
    let second = second.split(',').next().unwrap_or("");
    Ok((eliminate_sequences(first.as_bytes()).ok_or_else(malformed)?,
        eliminate_sequences(second.as_bytes()).ok_or_else(malformed)?))
}

/// How alike two ssdeep digests say their inputs are, 0 to 100: 0 for
/// digests at block sizes that cannot be compared, which libfuzzy decides
/// before reading the strings, and 100 for equal ones.
///
/// # Errors
/// A digest that is not one.
pub fn compare(a: &str, b: &str) -> Result<u32, String> {
    let (size_a, size_b) = (parse_size(a)?, parse_size(b)?);
    let doubled = size_a.checked_mul(2);
    let halved = size_a.is_multiple_of(2).then_some(size_a / 2);
    if size_a != size_b && doubled != Some(size_b) && halved != Some(size_b) {
        return Ok(0);
    }
    let (a1, a2) = parse_strings(a)?;
    let (b1, b2) = parse_strings(b)?;
    if size_a == size_b && a1 == b1 && a2 == b2 {
        return Ok(100);
    }
    Ok(match doubled {
        // The second strings are at twice the block size, when there is
        // such a number.
        Some(double) if size_a == size_b =>
            score_strings(&a1, &b1, size_a).max(score_strings(&a2, &b2, double)),
        None if size_a == size_b => score_strings(&a1, &b1, size_a),
        Some(double) if double == size_b => score_strings(&b1, &a2, size_b),
        _ => score_strings(&a1, &b2, size_a),
    })
}

// ------------------------------------------------------------------- CTPH ---

/// ctph.js's FNV-1 step, in doubles: the product is rounded to 53 bits
/// before JavaScript's `^` reduces it modulo 2^32.
fn ctph_fnv(base: u32, c: u8) -> u32 {
    let product = f64::from(base) * f64::from(FNV_PRIME);
    (product as u64 as u32) ^ u32::from(c)
}

/// ctph.js's rolling hash: the same three sums as ssdeep's, the first
/// two in exact integers.
#[derive(Default)]
struct CtphRoll {
    x: i64,
    y: i64,
    z: u32,
    c: usize,
    window: [u8; ROLLING_WINDOW],
}

impl CtphRoll {
    fn update(&mut self, d: u8) {
        self.y -= self.x;
        self.y += 7 * i64::from(d);
        self.x += i64::from(d);
        self.x -= i64::from(self.window[self.c % ROLLING_WINDOW]);
        self.window[self.c % ROLLING_WINDOW] = d;
        self.c += 1;
        self.z = (self.z << 5) ^ u32::from(d);
    }

    fn sum(&self) -> u64 {
        (self.x + self.y + i64::from(self.z)).rem_euclid(1 << 32) as u64
    }
}

fn ctph_pieces(data: &[u8], trigger: u64) -> (String, String) {
    const INIT: u32 = 0x2802_1967;
    let (mut first, mut second) = (String::new(), String::new());
    let (mut h1, mut h2) = (INIT, INIT);
    let mut roll = CtphRoll::default();
    for (i, &c) in data.iter().enumerate() {
        h1 = ctph_fnv(h1, c);
        h2 = ctph_fnv(h2, c);
        roll.update(c);
        let last = i == data.len() - 1;
        if last || roll.sum() % trigger == trigger - 1 {
            first.push(char::from(B64[(h1 & 63) as usize]));
            h1 = INIT;
        }
        if last || roll.sum() % (2 * trigger) == 2 * trigger - 1 {
            second.push(char::from(B64[(h2 & 63) as usize]));
            h2 = INIT;
        }
    }
    (first, second)
}

/// The CTPH digest ctph.js 0.0.5 gives `data`, and CyberChef with it:
/// `exponent:string:string`, the exponent one base64 digit.
///
/// # Errors
/// Input of 192 · 2^29 bytes or more, where ctph.js's 32 bit block size
/// overflows.
pub fn ctph(data: &[u8]) -> Result<String, String> {
    // As ctph.js computes it: in doubles, with JavaScript's ceiling, and
    // three at the least - which is what the empty input gets, where
    // the logarithm is minus infinity.
    let estimate = ((data.len() as f64 / 192.0).ln() / 2f64.ln()).ceil();
    let mut bi = if estimate > 3.0 { estimate as u32 } else { 3 };
    if bi >= 30 {
        return Err("ctph.js's block size overflows 32 bits on input this long.".to_string());
    }
    let mut pieces = ctph_pieces(data, 3 << bi);
    while bi > 0 && pieces.0.len() < 32 {
        bi -= 1;
        pieces = ctph_pieces(data, 3 << bi);
    }
    Ok(format!("{}:{}:{}", char::from(B64[bi as usize]), pieces.0, pieces.1))
}

/// ctph.js's `similarity`: 100 times one less the Levenshtein distance
/// over the longer length, between the strings the two digests share - the
/// first strings at the same exponent, the smaller exponent's second and
/// the larger's first at adjacent ones - or 0 for exponents further apart.
/// In ctph.js's arithmetic, so NaN when both strings compared are empty.
/// Strings are compared in UTF-16 code units, as JavaScript's are.
///
/// # Errors
/// A digest without the string to compare, where ctph.js throws.
pub fn ctph_similarity(a: &str, b: &str) -> Result<f64, String> {
    // `B64.indexOf(d.charAt(0))`: -1 for a character that is not a digit,
    // and 0 for an empty digest, whose `charAt(0)` is the empty string.
    let index = |d: &str| match d.encode_utf16().next() {
        None => 0,
        Some(c) => B64.iter().position(|&x| u16::from(x) == c).map_or(-1, |i| i as i64),
    };
    let (a, b) = if index(a) > index(b) { (b, a) } else { (a, b) };
    let part = |d: &str, n: usize| d.split(':').nth(n).map(|p| p.encode_utf16().collect::<Vec<_>>())
        .ok_or_else(|| format!("{d:?} has no string {n} to compare."));
    let (ia, ib) = (index(a), index(b));
    let (s, t) = if (ia - ib).abs() > 1 {
        return Ok(0.0);
    } else if ia == ib {
        (part(a, 1)?, part(b, 1)?)
    } else {
        (part(a, 2)?, part(b, 1)?)
    };
    let distance = if s == t {
        0
    } else if s.is_empty() || t.is_empty() {
        s.len().max(t.len())
    } else {
        let mut row: Vec<usize> = (0..=t.len()).collect();
        for (i, x) in s.iter().enumerate() {
            let mut next = vec![i + 1];
            for (j, y) in t.iter().enumerate() {
                next.push((row[j] + usize::from(x != y)).min(next[j] + 1).min(row[j + 1] + 1));
            }
            row = next;
        }
        row[t.len()]
    };
    Ok((1.0 - distance as f64 / s.len().max(t.len()) as f64) * 100.0)
}
