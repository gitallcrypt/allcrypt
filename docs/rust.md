# Using allcrypt from Rust

Everything returns `Result<_, String>` where it can fail. Nothing panics on
bad input; a mode that is not implemented returns an error rather than
quietly producing no output.

## Hashing

Every hash implements `HashFunction`: `update`, `digest`, `digest_len`,
`name`. Pass the whole message to the constructor, or build it up with
`update`.

```rust
use allcrypt::hash_functions::{sha2, HashFunction};

let mut hash = sha2::SHA256::new(b"abc");
assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(),
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
```

`digest()` does not consume the hash, and you can keep feeding it afterwards:

```rust
use allcrypt::hash_functions::{sha2, HashFunction};

let mut hash = sha2::SHA256::new(&[]);
hash.update(b"hello ");
let _intermediate = hash.digest();
hash.update(b"world");

let mut direct = sha2::SHA256::new(b"hello world");
assert_eq!(hash.digest(), direct.digest());
```

SHA-512 takes an output length, which is how SHA-512/224 and SHA-512/256 are
spelled. SHA-0 is SHA-1 with the message schedule rotation removed:

```rust
use allcrypt::hash_functions::{sha1, sha2, HashFunction};

let mut truncated = sha2::SHA512::new(b"abc", 256);   // SHA-512/256
assert_eq!(truncated.digest().len(), 32);

let mut sha0 = sha1::SHA1::new(&[]);
sha0.set_to_sha0();
sha0.update(b"abc");
assert_eq!(allcrypt::to_hex(&sha0.digest()).to_lowercase(),
           "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
```

SM3 is the Chinese national hash, GB/T 32905-2016. It shares SHA-256's
output length, block size and padding and is a different function
throughout; it is the hash SM2 is defined against, and the one RFC 8998's
TLS 1.3 suites use.

```rust
use allcrypt::hash_functions::{sm3, HashFunction};

let mut hash = sm3::Sm3::new(b"abc");
assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(),
           "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
```

Whirlpool (ISO/IEC 10118-3) is a 512 bit hash built as
Miyaguchi-Preneel over a block cipher that is AES's shape scaled up to
an 8x8 byte matrix. Unlike MD2 and MD4 it is not broken; it is here
because **TrueCrypt and VeraCrypt derive their header keys with
PBKDF2-HMAC-Whirlpool**, so a volume made with that option cannot be
opened without it, and because `hashlib` has never had it.

```rust
use allcrypt::hash_functions::{whirlpool, HashFunction};

let mut hash = whirlpool::Whirlpool::new(b"abc");
assert_eq!(hash.digest_len(), 64);
assert!(allcrypt::to_hex(&hash.digest()).to_lowercase()
        .starts_with("4e2448a4c6f486bb"));
```

Its 256-byte S-box is **generated** from two 16-entry mini boxes rather
than tabulated, which is how the specification states it - so the only
constants typed in that file are 32 nibbles, and the round constants and
the circulant matrix's multiples are computed from them. Two things
about it catch people out: the padding carries a **256 bit** length
field, not 64, and its field is GF(2^8) modulo **0x11d**, not AES's
0x11b. Both give a self-consistent hash when wrong.

OpenSSL 3 moved Whirlpool to its `legacy` provider, which is where
`scripts/diff_check.py` finds the reference it checks against. That the
reference is one release from disappearing is the reason this was
implemented now rather than later.

MD2 and MD4 are here for what still speaks them, not for what they
protect. Both are thoroughly broken - MD4 collides by hand in under a
minute - and both are unavoidable in places nobody gets to upgrade:

- **MD2** signs old root certificates, as `md2WithRSAEncryption`. A
  relying party that cannot compute it cannot verify them.
- **MD4** is the NT hash, `MD4(UTF-16LE(password))`, so it is NTLM,
  NTLMv2, CHAP and MS-CHAPv2. It is also `rsync`'s pre-3.0 checksum and
  the root of the MD5/RIPEMD/SHA family.

```rust
use allcrypt::hash_functions::{md2, md4, HashFunction};

let mut hash = md2::Md2::new(b"abc");
assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(),
           "da853b0d3f88d99b30283a69e6ded6bb");

// The NT hash of "password", which is what a Windows box stores.
let utf16le: Vec<u8> = "password".encode_utf16()
    .flat_map(|unit| unit.to_le_bytes())
    .collect();
let mut hash = md4::Md4::new(&utf16le);
assert_eq!(allcrypt::to_hex(&hash.digest()).to_lowercase(),
           "8846f7eaee8fb117ad06bdd830b7586c");
```

MD2 is unlike everything else in this module: sixteen-byte blocks, no
32-bit words anywhere, no length field at all, and a checksum appended
to the message and then hashed with it. Its `block_size()` is therefore
**16**, not 64 - which matters if you are sizing a buffer from it.

RFC 1319's prose and RFC 1319's own reference code disagree about the
checksum step, and the document's vectors follow the code. See
`md2::CHECKSUM_DISAGREEMENT` and `docs/pitfalls.md`.

`hash_functions::hash_all(data)` returns a map of every hash of one input,
which is handy when you do not know which one you want yet.

## SM2

GB/T 32918: the Chinese national signature and public key encryption,
over one curve. It is **not** ECDSA with different constants - the
signing equation differs, and the value signed is `SM3(Z_A || M)` where
`Z_A` folds the signer's identity and the whole curve into the hash
before the message is seen. So there is no digest to pass in; the
functions take the message.

```rust
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, sm2};

let curve = curves::sm2();
let private = BigUint::from_hex(
    "128b2fa8bd433c6c068c8d803dff79792a519a55171b1b650c23661d15897263")?;
let public = curve.generator_mul(&private);

// The identity defaults to GB/T 32918.2's `1234567812345678`.
let signature = sm2::sign(&curve, &private, sm2::DEFAULT_ID, b"message digest")?;
assert!(sm2::verify(&curve, &public, sm2::DEFAULT_ID, b"message digest",
                    &signature)?);

// A different identity is a different signature, and verifying under
// the wrong one is indistinguishable from a forgery.
assert!(!sm2::verify(&curve, &public, b"someone else", b"message digest",
                     &signature)?);
```

Encryption returns `C1 || C3 || C2` - the 2012 ordering. `ciphertext_to_der`
converts to the `SEQUENCE { x1, y1, C3, C2 }` OpenSSL exchanges.

```rust
use allcrypt::bignum::BigUint;
use allcrypt::ec::{curves, sm2};

let curve = curves::sm2();
let private = BigUint::from_hex(
    "1649ab77a00637bd5e2efe283fbf353534aa7f7cb89463f208ddbc2920bb0da0")?;
let public = curve.generator_mul(&private);

let ciphertext = sm2::encrypt(&curve, &public, b"sixteen byte msg")?;
assert_eq!(ciphertext.len(), 65 + 32 + 16);
assert_eq!(sm2::decrypt(&curve, &private, &ciphertext)?, b"sixteen byte msg");

let der = sm2::ciphertext_to_der(&curve, &ciphertext)?;
assert_eq!(sm2::ciphertext_from_der(&curve, &der)?, ciphertext);
```

**Signing is deterministic here and random in the standard.** GB/T
32918.2 says `k` is a random number; this library derives it through RFC
6979 with SM3, so nothing reaches the random source and a repeated nonce
- which gives away the private key in one step, exactly as in ECDSA - is
impossible rather than unlikely. Both are valid SM2 and verify
everywhere; a signature from here will not equal one from a Chinese
implementation given the same inputs, and does not have to.

## Block ciphers, one shot

Construct a cipher, then call the mode you want. ECB and CBC require the
input to be a whole number of blocks; CFB, OFB and CTR accept any length.

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::BlockCipher;

let key = vec![0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
let iv = vec![0u8; 16];
let plaintext = b"sixteen byte blk";

let mut cipher = AesCrypto::new(key.clone())?;
let mut ciphertext = vec![];
cipher.cbc_encrypt(plaintext, &mut ciphertext, iv.clone())?;

let mut recovered = vec![];
AesCrypto::new(key)?.cbc_decrypt(&ciphertext, &mut recovered, iv)?;
assert_eq!(recovered, plaintext);
```

The output buffer is appended to, never cleared, so you can build up a result
across several calls without the modes trampling what is already there.

Available ciphers: `aes::AesCrypto` (16, 24 or 32 byte keys),
`blowfish::Blowfish` (1..=56 bytes), `blowfish::BlowfishLe` (the same
cipher reading its block as little-endian words, as TrueCrypt does; named
`blowfish-le` in the facade), `des::Des` (8 bytes),
`des::TripleDes` (8, 16 or 24), `gost::GostCrypto` (32 bytes plus an
S-box parameter set name). Available modes: `ecb`, `cbc`, `pcbc`, `cfb`, `ofb`,
`ctr`, `ctr_le` (the whole block one little-endian counter, WinZip's) and
`cbc_cs` (CBC with ciphertext stealing, in `CtsVariant::Cs1`, `Cs2` or `Cs3`):

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{BlockCipher, CtsVariant};

let mut aes = AesCrypto::new(vec![0u8; 16])?;
let mut ct = vec![];
aes.cbc_cs_encrypt(b"seventeen bytes!!", &mut ct, &[0u8; 16], CtsVariant::Cs3)?;
assert_eq!(ct.len(), 17);
let mut back = vec![];
aes.cbc_cs_decrypt(&ct, &mut back, &[0u8; 16], CtsVariant::Cs3)?;
assert_eq!(back, b"seventeen bytes!!");
```

`mac::cbc_mac` is the CBC-MAC of whole blocks, or after zero padding;
it is forgeable over messages of varying length, which CMAC fixes.

### The ones other libraries are retiring

Twofish and Serpent are here too - the two AES finalists people kept
using - and like everything else they implement three methods and get
all five modes, plus XTS and key wrap:

```rust
use allcrypt::block_ciphers::serpent::Serpent;
use allcrypt::block_ciphers::BlockCipher;

let mut cipher = Serpent::new(vec![0x42; 32])?;
let mut ciphertext = vec![];
cipher.cbc_encrypt(b"sixteen byte blk", &mut ciphertext, vec![0u8; 16])?;
assert_eq!(ciphertext.len(), 16);

let mut back = vec![];
cipher.cbc_decrypt(&ciphertext, &mut back, vec![0u8; 16])?;
assert_eq!(&back, b"sixteen byte blk");
```

**Nothing on this machine implements either**, so the reference is
Botan's vector files, vendored in `vectors/` and read at compile time -
723 Twofish cases and 1047 Serpent, across all three key sizes.

CAST5, IDEA, SEED, Camellia and SM4 are all here and all take the same
interface as AES — they implement the block function and inherit every
mode. Three of the five now live in `python-cryptography`'s
`hazmat.decrepit`, which is a module named after what is expected to
happen to them; they were implemented here while a reference still
existed to check them against. `docs/pitfalls.md` has the reasoning and
the traps in each.

Two are worth knowing about before use:

- **CAST5 takes 1 to 16 bytes**, zero padded, and a key of 10 bytes or
  fewer uses twelve rounds rather than sixteen. That makes a short key a
  *different cipher*, not a weaker setting of the same one.
- **Camellia takes 16, 24 or 32 bytes**, with 18 rounds for the first
  and 24 for the others.

### ARIA

ARIA (RFC 5794, KS X 1213) is the Korean national block cipher: AES's
block and key sizes, AES's S-box as one of its four, and neither AES's
diffusion nor AES's key schedule. Its diffusion layer is a 16x16 binary
matrix that is **its own inverse**, which is what lets the decryption
round keys be derived from the encryption ones rather than from a second
schedule. RFC 6209 defines TLS cipher suites for it.

```rust
use allcrypt::block_ciphers::aria::Aria;
use allcrypt::block_ciphers::BlockCipher;

// RFC 5794 Appendix A.1.
let key: Vec<u8> = (0..16u8).collect();
let mut cipher = Aria::new(&key)?;
let mut out = Vec::new();
cipher.block_encrypt(
    &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], &mut out);
assert_eq!(allcrypt::to_hex(&out).to_lowercase(),
           "d718fbd6ab644c739da95f3be6451778");
```

Nothing about ARIA is typed in this crate. The four S-box tables (1024
bytes), the sixteen diffusion equations (112 term indices) and the three
key-schedule constants are all parsed out of `rfcs/rfc5794.txt` at
**compile time**, and the four properties the RFC states about them —
SB3 inverts SB1, SB4 inverts SB2, the diffusion layer is an involution,
and `SB1(0x23) = 0x26` — are each a test. `SB1` is also compared against
AES's S-box built from its algebraic definition, so a table read from
one document is checked against a construction that shares nothing with
it.

RFC 5794's appendix is unusually generous: for the 128 bit key it gives
every round key and every intermediate round value, so the key schedule
and each individual round are tested separately and a failure names the
round.

### TEA and XTEA, and their round count

TEA is eleven lines of C, which is why it is in set-top boxes, smart
cards, the original Xbox's boot ROM, sensor firmware and a great deal of
1990s protocol obfuscation. XTEA is the same block, key and shape with a
different key schedule. Both take a 16 byte key and an 8 byte block and
inherit every mode.

```rust
use allcrypt::block_ciphers::tea::{Tea, Xtea};
use allcrypt::block_ciphers::BlockCipher;

let key = vec![0u8; 16];
let mut cipher = Tea::new(&key)?;
let mut out = Vec::new();
cipher.block_encrypt(&[0u8; 8], &mut out);
assert_eq!(allcrypt::to_hex(&out).to_lowercase(), "41ea3a0a94baa940");

// XTEA is a different cipher, not a setting of the same one.
let mut xtea = Xtea::new(&key)?;
let mut other = Vec::new();
xtea.block_encrypt(&[0u8; 8], &mut other);
assert_ne!(out, other);
```

**TEA has equivalent keys.** Flipping the top bit of `k[0]` and of
`k[1]` together gives a key that encrypts identically, and the same for
`k[2]` and `k[3]` - so every key has three others equivalent to it and
the effective length is 126 bits. Where TEA is used to build a hash that
is a practical break, and it is what broke the Xbox. XTEA exists to
remove it. `test_teas_equivalent_keys` asserts the property rather than
describing it, and `test_xtea_has_no_such_equivalent_keys` asserts that
XTEA does not inherit it.

Both take a **round count**, where one round is what the papers call a
cycle - two Feistel half-rounds, one per word. The published cipher is
32 of them, which is what `new` gives; `with_rounds` is there because
the published vectors sweep it from 1 to 64 and because firmware in the
wild ships reduced-round builds. Zero is refused rather than silently
being the identity function.

```rust
use allcrypt::block_ciphers::tea::Xtea;
use allcrypt::block_ciphers::BlockCipher;

let mut one_cycle = Xtea::with_rounds(&[0u8; 16], 1)?;
let mut out = Vec::new();
one_cycle.block_encrypt(&[0u8; 8], &mut out);
// One cycle on a zero block and a zero key leaves delta in the second
// word, which is where the published vector chain starts.
assert_eq!(allcrypt::to_hex(&out).to_lowercase(), "000000009e3779b9");
```

XXTEA - "Corrected Block TEA" - is deliberately absent. It is not a
64 bit block cipher: it works on a whole message of two or more words
at once, so it has no place in `BlockCipher` and would inherit chaining
modes it cannot use.

### RC5, and a round count that means something different

RC5 (RFC 2040) is written RC5-w/r/b: word size, rounds, key bytes. The
block is two words, so RC5-32/12/16 — the nominal cipher, and what
"RC5" means anywhere it was deployed — is a 64 bit block, twelve rounds
and a 128 bit key. **Only w = 32 is implemented**, because RFC 2040
profiles only that and no published vectors exist for the other two;
an unverified variant is worse than an absent one.

It was patented until 2015, which is why it is missing from software
that is otherwise complete — and why traces and files encrypted with it
are still around with nothing left to read them.

```rust
use allcrypt::block_ciphers::rc5::Rc5;
use allcrypt::block_ciphers::BlockCipher;

// RFC 2040's first vector: zero rounds, a one byte key, a zero block.
let mut cipher = Rc5::with_rounds(&[0u8], 0)?;
let mut out = Vec::new();
cipher.block_encrypt(&[0u8; 8], &mut out);
assert_eq!(allcrypt::to_hex(&out).to_lowercase(), "7a7bba4d79111d1e");

// The nominal cipher, with the key length taken from the key.
let mut nominal = Rc5::new(b"sixteen byte key")?;
assert_eq!(nominal.rounds(), 12);
```

**Zero rounds is a legal RC5 and not the identity**, which is the
opposite of TEA above. The two words are still summed with `S[0]` and
`S[1]` before the round loop, so the result is a key-dependent
transformation — RFC 2040 publishes vectors for it, which is why the
constructor allows it where TEA's refuses. It is of course trivially
broken: with no rounds the cipher is an addition.

**An empty key is refused.** RFC 2040's own reference code divides by
the number of key words, which is zero, so there is no interoperable
answer to agree with; Rivest's paper patches around it and the RFC does
not.

The rotation amount is **data dependent** — `A <<< B` rotates by the low
five bits of the other half — which is where RC5's strength comes from
and why it cannot be made constant time without a rewrite. No attempt is
made; see `docs/pitfalls.md`.

### RC2, and the parameter that weakens a key on purpose

RC2 (RFC 2268) has an `effective_bits` parameter whose entire function is
to make the key *weaker* than the key you supplied — so that 1990s export
paperwork could say forty bits while the wire format stayed the same. It
changes the key schedule, not a length check.

```rust
use allcrypt::block_ciphers::rc2::RC2;
use allcrypt::block_ciphers::BlockCipher;

let key = vec![0x5a; 16];

// The ordinary meaning of "RC2 with this key", which is what every other
// library's plain constructor does: effective_bits = 8 * key length.
let mut ordinary = RC2::new(&key)?;

// TLS's RC2_CBC_40: the same sixteen bytes, forty bits of entropy.
let mut weakened = RC2::with_effective_bits(&key, 40)?;

let mut a = Vec::new();
let mut b = Vec::new();
ordinary.block_encrypt(&[0u8; 8], &mut a);
weakened.block_encrypt(&[0u8; 8], &mut b);
assert_ne!(a, b);      // a different cipher, not a shorter key
```

Through the `api` facade the parameter travels in the same slot GOST's
S-box set uses: `AnyBlockCipher::new("rc2", &key, Some("40"))`.

## Block ciphers, streaming

The one-shot calls above are thin wrappers over mode objects that borrow the
cipher and hold the mode's state. Use those directly when the data arrives in
pieces, or when you want to transform a buffer in place.

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{BlockCipher, Ctr};

let key = vec![0u8; 16];
let nonce = vec![0u8; 16];

let mut cipher = AesCrypto::new(key)?;
let mut stream = Ctr::new(&mut cipher, &nonce)?;

let mut out = vec![];
stream.update(b"first piece ", &mut out)?;
stream.update(b"second piece", &mut out)?;
```

Feeding a stream in pieces gives byte-identical output to one call, whatever
the split points. `apply` is the same transform with no copying at all:

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{BlockCipher, Ctr};

let key = vec![0u8; 16];
let nonce = vec![0u8; 16];
let mut buffer = b"transformed in place".to_vec();

let mut cipher = AesCrypto::new(key)?;
Ctr::new(&mut cipher, &nonce)?.apply(&mut buffer)?;
```

`BlockCipher::ctr(&iv)` is shorthand for `Ctr::new(self, &iv)`.

The four mode objects are `Ctr`, `Ofb`, `Cfb` and `Cbc`. `Ctr` and `Ofb` are
symmetric, so they have a single `new`. `Cfb` and `Cbc` need a direction, so
they have `encryptor` and `decryptor`:

```rust
use allcrypt::block_ciphers::blowfish::Blowfish;
use allcrypt::block_ciphers::{BlockCipher, Cbc};

let iv = vec![0u8; 8];
let mut cipher = Blowfish::new(vec![1, 2, 3, 4, 5, 6, 7, 8]);
let mut out = vec![];
{
    let mut stream = Cbc::encryptor(&mut cipher, &iv)?;
    stream.update(&[0u8; 8], &mut out)?;
    stream.update(&[0u8; 8], &mut out)?;
    stream.finish()?;        // errors if a partial block is left over
}
assert_eq!(out.len(), 16);
```

CBC is the one mode that is not a byte stream: `update` emits whole blocks
and buffers the remainder, so `finish()` is what tells you the input ended
mid-block.

## Authenticated encryption

AES-GCM, following the same split as the other modes: a `GcmState` that owns
the state and takes the cipher per call, and a `Gcm` wrapper that pairs
them. The difference is that it authenticates, so it has a tag and
decryption can fail.

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::{BlockCipher, Gcm};

let key = vec![0x2b; 16];
let nonce = [0x11u8; 12];
let aad = b"headers in the clear";

let mut cipher = AesCrypto::new(key.clone())?;
let mut gcm = Gcm::encryptor(&mut cipher, &nonce, aad)?;
let mut sealed = Vec::new();
gcm.update(b"the payload", &mut sealed)?;
let tag = gcm.tag()?;

let mut cipher = AesCrypto::new(key)?;
let mut gcm = Gcm::decryptor(&mut cipher, &nonce, aad)?;
let mut opened = Vec::new();
gcm.update(&sealed, &mut opened)?;
gcm.verify(&tag)?;              // an error here means forged, not corrupt
assert_eq!(opened, b"the payload");
```

Or in one call, through the trait:

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::BlockCipher;

let mut cipher = AesCrypto::new(vec![0x2b; 32])?;
let (mut sealed, mut tag) = (Vec::new(), Vec::new());
cipher.gcm_encrypt(b"payload", &mut sealed, &[0x11; 12], &mut tag, b"aad")?;

let mut opened = Vec::new();
let mut cipher = AesCrypto::new(vec![0x2b; 32])?;
cipher.gcm_decrypt(&sealed, &mut opened, &[0x11; 12], &tag, b"aad")?;
assert_eq!(opened, b"payload");

// A forgery leaves nothing behind. Handing back plaintext alongside an
// error is how a caller that checks one line too late uses forged data.
let mut forged = sealed.clone();
forged[0] ^= 1;
let mut out = Vec::new();
let mut cipher = AesCrypto::new(vec![0x2b; 32])?;
assert!(cipher.gcm_decrypt(&forged, &mut out, &[0x11; 12], &tag, b"aad").is_err());
assert!(out.is_empty());
```

### AES-CCM

The older AEAD (RFC 3610), and the one constrained hardware uses: a
CBC-MAC and a CTR keystream under the same key, so it needs no field
arithmetic and no tables beyond AES itself.

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::ccm;

let mut cipher = AesCrypto::new(vec![0x2b; 16])?;
let nonce = [0x11u8; 12];

let (sealed, tag) = ccm::encrypt(&mut cipher, &nonce, b"headers",
                                 b"the payload", 16)?;
assert_eq!(tag.len(), 16);
assert_eq!(ccm::decrypt(&mut cipher, &nonce, b"headers", &sealed, &tag)?,
           b"the payload");

// An eight byte tag is a real choice, not a saving: a blind forgery
// succeeds once in 2^64 attempts rather than once in 2^128.
let (_, short) = ccm::encrypt(&mut cipher, &nonce, b"headers",
                              b"the payload", 8)?;
assert_eq!(short.len(), 8);
```

Two things about CCM that GCM does not have:

- **It cannot stream.** The MAC begins with the message's length, so
  nothing can be processed until all of it has arrived. These functions
  are one-shot for that reason; the `api::AeadStream` facade buffers, and
  says so through `buffers_everything()`.
- **The nonce and the message length share fifteen bytes.** A 13 byte
  nonce caps the message at 65535 bytes and a 7 byte one allows more than
  any real message. Exceeding the cap is an error rather than a silent
  truncation — a truncated length would be authenticated as the wrong
  number.

```rust
use allcrypt::block_ciphers::aes::AesCrypto;
use allcrypt::block_ciphers::ccm;

let mut cipher = AesCrypto::new(vec![3u8; 16])?;
let long_nonce = [4u8; 13];                    // leaves 2 bytes for the length
assert!(ccm::encrypt(&mut cipher, &long_nonce, b"", &vec![0; 65535], 16).is_ok());
assert!(ccm::encrypt(&mut cipher, &long_nonce, b"", &vec![0; 65536], 16).is_err());
```

### MGM

Multilinear Galois Mode (RFC 9058), the AEAD the GOST TLS 1.3 cipher
suites are built on. A counter mode for confidentiality and a
multilinear function over GF(2^n) for authenticity, over any block
cipher — and unlike GCM, CCM, XTS and key wrap, **it works on a 64 bit
block too**, because RFC 9058 gives a field polynomial for each size.

```rust
use allcrypt::block_ciphers::mgm::Mgm;

let key = vec![0x2bu8; 32];
let mgm = Mgm::new("kuznyechik", &key)?;

// The nonce is **one block with the top bit clear**: that bit is the
// domain separator between MGM's two counter chains, so it is not part
// of the nonce and a value with it set is refused rather than masked.
let icn = [0x11u8; 16];
let (sealed, tag) = mgm.encrypt(&icn, b"headers", b"the payload")?;
assert_eq!(tag.len(), 16);
assert_eq!(mgm.decrypt(&icn, b"headers", &sealed, &tag)?, b"the payload");

// Magma: the same mode, a different field, and an 8 byte everything.
let magma = Mgm::new("magma", &key)?;
let (sealed, tag) = magma.encrypt(&[0x11u8; 8], b"headers", b"payload")?;
assert_eq!(tag.len(), 8);
assert_eq!(magma.decrypt(&[0x11u8; 8], b"headers", &sealed, &tag)?,
           b"payload");

// RFC 9058 section 4 allows a tag from 32 bits up to the block.
let short = Mgm::with_tag_len("kuznyechik", &key, 8)?;
assert_eq!(short.encrypt(&icn, b"h", b"m")?.1.len(), 8);
```

Two things it refuses, both because the standard says the result would
not be safe rather than because it would be awkward:

- **Empty associated data and an empty message together.** RFC 9058
  section 6: the tag then no longer depends on the nonce, so one
  captured tag forges every such message under that key.
- **A nonce with its top bit set.** `0 || ICN` starts the keystream's
  counter and `1 || ICN` starts the authentication's; masking silently
  would turn two nonces that differ only there into one.

```rust
use allcrypt::block_ciphers::mgm::Mgm;

let mgm = Mgm::new("magma", &[0x33u8; 32])?;
assert!(mgm.encrypt(&[0x01u8; 8], b"", b"").is_err());
assert!(mgm.encrypt(&[0x81u8; 8], b"a", b"b").is_err());
```

### OCB

Krovetz and Rogaway's OCB3 (RFC 7253): one block cipher call per block
and a checksum of the plaintext, over any 128 bit block cipher. It is
the default AEAD of OpenPGP's encrypted data packets.

```rust
use allcrypt::block_ciphers::ocb::Ocb;

let ocb = Ocb::new("aes", &[0x2bu8; 16])?;
let nonce = [0x11u8; 15];                      // up to 120 bits
let (sealed, tag) = ocb.encrypt(&nonce, b"headers", b"the payload")?;
assert_eq!(ocb.decrypt(&nonce, b"headers", &sealed, &tag)?, b"the payload");

// The tag length is written into the nonce block, so a 12 byte tag is
// not the 16 byte one cut short: it is a different ciphertext as well.
let short = Ocb::with_tag_len("aes", &[0x2bu8; 16], 12)?;
let (other, short_tag) = short.encrypt(&nonce, b"headers", b"the payload")?;
assert_ne!(other, sealed);
assert_ne!(&tag[..12], &short_tag[..]);

// 128 bit blocks only.
assert!(Ocb::new("des", &[0u8; 8]).is_err());
```

### AES-CBC with HMAC-SHA-2

RFC 7518 5.2's encrypt-then-MAC: AES-CBC with PKCS#7 padding, then
HMAC over the associated data, the IV, the ciphertext and the
associated data's length in bits, cut to half. The key is the MAC key
then the AES key.

```rust
use allcrypt::block_ciphers::cbc_hmac::{CbcHmac, Variant};

let aead = CbcHmac::new(Variant::Aes128HmacSha256, &[7u8; 32])?;
let (ciphertext, tag) = aead.encrypt(&[1u8; 16], b"header", b"the payload")?;
assert_eq!((ciphertext.len(), tag.len()), (16, 16));
assert_eq!(aead.decrypt(&[1u8; 16], b"header", &ciphertext, &tag)?, b"the payload");
```

Through the facade it is `aes-128-cbc-hmac-sha256` and its two siblings,
with the IV as the nonce.

### ChaCha20-Poly1305

The other AEAD (RFC 8439), and the one to use where there is no AES
instruction: both halves are 32 bit adds, XORs and rotations, so a
software implementation is fast and constant time without effort, where
software AES needs either lookup tables, which leak through the cache, or
bitslicing, which is slower (`docs/pitfalls.md` section 1).

```rust
use allcrypt::stream_ciphers::chacha20poly1305::{open, seal};

let key = [0x2bu8; 32];
let nonce = [0x11u8; 12];

let (sealed, tag) = seal(&key, &nonce, b"headers", b"the payload")?;
assert_eq!(open(&key, &nonce, b"headers", &sealed, &tag)?, b"the payload");

// Any change at all fails, and returns nothing.
let mut forged = tag;
forged[0] ^= 1;
assert!(open(&key, &nonce, b"headers", &sealed, &forged).is_err());
```

A 256 bit key and a 96 bit nonce, and only those: RFC 8439 fixes the nonce
at 96 bits so the block counter gets a full 32, and ChaCha's original 8
byte nonce belongs to a different construction.

`mac::Poly1305` is the authenticator on its own, for the rare case that
wants it. It is a **one-time** authenticator, not a small HMAC: two
messages under one key give two equations in r and s, r falls out, and
every later tag can be forged. Nothing here takes a long-lived key for
it, and neither should anything else.

### What GCM will not do

Three things:

- **A 64 bit block cipher.** GHASH lives in GF(2^128) and nowhere else, so
  GCM over Blowfish or GOST is an error rather than an improvisation.
- **An empty nonce.** GHASH of nothing is zero, which would give every key
  the same first counter block.
- **A tag under 12 bytes.** SP 800-38D allows shorter ones only where the
  number of forgery attempts can be bounded, and nothing here can bound it.

**A nonce must never repeat under one key.** Two messages sharing one give
away their XOR and the authentication key H, after which anything can be
forged under that key. Nothing in this library can check that; only the
caller knows what was used before. 12 bytes from the OS random source, or a
counter you can keep, are the two answers.

`block_ciphers::ghash` is the field arithmetic on its own, usable directly
and worth reading for the bit order, which runs backwards from every other
convention in this library.

## XTS, the disk mode

IEEE 1619, adopted by NIST as SP 800-38E. The mode that encrypts a
*place* rather than a stream: a sector is encrypted under its own
number, the ciphertext is exactly as long as the plaintext, and there is
no IV to store and no tag to check.

```rust
use allcrypt::api;

// Two AES-128 keys end to end. The halves must differ.
let key: Vec<u8> = (0..32u8).collect();
let plaintext = b"a sector's worth of bytes, and then some more";

let ciphertext = api::xts_encrypt("aes", &key, 1234, plaintext)?;
assert_eq!(ciphertext.len(), plaintext.len());
assert_eq!(api::xts_decrypt("aes", &key, 1234, &ciphertext)?, plaintext.to_vec());

// The same bytes in a different sector encrypt differently, which is
// the whole reason the mode exists.
assert_ne!(api::xts_encrypt("aes", &key, 1235, plaintext)?, ciphertext);
```

**XTS is not authenticated and cannot be.** There is no room: the
ciphertext is the same length as the plaintext. Anyone who can write to
the storage can replace any block with bytes of their choosing, and
decryption returns plaintext rather than an error. It also leaks
equality — the same plaintext written to the same sector twice gives the
same ciphertext. Both are properties of the problem rather than gaps
here, and [pitfalls.md](pitfalls.md) records them.

Lengths that are not a multiple of sixteen use ciphertext stealing, so
no padding is needed, and anything under one block is refused because
there is nothing to steal from:

```rust
use allcrypt::api;

let key: Vec<u8> = (0..64u8).collect();          // two AES-256 keys
for length in [16usize, 17, 31, 32, 33] {
    let plaintext = vec![0xabu8; length];
    let ciphertext = api::xts_encrypt("aes", &key, 0, &plaintext)?;
    assert_eq!(ciphertext.len(), length);
    assert_eq!(api::xts_decrypt("aes", &key, 0, &ciphertext)?, plaintext);
}
assert!(api::xts_encrypt("aes", &key, 0, &[0u8; 15]).is_err());

// And the two halves of the key must differ: equal halves collapse the
// tweak into the data cipher.
let duplicated = [[7u8; 16], [7u8; 16]].concat();
assert!(api::xts_encrypt("aes", &duplicated, 0, &[0u8; 32]).is_err());
```

The mode is generic over any 128 bit block cipher, as everything else
here is. Camellia-XTS and SM4-XTS are not in any standard and exist
here; there is no 64 bit form, so `des` and `magma` are refused with an
error that names the block size rather than calling the cipher unknown.

### LRW, the mode before it

IEEE P1619 drafted LRW first, and dm-crypt (`lrw-benbi`, `lrw-plain64`)
and TrueCrypt 4.1 to 4.3 used it, so volumes in it exist. The key is the
cipher's key and then a 16 byte tweak key, and the index counts 16 byte
blocks:

```rust
use allcrypt::api;

let key: Vec<u8> = (0..32u8).collect();          // AES-128, then the tweak key
let sector = 7u128;
// dm-crypt's lrw-benbi: a 512 byte sector's first block is 32 * sector + 1.
let ciphertext = api::lrw_encrypt("aes", &key, 32 * sector + 1, &[0u8; 512])?;
assert_eq!(api::lrw_decrypt("aes", &key, 32 * sector + 1, &ciphertext)?, vec![0u8; 512]);
assert!(api::lrw_encrypt("aes", &key, 0, &[0u8; 17]).is_err());   // whole blocks only
```

It is checked against IEEE P1619's nine vectors (`vectors/lrw_aes.vec`)
and a LUKS volume the Linux kernel wrote in LRW. Not authenticated.

### BitLocker's sectors

`block_ciphers::bitlocker` is the sector encryption of a BitLocker
volume's six methods. Both CBC methods take the IV from the sector's
**byte offset**, AES-encrypted; Elephant (Windows Vista and 7) also
XORs a per-sector key into the plaintext and mixes the sector with two
keyless diffusers before CBC, so that one changed ciphertext bit changes
the whole decrypted sector. XTS numbers sectors in sector-size units.
The volume key is in dm-crypt's form - for Elephant, the CBC key then
the tweak key:

```rust
use allcrypt::block_ciphers::bitlocker::{Method, SectorCipher};

let key = [7u8; 32];                        // AES-128 CBC key, then tweak key
let mut cipher = SectorCipher::new(Method::from_name("aes-cbc-elephant-128")?, &key)?;
let mut sector = vec![0u8; 512];
cipher.encrypt_sector(1 << 20, &mut sector)?;   // the byte offset on the volume
cipher.decrypt_sector(1 << 20, &mut sector)?;
assert_eq!(sector, vec![0u8; 512]);
```

`kdf::password::bitlocker_stretch` is the 2^20-round SHA-256 that turns a
password or recovery password into the key for its protector. Volumes
Windows made are read by the BitLocker product example.

### Wi-Fi: WEP, TKIP and the WPA key hierarchy

`stream_ciphers::wep` is WEP's RC4-over-data-and-CRC, `stream_ciphers::tkip`
TKIP's per-packet key mixing, `mac::michael` TKIP's MIC, and
`kdf::ieee80211` the PSK, PRF, PTK and PMKID. CCMP is `block_ciphers::ccm`
(AES-CCM). The 802.11 frame framing lives in the `wifi` product example;
these are the pieces:

```rust
use allcrypt::kdf::ieee80211;
use allcrypt::stream_ciphers::{tkip, wep};

// WPA2: the pre-shared key, then the pairwise key from the handshake's
// two nonces and the two addresses.
let pmk = ieee80211::psk(b"password", b"IEEE")?;
let ptk = ieee80211::ptk_sha1(&pmk, &[0; 6], &[1; 6], &[2; 32], &[3; 32], 384);
assert_eq!(ptk.len(), 48);

// TKIP mixes a fresh RC4 key per frame; WEP's encapsulation decrypts it.
let rc4_key = tkip::rc4_key(&[7; 16], &[1, 2, 3, 4, 5, 6], 0x1_0002);
let sealed = wep::seal(&rc4_key, b"payload");
assert_eq!(wep::open(&rc4_key, &sealed)?, b"payload");
```

Captures that aircrack-ng's `airdecap-ng` opens are opened the same way
by the Wi-Fi product example.

## Key wrap

RFC 3394, and the padded form from RFC 5649 (`block_ciphers::keywrap`);
CMS's older RFC 3217 Triple-DES and RC2 wraps and RFC 3211's password
recipient wrap are in `block_ciphers::cms_wrap`. Encrypting a key with a
key — which looks like a mode and is not one, because there is no IV
and nothing random anywhere.

```rust
use allcrypt::api;

let kek = [0x42u8; 32];
let key_to_protect = [0x17u8; 32];

let wrapped = api::key_wrap("aes", &kek, &key_to_protect)?;
assert_eq!(wrapped.len(), key_to_protect.len() + 8);
assert_eq!(api::key_unwrap("aes", &kek, &wrapped)?, key_to_protect.to_vec());

// Deterministic, on purpose: two copies of one key must look like two
// copies, so a wrapped key can be stored, copied and compared.
assert_eq!(api::key_wrap("aes", &kek, &key_to_protect)?, wrapped);
```

What replaces the randomness is **integrity without a separate MAC**.
Six passes mix every 64 bit half into every other one, and unwrapping
ends with a check against a known constant, so a wrapping either yields
the key or yields an error:

```rust
use allcrypt::api;

let kek = [0x42u8; 32];
let wrapped = api::key_wrap("aes", &kek, &[0x17u8; 32])?;

let mut altered = wrapped.clone();
altered[9] ^= 1;
assert!(api::key_unwrap("aes", &kek, &altered).is_err());
assert!(api::key_unwrap("aes", &[0x43u8; 32], &wrapped).is_err());
```

RFC 3394 takes whole 64 bit blocks and at least two of them, so it
cannot wrap a 20 byte HMAC key or a 57 byte Ed448 one. RFC 5649 adds a
length field to the constant and zero pads; it is a *different*
algorithm rather than an option, and eight bytes or fewer skips the six
passes entirely.

```rust
use allcrypt::api;

let kek = [0x42u8; 24];
assert!(api::key_wrap("aes", &kek, &[0u8; 20]).is_err());

let wrapped = api::key_wrap_with_padding("aes", &kek, &[0u8; 20])?;
assert_eq!(wrapped.len(), 32);                    // 24 padded, plus 8
assert_eq!(api::key_unwrap_with_padding("aes", &kek, &wrapped)?, vec![0u8; 20]);

// Eight bytes or fewer is one block and a single encryption.
assert_eq!(api::key_wrap_with_padding("aes", &kek, b"a key")?.len(), 16);
```

## Padding

CBC and ECB need block-aligned input. PKCS#7 padding is on the trait, and
also available as free functions that return a new buffer:

```rust
use allcrypt::api::{pad_pkcs7, unpad_pkcs7};

let message = b"awkward length";
let padded = pad_pkcs7(message, 16)?;
assert_eq!(padded.len(), 16);
assert_eq!(unpad_pkcs7(&padded, 16)?, message);
```

Padding always adds between 1 and `block_size` bytes — input that is already
aligned gets a whole extra block, which is what makes unpadding unambiguous.

## Stream ciphers

```rust
use allcrypt::stream_ciphers::{chacha::Chacha, rc4::RC4, StreamCipher};

let mut cipher = Chacha::new(vec![0u8; 32], vec![0u8; 12], 20)?;
let mut out = vec![];
cipher.crypt(b"abc", &mut out);

let mut rc4 = RC4::new(vec![1, 2, 3, 4, 5])?;
let mut keystream = vec![];
rc4.crypt(&[0u8; 16], &mut keystream);
assert_eq!(allcrypt::to_hex(&keystream).to_lowercase(),
           "b2396305f03dc027ccc3524a0a1118a8");
```

ChaCha takes 8 or 12 byte nonces and 8, 12 or 20 rounds. With a 12 byte nonce
it follows RFC 8439 (32 bit counter); with 8 bytes it is the original DJB
construction (64 bit counter). Keystream position carries across `crypt`
calls, so a cipher object is a stream, not a one-shot.

ZipCrypto, PKWARE's traditional ZIP encryption, is keyed by a password
and has no keystream of its own: its three keys absorb each byte of
*plaintext*, so encrypting and decrypting are different operations and
it does not implement `StreamCipher`. It is broken - twelve bytes of
known plaintext give the keys - and `from_keys` and `keys` work with the
internal state such an attack recovers.

```rust
use allcrypt::stream_ciphers::zipcrypto::ZipCrypto;

let mut out = vec![];
ZipCrypto::new(b"secret").encrypt(b"hello, world", &mut out);
assert_eq!(allcrypt::to_hex(&out).to_lowercase(), "a0254d7b73bee67c15583a7e");

let mut back = vec![];
ZipCrypto::new(b"secret").decrypt(&out, &mut back);
assert_eq!(back, b"hello, world");
```

A ZIP entry also carries a 12-byte encryption header with a check byte;
that is the format's, and `examples/products/zip` writes and reads it.

Office XOR obfuscation (`stream_ciphers::office_xor`, [MS-OFFCRYPTO]
method 1) is the `.xls` password protection before RC4. The password
gives a 16-byte array that the data is XORed with, repeating, each byte
then rotated; `index` is the array index the first byte meets.

```rust
use allcrypt::stream_ciphers::office_xor::{password_verifier, OfficeXor};

assert_eq!(password_verifier(b"VelvetSweatshop")?, 0x9a0a);
let xor = OfficeXor::new(b"secret")?;
let mut data = *b"sheet data";
xor.encrypt(&mut data, 3);
xor.decrypt(&mut data, 3);
assert_eq!(&data, b"sheet data");
```

## Telling it what an OID means

`allcrypt::registry` maps an object identifier to a meaning at run
time, for the equipment that names a digest, a parameter set or a
curve by an OID this library does not carry.

```rust
use allcrypt::registry::{self, Meaning};
use allcrypt::api::AnyHash;
use allcrypt::hash_functions::HashFunction;

registry::register("1.3.6.1.4.1.99998.1.1", Meaning::hash("gost94"))?;
let mut hash = AnyHash::new("1.3.6.1.4.1.99998.1.1")?;
hash.update(b"abc");
assert_eq!(hash.digest().len(), 32);
registry::forget("1.3.6.1.4.1.99998.1.1");
```

Four meanings. `Meaning::hash` and `Meaning::curve` move a **name** -
this OID means a hash or a curve already compiled in. The other two
supply the **cryptography**, because a GOST cipher is its S-box and a
short Weierstrass curve is its parameters, and both are distributed as
parameter sets rather than as code:

* `Meaning::gost_param_set` takes the eight substitution rows, checked as
  eight permutations of sixteen values.
* `Meaning::curve_parameters` takes `ec::curves::CurveParameters`, checked
  by `ec::curves::from_parameters` - which is also the entry point for a
  Rust caller who wants the `Curve` directly rather than through an OID:

```rust
use allcrypt::ec::curves::{self, CurveParameters};
use allcrypt::bignum::BigUint;

let hex = |s: &str| BigUint::from_hex(s).unwrap();
// Brainpool P-256r1, RFC 5639 section 3.4.
let curve = curves::from_parameters(CurveParameters {
    name: "brainpoolP256r1".to_string(),
    p: hex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
    a: hex("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
    b: hex("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
    gx: hex("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
    gy: hex("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
    n: hex("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
    h: BigUint::one(),
})?;
assert_eq!(curve.name, "brainpoolP256r1");
assert!(curve.is_on_curve(&curve.g));

// Parameters that are not a curve are refused rather than used. Here
// the base point has moved by one, which is still a perfectly good
// number and is not on the curve.
let off_the_curve = CurveParameters {
    name: "not-a-curve".to_string(),
    p: curve.p.clone(), a: curve.a.clone(), b: curve.b.clone(),
    gx: curve.g.x().unwrap().clone(),
    gy: curve.g.y().unwrap().add(&BigUint::one()),
    n: curve.n.clone(), h: curve.h.clone(),
};
let refused = curves::from_parameters(off_the_curve).unwrap_err();
assert!(refused.contains("not on the curve"), "{}", refused);

// And a name that is already built in is refused rather than shadowed:
// a registered curve under it would never be reached, because the
// compiled-in tables are consulted first.
let shadowing = CurveParameters { name: "P-256".to_string(),
                                  p: curve.p.clone(), a: curve.a.clone(),
                                  b: curve.b.clone(),
                                  gx: curve.g.x().unwrap().clone(),
                                  gy: curve.g.y().unwrap().clone(),
                                  n: curve.n.clone(), h: curve.h.clone() };
assert!(curves::from_parameters(shadowing).unwrap_err()
        .contains("already a curve"));
```

The checks are listed in `docs/python.md`, with what each one catches; the
short version is that a curve which is merely plausible still computes and
still produces signatures, so "it worked" is not evidence.

Registrations are consulted **after** the compiled-in tables, so a
registration can never change what a standard OID means. See
`docs/python.md` for the same thing from Python, which is where it is
most useful.

## MAC

GOST implements `Mac` alongside `BlockCipher`:

```rust
use allcrypt::block_ciphers::gost::GostCrypto;
use allcrypt::Mac;

let key = vec![0xBE, 0x5E, 0xC2, 0x00, 0x6C, 0xFF, 0x9D, 0xCF,
               0x52, 0x35, 0x49, 0x59, 0xF1, 0xFF, 0x0C, 0xBF,
               0xE9, 0x50, 0x61, 0xB5, 0xA6, 0x48, 0xC1, 0x03,
               0x87, 0x06, 0x9C, 0x25, 0x99, 0x7C, 0x06, 0x72];
// The parameter set names the S-box, and the S-box *is* the cipher.
// There is no default: an unknown name is an error rather than a
// quiet substitution, since two parameter sets are two different
// ciphers that both work.
let mut mac = GostCrypto::new(key, GostCrypto::DEFAULT_PARAM_SET.to_string())?;
mac.set_mac_iv(&[1, 2, 3, 4, 5, 6, 7, 8]);
mac.update(&[0u8; 14]);
assert_eq!(mac.digest(), vec![0xd8, 0xb5, 0xa9, 0x78, 0xdf, 0x19, 0x17, 0xcb]);
```

### UMAC

`mac::umac::Umac` is RFC 4418: a 16 byte AES key, a tag of 4, 8, 12 or
16 bytes, and a nonce of 1 to 16 bytes that **must not repeat** under one
key. The value here is RFC 4418's own 64 bit example:

```rust
use allcrypt::mac::umac::Umac;

let mut umac = Umac::new(b"abcdefghijklmnop", 8)?;
let tag = umac.tag(&b"abc".repeat(500), b"bcdefghi")?;
assert_eq!(tag, [0xD4, 0xCF, 0x26, 0xDD, 0xEF, 0xD5, 0xC0, 0x1A]);
```

It is one-shot: the whole message is in hand, as it is for an SSH
packet. In SSH it is reached by name - `umac-64@openssh.com`,
`umac-128@openssh.com` and their `-etm` forms - with the packet sequence
number as the nonce.

## HMAC and key derivation

HMAC is generic over any hash in the library. Pass a freshly constructed hash
as the template:

```rust
use allcrypt::hash_functions::sha2;
use allcrypt::mac::Hmac;
use allcrypt::Mac;

let tag = Hmac::mac(sha2::SHA256::new(&[]), b"Jefe", b"what do ya want for nothing?");
assert_eq!(allcrypt::to_hex(&tag).to_lowercase(),
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

// or streamed
let mut mac = Hmac::new(sha2::SHA256::new(&[]), b"key");
mac.update(b"first ");
mac.update(b"second");
let _tag = mac.digest();
```

`digest()` is repeatable and does not end the MAC, same as the hashes. There
are shorthand constructors — `hmac_sha256(key)` and friends — in
`allcrypt::mac::hmac`.

The key derivation functions build on it. HKDF is RFC 5869; the TLS PRFs are
RFC 5246 section 5 for 1.2 and RFC 2246 section 5 for 1.0/1.1:

```rust
use allcrypt::hash_functions::sha2;
use allcrypt::kdf::{hkdf, tls10_prf, tls12_prf};

let keying = hkdf(sha2::SHA256::new(&[]), b"salt", b"input key material",
                  b"context info", 42)?;
assert_eq!(keying.len(), 42);

let master = tls12_prf(sha2::SHA256::new(&[]), b"pre master secret",
                       b"master secret", b"client random + server random", 48);
let legacy = tls10_prf(b"pre master secret", b"master secret", b"randoms", 48);
assert_eq!((master.len(), legacy.len()), (48, 48));
```

An empty HKDF salt means the all-zero salt the RFC specifies, not "no salt".
`hkdf_extract` and `hkdf_expand` are available separately for TLS 1.3, which
uses them independently.

`kdf::nist` has SP 800-108's KBKDF in counter and feedback modes over a
named PRF, and the two hash KDFs used by ECDH key agreement - SP
800-56C's one-step "Concat KDF" and ANSI X9.63's, which differ only in
where the counter goes. `kdf::kerberos` has RFC 3961's n-fold, DR,
random-to-key and DES string-to-key:

```rust
use allcrypt::kdf::kerberos::{des_string_to_key, nfold};
use allcrypt::kdf::nist::{concat_kdf, kbkdf_counter, x963_kdf, Prf};

let k = kbkdf_counter(Prf::named("hmac-sha256")?, b"key", b"label", b"context", 32)?;
assert_eq!(k.len(), 32);
assert_ne!(concat_kdf("sha256", b"z", b"info", 32)?, x963_kdf("sha256", b"z", b"info", 32)?);

assert_eq!(allcrypt::to_hex(&nfold(b"012345", 8)).to_lowercase(), "be072631276b1955");
let key = des_string_to_key(b"password", b"ATHENA.MIT.EDUraeburn")?;
assert_eq!(allcrypt::to_hex(&key).to_lowercase(), "cbc22fae235298e3");
```

### From a password

A password is not a key: it is short, it comes from a small alphabet and
somebody chose it. `kdf::password` turns one into a key at a cost the
caller sets.

```rust
use allcrypt::hash_functions::sha2;
use allcrypt::kdf::password::{pbkdf2, pbkdf2_recommended_iterations};

let key = pbkdf2(sha2::SHA256::new(&[]), b"correct horse", b"some salt",
                 pbkdf2_recommended_iterations("sha256"), 32)?;
assert_eq!(key.len(), 32);
```

**No minimum iteration count is enforced**, and that is deliberate rather
than an oversight. RFC 8018 suggested 1000 in 2000; OWASP now says
600,000 for HMAC-SHA-256. A file written in 2009 with `c=1000` still has
to be readable in 2026, and a library that refuses to compute it is a
library that cannot open the file. `pbkdf2_recommended_iterations` is
there to answer the question for *new* work; nothing consults it when
reading, where the count comes from the file.

Two older derivations are there for the same reason — not because
anything new should use them, but because files that already exist do:

- `pbkdf1` (RFC 8018 section 5.1), which PBES1 uses. Its output is one
  hash digest, so it can never yield more than 20 bytes — which is why
  no PBES1 scheme has an AES variant.
- `pkcs12_kdf` (RFC 7292 Appendix B), a third construction again, with
  its own padding rules and a big-endian addition over 64-byte blocks.
  It hashes the password as a **BMPString** — UTF-16 big endian with a
  terminating NUL character — and `pkcs12_bmp_password` does that
  conversion. This is what every `.p12` file uses and what
  `openssl pkcs8 -topk8 -v1` still writes by default.

And the file formats' own derivations, each written for one program and
still in every file that program wrote: OpenPGP's string-to-key,
7-Zip's AES key, KeePass's AES-KDF, and LUKS's anti-forensic splitter,
which stores a key rather than deriving one:

```rust
use allcrypt::hash_functions::sha1::SHA1;
use allcrypt::kdf::luks_af::{af_merge, af_split};
use allcrypt::kdf::password::{keepass_aes_kdf, openpgp_s2k, openpgp_s2k_count,
                              sevenzip_aes_key};

// Iterated and salted S2K: 65,536 octets of salt || passphrase, SHA-1.
let count = openpgp_s2k_count(0x60);
let key = openpgp_s2k(SHA1::new(&[]), b"passphrase", b"8 bytes!", count, 16);
assert_eq!(key.len(), 16);

// 7-Zip: the password is UTF-16LE; 2^19 rounds is what 7-Zip writes.
let password: Vec<u8> = "pw".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
let key = sevenzip_aes_key(&password, &[], 4)?;
assert_eq!(key.len(), 32);

let key = keepass_aes_kdf(&[0; 32], &[1; 32], 1000)?;
assert_eq!(key.len(), 32);

// The random stripes come from the caller.
let mut random = |buf: &mut [u8]| -> Result<(), String> {
    buf.fill(0x5a);
    Ok(())
};
let stripes = af_split(&[7; 32], 4000, "sha256", &mut random)?;
assert_eq!(af_merge(&stripes, 32, 4000, "sha256")?, [7; 32]);
```

For anything new, prefer one of the memory-hard two. PBKDF2's cost is
*time* only, so an attacker with a GPU runs thousands of guesses in
parallel for the price of one; these make each guess need memory as
well, which costs silicon area instead.

```rust
use allcrypt::kdf::argon2::{Argon2, Variant};
use allcrypt::kdf::scrypt::scrypt;

// scrypt: N is a power of two, memory is 128 * N * r bytes
let key = scrypt(b"correct horse", b"some salt", 16384, 8, 1, 32)?;
assert_eq!(key.len(), 32);

// Argon2id, which is what RFC 9106 section 4 recommends
let mut argon = Argon2::new(Variant::Id);
argon.memory_kib = 1024;          // small, so this doc example runs fast
argon.passes = 1;
let key = argon.derive(b"correct horse", b"a sixteen  byte!", 32)?;
assert_eq!(key.len(), 32);
```

All three Argon2 variants are here and none of them is the deprecated
one. `Variant::D` has the best trade-off resistance and is right when
nothing can observe the machine's memory; `Variant::I` leaks nothing
through the access pattern; `Variant::Id` is the first for half of the
first pass and the second thereafter.

### Windows password hashes

`kdf::windows` has the two hashes Windows stores (MS-NLMP 3.3.1). Both
are keys rather than verifiers - NTLM authenticates with the hash
itself - and neither has a salt or a cost.

```rust
use allcrypt::kdf::windows::{lm_hash, nt_hash};

// NT: MD4 of the password as UTF-16LE.
assert_eq!(allcrypt::to_hex(&nt_hash("Password")).to_lowercase(),
           "a4f49c406510bdcab6824ee7c30fd852");

// LM: bytes in the OEM code page, at most 14 of them. ASCII letters are
// uppercased here; anything above 0x7f is the caller's to uppercase,
// because which byte that is depends on the code page.
assert_eq!(allcrypt::to_hex(&lm_hash(b"Password")?).to_lowercase(),
           "e52cac67419a9a224a3b108f3fa6cb6d");
assert!(lm_hash(b"fifteen letters").is_err());
```

A password over fourteen bytes has no LM hash - Windows keeps the hash
of the empty password in its place - so `lm_hash` refuses one rather
than quietly hashing its first fourteen bytes.

## Randomness

`random` reads the operating system's generator. Use it for anything keyed.

```rust
use allcrypt::bignum::BigUint;
use allcrypt::random;

let iv = random::bytes(16)?;
assert_eq!(iv.len(), 16);

// A private scalar in [1, n). Rejection sampled, so it is unbiased - taking
// a random value mod n skews towards small values, and for ECDSA that bias
// leaks the private key over enough signatures.
let order = BigUint::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")?;
let scalar = random::below(&order)?;
assert!(!scalar.is_zero() && scalar < order);
```

It errors rather than falling back to anything weaker, and never buffers
across a `fork`. The separate `prng` module is a linear congruential
generator for simulation and for talking to systems that used one — it is
**not** for keys, and says so.

## Big integers

`BigUint` is arbitrary precision unsigned arithmetic, written from scratch so
the public key work has no external dependency:

```rust
use allcrypt::bignum::BigUint;

let a = BigUint::from_hex("deadbeefcafe")?;
let b = BigUint::from_u64(65537);
let m = BigUint::from_hex("fffffffffffffffffffffffffffffffeffffffffffffffff")?;

let powered = a.mod_pow(&b, &m)?;
let inverse = a.mod_inverse(&m)?;
assert!(a.mod_mul(&inverse, &m)?.is_one());
assert!(powered < m);

// wire encoding: big endian, with a fixed width form that refuses to truncate
assert_eq!(BigUint::from_bytes_be(&[0, 0, 1]), BigUint::one());
assert_eq!(a.to_bytes_be_padded(8)?.len(), 8);
assert!(a.to_bytes_be_padded(2).is_err());
```

Subtraction returns `Result` rather than wrapping, and division by zero is an
error rather than a panic.

`mod_pow` takes a Montgomery path automatically when the modulus is odd. For
a **secret** exponent use `mod_pow_ct`, which runs a Montgomery ladder: one
multiply and one square per exponent bit whatever its value, selected with a
branchless swap.

```rust
use allcrypt::bignum::BigUint;

let base = BigUint::from_hex("deadbeef")?;
let secret_exponent = BigUint::from_hex("c0ffee")?;
let modulus = BigUint::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43")?;

let fast = base.mod_pow(&secret_exponent, &modulus)?;          // public exponents
let uniform = base.mod_pow_ct(&secret_exponent, &modulus)?;    // secret ones
assert_eq!(fast, uniform);
```

The rest of `BigUint` is **not** constant time, and cannot be made so: it is
normalised, so the limb count is a measurement of the value. `divrem` and
`mod_inverse` branch on their inputs outright.

### Secrets

For a value that must not leak, `bignum::ct::Secret` is the fixed-width type:
exactly `k` limbs, never normalised, with `Montgomery` on top of it for
modular arithmetic. It has no `Ord`, `PartialEq` or `Debug` on purpose, so
`a == b`, `a < b` and `{:?}` on a secret do not compile — comparison is
`ct_eq` and `ct_lt`, which return an all-ones-or-all-zeros mask.

```rust
use allcrypt::bignum::{BigUint, Montgomery, Secret};

let modulus = BigUint::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43")?;
let field = Montgomery::new(&modulus)?;
let width = field.limbs();

let base = Secret::from_biguint(&BigUint::from_hex("deadbeef")?, width)?;
let exponent = Secret::from_biguint(&BigUint::from_hex("c0ffee")?, width)?;

// The loop bound is public and comes from the modulus, not the exponent,
// so a short secret costs exactly what a long one does.
let result = field.pow_ct(&base, &exponent, field.modulus_bits());

// Fixed width on the way out: no leading zeros are trimmed, which is what
// key material needs.
assert_eq!(result.to_bytes_be().len(), width * 8);

// `declassify` is named for what it costs - it normalises, which makes the
// value's length visible again. Right for something about to be published.
assert_eq!(result.declassify(),
           BigUint::from_hex("deadbeef")?.mod_pow(&BigUint::from_hex("c0ffee")?, &modulus)?);

// Inversion modulo a prime, by Fermat rather than Euclid.
let inverse = field.inverse_prime(&base, field.modulus_bits());
assert!(field.mul_mod(&base, &inverse).declassify().is_one());
```

`BigUint::mod_pow_ct` and `BigUint::mod_inverse_prime` are convenience
wrappers over those. Both return a `BigUint`, which normalises the result —
fine for a value about to be published, wrong for one that stays secret, and
the reason `dh.rs` calls `Montgomery::pow_ct` directly.

`scripts/ct_check.py` verifies all of this under valgrind. See
[pitfalls.md](pitfalls.md) for what each operation leaks and
[building.md](building.md) for how to run it.

## Elliptic curves

`ec` has the curve arithmetic; `ec::curves` has the named parameters. P-256,
P-384, P-521 and secp256k1 are in, and a curve is just a struct, so adding
one is filling in six numbers - copied by script from a document, and read
back out of it by a test, because P-521's were typed by hand first and
were wrong (see `docs/pitfalls.md`).

```rust
use allcrypt::ec::curves;

let curve = curves::p256();
let (private, public) = curve.generate_key_pair()?;

// SEC1 encoding, which is what goes on the wire and into a certificate.
let uncompressed = curve.encode_point(&public, false)?;   // 0x04 || X || Y
let compressed = curve.encode_point(&public, true)?;      // 0x02/0x03 || X
assert_eq!(uncompressed.len(), 65);
assert_eq!(compressed.len(), 33);

// Decoding always validates: the point must be on the curve and in range.
assert_eq!(curve.decode_point(&compressed)?, public);
```

ECDH, with the peer's point validated before any arithmetic touches it:

```rust
use allcrypt::ec::curves;

let curve = curves::p256();
let (my_private, my_public) = curve.generate_key_pair()?;
let (their_private, their_public) = curve.generate_key_pair()?;

let mine = curve.ecdh(&my_private, &their_public)?;
let theirs = curve.ecdh(&their_private, &my_public)?;
assert_eq!(mine, theirs);
```

Two scalar multiplications are on offer and the difference matters:

| Method | Use for |
|---|---|
| `scalar_mul` | Public scalars: verification, validation. |
| `scalar_mul_ct` | Private scalars. A four-bit window with masked table reads, on fixed-width Montgomery arithmetic (`ec::fixed`) for every field up to 576 bits and on `bignum::ct::Secret` (`ec::ct`) above that; nothing branches on the scalar or on a coordinate. `scalar_mul_secret` is the same returning an error rather than panicking. |

`generate_key_pair` and `ecdh` already use the constant-time path. `validate` is the
function that refuses a point that is the identity, out of range, or not on
the curve — call it on anything that arrived from outside, or use
`decode_point`, which calls it for you. Skipping that check is the
invalid-curve attack, and it recovers the private scalar.

## X25519

A different shape from the curves above, not another parameter set: a
Montgomery ladder on one coordinate, little-endian throughout, and a
scalar that is clamped before use. There is no point type and no encoding
to agree on — 32 bytes in, 32 bytes out.

```rust
use allcrypt::ec::x25519;

let (my_private, my_public) = x25519::generate_key_pair()?;
let (their_private, their_public) = x25519::generate_key_pair()?;

let mine = x25519::exchange(&my_private, &their_public)?;
let theirs = x25519::exchange(&their_private, &my_public)?;
assert_eq!(mine, theirs);
```

There is no point validation, and that is correct rather than missing:
every 32 byte string is a valid u coordinate, and the curve's twist was
chosen to have a large prime order subgroup too, so landing on it is not
an attack. What replaces it is the all-zero check — `exchange` refuses a
secret of zero, which is what a peer sending a low-order point produces:

```rust
use allcrypt::ec::x25519;

let (private, _public) = x25519::generate_key_pair()?;

// u = 1 has order 1, so every scalar maps it to zero.
let mut low_order_point = [0u8; 32];
low_order_point[0] = 1;
assert!(x25519::exchange(&private, &low_order_point).is_err());

// The raw primitive still computes it - the refusal belongs to the key
// exchange, which is the layer that knows a constant secret is useless.
assert_eq!(x25519::x25519(&private, &low_order_point)?, [0u8; 32]);
```

Clamping happens inside `x25519`, so it cannot be forgotten, and it is
idempotent so clamping twice is harmless. The TLS client offers X25519
ahead of P-256 for the reason above: fewer ways to be wrong.

## X448

The same shape over Curve448, and **not X25519 with bigger numbers.**
Four things differ and three of them are silent:

```rust
use allcrypt::ec::x448;

let (my_private, my_public) = x448::generate_key_pair()?;
let (their_private, their_public) = x448::generate_key_pair()?;

let mine = x448::exchange(&my_private, &their_public)?;
assert_eq!(mine, x448::exchange(&their_private, &my_public)?);
assert_eq!(mine.len(), x448::KEY_LEN);   // 56, not 32
```

* `p = 2^448 - 2^224 - 1`, and `a24 = 39081` from `A = 156326` — where
  X25519's is 121665. A ladder built with the wrong constant is
  self-consistent and matches no published vector.
* **The clamp is different**: two low bits cleared rather than three,
  because Curve448's cofactor is 4 where Curve25519's is 8, and bit 447
  set rather than bit 254. A scalar clamped the X25519 way is a perfectly
  good scalar of the wrong value.
* **There is no spare high bit.** X25519's u coordinate is 255 bits in 32
  bytes, so RFC 7748 says to ignore the top bit; 448 bits is exactly 56
  bytes, so there is no such bit and no masking step. A coordinate at or
  above `p` is reduced rather than refused, which is the same decision
  for the same reason — being stricter than the document breaks
  handshakes against peers doing what it says.

The all-zero refusal is the same:

```rust
use allcrypt::ec::x448;

let (private, _public) = x448::generate_key_pair()?;

let mut low_order_point = [0u8; x448::KEY_LEN];
low_order_point[0] = 1;
assert!(x448::exchange(&private, &low_order_point).is_err());
assert_eq!(x448::x448(&private, &low_order_point)?, [0u8; x448::KEY_LEN]);
```

**Offered by the TLS client and accepted by the server**, as supported
group 30, at TLS 1.2 and 1.3. It is named in `supported_groups` but no
key share is sent for it unsolicited: a share costs a key generation on
every connection — 2.3 ms against X25519's 1.0 ms here — and no server
prefers X448, so one that wants it asks with a HelloRetryRequest. `ED448`
is still not offered as a signature scheme, which is its own decision.

## EdDSA: Ed25519 and Ed448

The signature side of the Edwards curves, RFC 8032. A third shape again:
twisted Edwards arithmetic, little-endian throughout, and a private key
that is **not** the scalar — the scalar is the clamped first half of the
key's hash.

```rust
use allcrypt::ec::eddsa::{self, Variant};

let (private, public) = eddsa::generate_key_pair(Variant::Ed25519)?;
assert_eq!(private.len(), 32);
assert_eq!(public.len(), 32);

let signature = eddsa::sign(Variant::Ed25519, &private, b"a message", &[])?;
assert_eq!(signature.len(), 64);
eddsa::verify(Variant::Ed25519, &public, b"a message", &signature, &[])?;
```

`verify` returns `Ok(())` only for a good signature and an error naming
what was wrong for everything else, rather than a boolean a caller can
forget to check. The facade in `api` makes the other split — `false` for a
well-formed signature that is wrong, `Err` for something that is not a
signature — because that is the shape the Python bindings and the rest of
the library use.

**There is no nonce.** The same key and message always give the same
signature, which is the design rather than a limitation: ECDSA needs a
fresh random nonce per signature and gives up the private key outright if
one is ever reused.

```rust
use allcrypt::ec::eddsa::{self, Variant};

let (private, _public) = eddsa::generate_key_pair(Variant::Ed25519)?;
let first = eddsa::sign(Variant::Ed25519, &private, b"same", &[])?;
let second = eddsa::sign(Variant::Ed25519, &private, b"same", &[])?;
assert_eq!(first, second);
```

Ed448 takes a **context** of up to 255 bytes, which is a domain separator:
the same key and message under two contexts give two unrelated signatures,
and neither verifies under the other. Ed25519 has no context in its pure
form and refuses one rather than ignoring it.

```rust
use allcrypt::ec::eddsa::{self, Variant};

let (private, public) = eddsa::generate_key_pair(Variant::Ed448)?;
let signature = eddsa::sign(Variant::Ed448, &private, b"a message", b"my app")?;
eddsa::verify(Variant::Ed448, &public, b"a message", &signature, b"my app")?;

// The same signature under a different context, or none, is not valid.
assert!(eddsa::verify(Variant::Ed448, &public, b"a message", &signature, &[]).is_err());

// And Ed25519 will not take one at all.
let (private, _public) = eddsa::generate_key_pair(Variant::Ed25519)?;
assert!(eddsa::sign(Variant::Ed25519, &private, b"x", b"ctx").is_err());
```

Ed25519ctx, Ed25519ph and Ed448ph are not implemented. They are separate
schemes over the same two curves, so `api::eddsa_variant` refuses them by
name and says so, rather than treating them as spellings of the pure
variant.

This is the one place in the library where a **modular inversion per
operation** would have been the obvious implementation and is not what
happens: the points are projective, so a scalar multiplication pays one
inversion at the end rather than one per addition. It is also not constant
time — the scalar multiplication branches on each bit of a secret — which
is recorded in [pitfalls.md](pitfalls.md) rather than argued away.

## XEdDSA: signing with an X25519 key

Signal signs with the same Curve25519 key it agrees keys with. A
Montgomery key is only `u`, so the Edwards point it signs as is rebuilt
from it, and which of the two possible points is the whole question.
`ec::xeddsa` has both answers in use:

- `Form::Signal`, libsignal's: the signer's own point, with its sign bit
  carried in the top bit of `S`. This is what Signal's prekeys and group
  messages are signed with.
- `Form::Specification`, the XEdDSA document's: the sign bit is always
  zero, and a key whose point is negative signs with its negation.

```rust
use allcrypt::ec::{x25519, xeddsa::{self, Form}};

let (private, public) = x25519::generate_key_pair()?;
let mut random = [0u8; 64];
allcrypt::random::fill(&mut random)?;
let signature = xeddsa::sign(Form::Signal, &private, b"a message", &random);
xeddsa::verify(Form::Signal, &public, b"a message", &signature)?;

// A specification signature verifies under the Signal verifier for
// every key; the converse holds only for half of them.
let signature = xeddsa::sign(Form::Specification, &private, b"a message", &random);
xeddsa::verify(Form::Signal, &public, b"a message", &signature)?;
```

The 64 random bytes go into the nonce alongside the key and the message,
so the same inputs give the same signature - which is how
`tests/test_xeddsa_vectors.rs` compares this with libsignal-protocol-c
byte for byte. A real signer draws them fresh; `api::xeddsa_sign` does
when given `None`.

Verification accepts what libsignal accepts, and that is looser than RFC
8032 in one place: `S` is checked against `2^253` rather than the group
order, so `S + L` verifies wherever `S` does.
[pitfalls.md](pitfalls.md) section 7zk has the rest.

## NaCl: secretbox, box and sealed boxes

`allcrypt::nacl` is NaCl's boxes and libsodium's additions, byte for
byte with libsodium. A `Construction` picks the stream cipher -
XSalsa20, NaCl's, or XChaCha20, libsodium's - and the combined forms are
the tag followed by the ciphertext.

```rust
use allcrypt::nacl::{self, Construction};

let construction = Construction::XSalsa20Poly1305;
let (alice, alice_public) = nacl::box_seed_keypair(&[1u8; 32])?;
let (bob, bob_public) = nacl::box_seed_keypair(&[2u8; 32])?;
let nonce = [7u8; 24];

let boxed = nacl::box_encrypt(construction, &bob_public, &alice, &nonce, b"hi bob")?;
assert_eq!(boxed.len(), nacl::MAC_BYTES + 6);
assert_eq!(nacl::box_decrypt(construction, &alice_public, &bob, &nonce, &boxed)?, b"hi bob");

// A box is a secretbox under the key both ends agree on.
let key = nacl::box_beforenm(construction, &alice_public, &bob)?;
assert_eq!(nacl::secretbox_decrypt(construction, &key, &nonce, &boxed)?, b"hi bob");

let sealed = nacl::box_seal(Construction::XChaCha20Poly1305, &bob_public, b"anonymous")?;
assert_eq!(nacl::box_seal_open(Construction::XChaCha20Poly1305, &bob_public, &bob, &sealed)?,
           b"anonymous");
```

`api` has the same functions with the construction by name, which is how
Python reaches them. libsodium's XChaCha20 box is a different
construction from the XChaCha20-Poly1305 AEAD in `stream_ciphers`; the
module comment in `src/nacl.rs` lists the three differences.

## Finite-field Diffie-Hellman

The other kind of Diffie-Hellman: the one in a multiplicative group mod a
prime, which is what a server too old for elliptic curves offers.

```rust
use allcrypt::publickey_ciphers::dh::{modp_group, MODP_2048};

let group = modp_group(MODP_2048)?;          // RFC 3526 group 14
assert_eq!(group.bits(), 2048);

let (my_private, my_public) = group.generate_key_pair()?;
let (their_private, their_public) = group.generate_key_pair()?;

let mine = group.shared_secret(&my_private, &their_public)?;
let theirs = group.shared_secret(&their_private, &my_public)?;
assert_eq!(mine, theirs);
assert_eq!(mine.len(), 256);                 // padded to the width of p
```

A group can also be built from numbers that arrived from somewhere, which
is what the TLS client does with a ServerKeyExchange:

```rust
use allcrypt::bignum::BigUint;
use allcrypt::publickey_ciphers::dh::{modp_group, DhGroup, MODP_1024};

let wire = modp_group(MODP_1024)?;
let group = DhGroup::from_bytes(&wire.p().to_bytes_be(), &[2])?;

// Size is a policy question, asked separately from "is this a group".
assert!(group.check_size(2048).is_err());    // 1024 bits, Logjam territory
assert!(group.check_size(1024).is_ok());     // reachable on purpose

// Three peer values must never be accepted: they make the shared secret
// a constant, or leak the parity of our own exponent.
let p_minus_1 = group.p().sub(&BigUint::one())?;
for bad in [BigUint::zero(), BigUint::one(), p_minus_1] {
    assert!(group.validate_peer(&bad).is_err());
}
```

`check_prime` is there for the case that matters most and costs most: a
server sending a composite modulus makes the shared secret computable by
whoever chose it, while the handshake looks perfect. It is several
full-width exponentiations, so it is a question you ask rather than
something done for you.

One convention to know about: `shared_secret` pads to the width of `p`, and
TLS 1.0-1.2 then strip those zeros again for the premaster secret
(`strip_leading_zeros`, RFC 5246 §8.1.2) while TLS 1.3 keeps them. It
differs about one exchange in 256. See [pitfalls.md](pitfalls.md) §3b.

## ElGamal

ElGamal is Diffie-Hellman turned into an encryption scheme, and
separately into a signature scheme. Both live in the same group, so the
module is built on `DhGroup` — the validation a group and a public value
need is exactly what Diffie-Hellman needs.

It is here for **old PGP keyrings**. OpenPGP algorithm 16 is ElGamal
encryption, and it was GnuPG's default encryption subkey for years — the
`elg` half of the `dsa/elg` keypairs everybody was told to make through
the 2000s. Those keys are still in keyrings and those messages are still
in archives. OpenSSL dropped ElGamal entirely and `python-cryptography`
has never had it.

```rust
use allcrypt::publickey_ciphers::dh::{modp_group, MODP_1024};
use allcrypt::publickey_ciphers::elgamal::{decrypt_pkcs1v15,
                                           encrypt_pkcs1v15,
                                           ElGamalPrivateKey};

let group = modp_group(MODP_1024)?;
let key = ElGamalPrivateKey::generate(group)?;

// OpenPGP's framing: PKCS#1 v1.5 inside the raw scheme. The ciphertext
// is `c1 || c2`, so twice the modulus width.
let sealed = encrypt_pkcs1v15(key.public(), b"from an old keyring")?;
assert_eq!(sealed.len(), 2 * key.public().size());
assert_eq!(decrypt_pkcs1v15(&key, &sealed)?, b"from an old keyring");
```

**Use the padded functions.** Raw ElGamal is malleable: multiply `c2` by
`t` and the plaintext is multiplied by `t`, with no key and no way to
tell. That is why OpenPGP pads, and `elgamal::ElGamalPublicKey::encrypt`
exists for the cases that specify their own framing.

Signing is here too, and comes with a warning. **GnuPG withdrew ElGamal
signing in 2003** after Phong Nguyen showed that its sign+encrypt keys
were broken — to make signing fast it used a short nonce, and a short
nonce in the signature equation recovers the private key. That was a
flaw in one implementation's choice of `k`, not in the equation, and the
scheme is here because old signatures still need verifying. `k` is drawn
full width and redrawn until it is coprime to `p-1`.

Verification range-checks `r` and `s`. That is not a formality:
Bleichenbacher showed in 1996 that a verifier accepting `r >= p` can be
handed a forged signature for a chosen message, and the check is
invisible against honest signatures.

## ECDSA

Signatures use deterministic nonces (RFC 6979), so no random source is
involved and the same key and digest always produce the same bytes:

```rust
use allcrypt::ec::curves;
use allcrypt::hash_functions::{sha2::SHA256, HashFunction};

let curve = curves::p256();
let (private, public) = curve.generate_key_pair()?;

let digest = SHA256::new(b"the message").digest();

// The hash passed to `sign` must be the one that produced the digest:
// RFC 6979 derives the nonce with an HMAC over that same hash.
let signature = curve.sign(&private, &digest, SHA256::new(b""))?;
assert!(curve.verify(&public, &digest, &signature)?);

// Deterministic, so this is byte for byte the same signature.
assert_eq!(curve.sign(&private, &digest, SHA256::new(b""))?, signature);

// r || s, each padded to the field size.
assert_eq!(signature.to_bytes(&curve)?.len(), 64);
```

The nonce is the one part of ECDSA that leaks the private key when it goes
wrong, and it goes wrong quietly: reuse it once and two signatures give the
key away, bias it slightly and enough signatures do the same. Deriving it
from the key and the message removes the question. Nothing in `ec::ecdsa`
calls `random`.

`verify` takes no hash, because verification never derives a nonce. It
returns `false` for a signature that is well formed and wrong, and an error
for something that is not a signature — a point off the curve, the wrong
number of bytes.

Checked against OpenSSL in `tools/src/bin/diff_ec.rs` and `tools/src/bin/diff_ecdsa.rs`:
324 cases over the three curves covering `k*G`, both encodings and ECDH, plus
396 signatures that OpenSSL verifies, over four hashes and eleven message
lengths. Note that the curve
constants themselves are checked rather than trusted — a unit test verifies
that G is on the curve and that `n*G` is the identity, which a typo in any
of p, a, b, Gx, Gy or n would break.

## DSA

`publickey_ciphers::dsa` is FIPS 186-4's DSA with RFC 6979 nonces;
`api::DsaKey` wraps it with DER signatures over a hashed message, which
is the shape certificates and TLS use:

```rust
use allcrypt::api::DsaKey;
use allcrypt::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey};

// A group search takes seconds; (1024, 160) is the size old boxes have.
let parameters = DsaParameters::generate(1024, 160)?;
let raw = DsaPrivateKey::generate(parameters)?;
let p = raw.public.parameters.p.to_bytes_be();
let q = raw.public.parameters.q.to_bytes_be();
let g = raw.public.parameters.g.to_bytes_be();
let key = DsaKey::from_numbers(&p, &q, &g, &raw.x().to_bytes_be())?;
let signature = key.sign("sha1", b"message")?;
assert!(key.verify("sha1", b"message", &signature)?);
```

In X.509 a DSA key is `x509::PublicKey::Dsa` and its signatures
`SignatureAlgorithm::Dsa(hash)`; `x509::builder` takes `SigningKey::Dsa`
and `SubjectKey::Dsa`, and `x509::private_key` reads PKCS#8 and the
traditional `DSA PRIVATE KEY`. The group is held to `min_rsa_bits`.

## RSA

`publickey_ciphers::rsa` has the primitives, key generation, PKCS#1 v1.5
for both encryption and signatures, PSS signatures and OAEP encryption.

```rust,ignore
use allcrypt::hash_functions::{sha2::SHA256, HashFunction};
use allcrypt::publickey_ciphers::rsa::{self, RsaPrivateKey};

// Generation searches for primes, so it is slow and of unpredictable
// duration - about 350 ms for 2048 bits here. Do it in advance.
let key = RsaPrivateKey::generate(2048)?;

let ciphertext = rsa::encrypt_pkcs1v15(&key.public, b"a short message")?;
assert_eq!(rsa::decrypt_pkcs1v15(&key, &ciphertext)?, b"a short message");

let digest = SHA256::new(b"a message").digest();
let signature = rsa::sign_pkcs1v15(&key, "sha256", &digest)?;
assert!(rsa::verify_pkcs1v15(&key.public, "sha256", &digest, &signature)?);

// OAEP: the label's hash, MGF1's hash, the label.
let sealed = rsa::encrypt_oaep(&key.public, "sha256", "sha256", b"context", b"a short message")?;
assert_eq!(rsa::decrypt_oaep(&key, "sha256", "sha256", b"context", &sealed)?,
           b"a short message");
```

That example is `,ignore` for one reason: it generates a key, and the
documentation check runs on every build. The same code with a key built from
known primes is in the module's tests.

Three things it does that are easy to leave out, and each of which is an
attack if you do:

- **The CRT result is verified before it is returned.** One flipped bit in a
  CRT private operation lets an attacker factor the modulus from a single
  bad signature. The check costs one public exponentiation, under 2% of a
  signature.
- **Private operations are blinded.** The bignum underneath is not constant
  time, so the duration of `c^d mod n` depends on `c` — which the attacker
  chooses. Blinding means the arithmetic runs on a value they cannot predict.
- **Decryption reports nothing about why it failed.** One error for every
  failure, because distinguishing them is Bleichenbacher's attack. A caller
  that catches it and reports the difference has rebuilt the oracle.
- **OAEP's padding check is branch-free on the decrypted block**, and
  `scripts/ct_check.py` measures it (`rsa_oaep_decode`): the label hash
  comparison, the leading byte and the scan for the separator fold into
  one mask. Learning only whether the leading byte was zero is Manger's
  attack. `eme_oaep_decode` is the check alone, public so it can be
  tested apart from the private operation; Wycheproof's 898 OAEP vectors
  run against both (`tests/test_rsa_oaep.rs`).

Verification compares the whole recovered block against the one it would
have produced, rather than parsing it — parsing is the 2006 forgery.

Timings on this machine, 2048 bit: sign 5.2 ms, decrypt 5.2 ms, verify 72 µs,
encrypt 75 µs, key generation ~350 ms. Run `tools/src/bin/bench_rsa.rs` for yours.

`is_probably_prime(&n, rounds)` is public, since a Miller-Rabin test is
useful on its own. The bases are random rather than fixed: composites that
pass any fixed set of bases can be constructed deliberately.

## ASN.1 and DER

`asn1` is a strict DER reader and writer. Strict is the point: DER has
exactly one encoding for every value, and a parser that accepts a second one
lets an attacker produce two byte strings that mean the same thing to the
verifier and hash differently.

```rust
use allcrypt::asn1::{encode_oid, Reader, Writer};

// The closure's job is only to write, so anything fallible - encoding an
// OID, say - happens before it.
let algorithm = encode_oid("1.2.840.113549.1.1.11")?;

let mut writer = Writer::new();
writer.write_sequence(|w| {
    w.write_u32(65537);
    w.write_oid(&algorithm);
    w.write_octet_string(b"hello");
});
let der = writer.finish();

let mut reader = Reader::new(&der);
let mut sequence = reader.read_sequence()?;
assert_eq!(sequence.read_u32()?, 65537);
assert_eq!(sequence.read_oid()?.to_string(), "1.2.840.113549.1.1.11");
assert_eq!(sequence.read_octet_string()?, b"hello");
sequence.finish()?;      // errors if anything is left over
reader.finish()?;
```

Things it refuses, each of which has been a real parser bug somewhere: an
indefinite length, a non-minimal length, a redundant leading byte in an
INTEGER, a BOOLEAN that is not `0x00` or `0xFF`, a BIT STRING whose unused
bits are not zero, a non-minimal OID subidentifier, and nesting deeper than
`MAX_DEPTH`. `finish()` is an error if bytes remain, because trailing data
after a structure is how a second interpretation gets smuggled past a
verifier.

`read_raw` returns a value with its tag and length still attached. That is
what signature verification needs: the exact bytes that arrived, not a
re-encoding of what we understood them to mean.

## GOST

Everything RFC 9189's suites are built on, none of which anything else on
a normal machine implements. The ciphers and hash go through the same
facades as everything here, so nothing new is needed to reach them:

```rust
use allcrypt::api::{AnyBlockCipher, AnyHash};
use allcrypt::block_ciphers::BlockCipher;
use allcrypt::hash_functions::HashFunction;

// GOST R 34.12-2015, section A.1.
let key = [0x88u8, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
           0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
           0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
let mut cipher = AnyBlockCipher::new("kuznyechik", &key, None)?;
let mut out = Vec::new();
cipher.block_encrypt(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
                       0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88], &mut out);
assert_eq!(out.len(), 16);

// Streebog. "streebog" alone means the 256 bit one, which is what
// RFC 9189 uses; it is not the 512 bit one truncated.
let mut hash = AnyHash::new("streebog256")?;
hash.update(b"");
assert_eq!(hash.digest().len(), 32);

// GOST R 34.11-94, the hash Streebog replaced and what the 0x0081 TLS
// suite still uses. "gost94" is the CryptoPro parameter set, which is
// what certificates carry; "gost94_test" is the standard's own test
// S-box and a different hash of the same message.
let mut old_hash = AnyHash::new("gost94")?;
old_hash.update(b"This is message, length=32 bytes");
assert_eq!(old_hash.digest().len(), 32);
```

`magma` is there too. It is GOST 28147-89 with a fixed S-box read **big
endian**, so the same key and plaintext give a different answer under the
two standards and both are correct — which is why `gost` and `magma` are
separate names rather than aliases.

The asymmetric half lives on `Curve`, alongside ECDSA:

```rust,ignore
use allcrypt::ec::curves;
use allcrypt::hash_functions::streebog::Streebog;

let curve = curves::by_name("gost256-a")?;          // = CryptoPro-A
let (private, public) = curve.generate_key_pair()?;

// GOST R 34.10-2012. Not ECDSA: the digest is read little endian, the
// signing equation has no inversion in it, and the encoding is s || r.
let signature = curve.gost_sign(&private, &digest, Streebog::new_256(&[]))?;
assert!(curve.gost_verify(&public, &digest, &signature)?);
let wire = curve.gost_signature_bytes(&signature)?;   // s first

// VKO (RFC 7836). Not ECDH with a hash on the end.
let key = curve.vko(&private, &peer_point, b"user keying material", 256)?;

// And on the two curves whose cofactor is four, which reading of the
// scalar. `vko` above is the document's; this is OpenSSL's GOST
// engine's, which is what the TLS key exchange here uses.
use allcrypt::ec::vko::Cofactor;
let deployed = curve.vko_using(&private, &peer_point, b"user keying material",
                               256, Cofactor::AsDeployed)?;
```

The key derivation and the record protection RFC 9189's cipher suites use
sit on top of those:

```rust
use allcrypt::kdf::gost::{kdf_gostr3411_2012_256, tlstree, TlsTree, TlsTreeParams};
use allcrypt::tls::record::SequenceNumber;
use allcrypt::tls::record_gost::{encrypt, decrypt, CtrOmac, CtrOmacSuite};
use allcrypt::tls::{ContentType, Version};

// KDF_GOSTR3411_2012_256 (RFC 7836 4.5): one framed HMAC-Streebog-256.
let derived = kdf_gostr3411_2012_256(&[0x11; 32], b"label", b"seed");
assert_eq!(derived.len(), 32);

// TLSTREE (RFC 9189 8.1): three of those chained over a masked sequence
// number, so every record gets its own key. The constants are per suite
// and are not interchangeable.
let root = [0x22u8; 32];
// (64 is past Kuznyechik's third-level boundary and not past Magma's.
// At sequence 0 every mask is zero and the two suites agree.)
let record_key = tlstree(&root, 64, TlsTreeParams::MAGMA);
assert_ne!(record_key, tlstree(&root, 64, TlsTreeParams::KUZNYECHIK));

// `TlsTree` caches the upper levels, which is the point of the shape:
// the first level changes once in billions of records.
let mut tree = TlsTree::new(&root, TlsTreeParams::MAGMA);
assert_eq!(tree.key(64), record_key);

// The CTR_OMAC key exchange (RFC 9189 4.2.4.1). The client picks a 32
// byte preliminary secret and wraps it under keys agreed against the
// server's certificate key - there is no ServerKeyExchange.
use allcrypt::ec::curves;
use allcrypt::tls::gost_kex::{algorithm_id_for, client_key_exchange,
                              unwrap_secret};

let curve = curves::by_name("gost256-a")?;
let (server_private, server_public) = curve.generate_key_pair()?;
let (client_random, server_random) = ([1u8; 32], [2u8; 32]);

// The ephemeral key in the message wears the **server's**
// `AlgorithmIdentifier`, copied from its certificate, so it is an input
// here rather than something derived from the curve. Several parameter
// set OIDs name each of these curves - `XchA` is CryptoPro-A to the
// digit - and a client that rebuilt the OID from the curve answered a
// server on one spelling with the other, which CryptoPro refuses with
// `decode_error`. `algorithm_id_for` gives the canonical one, which is
// what to use only when *you* are choosing the curve.
let server_algorithm_id = algorithm_id_for(&curve)?;

let (message, premaster) = client_key_exchange(
    CtrOmacSuite::MAGMA, &curve, &server_algorithm_id, &server_public,
    &client_random, &server_random)?;
assert_eq!(premaster.len(), 32);

// What the server does with it, here only so the example is complete.
assert_eq!(unwrap_secret(CtrOmacSuite::MAGMA, &curve, &server_private,
                         &client_random, &server_random, &message)?,
           premaster);

// The CNT_IMIT suite is a different construction at every level: one
// keystream and one cumulative MAC for the whole connection, so the
// state is built once per direction and kept.
use allcrypt::tls::record_cnt_imit::{self, CntImit};

let mut sender = CntImit::new(&[0x33; 32], &[0x44; 32], &[0; 8])?;
let mut receiver = CntImit::new(&[0x33; 32], &[0x44; 32], &[0; 8])?;
for n in 0..3u64 {
    let wire = record_cnt_imit::encrypt(
        &mut sender, SequenceNumber::at(n), ContentType::ApplicationData,
        Version::TLS12, b"same payload").map_err(|e| e.describe())?;
    let back = record_cnt_imit::decrypt(
        &mut receiver, SequenceNumber::at(n), ContentType::ApplicationData,
        Version::TLS12, &wire).map_err(|e| e.describe())?;
    assert_eq!(back, b"same payload");
}

// CTR_OMAC record protection (RFC 9189 4.1.1). One value per direction,
// holding both trees and the IV; the sequence number is passed in.
let mut out = CtrOmac::new(CtrOmacSuite::MAGMA, &[0x33; 32], &[0x44; 32],
                           &[0, 0, 0, 0])?;
let mut back = CtrOmac::new(CtrOmacSuite::MAGMA, &[0x33; 32], &[0x44; 32],
                            &[0, 0, 0, 0])?;
let wire = encrypt(&mut out, SequenceNumber::at(7), ContentType::ApplicationData,
                   Version::TLS12, b"payload")
           .map_err(|e| e.describe())?;
let plain = decrypt(&mut back, SequenceNumber::at(7), ContentType::ApplicationData,
                    Version::TLS12, &wire)
            .map_err(|e| e.describe())?;
assert_eq!(plain, b"payload");
```

Seven things worth knowing before using any of it, each with its own
entry in [pitfalls.md](pitfalls.md):

**Streebog's published test vectors are printed backwards.** The standard
writes messages and digests as 512-bit numbers, most significant byte
first; every implementation works on byte strings in order. The symptom of
not knowing that is identical to a wrong implementation.

**GOST R 34.10-2012 is not ECDSA with different curves.** Four
differences, every one silent: the little-endian digest, the inversion-free
signing equation, the `s ‖ r` wire order, and the component width coming
from the group order rather than the field.

**VKO is symmetric, so two wrong implementations agree perfectly.** Both
sides compute `ukm · da · db · G` and the order does not matter, so a
round trip against yourself produces a matching key however the UKM and
the coordinates are serialised. Only a second implementation can see it,
which is what `scripts/diff_check.py` is.

**VKO's cofactor is not settled by any document.** RFC 7836 writes the
scalar as `m/q · UKM · x mod q`; OpenSSL's GOST engine computes it
without the `m/q`. The two are the same number on the seven curves with
`h = 1` and a different point on `gost256-tc26-a` and `gost512-c`, where
no published vector says which is right. `Cofactor::AsSpecified` and
`Cofactor::AsDeployed` name the two, `Curve::vko` is the document's, and
the TLS key exchange asks for the deployed one — because its job is to
reach equipment, and the equipment runs gost-engine.

**TLSTREE's counter is big endian and its constants are per suite.** RFC
9189 defines `STR_8` and `str_8`, big and little endian, and uses both.
At sequence number 0 every mask is zero, so the two suites agree there
and so does a mask with a bit wrong — the first record of a connection
cannot distinguish any of the three mistakes.

**CNT_IMIT is cumulative in both halves**, which is the opposite of
CTR_OMAC: one keystream and one running MAC for the whole connection,
so each record's tag covers every record before it. Rebuilding the state
per record repeats the keystream, and round-trips perfectly against an
implementation doing the same. Its tag is also four bytes, so a blind
forgery succeeds once in 2^32 attempts — which is the reason to prefer
the other two where there is a choice.

**CTR_OMAC starts a fresh keystream per record.** That is the opposite
of RC4, where it runs for the whole connection, and the difference shows
on the second record rather than the first. The IV is *added to* the
sequence number and wraps in its own width, which is four bytes for
Magma — the reason that suite's sequence number is capped at 2^32-1, and
`CtrOmac` refuses past it rather than wrapping.

And the honest caveat for all of it: **nothing on a normal machine
implements any of these.** OpenSSL is built without the GOST engine and
`python-cryptography` has never offered them, so the differential
references are a second reading of the standards rather than somebody
else's code — the same position as SSLv3. Each algorithm is additionally
pinned to its own standard's published vectors, and the constant tables
were cross-checked between independent projects rather than transcribed.

## Post-quantum: SLH-DSA

FIPS 205, the hash-based signature scheme that used to be called SPHINCS+.
Key generation, signing and verification, through both the internal and
the external interface, with all twelve pre-hash functions.

Twelve parameter sets, named as FIPS 205 names them. The name is matched
exactly, because these are fixed strings in a standard rather than
identifiers anyone types:

```rust
use allcrypt::pq::slh_dsa;

let set = slh_dsa::parameters("SLH-DSA-SHAKE-128f")?;
assert_eq!((set.n, set.h, set.d, set.h_prime), (16, 66, 22, 3));
assert_eq!(set.len(), 35);              // hash chains in a WOTS+ key
assert_eq!(set.public_key_len(), 32);   // PK.seed ‖ PK.root
assert_eq!(set.secret_key_len(), 64);   // SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root

// `slh_keygen_internal` in FIPS 205: the three seeds are the caller's.
// Fixed bytes here so the example is reproducible — a real key takes them
// from `allcrypt::random`, and a key generated from a guessable seed is
// a key anyone else can generate too.
let sk_seed = [0x01u8; 16];
let sk_prf = [0x02u8; 16];
let pk_seed = [0x03u8; 16];

let (secret, public) =
    slh_dsa::key_gen_internal(set, &sk_seed, &sk_prf, &pk_seed)?;

assert_eq!(public.len(), set.public_key_len());
assert_eq!(secret.len(), set.secret_key_len());

// The public key is the tail of the private one, which is worth knowing
// before writing a parser for either.
assert_eq!(&secret[2 * set.n..], &public[..]);
assert_eq!(&public[..set.n], &pk_seed[..]);
```

`slh_dsa::PARAMETER_SETS` is the whole table if you want to iterate it.

### Signing and verifying

`sign` and `verify` are the ones to use. They take a **context string**,
which is a domain separator, and an optional **pre-hash**:

```rust
use allcrypt::pq::slh_dsa::{self, PreHash};

let set = slh_dsa::parameters("SLH-DSA-SHAKE-128f")?;
let (secret, public) = slh_dsa::key_gen_internal(
    set, &[0x01u8; 16], &[0x02u8; 16], &[0x03u8; 16])?;

// `opt_rand` is the last argument and it chooses the mode. PK.seed — the
// third quarter of the private key — gives the deterministic signature
// FIPS 205 defines; `n` fresh random bytes give a hedged one. Both are
// standard and they differ.
let pk_seed = secret[2 * set.n..3 * set.n].to_vec();

// No context, no pre-hash: the plain case.
let signature = slh_dsa::sign(set, &secret, b"a message", b"", None,
                              &pk_seed)?;
assert_eq!(signature.len(), set.signature_len());
assert!(slh_dsa::verify(set, &public, b"a message", b"", None, &signature)?);

// A context separates one use of a key from another. A signature made
// under one context does not verify under another, which is the point.
let scoped = slh_dsa::sign(set, &secret, b"a message", b"invoice v1", None,
                           &pk_seed)?;
assert!(slh_dsa::verify(set, &public, b"a message", b"invoice v1", None,
                        &scoped)?);
assert!(!slh_dsa::verify(set, &public, b"a message", b"invoice v2", None,
                         &scoped)?);

// Pre-hashing signs a digest instead of the message, which is what you
// want when the message is large or arrives in pieces. The hash function
// is part of what gets signed, so a SHA-256 signature is not a SHA3-256
// one even though both digests are 32 bytes.
let prehashed = slh_dsa::sign(set, &secret, b"a message", b"",
                              Some(PreHash::Sha256), &pk_seed)?;
assert!(slh_dsa::verify(set, &public, b"a message", b"",
                        Some(PreHash::Sha256), &prehashed)?);
assert!(!slh_dsa::verify(set, &public, b"a message", b"",
                         Some(PreHash::Sha3_256), &prehashed)?);
```

A context is at most 255 bytes — its length is written in one byte — and a
longer one is refused rather than truncated.

`slh_dsa::PRE_HASHES` is all twelve, and `PreHash::by_name` takes NIST's
own spelling (`"SHA2-512/224"`, `"SHAKE-128"`).

`sign_internal` and `verify_internal` are the layer underneath, without the
wrapping. Use them only if a protocol specifies the internal interface:
they sign a different byte string, so their signatures are not
interchangeable with `sign`'s.

Two things about `verify`'s signature that are deliberate:

* It returns `Ok(false)` for a signature that is well formed and wrong,
  and `Err` only when an input could never have been a signature — a
  public key of the wrong length. A signature of the wrong *length* is
  `Ok(false)`, not an error, so a caller handed a truncated one does not
  need a second code path.
* Signing takes `opt_rand` rather than drawing it. That is what makes it
  testable against NIST's vectors, which state it. A wrapper that draws
  from `allcrypt::random` is the right public API and belongs on top.

**A hedged signature needs real randomness.** Passing a counter, a
timestamp, or the same value twice for two different messages is worse
than passing `PK.seed`: the deterministic mode is at least well defined.

### Which set to pick, and what it costs

`s` and `f` mean "small signature" and "fast signing", and the difference is
the tree shape: `s` has a few tall trees, `f` has many short ones. That
inverts for key generation — a key is the root of a Merkle tree over `2^h'` one-time keys, and **every leaf has
to be computed to get the root**:

| Parameter set | `h'` | One-time keys per key | Rough cost |
|---|---|---|---|
| `…-128f`, `…-192f` | 3 | 8 | milliseconds |
| `…-256f` | 4 | 16 | milliseconds |
| `…-256s` | 8 | 256 | ~250k hash calls |
| `…-128s`, `…-192s` | 9 | 512 | ~270k–390k hash calls |

So generating an `s` key takes visible time — a second or so in a release
build, twenty in a debug one. That is the algorithm, not this
implementation: there is no shortcut to a Merkle root.

Signatures are large in every set: 7,856 bytes at `SLH-DSA-SHA2-128s`
and 49,856 at `SLH-DSA-SHAKE-256f`. If that is a problem, ML-DSA is the
lattice signature standard, and it is not built yet.

### From Python

`allcrypt.SlhDsaKey` wraps the external interface — see
[python.md](python.md#post-quantum-slh-dsa). `api::SlhDsaKey` is the layer
it translates, and it is the right thing to use from Rust too unless you
want to supply your own seeds or `opt_rand`:

```rust
use allcrypt::api::SlhDsaKey;

let key = SlhDsaKey::generate("SLH-DSA-SHAKE-128f")?;
let signature = key.sign(b"a message", b"", None)?;   // hedged
assert!(key.verify(b"a message", b"", None, &signature)?);
assert_eq!(key.public_bytes(), &key.private_bytes()[32..]);
```

The internal interface has no Python binding on purpose: signatures made
with it are not ones another implementation's default verifier accepts, so
the obvious thing to reach for should not be that one.

## Post-quantum: ML-KEM

FIPS 203's key encapsulation mechanism, in its three parameter sets
`ML-KEM-512`, `ML-KEM-768` and `ML-KEM-1024`. `api::MlKemKey` is the
decapsulation key and `api::MlKemPublicKey` the encapsulation key; they
draw their randomness from the OS:

```rust
use allcrypt::api::{MlKemKey, MlKemPublicKey};

let key = MlKemKey::generate("ML-KEM-768")?;
let published = key.public_bytes();            // 1,184 bytes

let theirs = MlKemPublicKey::from_public("ML-KEM-768", published)?;
let (shared, ciphertext) = theirs.encapsulate()?;   // keep, send
assert_eq!(key.decapsulate(&ciphertext)?, shared);

// 64 bytes of seed, d || z, in place of the 2,400 byte key.
let seed = [9u8; 64];
let a = MlKemKey::from_seed("ML-KEM-768", &seed)?;
let b = MlKemKey::from_seed("ML-KEM-768", &seed)?;
assert_eq!(a.private_bytes(), b.private_bytes());
```

`from_public` and `from_private` run FIPS 203's modulus check and hash
check respectively, and refuse a key that fails. Neither key type has
`Debug` or `Clone`.

`allcrypt::pq::ml_kem` is the layer underneath, with key generation,
encapsulation and decapsulation as FIPS 203 states them, **taking their
random inputs as arguments** - the seeds `d` and `z`, and the
encapsulation's `m` - because that is what NIST's vectors state:

```rust
use allcrypt::pq::ml_kem;

let set = ml_kem::parameters("ML-KEM-768")?;
// d and z must be 32 fresh random bytes each in real use; m likewise.
let (ek, dk) = ml_kem::key_gen_internal(set, &[1u8; 32], &[2u8; 32])?;
assert_eq!((ek.len(), dk.len()), (1184, 2400));

// The sender has only ek.
let (shared, ciphertext) = ml_kem::encapsulate_internal(set, &ek, &[3u8; 32])?;
assert_eq!(ciphertext.len(), set.ciphertext_len());

// The holder of dk recovers the same 32 byte secret.
assert_eq!(ml_kem::decapsulate_internal(set, &dk, &ciphertext)?, shared);

// An altered ciphertext is NOT an error: it gives a different secret,
// derived from dk's hidden seed z and the ciphertext. Reporting the
// mismatch would be a decryption oracle.
let mut altered = ciphertext;
altered[0] ^= 1;
let other = ml_kem::decapsulate_internal(set, &dk, &altered)?;
assert_ne!(other, shared);
```

`Err` from these means a malformed **public** input, decided before
anything secret is touched: `m` not 32 bytes, an encapsulation key that
fails FIPS 203's modulus check (a non-canonical coefficient), a ciphertext
of the wrong length, or a decapsulation key whose embedded `H(ek)` does
not match. `modulus_check` and `hash_check` are public if you want the
verdict without the operation.

Nothing checks this against a second implementation yet - only against
NIST's 195 ACVP cases, 30 of them keys that must be refused. See
[post-quantum.md](post-quantum.md) and section 7v of
[pitfalls.md](pitfalls.md).

## Post-quantum: ML-DSA

FIPS 204's lattice signatures. `api::MlDsaKey` and `api::MlDsaPublicKey`
are the external interface, hedged by default:

```rust
use allcrypt::api::{MlDsaKey, MlDsaPublicKey};

let key = MlDsaKey::generate("ML-DSA-44")?;
let signature = key.sign(b"a message", b"", None)?;
assert_eq!(signature.len(), 2420);

let public = MlDsaPublicKey::from_public("ML-DSA-44", key.public_bytes())?;
assert!(public.verify(b"a message", b"", None, &signature)?);
// A different context, a different pre-hash, a different message: false.
assert!(!public.verify(b"a message", b"ctx", None, &signature)?);
assert!(!public.verify(b"a message", b"", Some("SHA2-256"), &signature)?);
```

`allcrypt::pq::ml_dsa` is the layer underneath: `key_gen_internal` from
a 32 byte seed, `sign_internal`/`verify_internal` on `M'` as given,
`sign_mu`/`verify_mu` from an externally computed `mu`, and
`sign`/`verify` for the external interface with the randomness `rnd` as
an argument - 32 zero bytes is the deterministic variant.

```rust
use allcrypt::pq::ml_dsa;

let set = ml_dsa::parameters("ML-DSA-65")?;
let (pk, sk) = ml_dsa::key_gen_internal(set, &[1u8; 32])?;
let a = ml_dsa::sign(set, &sk, b"m", b"", None, &[0u8; 32])?;
let b = ml_dsa::sign(set, &sk, b"m", b"", None, &[0u8; 32])?;
assert_eq!(a, b, "deterministic");
assert!(ml_dsa::verify(set, &pk, b"m", b"", None, &a)?);

// The private key does not contain the public key; it can be recomputed.
assert_eq!(ml_dsa::public_from_private(set, &sk)?, pk);
```

A signature that does not verify - wrong, wrong length, malformed hint -
is `Ok(false)`. `Err` is for a public key of the wrong length, a context
over 255 bytes, or an unknown pre-hash name.

In certificates (RFC 9881) the key is `x509::PublicKey::MlDsa` and the
signature `SignatureAlgorithm::MlDsa`; `x509::builder` signs with
`SigningKey::MlDsa`, and `api::CertificateAuthority` issues them when
its key type is a parameter set. A private key file in any of RFC 9881's
three forms is `x509::private_key::PrivateKey::MlDsa`:

```rust
use allcrypt::api::CertificateAuthority;
use allcrypt::x509::{verify, Certificate, PublicKey};

let ca = CertificateAuthority::generate_with("ML-DSA-44", "Example PQ CA",
                                             "20250101000000Z", "20350101000000Z")?;
let (leaf, seed) = ca.issue("localhost", "20250101000000Z", "20350101000000Z")?;
let leaf = Certificate::parse(&leaf)?;
let root = Certificate::parse(ca.certificate())?;
assert!(matches!(leaf.public_key, PublicKey::MlDsa { parameter_set: "ML-DSA-44", .. }));
verify::verify_signature(&leaf, &root, &verify::Policy::default())?;
assert_eq!(seed.len(), 32);
```

At TLS 1.3 the schemes are `mldsa44`, `mldsa65` and `mldsa87`
(`tls::handshake13::scheme::MLDSA44` and so on): `tls::server::ServerKey::MlDsa`
and `tls::client::ClientKey::MlDsa` sign with them, and both ends verify
them. Neither key authenticates anything at TLS 1.2.

## X.509 certificates

Parsing and judging are separate. `Certificate::parse` reads and does not
decide — an expired certificate parses, one signed with MD5 parses — and
`verify` applies policy.

```rust,ignore
use allcrypt::x509::verify::{verify_chain, matches_hostname, Policy, Purpose};
use allcrypt::x509::Certificate;

let leaf = Certificate::parse(&leaf_der)?;
let intermediate = Certificate::parse(&intermediate_der)?;
let root = Certificate::parse(&root_der)?;

println!("{}", leaf.subject.to_string());
println!("valid until {}", leaf.not_after);
println!("{:?}", leaf.extensions.dns_names());

let policy = Policy::at(now_in_seconds);
verify_chain(&[leaf, intermediate], &[root], &policy, Purpose::ServerAuth)?;
```

`Policy` is where "talk to old things" lives. The defaults refuse SHA-1, MD5
and RSA keys under 2048 bits; `Policy::legacy(now)` accepts all three, and
it is a named constructor rather than a set of flags so that using it is a
decision somebody made rather than a default somebody inherited.

Hostname matching is RFC 6125: a subjectAltName wins over the common name, a
wildcard covers exactly one label and only the leftmost one, and `*.com`
matches nothing.

```rust,ignore
if !matches_hostname(&leaf, "example.test") {
    return Err("certificate is for somebody else".into());
}
```

### Name constraints

A CA certificate may carry a nameConstraints extension saying which names
the certificates below it may have, and `verify_chain` enforces it — for
dNSName, rfc822Name, uniformResourceIdentifier, iPAddress and
directoryName. Nothing has to be switched on: a CA that says what it may
issue for is making a promise the relying party is the only one who can
keep.

This is what makes a private root safe to add to a store. Without it,
trusting a company's internal CA means trusting it for `google.com`.

```rust,ignore
let constraints = &intermediate.extensions.name_constraints;
if let Some(constraints) = constraints {
    println!("{} permitted subtrees, {} excluded",
             constraints.permitted.len(), constraints.excluded.len());
}
```

Two things worth knowing before writing one. A **dNSName** base covers
itself and every name below it, so `example.test` admits
`www.example.test`; a **URI or rfc822Name** base without a leading period
is one host exactly, and with one is strictly below it, so
`.example.test` does *not* admit `example.test`. And an **iPAddress
subtree is an address followed by a mask** — eight bytes for IPv4, where
the same field in a subjectAltName is four.

`x509::builder` goes the other way and produces signed certificates, which
is how the verifier's tests get chains that are real rather than
hand-assembled — and what a client certificate or a private test CA needs.

### Revocation

`verify_chain_with_crls` takes the same arguments plus a slice of parsed
CRLs. Nothing here fetches one — no socket is opened anywhere in this
library — so the caller brings the bytes.

```rust,ignore
use allcrypt::x509::crl::{distribution_points, CertificateList};
use allcrypt::x509::verify::verify_chain_with_crls;

// Where the certificate says its list lives. Fetching it is your job.
for uri in distribution_points(&leaf) {
    println!("{}", uri);
}

let crls: Vec<CertificateList<'_>> = fetched.iter()
    .map(|der| CertificateList::parse(der))
    .collect::<Result<_, _>>()?;

verify_chain_with_crls(&[leaf, intermediate], &[root], &policy,
                       Purpose::ServerAuth, &crls)?;
```

Every certificate in the chain is checked, not only the leaf: a revoked
*intermediate* is the case revocation exists for.

`crl::check` answers on its own with three values, and the third is the
point:

```rust,ignore
match allcrypt::x509::crl::check(&leaf, &issuer, &crls, &policy, now) {
    Status::Revoked { at, reason } => { /* refuse */ }
    Status::NotRevoked            => { /* a list covering this said nothing */ }
    Status::Unknown(why)          => { /* nothing could be established */ }
}
```

**`Unknown` is not `NotRevoked`.** No CRL, a stale one, one from the
wrong signer, one covering the wrong part of the space — all of those
are `Unknown`, and every way of getting a revocation check wrong is a
way of turning one into the other. `Policy::require_revocation` decides
what to do about it: off by default (soft fail), and on it is hard
fail, which with no CRLs supplied means every chain fails. A *revoked*
certificate is refused either way.

### OCSP

An OCSP response answers about one certificate, where a CRL lists
everything. `verify_chain_with_revocation` takes both and consults OCSP
first, because it is normally fresher; a CRL is the fallback.

```rust,ignore
use allcrypt::x509::ocsp::{build_request, responder_urls};
use allcrypt::x509::verify::{verify_chain_with_revocation, Revocation};

for url in responder_urls(&leaf) {
    println!("{}", url);            // POST the request here yourself
}

let nonce: [u8; 16] = allcrypt::random::bytes(16)?.try_into().unwrap();
let request = build_request(&leaf, &intermediate, "sha1", Some(&nonce))?;

// ... send `request`, get `response` ...

verify_chain_with_revocation(
    &[leaf, intermediate], &[root], &policy, Purpose::ServerAuth,
    &Revocation { crls: &crls, ocsp: &[&response],
                  ocsp_nonce: Some(&nonce) })?;
```

Responses need no labelling: each is matched to a certificate by its
CertID, so a stapled one and a fetched one can go in together.

**Send a nonce if you can.** It is the only defence against a replayed
response — without one, a captured `good` stays valid until its
nextUpdate, which is how a revoked certificate stays usable. `check`
refuses a response that does not carry back the nonce it was given.

`ocsp::check` answers on its own with the same three values a CRL check
gives, because it is the same question:

```rust,ignore
match allcrypt::x509::ocsp::check(&leaf, &issuer, &response,
                                  Some(&nonce), &policy, now) {
    Status::Revoked { .. } => { /* refuse */ }
    Status::NotRevoked     => { /* the responder said good */ }
    Status::Unknown(why)   => { /* including "the responder said unknown" */ }
}
```

The responder answering `unknown` is not the certificate being fine: it
means the responder cannot speak for it, which is what a responder for
a different CA says about yours.

What is **not** implemented: OCSP stapling in the TLS handshake (the
`status_request` extension is not offered), and policy constraints.
Each is in [pitfalls.md](pitfalls.md) rather than only in a comment,
because a missing check that nobody wrote down is one nobody will add.

## Trusted roots

`trust::TrustStore` reads the platform's own trust store — the CA bundle
files on unix, the ROOT certificate store on Windows. Nothing is bundled in
the crate, so the roots follow the system's updates.

```rust,ignore
use allcrypt::trust::TrustStore;

let store = TrustStore::system()?;
println!("{} roots from {}", store.len(), store.source());

// Or explicitly, which is what a test or a pinned deployment wants.
let store = TrustStore::from_pem_file("/etc/ssl/certs/ca-certificates.crt")?;
```

Two rules, both about failing loudly. **Nothing usable is an error, not an
empty store** — an empty store silently becomes "trust nothing" two calls
later, and that looks like a network problem rather than a configuration
one. And **a root that will not parse is skipped and counted**, so one bad
entry does not take the other four hundred with it, but `store.skipped()`
tells you it happened and `store.skipped_reasons()` says why — a count
cannot distinguish a malformed certificate from a parser that is too
strict, and those have opposite remedies.

On unix, `SSL_CERT_FILE` and `SSL_CERT_DIR` take precedence, as they do for
everything else. On macOS this falls back to the file paths; the Keychain
needs the Security framework and is not done. The Windows path reads the
ROOT store through `wincrypt` and is confirmed working there — see
[pitfalls.md](pitfalls.md).

`pem` handles the encoding, including a base64 decoder that rejects
characters outside the alphabet rather than skipping them:

```rust
use allcrypt::pem;

let der = vec![1u8, 2, 3];
let text = pem::wrap("CERTIFICATE", &der);
assert_eq!(pem::certificates(&text)?, vec![der]);

// Strict: a block that opens as one label and closes as another is an
// error, not a block that happens to be mislabelled.
assert!(pem::parse("-----BEGIN CERTIFICATE-----\nZm9v\n-----END PRIVATE KEY-----").is_err());
```

## TLS records

`tls::record` is the framing layer, and it is sans-I/O: bytes in, records
out, no socket anywhere.

```rust
use allcrypt::tls::record::{RecordReader, RecordWriter};
use allcrypt::tls::{ContentType, Version};

let mut writer = RecordWriter::new(Version::TLS12);
let bytes = writer.write(ContentType::Handshake, b"a handshake message")?;

let mut reader = RecordReader::new();
reader.push_incoming(&bytes);          // however the transport split them
let record = reader.read()?.expect("a whole record");
assert_eq!(record.payload, b"a handshake message");
assert!(reader.read()?.is_none());     // nothing left
```

`push_incoming` takes whatever arrived — half a header, three records at
once, one byte at a time — and `read` returns `Ok(None)` until a whole
record is there. That is the property everything else rests on, and it is
checked against real captured handshakes in
`tests/test_tls_transcripts.rs`.

Protection is a state the writer and reader each hold, switched by
`change_cipher_spec`, which also restarts the sequence number as the spec
requires:

```rust,ignore
use allcrypt::tls::record::{CbcHmac, Protection};

let keys = CbcHmac::new("aes", "sha1", &key, &mac_key, &iv, Version::TLS12)?;
writer.change_cipher_spec(Protection::CbcHmac(keys));
```

TLS 1.1 and later put a fresh explicit IV in every record; TLS 1.0 and
SSLv3 chain it from the previous record, which is what BEAST exploits.
`CbcHmac` does whichever the version calls for, because this library
implements the old ones too.

**Encrypt-then-MAC (RFC 7366) is supported and preferred.** With it the MAC
covers the ciphertext and is checked before anything is decrypted, so a
forged record is rejected without its padding ever being examined — which
removes the padding oracle rather than making it hard to measure. Modern
OpenSSL negotiates it by default for CBC suites:

```rust,ignore
let keys = CbcHmac::new("aes", "sha1", &key, &mac_key, &iv, Version::TLS12)?
    .with_encrypt_then_mac();
```

Both sides have to agree, which is what the extension is for; turning it on
unilaterally produces records the peer cannot read, and there is a test
that says so.

**The decrypt path is shaped by Lucky 13.** In a CBC suite the record is
MAC-then-encrypt, so padding can only be checked after decryption and the
MAC only after that. An implementation that returns early on bad padding
takes measurably less time, and that difference recovers plaintext. So the
decrypt path computes the MAC over a fixed length whatever the padding
claimed, never returns early between the two checks, and reports one error
for every failure. It is still not constant time, because the primitives
underneath are not — what it removes is the large, easily measured
difference. See [pitfalls.md](pitfalls.md).

Verified against independent implementations of RFC 5246 §6.2.3.2 and
RFC 7366 — 582 records over TLS 1.0/1.1/1.2, AES-128 and AES-256, SHA-1,
SHA-256 and MD5, in both constructions.

## The TLS key schedule

`tls::keys` goes from a premaster secret to the keys the record layer uses.
Two details in there are the ones implementations get wrong, and both are
silent: the randoms go in **client-first** for the master secret and
**server-first** for the key block, and the key block splits into both MAC
keys, then both encryption keys, then both IVs, client first in each pair.
Get either wrong consistently and your own code still agrees with itself.

Which is why `tests/test_tls_keys.rs` does not round trip. It takes a real
captured session's master secret, derives the key block with our code, and
decrypts records that Python's `ssl` encrypted — then checks our
verify_data against the Finished a real implementation computed.

## The TLS 1.3 key schedule

`tls::keys13` is a separate module because TLS 1.3 shares no step with the
schedule above. It is three HKDF-Extract stages, each with a chain of
derivations hanging off it, and `Schedule` walks them in order:

```rust
use allcrypt::tls::keys13::{finished, Schedule};
use allcrypt::tls::suites::MacAlgorithm;

// With no pre-shared key the early secret is a constant, the same in
// every TLS 1.3 connection that does not resume.
let early = Schedule::early(MacAlgorithm::Sha256, None)?;

// The shared secret from X25519 or an EC group goes in here.
let handshake = early.handshake(&[0x9f; 32])?;
let transcript = [0x11u8; 32];                 // through ServerHello
// The last argument is the AEAD's nonce length, which is **not twelve
// for every suite**: RFC 8446's AEADs all take twelve, and RFC 9367's
// GOST suites take the cipher's block - sixteen for Kuznyechik and
// eight for Magma. `BulkCipher::iv_len_13` is what a caller asks.
let (client, server) = handshake.handshake_traffic(&transcript, 16, 12)?;
assert_eq!(client.key.len(), 16);
assert_eq!(client.iv.len(), 12);

// Finished is a plain HMAC here, not the TLS 1.2 PRF, and it is the
// hash's full length rather than 12 bytes.
let verify = finished("sha256", &client.finished_key, &transcript)?;
assert_eq!(verify.len(), 32);

// And the application keys come off the next stage, not this one.
let master = handshake.master()?;
assert!(handshake.application_traffic(&transcript, 16, 12).is_err());
let (_client_app, _server_app) = master.application_traffic(&transcript, 16, 12)?;
```

The stage is tracked rather than assumed. A secret taken from the wrong
stage is still the right number of pseudorandom bytes, so nothing
downstream would notice — the three Extract steps exist precisely so the
stages cannot be confused, and reconnecting them by accident is easy.

Everything that is easy to get wrong here is easy to get wrong *silently*:
the `"tls13 "` label prefix with its trailing space, `Hash("")` rather than
nothing as the context for an empty message list, the derived secret rather
than the stage secret as the next salt. Each of those gives a schedule that
agrees with itself and with no other implementation, so the checks are in
`tools/src/bin/diff_tls13_keys.rs` against a reference transcribed from RFC 8446
§7.1 — see [pitfalls.md](pitfalls.md).

## The TLS 1.3 record layer

`tls::record13` is the other half, and also a separate module, because
four things change at once:

```rust
use allcrypt::tls::keys13::Schedule;
use allcrypt::tls::record::{Protection, RecordWriter};
use allcrypt::tls::record13::Aead13;
use allcrypt::tls::suites::MacAlgorithm;
use allcrypt::tls::{ContentType, Version};

let schedule = Schedule::early(MacAlgorithm::Sha256, None)?
    .handshake(&[0x5c; 32])?;
let (client, _server) = schedule.handshake_traffic(&[0x2b; 32], 16, 12)?;

let mut writer = RecordWriter::new(Version::TLS12);
writer.change_cipher_spec(Protection::Aead13(
    Aead13::new("aes-gcm", "sha256", client, 16)?));

// A handshake record. The header says application_data anyway.
let bytes = writer.write(ContentType::Handshake, b"inside")?;
assert_eq!(bytes[0], 0x17);
assert_eq!(&bytes[1..3], &[0x03, 0x03]);
```

The header is a decoy: every protected record claims `application_data`
and `0x0303`, and the real content type is the last non-zero byte of the
*decrypted* plaintext. The nonce is the static IV XOR the sequence number
in its last eight bytes, and nothing on the wire says which nonce was
used — so a nonce assembled the wrong way round is invisible until a real
peer refuses every record. The additional data is the five byte header as
sent, whose length covers the ciphertext plus the tag.

And the sequence number belongs to the keys rather than to the
connection: handshake keys start at zero, application keys start at zero
again, and each `KeyUpdate` starts at zero. `Aead13` holds the counter
next to the keys for that reason, so an update cannot replace one without
the other.

## The TLS 1.3 handshake's shapes

`tls::handshake13` holds the extensions that carry the TLS 1.3
negotiation and the messages whose shape changed. The thing it exists to
contain is that **the same extension type has a different wire format
depending on which message it is in**, with nothing on the wire to say
which:

| | ClientHello | ServerHello | HelloRetryRequest |
|---|---|---|---|
| `supported_versions` | `uint8` length, then versions | bare 2 bytes | — |
| `key_share` | `uint16` length, then entries | one entry, no length | bare `uint16` group |

So there is a function per pair and none of them take a flag:

```rust
use allcrypt::tls::handshake13::{encode_client_key_share, encode_client_supported_versions,
                                 parse_server_key_share, parse_server_supported_version,
                                 KeyShareEntry};
use allcrypt::tls::handshake::groups;
use allcrypt::tls::Version;

let versions = encode_client_supported_versions(&[Version::TLS13, Version::TLS12])?;
assert_eq!(versions, vec![0x04, 0x03, 0x04, 0x03, 0x03]);   // length byte first

let shares = encode_client_key_share(&[KeyShareEntry {
    group: groups::X25519,
    key_exchange: vec![0xab; 32],
}])?;

// The server's answers are the other formats, and each refuses the
// client's. A share list read as a single entry would take the list
// length for a group code and report a group nobody offered.
assert!(parse_server_key_share(&shares).is_err());
assert!(parse_server_supported_version(&versions).is_err());
```

`HELLO_RETRY_REQUEST_RANDOM` is the fixed random that makes a ServerHello
a HelloRetryRequest — it is `SHA-256("HelloRetryRequest")`, and the test
derives it rather than trusting the transcription.
`certificate_verify_content` builds the 64 spaces, the side's context
string, the zero byte and the transcript hash that a CertificateVerify
actually signs, and `scheme::allowed_in_certificate_verify` enforces RFC
8446 §4.4.3's rule that an RSA signature there must be PSS.

None of this is checked by round-tripping, which is the point.
`tests/test_tls13_transcript.rs` takes the traffic secrets from a real
OpenSSL handshake's key log, derives the record keys with our schedule,
decrypts the server's flight, and parses every message in it.

## TLS handshake messages

`tls::handshake` parses and builds the messages; `tls::codec` is the wire
format underneath, where every length prefix is read and therefore where
every length is checked.

```rust,ignore
use allcrypt::tls::handshake::{ClientHello, HandshakeReader, HandshakeType};

let mut handshake = HandshakeReader::new();
handshake.push(&record.payload);          // every handshake record's payload

while let Some(message) = handshake.next()? {
    if message.message_type == HandshakeType::ServerHello {
        let hello = ServerHello::parse(&message.body)?;
        println!("{} {:04x}", hello.negotiated_version(), hello.cipher_suite);
    }
    transcript.update(&message.raw);      // the exact bytes, not a re-encoding
}
```

Two things it is careful about. Messages and records do not line up — one
record can hold several messages and one message can span several records —
so `HandshakeReader` reassembles rather than assuming. And `message.raw` is
the bytes exactly as they arrived, because the transcript hash that
Finished covers is computed over them; a re-encoding that differs anywhere
makes the handshake fail, or worse, succeed while the two sides disagree
about what they agreed.

`negotiated_version()` exists because a TLS 1.3 ServerHello still says 1.2
in its version field, to get past middleboxes, and puts the real answer in
an extension. Reading only the legacy field means silently treating a 1.3
connection as 1.2.

Checked against three real captured handshakes in
`tests/test_tls_transcripts.rs` — every ClientHello, ServerHello and
certificate chain re-encodes byte-identically to what Python's `ssl`
produced.

## TLS 1.3 session resumption

A server hands out tickets after the handshake; keep them and hand them
back, and the next connection skips the certificate, the signature and
a round trip.

```rust,ignore
use allcrypt::tls::client::{ClientConfig, ClientConnection};

let mut first = ClientConnection::new(config.clone(), "example.test")?;
// ... handshake, then read: the tickets arrive under the application
// keys, so they come with or after the first data.
let tickets = first.take_tickets();

let mut config = config;
config.tickets = tickets.into_iter().take(1).collect();
let later = ClientConnection::new(config, "example.test")?;
// ... handshake ...
assert!(later.resumed());
```

`Ticket::encode` and `Ticket::decode` give an opaque blob for a caller
that has to store one between processes.

**A ticket is key material.** Anybody with one can resume the
connection it came from, and anybody who can rewrite one chooses the
key for a connection that will then appear to have resumed.

**Offer each ticket once.** `take_tickets` takes rather than copies for
that reason: offering one twice lets a passive observer link the two
connections, which is exactly what the ticket's obfuscated age exists
to prevent.

A resumed connection has **no certificate** — the pre-shared key
authenticates the server, because only the peer that ran the original
handshake could derive the same key — so `resumed()` is what to ask
before treating an empty chain as a failure.

`tls::resumption` holds the binder machinery, and its module comment is
where the traps are written down. The one worth repeating here: the
binder is an HMAC over the ClientHello with **exactly the binder bytes
cut off the end** and every length still counting them, so it is
computed by slicing the encoded hello rather than by re-encoding it
without the binders. Re-encoding gives three smaller length fields and
a binder that is perfectly self-consistent and that no server accepts.

Verified against a live OpenSSL server in `pytests/test_tls_handshake.py`,
which is the only thing that can tell us the binder is right — a round
trip against ourselves passes whatever we got wrong.

## Cipher suites

`tls::suites` is the registry, and it is the part of this library that the
whole thing exists for. Every other implementation has spent twenty years
deleting rows from this table; this one keeps them.

Keeping is not offering:

```rust
use allcrypt::tls::suites::{by_name, Selection, Strength};

// The default: implemented, and nothing broken.
let modern = Selection::modern();

// The "I have to talk to it anyway" selection: adds RC4 and friends.
let legacy = Selection::legacy();
assert!(legacy.codes().len() > modern.codes().len());

// Or exactly what you name, which is the only way to reach the ones that
// provide no confidentiality or no authentication at all.
let exact = Selection::named(&["AES128-SHA", "RC4-SHA"])?;
assert_eq!(exact.codes(), &[0x002f, 0x0005]);

assert_eq!(by_name("AES128-SHA").unwrap().strength, Strength::Weak);
assert_eq!(by_name("RC4-SHA").unwrap().strength, Strength::Broken);
```

The strength labels are not opinions. `Modern` means no known practical
attack; `Weak` means attacks needing unusual conditions or a lot of traffic
(3DES and Sweet32, CBC with SHA-1); `Broken` means practical attacks (RC4,
export grade, single DES); `Insecure` means no confidentiality or no
authentication at all — the NULL ciphers and the anonymous key exchanges,
which are diagnostic tools and which nothing but an explicit request will
select.

A suite whose pieces are not built yet stays in the table, marked, and is
never offered — so the registry doubles as the list of what is left to
build. `Selection::named` says so rather than quietly producing a shorter
hello.

Of the 65 suites in the registry, this machine's OpenSSL still knows 45.
The 20 it has deleted are exactly the ones worth keeping: export grade,
RC4, single DES, 3DES, IDEA, SEED, the anonymous suites, and all three GOST
suites from RFC 9189.

## The TLS client

`tls::client::ClientConnection` is the state machine. It is sans-I/O: bytes
in, bytes out, and whoever owns the connection does the reading and writing.

```rust,ignore
use allcrypt::tls::client::{ClientConfig, ClientConnection};
use allcrypt::trust::TrustStore;

let config = ClientConfig::new(TrustStore::system()?, now);
let mut connection = ClientConnection::new(config, "example.test")?;

while connection.is_handshaking() {
    let out = connection.take_outgoing();
    if !out.is_empty() {
        socket.write_all(&out)?;
    }
    let mut buffer = [0u8; 16384];
    let read = socket.read(&mut buffer)?;
    connection.push_incoming(&buffer[..read]);
    connection.process()?;          // the reason, on any failure
}

println!("{:?} {:?}", connection.version(), connection.cipher());
println!("{:?}", connection.named_group());     // Some("secp256r1")
```

`process()` returns the reason rather than a status, and the connection
stays failed afterwards — a connection that failed and then carried on is
the bug the state machine is written against.

The configuration is a struct with named fields rather than a builder, so
every weakening is visible at the call site:

```rust
use allcrypt::tls::client::ClientConfig;
use allcrypt::tls::suites::Selection;
use allcrypt::tls::Version;
use allcrypt::trust::TrustStore;

// The default: TLS 1.2 only, verification on, nothing broken offered.
let config = ClientConfig::new(TrustStore::new(), 1_700_000_000);
assert!(config.verify_certificate);
assert_eq!(config.min_version, Version::TLS12);

// And the named constructor for reaching something old, which is one
// decision rather than five.
let old = ClientConfig::legacy(TrustStore::new(), 1_700_000_000);
assert_eq!(old.min_version, Version::TLS10);
assert!(old.suites.codes().len() > Selection::modern().codes().len());
```

`ClientConnection::new` refuses a configuration with verification on and no
roots. A client with no roots verifies nothing, and that has to be a
decision rather than an oversight — `verify_certificate: false` is how you
say it out loud, and `certificate_verified()` reports it afterwards.

### Decrypting a capture

`ClientConnection::key_log_line` returns this session's line in the NSS key
log format, which is what Wireshark reads:

```rust,ignore
if let Some(line) = connection.key_log_line() {
    writeln!(keylog, "{}", line)?;     // CLIENT_RANDOM <random> <master>
}
```

Nothing is written anywhere by this crate - no environment variable is read
down here, and no file is opened. The Python shim is where `SSLKEYLOGFILE`
and `keylog_filename` live, because that is the layer that already owns
I/O. **The line hands out the session keys**, so treat it accordingly.

### Record protection

`Protection` is the record layer's state after the ChangeCipherSpec:
`CbcHmac` for the CBC suites, `Aead` for the GCM ones. The AEAD path takes
the nonce's fixed half from the key block's IV slot and sends the sequence
number as the explicit half - which is what makes the nonce unique without
a second counter to keep right. See [pitfalls.md](pitfalls.md) §7.

### Key exchange

Static RSA, ephemeral ECDH with either an RSA or an ECDSA certificate over
P-256, P-384 and P-521, and finite-field DHE with an RSA certificate.
`named_group()` reports what was agreed - the curve name for ECDHE, or
`dh2048` and the like for DHE, because a suite name says which kind of key
exchange but not in which group, and the group is what decides the
strength.

The signature over the server's ephemeral key is verified against the leaf
certificate before the key exchange proceeds. It is the only thing binding
that key to the certificate: without it anyone in the path substitutes
their own key, reads everything, and the handshake still completes. The
bytes signed are the ones that arrived, not a re-encoding of them.

Three things are refused, each of which is a way to end up computing in a
group somebody else chose: explicit curve parameters instead of a named
curve, a named curve this client did not offer, and a point that is not on
the curve or is in the wrong subgroup. See
[pitfalls.md](pitfalls.md) §2.

DHE has the same problem in a sharper form, because the server sends the
group itself rather than naming one. `ClientConfig::min_dh_bits` (2048 by
default) is the floor, `check_dh_prime` turns on a primality test of the
modulus, and the degenerate public values are refused as they arrive.
`ClientConfig::legacy` lowers the floor to 512, which is what reaches a
server nobody has reconfigured since export restrictions were a thing.
See [pitfalls.md](pitfalls.md) §3b.

## The TLS server

`tls::server::ServerConnection` is the other side, and the same shape:
sans-I/O, bytes in and bytes out. Everything the two share — the record
layer, the key block, the transcript, `record::protection_for`,
`kex::EphemeralKey` — is one copy that both call, because two copies
would agree about AES and disagree about something small, and that
disagreement shows as a handshake that fails against one peer in
twenty.

It speaks TLS 1.2 — `ECDHE_RSA`, `ECDHE_ECDSA` and RSA key transport —
and TLS 1.3. The default ceiling is 1.3 and the default floor is 1.2.

```rust,ignore
use allcrypt::tls::server::{ServerConfig, ServerConnection, ServerKey};

let key = ServerKey::Ec { curve: "P-256", private: scalar };
let mut connection = ServerConnection::new(
    ServerConfig::new(vec![leaf_der, intermediate_der], key))?;

while connection.is_handshaking() {
    let mut buffer = [0u8; 16384];
    let read = socket.read(&mut buffer)?;
    connection.push_incoming(&buffer[..read]);
    connection.process()?;
    let out = connection.take_outgoing();
    if !out.is_empty() {
        socket.write_all(&out)?;
    }
}

println!("{:?} for {:?}", connection.negotiated_suite(),
         connection.server_name());
```

### TLS 1.3

`tls::server13` is the 1.3 half, a separate module rather than a version
flag in `server.rs`, because the two handshakes share no step: no
ServerKeyExchange, no ChangeCipherSpec that means anything, no master
secret from a premaster, and a signature over a transcript hash rather
than over the two randoms. Nothing in the 1.2 path is reachable from the
1.3 one, which is the point — a shared state machine would accept
messages from both.

There is nothing extra to call. `ServerConnection` branches on the
version it negotiated, and the same `process` / `take_outgoing` loop
above drives either:

```rust,ignore
let mut config = ServerConfig::new(chain, key);
config.max_version = Version::TLS13;    // the default
config.min_version = Version::TLS12;
```

Two things behave differently there, and both surprise:

- **A 1.3 suite names no key exchange and no authentication.** It is an
  AEAD and a hash. So all three 1.3 suites work with either kind of key,
  and the `KeyExchange` in those rows of the suite table is a
  placeholder that `server13` deliberately does not consult — applying
  the 1.2 rule would refuse every 1.3 handshake made with an EC key.
- **RSA signs with PSS.** RFC 8446 §4.4.3 forbids the `rsa_pkcs1_*`
  codepoints in a CertificateVerify, which is all the 1.2 signature
  table produces.

HelloRetryRequest is handled, including the transcript surgery RFC 8446
§4.4.1 requires — the first ClientHello is replaced by a synthetic
`message_hash` message holding its hash.

**Session tickets** live in `tls::tickets`. They are stateless: the server
hands the client its own session back, sealed with AES-256-GCM under a key
only the server has, so there is no table to keep and nothing to share
between machines except the key.

```rust,ignore
use allcrypt::tls::server::{ServerConfig, ServerKey};
use allcrypt::tls::tickets::TicketKey;
use std::sync::Arc;

// Forty bytes, generated out of band and the same on every instance.
let key = Arc::new(TicketKey::from_bytes(&configured)?);

let mut config = ServerConfig::with_clock(chain, server_key, now);
config.ticket_key = Some(Arc::clone(&key));
```

`ServerConfig::with_clock` is the constructor that turns tickets on,
because they need a clock and nothing else here does. `session_tickets`
defaults to zero for that reason: a server that cannot expire a ticket
should not issue one.

### Asking the client for a certificate

TLS 1.2 and 1.3. Three fields, and they are separate because they
are three different decisions:

```rust,ignore
use allcrypt::tls::server::ServerConfig;
use allcrypt::x509::verify::Policy;

let mut config = ServerConfig::with_clock(chain, server_key, now);
config.request_client_certificate = true;
config.require_client_certificate = true;
config.client_roots = Some(client_ca_store);
config.client_policy = Policy::at(now);
```

`request_client_certificate` asks; on its own that is *optional* client
authentication, and a client with nothing suitable answers with an empty
Certificate, which is legal (RFC 8446 4.4.2.1) and completes the
handshake. `ServerConnection::peer_certificates` is the only thing that
says whether one arrived, and `client_certificate_verified` the only
thing that says whether it was judged.

`require_client_certificate` refuses the empty answer.

`client_roots` is its own `TrustStore`, not the server's. The CAs
allowed to issue identities for a service are almost never the public
web PKI, and a server verifying client chains against the system store
would accept anything holding a certificate from any public CA. `None`
means the chain is not judged — the signature still is, so the client
does hold the key for what it sent, and recognising that key is the
application's job.

The chain is judged with `Purpose::ClientAuth`, so a certificate whose
`extendedKeyUsage` says `serverAuth` only is refused. Without that, a
service could authenticate as a client to any peer trusting the same CA
with the key it already has.

The signature is checked **before** the chain: a chain that verifies but
did not sign this transcript is somebody else's certificate, replayed.

### Early data (0-RTT)

Off by default at both ends, and the default is the argument.

```rust,ignore
use allcrypt::tls::server::ServerConfig;
use allcrypt::tls::tickets::ReplayGuard;
use std::sync::{Arc, Mutex};

// ONE register, shared by every connection this server serves. A
// register per connection has seen nothing and refuses nothing.
let guard = Arc::new(Mutex::new(ReplayGuard::default()));

let mut config = ServerConfig::with_clock(chain, server_key, now);
config.ticket_key = Some(Arc::clone(&ticket_key));
config.max_early_data = 16_384;
config.replay_guard = Some(Arc::clone(&guard));
```

```rust,ignore
use allcrypt::tls::client::ClientConfig;

let mut config = ClientConfig::new(roots, now);
config.tickets = stored;
config.early_data = b"GET / HTTP/1.1\r\n\r\n".to_vec();
// ... and afterwards:
//   if !connection.early_data_accepted() { write it again }
```

Early data is unlike every other byte on the connection in two ways:

* It is **not forward secret.** The key comes from a PSK that has been
  in storage since the previous connection, so anyone who later obtains
  that ticket reads the early data out of a capture.
* It can be **replayed.** Nothing fresh from the server is in those
  keys, because the server has not spoken yet. `ReplayGuard` bounds how
  often a replay works — a bounded, in-memory strike register over the
  binders already accepted — and RFC 8446 8.2 is explicit that this
  cannot be made impossible: another machine in the same cluster, or a
  long enough wait, gets it through.

So the rule is the RFC's: put in early data only what may happen twice.

`ServerConnection::take_early_data` is separate from `take_incoming` for
that reason, and `ClientConfig::early_data` is not resent on rejection:
resending is the same decision as sending.

A server declines quietly — a full handshake, and nothing said — when
the ticket was not the client's first identity, when the ticket allows
none, when the server name differs from the one it was issued under,
after a HelloRetryRequest, or when the register has seen that flight.
Each reason is a fact about the ticket, and naming it would tell an
attacker how close they got.

### Sending one as a client

```rust,ignore
use allcrypt::tls::client::{ClientConfig, ClientIdentity, ClientKey};

let mut config = ClientConfig::new(roots, now);
config.client_certificate = Some(ClientIdentity {
    chain: vec![leaf_der],
    key: ClientKey::Ec { curve: "P-256", private: scalar },
});
```

Nothing is sent unless the server asks. `ClientKey::schemes` decides
what may be offered: RSA gets PSS only, because RFC 8446 4.4.3 forbids
the `rsa_pkcs1_*` codepoints in a CertificateVerify, and an EC key is
bound to its own curve. The scheme chosen is the first that the server
offered, our key can make, and is legal in a CertificateVerify — all
three, since `signature_algorithms` also covers certificates and lists
schemes that are not allowed here.

### Three things are different from writing a client

**The server chooses.** A client offers and checks what came back; a
server picks the version and the suite out of what was offered, and
every choice is a chance to pick something weaker than it had to be.
`ServerConfig::suites` is consulted **in its own order**, and the first
suite the client also offered wins — so a server that should honour the
client's preference passes a different order rather than setting a flag.
The key narrows it further: an EC key can only authenticate
`EcdheEcdsa`, so a suite it cannot sign for is never chosen.

**The server signs, and not over the transcript.** A TLS 1.2 ECDHE
ServerKeyExchange is signed over
`client_random || server_random || ServerECDHParams`. Both randoms are
in the hellos, which are in the transcript, but this signature names
them directly and in that order. Nothing on this side of the wire can
check it: our own client would accept whatever our server produced,
which is why `pytests/test_tls_server.py` drives a real OpenSSL client.

**RSA key transport is a Bleichenbacher oracle if you let it be.**
`decrypt_premaster` returns 48 bytes and cannot fail. RFC 5246 §7.4.7.1
requires that bad padding, the wrong length and a rolled-back version
all continue with a *random* premaster and die at the Finished, with
nothing to say which happened — so there is no `Result` to branch on,
because a caller with one would write `?` and put the oracle back. See
[pitfalls.md](pitfalls.md) §7.

Everything the handshake settled is reported rather than assumed, which
is what a proxy in front of it reads:

```rust,ignore
connection.server_name();               // Some("example.test"), from SNI
connection.offered_alpn();              // ["h2", "http/1.1"], all of them
connection.negotiated_alpn();           // Some("h2"), or None
connection.negotiated_suite();          // Some(&CipherSuite)
connection.uses_encrypt_then_mac();     // RFC 7366 was agreed
connection.uses_extended_master_secret();
```

`server_name()` is the one that matters: it is the only thing in a TLS
handshake that says which host the client thinks it is reaching, and it
arrives before anything has to be decided. A client connecting by IP
address sends none, and `None` is an answer rather than a failure.

**ALPN needs a list, and the list is the server's own preference
order** (`ServerConfig::alpn`). The first protocol in it that the client
also offered wins; empty - the default - answers nothing, because a
proxy that promised `h2` on behalf of something speaking HTTP/1.1 would
have promised what it cannot deliver. `ServerConfig::require_alpn` turns
"nothing in common" into a `no_application_protocol` alert rather than a
handshake without the extension; it is ignored when the client offered
none, since a client that did not ask has not disagreed.

`ClientConfig::alpn` is the other half. The server may choose against
the client's order, but the answer must be one the client offered and
must name exactly one protocol (RFC 7301 4.2) - both are refused rather
than shrugged at, because either is an application speaking a protocol
it never agreed to.

### Reading a private key

`x509::private_key::parse` takes PEM text or DER bytes and returns the
two shapes this library can compute with:

```rust,ignore
use allcrypt::x509::private_key::{self, PrivateKey};
use allcrypt::tls::server::{ServerConfig, ServerKey};

let key = match private_key::parse(&std::fs::read("server.key")?)? {
    PrivateKey::Ec { curve, private } =>
        ServerKey::Ec { curve, private: BigUint::from_bytes_be(&private) },
    PrivateKey::Rsa { p, q, e } => ServerKey::Rsa(Box::new(
        rsa::RsaPrivateKey::from_primes(p, q, e)?)),
};
```

PKCS#8, SEC1 and PKCS#1, and **the bytes decide rather than the label**.
Two things it deliberately does not do: keep the CRT parameters (they
are derived from `p`, `q` and `e`, and a file whose stored `dP` disagrees
would sign wrongly in a way nothing checks), or resolve an EC key that
names two different curves (RFC 5915 §3 says the inner parameters must
be omitted inside PKCS#8, so a disagreement is malformed and picking one
is guessing). An encrypted key needs `parse_with_password`; `parse`
refuses one *by name*, because the remedy is a password rather than a
different file.

`x509::encrypted_key` is the layer underneath: `decrypt` takes an
`EncryptedPrivateKeyInfo` to the `PrivateKeyInfo` inside, `encrypt` goes
the other way under any PBES2, PBES1 or PKCS#12 scheme, and
`parameters` reads a file's scheme, salt, count and IV, which handed
back to `encrypt` with the same key reproduce the file:

```rust
use allcrypt::x509::encrypted_key::{decrypt, encrypt, parameters};

let plain = b"stands in for a PrivateKeyInfo";
let sealed = encrypt(plain, b"hunter2", "aes-256-cbc", Some("sha256"), 1000,
                     &[1; 16], &[2; 16])?;
assert_eq!(decrypt(&sealed, b"hunter2")?, plain);
let p = parameters(&sealed)?;
assert_eq!((p.scheme, p.prf, p.iterations), ("aes-256-cbc", Some("sha256"), 1000));
assert_eq!(encrypt(plain, b"hunter2", p.scheme, p.prf, p.iterations, &p.salt, &p.iv)?,
           sealed);
```

### OCSP stapling

`ServerConfig::ocsp_response` is a cached response as DER, stapled to the
certificate when the client asks (RFC 6066 §8). **Nothing here fetches
it**: a server that went to the responder mid-handshake would add the
responder's latency and availability to every connection, which is the
problem stapling exists to solve rather than a way to solve it. It is not
checked on the way out either — a server judging a statement about its
own certificate is checking its own homework.

On the client, `ClientConfig::request_stapled_ocsp` is on by default and
`ClientConnection::stapled_ocsp` hands over what arrived. What it is
allowed to decide is asymmetric: *revoked* fails the handshake whatever
else is set, because that is an answer; anything that settles nothing
costs nothing unless `ClientConfig::require_stapled_ocsp` says otherwise.
That flag is **not** `Policy::require_revocation`, which is about CRLs
and would refuse every chain here, since nothing fetches one.

Client certificates work at TLS 1.2 as well, through the same
`request_client_certificate`, `require_client_certificate` and
`client_roots` fields — though they are a different message and a
different signature underneath, not a version flag. A 1.2
CertificateVerify signs the raw concatenation of every handshake message
under a hash the message names, RSA signs it with PKCS#1 v1.5, and the
order is reversed: Certificate before ClientKeyExchange,
CertificateVerify after.

They work at TLS 1.0 and 1.1 too, which is a third construction again:
no signature-algorithm list, a bare signature with no algorithm field,
RSA over 36 bytes of MD5 and SHA-1 with no DigestInfo, and ECDSA over
the SHA-1 half alone.

Not implemented on this side: post-handshake authentication. That is
absent rather than half-done: `ServerConfig::max_version` is a ceiling
the server applies rather than a description of what it happens to
implement, so setting it to `TLS12` really does refuse a 1.3-only
client.

## A certificate authority

`api::CertificateAuthority` issues leaf certificates on demand — the
other half of a terminating proxy. It reads nothing and opens nothing;
the caller supplies the host and the validity window.

```rust,ignore
use allcrypt::api::CertificateAuthority;

let ca = CertificateAuthority::generate("allcrypt proxy CA",
                                        "20240101000000Z", "20340101000000Z")?;
std::fs::write("proxy-ca.pem", ca.certificate_pem())?;   // install this

// Per connection, once SNI has said which host:
let (leaf, key) = ca.issue(host, "20240101000000Z", "20250101000000Z")?;
```

**Installing that certificate in a browser is a serious act**, and the
API does not pretend otherwise: anything holding the key can impersonate
any site to anyone who installed it. The validity window is required
rather than defaulted, because a proxy CA that outlives its usefulness
is a key somebody forgot they installed.

A fresh key per issuance, and a sixteen-byte random serial. The first
costs microseconds and the alternative is one key whose compromise is
every site the proxy ever served; the second avoids state that has to
survive restarts, and a repeated serial from one issuer is what a
browser caches and then refuses.

`issue` decides the subjectAltName form from the host string, because
**an address in a `dNSName` matches nothing** — a verifier asked about
an address looks only at `iPAddress` entries.

`CertificateBuilder::key_identifiers` is what puts the
`subjectKeyIdentifier` and `authorityKeyIdentifier` on both. RFC 5280
requires the first on every CA certificate, and a strict relying party
refuses a chain without the second before looking at anything else.
Both are computed by method 1 — the SHA-1 of the `subjectPublicKey` BIT
STRING's *contents*, which is one of three plausible readings and the
only one that interoperates. `tools/src/bin/diff_x509.rs` emits them for
python-cryptography to recompute, because a chain built entirely with
the wrong reading links up perfectly and matches nothing anybody else
produced.

## DSA

`publickey_ciphers::dsa`: FIPS 186-4's DSA, for the `ssh-dss` keys and
DSA certificates of the 2000s. Nonces are RFC 6979's, from the HMAC
DRBG ECDSA uses, and the RFC's twenty DSA signatures are reproduced
exactly by `tests::test_the_rfc_6979_dsa_vectors`.

```rust,ignore
// ignore: generating a group takes several seconds in a debug build.
use allcrypt::publickey_ciphers::dsa::{DsaParameters, DsaPrivateKey};
use allcrypt::hash_functions::{sha1::SHA1, HashFunction};

let group = DsaParameters::generate(1024, 160)?;   // what ssh-dss needs
let key = DsaPrivateKey::generate(group)?;
let digest = SHA1::new(b"message").digest();
let (r, s) = key.sign(&digest, SHA1::new(&[]))?;
assert!(key.public.verify(&digest, &r, &s)?);
```

`DsaParameters::new` checks a group's structure (`q | p - 1`, `g` of
order `q`) and `DsaPublicKey::new` that `y` is in it; primality is the
separate, slower `check_primes`.

## SSH keys and signatures

`ssh` has SSH's formats, checked against OpenSSH 10.0 in both
directions (`vectors/ssh_keys.vec` and `scripts/check_ssh_witness.py`):
`wire` (RFC 4251's types), `keys` (blobs, `authorized_keys` lines,
fingerprints), `private_key` (`openssh-key-v1`, encrypted with
`kdf::bcrypt_pbkdf`), `cipher` (SSH's ciphers by name) and `signature`
(signature blobs and SSHSIG).

```rust
use allcrypt::ssh::{keys, private_key, signature};
use allcrypt::ssh::private_key::{Encryption, PrivateKey};

fn ssh_example() -> Result<(), String> {
    let key = PrivateKey::generate("ecdsa", Some(384))?;
    let line = key.public().to_openssh("me@host");
    let read = keys::parse_line(&line)?;
    assert_eq!(read.key, key.public());
    assert!(read.key.fingerprint_sha256().starts_with("SHA256:"));

    // An encrypted key file, as ssh-keygen writes them.
    let encryption = Encryption { cipher: "aes256-ctr", passphrase: b"pw", rounds: 16 };
    let file = private_key::write(&key, "me@host", Some(&encryption))?;
    let (again, comment) = private_key::read(&file, Some(b"pw"))?;
    assert_eq!((again.public(), comment.as_str()), (key.public(), "me@host"));

    // A signature blob, and SSHSIG.
    let blob = signature::sign(&key, b"data", None)?;
    assert_eq!(signature::verify(&key.public(), b"data", &blob)?,
               Some("ecdsa-sha2-nistp384"));
    let armoured = signature::sshsig_sign(&key, "file", b"contents", "sha512")?;
    assert_eq!(signature::sshsig_verify(&armoured, "file", b"contents")?, key.public());
    Ok(())
}
```

The transport is `kex` (every key exchange, the exchange hash, the key
derivation), `mac`, `transport` (the packet layer) and `client`, a
sans-I/O client in the shape of `tls::client`: `push_incoming`,
`process`, `take_outgoing`. `examples/ssh_exec.rs` drives it over a
`TcpStream`; it is run against OpenSSH's `sshd` by
`scripts/check_ssh_client.py`, and sessions recorded that way are
replayed byte for byte by `tests/test_ssh_sessions.rs`.

```rust
use allcrypt::ssh::client::{Auth, Client, ClientConfig, HostKeyCheck};
use allcrypt::ssh::private_key::PrivateKey;

fn ssh_client_example() -> Result<(), String> {
    let mut config = ClientConfig::new("admin", HostKeyCheck::Fingerprint(
        "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU".to_string()));
    config.auth.push(Auth::PublicKey(PrivateKey::generate("ed25519", None)?));
    // An old device: name what it speaks, and nothing else is offered.
    config.kex = vec!["diffie-hellman-group14-sha1"];
    config.ciphers = vec!["aes128-cbc"];
    config.macs = vec!["hmac-sha1"];
    let mut client = Client::new(config)?;
    client.exec("show version");
    let first = client.take_outgoing();       // version line and KEXINIT
    assert!(first.starts_with(b"SSH-2.0-allcrypt_"));
    // ... write `first` to the socket, then loop: push_incoming what
    // arrives, process(), send take_outgoing(), read take_stdout(),
    // until closed().
    Ok(())
}
```

`server` is the other end, in the same shape. It negotiates by the
client's preferences, signs the exchange hash with whichever host key the
negotiated algorithm names, authenticates against a list the caller
gives, and reports what the session channel asked for; what a command
does is the caller's. `examples/ssh_serve.rs` drives it over a
`TcpListener`; OpenSSH's own `ssh` is run against it by
`scripts/check_ssh_server.py`, and sessions recorded that way are
replayed byte for byte by `tests/test_ssh_server_sessions.rs`.

```rust
use allcrypt::ssh::private_key::PrivateKey;
use allcrypt::ssh::server::{Server, ServerConfig, SessionRequest};

fn ssh_server_example(alice: allcrypt::ssh::keys::PublicKey) -> Result<(), String> {
    let mut config = ServerConfig::new(vec![PrivateKey::generate("ed25519", None)?]);
    config.authorize_key("alice", alice);
    config.authorize_password("backup", "a long passphrase");
    // An old management station: offer what it speaks as well.
    config.kex.push("diffie-hellman-group14-sha1");
    config.host_key_algorithms.push("ssh-rsa");
    let mut server = Server::new(config)?;
    let first = server.take_outgoing();       // version line and KEXINIT
    assert!(first.starts_with(b"SSH-2.0-allcrypt_"));
    // ... write `first` to the accepted socket, then loop: push_incoming
    // what arrives, process(), and once request() is Some, take_stdin(),
    // write() the output and finish(exit_status); send take_outgoing()
    // each time round, until closed().
    if let Some(SessionRequest::Exec(command)) = server.request() {
        println!("{:?} asked for {command}", server.user());
    }
    Ok(())
}
```

`signature::verify` returns the algorithm it verified under, because for
RSA that is a policy question: `ssh-rsa` is SHA-1, `rsa-sha2-256` and
`rsa-sha2-512` are not, and the key blob says `ssh-rsa` for all three.

## Choosing an algorithm at run time

When the algorithm is a string rather than a type — a CLI flag, a config
file, a foreign runtime — use the `api` module. It trades static dispatch for
a name lookup and owns its state rather than borrowing:

```rust
use allcrypt::api::{AnyBlockCipher, CipherStream, Mode};

let cipher = AnyBlockCipher::new("aes", &[0u8; 16], None)?;
let mut stream = CipherStream::new(cipher, Mode::from_name("ctr")?, &[0u8; 16], false)?;
let mut out = stream.update(b"some data")?;
out.extend_from_slice(&stream.finish()?);
```

`api::EcKey` and `api::EcPublicKey` are the same idea for elliptic curves — a
key pair that carries its own curve, so the caller only ever deals in names
and bytes:

```rust
use allcrypt::api::{AnyHash, EcKey, EcPublicKey, CURVES};
use allcrypt::hash_functions::HashFunction;

assert!(CURVES.contains(&"P-256"));
let mine = EcKey::generate("P-256")?;
let theirs = EcKey::generate("P-256")?;

let shared = mine.exchange(&theirs.public_bytes(false)?)?;
assert_eq!(shared, theirs.exchange(&mine.public_bytes(true)?)?);
assert_eq!(mine.key_size(), 256);

let mut hash = AnyHash::new("sha256")?;
hash.update(b"a message");
let digest = hash.digest();

let signature = mine.sign(&digest, "sha256")?;
let verifier = EcPublicKey::from_bytes("P-256", &mine.public_bytes(false)?)?;
assert!(verifier.verify(&digest, &signature)?);
```

`api::RsaKey` and `api::RsaPublicKey` are the same for RSA, dealing in bytes
rather than `BigUint`:

```rust,ignore
use allcrypt::api::{AnyHash, RsaKey};
use allcrypt::hash_functions::HashFunction;

let key = RsaKey::generate(2048)?;
let public = key.public_key();

let ciphertext = public.encrypt(b"a short message")?;
assert_eq!(key.decrypt(&ciphertext)?, b"a short message");

let mut hash = AnyHash::new("sha256")?;
hash.update(b"a message");
let digest = hash.digest();
assert!(public.verify("sha256", &digest, &key.sign("sha256", &digest)?)?);
```

`api::BLOCK_CIPHERS`, `api::STREAM_CIPHERS`, `api::HASHES`, `api::MODES` and
`api::CURVES` list what the names can be. `AnyHash` and `AnyStreamCipher` are the same idea
for the other two families; `AnyHash` is `Clone`, so forking a hash's state is
just a clone.

Code that knows its algorithm at compile time should prefer the concrete
types above — they avoid the dispatch entirely.

## Error handling

Errors are `String`. The cases worth knowing:

| Situation | Behaviour |
|---|---|
| Wrong key length | `Err` from the constructor |
| IV length not the block size | `Err` from the mode call |
| ECB/CBC input not block aligned | `Err`, and nothing is written to the output |
| Mode not implemented for that cipher | `Err` naming the mode |
| GCM, CCM | `Err`; not implemented yet |
| Invalid PKCS#7 padding on unpad | `Err` |
