# Pitfalls

The side channels, correctness traps and protocol hazards this library
has to get right, written down so they are known rather than discovered:
what each one is, how it shows up when it goes wrong, and whether it is
mitigated, accepted or open - with the test that holds it, where there
is one. Much of it was found by breaking the code on purpose and seeing
what the tests missed.

The rule for the whole document: **a pitfall that is written down and
accepted is a decision. A pitfall that is not written down is a bug waiting
to be someone's CVE.**

## Status key

| | meaning |
|---|---|
| **mitigated** | handled, with a test that would catch a regression |
| **accepted** | known, deliberately not handled yet, safe for the current use |
| **open** | known, not handled yet, and it matters |

## Contents

- [1. Timing and side channels](#1-timing-and-side-channels)
- [2. Elliptic curve pitfalls](#2-elliptic-curve-pitfalls)
- [2b. X25519 pitfalls](#2b-x25519-pitfalls)
- [2c. EdDSA pitfalls](#2c-eddsa-pitfalls)
- [2d. Trust store and SNI pitfalls](#2d-trust-store-and-sni-pitfalls)
- [2e. The `ssl` drop-in](#2e-the-ssl-drop-in)
- [3. RSA pitfalls](#3-rsa-pitfalls)
- [3b. Finite-field Diffie-Hellman pitfalls](#3b-finite-field-diffie-hellman-pitfalls)
- [3c. TLS 1.3 session tickets, server side](#3c-tls-13-session-tickets-server-side)
- [3d. Private key parsing](#3d-private-key-parsing)
- [3e. OCSP stapling](#3e-ocsp-stapling)
- [3f. ALPN](#3f-alpn)
- [3g. TLS 1.3 early data (0-RTT)](#3g-tls-13-early-data-0-rtt)
- [3h. Client certificates](#3h-client-certificates)
- [4. Randomness](#4-randomness)
- [5. Bignum correctness traps](#5-bignum-correctness-traps)
- [6. Certificates: parsing and chain validation](#6-certificates-parsing-and-chain-validation)
- [7. Protocol level](#7-protocol-level)
- [7b. GOST](#7b-gost)
- [7c. SM3, and the SM family generally](#7c-sm3-and-the-sm-family-generally)
- [7d. SM2](#7d-sm2)
- [7e. EdDSA in certificates and in TLS](#7e-eddsa-in-certificates-and-in-tls)
- [7f. Twofish and Serpent](#7f-twofish-and-serpent)
- [7g. PCBC and EAX](#7g-pcbc-and-eax)
- [7h. Buffers at the Python boundary](#7h-buffers-at-the-python-boundary)
- [7i. MD2 and MD4](#7i-md2-and-md4)
- [7j. TEA, XTEA, and the table that hid a panic](#7j-tea-xtea-and-the-table-that-hid-a-panic)
- [7k. RC5](#7k-rc5)
- [7l. ARIA](#7l-aria)
- [7m. Whirlpool](#7m-whirlpool)
- [7n. ElGamal](#7n-elgamal)
- [7o. The GOST curves with cofactor four](#7o-the-gost-curves-with-cofactor-four)
- [7p. GOST R 34.11-94](#7p-gost-r-3411-94)
- [7q. The 2001 GOST suite, 0x0081](#7q-the-2001-gost-suite-0x0081)
- [7r. MGM, the AEAD the GOST TLS 1.3 suites use](#7r-mgm-the-aead-the-gost-tls-13-suites-use)
- [7s. GOST at TLS 1.3, RFC 9367](#7s-gost-at-tls-13-rfc-9367)
- [7t. What three live GOST certificates found](#7t-what-three-live-gost-certificates-found)
- [7u. SLH-DSA (FIPS 205), where the address is the security](#7u-slh-dsa-fips-205-where-the-address-is-the-security)
- [7v. ML-KEM, where a round trip proves nothing](#7v-ml-kem-where-a-round-trip-proves-nothing)
- [7w. ML-DSA, where a valid signature can still be the wrong one](#7w-ml-dsa-where-a-valid-signature-can-still-be-the-wrong-one)
- [7x. Hybrid post-quantum key exchange in TLS 1.3](#7x-hybrid-post-quantum-key-exchange-in-tls-13)
- [7y. SSH](#7y-ssh)
- [7z. Streamlined NTRU Prime](#7z-streamlined-ntru-prime)
- [7za. UMAC](#7za-umac)
- [7zb. ML-DSA in certificates and TLS 1.3](#7zb-ml-dsa-in-certificates-and-tls-13)
- [7zc. DSA in certificates and TLS](#7zc-dsa-in-certificates-and-tls)
- [7zd. The SSH server](#7zd-the-ssh-server)
- [7ze. LRW](#7ze-lrw)
- [7zf. The LUKS example](#7zf-the-luks-example)
- [7zg. The TrueCrypt and VeraCrypt example](#7zg-the-truecrypt-and-veracrypt-example)
- [7zh. The age example](#7zh-the-age-example)
- [7zi. OCB](#7zi-ocb)
- [7zj. The OpenPGP example](#7zj-the-openpgp-example)
- [7zk. XEdDSA](#7zk-xeddsa)
- [7zl. The Signal example](#7zl-the-signal-example)
- [7zm. The KeePass example](#7zm-the-keepass-example)
- [7zn. The ZIP example](#7zn-the-zip-example)
- [7zo. The PDF example](#7zo-the-pdf-example)
- [7zp. The Office example](#7zp-the-office-example)
- [7zq. The OpenDocument example](#7zq-the-opendocument-example)
- [7zr. The key store example](#7zr-the-key-store-example)
- [7zs. The JOSE example](#7zs-the-jose-example)
- [7zt. The 7z example](#7zt-the-7z-example)
- [7zu. The CMS and S/MIME example](#7zu-the-cms-and-smime-example)
- [7zv. The Kerberos example](#7zv-the-kerberos-example)
- [7zw. The wallet example](#7zw-the-wallet-example)
- [7zx. The DNSSEC example](#7zx-the-dnssec-example)
- [7zy. The WireGuard example](#7zy-the-wireguard-example)
- [7zz. The git signing example](#7zz-the-git-signing-example)
- [7zza. Ciphertext stealing, the little-endian counter, CBC-HMAC and CBC-MAC](#7zza-ciphertext-stealing-the-little-endian-counter-cbc-hmac-and-cbc-mac)
- [7zzb. SP 800-108, the Concat and X9.63 KDFs, and RFC 3961](#7zzb-sp-800-108-the-concat-and-x963-kdfs-and-rfc-3961)
- [7zzc. OpenPGP's S2K, 7-Zip's key, KeePass's AES-KDF, LUKS's AF splitter](#7zzc-openpgps-s2k-7-zips-key-keepasss-aes-kdf-lukss-af-splitter)
- [7zzd. Writing encrypted private keys](#7zzd-writing-encrypted-private-keys)
- [7zze. BitLocker](#7zze-bitlocker)
- [7zzf. Wi-Fi: WEP, TKIP, Michael and the WPA handshake](#7zzf-wi-fi-wep-tkip-michael-and-the-wpa-handshake)
- [7zzg. The smart card example](#7zzg-the-smart-card-example)
- [7zzh. The C interface](#7zzh-the-c-interface)
- [7zzi. NaCl and libsodium](#7zzi-nacl-and-libsodium)
- [8. What to do with this document](#8-what-to-do-with-this-document)

---

## 1. Timing and side channels

`BigUint` is correctness-first and is **not constant time**. That is a
deliberate choice, and it has a precise consequence: any operation on a
*secret* value can leak that value through how long it takes. Secrets now go
through a second type instead — see "The two integer types" below.

The dividing line that matters is **public versus private data**:

- Verifying a signature, parsing a certificate, checking a public key — the
  attacker already knows the inputs. Timing leaks nothing. Variable-time code
  is fine.
- RSA private key operations, ECDH scalars, ECDSA nonces, session keys,
  padding checks on data an attacker chose — a leak here recovers the secret.

### What our bignum leaks

| Operation | Leaks | Why |
|---|---|---|
| `cmp`, `PartialOrd` | position of the first differing limb | early return on the first mismatch |
| `add`, `sub` | operand limb count | loop bound is the operand length |
| `mul` | operand limb counts | schoolbook loop bounds |
| `divrem` | quotient magnitude, and the add-back path | data dependent iteration and a rare correction branch |
| `mod_pow` | **the exponent's bit length and Hamming weight** | square-and-multiply skips the multiply on a zero bit |
| `mod_pow_ct` | nothing through the loop | routed through `Montgomery::pow_ct`; the bound is the modulus's width |
| `mod_inverse` | the whole Euclidean trace | iteration count depends on the inputs |
| `mod_inverse_prime` | nothing through the exponentiation | routed through `Montgomery::inverse_prime`, so Fermat; like `mod_pow_ct`, the result is declassified to a `BigUint` |
| `is_zero`, `bit_len` | the value's magnitude | normalised representation, so length is the value |

Most rows of that table are live rows in `scripts/ct_check.py` - `cmp`,
`add`, `mul`, `rem`, `mod_pow_public`, `mod_pow_ct_biguint`,
`mod_inverse`, and `inverse_prime` for the arithmetic under
`mod_inverse_prime` - which runs each one under valgrind with the
operands marked secret. A row that stops behaving as stated fails the
check. `sub`, `is_zero` and `bit_len` have no row of their own.

### The two integer types

The leak is the **representation**, not any particular function. `BigUint` is
normalised — the top limb is never zero — so its limb count is a measurement
of the value, every loop bound derived from it depends on the secret, and
`normalise` pops zeros in a loop. No amount of branchless arithmetic fixes
that while the length still talks.

So there are two types:

| | `BigUint` | `bignum::ct::Secret` |
|---|---|---|
| width | normalised, so variable | fixed at `k` limbs, always |
| comparison | `Ord`, `PartialEq` | `ct_eq`, `ct_lt`, returning masks |
| `Debug` | yes | **no** — printing a secret is the secret in a log |
| to bytes | trims leading zeros | fixed width |
| for | certificates, public keys, signatures | private keys, nonces, shared secrets |

`Secret` deliberately has no `Ord`, `PartialEq` or `Debug`, so `a == b`,
`a < b` and `{:?}` on a secret **do not compile**. That is the type that
separates secret values from public ones.

Crossing back is named for what it costs: `Secret::declassify` normalises,
which is what makes the value's length visible again. It is correct for
something about to be published and wrong for anything else.

### Two things ctgrind found that reading the code could not

**The compiler un-does branchless code.** `Montgomery::conditional_subtract`
was written as `t[i] = select(diff[i], t[i], mask)` over the limbs. LLVM
proved the mask was all-ones or all-zeros, concluded the loop was "copy
`diff` over `t`, or do not", and emitted

```
test %rax, %rax
jne  ...
call memcpy
```

The source was branchless and the binary was not. The fix is
`bignum::ct::opaque`, an empty inline-asm block that makes the optimiser lose
track of the mask; every mask in the module is born opaque so no call site
has to remember. Nothing about this is visible in the Rust.

**And it un-does branchy code too.** Writing `ct_lt`'s last line as
`if borrow != 0 { TRUE } else { FALSE }` compiles to `neg; sbb` — no branch —
and the ctgrind sweep does not notice the difference. So "there is no `if` in
this function" is not the criterion either, in either direction. The binary
is the artefact; the harness is what reads it.

### Where the secrets actually go now

| Caller | State | What is left |
|---|---|---|
| `rsa.rs` private operation | fixed width throughout | the final `declassify` of the plaintext — the API boundary |
| `dh.rs` shared secret | fixed width throughout | one branch on the folded degenerate-value mask, which aborts the handshake anyway |
| `ecdsa.rs` signing | fixed width | the RFC 6979 rejection test, the nonce-below-the-order test that picks the base point's table, the private key's limb count (read once by `Secret::from_biguint`), and the declassification of the nonce's point and of `r` and `s` |
| `ec/mod.rs` scalar multiplication | fixed width (`ec::fixed`; `ec::ct` above nine limbs) | the result leaves through `ec::fixed::publish` as a normalised `BigUint`, and for ECDH that result is the shared secret |

Two of those were found by the harness rather than by reading:
`RsaPrivateKey::raw` built a `Montgomery` per operation, and building one
divides by its modulus — so every private operation began with two divisions
by the secret primes, worse than the `rem` calls the rewrite removed. The
contexts live in the key now. And the Bellcore fault check exponentiated the
plaintext through the public `BigUint` path, so the check on the value leaked
the value; it is `Montgomery::pow_public` on a `Secret` now.

### What our elliptic curves leak

| Operation | Leaks | Why |
|---|---|---|
| `scalar_mul_ct`, `scalar_mul_secret` | nothing | `ec::fixed` for every field up to nine limbs: fixed-size arrays in the Montgomery domain, a four-bit window read by touching every entry with masks, additions whose special cases are masks; `ec::ct` (the same on `Secret`) above nine limbs |
| the same, on the curve's base point | **one bit: whether the scalar is below the order** | the base point has a table of its multiples (`ec::fixed::base_mul`), read the same way, which is only right for a scalar below the order - so that comparison becomes a branch. For a key or an ECDSA nonce it is the same bit on every call |
| `scalar_mul` (public scalars) | nothing up to nine limbs; above that **the scalar's bit length and Hamming weight** | it takes the constant-time path where there is one, and double-and-add otherwise |
| ECDSA verification | **the scalars** | `ec::fixed::verify_sum` slides a window over `u2` and branches on special cases: every input is public |
| any of them, on the way out | nothing in the arithmetic | Fermat inversion of z, whose exponent is public; `ec::fixed::publish` is where the point is normalised and becomes public, and `ct_check.py` names it |

The history below - `mod_inverse` on the way out, a ladder on `Secret` as
the only constant-time path - is kept for the record of what each step
fixed.

**The fixed width is the wider of the field and the group order.** Hasse's
bound lets n exceed p by up to 2*sqrt(p). On a registered curve whose p sits
just below a multiple of 2^64, a reduced scalar can need one more limb than
the field, and sizing the `Secret` by the field alone refused it. The refusal
became a panic in `scalar_mul_ct`, which Python saw from
`EcKey.from_private`. The same curves showed that a private scalar's encoding
width is the order's (RFC 5915), not the field's: `Curve::scalar_bytes`. Every
built-in curve has equal widths, so only a 64-bit test curve with a 65-bit
order (`pytests/test_registered_curve.py`) shows the difference.

The last row is the one to watch: for ECDH the point is the shared
secret, not something about to be published, so `publish` normalising
its x coordinate through `BigUint` leaks the secret's limb count.
`ct_check.py` has no ECDH row; its `sm2_decrypt` row has the same shape
and reports. See section 2, "Scalar handling".

**Status: accepted** for public-value work. **Mitigated** for modular
exponentiation, for the RSA and finite-field Diffie-Hellman paths, which
run entirely on `Secret`, and for elliptic curve scalar multiplication,
which runs on `ec::fixed` (or `ec::ct` above nine limbs); what is left
there is in the table above. **Open** for the ECDH shared secret's exit
through `publish`.

`Montgomery::pow_ct` does one multiply and one square per exponent bit
regardless of its value, selects between the registers with a branchless
conditional swap, and takes its **iteration count as a public parameter**.
That last part was a real leak: the loop used to run `exp.bit_len()` times,
so two private exponents of different lengths did different amounts of work.
The bound is the modulus's width now, and a short secret costs exactly what a
long one does.

**Still open:** the ECDH shared secret leaves `ec::fixed::publish` as a
normalised `BigUint` (the last row of the table above). Reaching for
`mod_pow` with a secret by mistake is no
longer silent — the secret has to be a `Secret` to get into the fixed-width
path at all, and converting back is a call named `declassify`.

The specific attack this enables is not hypothetical: variable-time modular
exponentiation has been used to extract RSA private keys over a network
(Brumley and Boneh, 2003), and the same shape of leak applies to any
square-and-multiply that skips work on zero bits.

**Done:** `Montgomery::pow_ct` is that path — a Montgomery ladder over a
division-free reduction, with a public loop bound — and `bignum::ct::Secret`
is the type that separates secret from public, so that `==` and `<` on a
secret are compile errors. Elliptic curve point arithmetic followed:
`ec::ct` on that type, and `ec::fixed` on fixed-size arrays for every
field up to nine limbs.

### How any of this is checked

`scripts/ct_check.py` runs `tools/src/bin/ct_bignum.rs` under valgrind with the
secrets marked undefined, which turns "branched on a secret" into a memcheck
report. Half the table is code **known** to be variable time, and a clean
result from any of those rows fails the run: a harness that only asserts "no
reports" passes just as well when it has stopped working. The first version
of that harness used a literal as its secret, LLVM folded the branch away,
and it reported a clean bill of health for code that was plainly variable
time.

Seven deliberate breaks of the constant-time code; six caught. The seventh —
writing `ct_lt` through a `bool` — is the second finding above, and is not a
hole.

The call-site rows — `rsa_private`, `rsa_oaep_decode`, `dh_shared`,
`ecdsa_sign`, `aes_xts`, `ml_kem_compress_checked`, `ml_dsa_sign` — assert
that each one leaks **only in the functions named beside it**. Not a
count: those held exact numbers briefly and broke the first time an
unrelated change shifted the optimiser's inlining, because a valgrind
count is the number of distinct stacks rather than a property of the code.
Putting the leading-zero scan back into `dh.rs` now fails with
`position<…to_bytes_be…>` named, which is the line that did it.

### What AES leaks, and which modes are constant time

**Status: mitigated for the modes that encrypt several independent blocks;
accepted for the chained ones.**

AES has two routes (`src/block_ciphers/aes.rs`). One block at a time it is
a 32-bit table implementation, which indexes its tables with bytes of the
state and so leaks key and data through the cache. Several blocks at a time
- `BlockCipher::encrypt_blocks` and `decrypt_blocks` - it is bitsliced and
fixsliced (`aes_bitsliced.rs`): no table lookups and no branches on key or
data. The bitsliced route costs as much for one block as for four, so it is
the route only where the mode has the blocks to fill it.

| Operation | Leaks | Why |
|---|---|---|
| AES key schedule | nothing | `SubWord` through the bitsliced S-box; the decryption keys' InvMixColumns in branch-free arithmetic |
| ECB, CTR, CBC decryption, XTS, GCM, CCM's keystream | nothing | `encrypt_blocks`/`decrypt_blocks` throughout, including GCM's `H` and tag mask, XTS's tweak key and stolen blocks |
| CBC encryption, CFB, OFB, CMAC, CCM's CBC-MAC, a lone `block_encrypt` | **key material through cache timing** | each block depends on the previous one's output, so there is only ever one block to encrypt, and it takes the table route |
| OCB | **key material through cache timing** | its blocks are independent, but `ocb.rs` enciphers them one at a time through `block_encrypt`, so it takes the table route |
| GHASH | nothing | 64x64 carry-less products by integer multiplication with masked operands (BearSSL's `ghash_ctmul64`); see `ghash.rs` |
| XTS tweak doubling | nothing | the reduction is folded in with a mask; it branched on the tweak's top bit, which is secret, before `ct_check.py` reported it |
| XTS key-halves check | only whether they are equal | every byte is compared before the verdict; `==` on the slices stopped at the first difference |
| tag comparison | nothing | fixed-length XOR accumulation, no early return |

Apart from the tag comparison (tested functionally, below), ECB and
CCM's keystream, the rows marked "nothing" are live rows in
`scripts/ct_check.py` (`aes_blocks`, `aes_gcm_seal`, `aes_xts`,
`aes_ctr_cbc_decrypt`, `ghash`), which run them under valgrind with the
key and the data marked secret, and `aes_block_table` is the control
that must report: the same key and data through the table route.

**With the `aes-ni` feature on a processor that has the instructions,
every row above is constant time**, the chained modes included: they run
on `aesenc`, and `python3 scripts/ct_check.py --aes-ni` runs the same
table with the one-block row required to come back clean. The feature is
opt-in because reaching the instructions needs `unsafe`; see "Building
for speed" in `docs/building.md`.

Which route the chained modes take in the portable build was a choice
between two costs, measured on one processor: the table route encrypts
one block at about 270 MB/s, the bitsliced route one block at about a
quarter of its sixteen-block speed,
roughly 55 MB/s. A caller who needs CBC encryption or CMAC to be constant
time is better served by a mode that does not chain - CTR with a MAC, or
GCM - than by a slower CBC.

The tag comparison matters more than it looks: an early return on the first
differing byte turns forgery from 2^128 work into about 4,000 tries, one
byte at a time. It is written as an accumulating XOR over the whole tag for
that reason, and there is a test that every single-byte change is rejected.

### CCM's parameters are entangled, and its tag length is a choice

**Status: mitigated, with one deliberate trade left to the caller.**

CCM shares fifteen bytes between the nonce and the message length field,
so a longer nonce means a shorter maximum message: 13 bytes of nonce caps
a message at 65535 bytes. Exceeding it is refused rather than truncated -
a truncated length would be authenticated as the wrong number, which is a
forgery the sender commits against itself.

The tag may be 4 to 16 bytes. TLS's `_8` suites use 8, and that is a real
trade rather than a saving: a blind forgery succeeds once in 2^64 attempts
instead of once in 2^128. Both are offered because both exist in RFC 6655;
`BulkCipher::tag_len` carries the choice so the record layer cannot assume
sixteen, which would read the last eight bytes of every CCM_8 ciphertext
as part of the tag.

### CCM cannot stream, and an interface that pretended otherwise would lie

The MAC's first block encodes the plaintext's length, so nothing can be
processed until all of it is present.

**Status: mitigated by saying so.** `block_ciphers::ccm` is one-shot.
`api::AeadStream` buffers, and reports it through `buffers_everything()`.
The Python streaming constructors refuse outright, which is the line
`cryptography` draws too. The alternative - an `update` that silently
accumulates - would promise constant memory and not deliver it, and the
caller who needed to know would find out by running out of it.

### Poly1305 is a one-time authenticator

**Status: mitigated by construction, and easy to break if used directly.**

Poly1305 is not a small HMAC. Its security rests entirely on r being
unknown, and two tags under one key give two equations in r and s over a
small field - r falls out, and every later tag can be forged. There is no
"weakened"; it is over.

In ChaCha20-Poly1305 this cannot happen by accident: the key is the first
32 bytes of a ChaCha block generated from the nonce at counter zero, so a
fresh one exists per message, and the payload starts at counter one so the
two never overlap. `mac::Poly1305` is also public, and a caller who keys it
from something long-lived has the failure above. HMAC is the thing to reach
for when a key has to be reused, and `src/mac/poly1305.rs` says so at the
top.

### XTS is not authenticated, and cannot be

The ciphertext is exactly as long as the plaintext, because a disk
sector has nowhere to put an IV or a tag. So there is no room for
authentication, and adding some would mean not implementing XTS.

What follows from that:

* anyone who can write to the storage can replace any 16 byte block with
  bytes of their choosing, and decryption returns plaintext rather than
  an error;
* the same plaintext written to the same sector twice gives the same
  ciphertext, so an observer watching over time learns which sectors
  changed and which reverted;
* a block can be *moved* within its own sector's neighbours only in the
  sense that its tweak fixes its position - XTS does bind a block to its
  place, which is the one integrity-flavoured property it has, and it is
  not integrity.

**Status: accepted**, and said in the doc comment, in `docs/rust.md`, in
`docs/python.md` and in the type stubs, because a caller who thinks
otherwise has a real problem and no way to find out.

### XTS's two key halves must differ

Equal halves make the tweak cipher the data cipher, which collapses the
construction. OpenSSL refuses such a key outright ("In XTS mode
duplicated keys are not allowed"), and `api::xts_encrypt` does too.

This is the one place in the library that is strict about *reading* as
well as writing, and the reason is narrow: no storage was ever written
with such a key, so there is nothing to stay compatible with. Everywhere
else, refusing to read is refusing to do the job this library exists
for.

**Status: mitigated** - `test_xts_refuses_a_key_whose_halves_match`, and
`pytests/test_xts.py` asserts OpenSSL refuses the same key.

### XTS's tweak, and its field, are little endian

Sector 1 is `01 00 00 ... 00`. The multiply by alpha shifts left through
all 128 bits with the carry moving from byte `i` to byte `i+1`, and
`0x87` folds into byte **zero**. Both are the opposite of `ghash.rs`,
which is the other GF(2^128) in this library and is big-endian with
`0xe1` - so copying its doubling gives a self-consistent XTS that mounts
no filesystem anywhere.

**Status: mitigated** - `test_the_tweak_is_little_endian` and
`test_the_alpha_multiply` assert the byte positions directly, and
`pytests/test_xts.py` compares with OpenSSL at ten sector numbers
including 0, where the two endiannesses agree and cannot be told apart.

### Key wrap authenticates without a MAC, and the check must be constant time

Six passes mix every 64 bit half into every other one, and unwrapping
ends by comparing against a known constant. That comparison is the
entire integrity guarantee, so a `==` that stops at the first differing
byte is an oracle for the wrapped key's leading bytes. It is a fold over
all eight bytes here, and the padded form folds its length and padding
checks into the same verdict so the error cannot say which part failed.

**Status: mitigated** for the early exit;
**accepted** that the rest of the unwrap is variable time in the usual
`BigUint`-free sense - it is a fixed number of block cipher calls
determined by a public length.

### Key wrap's counter runs across the passes

`t = n*j + i`, counting passes from 0 and registers from 1, so it takes
`6n` distinct values and never repeats. A counter that restarts each
pass, or that counts from zero, gives a wrap and an unwrap that agree
with each other perfectly and with nothing else.

Unwrapping also runs **both** loops backwards. Reversing only the outer
one is self-consistent whenever `n = 1`, which RFC 3394's vectors never
exercise because its smallest key data is two blocks - RFC 5649's
one-block case is a different code path entirely.

**Status: mitigated** - all six RFC 3394 vectors and both RFC 5649
examples are read out of `rfcs/` at test time, and
`test_the_single_block_boundary` covers `n = 1` on both sides of eight
bytes.

### RFC 5649's padding is part of the authentication

The alternative initial value carries the real message length. On
unwrapping, that length has to be within eight bytes of the padded size
*and* every pad byte has to be zero. Skipping either accepts a forgery
that differs from a real wrap only in bytes nobody reads back.

**Status: mitigated** -
`test_a_length_field_that_does_not_match_the_padding_is_refused` builds
such a forgery by wrapping a bad value directly, because altering a
wrapping at random never gets past the integrity check to reach this.

### AEAD nonce reuse

**Status: accepted, because it cannot be mitigated here, and it is the
worst failure in the library.** It gets its own section because it is not
a side channel and not a gradual weakening - it is total, silent and
immediate.

It applies to every AEAD here. The consequences below are those of GCM
and (X)ChaCha20-Poly1305, which are a stream cipher plus a polynomial
authenticator. The others fail differently - CCM, EAX and MGM also leak
the XOR of the plaintexts through their counter mode - but none of them
is safe under a repeated nonce.

Encrypting two messages under the same key and nonce:

1. Gives away the XOR of the two plaintexts, as any keystream reuse does.
2. Gives away the authentication key - GHASH's H, or Poly1305's r - which
   follows from the two tags by solving a polynomial. After that an
   attacker can forge **any** message under that key, for as long as the
   key is in use, not just alter the two messages involved.

There is no warning, no error and no recovery short of changing the key.

Nothing in `GcmState` or `ChaCha20Poly1305` can detect it, because a nonce
is only a repeat relative to history that lives with the caller. What the
code does instead:

- An **empty** nonce is refused, since GHASH of nothing is zero and J0 would
  then be one fixed block for every key - a guaranteed collision rather than
  a possible one.
- The message length is capped at 2^36 - 32 bytes, so the 32 bit counter
  cannot wrap back onto its own keystream *within* one message.
- Every doc comment on the way in says so, because the only real mitigation
  is the caller knowing.

A short nonce is accepted, unlike in `cryptography`, which refuses anything
under 8 bytes. That is this library's premise - something out there is using
one - but it makes the rule above much easier to break: a 1 byte nonce has
256 values, so a repeat is not a risk, it is a certainty.

### The normalised-representation trap

Our `BigUint` strips leading zero limbs, so the *length of the representation
is a function of the value*. Even a constant-time inner loop leaks through
the loop bound. Any future constant-time path has to work on fixed-width
values, not on normalised ones. This is easy to get wrong by reusing the
existing type.

**Status: mitigated by type.** `Montgomery` works on
`bignum::ct::Secret` - `Montgomery::mul` takes `&Secret` rather than
`&BigUint` - and `bignum::fixed` on `[u64; N]`; the only way in from a
normalised value is `Secret::from_biguint`, which reads its limb count
once. `BigUint` itself stays variable time by design (section 1), and
reusing it on a secret is still the mistake that would make a future
"we made it constant time" quietly untrue.

---

## 2. Elliptic curve pitfalls

Curve arithmetic, ECDH and ECDSA are implemented (`src/ec/`). Each item says
where its test lives.

### Invalid curve attacks

If a peer sends a point that is not on the stated curve, and we do arithmetic
with it anyway, the result can leak the private scalar — often completely,
over a handful of handshakes.

**Status: mitigated.** `Curve::validate` rejects the point at infinity, a
coordinate outside `[0, p)`, and any point that does not satisfy the curve
equation. `decode_point` calls it, so a point that arrived as bytes cannot
reach the arithmetic unvalidated, and `ecdh` calls it again on its own
argument rather than trusting the caller to have done it.

Tested in `src/ec/mod.rs` (off-curve and out-of-range points rejected) and
`pytests/test_ec.py::test_invalid_peer_point_raises`, which also offers a
P-256 point to a secp256k1 key — same field size, so only the on-curve check
catches it.

In TLS there are two further ways to end up in a group you did not choose,
and neither is caught by validating a point, because the point is perfectly
valid in the group the *server* named:

- **Explicit curve parameters.** RFC 4492's `ECParameters` lets a server
  send arbitrary `a`, `b`, `p` and a base point instead of naming a curve —
  the attacker picks the group outright. **Status: mitigated.** Only
  `named_curve` is accepted; `ServerEcdhParams::parse` refuses the other
  two curve types, tested in `src/tls/handshake.rs`.
- **A named curve the client never offered.** Still a real curve, so every
  point check passes. **Status: mitigated.** `handle_server_key_exchange`
  refuses any group outside `OFFERED_GROUPS`, before the signature check
  and therefore before any arithmetic in that group. Tested in
  `src/tls/client.rs` with secp256k1, which we implement and do not offer.

### What actually validates, and where

Audited by deliberate breakage rather than by reading. Every point that
arrives from outside passes through one of two doors, and **both**
validate:

* `Curve::decode_point` validates what it decoded, so every point that
  arrives as bytes is checked - the TLS 1.2 ServerKeyExchange, the
  TLS 1.3 `key_share` on both the client and the server side, the
  ClientKeyExchange, and a certificate's EC key on its way to an ECDSA
  verification;
* `Curve::ecdh` validates the peer point again before multiplying, and
  `ecdsa::verify`, `gost3410::verify` and `vko` each validate the public
  point they are given.

`validate` refuses the identity, a coordinate at or above `p`, and
anything off the curve equation. Removing the on-curve test, or making
`is_on_curve` return true, fails tests in `ec`, `ecdsa` and `vko`;
removing the validation from `decode_point` or from `ecdh` fails tests
too. Compressed decoding cannot produce an off-curve point in the first
place, since `y` is *derived* from the curve equation - it is validated
anyway.

Two checks in that path are **unreachable**, which a sweep reports as
"not caught" and which is not the same as untested:

* `validate`'s explicit `x >= p` is redundant with `is_on_curve`, which
  bounds its own coordinates. Kept because the *reason* matters to
  whoever reads the error, and pinned by
  `test_an_out_of_range_coordinate_says_so`;
* `ecdh`'s refusal of a degenerate shared secret cannot fire once
  `validate` has passed on a cofactor-1 curve. Kept because the
  alternative is returning a secret of zeros, and pinned by
  `test_ecdh_refuses_a_degenerate_secret`.

**Status: mitigated.**

### Small subgroup and twist attacks

For curves with a cofactor, a peer can send a point in a small subgroup and
learn the scalar modulo the subgroup order. For x-only ladders, an invalid x
can land on the quadratic twist, which may have a weak order.

**Status: mitigated.** On the Weierstrass curves the on-curve check
above already excludes the twist. Two built-in curves, `gost256-tc26-a`
and `gost512-c`, have cofactor h = 4, and `validate` multiplies by `n` on
any curve with `h > 1` - which is what `Curve` carries `h` for (next
section, and section 7o). Curve25519 (h = 8) and Curve448 (h = 4) are
section 2b's: their scalars are clamped to a multiple of the cofactor,
and an all-zero shared secret is refused.

### The subgroup branch in `validate` was dead code

While every curve here had cofactor 1, being on the curve and not the
identity was the whole of membership and `validate`'s
prime-order-subgroup test never executed. A test asserted the cofactors
so that adding a curve with `h > 1` would fail there first and say the
branch had become live.

**Status: mitigated.** The branch is live code now: the two cofactor-4
GOST curves made it so, and section 7o, "`validate`'s subgroup branch
became live code", records that and the test that now covers it.

### Ed25519 and Ed448 do no subgroup check at all

Different from the Weierstrass curves above, and worth stating plainly
because it is the one place a "the signature verified" is weaker than it
looks.

Ed25519 has cofactor 8 and Ed448 cofactor 4. `verify` uses the
**cofactorless** equation `S*B == R + k*A`, which RFC 8032 section 5.1.7
explicitly allows, and neither `A` nor `R` is checked for small order.
The consequence is concrete: the identity point is accepted as a public
key, and the signature `R = identity, S = 0` verifies under it **for
every message**.

That forges nothing - nobody holds a private key for the identity, and
anyone can construct this - but it means a verified signature is not on
its own evidence that a particular party signed. A protocol that takes a
public key from the caller and treats it as an identity has to reject
small-order keys itself.

**OpenSSL does exactly the same**, and
`test_a_small_order_public_key_is_accepted_as_openssl_accepts_it`
asserts that rather than assuming it - so this is a recorded decision to
match the reference implementation, and the test fails if either side
changes its mind. libsodium is the counter-example: it rejects
small-order `A` and `R`. ZIP-215 is the written-down set of rules for
protocols that need this pinned down exactly.

**Status: accepted**, deliberately, with the reference implementation's
behaviour as the reason. It is a candidate for an opt-in strict mode
rather than a default, because being stricter than the world refuses
signatures the user cannot fix.

### Incomplete addition formulas

The classic Jacobian addition formulas are wrong when the two inputs are
equal (they compute a doubling incorrectly) or when one is the point at
infinity. Scalar multiplication hits both cases for specific scalars, so the
bug only appears for some inputs — which unit tests with one test vector will
not find.

**Status: mitigated.** `add_jacobian` branches explicitly on `u1 == u2`:
equal x with equal y is a doubling, equal x with opposite y is the identity.
`double_jacobian` handles y = 0. The identity is representable (z = 0) rather
than being a special case the caller has to remember.

Those branches are in the `BigUint` reference arithmetic; the secret
paths, `ec::fixed` and `ec::ct`, select the same cases by mask (see
"Scalar handling" below).

Tested in `tools/src/bin/diff_ec.rs` — 1,320 cases across every curve in
`curves::all()`, against OpenSSL for the curves it has and against the
checker's own arithmetic for the GOST curves and SM2 — plus unit tests
for exactly the awkward scalars: 0, 1, 2, n-1, n, n+1, and P + (-P).

### Nonce generation for ECDSA

A biased, repeated, or partially known ECDSA nonce leaks the private key. Two
signatures with the same nonce leak it immediately and trivially. Even a few
bits of bias across many signatures is enough via lattice reduction. This is
how the PS3 signing key went, and how several Bitcoin wallets were drained.

**Status: mitigated, structurally.** `src/ec/ecdsa.rs` derives k through the
RFC 6979 HMAC chain from the private key and the message hash. Nothing in
that file calls `random`, so there is no entropy source to fail, no repeat to
stumble into, and nothing for a bad `/dev/urandom` to poison. A reused nonce
is not a bug that can happen here; it would require the same key signing the
same digest, which produces the same signature and reveals nothing.

The RFC's own appendix A.2.5 vectors are checked in `src/ec/ecdsa.rs`, and
`tools/src/bin/diff_ecdsa.rs` has OpenSSL verify 528 of our signatures across
four curves (P-256, P-384, P-521, secp256k1), four hashes and eleven
message lengths.

Two details in there that are easy to get wrong and would not show up as a
test failure without a vector: the digest is truncated from the *left* to the
order's bit length rather than reduced modulo the order, and a retry
continues the same K/V chain rather than restarting it — restarting would
make k depend on the retry count.

The nonce never becomes a `BigUint`. It is a fixed-width `Secret` from
the HMAC chain on, `k * G` goes through `scalar_mul_secret_bytes`, and
`s = k^-1 (e + r d)` is `ec::fixed::signature_s`, with Fermat inversion
over `n` (`Montgomery::inverse_prime` above nine limbs). What the
`ecdsa_sign` row of `ct_check.py` still reports is in "Scalar handling"
below.

### The base point's table assumes a scalar below the order

`ec::fixed::base_mul` computes `k * G` from a table of `j * 16^i * G` with
one affine addition per nibble and no doublings (the reason ECDSA P-256
signing went from 5,800 to 18,600 a second). The additions handle the
identity by mask but not `P = Q` or `P = -Q`, and that is only safe
because neither can happen: after row `i` the accumulator is `m * G` with
`m < 16^i`, so it cannot equal `j * 16^i * G`, and the two can only be
opposite if the low `4i + 4` bits of `k` are a multiple of the order -
impossible when `k` itself is below it.

So the precondition is load-bearing, and `Curve::scalar_mul_secret_bytes`
checks it with `Secret::ct_lt` before taking the table, falling back to the
general window otherwise. The comparison's answer is a branch: one bit,
"below the order", which for a private key or an RFC 6979 nonce is the same
on every call. A test multiplies the base point by `n - 1`, `n`, `n + 1`
and the widest scalar the call accepts, which all must agree with
double-and-add whichever path they take.

The tables are cached per curve - keyed on every parameter, the generator
included, because a curve with `2G` as its base point needs another
table - and at most sixteen are kept.

### Scalar handling

Scalar multiplication whose loop bound or branch pattern depends on the
scalar leaks it. The same public/private split applies as for `mod_pow`.

**Status: mitigated.** The split is deliberate:

| Function | Behaviour | For |
|---|---|---|
| `scalar_mul` | `ec::fixed`'s four-bit window up to nine limbs; double-and-add on `BigUint` above | public scalars |
| `scalar_mul_secret`, `scalar_mul_secret_bytes`, `scalar_mul_ct` | `ec::fixed`'s four-bit window with masked table reads (the base point's table for `G` and a scalar below the order); `ec::ct`'s ladder above nine limbs; the width is the wider of the field and the order | private scalars |
| `ec::fixed::verify_sum` | the base point's table for `u1`, a sliding window over `u2`, special cases by branch | ECDSA verification |

`generate_key_pair`, `ecdh`, ECDSA signing and `api::EcKey` all go
through `scalar_mul_secret`, directly or by way of `scalar_mul_ct` and
`scalar_mul_secret_bytes`, so the scalar's Hamming weight and magnitude
do not change the operation count. Verification deliberately uses
`verify_sum` (or `scalar_mul` above nine limbs): everything in it is
public.

**Closed.** Up to nine limbs the secret path is `ec::fixed`, on
fixed-size arrays in the Montgomery domain, whose addition selects its
special cases by mask in the same way as `ec::ct`. Above nine limbs
`Curve::scalar_mul_ct` runs on `ec::ct`, where every coordinate
is a `bignum::ct::Secret` of the field's width in the Montgomery domain, the
registers are exchanged by a masked swap, and the three special cases of
Jacobian addition — P = Q, P = −Q, either operand the identity — are computed
as masks rather than tested. That costs one extra doubling per addition: both
the generic sum and the doubling are computed every time, because *which* case
applies is a fact about secret values.

An earlier step follows, for the record of what it fixed.

**The inversion on the way out:** the inverse called once per scalar
multiplication, to convert out of Jacobian coordinates, takes the Z
coordinate — a value derived from the secret scalar. It used to be
`mod_inverse`, the extended Euclidean algorithm, whose iteration count is
about as direct a readout of a secret as a side channel gets. It is
`mod_inverse_prime` now: Fermat, so an exponentiation, so constant time.
The field characteristic is prime by definition, and one extra
exponentiation per scalar multiplication is a price worth paying.

**What the ECDSA row still reports**, after all of that, is four things and
none of them is the arithmetic: the RFC 6979 rejection test (a branch on the
candidate by construction); the nonce-below-the-order test that chooses
the base point's table (one bit, the same on every call); the
declassification of the nonce's point in `ec::fixed::publish` and of `r`
and `s` (which are half a signature each and about to be published); and
the private key's limb count, read once per signature by
`Secret::from_biguint` because the key arrives as a `BigUint`. The last is
the same on every call with the same key, so it is not a channel that
accumulates.

Two things from the breakage sweep of the constant-time EC code are worth
keeping:

- **The P = −P select in `ec::ct::Field::add` is redundant**, and removing it
  fails no test. When `u1 == u2` the generic formula has `h = 0`, so
  `z3 = h·z1·z2 = 0` — the identity, whatever `x3` and `y3` came out as. It
  is kept as defence in depth with a comment saying exactly that, because a
  reader would otherwise believe it load-bearing and a sweep cannot tell the
  two apart.
- **A regression can make the valgrind report count go *down*.** Replacing
  the ladder's masked `cond_swap` with `if bit { mem::swap }` — a serious
  leak of the scalar — took `ecdsa_sign` from 9 reports to 5, because the
  different code shape merged several stacks. That is the second and better
  reason `ct_check.py` compares function names rather than counts.

### P-521 is 66 bytes, and its constants are not to be typed

P-521's field is `2^521 - 1`: 521 bits, which is eight 64 bit limbs and
one bit, and 65 bytes and one bit. Every fixed-width encoding of one of
its values - a coordinate, a shared secret, an ECDSA `r` or `s`, a
private key - is **66 bytes**, and the top byte is 0 or 1. Anything that
computes a width as `bits / 8` instead of rounding up is one byte short,
and anything that strips leading zeros before sending is short half the
time rather than one time in 256, so the bug shows up quickly - which
is the good news. `field_bytes` rounds up; `pytests/test_ec.py` pins 66
against OpenSSL's encoder; and the TLS tests run P-521 at both versions
in both directions, so the widths in a ServerKeyExchange, a key share
and a CertificateVerify are all checked by somebody else's parser.

**Its constants were typed once, and were wrong.** The first `p521()`
had its parameters retyped from a terminal into a script - and `p` came
out with two extra `f`s, a 529 bit number that is not prime. Every
other test then failed in ways that pointed nowhere in particular ("G is
not on the curve"). What named the cause was `rfc5903_tests`, which reads
all three NIST curves out of RFC 5903 at test time and compares; the
constants now in the source were generated from the document by script.
The same test also checks P-256 and P-384, which had only ever been
checked for consistency, and RFC 5903's section 8 exchange on each.

**Status: mitigated**, by `ec::curves::rfc5903_tests` and the P-521 rows
in `scripts/diff_check.py` (ECDSA and premaster against OpenSSL).

---

## 2b. X25519 pitfalls

Implemented in `src/ec/x25519.rs`. The curve was designed so that several
of section 2's pitfalls cannot happen; the ones that replace them are
different in kind, and mostly about interoperating rather than about
attacks.

### There is no point validation, and adding one would be the bug

Every 32 byte string is a valid u coordinate. Values that are not on the
curve land on its quadratic twist, which Curve25519 was chosen to give a
large prime order subgroup — so there is nothing to refuse. RFC 7748 also
says the u coordinate's top bit is **ignored** rather than rejected.

**Status: mitigated by construction.** The top bit is masked, not
refused. An implementation that validates instead would refuse input the
specification requires it to accept and would fail against a peer doing
exactly what it was told to. The differential corpus deliberately feeds
arbitrary 32 byte strings, a quarter of them with the spare bit set, and
compares with OpenSSL.

### The scalar must be clamped

Low three bits cleared so the scalar is a multiple of the cofactor, top
bit cleared and the next one set so every scalar has the same length.
Without it: small-subgroup exposure, and a ladder whose iteration count
depends on the secret.

**Status: mitigated.** `x25519()` clamps, so no caller can forget, and
clamping is idempotent so doing it twice is harmless.
`generate_key_pair` stores the clamped form, so the private bytes and the
public key cannot disagree about which scalar this is. The visible symptom
of getting this wrong is not a break but an implementation that agrees
with itself and with nobody, which no round-trip test catches — so the
test is the RFC 7748 vectors and agreement with OpenSSL.

### Little-endian, in a library that is otherwise big-endian

RFC 7748 encodes everything little-endian. Every other encoding in this
library is big-endian.

**Status: mitigated**, by `Fe::from_bytes`/`Fe::to_bytes` in
`ec/field25519.rs` being the only conversions, both little-endian by
construction, and by the section 6.1 vector, which fixes the public keys
as well as the shared secret and so fails loudly if the order is wrong. A
section 5.2 vector alone would not: it is symmetric enough to pass by
luck.

### The all-zero output

A peer sending one of the low-order points forces the shared secret to
zero — a constant every observer knows. RFC 7748 §6.1 says an
implementation "MAY" check for it.

**Status: mitigated.** `exchange` refuses it; `x25519` (the raw
primitive) does not, because the primitive is what the specification's
test vectors are stated in terms of and the judgement belongs to the key
exchange. A test covers all five published low-order points.

### The all-zero check stopped at the first non-zero byte

`exchange` tested for zero with `iter().all(|b| *b == 0)`, which returns
at the first non-zero byte - so its running time said where that byte
was, which is more about the shared secret than the verdict. The
`x25519` row in `scripts/ct_check.py` runs the raw ladder, to keep the
verdict's own branch out of a clean row, and so left the loop before the
verdict out as well. X448 had the same line.

**Status: mitigated.** Both fold the bytes with OR and branch once. The
`x25519_exchange` and `x448_exchange` rows allow a report from
`exchange` itself and nowhere else; the early exit reported from inside
`all`, which those rows would name as new.

### The ladder swapped its registers with a branch on the scalar

The ladder's iteration count is fixed by clamping and its inversion is
Fermat's, not Euclid's, so its *shape* never depended on the scalar. Its
swaps did: the first version ran on `BigUint` and selected the registers
with `if bit != swapped { swap }` - a branch on every bit of the private
key - under a comment that said the swap was masked. There was nothing of
fixed width to mask between, since a `BigUint`'s length is a measurement
of its value, and `scripts/ct_check.py` had no row for it, so nothing
noticed the comment and the code disagreeing. X448 had the same code.

**Status: mitigated.** Both ladders now run on fixed-limb fields
(`ec/field25519.rs`, five 51-bit limbs; `ec/field448.rs`, eight 56-bit
limbs) with no branch or memory index on a value, and the swap is a mask.
The `x25519` and `x448` rows in `scripts/ct_check.py` are expected clean,
and replacing the masked swap with an `if` makes the `x25519` row report.
The old `BigUint` ladders are kept in each module's tests as the
reference the new ones are compared against over random and edge-case
inputs. The new ladder is also some 25 times faster, within 25% of
OpenSSL.

### X448 is not X25519 with bigger numbers

Implemented in `src/ec/x448.rs`, and everything in this section applies
to it — but four things differ, and three of them are silent:

| | X25519 | X448 |
|---|---|---|
| field | `2^255 - 19` | `2^448 - 2^224 - 1` |
| `a24` | 121665 | **39081** (`A = 156326`) |
| base point u | 9 | **5** |
| clamp | three low bits, bit 255 clear, bit 254 set | **two** low bits, bit **447** set |
| spare high bit | one, and RFC 7748 says ignore it | **none** — 448 bits is exactly 56 bytes |
| ladder rounds | 255 | **448** |

**Status: mitigated, by vectors rather than by care.** Each of those
produces something that round-trips, agrees with itself, exchanges
successfully against another copy of itself, and matches no published
value:

- **A copied `a24`** gives a different curve. Pinned by
  `test_the_constants_are_curve448_s`, which checks `(a24 * 4) + 2 ==
  156326` and asserts it is not 121665.
- **A copied clamp** gives a valid scalar of a different value — the
  public key is a real point on the right curve.
  `test_the_clamping_is_x448_s_and_not_x25519_s` asserts the bit
  positions, including that the third low bit is *left alone*, and a
  second assertion on a zero input pins the direction so the test cannot
  pass on an implementation that set the first byte's top bit instead.
- **447 rounds instead of 448** drops the highest bit of every scalar —
  the bit clamping has just set — so every answer is wrong and every
  answer is still a point on the curve. Only a published vector notices.
- **Masking a spare bit that does not exist** clears a real bit of the
  peer's coordinate. There is no such bit here, and a coordinate at or
  above `p` is reduced rather than refused, which is what OpenSSL does;
  `diff_x448.rs` builds such coordinates on purpose and asserts how many
  it made, because a random 56 byte string is below `p` essentially
  always.

The thousand-round chained vector from RFC 7748 §5.2 is the one that
catches a ladder which is right for *some* scalars: each answer is fed
back as the next coordinate, so one wrong bit anywhere wrecks everything
after it. The comment on it says not to shrink the count — 1, 1,000 and 1,000,000 are the only checkpoints
the document publishes, so a chain of any other length is a test of the
code against itself.

### X448 over TLS, and the trap that is not about X448 at all

It is offered now, as group 30, at 1.2 and 1.3 on both sides. Two things
there are worth knowing before touching them.

**The width to check comes from a table, not from a literal at the point
of use.** X25519 is 32 bytes and X448 is 56, and the two are handled by
one function in `tls::client`. Writing each width where it is needed is
how one curve comes to be measured against the other's — and the failure
is silent in the worst way: 56 bytes truncated to 32 is still a perfectly
valid u coordinate, every byte string of the right length is, so nothing
downstream has anything to object to. The client's error message names
the group and the width it wanted for the same reason, because "32 bytes"
in an X448 failure is the bug rather than the diagnosis.
`test_an_x25519_point_of_the_wrong_length_is_refused` and
`test_an_unimplemented_group_is_refused` - whose name predates X448
being offered - each send a 65 byte point in a ServerKeyExchange: the
first asserts the refusal says `32 bytes`, the second that it names
`x448`. Nothing yet asserts that an X448 refusal does *not* say
`32 bytes`.

**And the trap.** An OpenSSL client pinned to one Montgomery group
refused our TLS 1.2 ServerKeyExchange with `illegal_parameter`, for
X25519 as well as X448 — which reads precisely like a malformed
ServerKeyExchange, and is not. At TLS 1.2, RFC 4492 gives
`supported_groups` a **second job**: it constrains the curve of an ECDSA
*certificate* as well as the ECDHE group. A client offering only X25519
is therefore saying it will not accept a P-256 certificate, and OpenSSL
enforces that. TLS 1.3 dropped the overlap — there the certificate's
curve comes from `signature_algorithms` — which is why the 1.3 rows of
the same test passed while both 1.2 rows failed, and that asymmetry is
the clue to read. The fix was an RSA certificate in the test; the code was
right the whole time.

Worth remembering in the other direction too: a client that sends a
narrow `supported_groups` at 1.2 is also narrowing which certificates a
server may present to it.

---

## 2c. EdDSA pitfalls

Implemented in `src/ec/eddsa.rs`: pure Ed25519 and pure Ed448, RFC 8032.
A third arithmetic beside the Weierstrass curves and X25519's Montgomery
ladder, and a third set of ways to build something self-consistent that
interoperates with nothing.

### The private key is not the scalar

It is 32 (or 57) random bytes, and the scalar is the *clamped first half
of their hash*; the second half is the `prefix` that makes the nonce
deterministic. Signing with the key bytes directly gives well-formed
signatures that verify perfectly against any implementation making the
same mistake — which, if both ends are yours, is every implementation you
test against.

This is also why the private key is **not** stored clamped, where
X25519's is: clamping these bytes would change which key they are, and
the public key would stop matching the one OpenSSL derives from the same
file. `test_the_private_key_is_not_stored_clamped` asserts it.

**Status: mitigated** — `test_the_key_is_hashed_before_it_is_a_scalar`,
and every vector in RFC 8032 section 7.

### Ed448's `dom4` goes on two of the three hashes, not all three

RFC 8032 section 5.2.5 expands the private key with plain
`SHAKE256(x, 114)`. Only the `r` and `k` hashes carry `dom4` — the string
`"SigEd448"`, the pre-hash flag and the context length. This library
applied it to all three at first, which produced a completely
self-consistent Ed448: signing and verification agreed, the group law
held, the base point had the right order, and every public key was wrong.

Nothing but a published vector can see it. `hash` and `hash_private_key`
are two functions rather than one with a flag, because a flag is
something a call site can pass wrongly.

**Status: mitigated** — the RFC's own vectors, read out of
`rfcs/rfc8032.txt` at test time rather than copied.

### The square root has two roots and both are on the curve

Decoding a point recovers `x` from `y`, and the encoding's top bit says
which root. Picking the other one gives a point that is still on the
curve, so nothing errors anywhere downstream and every signature is
simply wrong. Ed25519 needs `p = 5 mod 8`'s two-step root (with a
multiply by `sqrt(-1)` when the first candidate squares wrongly); Ed448
needs `p = 3 mod 4`'s one-step root. Using one curve's method on the
other silently produces a non-root.

**Status: mitigated** — `test_point_encoding_round_trips` asserts the
sign bit selects a *different* `x` and the *same* `y`, and
`test_the_primes_suit_their_square_roots` pins each prime to the
exponentiation that assumes it.

### An unreduced `S` is a second valid signature

RFC 8032 section 5.1.7 requires `S < L`. Without the check, `S + L` gives
another signature over the same message under the same key, which has
broken real systems that used a signature as an identifier. The check is
cheap, it is easy to leave out, and nothing that only ever sees honest
signatures notices.

**Status: mitigated** — `test_an_unreduced_s_is_refused` in both the
Rust and the Python suites, and the Python one asserts OpenSSL refuses it
too, so the row is a comparison rather than a claim.

### The pure, context and pre-hashed variants are different schemes

Ed25519ctx, Ed25519ph and Ed448ph use the same curves and the same key
sizes as the pure variants. Treating one as a spelling of the other
produces signatures that verify here and nowhere else, and the key and
signature lengths give nothing away. `api::eddsa_variant` refuses all
three **by name**, with an error saying they are different schemes rather
than unknown curves.

**Status: mitigated** for the confusion;
**open** as a feature — they are simply not implemented.

### The scalar multiplication was not constant time

The first `multiply` was double-and-add over `BigUint`: it branched on
each bit of the scalar, and `BigUint`'s normalised limb count is itself a
measurement of the value. Both the long-term scalar `s` and the
per-message nonce `r` went through it. A nonce leak matters more here
than it looks: EdDSA has no inversion in its signing equation, but
`S = r + k*s` with a known `r` gives `s` directly.

Adding the `eddsa_sign` row to `scripts/ct_check.py` found a second leak
before the first was fixed: `multiply` looped `scalar.bit_len()` times,
so the iteration count announced the nonce's magnitude on every
signature. That was closed first by looping `Variant::scalar_bits()`
times.

**Status: mitigated.** Signing, key derivation and verification now run on
`ec/edwards.rs`: extended coordinates over the fixed-limb fields
`ec/field25519.rs` and `ec/field448.rs`, complete addition and doubling
(no special cases to branch on), and a four-bit fixed window whose table
lookup reads all sixteen entries and keeps one with a mask. The
arithmetic modulo `L` - the reduction of the 64 or 114 byte hashes and
`S = r + k*s` - is `bignum::Montgomery` on fixed-width `Secret`s, with
`L` public. The `eddsa_sign` and `ed448_sign` rows are expected clean,
and replacing the masked lookup with an `if` makes `eddsa_sign` report.

The `BigUint` implementation is kept, test-only, as
`eddsa::reference`: the new arithmetic is compared against it on scalar
multiples, joint multiplications and decodings of random and edge-case
encodings. It is also what made the change safe to make - two
implementations from different formulas that have to agree on every
point.

### The points are projective, so equality is not coordinate equality

Two representations of the same point differ in all three coordinates.
`Point::equals` cross-multiplies by the other's `Z`. Comparing `x` and
`y` directly makes verification reject every valid signature, which at
least fails loudly — but the same shortcut inside the group-law tests
would make them pass vacuously, which does not.

**Status: mitigated** — `test_the_group_law` compares points that arrive
by different routes on purpose.

---

## 2d. Trust store and SNI pitfalls

Found by running this library on a second machine, which is the only
thing that finds them: every one is an assumption that is true of the
machine the code was written on.

### A trust store's size is a property of the machine

`assert len(store) > 20` failed on a box with a smaller store - a
minimal container image, a locked-down build, a device that trusts one
internal CA. It caught nothing either: `TrustStore::system` already
errors rather than returning an empty store, so the threshold sat
between "some" and "some", and its only effect was to fail on hardware
nobody had tried.

**Status: mitigated** - the count is printed and nothing is asserted
about it. The third time this project has had to learn that a count is
not a diagnosis; see `TrustStore::skipped` and `ct_check.py`'s rows.

### A root in a trust store need not be self-issued

Cross-signing is how CA transitions work: the new CA's key and name,
certified by the *old* CA, so clients that do not know the new root can
still build a path to one they do. Both forms then sit in stores at
once, and the cross-signed one has subject != issuer.

`x509::verify` was already right - it matches an anchor by name and
checks the signature that anchor made, so being in the store is what
makes something trusted. Only the test believed a root must be
self-signed, and it failed on a machine whose store held one.

**Status: mitigated** - the real-store test counts and names
cross-signed entries instead of refusing them, and
`test_a_cross_signed_root_is_a_usable_anchor` constructs the pair so
the property is covered on every machine rather than on one.

### The chain a server sends is a hint, not the path

The other half of cross-signing, and the one that bit: a server sends
its chain *up to the cross-signed copy* of its root, for clients that
only know the older root. Google and Cloudflare both send `GTS Root R1`
certified by `GlobalSign Root CA`. A store that has the self-signed GTS
Root R1 - and, as stores retire old roots, no longer has GlobalSign's -
must stop at GTS Root R1. Walking to the end of what was sent asks for
the one root that is not there, and every connection to those servers
failed with `unknown_ca: No trusted root issued CN=GlobalSign Root CA`.

`verify_chain` now tries the shortest prefix of the sent chain whose top
a trusted root issued, from the leaf up - OpenSSL's default since 1.1.0
(`X509_V_FLAG_TRUSTED_FIRST`). Nothing offline could see it: every
chain in the tests was one this repository built, ending exactly at the
root it trusted. `check_live.py` found it.

**What is cut off must continue the chain.** The first version cut any
tail, and a chain sent the wrong way round, `[intermediate, leaf]`,
then verified as a path of one: the intermediate, which a root did
issue, standing in as the end-entity. `test_chain_order_matters` in
the Python suite caught it. A prefix is taken only when the first
certificate dropped names itself the issuer of the last one kept, so
going *too far* up is forgiven and going *sideways* - a misordered
chain, or an unrelated certificate after the path - is still refused,
as it was before. OpenSSL is more forgiving than that (it treats what
was sent as an unordered pool); this library keeps order as the
sender's job, because reordering has hidden real misconfigurations.

**Status: mitigated** - `test_a_path_stops_at_a_trusted_root_the_chain_runs_past`
builds the Google shape and the two sideways ones, and
`test_a_refusing_root_part_way_up_is_the_reason_given` keeps the error
pointing at the root that refused rather than at the end of the line.

### `server_hostname` is required only when something checks it

Python's `ssl` accepts `server_hostname=None` once `check_hostname` is
off, and sends no SNI - which is how you talk to a box by address, or
to something whose certificate you are not going to judge. This shim
demanded a hostname unconditionally, so neither was possible.

Being stricter than the thing you are standing in for is not caution
here: there is nothing to check the name against, so requiring one only
makes the caller invent it - and an invented name in SNI is a name the
server may route on.

**Status: mitigated** - `ClientConnection::new` refuses an empty
hostname only while `verify_hostname` is on, and the shim raises
CPython's exact message otherwise.

### "No SNI" is an absent extension, not an empty one

RFC 6066 section 3 defines `server_name`'s body as a **non-empty** list
of names and forbids a literal address in one, so a client with nothing
to say omits the extension - which is what a browser does when you type
an IP address. Sending the empty form gets an alert from some servers
and the default certificate from others: it works until it does not,
and from the client both look like the server's choice.

**Status: mitigated** - the hello is parsed rather than scanned for
bytes (0x0000 is the `server_name` code and also appears inside a
random and a key share), and a real OpenSSL server at TLS 1.2 and 1.3
completes the handshake and reports `server_hostname is None`.

### Wrapping an unconnected socket

`ssl` wraps one happily and waits for `connect`; this shim handshook
immediately and died with `BrokenPipeError`. Worse, `connect` fell
through `SSLSocket.__getattr__` to the raw socket, so it connected the
TCP socket and never started a handshake - leaving the caller reading
TLS records as though they were the reply.

**Status: mitigated** - `__init__` asks the socket for a peer before
handshaking, and `connect`/`connect_ex` are defined rather than
forwarded. The general lesson is about `__getattr__`: it makes every
method the shim *forgot* look implemented.

---

## 2e. The `ssl` drop-in

`allcrypt_ssl` carries every name the standard library's `ssl` exports
so it can be substituted wholesale. The traps are not about TLS.

### A flag that is accepted and ignored is a lie the caller acts on

`OP_*` and `VERIFY_*` are not data. `urllib3` sets
`OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_COMPRESSION | OP_NO_TICKET` on every
context it builds. `OP_NO_SSLv2` and `OP_NO_COMPRESSION` were already
true of this stack, `OP_NO_SSLv3` narrows its version window, and
**`OP_NO_TICKET` was ignored**. A context that stored the flag and
carried on turned "I asked for no session tickets" into "I got session
tickets", with nothing anywhere to report it.

So every flag now either changes what this stack does, is already true
of it, does not apply to it (`OP_ALL`, a bag of workarounds for other
stacks' bugs), or raises, and `option_report()` /
`verify_flags_report()` say which of the first three. There is
deliberately no fourth answer: a flag that would need one raises when
it is set, which is why `"unknown"` appearing in a report means the
report and the implementation have drifted apart.

**Status: mitigated** - and the tests are load bearing here in a way
they usually are not, because a flag quietly doing nothing looks
exactly like a flag working.

### Options describe a set; this stack offers a range

`minimum_version`/`maximum_version` give a contiguous window and the
`OP_NO_*` flags give a set. Narrowing at either end is the case every
real caller produces. A hole in the middle is refused by name, because
offering TLS 1.2 after being told not to is the quiet disagreement the
whole module exists not to do, and an empty window is refused with both
the range and the flag that emptied it named.

**Status: mitigated.**

### Composite flags need `x & flag == flag`

`VERIFY_CRL_CHECK_CHAIN` is `VERIFY_CRL_CHECK_LEAF` with a second bit,
and `OP_ALL` is a bag of bits. A truthiness test matches the composite
for a caller who set only part of it and reports the wrong name - the
right refusal with the wrong reason, which sends whoever reads it
looking for a setting they never made. Zero-valued members
(`OP_NO_SSLv2` on any OpenSSL that dropped SSLv2, `VERIFY_DEFAULT`)
match *everything* under that test and are skipped explicitly.

**Status: mitigated**, by tests that set each flag alone and assert the
name in the error.

### Assigning `minimum_version` clears the matching `OP_NO_*` bits

Every context starts with `OP_NO_SSLv3` set, so asking for SSLv3 looks
like it should need two decisions. It does not: the standard library's
`minimum_version` setter rewrites the option bits, so lowering the floor
clears the flag. Worth knowing, because the behaviour is surprising in
both directions - and a future change to that setter would silently
make the documented SSLv3 path stop working, which is why there is a
test asserting the side effect rather than only the result.

**Status: mitigated** - `test_asking_for_sslv3_by_version_just_works`.

### `tls-unique` is returned at TLS 1.3, and that is a decision

RFC 9266 does not define `tls-unique` for TLS 1.3 and offers
`tls-exporter` in its place, so the sound answer at 1.3 would be
nothing at all. OpenSSL returns the Finished anyway, every peer that
asks for `tls-unique` at 1.3 gets it, and a client that alone returned
`None` would fail every SCRAM exchange against them while being no
safer - the value is exactly as unsound at both ends.

So this matches OpenSSL, `tls-exporter` is the one to ask for at 1.3,
and the selection rule is OpenSSL's too: our own Finished unless the
session was resumed, then the peer's. A client that always used its own
agrees with itself on every handshake and with the server on only some
of them, and SCRAM then fails looking like a bad password.

**Status: accepted**, with the reference implementation's behaviour as
the reason, and pinned by a test that compares the bytes with what the
peer computed.

### The exporter is two derivations and every wrong answer is plausible

RFC 8446 section 7.5:

```text
Derive-Secret(exporter_master, label, "")
HKDF-Expand-Label(that, "exporter", Hash(context), length)
```

The first step's context is `Hash("")` - the label alone identifies the
consumer - and only the second carries the caller's context, *hashed*.
Feeding the context into the first step, handing the second the raw
context, or collapsing the two produces an exporter that agrees with
itself and with nothing else. There is no error anywhere, because every
intermediate value is the right length.

The exporter master secret is also taken over the transcript through
the **server's** Finished - the same one the application keys use, one
message earlier than the resumption master secret. Taking it later,
where it would be more convenient, gives a different secret with
nothing to say so.

**Status: mitigated** - `test_tls_exporter_matches_openssls_own_exporter`
compares our value with `openssl s_server -keymatexport` for the same
connection, which is the only independent opinion available: Python's
`ssl` module offers only `tls-unique` through `get_channel_binding`.

---

## 3. RSA pitfalls

Implemented in `src/publickey_ciphers/rsa.rs`: the primitives, key
generation, PKCS#1 v1.5 for both encryption and signatures, OAEP (RFC
8017 section 7.1) and PSS (RFC 8017 section 8.1).

### Bleichenbacher's attack on PKCS#1 v1.5

If a decryption error can be distinguished from a padding error — by error
message, by timing, or by connection behaviour — an attacker decrypts
arbitrary ciphertexts with enough queries. Rediscovered repeatedly for
twenty-five years (ROBOT, 2017).

**Status: mitigated** for the error and in the TLS server; **open** for
the timing of the padding check.

`decrypt_pkcs1v15` returns one error string for every failure — wrong
length, wrong leading bytes, missing separator, separator too early — and
gathers all the conditions before branching on any of them, so the control
flow does not describe which one failed either.
`test_decryption_failures_are_indistinguishable` asserts this directly,
collecting the error from five different kinds of bad ciphertext and
requiring exactly one distinct message; `pytests/test_rsa.py` does the
same, with six, through the bindings. **A caller must not add detail.**
Catching that error and reporting "bad padding" versus "bad length"
rebuilds the oracle.

What is **open** is timing around the padding check. The private
operation is fixed width (see *Timing of the private operation* below),
but the plaintext leaves it as a normalised `BigUint`, and
`decrypt_pkcs1v15`'s scan and its single branch have no `ct_check.py`
row of their own, as OAEP's decoding does. Blinding removes the
attacker's control over the value, which is most of the practical
exposure, but it is not a proof.

And what no padding function can fix from inside: in TLS, on any
failure, the handshake must continue with a *random* premaster secret so
it fails later at the Finished check, identically to a wrong key. The
server does this in `ServerConnection::decrypt_premaster`, which cannot
return an error. The 48-byte fallback is drawn before anything is
examined, and every condition, the rollback version included, folds
into one mask (`test_every_failing_premaster_is_forty_eight_fresh_bytes`,
`test_a_premaster_with_the_wrong_version_is_replaced`).

### Manger's attack on OAEP

OAEP's decoded block must start with a zero byte. An attacker who can
learn whether it did - from the error, the timing or the behaviour -
decrypts a ciphertext in about a thousand queries (Manger, 2001), far
fewer than Bleichenbacher needs, because OAEP's own checks run *after*
the one that leaks.

**Status: mitigated.** `decrypt_oaep` returns one error for every
failure of the ciphertext - wrong length, not reduced, the leading
byte, the label hash, the separator. The first two are public facts
about the ciphertext and are refused before the private operation;
`eme_oaep_decode` folds the other three into one mask before the
single branch, which lives in `oaep_verdict`, a function of
its own so `scripts/ct_check.py` can tell it from the rest
(`rsa_oaep_decode`: only the verdict and the message's length are
reported). A label hash compared with `==` - `bcmp`, the textbook
variable-time comparison - fails that row; the private operation
underneath is the `rsa_private` row. `tests/test_rsa_oaep.rs` runs
Wycheproof's 898 vectors, 389 of them ciphertexts that must be refused,
and requires the one message for each.

**`ct_check.py` named nothing in a preloaded library until this row.**
Its frame pattern wanted `(file:line)`, and valgrind writes a frame in
its own preload as `(in /usr/libexec/...)`, so a report whose innermost
frame was `bcmp`, `memmove` or `malloc` was counted and attributed to
nobody - and a row that lists names passed it. Breaking OAEP's label
comparison into a slice `==` added two reports and failed nothing. Both
forms match now, and the full table still passes with the names it had.

The hashes are parameters, and both ends must agree on two of them: the
one that hashes the label and sets the seed's length, and MGF1's. RFC
8017 lets them differ, deployed systems do (some Java configurations
pair SHA-256 with MGF1-SHA-1), and a decryptor that assumed they match
refuses those ciphertexts with the same error as a wrong key.

### CRT fault attacks

RSA-CRT that produces one faulty half leaks the factorisation from a single
bad signature: `gcd(s^e - m, n)` gives away a prime. A bit flip from bad
memory does as well as a deliberately induced fault.

**Status: mitigated.** `RsaPrivateKey::raw` exponentiates the result back up
with the public exponent and compares it with its input before returning
anything. A result that does not check out is an error, not a value. This
costs one public exponentiation — 72 µs against a 5.2 ms signature at 2048
bits, so under 2%.

### Small exponents and unpadded operations

`e = 3` with no padding, or the same message to several recipients, breaks by
Coppersmith or CRT. Textbook RSA is deterministic and malleable.

**Status: mitigated**, by naming and by padding. The unpadded primitives are
`RsaPublicKey::raw` and `RsaPrivateKey::raw` — nothing else in the API
reaches them, and neither is exposed to Python. Everything a caller can
reach through `api` or the bindings goes through PKCS#1 v1.5, OAEP or
PSS, and the encryption padding is randomised, so the same message never
encrypts to the same bytes twice. A test asserts that, because a padding
that quietly lost its randomness would still round trip.

### Signature forgery by parsing instead of comparing

A PKCS#1 v1.5 verifier that *parses* the recovered block and pulls the
digest out of it, rather than comparing the whole block against what it
would have produced, accepts forged signatures when `e` is small — the
Bleichenbacher 2006 forgery, which hit several libraries at once and came
back in 2014 and 2016.

**Status: mitigated.** `verify_pkcs1v15` rebuilds the expected block with
`emsa_pkcs1v15` and compares all of it, byte for byte, in fixed time. There
is no ASN.1 parser in the verification path at all, and the DigestInfo
prefixes are constants for exactly that reason. The X.509 code has a real
ASN.1 parser (`src/asn1`), and it is deliberately not wired into this
path.

### Timing of the private operation

`BigUint` is not constant time, so how long `c^d mod n` took used to depend
on both `d` and `c` — and in an attack the adversary chooses `c`. That is
what Brumley and Boneh used to pull an RSA key out of a server over a local
network in 2003.

**Status: mitigated**, by blinding and a fixed-width CRT path; the
blinding factors themselves are accepted, below. Every private operation
multiplies its input by `r^e` for a fresh random `r`, exponentiates that,
and divides `r` out afterwards. The attacker no longer controls, or knows,
the value the arithmetic runs on, so timing it tells them nothing about
the input they chose. The exponent-dependent part is addressed separately
by `Montgomery::pow_ct`, which the CRT halves use with a loop bound fixed
by the prime's width.

**Also mitigated:** the CRT path is fixed width now. It used to reduce the
blinded value with `blinded.rem(&self.p)` — a Knuth division whose add-back
path depends on both operands, one of which is the secret prime — and to
recombine with ordinary `BigUint` arithmetic on the plaintext. It now uses
`Montgomery::reduce_wide` for both reductions, the Montgomery ladder for both
exponentiations, and `Secret` arithmetic for the recombination and the
unblinding. `scripts/ct_check.py`'s `rsa_private` row allows only the
final `declassify` of the plaintext, which valgrind names as `normalise`
or `UnknownInlinedFun` depending on inlining.

Two things in here were found by that harness and not by reading the code.
`RsaPrivateKey::raw` built a `Montgomery` context per operation, and building
one divides by its modulus — so every private operation began with two
divisions by the secret primes, which is a worse leak than the one the
rewrite removed. The contexts are built once, in `from_primes`. And the
Bellcore check called `self.public.raw(&m)`, taking the plaintext out to a
normalised `BigUint` and comparing it with `!=`; a fault check that leaks the
value it is checking is a poor trade, so it is `Montgomery::pow_public` and a
`ct_eq` mask now.

**Also mitigated:** the blinding factors. `r^e` and `c * r^e` are
`Montgomery::pow_public` and `mul_mod` at fixed width. The inverse is
still the Euclidean algorithm, which is variable time, but it is never
taken of `r`: it is taken of `r * s` for a second random `s`, a value
independent of `r`, and `s` is multiplied back in afterwards. They used
to be `BigUint` `mod_pow`, `mod_mul` and `mod_inverse` on `r` itself,
accepted because `r` is fresh and discarded. `ct_check.py` cannot see
either version, because its harness marks the key, not `r`.

### Small keys and weak primes

A 512 bit modulus is factorable, and primes that are close together fall to
Fermat's method in seconds — which is not theoretical, it has been found in
shipped hardware.

**Status: mitigated for what is generated here.** `generate` refuses
anything below 512 bits, forces the top two bits of each prime so the
modulus has exactly the requested size, and rejects any pair whose
difference is shorter than `bits/2 - 100`. Primality uses Miller-Rabin with
64 **random** bases, not fixed ones: composites that pass any fixed base set
can be constructed deliberately. The Carmichael numbers are in the tests,
since they are what a Fermat test mislabelled as Miller-Rabin would accept.

Nothing stops a caller *importing* a 512 bit key, and nothing should —
talking to old things is the point of this library. The refusal is on
generating one.

---

## 3b. Finite-field Diffie-Hellman pitfalls

Implemented in `src/publickey_ciphers/dh.rs`, and used by the TLS `DHE_RSA`
and `DHE_DSS` suites and by SSH's `diffie-hellman-*` key exchanges. The
arithmetic is three lines; almost everything that has gone
wrong with DH in practice is a missing check rather than a wrong answer,
which is why this section is longer than the module.

### The peer's public value is a claim, not a number

`y = 0` makes every shared secret 0. `y = 1` makes it 1. `y = p-1` has
order 2, so the secret is 1 or `p-1` according to the parity of our own
exponent — one bit of the private key leaked per exchange, to anybody
watching. All three complete a key exchange perfectly.

**Status: mitigated.** `validate_peer` requires `2 <= y <= p-2` and is
called both when the ServerKeyExchange arrives and again inside
`shared_secret`, so no path reaches the exponentiation without it. A
degenerate *result* is refused as well, which catches a group whose
generator has tiny order even when `y` itself looked fine.
`pytests/test_dh.py::test_degenerate_peer_values_are_refused` covers each
value, and the corpus in `tools/src/bin/diff_dh.rs` re-checks the boundaries on
both standard groups.

### The server chooses the group, and nothing proves it is a good one

In TLS 1.2 DHE the server sends `p` and `g` and the client's only options
are to use them or hang up. Nothing in the protocol says `p` is prime, or
large, or that `p-1` has a large prime factor.

**Status: mitigated** for size; **accepted** for primality, which is
opt-in, and for subgroup order, which cannot be checked.

*Size* is checked: `ClientConfig::min_dh_bits` defaults to 2048 and the
connection is refused below it. Logjam broke 512 bit export groups in real
time and made precomputation against the handful of common 1024 bit groups
a state-level attack; the floor is what a client can actually do about
that. It is lowerable, because reaching a box that was configured once in
2003 is the point of this library — `ClientConfig::legacy` sets 512.
Going below export grade is a separate decision, made by setting
`min_dh_bits` lower (a real 480 bit group is served at
dh480.badssl.com).

The size check runs **before** the primality check, and that has a
consequence worth knowing: a composite modulus that is also below the floor
is refused for its size, and the primality check never runs. A real server
made this concrete — `dh-composite.badssl.com` serves a composite modulus
of 2047 bits, so with the default floor of 2048 it is refused on size, and
a live-test row written to exercise `check_dh_prime` passed while testing
nothing. The ordering is right, since the size check is free and the prime
check is two dozen full-width exponentiations; the consequence is that
asking for the primality answer means lowering the floor far enough to
reach it. `test_a_composite_modulus_below_the_floor_is_refused_for_size_first`
pins it.

*Primality* is not checked by default. A composite `p` splits the discrete
log by the Chinese remainder theorem into two small ones and makes the
shared secret computable by whoever chose `p`, while every other check in
the handshake passes: the arithmetic works, and the signature over the
parameters verifies because the server signed them and the server is the
attacker. `check_dh_prime` turns on a Miller-Rabin test with random bases
(fixed bases can be beaten by a number chosen to pass them). It is off by
default only because it costs more than the key exchange itself — several
full-width modular exponentiations on every connection.

*Subgroup order* is not checked at all, because TLS 1.2 does not send `q`.
A group where `p-1` is smooth allows a Pohlig-Hellman attack, and we
cannot detect it. This is why the private exponent is full width — see
below.

### Short exponents are only safe in a group you trust

Drawing the private exponent from `[2, p-2]` costs a full-width
exponentiation; drawing a 256 bit one would be several times faster and is
what a library with a known subgroup order would do.

**Status: accepted**, as a cost, on purpose. Van Oorschot-Wiener recovers
a short exponent when `p-1` is smooth, and the previous item says we cannot
tell whether it is. A group we cannot check is a group we do not take
shortcuts in.

### The shared secret's encoding is a convention, and the two conventions disagree

A shared secret is a number. Roughly one in 256 has a leading zero byte,
and what happens to that byte is not implied by any of the arithmetic:

  * PKCS#3 and OpenSSL's `DH_compute_key` pad to the width of `p`;
  * TLS 1.0 through 1.2 **strip** leading zeros before using it as the
    premaster secret (RFC 5246 section 8.1.2);
  * TLS 1.3 and RFC 7919 keep them.

Get it wrong and everything interoperates for days, and then one
connection in 256 fails in a way nobody can reproduce.

**Status: mitigated, and tested deliberately rather than by luck.**
`shared_secret` always pads. The TLS client strips through
`keys::premaster_from_shared`, which asks `keys::strips_leading_zeros`,
so the rule for both key-exchange families appears once, next to the
citation.
`pytests/test_dh.py::test_a_shared_secret_shorter_than_the_modulus_is_still_padded`
searches a small group for an exponent that *produces* a short secret
instead of waiting for one, and the `p192` and `p256` rows of the
differential corpus make short secrets routine — `scripts/diff_check.py`
fails if the corpus contains none, because a corpus that never exercises
the rule would look exactly like one that does.

### The exponent is secret and `mod_pow_ct` is only half an answer

`shared_secret` runs entirely on `bignum::ct::Secret`: the exponentiation is
`Montgomery::pow_ct` with the modulus's width as the loop bound, and the
result is serialised with `Secret::to_bytes_be`, which is fixed width by
construction. Going through `BigUint::mod_pow_ct` instead would normalise the
shared secret and then scan it for its first non-zero byte — two branches on
the value, at the moment it is most worth protecting. That is also why the
one-in-256 short buffer this function's doc comment warns about cannot happen
here at all.

**Status: mitigated.** `scripts/ct_check.py`'s `dh_shared` row names one
site: the degenerate-value test, whose three comparisons are
folded into a single mask before anything branches, and whose one branch
decides whether to abort the handshake — which tells the peer anyway.

### Nothing here authenticates anything

Plain DH has no notion of who is on the other end; an active attacker runs
it separately with each side and relays. In TLS the ServerKeyExchange
signature is what binds `p`, `g` and `Ys` to the certificate.

**Status: mitigated in the TLS client**, where the signature is verified
before the group is even examined — there is no point having an opinion
about a stranger's parameters.
`pytests/test_tls_handshake.py::test_a_tampered_dh_key_exchange_is_refused`
flips a bit in a real OpenSSL ServerKeyExchange and requires the
connection to fail.

---

## 3c. TLS 1.3 session tickets, server side

**Status: mitigated**, and the mitigation is checked by things that can
actually fail.

A ticket is the server's own session handed back to the client, sealed with
AES-256-GCM under a key only the server has. Three properties, each with a
test that would fail without it: the PSK is not in the clear, no single byte
of the ticket can be changed (including the key name and the nonce, which
are not encrypted), and the lifetime the client was *told* is not the check
— the server stamps its own tickets and expires them against its own clock.

**The binder is the whole security property, and no handshake test can check
it.** Deleting it left all seven OpenSSL resumption tests passing, because an
honest client always sends a correct one. The ticket proves the *server*
issued it; only the binder proves the client holds the PSK sealed inside it,
over *this* ClientHello. Without it, anybody who captured a ticket off the
wire resumes the session. `test_a_wrong_binder_is_refused` flips every bit of
a binder and offers one computed over a different transcript — which is
exactly the replay — and is the only thing that covers this.

Two structural rules that are silent when broken:

- **`pre_shared_key` must be the last extension**, because the binder covers
  the hello up to itself. A server that truncates by `binders_length` without
  checking the position hashes the wrong bytes and rejects every honest
  client, or worse, accepts on a hash it computed the same wrong way.
- **A NewSessionTicket does not go into the transcript.** The resumption
  secret is over "ClientHello … client Finished"; adding the ticket moves
  the transcript past that point and the second ticket is derived from
  something the client does not share.

**Not offered:** PSK-only resumption. Every resumed handshake here also does
a fresh key exchange, so the session keeps forward secrecy — a PSK-only one
does not, and a stolen ticket would then decrypt the traffic rather than
merely authenticate.

---

## 3d. Private key parsing

**Status: mitigated**, and the mitigation is a differential test rather
than a vector.

**A private-key parser never looks at the public half**, so it accepts a
well-shaped forgery. The first version of the unit tests here used
vectors typed from memory: they parsed, they agreed with each other, and
`openssl pkey` refused every one of them. A parser checked only against
itself is checked against nothing, which is the same lesson as every
differential corpus in this repo and it had to be learned again here.
`pytests/test_private_key.py` generates every key with
python-cryptography, compares the numbers, and then **uses** the key - a
signature the other side verifies - because a scalar off by a byte of
padding is still a plausible scalar.

**The label does not decide.** `openssl` will put a SEC1 body under a
`PRIVATE KEY` header, so the structure is what is tried and the label
only narrows the search. Refusing on the strength of a header would
refuse valid keys.

**The CRT parameters in the file are not kept.** `dP`, `dQ` and `qInv`
are derived from `p`, `q` and `e`. A file whose stored `dP` disagrees
with `d mod (p-1)` would otherwise sign wrongly, and the failure would
land at a signature nobody could explain.

**Two curves that disagree is a refusal, not a preference.** RFC 5915
§3 says the inner ECParameters must be omitted when the key is carried
inside PKCS#8, precisely so there is one answer; a file with both and a
disagreement is malformed, and picking either is guessing which half the
writer meant.

**An encrypted key given no passphrase is refused by name.** The
`*_with_password` functions decrypt one (`x509::encrypted_key` removes
the PKCS#8 layer); without a passphrase the error names one as the
remedy, because a reader told only "unsupported" goes looking for the
wrong thing.

**Four of the ten deliberate breaks were missed the first time, and all
four were shapes nothing generates**: a scalar shorter than the curve
(one key in 256), one longer than it, an EC key naming two curves, and a
multi-prime RSA key. `cryptography` and `openssl` both write well-formed
files, so every one of those checks is unreachable from a generated key
- each now has a test built by *editing* a real file, because a file
built from scratch only tests what the test itself encoded.

The padding one is subtler still: it is invisible from Python, because
`EcKey::private_bytes` pads to the field size on the way out, so a
parser returning a short scalar looks identical from there. It is a Rust
test for that reason.

---

## 3e. OCSP stapling

**Status: mitigated**, both ends and both versions, against the `openssl`
command line tool - the one readily available program that will both
serve a staple and say out loud what it saw.

**`status_request` has three bodies and they are in three different
messages.** A `CertificateStatusRequest` in a ClientHello; **empty** in a
TLS 1.2 ServerHello, where it only says one is coming; a whole
`CertificateStatus` in a TLS 1.3 certificate entry. Same trap as
`supported_versions` and `key_share`, handled the same way: one function
per (extension, message) pair and none takes a flag. A server writing the
1.3 body into the 1.2 ServerHello gives the client a length field where
it expects none.

**Nothing fetches a response.** A server that went to the responder
during a handshake would add the responder's latency and its availability
to every connection, which is the problem stapling exists to solve. The
operator supplies the DER out of band. The server does not check it
either: judging a statement about its own certificate is checking its own
homework, and a response the server disliked is one the client still has
to judge.

**What a staple is allowed to decide is asymmetric.** *Revoked* fails the
handshake whatever else is configured - it is an answer, signed by
somebody the certificate's own issuer delegated to. Anything that settles
nothing is `Unknown`, and `Unknown` is not `NotRevoked`; what it costs is
`ClientConfig::require_stapled_ocsp`, off by default because most servers
staple nothing.

**That flag is deliberately not `Policy::require_revocation`.** Reusing
it was the first attempt, and it made "require a staple" refuse every
connection - `verify_chain` reads that field as "require a CRL", and
nothing here fetches one. Two different questions with two different
answers.

**A client that looks for the issuer only in the chain checks nothing for
the servers most likely to staple.** A server whose CA is a well-known
root often sends the leaf alone, and RFC 8446 4.4.2 lets it omit anything
the client already has - so the trust store has to be consulted as well.
Found by a test whose server happened to send one certificate; with the
chain lookup alone the staple was read, stored, reported, and never
judged.

**No nonce, on purpose.** A stapled response is cached by the server and
shared between connections, so demanding a fresh nonce defeats stapling
rather than adding freshness. What bounds a replayed staple is its own
`nextUpdate`, which `ocsp::check` enforces.

**Two of the nine deliberate breaks were invisible from the wire.** A
staple copied onto *every* certificate entry looks identical to a correct
one, because a client reads the leaf's - so `certificate_entries` is a
function with a test rather than a loop inline. And a `CertificateStatus`
accepted without the ServerHello's acknowledgement is something no real
server sends, so it needs a hand-built message; without the check, a peer
can pad the flight with bytes the client parses before the transcript
catches it at the Finished.

---

## 3f. ALPN

**Status: mitigated.** Both ends, both versions, checked against
`ssl.SSLContext` in each direction — our own two ends share an encoder,
so they would agree about a wrong wire shape perfectly.

**The answer is in a different message in each version.** ServerHello at
TLS 1.2, EncryptedExtensions at 1.3. A server that wrote the 1.3 one
into the ServerHello would announce the application protocol to the
network, and every handshake would still complete — both our client and
OpenSSL's accept it wherever it is put, because a client looks for the
extension rather than for the message it arrived in. Only reading the
plaintext bytes finds it, which is what
`test_the_answer_is_encrypted_at_tls13` does.

**Whose order decides is invisible to a symmetric test.** The server's
list wins. A test listing the same protocols in the same order at both
ends cannot tell a correct implementation from one that takes the
client's preference, so every row lists them opposite.

**Empty is the default and answers nothing**, because a proxy that
answered `h2` on behalf of something speaking HTTP/1.1 would have
promised what it cannot deliver. The list is what the application can
do, not what this code can parse. `require_alpn` is off for the same
sort of reason: RFC 7301 3.1 allows either failing or carrying on, and
carrying on is right when the protocol is settled by a URL scheme or a
port. It is ignored when the client offered no ALPN at all — otherwise
it would silently mean "refuse every client that does not do ALPN",
which is a much larger setting than its name.

**A client must refuse an answer it did not offer, and one that names
two.** RFC 7301 4.2 says the server selects exactly one. Taking the
first of two means the ends can disagree about which was picked;
accepting an unoffered name means the application speaks a protocol it
never agreed to, chosen by whoever is on the wire. No real server does
either, which is why removing the second check failed nothing in the
sweep and now has a hand-built message.

---

## 3g. TLS 1.3 early data (0-RTT)

**Status: accepted, and the acceptance is the design.** 0-RTT cannot be
made safe; it can only be made a decision. Off by default at both ends.

Two properties, and neither is a detail:

* **Not forward secret.** The key comes from a PSK that has been in the
  client's storage since the previous connection. Anyone who later
  obtains that ticket reads the early data out of a capture. Nothing
  sent after the handshake has that property.
* **Replayable.** Early data is written before the server has said a
  word, so nothing fresh from the server is in those keys. A captured
  flight, resent byte for byte, is as valid the second time.
  `tickets::ReplayGuard` is a bounded strike register over the binders
  already accepted — the *binder*, because an honest client reusing a
  ticket has a different binder each time and only a byte-for-byte
  replay repeats one. RFC 8446 8.2 says a single-machine register does
  not stop an attacker who can reach another machine, and neither does
  this one. What it bounds is how *often* a replay works.

So the API is deliberately awkward in two places.
`ServerConnection::take_early_data` is separate from `take_incoming`,
and `ClientConfig::early_data` is not resent when the server declines.
A caller reading those bytes out of the ordinary buffer would have no
way to tell which they were; resending them automatically would be
making the decision for the caller a second time.
`max_early_data` without a `replay_guard` is a `ValueError` from
Python — a register built per connection has seen nothing, and that is
exactly the mistake a default would hide.

Seven conditions refuse early data quietly, with a full handshake and
nothing said. Each is a way for it to land in the wrong context:

1. **Not the first PSK identity.** RFC 8446 4.2.10 binds the keys to
   `identities[0]`; the client derived them before hearing anything
   back. Removing this check does not fail safe - a client offering two
   tickets can have the second accepted, and the flight is then
   decrypted with a key the client did not use.
2. **A ticket that allows none**, checked against the *sealed* copy, not
   the number the client was told. That number is one we handed out and
   can no longer see.
3. **A different server name** from the one the ticket was issued under.
   Early data arrives before anything is negotiated, so the only thing
   that can say what it was meant for is what the previous connection
   settled; without this a ticket for one virtual host replays its early
   data into another.
4. **After a HelloRetryRequest.** We have already spoken, and the
   client's early keys were derived over the first hello.
5. **A flight the register has seen.**
6. **A server that does not offer it at all.**
7. **An `early_data` extension that is not empty.** In a ClientHello it
   has no body; the `max_early_data_size` form belongs to a
   NewSessionTicket.

None of them is reported, because every one is a fact about the ticket
and naming it tells an attacker how close they got.

**Three findings, and the first is the one that bites.**

**A failed deprotection must not advance the reader's sequence number.**
A server that *declines* early data is required to attempt and discard
the records the client already sent under keys it never derived (RFC
8446 4.2.10) — failing on the first one would mean 0-RTT could be
forbidden but never declined. A counter advanced by each discarded
record then leaves the client's real Finished decrypting under the wrong
nonce, and the symptom is a handshake that fails *only* when 0-RTT was
offered and refused, which no ordinary test covers. `Aead13::decrypt`
peeks the sequence and commits it only when the record authenticates.

**`established` is our own opinion, not the peer's verdict.** The client
sets it when it writes its Finished. A test asserting `established` and
`early_data_accepted` passed with EndOfEarlyData left out of the
transcript entirely — the server rejected the Finished, sent an alert,
and the test had already stopped looking. Only a record the peer
decrypted under the **application** keys says our Finished was right, so
`test_we_send_early_data_to_an_openssl_server` asserts on data sent
*after* the handshake.

**The writer changes keys three times and the order is the whole
thing**: plaintext for the ClientHello, early keys for the data,
handshake keys only after EndOfEarlyData has gone out *under the early
ones*. The compatibility ChangeCipherSpec moves earlier for the same
reason - it is plaintext, and from the early keys onward the writer is
not writing plaintext - and the record version has to be pinned to
0x0303 before it, not after, or a 1.3 peer refuses the first record it
sees.

**Where the tests are.** Python's `ssl` module has no early-data API -
no `SSL_write_early_data`, nothing - so the memory-BIO harness the rest
of this repo uses cannot reach the feature at all.
`pytests/test_tls13_early_data.py` runs the real `openssl` binary over
loopback in both directions. The round trip between our own two ends, in
`src/tls/server.rs`, settles the wiring and cannot settle a byte: every
value in 0-RTT comes from the previous connection, so both of our ends
can be wrong in the same way and agree perfectly.

---

## 3h. Client certificates

**Status: mitigated** for TLS 1.0 through 1.3, both ends, each checked
against the other end's OpenSSL in `pytests/test_tls13_client_auth.py`.

**The context string differs by one word and both ends are ours.**
`Side13::Client` and `Side13::Server` produce signatures over different
bytes; a library that used the server's word at both ends completes a
handshake with itself perfectly and with nobody else. Our own server
would accept whatever our client signed, so the only check is a real
peer — which is why this file drives an OpenSSL *client* against our
server and an OpenSSL *server* against our client rather than our two
ends against each other.

**The transcript the CertificateVerify covers ends one message earlier
than the transcript the handler can see.** `handle_handshake` adds each
message before dispatching it, so reading the transcript inside
`handle_client_certificate_verify_13` signs over the CertificateVerify's
own bytes. The hash is taken on the way in
(`before_client_certificate_verify`), the same way
`before_client_finished` already was, because a hash cannot be rewound.
Found by the first run against OpenSSL, which said only
`decrypt_error`.

Four asymmetries with the server's own certificate, each with a test:

- **The client's chain has its own roots.** `ServerConfig::client_roots`
  is a separate `TrustStore`. Verifying client chains against the system
  store would let anything holding a certificate from any public CA
  authenticate to the service. `None` means the chain is not judged at
  all — the signature still is, so the client does hold the key for what
  it sent — which is the deployment where the application recognises the
  key itself.
- **The purpose is `ClientAuth`.** A `serverAuth`-only certificate is
  refused; without that check a service could authenticate *as a client*
  to any peer trusting the same CA, with the key it already holds.
- **The signature is checked before the chain.** A chain that verifies
  against a root but did not sign this transcript is somebody else's
  certificate, replayed.
- **An empty Certificate is a legal answer** (RFC 8446 4.4.2.1), not
  silence — the peer waits for the message either way. So *asked* is not
  *got*: `peer_certificates` is the only thing that says which happened,
  `client_certificate_verified` the only thing that says whether the
  chain was judged, and `require_client_certificate` is the separate
  decision. Requiring without asking is a contradiction rather than a
  stricter setting, and raises.

Nine deliberate breaks, all nine caught. One of them matters for how the
sweep is read: replacing the chain check while *still* setting
`client_certificate_verified` is caught only because the tests assert
both the flag and the refusal — asserting the flag alone would have
passed.

**TLS 1.2 is done too, and it is a different message and a different
signature rather than the same feature with a version flag.**

* `CertificateVerify` signs `Hash(handshake_messages)` - the raw
  concatenation - under a hash the *message* names, where 1.3 signs a
  context string and a transcript hash. A running hash cannot produce
  it, so `Transcript::keep_messages` buffers the bytes, and only on the
  handshakes that will need them. It has to be called **before the
  first `update`**, or the buffer starts mid-handshake and the
  signature covers the wrong bytes.
* RSA signs it with **PKCS#1 v1.5**. RFC 8446 4.4.3 forbids those
  codepoints at 1.3 and nothing at 1.2 expects anything else, which is
  why there are two signing routines and two `VERIFIABLE` lists rather
  than one of each with a flag.
* The **certificate types** in the 1.2 CertificateRequest have no 1.3
  equivalent. A client whose key is not of a listed type has been told
  not to send that certificate; ignoring the list means signing with a
  key the server refused in advance, and the failure then lands at the
  signature rather than at the decision.
* The **order is reversed**: the client's Certificate goes before its
  ClientKeyExchange and the CertificateVerify after it, where 1.3 puts
  the whole flight after the server's Finished.

**The finding that is easiest to miss**: `session_hash` for the extended
master secret is the transcript through the *ClientKeyExchange* (RFC
7627), and the CertificateVerify comes after that message - so a client
that derived the master secret after writing it computed a different one
from every server. It fails as `bad_record_mac` at the Finished, which
reads as a broken cipher rather than as a hash taken one message late.

Three of the ten deliberate breaks were missed first time. The
certificate types are unreachable from any handshake test, because a
real server lists both types - a unit test now. The message-order break
was a no-op as first written, and a real reorder is caught. And a
CertificateVerify from a client that sent no certificate is already
unreachable through the state machine: that check is kept as defence in
depth with a comment saying so, the way `ec::ct::Field::add` keeps its
redundant P = -P arm.

**TLS 1.0 and 1.1 are done too, and they are a third construction rather
than a second version of the 1.2 one.**

* The CertificateRequest has **no signature-algorithm list**. TLS 1.2
  added that field in the middle; a 1.2 parser reading a 1.0 message
  takes the CA list's length for a signature list, and the failure is a
  decode error two fields later.
* The CertificateVerify is a **bare signature** with no algorithm field:
  what was signed is decided by the certificate's key type.
* RSA signs `MD5(handshake_messages) || SHA1(handshake_messages)` - 36
  bytes - with **no DigestInfo**, because the version fixes the pair.
  Signing it the 1.2 way produces a block that never matches, in either
  direction, and that is invisible between our own two ends.
* ECDSA signs the **SHA-1 half alone**. Handing a verifier all 36 bytes
  truncates them to the group's width and checks something nobody
  signed - which succeeds or fails depending on the curve, so it is the
  kind of mistake that works in testing.

`Transcript::hash` already returns exactly those 36 bytes before 1.2, so
this path needs no message buffer - the older version is the simpler one
exactly once.

Ten deliberate breaks, all caught, which took a real OpenSSL at both
versions and with both key types: nothing else can tell a DigestInfo
from no DigestInfo.

**Not there:** post-handshake authentication (RFC 8446 4.6.2), and
client certificates over SSLv3, whose CertificateVerify covers
`master_secret || pad || handshake_messages` rather than the messages
alone. A CertificateRequest
carrying a non-empty context is refused rather than answered, because
echoing a context we do not understand answers a question nobody asked.

---

## 4. Randomness

TLS needs a CSPRNG for client randoms, key shares, IVs and nonces.

**Status: mitigated.** `crate::random` reads the OS generator — `/dev/urandom`
through `std::fs` on unix, `BCryptGenRandom` via a bare `extern "system"`
declaration on Windows. No dependency is needed.

We do not implement a CSPRNG and should not. The three rules the module is
built on, each of which has been somebody's CVE:

- **Never fall back.** An unreachable source returns an error. Silently
  degrading to a time-seeded PRNG when a file descriptor cannot be opened is
  the classic failure, and it is silent because the output still looks random.
- **Never buffer.** Cached OS bytes survive `fork()` into both processes,
  which then generate identical keys. Every call reads fresh.
- **`random::below(n)` uses rejection sampling, not `mod n`.** Reducing a
  random value modulo the bound biases it towards small values, and for ECDSA
  a few bits of bias across enough signatures recovers the private key by
  lattice reduction. Having one function that gets this right is why it
  exists rather than being open-coded per caller.

**The `prng` module is still not a CSPRNG** and now says so in its own header.
It is an LCG, for simulation, test data, and for talking to old systems that
used one. Keeping the two in separate modules is deliberate.

**Windows:** both Windows paths have been run, not only compiled.
`cargo test` on a Windows machine draws every test's bytes through
`BCryptGenRandom` - `test_the_source_is_the_one_this_platform_should_use`
asserts which source the build uses - and opens the ROOT and AuthRoot
stores through `wincrypt` and parses every root in them.
`test_the_system_store_if_there_is_one` fails rather than skips there, so
a green run is evidence.

---

## 5. Bignum correctness traps

Less glamorous than side channels, and much more likely to bite first. These
are the ones our fuzzing is aimed at.

| Trap | Status |
|---|---|
| Unsigned subtraction wrapping instead of erroring | **mitigated** — `sub` returns `Err`; only the internal `sub_unchecked` can wrap, and it debug-asserts |
| Non-normalised values comparing unequal to equal ones | **mitigated** — every constructor normalises, and `from_limbs` is the only way in |
| Zero represented inconsistently (empty vs `[0]`) | **mitigated** — zero is always the empty limb vector |
| Knuth D add-back path never exercised | **mitigated** — a targeted test plus 720 fuzzed division cases |
| Off-by-one in `bit_len` for exact limb multiples | **mitigated** — fuzzed against Python's `bit_length` |
| Leading zeros in wire encoding changing the value | **mitigated** — `from_bytes_be` ignores them, tested |
| Fixed-width fields silently truncating | **mitigated** — `to_bytes_be_padded` errors rather than truncating |
| Division by zero | **mitigated** — returns `Err`, tested |
| Shift by more than the value's width | **mitigated** — fuzzed at 0, 1, 7, 63, 64, 65 and 200 bits |
| Schoolbook multiply carry propagation past the operand | **mitigated** — fuzzed to 2048 bits |

Verified against Python's exact integers over 16,997 cases spanning 1 to 2048
bits. Python's `int` is an independent arbitrary-precision implementation,
which makes it an unusually good oracle: every operation has a direct
equivalent and there is no shared lineage with our code.

**Montgomery is in.** `mod_pow` takes it automatically for odd moduli, which
is every modulus that matters; `mod_pow_schoolbook` remains for even ones and
as a second independent implementation to test the first against.

A measured correction to an earlier claim in this project: Montgomery was
expected to be a large speedup and it is not. Knuth division does *less* limb
work than CIOS; it wins mainly by avoiding slow hardware divides. Measured
when it went in: about 1.6x for a 2048 bit private exponent, roughly break
even for a small public one, with a 2048 bit private operation at ~12 ms
and a public one at ~88 µs. With CRT, a later measurement put a 2048
bit private operation at about 5.2 ms against 72 µs for a public one
(see *CRT fault attacks* above). For a TLS *client* that is
comfortable, since the client does public-key operations
and the server carries the private ones.

The reason Montgomery is worth having is the constant-time path, not the
speed. Worth remembering when the next optimisation is proposed on the
assumption that it will be a big win.

---

## 6. Certificates: parsing and chain validation

Implemented in `src/asn1` and `src/x509`. This is the part of the library
that reads bytes from somebody we have not authenticated yet, so it gets its
own section.

### Parser differentials

If two implementations disagree about what a certificate says, an attacker
picks the disagreement. A certificate that means one thing to the CA that
signed it and another to the client that reads it is the whole family:
non-minimal lengths, redundant INTEGER prefixes, BER's indefinite length,
trailing data after a structure.

**Status: mitigated.** `src/asn1` accepts only DER, and refuses every
alternative encoding it can: indefinite and non-minimal lengths, redundant
INTEGER bytes, a BOOLEAN that is not `0x00`/`0xFF`, nonzero unused bits in a
BIT STRING, non-minimal OID subidentifiers and high tag numbers. `finish()`
is an error if any bytes are left over. A table of nineteen malformed
encodings is in that module's tests, each with a note of what it is a second
encoding of.

### Parser crashes on hostile input

A parser that panics is a denial of service, and in a language where it
would be a buffer overflow it is worse.

**Status: mitigated.** Every read is length-checked; nothing unwraps on
input. Nesting is capped at `MAX_DEPTH`, because a thousand nested
SEQUENCEs is four bytes a level to write and a stack overflow to parse.
Both `asn1` and `x509` have a test that truncates a valid input at every
single offset, and `x509` also flips every byte, requiring an error rather
than a panic in all of them.

### The null-prefix attack

`www.good.test\0.evil.test` is one valid ASN.1 string. A CA that reads it
as a name under `evil.test` will sign it; a client that hands it to
something which stops at a NUL sees `www.good.test`. Moxie Marlinspike,
2009.

**Status: mitigated.** DNS, email and URI general names containing a
zero byte are a parse error, not a comparison-time check - by then the
string may already have been handed to something that stops at NUL. A
name attribute whose *decoded* text contains one is withheld instead:
the certificate parses, `Attribute::text` never returns that attribute,
and neither half can be matched against. The check is on the decoded
text because a BMPString holds a zero byte in every ASCII character.

### Duplicate extensions

Where two copies of an extension are tolerated, the question becomes which
one is enforced. An attacker supplies a second basicConstraints and hopes
the checker reads a different one than the parser did.

**Status: mitigated.** A repeated extension OID is a parse error.

### Unrecognised critical extensions

Critical means "if you do not understand this, do not use this
certificate". Ignoring one means using a certificate in a way its issuer
explicitly excluded.

**Status: mitigated.** The parser records them; `verify` rejects any
certificate that carries one.

### basicConstraints not checked

The one that keeps coming back: 2002, 2009, and a mobile stack in 2011.
Without it, any certificate anybody can buy can sign a certificate for any
name at all.

**Status: mitigated.** Every certificate acting as an issuer must carry
`cA=TRUE`, and `pathLenConstraint` is enforced against the number of
certificates below it. A version 3 certificate with no basicConstraints at
all is treated as a leaf, not as unconstrained. There are tests on both
sides: our builder makes such a chain and the verifier must refuse it, and
`cryptography` makes one and the verifier must refuse that too.

**With one exception, which is in RFC 5280 rather than a relaxation of it:**
the trust anchor is an *input* to path validation (§6.1), not a certificate
that gets validated, because the decision to trust it was made out of band
by whoever put it in the store. So an anchor that simply omits
basicConstraints may still have issued the chain below it, and an anchor
that *is* the certificate presented — a pinned self-signed server
certificate, which is what most equipment too old for a public certificate
has — is not subjected to the CA question at all, since it issues nothing.

The exception is narrow on purpose. An anchor saying `cA=FALSE`, or a
`keyUsage` without `keyCertSign`, is still refused: that is not silence, it
is the certificate stating that it must not be used this way, and honouring
it is the whole of the bug above. Trusting a certificate is not the same as
overruling it. `test_anchor_ca_rules_soften_for_silence_only` pins all
three cases, and `test_a_pinned_self_signed_certificate_verifies` pins the
shape that was broken — which every existing test missed, because they all
build a well-formed three-certificate chain.

### Hostname matching

`*.com`, a wildcard in the middle, a wildcard matching across a dot, a
common name consulted when a subjectAltName exists - every one of these has
shipped.

**Status: mitigated.** RFC 6125 rules, in `matches_hostname`: SAN wins over
CN absolutely, the wildcard must be in the leftmost label, there must be at
least two labels after it, it covers exactly one label, and comparison is
ASCII case-insensitive and nothing more. IP addresses match only
`iPAddress` entries, and an address with a leading zero in a component is
refused because `010` is octal to some resolvers and decimal to others.

### Signature over a re-encoding

A verifier that parses a certificate and then re-encodes it to hash is
verifying its own understanding, not the certificate.

**Status: mitigated.** `Certificate::tbs` is a slice of the original bytes.
The differential corpus compares its SHA-256 against OpenSSL's
`tbs_certificate_bytes` for every certificate, so a wrong slice is caught.

### Algorithm confusion between the two identifiers

A certificate names its signature algorithm twice, inside the TBS and
outside it. If they may differ, an attacker puts a weak one where the
verifier looks and a strong one where an inspector looks.

**Status: mitigated.** They must be equal, or parsing fails.

### Revocation

**Status: mitigated.** `src/x509/crl.rs` implements RFC 5280 section 5
and `src/x509/ocsp.rs` implements RFC 6960.
`verify_chain_with_revocation` checks every certificate in the chain —
not only the leaf, because a revoked *intermediate* is the case
revocation exists for. OCSP is consulted first, because it answers
about one certificate and is normally fresher; a CRL is the fallback.

Nothing here fetches anything: no socket is opened anywhere in this
library, so the caller brings the list. `crl::distribution_points` says
where a certificate claims its list lives.

**`Unknown` is not `NotRevoked`.** That is the whole shape of the
module. `Status` has three values, and every way of getting a CRL check
wrong collapses the third into the second — a certificate that is
revoked appearing clean. `Policy::require_revocation` decides what an
absence of evidence means, and it is off by default, which is soft
fail: with hard fail on and no CRL supplied, every chain fails, and
that is right for a machine issuing money and wrong for one that has to
reach a box whose distribution point stopped answering in 2014. A
*revoked* certificate is refused either way.

The rules that are silent when got wrong:

  * **A delta CRL is not a CRL.** It lists only what changed since a
    base, so read as a complete list every older revocation appears
    clean — and the old revocations are the ones that matter. RFC 5280
    5.2.4's four conditions decide whether a delta may be merged.
  * **`removeFromCRL` un-revokes**, and is the one reason code that is
    not a revocation.
  * **The `certificateIssuer` entry extension carries forward.** On an
    indirect CRL, an entry with no `certificateIssuer` belongs to the
    same issuer as the *previous* entry (5.3.3). A parser reading
    entries independently attributes every unmarked entry after the
    first marked one to the CRL issuer, which is wrong in both
    directions at once.
  * **A partitioned CRL does not cover everything.** `onlySomeReasons`
    makes a CRL complete, valid, correctly signed and silent about key
    compromise. Coverage is accumulated across CRLs, because RFC 5280
    5.2.5 describes a CA splitting its revocations across distribution
    points and two partitions that together cover everything *are* an
    answer.
  * **The `ReasonFlags` bit positions are not the `CRLReason`
    enumerated values.** They agree from 1 to 6 and then diverge, which
    is the shape that gets copied across.
  * **`cRLSign` is what permits signing a CRL.** A CA may keep separate
    keys for certificates and CRLs (5.1.1.3), so a CA certificate
    without that bit is not a CRL signer.

**The asymmetry that runs through all of it:** being *on* a list is an
answer; being *off* it is a claim about coverage. So a stale CRL
revokes and cannot clear, a partitioned one revokes and clears only its
own reasons, and a delta revokes and clears nothing. The first of those
was found by `tools/src/bin/diff_crl.rs`: the first implementation answered
"unknown" for a stale CRL listing the certificate, and `openssl verify`
reports both "CRL has expired" *and* "certificate revoked" on that
input.

**One deliberate divergence from OpenSSL**, argued at length in
`crl.rs`: a delta CRL supplied alone revokes what it lists, where
OpenSSL ignores it entirely. And one place where OpenSSL's reading won
over the stricter one: `removeFromCRL` on a *complete* CRL, which RFC
5280 says may not happen, is honoured as a withdrawal rather than read
as a malformed revocation — because the stricter reading refuses a
certificate everything else accepts over a mistake in a CA's own signed
list, and "the server is not ours to upgrade" is what this project is
for.

**What the differential corpus cannot reach.** `openssl verify
-CRLfile` uses only the **first** CRL it finds for an issuer, so every
row in `tools/src/bin/diff_crl.rs` carries at most one. Delta merging,
`removeFromCRL`, reason partitioning and indirect CRLs are covered by
`crl.rs`'s own tests and by nothing else.

### OCSP

**Status: mitigated.** `src/x509/ocsp.rs`, its own tests, and the
`diff_ocsp` corpus below.

A CRL is a list; an OCSP response is an answer about one certificate.
That makes almost every way of getting it wrong a way of accepting an
answer about **something else**:

  * **a response about a different certificate.** A responder may
    return several `SingleResponse`s; taking the first, or taking any
    without checking its `CertID`, means a `good` about somebody else
    answers for this one. That is the shape of a stapled response
    harvested from another connection. All four CertID fields are
    recomputed and compared.
  * **`issuerKeyHash` is over the BIT STRING's *contents*** — not the
    SubjectPublicKeyInfo, and not the BIT STRING's tag and length.
    Three plausible readings of "the value (excluding tag and length)
    of the subject public key field", and the wrong ones simply never
    match, which reads as "the responder does not know this
    certificate" rather than as a bug.
  * **the unsigned error statuses are not answers.** `responseStatus`
    sits *outside* the signature, so `tryLater` and `unauthorized` are
    bytes anybody on the wire can write, and they carry no
    `responseBytes` at all.
  * **`unknown` is not `good`.** It means the responder cannot speak
    for this certificate, which is what a responder for a different CA
    says about ours — and a match arm that groups it with `good`
    compiles.
  * **who may sign.** RFC 6960 4.2.2.2: a delegated responder must
    carry `id-kp-OCSPSigning` **and** be issued by the CA that issued
    the certificate in question. A certificate taken from the `certs`
    field without both checks is a complete bypass — every customer of
    a CA could answer for every other one.
  * **the nonce is checked after the signature.** An unsigned nonce
    proves nothing, and checking it first reports a nonce mismatch
    where the real problem is a forged response.

A nonce is the only defence against replay: without one, a captured
`good` stays valid until its nextUpdate. `ocsp::build_request` puts one
in when the caller passes it, and `check` requires it back when one was
sent. A stapled response cannot carry one - the server fetched it once
for every client - so a staple is only as fresh as its nextUpdate.

**Stapling.** The client offers `status_request` by default
(`ClientConfig::request_stapled_ocsp`) and judges a stapled response
with the same `ocsp::check`, looking for the issuer in the trust store
when the server sent the leaf alone. A staple that says *revoked* fails
the handshake; one that settles nothing is reported, and fails it only
under `require_stapled_ocsp`. The server staples
`ServerConfig::ocsp_response` when the client asked.
`pytests/test_ocsp_stapling.py` covers both ends against OpenSSL.
Nothing here fetches from a responder.

`tools/src/bin/diff_ocsp.rs` compares whole responses against `openssl
ocsp`. Rows carrying a **request** as well are how the CertID hashes
other than SHA-1 get checked at all — `openssl ocsp -cert` builds its
own with SHA-1 and finds no answer otherwise — and they check our
request encoder against their parser at the same time.

**One deliberate divergence.** A *stale* response that revokes is
honoured here, where `openssl ocsp` refuses the whole response with
"status expired" and reports no status. This is the same asymmetry
applied everywhere else in `crl.rs`, and OpenSSL's own CRL path reports
the revocation in that situation — so the inconsistency is theirs. The
row is out of the corpus and in `ocsp.rs`'s tests instead.

### The Windows paths had never executed

**Status: mitigated.** Both have now run green on a real Windows machine,
and the two tests below are what would catch a regression there.

How it got there: `BCryptGenRandom` and the `wincrypt` trust store
both compile everywhere and could only ever *run* on Windows, and for most
of this library's life nobody had run `cargo test` there.

Two things made that worse than it needed to be:

- Nothing said which random source a build used, so a green run told you
  every test passed and not which platform branch produced the bytes.
  `random::source()` now names it and a test asserts the right one for the
  build, so the answer is in the test output.
- `test_the_system_store_if_there_is_one` printed "no system trust store
  here" and **passed** on either platform. On Windows that swallowed the
  only answer that mattered: the one machine that could tell us whether
  `CertOpenSystemStoreW` worked was the one whose failure was being
  treated as a skip. It now fails on Windows, where every install has a
  ROOT store and an error is therefore our bug, and still skips on unix,
  where a scratch container genuinely can have no CA bundle.

With both changes in, a green `cargo test` on Windows is now evidence
rather than silence, and that is what it produced.

The general shape is worth keeping in mind: **a test that skips when the
thing under test is missing cannot tell you the thing is broken.** That is
fine when absence is a property of the machine and wrong when it is a
property of the code, and the two look identical from inside the test.

**Still open on this axis: macOS.** It falls back to the unix file paths,
so a mac with no `/etc/ssl/cert.pem` gets no roots and is told so. The
Keychain is the real store there and reading it needs the Security
framework. Nobody has run this on a mac either, and the same reasoning
applies - the test will skip there, honestly, because on macOS the absence
of a bundle file really is a property of the machine.

### DES and Triple DES: 56 bits, and a 64 bit block

**Status: accepted, loudly.** Both are implemented and both are broken, in
two different ways that are worth keeping separate.

**Single DES has a 56 bit key.** It was brute-forced in public in 1998 and
costs very little now. There is nothing to mitigate; it is marked `Broken`
in the suite registry and nothing but an explicit request will select it.

**Triple DES fixes the key length and nothing else.** It is still a 64 bit
block cipher, and that is what Sweet32 attacks: in CBC, birthday
collisions between ciphertext blocks leak plaintext after about 2^32
blocks, which is 32 GB on a single connection. Long-lived connections
carrying a repeated secret - a session cookie in every request - are the
case that actually falls. Marked `Broken`. It was once `Weak`, which put
it in the default selection, since `Selection::modern` takes everything
at `Weak` or better; Sweet32 recovered a session cookie from real HTTPS,
so it now takes `Selection::legacy` or a name. That distinction is the
whole reason the registry has four labels instead of two.

Two smaller things this implementation is deliberately relaxed about:

- **Parity bits are ignored**, so a key and the same key with any parity
  bit flipped are the same key. That is what PC1 does and refusing keys
  with bad parity would refuse keys real equipment uses.
- **Weak keys are reported, not refused.** `Des::is_weak` covers the four
  weak keys - where all sixteen subkeys are identical, so encryption is
  its own inverse - and the twelve semi-weak ones, ignoring parity so that
  a key differing from a weak one only in its parity bits is still caught.
  Nothing refuses to compute; a caller who wants the check asks for it.

### The trust store you read is not always the one you think

**Status: mitigated by reporting it.** There are three loaders - a Unix
bundle, the Windows ROOT and AuthRoot stores, and a macOS fallback to the
Unix paths - and which one runs is decided by the build target, not by the
machine you believe you are on. Under WSL this is Linux: it reads the
distribution's CA bundle and the Windows store is never involved, so a
root Windows trusts is not necessarily a root this sees. `SSL_CERT_FILE`
overrides even that.

This has already cost a wrong diagnosis. A run failed two badssl rows on
"No trusted root issued CN=DigiCert Global Root CA"; the first theory was
the Windows root store's on-demand population, and the run was under WSL,
where that store is not read at all. The parser was never involved either
- both DigiCert roots parse here without complaint.

So `TrustStore::source` names the store, `skipped()` counts what would not
parse, and `scripts/check_live.py` prints both before it verifies
anything, plus - when a row fails for a missing issuer - whether that
subject is in the store at all. The question "is this a missing root, a
broken chain, or a parser that refused it" is now answered in the output
rather than reasoned about afterwards.

Windows separately populates ROOT on demand, fetching from Windows Update
when Schannel needs a CA. Reading the store directly never triggers that,
so AuthRoot - where the auto-update mechanism caches the third-party root
programme - is read as well and merged. It narrows the gap rather than
closing it.

### The trust store can be empty without anyone noticing

A trust store that loads nothing does not fail; it verifies nothing, and
every connection fails with something that looks like a network problem.
Worse is a store that loads *some* roots — a bundle where most entries
failed to parse looks exactly like one that worked.

**Status: mitigated.** Every entry point in `src/trust` returns `Err` rather
than an empty store, and `skipped()` counts entries that were found but
could not be parsed. The Python tests assert `skipped == 0` against the real
system bundle.

### Over-strict parsing is its own vulnerability

A parser that refuses real certificates is not secure, it is unusable — and
the pressure to loosen it in a hurry, under an outage, is how the strictness
gets thrown away wholesale rather than adjusted.

**Status: mitigated, and measured.** `tools/src/bin/diff_roots.rs` parses every
certificate in the machine's real CA bundle and compares each field with
OpenSSL. On the bundle it was last run against that is 306 production
roots: all parsed, every field agreeing, and all 306 self-signatures
verified with our own RSA and ECDSA.

One thing found that way and kept: **serial number 0**. RFC 5280 says the
serial "MUST be a positive integer", and Go Daddy's G2 root, both Starfield
G2 roots and the Hellenic academic roots all use 0. `cryptography` warns
about them and plans to reject them. We accept them, deliberately —
refusing would mean being unable to verify a large slice of the public web.
Pinned by a test in `src/x509/mod.rs` so a future tightening fails there
with the reason rather than in a corpus.

A second one found the hard way: **an EC key on a curve we do not
implement used to be a parse error.** It is now `PublicKey::UnsupportedCurve`,
carrying the curve's OID, and it fails at verification instead. The cost of
the old behaviour was out of all proportion to the cause. `TrustStore` parses
each root as it loads it, so one such root was dropped from the store
entirely; a run against a distribution bundle reported *"120 roots loaded, 1
skipped as unparseable"* and there was nothing to say which root or why. And
a server presenting such a certificate got "cannot parse", which reads as a
malformed certificate rather than as a gap here — sending whoever reads it
looking for a problem that is not there.

The rule the module already stated is the right one and was not being
followed: `Certificate::parse` reads, `verify` judges. "I cannot do
arithmetic on this curve" is a judgement.

The measurement above is why this was not caught by `tools/src/bin/diff_roots.rs`:
that bundle has no root on an unimplemented curve, and
the corpus can only compare certificates that both implementations parse.
A gap in curve support is invisible to a differential test by construction.

The same failure mode, one level up: **`TrustStore::skipped` was a count with
the reason thrown away.** It now keeps `skipped_reasons()` — the first sixteen
explanations, each naming the entry by DER length and the first eight bytes of
its SHA-256, since an unparseable certificate has no subject to quote — and
`scripts/check_live.py` prints them. A count cannot distinguish "that entry is
malformed" from "we are too strict", and those have opposite remedies.

### Name constraints

**Status: mitigated for every name form, cross-checked for two.**
`src/x509/name_constraints.rs` implements RFC 5280 4.2.1.10 and
`verify_chain` enforces it after a trusted root has been chosen — which
is when it can be enforced at all, since a constraint on the root governs
the whole path and until a root is picked there is no path.

Three traps in that section, each silent when got wrong:

  * **A leading period means different things to different forms.** As a
    dNSName base, `example.test` covers itself *and* everything below it
    and there is no leading-period syntax at all. As a URI or rfc822Name
    base, `example.test` is one host exactly and `.example.test` is
    strictly below it. One matcher for both is wrong in one direction.
  * **iPAddress in a constraint is address *and mask*** — eight octets
    for IPv4 where the same field is four everywhere else in X.509.
    `read_general_name` takes the permitted lengths as an argument so a
    bare address cannot be read as a constraint whose mask is missing.
  * **A URI whose host is not a fully qualified domain name must be
    rejected**, not skipped, when a URI constraint applies. Skipping it
    is the natural implementation and is a bypass.

And one addition that RFC 5280 does not ask for and this library needs:
**a dNSName constraint also covers the common name when there is no
SAN.** `matches_hostname` falls back to the CN in that case, so without
it a CA constrained to `example.test` could issue a certificate with no
SAN and `CN=evil.test`, and this library would accept it for `evil.test`
while the dNSName constraint saw no DNS names and passed vacuously. The
constraint has to cover every name the *verifier* honours, not every
name the RFC lists. The CN-fallback test in `verify.rs` asserts the
fallback is really happening before
asserting the constraint stops it, so it cannot pass for the wrong
reason.

**Still open: the three forms nothing else here can check.**
`scripts/diff_check.py`'s `nameconstraints` corpus compares whole chains
against python-cryptography's path verifier, which covers **dNSName and
iPAddress only** — it accepts a chain carrying directoryName, rfc822Name
or uniformResourceIdentifier constraints whatever the names are. So
those three matchers are pinned by RFC 5280's own worked examples and by
nothing else. Rows for them are deliberately absent from the corpus
rather than present and vacuous.

That corpus found a real bug on its first run, recorded below.

### Validity dates were encoded in the wrong ASN.1 type

**Status: mitigated.** `x509::builder` wrote GeneralizedTime for every
validity date. RFC 5280 4.1.2.5 requires UTCTime through the year 2049
and GeneralizedTime from 2050, and a strict verifier refuses a
certificate that gets it wrong before looking at anything else — which
means every certificate this library built was unusable to one.

Nothing here caught it, and the reason is worth keeping: **our parser
accepts both forms**, exactly as the same paragraph requires of a
relying party. So every test that built a certificate and read it back
agreed with itself. It took handing a certificate to somebody else's
verifier, which is what `tools/src/bin/diff_name_constraints.rs` does.
`test_validity_dates_use_the_encoding_their_year_requires` now reads the
tag out of the DER rather than round-tripping, and brackets the 2049/2050
boundary from both sides.

---

## 7. Protocol level

TLS from SSLv3 to 1.3, client and server, and what sits on top of it:
the `ssl` drop-in, the OpenSSL shim and the proxy.

- **State machine confusion.** Accepting a handshake message in the wrong
  state is how FREAK, SMACK and Logjam worked. The state machine must reject
  by default and accept only what the current state permits.
  **Status: mitigated.** Every (state, message) pair the client does not
  list is `unexpected_message`; `test_messages_out_of_order_are_refused`.
- **Downgrade.** A peer or an attacker steering to the weakest mutually
  supported suite. Since this library deliberately keeps broken suites,
  the default set must exclude them and enabling one must be explicit and
  per-connection. **Status: mitigated for suites, open for the
  version.** `Selection::modern`, the default, excludes everything
  labelled `Broken` or `Insecure`, and reaching those takes
  `Selection::legacy` or a name. **Open:** RFC 8446 4.1.3's downgrade
  sentinel - the last eight bytes of the ServerHello random when a 1.3
  server negotiates something lower - is neither written by our server
  nor checked by our client. The 1.2 Finished still covers the hello, so
  what is missing is the protection against a downgrade to a 1.2
  handshake whose own authentication an attacker can break.
- **Certificate validation that is on by default.** Easy to write an
  `SSLContext` shim where `verify_mode` silently does nothing. There must be
  a test that an untrusted certificate is *rejected*, not just that a good
  one is accepted. **Status: mitigated.**
  `pytests/test_tls_handshake.py::test_an_untrusted_certificate_is_refused`,
  and `pytests/test_ssl_seam.py::test_verification_actually_rejects` for
  the `SSLContext` drop-in.
- **Padding oracles in CBC suites (Lucky 13).** **Status: mitigated when
  the peer agrees to encrypt-then-MAC, partly mitigated otherwise.**

  RFC 7366 moves the MAC to cover the ciphertext, so a forged record is
  rejected *before* it is decrypted and its padding is never examined.
  That removes the oracle rather than making it hard to measure, and it is
  implemented and preferred. Every modern OpenSSL negotiates it by default
  for CBC suites — which is how this library found out it needed it: a
  captured session would not decrypt until it was written.

  Without it the construction is MAC-then-encrypt and the oracle is only
  reduced. That path computes the MAC over a fixed length regardless of
  what the padding claimed, never returns early between the padding check
  and the MAC check, and returns one error for every failure — a test
  asserts that six different corruptions produce the identical message. It
  is **not** constant time: the HMAC underneath is not, and a one-block
  record's AES takes the table route (a longer record's CBC decryption
  takes the bitsliced one). The remaining exposure is in section 1's
  tables.
- **The AEAD record layer removes the padding oracle rather than timing
  around it.** **Status: mitigated by construction** for the AEAD suites
  (GCM, CCM and ChaCha20-Poly1305).
  There is no padding, so there is nothing for an oracle to be about; the
  tag covers the whole record and is checked before any plaintext exists;
  and every failure - a short record, a bad tag, the wrong keys - is the
  same `bad_record_mac` with the same message. Even the length check is
  reported that way, since a record's length is something an attacker
  chooses and a distinct error for it would be one bit of oracle.
- **The TLS AEAD nonce must not repeat, and here it structurally cannot.**
  **Status: mitigated.** A repeated nonce in GCM gives away the
  authentication key, so this needs to be a property rather than a hope.
  TLS 1.2's GCM splits the nonce into a fixed salt from the key block and
  an explicit per-record half; ours is the record sequence number, which
  the record layer already refuses to let wrap (see below). CCM uses the
  same split (RFC 6655) and inherits the same property. ChaCha20-Poly1305
  (RFC 7905) sends no explicit half: its nonce is the key block's 12 byte
  IV XORed with the sequence number. Either way, tying the nonce to the
  sequence number means there is one counter to be right about instead
  of two.
  `pytests/test_tls_handshake.py::test_gcm_carries_many_records` sends
  twenty records in each direction, because one record cannot catch a
  counter that never advances.
- **FREAK: a ServerKeyExchange for a suite that has none.**
  **Status: mitigated.** A plain RSA key exchange has no
  ServerKeyExchange - the premaster goes under the certificate's key. An
  *export* RSA suite does have one, carrying a temporary key small enough
  for the 1990s export rules, historically 512 bits.

  FREAK was clients accepting that message for a suite that has no such
  message: a man in the middle rewrites the ClientHello to ask for an
  export suite, the server answers with a 512 bit temporary key, and a
  client that takes it encrypts the premaster under a key anyone can
  factor - while believing it negotiated something else. Nothing in the
  message is malformed; it is a correct message for a different suite.

  So the decision is made from the **negotiated suite** and never from
  the message having arrived, and both directions are checked: an export
  suite that sends no ServerKeyExchange must not fall back to the
  certificate key either.
  `test_a_server_key_exchange_for_a_plain_rsa_suite_is_refused` pins the
  first direction, and `test_an_export_suite_expects_its_temporary_key`
  pins that an export suite takes the message. The reverse - an export
  suite with no ServerKeyExchange - is refused in `rsa_key_exchange` and
  has no test of its own yet.

  The temporary key is deliberately **not** held to `min_rsa_bits` - it
  is 512 bits by design, and applying the modern floor would refuse every
  export suite while looking like a policy. What is enforced is a
  *ceiling*: a temporary key above 1024 bits means this message is being
  used for something other than an export key exchange. The certificate
  that signs it is still held to the floor.

  None of which makes an export suite safe. A 512 bit modulus is hours of
  arithmetic and servers reused one for years. It is implemented because
  equipment that offers nothing else exists.

- **RC2's effective key length is part of the key schedule.**
  **Status: mitigated.** TLS's `RC2_CBC_40` is a 16 byte key with 40
  effective bits - not a 5 byte key, and not an unweakened 16 byte one.
  Two implementations that agree on the key and disagree on this produce
  completely different ciphertext, and each round-trips perfectly against
  itself. `BulkCipher::rc2_effective_bits` carries it from the suite to
  the record layer, and `RC2::new` defaults to `8 * key_len` so that
  ordinary use agrees with every other library.

- **The export key expansion is not a shorter key.**
  **Status: mitigated, checked against the specification.** The key block
  yields five bytes per direction and those five bytes are run through
  the PRF again to reach the cipher's real length. Two details are
  invisible to a round trip: the IVs come from a separate PRF pass with
  an **empty secret** rather than from the key block, and SSLv3's version
  is a bare MD5 that swaps the randoms for the server direction. Both are
  pinned by `tools/src/bin/diff_export_keys.rs` against RFC 2246 §6.3.1 and
  RFC 6101 §6.2.2 - the same standing as SSLv3, and for the same reason:
  OpenSSL removed the export suites in 1.1.0.

- **POODLE, and why SSLv3 is implemented and refused.**
  **Status: accepted, and gated.** SSLv3's CBC padding bytes are
  *unspecified* - only the final length byte means anything - so a
  receiver may not reject a record because the bytes before it are
  arbitrary. Combined with MAC-then-encrypt, that lets an attacker who
  can replay a record with its last block substituted learn one byte of
  plaintext per 256 attempts.

  There is no fix inside the protocol. Checking the padding bytes anyway
  would not help: the padding really is arbitrary, so we would simply
  stop being able to talk to the servers SSLv3 support exists for.
  Encrypt-then-MAC would help and cannot be negotiated, because SSLv3
  predates extensions entirely.

  So the mitigation is the only one there is - do not speak it unless you
  mean to. `ClientConfig::new` floors at TLS 1.2, and even
  `ClientConfig::legacy`, which lowers almost everything else, **floors
  at TLS 1.0**; `min_version` must name SSLv3 explicitly. The Python
  shim does the same: `_OUR_LOWEST` is TLS 1.0, so a context that has
  not said never reaches it. `test_ssl3_is_not_reachable_by_default` and
  `test_the_shim_does_not_reach_ssl3_without_being_told` are what keep
  that true.

- **SSLv3's constructions are checked against the specification, not
  against another implementation.** **Status: accepted, and stated.**
  Every current TLS library has removed SSLv3; current OpenSSL builds
  omit it (`ssl.HAS_SSLv3` is False on them), so there is no second
  implementation anywhere to compare bytes with.

  What exists instead: `tools/src/bin/diff_ssl3_keys.rs` and
  `tools/src/bin/diff_tls_record.rs` dump the key expansion, the key block
  split, the 36 byte Finished and the record MAC, and
  `scripts/diff_check.py` checks each against a reference written from
  RFC 6101 in Python. That catches a transcription error in the Rust. It
  would **not** catch a misreading of the RFC that both transcriptions
  shared, and no end-to-end handshake has been run against a real SSLv3
  server. `scripts/check_live.py` is where that would happen.

  This is a weaker claim than every other algorithm here makes, and it is
  the strongest one available for a protocol everybody has deleted -
  which is the situation this library was built for.

- **SSLv3's MAC is not HMAC and does not cover the record version.**
  **Status: mitigated.** The pads are concatenated rather than XORed into
  the key, they are 48 bytes for MD5 and 40 for SHA-1 rather than one
  block each, and the version is absent from the input. A port of the TLS
  code with HMAC swapped out is wrong in a way two implementations making
  the same assumption would agree on, which is why the reference is
  written from the RFC rather than from our code. A hash with no pad
  length in the specification - SHA-256 - is refused rather than given an
  invented one.

- **The BEAST IV.** TLS 1.0 and SSLv3 chain the CBC IV from the previous
  record, which is what BEAST exploits; TLS 1.1 added a fresh explicit IV
  per record. **Status: accepted.** Each version is implemented as it
  specifies, because talking to the old ones is the point of this
  library — so a TLS 1.0 connection here is as exposed to BEAST as TLS
  1.0 is. Using a stream
  cipher suite, or 1.1 and later, is the mitigation, and it is the caller's
  choice to make.
- **An unauthenticated ephemeral key.** In ECDHE the server signs its
  ephemeral public key with the key in its certificate, and that signature
  is the only thing connecting the two. Skip it, or check it wrongly in the
  permissive direction, and anyone in the path substitutes their own
  ephemeral key and reads everything — while the handshake completes
  normally and every happy-path test passes. **Status: mitigated.** The
  signature is verified against the leaf certificate's key before the key
  exchange proceeds, for both RSA and ECDSA, over the bytes exactly as they
  arrived rather than a re-encoding.
  `test_a_tampered_server_key_exchange_is_refused` flips one bit in a real
  OpenSSL ServerKeyExchange and requires the connection to fail.
- **A weak finite-field group is chosen by the server, not by us.**
  **Status: mitigated** for size, which is checked against
  `min_dh_bits` (2048 by default); **accepted** for the rest: primality
  is available behind `check_dh_prime`, and subgroup order cannot be
  checked at all because TLS 1.2 does not send `q`. Section 3b has the whole picture; Logjam is
  the reason there is a floor rather than a shrug.
- **Record sequence numbers must not wrap.** Two records authenticated
  under the same sequence number is a MAC used twice over different data.
  **Status: mitigated** — the counter is checked and the connection is torn
  down rather than wrapping.
- **Renegotiation and TLS 1.2 resumption** have their own history of
  flaws. **Status: accepted.** Neither is implemented. Renegotiation is
  refused: the client answers a HelloRequest with a `no_renegotiation`
  warning and the server accepts a ClientHello only as the first
  message. Both sides still send RFC 5746's signal, so a server that
  does renegotiate cannot have our hello spliced onto somebody else's
  session. The HelloRequest answer has no test of its own. TLS 1.2
  resumption is not implemented either: a 1.2 NewSessionTicket is
  ignored, and only 1.3 resumes (below).

### TLS 1.3 session resumption

**Status: mitigated.** `src/tls/resumption.rs` implements RFC 8446's
ticket and PSK machinery, and a resumed handshake is checked against a
live OpenSSL server — which is the only thing that can check it. Every
mistake in a binder produces a value that is perfectly self-consistent,
so a round trip against ourselves passes whatever it got wrong.

The traps, each silent:

  * **the binder covers the hello minus exactly the binder bytes**,
    with every length still counting them (RFC 8446 4.2.11.2).
    Re-encoding the hello without the binders gives three smaller
    length fields and a binder no server accepts. So it is computed by
    *slicing* the encoded message.
  * **the PSK is an `Expand-Label` with the nonce as context**, not a
    `Derive-Secret` — the two differ only in whether the context is
    hashed first.
  * **the binder key's context is the empty string**, so `Hash("")`,
    not the hello the binder will cover.
  * **the age is in milliseconds** and the lifetime beside it in
    seconds.
  * **`pre_shared_key` must be the last extension**, because the
    truncation above is only well defined if the binders are the last
    bytes of the message.
  * **after a HelloRetryRequest the binder covers all three messages**
    — `message_hash`, the retry, and the truncated second hello — so
    binding only the second would leave the retry unauthenticated.

**The resumption master secret is one message later than everything
else.** RFC 8446 7.1 puts it over "ClientHello ... client Finished",
where the application keys stop at the *server's* Finished. Two
separate bugs came out of that, both found by the OpenSSL test and
neither visible from inside:

  * the client's own Finished was never in the transcript at all.
    `emit_handshake` writes a record and nothing else — the transcript
    is fed by `handle_handshake` on the way *in* — so no outgoing
    message had ever been added to it, and nothing had needed one
    before.
  * the secret was then derived when a ticket *arrived*, and
    `handle_handshake` adds every incoming message to the transcript
    **before** dispatching it. So the transcript already contained the
    NewSessionTicket, and a second ticket's would contain the first.
    It is now taken once, when the handshake ends.

Both produced a PSK the server had never heard of, and the failure
appeared one connection later as a binder OpenSSL rejected — not as
anything wrong with the connection that made it.

### The TLS 1.3 key schedule

A new construction, sharing nothing with the TLS 1.2 PRF. Everything below
produces a schedule that is **perfectly self-consistent** — it agrees with
itself, derives keys that decrypt its own records, and interoperates with
nothing. A round-trip test against ourselves cannot see any of it.

**Status: mitigated** — `src/tls/keys13.rs`, checked by
`tools/src/bin/diff_tls13_keys.rs` against a reference transcribed from RFC 8446
§7.1 in `scripts/diff_check.py` (1,018 cases), with the HKDF primitive
underneath cross-checked against OpenSSL's.

- **The label prefix is `"tls13 "`, with the trailing space**, and the
  single length byte in front counts the prefix. `"tls13"`, or the bare
  label's length, both give a working-alone schedule.
- **An empty message list still gets hashed.** `Derive-Secret(s, "derived",
  "")` takes `Hash("")` as its context, not a zero-length string. The two
  `derived` steps are the only places this comes up and they are the hinges
  of the whole schedule. `empty_hash()` exists so it cannot be passed `&[]`
  by accident.
- **"finished" and "traffic upd" are the opposite case** — those go through
  HKDF-Expand-Label directly, with a genuinely empty context. Derive-Secret
  and Expand-Label look alike and differ exactly here.
- **The next Extract's salt is the *derived* secret, not the stage secret.**
  The derivation exists so the three stages cannot be confused; skipping it
  reconnects them.
- **With no PSK the IKM is `Hash.length` zero bytes**, not an empty input.
  HKDF-Extract forgives an empty *salt* by substituting zeros and does no
  such thing for the IKM, so the asymmetry has to be written out. Pinned by
  the one fixed constant in the schedule: with no PSK and SHA-256 the early
  secret is always
  `33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a`.
- **`Stage` is tracked, not assumed.** A secret from the wrong stage is
  still the right number of pseudorandom bytes, so nothing downstream
  notices. Taking the stages out of order is an error here.
- **The IV's length is the AEAD's nonce length** and is not a function of
  the key length. It is 12 for every AEAD RFC 8446 names, and RFC 9367
  makes it the cipher's block: 16 for Kuznyechik, 8 for Magma. The length
  is an input to the expansion, so a wrong one is a different IV rather
  than a length error. Deriving it from `key_len` is invisible for
  AES-128 and wrong for everything else; `BulkCipher::iv_len_13` is what
  to ask, and the corpus sweeps 8, 12 and 16 against both key lengths.
- **An empty (EC)DHE shared secret is refused.** A schedule built without
  one is a schedule an observer can compute.

### The TLS 1.3 record layer

**Status: mitigated** — `src/tls/record13.rs`, with 2,520 cases in
`tools/src/bin/diff_tls13_record.rs` checked against OpenSSL's AEAD plus a
nonce and AAD computed from RFC 8446 §5 in `scripts/diff_check.py`.

- **The sequence number belongs to the keys, not to the connection**, and
  restarts at zero on every key change — handshake keys, application keys,
  and each KeyUpdate. `Aead13` holds the counter *inside* the same
  structure as the keys so the two cannot be replaced separately, and
  `RecordWriter` does not take a number from its own counter when the
  protection is 1.3.
- **The nonce is the static IV XOR the sequence number, left-padded.** The
  counter goes in the last eight bytes of the IV. Nothing on the wire says
  which nonce was used, so padding it on the other side is invisible until
  a real peer refuses every record. Pinned by a test that writes the nonce
  out rather than round-tripping it.
- **The AAD is the five byte wire header**, whose length field counts the
  ciphertext *plus the tag*. TLS 1.2's AAD was `seq || type || version ||
  plaintext_len`; none of those fields survive, and the sequence number is
  now only in the nonce.
- **The header's content type is a decoy.** Every protected record says
  `application_data` and `0x0303`. The real type is the last non-zero byte
  of the decrypted plaintext, found by scanning back past the padding — so
  a record that decrypts to nothing but zeros has no type, and RFC 8446
  §5.4 makes that `unexpected_message` rather than something to guess at.
- **A ChangeCipherSpec after the keys are in place is never encrypted.**
  It is a middlebox-compatibility relic and must pass through undecrypted;
  trying to decrypt it fails its tag and tears down a healthy connection.
  It must also not advance the record counter. Anything *else* arriving
  unprotected is a peer bypassing encryption and is refused.
- **The expansion allowance shrank from 2048 bytes to 256.** There is no
  explicit nonce and no padding block any more. Checking against the old
  limit lets a peer claim eight times the memory for free.

### The TLS 1.3 handshake's shapes

**Status: mitigated** — `src/tls/handshake13.rs`, and
`tests/test_tls13_transcript.rs` reads a real OpenSSL flight end to end.

- **The same extension type has a different wire format in different
  messages**, with nothing to say which one you are looking at except the
  message around it:

  | | ClientHello | ServerHello | HelloRetryRequest |
  |---|---|---|---|
  | `supported_versions` | `uint8` length, then versions | bare 2 bytes | bare 2 bytes |
  | `key_share` | `uint16` length, then entries | one entry, no length | bare `uint16` group |

  Reading a ServerHello's `supported_versions` with the ClientHello rule
  at least fails loudly — the version's high byte becomes a length and
  runs out of data. The other direction does not: a ClientHello share list
  read as a single entry takes the list length for a group code and
  reports a group nobody offered. So there is one function per (extension,
  message) pair and none of them take a flag, because a function that
  chose from a parameter is a function whose caller can get it wrong.
- **HelloRetryRequest is not a message type.** It is a ServerHello whose
  random is a fixed constant — which is `SHA-256("HelloRetryRequest")`,
  and is pinned by deriving it rather than by transcription. Treating one
  as an ordinary ServerHello means deriving a handshake secret from a key
  share that was never sent.
- **CertificateVerify signs a constructed string**, not the transcript:
  64 bytes of `0x20`, a context string that differs by side, a zero byte,
  then the transcript hash. The 64 spaces stop the signature from also
  being valid over a TLS 1.2 signing input; the differing context string
  stops a client's signature being replayed as a server's, and the two are
  the same length, so a comparison that stopped at the length would pass.
- **A CertificateVerify's RSA signature must be PSS.** RFC 8446 §4.4.3:
  the `rsa_pkcs1_*` codepoints "refer solely to signatures which appear in
  certificates". They are still offered in `signature_algorithms`, because
  a certificate in the chain may be signed with one — so the check is on
  what arrives in the CertificateVerify, not on what was offered.
- **The TLS 1.3 signature schemes are opaque 16-bit codepoints**, not the
  TLS 1.2 `(hash, signature)` pair. `rsa_pss_rsae_sha256` is `0x0804`,
  which under the old split reads as hash 8 and signature 4 — both
  meaningless. TLS 1.3 also binds the curve to the ECDSA schemes, which
  TLS 1.2 left to the certificate.
- **The Certificate message gained a request context and per-entry
  extensions.** Parsing a TLS 1.2 chain with the 1.3 rule reads the first
  certificate's length bytes as the context length.

### The RSA premaster's version bytes are the hello's field

RFC 5246 §7.4.7.1: the client puts `ClientHello.client_version` in the
first two bytes of the RSA premaster, and the server compares them as a
rollback countermeasure — deliberately in a way that does not report what
failed, because reporting it is Bleichenbacher's oracle.

Until TLS 1.3 "the version in the hello", "the highest version offered"
and "the version field" were the same thing. TLS 1.3 pins the field at
0x0303 and moves the offer into `supported_versions`, and they are three
different things.

**Status: mitigated, after being live.** Raising the default ceiling to
1.3 put 0x0304 in the premaster and every RSA key exchange against a TLS
1.2 server failed with the server sending `bad_record_mac`. Sixteen
end-to-end tests caught it and not one unit test did, because every unit
test built a connection whose ceiling was 1.2. `offered_version` is now
the hello's own field by construction, pinned by
`test_the_premaster_version_is_the_hello_field_not_the_ceiling`.

### The server side: three things that are not the client's problem

`tls/server.rs` is the mirror of `tls/client.rs`, and everything the two
share is one copy that both call — the record layer, the key block, the
transcript, `protection_for`, `EphemeralKey`. Two copies would agree
about AES and disagree about something small, and a disagreement like
that shows as a handshake that fails against one peer in twenty.

Three things have no counterpart on the client side at all.

**The server chooses.** A client offers and checks what came back; a
server picks the version and the suite out of what was offered, and
every choice is a chance to pick something weaker than it had to. The
selection is the caller's `Selection` in the caller's order, and a
caller that wants the client's preference honoured passes a different
order rather than setting a flag — "whose order decides" is a property
of the list, and a boolean beside it would be a second place to look.
The key is also consulted: `ServerKey::authenticates` means an EC key
never chooses an RSA suite, which would otherwise be a handshake that
fails at the signature rather than at the selection.

**The server signs, and the signature is not over the transcript.** A
TLS 1.2 ECDHE ServerKeyExchange is signed over
`client_random || server_random || ServerECDHParams`. Both randoms are
in the hellos, which *are* in the transcript, but this signature names
them directly and in that order. Signing the params alone produces
something a client rejects with nothing to say, and nothing on our own
side of the wire can tell — our client would accept whatever our server
produced. `pytests/test_tls_server.py` exists for that one fact: it
drives a real OpenSSL client, which verifies the signature before it
sends its own key exchange. Breaking the signature on purpose fails 21
of its 31 tests; swapping the two randoms fails the same 21.

**The RSA key transport path is a Bleichenbacher oracle if you let it
be.** RFC 5246 §7.4.7.1: on *any* failure — bad PKCS#1 padding, the
wrong length, the wrong version in the first two bytes — the server
continues with a **random** premaster and dies at the Finished, and must
not report which happened. So `decrypt_premaster` returns `Vec<u8>` and
not `Result`: a function that returns `Result` invites a caller to write
`?` and put the oracle back. The random fallback is generated *before*
anything is examined, there is no early return, and the three failure
conditions fold into one mask byte that selects between the candidate
and the fallback without branching. Two tests pin the shape: the
fallback must be 48 fresh bytes every time (a fixed one is worse than
none — the attacker learns nothing from one connection and everything
from two), and a premaster carrying a rolled-back version must come back
*different* from what arrived.

The version bytes are the ClientHello's `legacy_version` **field**, and
the code originally said so in a comment while doing `let _ = d[0];` —
a comment claiming a check that was not there, which is worse than
either having the check or admitting its absence.

### A shim that fails to load tests the thing it replaced

`LD_PRELOAD=libssl.so curl https://host/` either replaces OpenSSL's TLS
with ours or does nothing at all, and **the two look identical from
outside**: the page comes back either way. A typo in the path, a
missing symbol, an ABI mismatch that makes the loader skip us - the
program carries on against the real library and every assertion about
the connection still passes.

**Status: mitigated.** The shim writes a line to `ALLCRYPT_LOG`, and
every test in `pytests/test_shim.py` asserts it is there. That is the
only evidence available; there is nothing observable about a
*successful* connection that distinguishes the two stacks.

The same shape appears in the legacy rows. "curl reached a TLS 1.0
server through the shim" is only evidence if curl cannot reach it
otherwise, so each row records whether an unaided curl succeeds and the
test checks that claim rather than assuming it. The assumption was
wrong once already - `AES256-SHA` over TLS 1.2 was written as a refused
row, and this OpenSSL accepts it - and a row that drifts now fails
loudly rather than quietly becoming decoration.

### Everything the shim does not intercept is still the real library

The real `libssl.so.3` stays loaded when the shim is preloaded, because
it is in the program's `DT_NEEDED`. Symbol interposition is per symbol:
ours win where we define them, and where we do not, the call goes to
OpenSSL - **which is then handed one of our structs to read as one of
its own.**

That is not a crash in our code that a test would find; it is a crash
inside OpenSSL, on a pointer it had every reason to trust.

**Status: mitigated by completeness, which is the only thing that
works.** The set started as the union of what `wget` and
`libcurl.so.4` reference, measured with `nm -D` rather than guessed -
sixty-three functions - and has grown to 104 as server, session and
other entry points were added. The rule for `shim/src/lib.rs` is to
implement the whole set a shimmed program references, not the set that
looked necessary.

The related trap in measuring: `nm -D /usr/bin/curl` shows **zero**
libssl symbols, because curl's TLS calls live in `libcurl.so.4`. Read
without care that says curl does not use OpenSSL, and `curl -V` says
the opposite.

### Linking libcrypto binds a soname, and two libcryptos in one process is a crash

The shim hands back genuine OpenSSL objects, so it has to call into
libcrypto. Declaring those calls with `#[link(name = "crypto")]` is the
obvious way and is wrong twice over.

The visible half is a build problem: `-lcrypto` resolves through the
unversioned `libcrypto.so` symlink, which only OpenSSL's *development*
package installs. A machine that runs OpenSSL but has never needed its
headers cannot link the workspace at all, so `cargo test` — which has
nothing to do with the shim — fails on the library too. On Windows
there is no `crypto.lib` to find in the first place.

The dangerous half is silent. Linking writes a `DT_NEEDED` for the
soname present on the **build** machine. Preload that into a program
linked against a different libcrypto and the process holds two of them:
`d2i_X509` from one builds the struct, `X509_get_subject_name` from the
other reads it. Same symbol name, different layout, different
allocator. It is the same failure as the section above — a pointer read
as the wrong struct — arrived at from the opposite direction, and it
does not need us to have forgotten anything. Building on a box with
OpenSSL 3 and running against a program using 1.1 is enough.

**Status: mitigated.** Nothing is linked. `shim/src/objects.rs`
resolves all nineteen functions with `dlsym` through
`dlopen(NULL, RTLD_LAZY)` — a handle onto the running program and what
it has already loaded, which under `LD_PRELOAD` is by construction the
libcrypto the program is itself using. Loading a copy by soname is a
fallback for a host program that brought none. `readelf -d` on the
built `libssl.so` is the check: `libc`, `libgcc_s`, the loader, and
nothing else.

Eighteen of the nineteen resolve or none does, deliberately: a
libcrypto missing one of them is not one we can use, and a table half
full turns the build-time link error we just removed into a null
dereference midway through a handshake. With none found the shim says
so once on stderr — the handshake still works, since that is all ours,
but `SSL_get1_peer_certificate` answers null and a program reading the
certificate for its own reasons sees a peer that sent none.

**The near miss in that fix**, recorded because the first version had
it: all-or-nothing was written for the whole set, and
`X509_STORE_get1_all_certs` is OpenSSL 3.0 and later. On a 1.1.1 host —
exactly the sort of host this library exists for — *nothing* would have
resolved, and every certificate object would have been lost to spare a
feature only `libcurl --cacert` uses. It is optional now, and its
absence is reported in the log rather than inferred. The general shape:
an all-or-nothing rule is only as good as the oldest member of the set,
and "the version this was developed against has all of these" is not the
question.

### A panic cannot cross back into C, and reading for that does not scale

Unwinding out of an `extern "C"` function is undefined behaviour, and
the caller here is `libcurl` or `wget` — a process with no idea a Rust
library is underneath it and no way to catch anything. The shim's rule
was therefore "no `unwrap`, `expect` or `panic!` in this crate", held
by reading.

**Status: mitigated, and the way it was found is the point.** A
deliberate-breakage sweep turned one `let Some(x) = .. else { .. }`
into `.unwrap()` in `objects.rs`, and **nothing failed** — twenty-two
pytest rows and six unit tests all passed. The value is always `Some`
on a machine with a current OpenSSL; only a host with an older one
would ever have found out, by crashing inside curl.

A convention that only the author's attention enforces is not a
mitigation. `shim/src/lib.rs` now carries
`#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic,
clippy::unreachable, clippy::todo, clippy::unimplemented)]`, with tests
allowed since an assertion failure there is the point. `cargo clippy
--all-targets` is already in the gate, so the same break now fails to
build.

### A terminating proxy that signs everything is a padlock that means nothing

`allcrypt-proxy` sits between a browser and a box the browser will not
talk to, and it has to present *some* certificate. The obvious choice -
sign one with the proxy's own CA - is a security failure rather than a
convenience: every server behind the proxy then looks equally
trustworthy, because the proxy vouches for all of them. The user sees a
padlock whether the box has a valid certificate, an expired one, or one
for somebody else entirely.

**Status: mitigated, by mirroring.** `src/proxy.rs` builds the
certificate to present *from* the one the server sent. The subject, the
subject alternative names, the validity window and the serial are
copied; extensions this library cannot parse are copied verbatim,
because dropping one would be deciding on the client's behalf about
something it could not read; and the signature comes from the installed
CA **only when the server's own chain verified**. A self-signed server
mirrors as self-signed, an unknown issuer as an unknown issuer.

Two consequences follow that are worth stating rather than discovering.
The key cannot be mirrored - the proxy has to hold the private half -
so a fingerprint pin does not survive, and "accept permanently" on a
self-signed box pins the mirror rather than the original. And there is
deliberately **no "verify nothing" switch**: an unverifiable server is
mirrored as unverifiable, the browser asks, and the person answers.

### The check nothing observes

Removing the hostname from the proxy's verdict left all twenty-four of
its tests passing. Not because the check was useless - because the
mirror copies the origin's names, so a *client* refuses a wrong-name
certificate whatever the proxy concluded. The check was invisible, and
an invisible check is one that can stop working without anyone noticing.

It still matters twice over: the `--verbose` line is what an operator
reads to find out why a page will not load, and a "verified" verdict is
what makes the proxy sign with the CA the browser trusts - so it must
never be reached for a certificate that is wrong for this host.

**The general shape**: a deliberate break that the end-to-end tests miss
is not necessarily uncovered. It may be a property that some *other*
layer happens to enforce, and then the test to write is one that
observes the property directly rather than its consequence.

### `supported_versions` is the whole offer, not a hint

RFC 8446 4.2.1: a client sending `supported_versions` lists "all
versions of TLS which they are prepared to negotiate". RFC 8446 4.1.2: a
server that sees the extension **ignores `legacy_version` entirely**.

So a client whose floor is TLS 1.0 and whose ceiling is 1.3 must list
1.3, 1.2, 1.1 and 1.0. Ours listed 1.3 and 1.2 and stopped.

**Status: mitigated, after being live.** Every version test pinned
`max_version` to the version under test, which puts the ceiling below
1.3 and skips the extension altogether - so the bug was in a
configuration nothing exercised. The proxy is the first thing here that
wants a *high* ceiling and a *low* floor at once, because a modern box
should get 1.3 and an old one should still be reachable, and it failed
against a TLS 1.0 server with `protocol_version`.

The failure shape is the one this document keeps warning about: an
OpenSSL old enough to ignore the extension negotiates from the version
field and works, while a current one honours it and refuses. "Works
against some servers", where the ones it fails against are the modern
boxes deliberately pinned to an old version - which is exactly the
population this library exists for.
`test_an_old_server_is_reached_with_the_ceiling_left_at_1_3` covers it.

### The two Diffie-Hellman families strip leading zeros in opposite directions

RFC 5246 §8.1.2, for finite-field DH: the premaster is "the negotiated
key Z, with leading zero bytes stripped". RFC 4492 §5.10, for elliptic
curve DH, about exactly the same position in exactly the same message:
"leading zeros found in this octet string MUST NOT be truncated".

They are opposites, they are one line of code apart, and a shared value
begins with a zero byte about once in 256.

**Status: mitigated, after living in the server for its whole short
life.** `tls/server.rs` applied the finite-field rule to ECDHE. Nothing
saw it:

- **Our client against our server** agreed, because neither side ever
  drew a shared value with a leading zero. (They would not have agreed
  if one had: the client was right all along.)
- **The OpenSSL handshake tests** in `pytests/test_tls_server.py` agreed
  for the same reason — thirty-one handshakes, each about 0.4% likely to
  hit it.
- **`tools/src/bin/diff_ec.rs`** checks `curve.ecdh`, which is the layer
  *below* the rule and was correct.
- **The deliberate-breakage sweep** reported the line as unprotected —
  it removed the stripping, every test passed, and the honest reading of
  that result is "no test covers this line". The true reading was that
  removing it *was the fix*. A break that nothing catches means one of
  two things and the sweep cannot tell them apart.

The rule now lives in one function, `keys::strips_leading_zeros`, which
both sides call and which lists every `KeyExchange` variant explicitly
so that adding one is a compile error rather than a silent `false`.
`tools/src/bin/diff_tls_premaster.rs` is the corpus: every row has a leading
zero in the raw shared value, found by **searching** rather than waited
for, and the checker requires our answer to match the row's own RFC
*and differ from the other one*. A one-sided check would pass with both
families implemented as the same rule, which is the bug.

The general lesson is the one this document keeps arriving at from new
directions: a case that occurs one time in 256 is not rare enough to
ignore and not common enough to meet by accident, so it has to be
constructed. `tools/src/bin/diff_dh.rs` uses small groups for its half of
this; there is no small curve, so this one searches.

### The TLS 1.3 signature schemes are legal in TLS 1.2 too

RFC 8446 §4.2.3. A client that offers `rsa_pss_rsae_sha256` for 1.3 will
be taken up on it by a 1.2 server signing a ServerKeyExchange.

**Status: mitigated, after being live.** The moment this client started
offering the PSS schemes, a TLS 1.2 handshake failed with *"the server
signed with hash 8, which is not implemented"* — 0x0804 read as a TLS 1.2
`(hash, signature)` pair. The 1.2 verification path now understands both
numbering schemes and verifies PSS.

---

## 7b. GOST

This section used to open by saying no other implementation of any of
it was available, so the differential reference in
`scripts/diff_check.py` was a second reading of the standards rather
than somebody else's code. **That is no longer the position**, and the
change is worth stating plainly because it is the single largest
improvement in confidence this family has had.

OpenSSL's **gost-engine** is now that other implementation. It is a
separate project, written by other people, and it is the code running
on the servers this library exists to reach.
`scripts/make_gost_vectors.py` drives it and writes
`vectors/gost_engine.vec`; `tests/test_gost_engine_vectors.rs` reads
that file back with no network, no engine and no OpenSSL. The
implementations remain entirely our own code — the engine is a witness,
not a dependency, and nothing in the build or the test gate links it.

What it now covers: both block ciphers in every mode the command line
reaches, GOST 28147-89 under two parameter sets, **CTR-ACPKM past its
section boundary**, all three digests, MGM far beyond RFC 9058's
vectors, OMAC over both ciphers, GOST 28147-89's own MAC, KExp15, VKO
on all nine parameter sets at both digest sizes, GOST R 34.10-2012
signatures, and TLSTREE for both RFC 9189 suites. What it still does
not: the TLS record layers, and the ACPKM-OMAC AEAD, which segfaults
when driven through EVP.

It found a real bug the first time it ran; see *The GOST MAC is never
fewer than two blocks* below, and *VKO's cofactor* in §7o for the other.

**And the record layers are no longer judged only by us.**
`tests/transcripts/gost_handshakes.txt` holds seven real GOST TLS 1.2
handshakes with OpenSSL plus gost-engine at *both* ends, recorded by a
relay that sat between them, plus the master secret from
`s_server -keylogfile`; `tests/test_gost_transcript.rs` derives the key
block and decrypts records the engine encrypted, in both directions,
across several records per direction. That is the only thing that can
settle the byte orders — our own client and server agree with each other
whichever way round any of them is, which is what
`tests/test_gost_handshake.rs` has always said about itself.

Both record layers are in it, and so are the two CNT_IMIT S-boxes and
both PRFs: 0xC102 with `id-tc26-gost-28147-param-Z` and Streebog-256,
and 0x0081 with `id-Gost28147-89-CryptoPro-A-ParamSet` and GOST R
34.11-94. A GOST cipher *is* its S-box, so those two produce entirely
different bytes from the same key material.

The capture pads both directions past 1024 octets on purpose. Every
re-keying mistake in these suites is right for the first record and wrong
afterwards — CTR-ACPKM restarts its keystream per record and its ACPKM
counter runs across the section boundary, TLSTREE changes the key at a
sequence boundary, and CryptoPro meshing fires after 1024 octets — so a
capture of a handshake alone would have exercised none of it. A
three-break sweep confirms the test notices: sequence numbers off by one,
the Finished left out of the protected run, and the two halves of the key
block swapped each fail three or more of its five tests.

`scripts/capture_gost_transcripts.py` had one trap worth recording.
`s_server` refuses to *load* the 2001 suite's certificate at all —
`SSL_CTX_use_certificate: ca md too weak`, because the chain is signed
with GOST R 34.11-94 and the default security level rejects it. That is a
policy about the CA's digest and not about the suite, so the capture
passes `@SECLEVEL=0` for that one row rather than dropping the suite.
Being unable to reach an algorithm because somebody else turned it off is
the situation this library exists for.

**How the constant tables were obtained**, since they are the part a
second reading cannot check: Kuznyechik's `pi` is byte-identical between
RustCrypto's `kuznyechik` crate and the `gostcrypto` Python package, two
implementations with no common ancestor. Streebog's `A`, `PI` and `C`
together reproduce the gost-engine project's precomputed linear table byte
for byte, and its `C` matches that project's constants word for word.
Magma's S-box is the `id-tc26-gost-28147-param-Z` table this library
already carried in `gost.rs`, pinned to it by a test. Each algorithm is
then checked against its own standard's published vectors, which is what
says the tables are right rather than merely two copies of the same wrong
one.

### Kuznyechik's field is not AES's

**Status: mitigated.** GF(2^8) modulo x^8 + x^7 + x^6 + x + 1 (0x1c3), not
AES's 0x11b. The two agree on enough inputs that a cipher built with the
wrong one still looks like a cipher, and agrees with nothing. Pinned by a
test on a product the two disagree about, so a change to the wrong
polynomial fails with the reason rather than in a corpus.

### Magma is GOST 28147-89 read the other way round

**Status: mitigated, and both are kept.** GOST R 34.12-2015 fixed the
S-box that 28147-89 left as a parameter, and reads the key words and the
block **big endian** where 28147-89 reads them little endian. Nothing else
differs. So the same key and the same plaintext produce two different
ciphertexts under the two standards, and each is correct under its own —
which is why `magma.rs` and `gost.rs` both exist and a test asserts they
*disagree*.

Within Magma, `pi_0` acts on the **least significant** nibble. Reversing
the rows gives a cipher that is self-consistent and interoperates with
nothing, so the order is pinned by a test that checks each row's effect
one nibble at a time.

### Streebog's test vectors are printed backwards

**Status: mitigated by saying so, loudly, in three places.**

GOST R 34.11-2012 writes messages and digests as 512-bit *numbers*, most
significant byte on the left. Every implementation — this one, OpenSSL's
GOST engine, everything — works on byte strings in order. So the
standard's M1, fed in as bytes, is the message backwards, and its expected
digest is the implementation's output backwards.

This matters more than a formatting note because **the symptom is
identical to a wrong implementation**: the digest is wrong and there is
nothing to say whether the code or the byte order is at fault. The tests
use the standard's messages and digests reversed and explain why; the
empty-string digests, which every implementation quotes in array order,
are pinned separately so the two conventions are both anchored.

### Streebog's other three

**Status: mitigated**, each with a test.

- **The state is a little-endian 512-bit integer.** Both running sums —
  the length counter and the block checksum — add modulo 2^512 with the
  carry running from byte 0 upwards. The wrong direction is invisible
  until a sum carries, which is to say from the second block.
- **The padding byte is 0x01 immediately after the message**, not at the
  end of the block, and a message that exactly fills a block still gets a
  whole extra padded block.
- **Streebog-256 is not Streebog-512 truncated.** Its IV is sixty-four
  0x01 bytes and its digest is the *last* 32 bytes of the state. Taking
  the first 32 bytes of a 512-bit digest gives a hash with no known
  weakness and no agreement with anybody.

---

### CBC-MAC is forgeable; CMAC is the fix, and its constant is not one constant

**Status: mitigated.** `src/mac/cmac.rs` - which GOST calls OMAC.

Plain CBC-MAC over variable-length messages is forgeable in one line:
given `T = CBC-MAC(M)` for a one-block `M`, the message `M || (M xor T)`
has the same tag, and no key is needed to work that out. CMAC's two
subkeys stop it, because a padded message and an unpadded one are finished
under different keys.

- **Rb depends on the block size** - 0x87 for 128 bits, 0x1b for 64 -
  because it is the low coefficients of the field's irreducible
  polynomial. One value for both gives a MAC that is perfectly consistent
  over DES, 3DES, Blowfish and Magma and agrees with nothing.
- **The empty message is padded**, so it uses K2. The condition is
  `len > 0 && len % b == 0`; leaving the first half off makes exactly one
  message's tag wrong.
- Checked against **OpenSSL's own CMAC** through `python-cryptography` for
  AES, Triple DES and Blowfish, which covers both values of Rb with
  somebody else's code. Kuznyechik and Magma then use the same
  construction against this file's own spec-derived ciphers.

### ACPKM's counter does not restart with the key

**Status: mitigated.** `src/block_ciphers/acpkm.rs`, RFC 8645.

CTR under one key is safe for a bounded number of blocks, and on a 64-bit
block that bound is 2^32 — 32 GB for Magma. ACPKM re-derives the key every
N bytes, one-way, so recovering a section's key says nothing about the
sections before it.

- **The counter runs across the whole message**, not per section.
  Restarting it is self-consistent and agrees with no other
  implementation.
- **The section size must be a whole number of blocks**, or one block
  would be encrypted under two keys.
- **`D` is a constant**, the same for every re-key; what changes is the
  key it is encrypted under.

---

### GOST R 34.10-2012 is not ECDSA with different curves

**Status: mitigated**, each point with a test, 280 signatures in
`tools/src/bin/diff_gost3410.rs` verified by a reading of the standard in
`scripts/diff_check.py`, and gost-engine's own signatures verified by
`test_the_engine_s_signatures_verify`. Signing and verifying against
ourselves would prove only that the two halves agree; verification by
something else is the check.

Four differences, every one silent:

- **The digest is read little endian.** GOST writes hash values as numbers
  with the most significant byte on the left; Streebog — like every
  implementation of it — emits a byte string in the other order. The two
  conventions cancel, which is why OpenSSL's GOST engine uses
  `BN_lebin2bn` here. Reading it big endian gives signatures that verify
  against themselves and nothing else. The differential checker asserts
  each signature does **not** also verify under the big-endian reading, so
  it cannot pass vacuously.
- **The signing equation has no inversion**: `s = r·d + k·e`, not
  `s = k⁻¹(e + r·d)`. So verification needs `e⁻¹` where ECDSA needs `s⁻¹`.
  Getting that backwards gives a scheme that is internally consistent and
  is not GOST.
- **The wire order is `s ‖ r`**, the opposite of ECDSA's. Two fixed-width
  integers of the same size swapped is a signature of the right length
  that parses cleanly and verifies against nothing.
- **The component width comes from the group order**, not the field. They
  match on every curve here, and writing the one that happens to be right
  is how it stops being right on the next curve.

And one thing that is a deliberate deviation rather than a pitfall: the
nonce is derived with RFC 6979 rather than drawn from the random source.
GOST does not standardise a deterministic scheme, but the failure mode of
a repeated nonce is identical to ECDSA's — two signatures sharing one hand
over the private key in four modular operations. The signatures are still
valid GOST signatures that any verifier accepts; they are also
reproducible, which makes them testable. Nothing in `gost3410.rs` calls
`random`.

### VKO is symmetric, so two wrong implementations agree perfectly

**Status: mitigated**, and this is the entry to read if only one gets
read. RFC 7836 §4.3, `src/ec/vko.rs`.

Both sides of VKO compute `ukm · da · db · G`, and the order of the
multiplications does not matter. So a round trip between two ends of the
*same* implementation produces a matching key **whichever way round the
UKM is read and whichever way round the coordinates are serialised**.
Every convention below is invisible from inside and produces a key a real
peer will not have:

- **The UKM is read as a little-endian integer.**
- **Both coordinates are written little endian** before hashing, x then
  y, each padded to the *field's* width — not the group order's, which is
  a different number that happens to have the same byte length on every
  curve here.
- **The digest size follows the key**, not the curve.

`tools/src/bin/diff_vko.rs` emits 224 exchanges, each under both
cofactor readings, and the checker recomputes both directions from the
RFC. It also asserts the key is **not** the same
under the big-endian UKM reading, and not the same under big-endian
coordinates — so the check cannot pass on an implementation that made
those mistakes.

There is a fourth convention, and it is not a byte order: **the
cofactor**, which RFC 7836 includes in the scalar. gost-engine includes
it too, inside `gost_ec_point_mul` rather than where a reader of
`VKO_compute_key` would look. It changes nothing on the GOST curves with
`h = 1` and changes the point entirely on the two with `h = 4`.
`Curve::vko` uses `Cofactor::AsSpecified`; `Cofactor::WithoutCofactor`
is kept only as the negative control, and §7o has the whole story.

A zero UKM is refused. It makes the scalar zero and the point the
identity, which every pair of keys agrees on — a shared secret an
observer has too.

### A curve's p is not always 3 mod 4

**Status: mitigated, after being an assumption.** The square root this
library has is the `p = 3 mod 4` shortcut, `a^((p+1)/4)`, and compressed
point decoding needs it. Every NIST curve satisfies that, so it was
asserted of *all* curves in a test — and the GOST curves broke it:
`gost256-b`'s p ends in `...c99`, which is 1 mod 4.

It is now `Curve::supports_compression()`, a property asked rather than
assumed, and the tests assert that a curve which cannot decompress
**fails** rather than being skipped — a point that decoded to something
else would be far worse than one that refused. `tools/src/bin/diff_ecdsa.rs`
likewise no longer sweeps `curves::all()`: nobody signs with ECDSA over a
GOST curve, and rows nothing can verify count towards a total and prove
nothing.

The general lesson, which is the same one as everywhere else in this
document: a fact that happens to hold for every case you have is not a
property of the code, and asserting it in a loop over "all" makes adding
a case a test failure rather than a silent wrong answer. That is the good
outcome — it is how this was found.

### TLSTREE's counter is big endian, and the constants are per suite

**Status: mitigated, by the RFC's own vectors.** RFC 9189 section 3
defines **both** `STR_8` (big endian) and `str_8` (little endian), and
uses both in the same document. TLSTREE feeds a masked sequence number
through `STR_8`. Reading it the other way round gives a key schedule
that is entirely self-consistent: every record encrypts and decrypts
against itself, and no peer agrees with any of it.

The masks are worse, because they are *nearly* the same between the two
suites and completely different in effect:

```
Kuznyechik  C1 = FFFFFFFF00000000  C2 = FFFFFFFFFFF80000  C3 = FFFFFFFFFFFFFFC0
Magma       C1 = FFFFFFC000000000  C2 = FFFFFFFFFE000000  C3 = FFFFFFFFFFFFF000
```

**At sequence number 0 every mask is zero, so the two suites produce the
same key**, and so does a mask with a bit wrong. A test that tried only
the first record of a connection would pass on all three mistakes at
once. `src/kdf/gost.rs` carries RFC 9189 Appendix A.1.1, which prints
every level at the sequence numbers *either side* of each boundary, and
a test asserts the two suites agree at 0 and disagree at 64 — so the
vacuous case is named rather than avoided.

### CTR_OMAC has two layers of re-keying that know nothing about each other

**Status: mitigated.** RFC 9189's CTR_OMAC suites re-key twice over:
TLSTREE derives fresh encryption and MAC keys for **every record** from
the sequence number, and CTR-ACPKM then re-keys again **inside** one
record every 1 KB (Magma) or 4 KB (Kuznyechik) — both smaller than the
16 KB a record may carry. Neither layer is visible to the other.

Three things about it that are silent when wrong:

* **Each record starts a fresh keystream.** That is the opposite of RC4
  in `StreamHmac`, where the keystream runs for the whole connection.
  Both are one line of code and the difference shows on the *second*
  record, never the first.
* **The IV is added to the sequence number, not XORed**, and the sum
  wraps in the IV's own width — four bytes for Magma, eight for
  Kuznyechik. A 64 bit add agrees with the correct one for the first
  four billion records.
* **Magma's SNMAX is 2^32 - 1** (RFC 9189 section 4.3.5), far below the
  record layer's own 2^64 wrap check, precisely because of that four
  byte IV: past the ceiling the IV repeats while TLSTREE has not
  necessarily moved, which is a reused keystream. `CtrOmac` refuses
  rather than wrapping.

It is also authenticate-then-**encrypt**, which is safe here because the
cipher is a stream cipher and is why RFC 7366 forbids negotiating
encrypt-then-MAC with these suites. A record built the other way round
has the same length and round-trips perfectly against itself;
`scripts/diff_check.py` computes the other ordering explicitly and fails
if it matches.

### The CTR_OMAC key exchange stacks four byte orders in one message

**Status: mitigated, by RFC 9189's own handshake example.** The
ClientKeyExchange of RFC 9189 section 4.2.4.1 makes four independent
byte-order decisions, and every one of them produces a message that two
implementations making the same choice exchange perfectly:

* `UKM = INT(H[1..16])` is **big endian** (RFC 9189 section 3), while
  VKO's own wire UKM is **little endian** (RFC 7836). Opposite
  conventions, one expression apart. `Curve::vko_with_ukm` takes the
  integer so that each caller states its own reading rather than
  inheriting the other's.
* The shared point is hashed with **little endian** coordinates.
* The ephemeral public key's coordinates are **little endian** again in
  the SubjectPublicKeyInfo, inside an OCTET STRING inside a BIT STRING
  (RFC 9215 section 4.3). The double wrapping is real.
* `seed = H[17..24]` and `IV = H[25..24 + n/2]` are **adjacent slices of
  the same hash**, so swapping them changes nothing about the shape of
  anything.

And one that is not a byte order at all: **KEG's 512 bit branch has no
KDF.** `KEG_256` runs VKO-256 through the tree KDF to reach 64 bytes;
`KEG_512` returns VKO-512 unchanged, because it already is 64 bytes.
Running the KDF in both branches is the tidier-looking code and is
wrong.

`test_rfc_9189_magma_handshake` reproduces Appendix A.1.3.1's whole
exchange byte for byte, which settles all five at once, and
`tools/src/bin/diff_gost_kex.rs` covers the other curves and both suites with
a checker that asserts each wrong reading gives a *different* message.

One thing about that example worth writing down: **it includes the
`digestParamSet` that RFC 9215 section 4.2 says not to send.** That is
not an error in either document - RFC 9215 postdates it and deprecates
the field. It is written when this library chooses the curve
(`algorithm_id_for`, for a certificate or our own key), because a server
old enough to want these suites may be old enough to expect it, a server
following RFC 9215 must accept it regardless, and writing it is what
makes the RFC's example reproducible byte for byte. In a
ClientKeyExchange the question does not arise:
`encode_public_key_like` copies the server's AlgorithmIdentifier,
`digestParamSet` included or not (§7o).

### The GOST suites' Magma key length was wrong in the suite table

**Status: mitigated, and the check that would have caught it added.**
`BulkCipher::Magma` declared a 16 byte key. Magma takes 32: GOST R
34.12-2015 gives both its ciphers a 256 bit key and they differ only in
block size, and Magma had been grouped with the 128 bit ciphers because
its *block* is 8 bytes.

Nothing noticed for as long as the suite was unimplemented, because
nothing ever built the cipher from the length the table claimed. The
tests that existed checked that every implemented suite named an
algorithm this library has - true of Magma - and nothing compared the
declared length against what that algorithm accepts.
`test_the_declared_lengths_are_the_ciphers_own` now does, over the
**whole** table rather than the implemented part: a wrong length that is
only wrong while unused is still wrong, and becomes a handshake that
fails on its first record the day the suite is turned on.

The same test cannot compare block sizes across the board, and the
reason is worth writing down rather than leaving as a narrower
assertion: `BulkCipher::block_size` is meant as the *record layer's*
block, which is not the cipher's when a counter mode is in play -
`Gost28147Cnt` and the MGM suites say zero, because a counter makes the
cipher a stream one as far as the record layer is concerned. So the
test compares only where `is_cbc()` holds. The two CTR_OMAC entries,
`Magma` and `Kuznyechik`, are the exception: they report the cipher's
block, so `is_cbc()` is true for them and the comparison runs there
too. The record layer and the key block check `ctr_omac()` before
`is_cbc()`, so neither treats those suites as CBC.

### The GOST suites are a TLS 1.2 profile in a hello that offers 1.3

**Status: mitigated.** RFC 9189 profiles TLS 1.2, and this client offers
1.3 by default - so both live in the same ClientHello. The 1.3 path
*rewrites* `signature_algorithms` rather than adding to it, because a
1.3 server needs the PSS schemes and the 1.2 list has none. Rewriting it
dropped the GOST pairs (8,64) and (8,65), leaving a hello that offered
two GOST suites and declared it could not authenticate either.

What makes this worth a section is how it would have failed. RFC 9189
section 4.2.1 lets a server that does not find those pairs proceed *as
if they had been sent*, so a lenient server works and a strict one does
not, with nothing in the handshake to say which. The suites' own tests
would not have caught it either: this library's test server has no
reason to care what the extension says, which is why it now asserts the
pairs are present rather than ignoring an extension it does not use.

### CryptoPro key meshing is off by one step, twice

**Status: mitigated, by RFC 9189 Appendix A.2.1's second record.** The
CNT_IMIT suite re-keys every 1024 octets under RFC 4357 section 2.3.2:

```
K[i+1]   = decryptECB(K[i], C)
IV0[i+1] = encryptECB(K[i+1], IVn[i])
```

Four readings of that are plausible and only one is right. The two that
matter are both a single step out:

* **`IVn[i]` is the counter that produced the *last* gamma block, not
  the next one.** The RFC says "the value of the initialization vector
  after processing", and after processing a block that is the block's
  own counter — the next one has not been used for anything yet.
* **The meshed IV is stepped before it is used.** `IV0[i+1]` replaces
  the *stored* counter, which in this mode always sits one step behind
  the next gamma. Using it directly skips a step; running it through
  the start-of-stream path (which encrypts the IV once) encrypts it
  twice.

And a third thing, which is not a step at all: **the MAC re-keys without
touching its chaining state.** The cipher's IV is re-derived and the
MAC's is not — gost-engine's `cryptopro_key_meshing` takes the IV as an
argument and its MAC caller passes `NULL`, with a comment saying
CryptoPro does not treat a MAC's internal state as an IV for this
purpose. Nothing in RFC 4357 says so, because RFC 4357 does not
distinguish the two callers.

Every one of these produces a stream that is **right for the first 1024
octets and wrong afterwards**, which is why the RFC's second record is
2048 bytes. Sixteen variants were tried against it and exactly one
matched; the unit test carries that record, and its last four bytes are
the encrypted MAC, so the MAC's meshing is pinned by the same vector.

Meshing is also not ACPKM, despite doing the same job for the same
reason: the key step is a *decryption* of a different constant, the IV
is re-derived rather than carried across, and the boundary is fixed at
1024 octets rather than chosen per suite. An implementation that reached
for the ACPKM habit would carry the counter over the boundary.

### A HelloRetryRequest's transcript is not what crossed the wire

**Status: mitigated, and checked against OpenSSL.** RFC 8446 section
4.4.1 **replaces the first ClientHello with a hash of itself** when a
retry happens:

```
Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
    Hash(message_hash || 00 00 Hash.length || Hash(ClientHello1)
         || HelloRetryRequest || ... || Mn)
```

A transcript built by concatenating the messages that actually arrived —
which is what every other part of TLS does — is wrong here, and wrong in
a way that surfaces only at the Finished check, with nothing to say a
retry was the cause. The synthetic first message is a real handshake
message with type 254 and a three byte length, not a bare hash.

Three other things the retry path has to get right, each silent:

* **the second hello carries the same random.** A fresh one is a
  different handshake, and the server has already hashed the first.
* **the cookie goes back verbatim.** It is the server's own state,
  carried so the server can stay stateless across the retry;
  interpreting any of it makes the two halves disagree about a value
  only one of them understands.
* **the compatibility ChangeCipherSpec arrives before the version is
  known.** `negotiated_version` is set by a real ServerHello, and the
  server sends a ChangeCipherSpec between the retry and that — so the
  1.3 "accept and drop" rule has to key off having answered a retry as
  well. Without it the path failed with "a ChangeCipherSpec while
  waiting for the ServerHello", which is true and unhelpful.

The end-to-end check is `pytests/test_tls13.py`, which restricts
OpenSSL's server to P-384 while the client sends shares for
X25519MLKEM768, x25519 and P-256 — so OpenSSL sends a real
HelloRetryRequest. That is the only
thing that can catch a transcript both ends would have to agree on, and
the test asserts application data flows afterwards rather than that the
handshake merely finished.

Found on the way: **`named_group` returned `None` for every TLS 1.3
connection.** It read the ServerKeyExchange fields, and 1.3 has no
ServerKeyExchange. Nothing noticed because no test asked a 1.3
connection which group it had used.

### A KeyUpdate changes one direction, and a test can pass on the wrong branch

**Status: mitigated.** RFC 8446's KeyUpdate says the *sender* has
changed its own key, so receiving one steps the **reading** epoch and
nothing else. Stepping the writer too encrypts under a key the peer has
not derived, and the failure looks like a MAC error on a record we sent
rather than like a missing feature. `update_requested` additionally asks
us to change ours — and the reply goes out under the **old** key, since
the peer has not moved its reading epoch until it has seen it. RFC 8446
requires that reply to carry `update_not_requested`: two implementations
that both asked would update each other forever.

The part worth recording is how the old test passed. It asserted that a
KeyUpdate was refused, and it drove the message into a connection with
`Protection::Null` — so it exercised the "this is not a 1.3 connection"
branch and never reached the epoch logic at all. When the feature was
implemented the test kept passing, still testing nothing. The
replacement drives a real `Aead13` on both halves and asserts that
records *decrypt*, which is a claim the wrong branch cannot satisfy.

That is the same shape as the trust store's skipped count and the DH
primality row: **a test that asserts an error can be satisfied by the
wrong error.**

### The RFC's `K_EXP` is not the export key

**Status: mitigated, after producing a wrapping nobody could unwrap.**
Both of RFC 9189's worked handshakes label the VKO output `K_EXP`,
before the last derivation step. In Appendix A.1.3.1 that is obvious,
because the tree KDF's output is separately labelled "Export keys
K_Exp_MAC | K_Exp_ENC". In A.2.2 there is no second label at all — so
`K_EXP` reads like the key `KExp28147` is keyed with, and it is not:
CryptoPro's KEK diversification still has to be applied to it.

Using it directly gives a wrapping of exactly the right length, with a
valid MAC under the wrong key, which the other end rejects with nothing
to say why. It is caught here only because the same appendix prints the
resulting `PMSEXP`.

This also makes that appendix the only check `CPDivers` has anywhere:
RFC 4357 gives it no test vector, and it is perfectly deterministic
under every wrong reading of the word order, the bit order and the two
sums.

### The 16 round MAC transform and the 32 round cipher end in opposite states

**Status: mitigated, and worth recording because the two look like the
same loop.** GOST 28147-89's MAC uses a reduced transform of sixteen
rounds rather than the cipher's thirty-two. Written as a loop that swaps
the halves on every step, the sixteen round version ends having swapped
on its last step and the thirty-two round version does not — RFC 5830's
final round omits the swap. So the MAC writes its halves uncrossed and
the cipher writes them crossed, from loops that differ only in their
count.

Copying one line from the other gives a MAC, or a cipher, that is
entirely self-consistent. The Python reference in `diff_check.py` had
exactly that bug in both directions in turn, and each was caught by a
different RFC vector.

### A GOST key of eight equal words makes the cipher its own inverse

**Status: mitigated, and recorded because it is a trap for tests
rather than for code.** GOST 28147-89's key schedule is
`K K K reverse(K)`, which is a palindrome when every 32 bit word is the
same — so encryption and decryption run the same subkeys in the same
order and produce the same output.

That matters because `[0u8; 32]` and `[0x11u8; 32]` are the obvious test
keys, and any test that asserts two *directions* differ will pass under
them no matter which direction the code actually takes. It was found by
`test_the_key_step_is_one_way_and_deterministic` failing on `[0x11; 32]`
while the meshing was correct. `test_a_key_of_equal_words_is_its_own_inverse`
now pins the property, and the meshing tests use varied keys.

### A reference too slow to run is a reference that does not run

**Status: mitigated, and worth recording as a testing pitfall rather
than a cryptographic one.** `scripts/diff_check.py`'s Kuznyechik was
written in the shape of the standard: `L` as sixteen rounds of `R`, and
the key schedule recomputed per block. That is 1 KB/s. The CTR_OMAC
corpus wants 8 KB records, so the honest reference could not check the
thing it existed to check, and the pressure is then to shrink the corpus
until it fits — which is how a corpus ends up sweeping nothing.

The fix keeps the reading of the standard and drops only the repetition:
the LS table is **built from the spec-shaped functions at import time**,
not transcribed from anywhere, and `_kuz_selftest` and `_magma_selftest`
assert the fast path equals the slow one. A shortcut that is allowed to
drift is a second implementation, and then the corpus is comparing the
Rust against it instead of against the standard.

(Magma's table needed one correction that is easy to miss: the round
function substitutes all eight nibbles, and `S(0)` is not zero in any of
these rows, so a per-byte table built naively carries that constant four
times. It is removed from each entry and added once at the end.)

### Salsa20's quarter-round is not ChaCha's with different numbers

**Status: mitigated, and it is the clearest example in this document of
why round-trip tests prove nothing.** Bernstein writes
`quarterround(y0, y1, y2, y3)` and assigns to `y1` first. A natural Rust
signature takes the word it writes first as the first argument, so the
translation is `quarterround(w, x, y, z)` → `quarter(x, w, y, z)` - and
the first version here swapped the last two as well, in all eight call
sites of the double round.

That is a different permutation, applied consistently. Everything still
worked: encrypt-then-decrypt round-tripped, streaming in irregular
pieces equalled one call, seeking to block 2 landed on the third block,
a 128 bit key differed from a doubled one. Nine tests, all green, all
measuring the implementation against itself.

RFC 7914 section 8's published Salsa20/8 core vector caught it on the
first run. The lesson is a rule of this repository now: vectors come
out of the specification's text, never out of memory, and an
implementation compared only with itself is not compared with anything.

### HChaCha20 has no feed-forward

**Status: mitigated.** A ChaCha keystream block adds the input state back
after the rounds; HChaCha20 does not, and returns the first and last rows
of the permuted state. Built from a block function, the add is the
natural thing to keep, and the 32 bytes that come out are a function of
key and nonce that encrypts and decrypts consistently and matches no other
XChaCha20. The draft's section 2.2.1 prints the state before and after the
rounds and the subkey, and the unit test reads all three out of
`rfcs/draft-irtf-cfrg-xchacha-03.txt`. The 24-byte nonce's last eight bytes
go to ChaCha20 after four zero bytes, with the counter at 1 for the AEAD's
payload. `vectors/xchacha.vec` is Go's x/crypto at counters 0, 1 and
2^32 - 1.

### scrypt's BlockMix is the identity at r=1

**Status: mitigated.** `scryptBlockMix` emits its `2r` outputs
interleaved - the even numbered ones and then the odd numbered ones. At
`r = 1` there are two outputs and "evens then odds" is the identity, so
an implementation that concatenates is correct at `r = 1` and wrong
everywhere else.

RFC 7914's own BlockMix and ROMix test vectors both use `r = 1`. So does
its first scrypt vector. An implementation checked against those three
and nothing else passes while being wrong for every parameter set anyone
actually uses. `test_the_block_mix_output_is_interleaved` pins the
property directly at `r = 2`, and the differential corpus sweeps `r`
from 1 to 8.

The same shape, one layer down: `Integerify` reads the **last** 64 byte
block, little endian. Reading the first block, or reading big endian,
gives a different walk through `V` that is every bit as deterministic -
stable, reproducible, and matching nobody.

### Argon2's address counter is only used above 2 MiB

**Status: mitigated, and found by a breakage sweep rather than by a
test.** For Argon2i - and for Argon2id's first half-pass - the reference
indices come from blocks of 128 addresses generated by running `G` twice
over a counter. The counter increments per block of addresses.

Every test vector in RFC 9106 uses 32 KiB over 4 lanes, which is **two
blocks per segment**. One address block covers 128. So the counter is
generated exactly once per segment in all three published vectors, and
an implementation that *assigns* 1 instead of incrementing passes every
one of them. It first goes wrong at a segment longer than 128 blocks,
which is 2 MiB - the smallest parameter set anybody uses in production.

`test_the_address_counter_advances` now pins the counter itself rather
than inferring it from a tag. The general shape is worth keeping in
mind: **a published vector exercises the parameters it was written with,
and a parameter that is small in the vector is a parameter nothing
tests.**

### The BLAKE2 block boundary, and the key that is not prepended

**Status: mitigated.** Two independent traps in one algorithm, both
invisible to a self-consistency test.

A BLAKE2 block is compressed only once more input has arrived, because
the last block carries a finalisation flag and which block that is is
unknown until the input ends. An implementation that compresses as soon
as its buffer fills is wrong for inputs that are exact multiples of the
block size and right for every other length - and wrong *consistently*,
so one-shot and streamed still agree. RFC 7693's vectors are "abc" and
the empty string, neither of which is a multiple of 128.

A keyed BLAKE2 hashes the key **padded to one whole block**, and also
records the key length in the parameter block. Those are two separate
things, and a test that compares a keyed hash against the key simply
prepended rules out getting *both* wrong while passing when only the
padding is. The fix for each is the same: a pinned answer from a
reference implementation, at 128 bytes and with a key, recorded as
hashlib's rather than typed.

### Reference implementations expire, so implement while one exists

**Status: mitigated, and the reason this section exists at all.**

Every algorithm in this library is held to a differential comparison
against an independent implementation. That comparison is only possible
while somebody else still ships the algorithm - and for the old ones,
that window is closing. Measured in September 2026, against OpenSSL 3.0
and python-cryptography:

| | reference today |
|---|---|
| CAST5, IDEA, SEED, RC2, RC4, Blowfish, 3DES | `cryptography.hazmat.decrepit` — a module named after their expected fate |
| Camellia, SM4 | still in `cryptography.hazmat.primitives`, not yet moved |
| RIPEMD-160 | `hashlib`, through OpenSSL's default provider on this build; behind `legacy` on others |
| MD4, MD2, Whirlpool | **already gone** — unreachable from `hashlib`, and MD4 only through `openssl -provider legacy` |
| the PBES1 schemes | `openssl -provider legacy` only, and two of the OIDs refused by `cryptography` outright |

The first row is the warning and the fourth is what it becomes. GOST
was tested for a long time against only a second reading of its
standard, which is weaker evidence and considerably more work, until
gost-engine was brought in as a witness (§7b).

So the six added together - CAST5, IDEA, SEED, Camellia, SM4 and
RIPEMD-160 - were implemented **because a reference still exists for
each**, not because they were the most interesting. The corpora in
`scripts/diff_check.py` look each one up rather than importing it
directly, so the day it moves or vanishes the row disappears loudly
instead of failing to import.

The practical rule: when an algorithm is on the list and something
still implements it, that is the moment. The specification
will still be there in ten years; the second opinion will not.

### The traps in the six, each of which passes a round trip

Recorded together because they are the same shape - an implementation
that is wrong consistently is still self-consistent:

- **CAST5 has three different round functions**, by round number, each
  mixing add, subtract and XOR in a different order. The RFC numbers the
  types from one; indexing from zero shifts every round and is wrong
  from the first block. And a key of 80 bits or fewer uses **twelve**
  rounds rather than sixteen, so a short key is a different cipher and
  not a weaker one.

- **Camellia's `SBOX4` rotates its index**, where `SBOX2` and `SBOX3`
  rotate the output. Writing it as an output rotation like its siblings
  is wrong in a quarter of the byte positions. Its 192 bit key builds
  `KR` from the last 64 bits **followed by the complement of those same
  bits** - not zero padding. And `k9` comes from `KA <<< 45` while `k10`
  comes from `KL <<< 60`, breaking the pattern every other subkey pair
  follows; it reads like an RFC typo and is not.

- **Camellia's decryption reverses the `ke` list and nothing more.** The
  first version here also swapped the two halves of each pair, reasoning
  that `FL` and `FL^-1` change places. They do, and reversing the list
  is already what does it; doing both puts them back. **Encryption was
  unaffected**, so all three published vectors passed and only the round
  trip failed.

- **SEED's key schedule is not symmetric**: `Ki0 = G(Key0 + Key2 - KCi)`
  against `Ki1 = G(Key1 - Key3 + KCi)`. And the two key halves rotate in
  *opposite directions on alternate rounds* - right by 8 on odd rounds
  for the first pair, left by 8 on even rounds for the second. Rotating
  one pair every round still produces thirty-two distinct subkeys.

- **IDEA's multiplication is modulo 65537 with zero meaning 65536**, at
  both ends. `65536 * 65536` is 2^32, which **does not fit in a u32**:
  the first version here used one and wrapped to zero in release,
  silently, for the single input the whole convention exists to reach.
  Its own `mul(0, 0)` test caught it.

- **RIPEMD-160's two lines differ in four ways at once** - boolean
  function direction, round constants, message word order and rotation
  amounts - and its final combination **rotates the state words by one**
  rather than adding the two lines position by position.

### SHA-3 and Keccak differ by one byte, and nobody ships both

**Status: mitigated; both are implemented, and the distinction is
load-bearing.**

The Keccak sponge is identical in all three of its standard uses. What
differs is a single domain-separation byte appended to the message:
`0x01` for the 2012 Keccak submission, `0x06` for SHA-3 as FIPS 202
standardised it in 2015, `0x1f` for the SHAKEs.

Ethereum was built on the 2012 version and kept it. Every Ethereum
address, every transaction hash and Solidity's `keccak256()` are the
`0x01` padding - and every mainstream library ships only `0x06` under
the name "SHA-3". Feeding a SHA-3 library to an Ethereum address gives a
wrong answer with no error anywhere, which is one of the most commonly
reported bugs in that ecosystem.

`test_an_ethereum_function_selector` is the check worth noting: a
function selector is the first four bytes of `keccak256(signature)`, and
`transfer(address,uint256)` is `a9059cbb` - a number fixed by the ERC-20
standard, printed in every block explorer and compiled into millions of
deployed contracts. **Nothing in this repository could have influenced
it.** The Python reference in `scripts/diff_check.py` is pinned to the
same two selectors, so both sides of the differential check are anchored
to something external.

### A sponge's boundaries are at the rate, and nothing else reaches them

Two breaks survived the first sweep here, and both are the same shape:

- **The padding fits in one byte at `rate - 1`.** The domain byte and
  the closing `0x80` normally land on different bytes; at exactly one
  short of the rate they land on the same one and must be ORed. Writing
  `=` instead of `|=` is wrong for that one length, right for every
  other, and wrong *consistently* - so streamed and one-shot still
  agree. Only a pinned answer at exactly that length notices.

- **Squeezing past the rate needs another permutation.** Every SHA-3
  digest is shorter than its rate, so nothing but SHAKE reaches the
  second squeeze block - and a SHAKE checked only against prefixes of
  itself is wrong the same way at every length, so the prefix property
  holds while the bytes are wrong.

The general lesson, which is the same one Argon2's address counter
taught: **a parameter that is small in every published vector is a
parameter nothing tests.** Find the boundary, then pin an answer at it.

### The GOST MAC is never fewer than two blocks

**Status: mitigated.** GOST 28147-89's imitovstavka over a message of one
block or less was a block short, so every such tag was one no GOST peer
would accept.

GOST 28147-89 section 4.1 defines the MAC for a message of **two blocks
or more** and says nothing at all about a shorter one. That is not a
gap a closer reading closes — there is nothing there to read — so what
settles it is what the deployed implementation does. gost-engine's
`gost_imit_final` runs an extra all-zero block through whenever no full
block has been MACed yet:

```c
if (c->count == 0 && c->bytes_left) {
    unsigned char buffer[8];
    memset(buffer, 0, 8);
    gost_imit_update(ctx, buffer, 8);
}
```

which is the same rule stated the other way round: **zero pad to a
whole number of blocks, with a minimum of two.** Both our Rust and the
Python reference in `scripts/diff_check.py` now do that, and the second
one is the point — the corpus had 170 cases and agreed with itself at
every length, because both sides were the same reading.

**Why nothing here could have found it.** The MAC's only callers are
the CNT_IMIT record layer, whose input is a sequence number, a header
and a fragment and so is never shorter than thirteen bytes, and
`KExp28147`, whose input is a 32 byte key. No caller can reach one
block. Every test of it was ours at both ends. It took an
implementation outside this repository, which is the whole argument for
`vectors/gost_engine.vec`.

The block count has to survive CryptoPro meshing, which builds a fresh
`GostCrypto` — so `restore_buffered` takes it alongside the buffered
bytes. A fresh context has MACed nothing, and would have padded a
message 1024 octets long as though it were its first block.

### gost-engine's cipher names do not mean what they look like

**Status: mitigated, by measuring rather than reading.** Four sections
of `vectors/gost_engine.vec` cover GOST 28147-89, and a name-based
guess gets all four wrong:

| the engine's name | the mode | the parameter set |
|---|---|---|
| `gost89` | **CFB** | id-tc26-gost-28147-param-Z |
| `gost89-cbc` | CBC | id-tc26-gost-28147-param-Z |
| `gost89-cnt` | CNT (RFC 5830) | **CryptoPro-A** |
| `gost89-cnt-12` | CNT | id-tc26-gost-28147-param-Z |

So the bare name `gost89` is CFB under the *2012* table, while the
`-12` suffix distinguishes something only on the counter mode. There is
no route to GOST 28147-89 ECB through `openssl enc` at all.

A parameter set **is** the cipher, so a wrong guess is not a near miss
and the rows simply never match — which is how this was found, by
sweeping all nine parameter sets against all six modes and seeing which
pair landed. `tests/test_gost_engine_vectors.rs` carries the table with
that reasoning beside it.

Two other traps in the same tool, both silent:

- **`openssl enc` zero-extends a short `-iv`** rather than refusing it.
  Give four bytes to a cipher that wants eight and you get a perfectly
  good vector for a different IV. The engine's CTR modes take **half a
  block** — eight bytes for Kuznyechik, four for Magma — where their
  CBC takes a whole one, so this is a trap a sensible guess walks into.
  The generator asks `EVP_CIPHER_get_iv_length` instead of guessing,
  and `check_a_short_iv_would_have_been_accepted` fails if the
  zero-extension ever stops happening, so the work-around cannot
  quietly become unnecessary.
- **`openssl dgst -engine gost -md_gost12_256 -in FILE` produces
  nothing**, with no error. Redirecting the file to stdin works.

### `openssl dgst -mac kuznyechik-mac` is Magma, plus stack

**Status: mitigated; the vectors do not come from there.** On OpenSSL
3.0 with this engine, `dgst -mac kuznyechik-mac` and `dgst -mac
magma-mac` print **the same bytes** for the same input, and
`-macopt size:16` is refused at `gost_pmeth.c:852`, which is Magma's
ctrl where 8 is the maximum. The name resolves to Magma's method. The
printed value then carries eight bytes past the MAC that change on
every run:

```
kuznyechik-mac: f3daae40c3613e9e 81d5bf80957f0000
kuznyechik-mac: f3daae40c3613e9e 8145358a547f0000
```

A vector file built from that would have been half stack addresses and
half the wrong cipher, and **every row would have looked plausible** —
an eight byte MAC is a normal thing to see. So the MACs are taken
through `EVP_PKEY_new_mac_key` in `scripts/gost_engine_probe.c`, which
asserts before writing anything that Kuznyechik's MAC is sixteen bytes
and that the two ciphers disagree.

The engine argument to that call is a decoy: `EVP_PKEY_new_mac_key(nid,
gost, ...)` returns a key whose `EVP_PKEY_get_id` is `NID_undef`,
because the type comes from the **default** ASN1 method table and an
explicit engine does not consult it. `ENGINE_set_default` first, then
pass `NULL`.

`tests/test_gost_engine_vectors.rs` re-asserts the same two properties
against the committed file, so a regeneration that went back through
the command line fails rather than silently replacing Kuznyechik's
answers with Magma's.

### KExp15's wrapping direction is not in the engine's EVP surface

**Status: mitigated; see `scripts/gost_engine_probe.c`.**
gost-engine registers `magma-kexp15` and `kuznyechik-kexp15` as
ciphers, but the encrypting half of each is `#if 0`'d out in
`gost_keyexpimp.c` and falls through to `return -1`; only unwrapping
works. Driving them through `EVP_EncryptUpdate` returns **success with
zero bytes of output**, which is how the first version of the probe
wrote two empty rows and said nothing — the test then failed with
"disagrees on a 32 byte secret", which is a misleading way to be told
the reference was empty.

`gost_kexp15` is an exported symbol in `gost.so`, so the probe reaches
it with `dlsym` (after `dlopen(..., RTLD_NOLOAD)`, so it gets the
already-mapped copy rather than a second one with its own static
tables). That is a liberty — it is the engine's internal API — and it
is taken for one reason: **no document says which half of a 64 byte
KExp15 key is the MAC key.** R 1323565.1.017-2018 names `K_MAC` and
`K_ENC`; RFC 9189 passes them separately. Until these vectors, every
KExp15 test here had our code at both ends, so it would have agreed
with itself either way round.
The engine's own unwrap path settles it — `cctx->key` is the MAC key,
`cctx->key + 32` the cipher key — and ours already matched.

---

## 7c. SM3, and the SM family generally

Like GOST since gost-engine, **the SM family has a real reference.**
OpenSSL 3.0 ships SM3, SM4 and the SM2 curve, so `hashlib.new("sm3")`
and `openssl pkeyutl` are implementations this project did not write.
Every claim about SM3 is checked against one of them.

### SM3 is SHA-256 shaped and is not SHA-256

Same 32 byte output, same 64 byte block, same `0x80`-zeros-length
padding with the length big endian. Everything inside differs, and four
of the differences are silent when wrong — each has its own test and
each was confirmed by breaking it on purpose:

* **Two message words per round.** The expansion makes 68 words `W` and
  then 64 more `W'[j] = W[j] ^ W[j+4]`; one is used in each half of the
  round. Feeding `W` to both gives a perfectly good hash function that
  matches nothing.
* **The chaining value is XORed, not added.** SHA-2 adds.
* **`P_0` and `P_1` differ only in their rotation amounts** — 9 and 17
  against 15 and 23 — and sit four lines apart. Swapping them is the
  easiest mistake in the algorithm, and it is invisible to any
  round-trip or streaming test, so
  `test_the_two_permutations_are_not_interchangeable` compares them
  directly.
* **`FF` and `GG` change shape at round 16 and do not change to the same
  thing**: majority and choice respectively.

**Status: mitigated.** Twenty vectors from the standard's own text, a
303-row differential sweep against `hashlib` in `diff_check.py`, and
twelve deliberate breaks of which twelve were caught.

### Two findings about the tests, not the code

**A vector parser that matches the table of contents parses nothing.**
`DRAFT.find("Appendix B.  Example Results")` reached the contents
listing, which names every appendix in the same words indented by three
spaces. The result was an empty vector list, so `test_appendix_b_examples`
iterated over nothing and **passed**. Only the count assertion caught
it. This is the third distinct way a vector parser has silently found
nothing in this repository — after RFC 3394's four label spellings and
`rfc_oids.py`'s four OID shapes — and it is the reason that assertion is
not optional. Headings are now matched at the start of a line.

**A data line can be two hex digits long.** The GB/T 32918.2 A.3
examples are over a 257 bit binary field, so each element is 33 bytes
and the document writes the leading byte alone on a line: a bare ` 00`.
A minimum line length written to exclude page numbers dropped all eleven
of them, which silently changed the input to four examples without
changing their shape — they still parsed, still had the right number of
vectors, and still produced 32 byte comparisons. The count assertion
cannot see this one; only the vectors failing did.

### A no-op break reads exactly like a missed one

The SM3 sweep reported one miss, and it was not a miss: the patch string
did not match the source's indentation, so the file was never modified
and the tests passed because nothing was wrong. A breakage sweep must
check that the edit applied — `cmp -s` against the pristine copy — or it
will eventually report a clean miss for a break that never happened, and
that reads as "no test covers this line". Same family as the entry on
the two Diffie-Hellman families' leading zeros in section 7: **a
deliberate break that nothing catches means one of three things now**,
and the third is that there was no break.

---

## 7d. SM2

The reference is `openssl pkeyutl`, driven from `pytests/test_sm2.py`.
**python-cryptography refuses the curve outright** - "Curve
1.2.156.10197.1.301 is not supported" - so every other public key
algorithm here can be checked through a library and this one cannot.
Signatures and ciphertexts are exchanged with the binary in both
directions.

### `Z_A` is what makes SM2 unlike ECDSA

    Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)
    e   = SM3(Z_A || M)

* **`ENTL_A` is a bit count in two bytes, not a byte count.** A 16 byte
  identity writes `0x0080`. Getting it wrong gives a signature that
  verifies perfectly against itself.
* **The signature covers an identity.** Verifying under a different
  `ID_A` fails and is indistinguishable from a forgery.
* **The curve is inside the hash**, so `api::EcKey::sm2_sign` refuses
  any curve but sm2p256v1 by name. SM2 over P-256 is self-consistent
  and unverifiable by anyone.
* **`e` is not a digest of the message**, so an API taking a
  pre-computed digest cannot express SM2 at all. Everything takes the
  message.

**GB/T 32918.2 A.2's own `Z_A` and `e` are reproduced** in
`test_the_standards_own_z_value`, parsed out of the vendored SM3 draft's
appendix B - and over the example's *own* curve, which is not
sm2p256v1. The standard works two examples on two different curves, and
taking the parameters from the vector's own input rather than from
`curves::sm2()` is what makes that visible.

### OpenSSL's command line signs under an empty identity

Measured. `openssl pkeyutl -sign -rawin -digest sm3` with no
`-pkeyopt distid:` produces a signature that verifies only against an
empty `ID_A` and fails against GB/T 32918.2's default
`1234567812345678`. A library following the standard and a script using
the command line therefore disagree, and the symptom is
`Signature Verification Failure` - which reads as a wrong key.

This library follows the standard.
`test_the_openssl_default_identity_is_empty` asserts OpenSSL's
behaviour explicitly, so a future change there fails a test rather than
silently fixing or breaking interoperability.

### Encryption: three things that round-trip perfectly when wrong

* **The KDF counter starts at 1**, 32 bits big endian, and runs across
  blocks.
* **`C3 = SM3(x2 || M || y2)`** - the plaintext is in the *middle*. A
  check value over `x2 || y2 || M` agrees with itself and rejects every
  foreign ciphertext.
* **The ciphertext is `C1 || C3 || C2`** in the 2012 standard and
  `C1 || C2 || C3` in the 2010 draft, and deployed Chinese software
  still uses both. The DER form names its fields and is the one to
  exchange.

### OpenSSL encrypts under an all-zero key

GB/T 32918.4 has the encryptor draw a new `k` when the KDF output is all
zeros (6.1 step A5) - `C2` would be the plaintext - and the decryptor
refuse one (7.1). OpenSSL 3.0 checks neither, so for a one-byte message
one of its ciphertexts in 256 carries the message in the clear, and
ours refuses it with the standard's reason where OpenSSL decrypts it.
**Accepted**, as the standard has it: the refusal says why, and such a
ciphertext was never encrypted. It surfaced as a pytest failing one
full run in a few hundred; `test_we_decrypt_what_openssl_encrypts` now
requires either the message or that refusal, with the message visible
as `C2`.

### What the breakage sweep found

Twenty deliberate breaks; eighteen caught first time. The two misses and
one near-miss are the useful part.

**The `r, s` range check stops malleability, on one side only.**
Removing it left every test passing. `s + n` is the same scalar - `n*G`
is the identity - so every other step of verification agrees and a
second, different byte string verifies for a signature somebody else
made. `r + n` does *not* slip through, because `r` is compared against a
value already reduced mod n. Every case the tests offered until then
failed for that second reason, which is why the check looked covered.
`test_a_signature_with_n_added_to_s_is_refused` is the one that holds
it.

**Two branches cannot be reached on purpose, and are kept anyway.**
Removing the `t = 0` refusal, or the all-zero KDF check, leaves every
test passing - reaching either needs a chosen `e`, which is an SM3
preimage. They are defence in depth, in the same standing as
`ec::ct::Field::add`'s redundant P = -P arm. The all-zero one got the
treatment the constant-time comparison gets: the *decision* is now a
named function with its own test, because a decision can be tested where
an unreachable branch cannot.

**A test that rebuilds the computation does not test the function.**
`test_the_standards_own_z_value` checked `e` by hashing `Z_A` and the
message itself rather than calling `message_digest`, so reversing that
function's arguments failed no Rust test at all - only the OpenSSL
interop caught it. It calls the function now.

### Side channels: what the ctgrind harness found, and what is open

`scripts/ct_check.py` has `sm2_sign` and `sm2_decrypt` rows. Both were
added after the algorithm worked, and both found something immediately.

**Two variable-time multiplications on secrets, now closed.** SM2's
`k*G` and `d*G` were going through `Curve::scalar_mul`, which is
double-and-add:

* `k` is the nonce, and `s = (1 + d)^-1 (k - r d)` solves for `d` in one
  step given `k`. This is the same catastrophe as ECDSA's and the module
  was written without noticing that `ecdsa::sign` takes a different
  route on purpose.
* `d*G` is worse in a quiet way. `Z_A` needs the *public* key, so
  signing derives it - and the obvious `generator_mul(private)` runs a
  variable-time multiplication on the private key once per signature.
  This one surfaced only after the first was fixed, which is the usual
  shape: closing the loud leak leaves the quiet one, and only the
  harness says so.

Both now take `scalar_mul_secret`. `Curve::scalar_mul` no longer appears
in either row, which is the check that they are closed - not the report
count, for the reason section 2 gives at length.

**Status: open** for what remains. The signing equation is still
`BigUint` throughout: `(1 + d)^-1` is extended Euclid on the private
key, and `r*d` and the reductions mod n normalise. Closing it means the
`Secret`/`Montgomery` treatment `ecdsa::sign` already has. The two rows
are listed as expected-to-leak positive controls rather than with a name
set, because a name set that had to hold `alloc`, `index` and `eq` to
pass would go green for any new leak that allocated - the table's rule
is named leaks or none, and this is none, said out loud.

`sm2_decrypt` has a second one worth naming: `d*C1` runs on the ladder,
but its coordinates leave as `BigUint` to be hashed, which normalises
them - and they are secret, since the KDF over them is the keystream.
`Curve::ecdh` has the same shape and no row here at all.

---

## 7e. EdDSA in certificates and in TLS

RFC 8410 and RFC 8446 codepoint 0x0807. Checked against OpenSSL and
python-cryptography in both directions, which is the only way: the two
ends of each of these is the other's obvious mistake.

### Four encodings that a neighbouring branch gets wrong

* **The BIT STRING is the key.** Every other key in this library wraps
  something — RSA a SEQUENCE, EC a SEC1 point with a format byte, GOST
  an OCTET STRING of little endian coordinates. RFC 8410 section 4 says
  the subjectPublicKey *is* the 32 bytes, and a parser written from its
  neighbours looks for a structure that is not there.
* **The parameters field must be absent, not NULL.** The RSA branch
  writes an explicit NULL and an encoder copied from it writes one here.
  **Both forms parse in most software**, so no round trip and no
  verification anywhere would notice — only a strict verifier, on
  somebody else's machine, months later. Exactly the shape of the
  UTCTime/GeneralizedTime bug in section 6, which only handing a
  certificate to somebody else found. Refused on the way in and omitted
  on the way out, with a test that reads the bytes.
* **One OID is both the key algorithm and the signature algorithm.**
  There is no `ed25519WithSHA512` arc, because the hash is not a
  parameter of the scheme. `SignatureAlgorithm::Eddsa` therefore carries
  no hash name and `hash_name()` returns `None` — so every path that
  computes a digest before dispatching has to branch *before* it does.
  There are three such paths (certificate verification, the client's
  CertificateVerify, the server's), and each has its own early branch.
* **The signature is 64 raw bytes**, not the DER `SEQUENCE { r, s }` an
  ECDSA certificate carries in the same field, and not GOST's
  fixed-width `s || r`. Three encodings of one idea sit next to each
  other in `verify.rs`.

### The private key is wrapped twice

RFC 8410 section 7 defines `CurvePrivateKey ::= OCTET STRING`, and
PKCS#8 then puts *that* inside the privateKey OCTET STRING. A parser
that unwraps once gets 34 bytes beginning `04 20` — the right length for
nothing, and the wrong key for everything. The seed is also **not a
scalar**: EdDSA's signing scalar is the hash of these bytes, clamped, so
storing it clamped or reduced mod the group order changes which key it
is.

And an RFC 8410 key has **no "traditional" form** at all: PKCS#8 is the
only serialisation defined. `cryptography` raises "format is invalid
with this key" for `TraditionalOpenSSL`, which is what caught this in
the test harness.

### The findings from the sweep

Nine deliberate breaks. Six caught first time; the other three are the
interesting ones.

**A duplicated check is not defence in depth if it duplicates the
message too.** `verify_eddsa` checked the signature length and so does
`api::eddsa_verify`, one layer down, **with the same wording**. Removing
the outer one failed no test even after a test was written to pin the
message — because the identical message came back from the inner check.
That is not two checks, it is one check and one place for it to drift
from, so the outer one is gone. Compare `require_128_bit` in `xts.rs`
and `keywrap.rs`, where the two checks produce *different* messages and
pinning the message is what holds them apart.

**A check that another check covers is invisible, again.** The public
key's length check in the parser is covered by `eddsa_verify` further
down, so removing it left every test passing — but here the messages
*do* differ, and which one fires is what tells a reader whether the
certificate or the signature is malformed. Pinned by
`test_a_wrong_length_ed25519_key_says_so_at_the_parser`.

**Every early return out of a state handler must carry the state
transition with it.** The client's CertificateVerify handler sets
`state = WaitServerFinished13` after its match; the EdDSA branch returns
before reaching it, and the handshake then failed with *"Received
finished while waiting for the server's CertificateVerify"* — a message
about the next message, which reads as the peer having sent the wrong
thing. Found by the first real handshake, not by any unit test, because
no unit test drives the state machine across two messages.

### EdDSA at TLS 1.2, and a premise that was wrong

This section once said RFC 8422 defines no TLS 1.2 suite
authenticated by EdDSA, and that nothing issues Ed448 certificates, so
`ed448` was not offered. Both claims were wrong. RFC 8422 section 2
describes ECDHE_ECDSA as "Ephemeral ECDH with ECDSA or EdDSA
signatures", section 5.1.3 assigns (8, 7) and (8, 8), and OpenSSL
issues and serves Ed448 certificates.

The wrong premise caused a real bug. The client put `ed25519` in every
hello, which included every 1.2 hello. A 1.2 OpenSSL server with an
Ed25519 certificate took the offer, and our client refused its
ServerKeyExchange with "The server signed with ed25519, which is not
implemented". The 1.2 path looked up `hash_name()` before it checked
for EdDSA, which is the same early-branch rule as above in a fourth
place. Two of our own ends could not show the bug, because our server
refused 1.2 for an EdDSA key. A probe against OpenSSL showed it at once.

At 1.2 the three EdDSA signatures cover these messages, each with no
digest taken first:

* the ServerKeyExchange covers `client_random || server_random ||
  params`;
* the client's CertificateVerify covers the raw handshake concatenation
  (section 5.10);
* the 1.3 CertificateVerify covers the context string and transcript
  hash, as before.

A client with an EdDSA certificate answers a request for `ecdsa_sign`
(section 3). The 1.2 hello has its own `signature_algorithms` list, apart
from the 1.3 one. Adding EdDSA to the 1.3 list alone leaves a 1.2-only
client unable to reach an EdDSA server, so
`test_a_tls12_only_hello_offers_eddsa` pins the 1.2 list.

### A module-level `NOW` is not the current time

`pytests/test_ed25519_certificates.py` computed `NOW = int(time.time())`
at import and checked certificates `openssl req` had dated from *now*.
The whole suite takes the better part of a minute, so by the time the
file ran, `NOW` was seconds before the certificate's own `notBefore`:
the test passed on its own and failed in the suite, which is the worst
shape a test comes in. It is a function now.

---

## 7f. Twofish and Serpent

Two AES finalists, and **neither OpenSSL nor python-cryptography
implements either**. So the reference is Botan's vector files, vendored
in `vectors/`, which carry the designers' own numbers rather than
Botan's. That is a weaker position than GOST's or SM2's, both of which
have a live implementation to exchange with.

Fourteen deliberate breaks, all fourteen caught.

### Twofish: three fields, and only one of them is AES's

* the **MDS matrix** multiplies in GF(2^8) mod `0x169`;
* the **Reed-Solomon** key schedule multiplies in GF(2^8) mod `0x14D`;
* AES's `0x11B` is neither.

Using one polynomial for both gives a cipher that encrypts, round-trips,
avalanches and matches nothing. `test_the_two_fields_are_different`
pins them apart on actual products, not just as numbers.

### Twofish: decryption is not encryption with the rotations reversed

This is the subtle one. The encryption round computes `g` over
`R0` and `R1` and writes `R2`, `R3`. Run backwards, **the round's inputs
`R0`, `R1` are the state's `R2`, `R3`** - so the inverse applies `g` to
those. A shared body with `if encrypt` around only the rotations looks
right, passes every encryption vector, and decrypts to noise. The two
are separate functions now, and the comment says why they cannot share.

The same shape appeared in Serpent's S-boxes, where it was avoided
rather than made: the inverse tables are stated, and
`test_the_inverse_boxes_invert` composes each with its forward box over
all sixteen inputs. Two tables that do not compose to the identity give
exactly the same failure.

### Twofish: the key words are XORed *between* the lookups

`h` is `q1[q0[q0[y] ^ l1] ^ l0]`, not `q1[q0[q0[y]]] ^ l1 ^ l0`. Written
the second way it compiles, permutes and round-trips.

And the S words come out of the Reed-Solomon code **in reverse order** -
the first eight key bytes give the *last* S word. Invisible to anything
but a vector.

### Serpent: a short key is padded with a 1 bit, not with zeros

So a 128 bit all-zero key is **not** the same as a 256 bit all-zero key.
An implementation that zero-pads agrees with itself perfectly and with
nothing else, and only vectors at more than one key size catch it -
which is why `test_every_vector` asserts it saw all three sizes rather
than trusting the file to contain them.

### Serpent: there are thirty-three subkeys

Rounds 0 to 30 are `S_i(X ^ K_i)` then the linear transform. Round 31
applies `S7` and then **XORs `K32` instead of** the linear transform. An
implementation with 32 subkeys and a linear transform on the end is a
different cipher and nothing about it looks wrong.

The key schedule's own S-box index also runs **backwards**: round `i`'s
subkey uses `S[(3 - i) mod 8]`, which is not the box that round uses on
the data.

### Serpent: it is the bitslice form, and the vectors are too

Serpent is specified twice - a standard form applying a 4-bit S-box to
each nibble, and a bitslice form applying it across one bit of each of
four words. They differ by an initial and final permutation. Every
implementation and every published vector uses the bitslice form; there
is no IP/FP in this file and there should not be.

### A vector file is a document, and gets the same parser discipline

`block_ciphers::vector_file` is one parser for all of these rather than
one per cipher, and **every caller asserts the count it expects**. Three
copies would be three chances to write the one that silently finds
nothing - which has now happened in three different documents in this
repository. `vectors/README.md` says to raise the count in the same
commit as a refetch, because a count that drifts quietly is the thing
the assertion exists to prevent.

---

## 7g. PCBC and EAX

### PCBC does not do what it was chosen for

Kerberos 4 used propagating CBC so that an altered message would
decrypt to garbage from the alteration onwards - a poor man's integrity
check. **Swapping two adjacent ciphertext blocks leaves everything after
them intact**, because the two `P ^ C` terms cancel, so the propagation
does not detect a reordering. That is why Kerberos 5 dropped it.

`test_swapping_two_blocks_is_not_detected` asserts the weakness rather
than only describing it, because a mode whose failure lives in a comment
is a mode somebody will reach for on the strength of its name.

The first block is identical to CBC's, so a test using one block passes
for either mode - `test_it_differs_from_cbc_from_the_second_block_on`
is what separates them.

### EAX: four silent ways to get it wrong

    N = OMAC(0, nonce);  H = OMAC(1, header);  T = OMAC(2, ciphertext)
    tag = N ^ H ^ T

* **The three tweaks must differ.** One index for all three makes `N`,
  `H` and `T` interchangeable and lets a forger move bytes between the
  nonce and the header.
* **The index is a whole block**, big endian, not a single byte. Both
  encodings produce a tag; only one interoperates.
* **The CTR nonce is `N`, not the nonce.**
* **The MAC covers the ciphertext**, not the plaintext. Authenticating
  the plaintext is encrypt-and-MAC and round-trips against itself
  perfectly.

Eleven deliberate breaks across both modes, all eleven caught.

### The tag is the block size, and that had a bug behind it

EAX's tag is one block, so EAX over a 64 bit cipher - DES, 3DES,
Blowfish - has an **8 byte tag**. Adding it exposed a bug that had been
sitting in the Python bindings:

`Aead.decrypt` split `ciphertext || tag` sixteen bytes from the end, and
`tag_size` was `if name ends with "-8" { 8 } else { 16 }`. Both were
true of the catalogue as it stood when they were written, and both were
already wrong: **`aes-ccm-8` had never round-tripped through the
one-shot Python interface**, and its whole reason for existing is the
shorter tag.

What makes it worth recording is the error. Not "wrong length" but *"the
tag does not match, so this ciphertext was not produced by whoever holds
the key - or was modified after it was"*. A caller reading that would
conclude their data had been tampered with, and would be wrong. **A
length bug that reports itself as an authentication failure is worse
than one that crashes.** The length is asked of the AEAD now, in one
place.

### A placeholder chosen from "things we have not implemented" expires

Three tests used an unimplemented AEAD as their stand-in for "not an
AEAD we have":

1. one named `aes-ccm`, and stopped testing anything the day CCM landed;
2. its replacement named `aes-eax`, and stopped the day EAX landed -
   **with the comment above it already warning about the first**;
3. a documentation example asserted `aeads_available` by equality and
   broke the same day.

The general form: *a test whose subject is the absence of something is a
test with an expiry date.* The fix is a name that cannot become valid -
`not-an-aead`, `nonesuch-eax` - and membership rather than equality in
the docs. The same reasoning as the generated name enums: anything
written down twice will disagree, so write it once or derive it.

---

## 7h. Buffers at the Python boundary

Every byte-taking argument in `src/python.rs` now accepts any contiguous
buffer of single bytes rather than only `bytes`. Four things came out of
doing it.

### Borrowing a `bytearray` across `allow_threads` is undefined behaviour

**Status: mitigated.** Almost every function in `python.rs` calls
`py.allow_threads` so that hashing and bulk encryption scale across
threads. A Rust slice borrowed from a `bytearray` and held across that
call is a pointer into a buffer another Python thread may resize, and a
resize reallocates. That is why `PyByteArray::as_bytes` is an `unsafe`
function in pyo3, and it is the whole reason the `Bytes` extractor
copies a mutable source instead of borrowing it.

The copy is made while the GIL is still held, so it is atomic with
respect to anything Python can do: a caller racing a resize against a
hash gets the digest of one state or the other, never of memory that
moved. `test_a_bytearray_may_be_resized_while_it_is_being_hashed` runs
that race for real, because **undefined behaviour has no assertion** -
the only available test is one that would crash or produce a third
answer under a borrowing implementation.

`Encryptor::update_into` is the mirror image and the only place a
`bytearray` specifically is taken: it writes in place and therefore must
*not* release the GIL. Borrowing a `bytearray` and releasing the GIL are
the two things that cannot both happen, and every function does exactly
one of them.

Note that the `PyBackedBytes` fast path is an *optimisation* - a
`bytearray` reaching the buffer fallback is copied there too, so
deleting the branch changes no answer and no sweep can see it. What is
load bearing is that nothing mutable is ever borrowed, and that holds on
both paths.

### `PyBuffer::to_vec` gathers, and a comment said it did not

**Status: mitigated.** The first version of the extractor read:

```text
// `PyBuffer::to_vec` refuses a non-contiguous or wrong-itemsize
// buffer rather than reading it wrongly, which is what makes this
// safe to offer at all.
```

It does not. `to_vec` calls `PyBuffer_ToContiguous`, whose entire job is
to walk the strides and write the elements out packed. So
`memoryview(bytearray(b"abcdef"))[::2]` - a view of `b"ace"` spread over
six bytes - was accepted and hashed as three bytes that appear nowhere
in the caller's memory, silently.

This is the exact failure shape recorded for `decrypt_premaster` further
up this file: **a comment claiming a check the code does not do is worse
than no check**, because it stops the next reader looking. Third time in
this repository. `is_c_contiguous()` is now tested explicitly, before the
copy, and the test that covers it asserts the refusal *and* that the
gathered answer is not what comes back.

A *contiguous* multidimensional buffer is accepted and read in memory
order, which is exactly what `bytes(x)` gives for it - no gather, so
nothing is decided on the caller's behalf. `hashlib` does the same.

### A `Vec<u8>` parameter is the same bug in a place nobody looked

**Status: mitigated.** Converting `&[u8]` parameters to the new extractor
left a second family untouched: pyo3 extracts `Vec<u8>` from any
sequence of integers, so `ocsp_responders`, `crl_status`, `verify_chain`
and a dozen others accepted `[1, 2, 3]` as a certificate *and* silently
flattened a strided memoryview, with a different error message from
everything else.

Every test of the new extractor passed, because none of those parameters
reached it. The property "no byte parameter escaped the extractor" is a
claim about the source and is tested by reading the source -
`test_no_byte_parameter_escaped_the_extractor`, with a named allow-list
for the internal helpers and a companion test that fails if an
allow-list entry stops matching anything.

### Where being stricter than `hashlib` is right, and where it is not

**Status: mitigated, both ways.**

`hashlib` accepts `array("I")` and hashes the machine's own bytes for
it. We refuse it with a `TypeError`. The reason is what the bytes are
*for*: a hash of arbitrary memory can afford a byte-order-dependent
answer, and a key, a nonce or a scalar cannot - the code works until
somebody moves it to a machine of the other endianness. This is one of
the few places the library is deliberately stricter than the world; the
remedy is one method call, `x.tobytes()`, which says which bytes were
meant.

In the other direction, the exception *types* follow CPython exactly: a
wrong type is a `TypeError` and a non-contiguous buffer is a
`BufferError` with CPython's own first clause, because that is what a
caller porting from `hashlib` already handles and what they will search
for. `CryptoError` stays a `ValueError` and means a bad key length, an
unknown algorithm name or a failed authentication - a wrong *type* in
that basket would be a category error.
`test_the_refusals_match_the_standard_library` compares the two at run
time rather than transcribing CPython's answers, so a CPython that
changed its mind would say so here.

The one difference that is neither: `data=None` on a hash constructor is
how pyo3 spells an omitted optional argument, where `hashlib` writes
`string=b""` and raises for an explicit `None`. Harmless where it
applies, since no-data and empty-data are the same digest - and where
the argument is *required*, `None` is a `TypeError` exactly as in
`hashlib`, which is the case that matters. A forgotten key must not
arrive as a key of zero length.

---

## 7i. MD2 and MD4

Both are broken past any argument - MD4 collides by hand in under a
minute, MD2 has a 2^73 preimage - and both are here because something
that is not ours to upgrade still speaks them: `md2WithRSAEncryption` on
old root certificates, and MD4 inside the NT hash, so NTLM, NTLMv2, CHAP
and MS-CHAPv2. **Neither is offered for anything new**, and nothing in
this library selects either by default.

### RFC 1319's prose and RFC 1319's own code are different algorithms

**Status: mitigated, and pinned by a test.** Section 3.2 writes the
checksum step as

```text
Set C[j] to S[c xor L].
```

and the reference implementation in the same document's appendix writes

```text
t = checksum[i] ^= PI_SUBST[block[i] ^ t];
```

which is `C[j] ^= S[c xor L]`. The document's own test vectors follow
the **code**, as does every implementation in the world; RFC 6149
records the discrepancy.

The two agree on a single block, because the checksum starts at zero and
`0 ^ x == x`. So a test written with one block passes under either
reading, and a reader who implements the prose gets a self-consistent
MD2 that matches no certificate ever signed.
`test_the_two_readings_of_the_checksum_disagree` writes out both, asserts
they agree at one block and differ at two, and asserts which one this
file implements. `md2::CHECKSUM_DISAGREEMENT` is the greppable name.

### A constant table split across a page break

**Status: mitigated.** RFC 1319's 256-byte π permutation runs across a
page boundary, with a running header and a `[Page 7]` footer sitting
between two of its rows. RFC 1320's round-2 table does the same.

Both are parsed out of the vendored documents at **compile time** rather
than pasted, which is this repository's rule for constant tables - and it
pays twice over, because a transcription would have had to notice and
drop the furniture by hand. The filters are written on what data *is*
rather than on what furniture looks like: a π row is digits, commas and
spaces and nothing else; an MD4 round group is four capitals followed by
two numbers, which `[Page 4]` is not. Listing the furniture instead
would mean a form not listed becomes silent data. RFC 3394 is the
cautionary tale: it writes one vector label four different ways, and
each spelling a parser does not know silently costs vectors.

The parsers assert their counts and panic at compile time, and a
breakage sweep confirmed it: dropping a row and widening the filter to
accept furniture both **failed to compile** rather than producing a
plausible table. `test_the_table_is_a_permutation_of_every_byte` is the
second net, because a parser that lost one row and gained a page number
would still produce 256 entries.

### MD4's round 3 is the most mistyped table in the family

**Status: mitigated.** `0 8 4 12, 2 10 6 14, 1 9 5 13, 3 11 7 15`. A
wrong entry gives a hash that streams correctly, agrees with itself, and
matches nothing. Since the schedules are read out of RFC 1320 there is
nothing to mistype - but the tests still assert the properties a
mis-*parse* would break: each round uses every message word exactly
once, the three rounds use three different orders, and the rotations
repeat in fours. Pointing the parser at round 1 three times is caught by
the second of those.

`scripts/diff_check.py`'s MD4 is **typed by hand from the document on
purpose**, so the corpus compares two independent readings, and it is
pinned to OpenSSL's legacy provider at import so a typo there says so
immediately instead of making every row disagree.

### MD2's block size is 16, and the catalogue assumed 64

**Status: mitigated.** `tests/test_api.rs` asserted
`block_size() >= 64` for every hash, with a comment explaining that a
sponge reports its rate. MD2's compression function takes sixteen bytes,
so it failed - correctly.

The number that assertion was standing in for is HMAC's: **`B >= L`**, a
key longer than the block is replaced by its own digest and that digest
has to fit in a block. MD2 is the one algorithm here where the two are
*equal* rather than `B` being larger, which is legal and has to actually
run. The test now asserts `block_size() >= digest_len()`, which says why
it is there; `assert!(>= 64)` said only that nothing small had been
added yet. Third time this document has recorded that a magic number
outlived the property it stood for.

### MD2 has no independent implementation to compare against

**Status: accepted, and said out loud.** `hashlib` has neither MD2 nor
MD4; OpenSSL 3 keeps MD4 behind the `legacy` provider and dropped MD2
entirely. So MD4 gets a real second opinion and MD2 gets what the GOST
hashes get - a second reading of the specification, written in
`scripts/diff_check.py`.

Two things keep that honest. The Python MD2 reads RFC 1319's π table
with a **different parser** over the same document, rather than a third
transcription of 256 numbers with nothing to check it against. And the
run prints which reference MD4 is being checked against, because a check
that quietly downgrades itself is a hole that looks like a pass.

### The buffering bug, for the third time

**Status: mitigated, and made unrepeatable.** MD2's first `update` fell
through to its tail on a call that did not fill a block, so
`update(b"a")` followed by `update(b"")` discarded the `a`. **Every
published vector still passed**, because each of them is a single call
- the same shape as two earlier bugs in this library: SHA-1 reserving a
16 byte length field, so every message of 48 to 55 bytes mod 64 hashed
wrong, and ChaCha reading its keystream at the wrong offset from the
third `crypt()` call on one object. Both passed every published vector.

The logic now lives once, in `hash_functions::buffer::BlockBuffer`, with
both ways of getting it wrong named in the code: a partial block must
return without touching the length again, and the tail must not
compress. Removing either fails eight and twelve tests respectively.

---

## 7j. TEA, XTEA, and the table that hid a panic

### TEA's equivalent keys are a break, not a curiosity

**Status: accepted, and asserted.** Flipping the top bit of `k[0]` and
of `k[1]` together gives a key that encrypts identically, and the same
holds for `k[2]` and `k[3]`. So every TEA key has three others
equivalent to it and the effective key length is 126 bits.

Where TEA is used to *build a hash* that is a practical break: collisions
come for free, which is what broke the original Xbox, whose boot ROM
hashed with a TEA-based construction. XTEA changes the key schedule to
remove it and does **not** fix the related-key attacks, so neither is a
cipher to choose. Both are here because firmware that uses them is not
ours to upgrade.

`test_teas_equivalent_keys` asserts the property rather than describing
it, including that there are exactly three - flipping one word alone
must change the ciphertext, or the test would pass for a cipher that
ignored the top bits entirely. `test_xtea_has_no_such_equivalent_keys`
is the other half.

### Two silent ways to write them wrong

**The word order is big endian.** The papers work on `v[0]` and `v[1]`
as numbers and say nothing about bytes. Reading the block little endian
gives a cipher that encrypts, decrypts and round-trips perfectly and
agrees with nobody. Only somebody else's vector notices.

**`sum` steps before the first half-round in TEA and after it in XTEA.**
One line apart in the reference code, and both give a working Feistel
cipher. TEA's decryption therefore starts at `delta * rounds` and
subtracts *after* each pair; XTEA's subtracts *between* them. Both
orders were swept and both are caught, by vectors and by nothing else.

XTEA's two key-word selectors are the third: the low two bits of `sum`
before the step and bits 11-12 after it. Using the same slice twice is
exactly TEA's weakness reintroduced, and it round-trips.

### A "which cipher takes which key length" table hid a panic for years

**Status: mitigated, and the table is gone.** `tests/test_api.rs` and
`pytests/test_allcrypt.py` both carried a map from cipher name to a key
length that cipher accepts, so that the catalogue loop could construct
every entry. It was wrong three times - when DES arrived, when IDEA,
SEED, SM4 and CAST5 did, and when TEA and XTEA did - which is the
ordinary cost of a second copy of the catalogue.

The expensive cost was different. GOST's entry in that table was
**correct**, so the loop always handed `GostCrypto::new` the one length
that works - and `GostCrypto::new` read eight little-endian words out of
the key with no length check at all, so every other length indexed past
the end and **panicked**. A panic is not an error: it unwinds through a
function whose signature is `Result`, and through pyo3 it arrives as
`PanicException`, which does not inherit from `ValueError` - so a caller
catching `allcrypt.CryptoError` around a user-supplied key length got an
uncatchable failure instead of a message.

Both loops now try every length and require one to succeed, which is
what found it, and `tests/test_api.rs` additionally asserts under
`catch_unwind` that **no** cipher panics on **any** length. The general
form, for the fourth time in this document: *a table beside the
catalogue is a second copy of the catalogue, and the entry that is right
is as dangerous as the entry that is wrong - because it stops the test
ever asking the question.*

### XXTEA is absent on purpose

"Corrected Block TEA" is not a 64-bit block cipher. It operates on a
whole message of two or more words at once, so it has no place in
`BlockCipher`: it would inherit five chaining modes it cannot use, and
`blocksize()` would have to lie. If it is ever wanted it belongs in a
module of its own, the way `xts.rs` and `keywrap.rs` are.

### EAX over a 64-bit block has an 8-byte tag

**Status: accepted.** `tea-eax` and `xtea-eax` came for free with the
generic EAX, and their tags are eight bytes, not sixteen - EAX's tag is
one CMAC output and a CMAC output is one block. That halves the forgery
resistance relative to the AES suites. It is a property of the cipher
rather than a choice, which is why `aead_tag_len` asks the cipher rather
than carrying a list; see section 7g, where the same fact cost a bug.

---

## 7k. RC5

### Zero rounds is a legal cipher here and the identity next door

**Status: mitigated, and asserted side by side.** RFC 2040 publishes test
vectors for `R = 0`, and they are not the plaintext: the two halves are
summed with `S[0]` and `S[1]` before the round loop starts, so zero
rounds is a key-dependent transformation rather than nothing. TEA, in
the neighbouring file, has no such pre-whitening, so zero rounds there
*is* the identity and the constructor refuses it.

Two ciphers with the same shape and the opposite answer to the same
question is exactly the sort of thing a reader generalises wrongly, so
each file states its own reason and
`test_rc5_zero_rounds_is_allowed_where_teas_is_not` asserts both in one
place. A cipher that silently returns its input is the worst failure
this library can have; a cipher that refuses a parameter its own RFC
publishes vectors for is the second worst.

### An empty key divides by zero in the RFC's own code

**Status: mitigated, by refusing rather than patching.** RFC 2040 5.3 computes
`LL = (b + 3) / 4` and the mixing loop does `j % LL`. For `b = 0` that
is a division by zero. Rivest's paper patches around it by taking
`c = max(1, ...)`; the RFC does not, and the RFC is what
implementations followed.

So there is no interoperable answer to agree with, and an empty RC5 key
is refused with a message that says why. Guessing one of the two
behaviours would produce ciphertext nobody else can reproduce, which is
worse than an error.

### The rotation amount is data dependent, so it cannot be constant time

**Status: accepted.** `A <<< B` rotates by the low five bits of
the *other* half. That is where RC5's strength comes from with so little
code, and it means the rotation distance is a secret-dependent quantity
reaching the shifter. No attempt is made to hide it, and RC5 is not on
`scripts/ct_check.py`'s list.

This is not a defect in the implementation but a property of the cipher,
and it is the reason RC5 should not be used to process secrets on a
machine an attacker can measure. It is here to read old data.

### Only the 32 bit word size

**Status: accepted.** RC5 is RC5-w/r/b, and Rivest's paper allows
`w` in {16, 32, 64}. RFC 2040 profiles only 32, and no published vectors
exist for the other two. An unverified variant is worse than an absent
one - so `w` is fixed and the block size with it. Adding 16 or 64 later
is a new type rather than a parameter, because the block size changes.

### A field name that is also a letter inside a word

**Status: mitigated, during development.** RFC 2040's vectors are written
`RC5_CBC_Pad R = 8 Key = ... IV = ... P = ... C = ...`, and the first
parser looked for the field `P` as a substring - which found the `P` in
`Pad` and read `ad` as the plaintext. Every padded row silently became
nonsense while the plain rows passed.

The fix is to require the `=`: a field is a name followed by optional
spaces and an equals sign, which `Pad` is not. Same family as RFC 3394's
four spellings of one label and RFC 1319's page furniture - **a parser
that matches on a fragment will find the fragment somewhere it did not
mean**, and only the count assertion or a wrong answer says so. Here it
was a wrong answer, because the count was right.

---

## 7l. ARIA

ARIA is not broken and is not going away - it is a current national
standard with TLS suites in RFC 6209. It is in this library for the
other reason: it is absent from most Western software, and a client that
cannot speak it cannot reach the systems that do.

### One entry in RFC 5794 is printed with a single digit

**Status: mitigated.** SB4's first row reads `... 72  9 62 3c`. Every
other entry in all four tables is two characters; this one is not. A
parser requiring two hex digits per entry finds fifteen values in that
row instead of sixteen, and then either drops the row or shifts the
table by one.

Same trap as RFC 1319's page furniture and RFC 3394's four spellings
of one label, and the third document in this repository to have it.
The rule that keeps working: **count what you found, per row, and
compare it with what the document promises.** The S-box parser keeps
only rows of seventeen tokens and asserts each row's own index at
compile time, so a row that comes up short is a compile error rather
than a shifted table.

### Four properties the document states about its own tables

**Status: mitigated; all four are tests.** RFC 5794 says SB3 and SB4 are the
inverses of SB1 and SB2, that the diffusion layer is an involution, and
- in prose, about tables printed elsewhere - that `SB1(0x23) = 0x26` and
`SB4(0xef) = 0xd3`.

Those are 1024 table bytes and 112 diffusion indices checked by
properties that no parser could arrange by accident. A single transposed
hex digit anywhere breaks the inverse property; a single wrong index
breaks the involution. They are worth more than any number of round-trip
tests, which pass for a cipher that is self-consistently wrong.

`SB1` gets a fifth check: it is AES's S-box, and the test compares it
against a *construction* - the multiplicative inverse in GF(2^8) plus
the affine transform - rather than against another table. A table read
from one document and a construction from a definition cannot share a
mistake.

### The key-schedule constants rotate with the key size

**Status: mitigated, and asserted.** 128 bit keys take C1 C2 C3, 192 take
C2 C3 C1, 256 take C3 C1 C2. An implementation that ignores the rotation
**passes the 128 bit vector** and fails the other two - which is the
worst possible shape, because the 128 bit case is the one everybody
tests first.

Likewise, KR is the remainder of the key *right*-padded with zeros. For
a 128 bit key KR is entirely zero, so a left pad is invisible there too.
Both have their own test with a key chosen to make the difference show.

### The appendix is unusually generous, so use it

**Status: mitigated.** RFC 5794 A.1 gives W0..W3, all thirteen round keys and
all eleven intermediate round values for the 128 bit key. So the key
schedule and each round are tested on their own, and a failure says
*which round* rather than "the answer is wrong".

Most specifications give a plaintext and a ciphertext and nothing in
between, which makes a wrong cipher a search problem. Where a document
offers intermediates, testing them is worth the extra parser.

### OpenSSL has ARIA and python-cryptography does not

**Status: mitigated, and pinned.** This is the rare algorithm where a
real independent implementation is at hand - the `openssl` binary -
but the usual Python reference cannot reach it.
`scripts/diff_check.py` therefore writes its own ARIA - reading the
same RFC with a *different* parser from the Rust one - and **pins it to the `openssl` binary at import**,
over every key size and mode, before using it for the three-hundred
length sweep. Three hundred subprocesses would be slow enough that
somebody would shrink the corpus to fit, which is how `diff_check`'s
Kuznyechik row once ended up sweeping nothing.

`pytests/test_aria.py` asserts that `cryptography` still has no ARIA, so
that the day it gains one, the shelling-out stops being necessary and
somebody is told.

---

## 7m. Whirlpool

Whirlpool is not broken. It is here because **TrueCrypt and VeraCrypt
derive their header keys with PBKDF2-HMAC-Whirlpool**, so a volume made
with that option cannot be opened without it - and because `hashlib` has
never had it while OpenSSL 3 has already moved it to the `legacy`
provider. The reference this was checked against is one release from
disappearing, which is why it was implemented now rather than later.

### A 256-byte table that did not need typing

**Status: mitigated: the table is generated.** Whirlpool's S-box is *constructed* from two
16-entry mini boxes, and the specification states the construction
rather than the table. So the only constants written out in
`src/hash_functions/whirlpool.rs` are 32 nibbles, and the S-box, the ten
round constants and the circulant matrix's eight lookup tables are all
computed from them at compile time.

What pins those 32 nibbles is that a single wrong one almost always
stops `E` or `R` being a permutation, which is asserted at the source -
and past that, eleven published vectors and a three-hundred-length sweep
against OpenSSL. The sweep confirms it: changing one nibble fails four
tests.

Where a specification gives a construction, use the construction. A
table is one transcription per entry.

### The field is GF(2^8) mod 0x11d, not AES's 0x11b

**Status: mitigated.** Whirlpool's cipher is AES's shape scaled to an
8x8 matrix, which makes copying AES's reduction polynomial the obvious
mistake - and the two agree on every multiplication by one, which is
most of the circulant row. Same trap as XTS's little-endian field
against GHASH's big-endian one, recorded earlier in this document. Three
fields now, and every one of them a self-consistent hash when wrong.

### What is actually wrong about a 64-bit length field: nothing

**Status: mitigated; the comment was corrected by a sweep.** The first draft of this
module's comment said that Whirlpool's 256 bit length field meant a 64
bit one was "wrong for every message, not just long ones". The sweep
disagreed: replacing the `u128` count with a `u64` in the **last** eight
of the 32 bytes changed no test, because for any message under 2^64 bits
the two are byte-for-byte identical.

So the width is not the hazard. Two things are, and both were confirmed
by breaking them: padding to 56 mod 64 the way MD5 and SHA-1 do rather
than to 32 mod 64 (seven tests), and putting the count at the *front* of
the 32 bytes rather than at the end (the vectors).

That is the useful lesson, and it is the mirror of the one this document
already records about `decrypt_premaster`: a comment can be wrong by
claiming a check the code does not do, and it can be wrong by claiming a
hazard that does not exist. **The second is harder to notice**, because
nothing fails - the comment simply misleads the next reader into
"fixing" something that was never broken. A deliberate-breakage sweep
catches it, which is a use for the technique beyond finding untested
code.

### Whirlpool-0 and Whirlpool-T are absent on purpose

The function was revised twice - Whirlpool-0 (2000), Whirlpool-T (2001,
a different S-box), Whirlpool (2003, a different diffusion matrix). Only
the last is standardised and only the last has a reference
implementation to check against. The other two would be unverifiable, and
this repository's rule is that an unverified variant is worse than an
absent one. Both are listed in [status.md](status.md#hashes) as not
implemented.

---

## 7n. ElGamal

ElGamal is Diffie-Hellman turned into an encryption scheme, and
separately into a signature scheme, so `src/publickey_ciphers/elgamal.rs`
is built on `DhGroup` - the validation a group and a public value need is
exactly what Diffie-Hellman needs, and having it once is why `DhGroup`
holds `p` and `g` together.

It is here for **old PGP keyrings**: OpenPGP algorithm 16 is ElGamal
encryption, and it was GnuPG's default encryption subkey for years.
OpenSSL dropped it and `python-cryptography` never had it.

### There is no second implementation to check against

**Status: accepted, and said in the output.** Unlike Diffie-Hellman,
nothing here can encrypt to us and tell us we agree on a convention. The
reference is Python's own integers, which is a real independent
implementation of `pow(g, x, p)` and nothing more.

So `tools/src/bin/diff_elgamal.rs` is shaped to make the conventions
checkable from the arithmetic alone. The `enc` rows carry a *chosen* `k`
so the checker can recompute both ciphertext components; `dec` checks
the inversion by a different route (Python's `pow(x, -1, p)` against our
Fermat exponentiation); `live` takes a ciphertext whose `k` is unknown
and checks the two components are consistent with *some* `k`; and `sig`
verifies a whole signature. The checker fails if any of the four kinds
is missing, because one of them alone proves much less.

### Bleichenbacher's 1996 forgery, and a test that did not test it

**Status: mitigated, and the test was rewritten.** A verifier that does not
require `r < p` can be handed a signature for any message without the
private key. `r` appears twice in `y^r * r^s == g^m`: as an exponent,
where it counts modulo `p-1`, and as a base, where it counts modulo `p`.
Those moduli are coprime, so an `r` larger than `p` satisfies both
independently. Take `s = 1`, ask for `r == 0 (mod p-1)` and
`r == g^m (mod p)`, and CRT gives `r = (p-1) * (p - g^m mod p)`.

**The first version of the test was worthless**, and a breakage sweep
said so: it offered `r = 0`, `r = p` and `r = p + r`, every one of which
the *arithmetic* rejects for unrelated reasons - so removing the range
check entirely changed nothing. The general form, and it is worth having
written down: **a test of a check has to offer a value that the check is
the only thing refusing.** Anything else is a test of whatever rejects it
first.

`s` has its own bound for a smaller reason: `s` and `s + (p-1)` verify
identically, which is malleability rather than forgery, but a system that
hashes or deduplicates signatures treats them as two different objects
with the same meaning.

### GnuPG withdrew ElGamal signing, and the reason was the nonce

**Status: mitigated.** In 2003 Phong Nguyen showed GnuPG's sign+encrypt
ElGamal keys were broken: to make signing fast it used a short `k`, and a
short `k` in the signature equation recovers the private key by lattice
reduction. A *repeated* `k` gives it by subtraction, which is the same
arithmetic that broke the PlayStation 3's ECDSA.

That was one implementation's choice of nonce rather than a flaw in the
equation, and the scheme is here because old signatures still need
verifying. `k` is drawn full width from the system source, and redrawn
until it is coprime to `p-1`.

### The separator is the *first* zero, and the tests all avoided zeros

**Status: mitigated, in two modules.** PKCS#1 v1.5 decryption finds the
padding separator as the first zero byte after the header. A search that
took the *last* zero - or the largest index seen - truncates any message
containing an interior zero.

Replacing the first-zero search with a last-zero one passed the entire
suite, for both ElGamal **and RSA**, because every round-trip test in
both modules built its messages with `| 1` or from short ASCII and so
had no zero bytes anywhere. Both now have a test with leading, interior
and trailing zeros.

Two lessons. A message with no zero bytes is not a message, it is a
convenient one - the same shape as `tools/src/bin/diff_crl.rs` when
every serial in it differed in its last byte, so a serial comparison
truncated to that byte passed every row. And a
sweep on a new module found a years-old gap in an old one, because the
two share the code: **when a sweep finds an untested path, check whether
anything else has the same path.**

### One branch that cannot be tested

`sign` refuses `s = 0`, which collapses the verification equation to
`y^r == g^m` and no longer depends on the nonce. It happens with
probability about `1/p` and the nonce is drawn inside the function, so
no test can reach it and removing the branch fails nothing. Kept as
defence in depth, with a comment at the code saying exactly that - the
convention this repository uses, and the same one `ec::ct::Field::add`'s
redundant arm carries.

---

## 7o. The GOST curves with cofactor four

Two of the parameter sets RFC 7836 defines - `id-tc26-gost-3410-2012-256-paramSetA`
and `id-tc26-gost-3410-2012-512-paramSetC` - have `m = 4q`, where
every other curve in this library has `m = q`. Adding them turned on
code that had never run and changed the answer of a function that had
never been wrong.

### The Edwards form is not the only form

Both sets are twisted Edwards curves, and this library said so in a
comment and refused them for it: "a twisted Edwards curve this library
has no arithmetic for". That was wrong, and it cost real handshakes.
RFC 7836 appendix A.2 states each set **twice** - as `(e, d, u, v)` in
the Edwards form and as `(a, b, x, y)` in the short Weierstrass form,
which is the form every function in `src/ec` already speaks. The
document even prints them in one structure, so the second form was
sitting three lines below the first.

What it cost: RFC 9189's own worked example, appendix A.1.3.2, has a
server certificate on 512-paramSetC. A client without that curve
refuses the handshake at the Certificate message - after the
ServerHello, so the failure looks like a handshake problem rather than
a missing curve.
`tests/test_gost_rfc9189_flight.rs` replays that flight now.

### `validate`'s subgroup branch became live code

`Curve::validate` has always had a branch for `h > 1` that multiplies
the peer's point by `n` and insists on the identity. With every curve
at `h = 1` it never ran, and the test that said so
(`test_the_subgroup_branch_is_unreachable_on_every_curve_here`)
existed to fail the moment it did - which is what happened.

It is a real check now and needs to be: on a curve of order `4n`, a
peer can send a point of order two or four. It is on the curve and it
is not the identity, so the cheap checks pass, and the shared secret
then lies in a group of four elements - which is the private scalar
modulo four, handed over for nothing.
`ec::tests::test_a_small_subgroup_point_is_refused` finds such a point
by search rather than by constant and checks that both curves refuse
it.

### VKO's cofactor: two wrong answers, and how the second was found

RFC 7836 section 4.3 writes the key agreement as

    K (x, y, UKM) = (m/q * UKM * x mod q) * (y*P)

and `m/q` is the cofactor `h`. On the five GOST curves with `h = 1` the
term changes nothing. On the two with `h = 4` — `gost256-tc26-a` and
`gost512-c` — `4P` and `P` are different points, so an implementation
that gets it wrong derives a key its peer does not have.

**Status: mitigated, after being wrong twice in opposite directions.** The
history is the useful part, because both mistakes were reasonable and
neither was visible from inside.

**First**, the term was left out altogether, with a comment saying every
GOST curve here had `h = 1` so it made no difference — true when it was
written. Two cofactor-four curves arrived and the comment stayed.

**Second**, and this is the one worth reading: the term was put back for
`Curve::vko`, but a `Cofactor` enum was added with an `AsDeployed`
variant that omitted it, and the TLS key exchange was pointed at
`AsDeployed`. The argument was that following a document while being
unable to talk to the only thing that speaks the protocol is not what
this library is for, and that argument is right. The premise was that
gost-engine omits the cofactor, on the strength of reading
`VKO_compute_key` in `gost_ec_keyx.c`:

    BN_mod_mul(scalar, scalar, priv, order);   /* no m/q anywhere */
    gost_ec_point_mul(grp, pnt, NULL, pub, scalar);

That is the whole of the function's arithmetic and there is no cofactor
in it. **Three lines below it there is a disabled block that says
where the cofactor went:**

```c
#if 0
    /*-
     * These two curves have cofactor 4; the rest have cofactor 1.
     * But currently gost_ec_point_mul takes care of the cofactor
     * clearing, hence this code is not needed.
     */
    switch (EC_GROUP_get_curve_name(grp)) {
        case NID_id_tc26_gost_3410_2012_256_paramSetA:
        case NID_id_tc26_gost_3410_2012_512_paramSetC:
            if (!BN_lshift(scalar, scalar, 2))
                goto err;
            break;
    }
#endif
```

`gost_ec_point_mul` dispatches to per-curve generated code, so the
cofactor is applied and does not appear anywhere a reader of
`VKO_compute_key` would look. The two curves the disabled block names
are exactly the two with `h = 4`.

**So gost-engine follows RFC 7836, and the TLS key exchange was pointed
at a reading nothing implements.** It would have derived a key no peer
shares — on two curves only, which is the shape that takes longest to
find, and one of those two is the curve RFC 9189's own worked example
puts its server certificate on.

**What found it was asking rather than reading.** `vectors/
gost_engine.vec`'s `vko-*` sections hold what `openssl pkeyutl -derive`
produces on all nine of the engine's parameter sets — every curve, plus
the two exchange aliases — at both digest sizes, eighteen derivations,
and every one is the document's reading.
`tests/test_gost_engine_vectors.rs` asserts that, *and* that the
cofactor-less reading differs on `gost256-tc26-a`, so the rows cannot
pass on an implementation where the distinction had collapsed.

Three things to take from it:

- **A function read carefully is still a guess.** That source was read
  carefully twice and the same wrong conclusion reached both times; one
  measurement settled it. The rule this repository applies to test
  vectors — *a vector that came from the implementation being tested is
  not a test* — has a mirror image: a claim about another implementation
  that came from reading it is not a measurement.
- **A differential corpus cannot see this class of bug.**
  `scripts/diff_check.py` had `vko` and `vkodeployed` rows and agreed
  with itself on all of them, because both sides were the same reading.
  It is the right tool for a transcription error and the wrong one for a
  misread specification.
- **A name can assert a falsehood.** `AsDeployed` said "this is what
  deployments do". The variant survives as
  `Cofactor::WithoutCofactor`, named for its arithmetic instead, and is
  kept only as the negative control the tests need. `by_name`
  **refuses** `"as-deployed"` with an error explaining the change rather
  than aliasing it, because that name meant "what the equipment does"
  and pointed at the one reading the equipment does not — a silent alias
  would hand such a caller the wrong key.

Both readings stay in the differential corpus, as `vko` and
`vkonocofactor` rows; `tools/src/bin/diff_vko.rs` asserts they agree on every
`h = 1` curve and differ on the two where `h = 4`, so neither row kind
can quietly turn into a duplicate of the other.

### The inverse of a many-to-one map is a choice

**Status: mitigated.** A real server refused us with a fatal
`decode_error`, and the cause was the ClientKeyExchange's ephemeral key
carrying a different parameter set OID from the one the server's
certificate had sent.

`oids::gost_curve_for` maps **twelve OIDs onto seven curves**, because
three namings overlap: RFC 4357's CryptoPro sets, TC 26's 2012
renumbering (shifted by one, so `paramSetB` is CryptoPro-A) and RFC
4357's two *exchange* sets (`XchA` is CryptoPro-A to the digit, `XchB` is
CryptoPro-C). That map is correct and it is many-to-one.

`spki_oids` was its inverse — curve name to OID — and **the inverse of a
many-to-one map is a choice.** It chose the CryptoPro spelling. So a
server whose certificate said `XchA`, or `paramSetB`, or `paramSetC`, or
`paramSetD`, got back an ephemeral key on the *same curve* under a
*different OID*. CryptoPro compares the bytes and answers
`decode_error`.

**The fix is to stop choosing.** All seven captured handshakes in
`tests/transcripts/gost_handshakes.txt` show OpenSSL's ephemeral key
repeating the server certificate's whole `AlgorithmIdentifier` — the
algorithm OID, the parameter set and the `digestParamSet` — byte for byte,
with only the point changed. So `PublicKey::Gost` keeps
`algorithm_id: &[u8]` as it arrived and
`gost_kex::encode_public_key_like` copies it.

That one rule settles three decisions that used to be made separately,
each of which could be made wrongly:

- which of the several OIDs naming this curve to write;
- whether the algorithm is `id-GostR3410-2001` or one of the 2012 pair;
- whether to include the `digestParamSet` that RFC 9215 4.2 deprecates
  and RFC 9189's own example carries — the `paramSetB` capture **omits**
  it, so a client that always wrote one would have added a field the
  server did not send.

The answer to all three is "whatever the server said", which is not a
thing a client can get wrong. `encode_public_key` and
`encode_public_key_2001` remain for the case they are right for — writing
a certificate, where *we* choose the curve and so may choose its OID —
and both now delegate to the copying encoder, so the two paths cannot
produce different shapes. Copying is not forwarding: the parameter set
inside the copied bytes must still resolve to the curve the point is on,
or it would be possible to hand a peer an internally inconsistent key.

**Why nothing here found it.** The usual shape — our reader accepts all
twelve spellings, our writer emits one, and every test has our code at
both ends, so the two agreed. And the near-miss is the instructive part:
the five handshakes captured from gost-engine *already contained* the
engine's own ClientKeyExchange, and comparing ours against them would
still not have caught this, because `genpkey` writes the canonical OID
and the engine's certificates agreed with our canonicalisation by
accident. Two more handshakes were captured on `XchA` and `paramSetB` for
that reason. `tests/test_gost_client_key_exchange.rs` holds both the
comparison and a direct statement of the rule, and reverting the fix
fails both.

### The field that hid it: reporting a curve where the OID decides

The distinction above lived in exactly one place — the parameter-set OID
— and nothing this library showed a caller printed it. `CertificateInfo`
reported `publicKeyType` as `GOST R 34.10-2012 gost256-a`, which is what
comes out for CryptoPro-A **and** CryptoPro-XchA, because they are the
same domain parameters under two OIDs. So the three saved CryptoPro
certificates in `vectors/live/` could be dumped, read, and reported as
being on curves this library handles perfectly — while carrying the one
field that made the handshake fail.

So the certificates could be read as evidence that the live failures
had some other cause, when they were the only evidence that explained
them.

`CertificateInfo::public_key_parameter_set` now carries the OID, exposed
to Python as `publicKeyParameterSet`, and
`tests/test_live_gost_certificates.rs` asserts it per certificate plus
the thing that keeps the fixture honest: **at least two of the three must
be on an exchange parameter set.** If a refetch ever replaced them all
with canonical spellings, every other test over those files would still
pass, and the corpus would have quietly stopped covering the bug it was
collected for.

EC keys are left with no parameter-set field, and that is not an
oversight: a named curve there maps one-to-one onto its OID, so the name
carries everything the OID does. GOST is the case where it does not.

### Three namings for two curves

`id-GostR3410-2001-CryptoPro-XchA-ParamSet` is CryptoPro-A and
`XchB` is CryptoPro-C - the same curves under a third set of names,
for key exchange rather than signing. This library mapped neither, so
a certificate carrying one was refused for a curve it has had all
along. RFC 4357 section 11.4 prints all five 2001 parameter sets, and
`ec::curves::document_tests` now compares them digit by digit rather
than taking the aliasing on trust.

The TC 26 renaming is shifted by one on top of that: paramSetB is
CryptoPro-A, paramSetC is CryptoPro-B, paramSetD is CryptoPro-C, and
paramSetA is the cofactor-four curve above that CryptoPro never named.
A table written from the letters alone is wrong in three places out of
four.

---

## 7p. GOST R 34.11-94

The hash Streebog replaced, here because the 0x0081 TLS suite uses it
for everything: the transcript, the PRF, the certificate's signature
and the key exchange.

### A message that exactly fills a block gets no extra block

Every Merkle-Damgård hash in this library - SHA-2, Streebog, MD5 and
the rest - follows a full final block with a padded one. **This one
does not.** The standard's iterative procedure takes the remaining part
of the message when it is "256 bits or fewer", so a 32 byte message is
one block and that block is the last. (BLAKE2 also holds its last block
back, for a different reason: that block carries the finalisation
flag.)

This is why `gost94.rs` does not use `BlockBuffer`, which MD2, MD4,
MD5, SHA-1, SHA-2 and Whirlpool share: that type compresses a block the
moment it is full, which is right for them. A block is held back
instead, and compressed only once something arrives after it.

Getting it wrong adds a block of zeros to the hash *and* to the
checksum, and the digest of every message whose length is a multiple
of 32 bytes comes out wrong - including the empty message. RFC 5831's
own first example is exactly 32 bytes, which is how the first draft of
the file was caught.

### An empty message is three compressions, not zero

Zero is also "256 bits or fewer", so the empty message gets a padded
block of zeros, then the length, then the checksum. An implementation
that skips the tail when there is no tail returns the initial value.

### RFC 5831 misprints one of its own intermediates

Appendix 7.3.1 prints `K[1]` of its first compression with two of its
eight 32 bit words - the second and the fifth - transposed. Everything
else in both examples agrees to the digit: `K[2]`, `K[3]` and `K[4]` of
that same step, all four keys of every other step in both examples, the
`S` those four keys produce two lines below, the `KSI` after it, and
both final digests - one of which is the published vector for the
message.

A `P` transformation that produced the printed `K[1]` would produce a
different `S`, so the document disagrees with itself and the rest of it
wins. `test_the_key_schedule_of_the_first_example` asserts the
discrepancy *exactly*: two words, transposed, and nothing else. A
future reading of the standard that changes `P` fails it whichever way
it moves.

### The S-box is a parameter and the two in use are different hashes

`id-GostR3411-94-TestParamSet` is what the standard's examples use.
`id-GostR3411-94-CryptoProParamSet` is what every certificate and every
TLS connection uses. Confusing them gives a digest that is a perfectly
good digest and agrees with nobody, and the only symptom is a signature
that does not verify - against a peer, days later. So the default is
CryptoPro, an unknown name is an error rather than a fallback, and both
tables are checked against RFC 4357 section 11.2's packed form.

While fixing that, `GostCrypto::new` turned out to do the opposite:
an unknown S-box name became CryptoPro-A silently. A GOST cipher *is*
its S-box, so that produced a working cipher of the wrong kind from a
misspelt parameter set. It is an error now, and the one caller that
relied on the fallback passed the string `"Default"`, which matched
nothing.

### `digest()` works on a copy

**Status: mitigated.** `finish` pads the tail and absorbs it, the
length and the checksum into the hash's own state, and `digest()` used
to call it in place. So a second `digest()`, or an `update` after one,
gave a wrong answer - for this hash alone, since every other one here
already left its state untouched. Every test digested exactly once; the
C interface's test, which digests and then carries on, was the first to
do otherwise. `digest()` now finishes a clone, which is what `hashlib`'s
`digest()` promises, and `test_hash_facade` in `tests/test_api.rs`
digests twice and then continues the message, for every hash in the
catalogue.

---

## 7q. The 2001 GOST suite, 0x0081

`TLS_GOSTR341001_WITH_28147_CNT_IMIT` is a decade older than RFC
9189's suites and shares a record layer with one of them, which is the
trap: everything that differs is invisible from the shape of the
handshake.

### Four algorithms change and nothing about the structure does

The 0x0081 suite and RFC 9189's 0xC102 have the same ClientKeyExchange
message, the same key material lengths, the same cumulative CNT
keystream and the same cumulative four byte MAC. What differs:

| | 0xC102 | 0x0081 |
|---|---|---|
| PRF and transcript hash | Streebog-256 | GOST R 34.11-94 |
| `shared_ukm` | Streebog-256 of the randoms | GOST R 34.11-94 of them |
| key agreement | VKO GOST R 34.10-2012 | VKO GOST R 34.10-2001 |
| S-box, everywhere | `id-tc26-gost-28147-param-Z` | `id-Gost28147-89-CryptoPro-A-ParamSet` |
| certificate | `id-GostR3410-2012-256` | `id-GostR3410-2001` |

Each of those produces a value of the right length from the wrong
function. Choosing the wrong hash gives a UKM of eight bytes that
derives a different key; the wrong S-box gives records the peer reads
as a MAC failure; the wrong VKO gives a 32 byte KEK that unwraps to
nothing.

### The certificate is the same key under a different OID

A 2001 certificate and a 2012 one can carry **the same point on the
same curve**. Only the algorithm OID in the `SubjectPublicKeyInfo`
says which standard it belongs to, so `PublicKey::Gost` carries a
`legacy` flag and the client refuses a certificate whose generation
does not match the suite. Without that check a handshake completes
having authenticated the server with an algorithm neither end agreed
to. `test_a_2012_certificate_is_refused_for_the_2001_suite` checks it
in both directions, because a check that only refuses one way round is
half a check.

### VKO GOST R 34.10-2001 has no published test vector

RFC 4357 states it in four lines and prints no example; the CryptoPro
draft prints none either. A round trip between our own two ends proves
nothing at all here - the agreement is symmetric, so two
implementations that both read it wrongly agree perfectly. The only
outside check is `scripts/diff_check.py`, which recomputes
`((UKM*d) mod q) . Q` from the curve parameters and hashes it with its
own reading of GOST R 34.11-94, and which asserts that the result
differs from the 2012 agreement over the same point - the one mistake
most likely to be made.

### It is `Weak`, which in this library still means offered

GOST R 34.11-94 has had published collisions since 2008 and the
standard was withdrawn in 2013, so the suite is `Strength::Weak` -
the same band as `TLS_RSA_WITH_AES_128_CBC_SHA`, and **`Weak` is
included in `Selection::modern()`**, which means "not broken and not
insecure" rather than "current".

That is worth stating because the first version of this note said the
opposite - that `modern` left it out and naming it was how a caller asked
for it. It does not, and a comment claiming a protection that is not
there is worse than no comment: it answers the question wrongly for
whoever reads it next. `Selection::legacy()` reaches down to `Broken`
(RC4, 3DES, single DES) and `Selection::all()` to `Insecure` (no
encryption, no authentication); `Weak` is above both.

The practical effect is that the proxy offers 0x0081 by default, which
is what somebody pointing this at a GOST box wants, and costs two
bytes in a ClientHello to everybody else.

---

## 7r. MGM, the AEAD the GOST TLS 1.3 suites use

**Status: mitigated.** RFC 9058, `src/block_ciphers/mgm.rs`. Written for
RFC 9367's four TLS 1.3 cipher suites, and useful on its own as the one
authenticated mode here that is defined for a 64 bit block.

Nothing on a normal machine implements MGM - OpenSSL has it only through
the GOST engine - so the reference is the document twice: the four
worked examples in RFC 9058's appendix, parsed out of the vendored text
at test time, and a second reading in `scripts/diff_check.py`.

### `incr_l` and `incr_r` are different functions and both are used

MGM runs **two** counter chains from two different starting blocks.
`Y_1 = E_K(0 || ICN)` drives the keystream and steps with `incr_r`;
`Z_1 = E_K(1 || ICN)` drives the authentication and steps with
`incr_l`. RFC 9058 section 6 says why in one line: the two sequences are
chosen to minimise any intersection between them.

Every way of confusing them is silent. One function used for both, or
the two swapped, gives a mode that encrypts, authenticates, round-trips
against itself perfectly and agrees with nobody. So the counters are
checked one block at a time against the document's printed `Y_i` and
`Z_i` sequences rather than only through the tag -
`test_the_two_counter_sequences_match_the_document`.

### Each half wraps in its own width

`incr_r` adds one to the right half modulo `2^{n/2}` and carries nothing
into the left half; `incr_l` is the mirror image. A `+= 1` over the
whole block as one integer is **identical for every message short enough
to appear in a document**, and differs at the first wrap. None of RFC
9058's examples reach one. `tools/src/bin/diff_mgm.rs` carries rows whose ICN
halves sit one step below their maximum for exactly that reason, and
asserts that at least four such rows exist.

### The field is MSB-first, and it is neither GHASH's nor XTS's

Three modes in this library multiply in GF(2^128) and no two of them
agree about what a byte string means:

| | bit order | reduction |
|---|---|---|
| MGM | MSB first | `w^128 + w^7 + w^2 + w + 1` |
| GHASH | bits reversed within each byte | the same polynomial, applied at the other end |
| XTS | little endian at the byte level too | `w^128 + w^7 + w^2 + w + 1` |

Copying either of the other two gives a self-consistent MGM that mounts
no connection. The 64 bit field is a fourth thing again:
`w^64 + w^4 + w^3 + w + 1`, so `magma-mgm` and `kuznyechik-mgm` are two
different modes sharing a name. The differential checker computes the
tag under GHASH's convention as well and requires it to differ, so a row
cannot pass on an implementation that used the wrong one.

### The last multiplicand is the lengths, in bits

`len(A) || len(C)` is one block, each half `n/2` bytes, and it is the
**bit** length. It is also what keeps `A` and `A || 0x00` apart, since a
partial block is zero padded - without it, the padding would be a
forgery. A tag over byte lengths is a perfectly good tag over the wrong
number, and `test_the_length_block_is_bits` reads the document's own
printed block rather than recomputing it.

### Two things the mode refuses rather than answers

**Both inputs empty.** RFC 9058 section 6: with no associated data and
no plaintext the tag stops depending on the nonce at all, so one
captured tag forges every empty message under that key. The RFC states
it as a requirement on the caller; here it is an error, because a caller
who does it gets no other warning.

**A nonce with its top bit set.** The ICN is `n-1` bits and the missing
bit is the domain separator above. Masking it silently - which is what
an implementation taking a full block would do - turns two nonces
differing only in that bit into one nonce, which is the single thing
MGM says must never happen. RFC 9367's TLS profile does the masking
itself, one layer up, and says so at the call site.

### What the tests are worth

Ten deliberate breaks, ten caught: each counter function swapped for the
other, `incr_r` carrying across the halves, the lengths in bytes,
GHASH's reduction constant, both domain separators the same, the MAC
taken over the plaintext, the two length halves transposed, a tag
compared on its first byte only, and a partial block padded with ones.

---

## 7s. GOST at TLS 1.3, RFC 9367

**Status: mitigated**, by the document's own two worked handshakes -
`tests/test_rfc9367_flight.rs`. The four suites 0xC103..0xC106 use RFC
8446's record layer unchanged in everything that shows on the wire and
change four things that do not show at all.

### The static IV is not twelve bytes

RFC 8446 section 7.3 expands `"iv"` to the AEAD's nonce length, and
AES-GCM, AES-CCM and ChaCha20-Poly1305 all take twelve — so twelve
became a constant here, `keys13::NONCE_LEN`, and `Aead13::new` asserted
it. RFC 9367 section 4.1.1 sets `IVlen = n`: sixteen bytes for
Kuznyechik and **eight** for Magma.

**The length is an input to the expansion, not a truncation of it.**
HKDF-Expand-Label puts the requested length into the `HkdfLabel`
structure it hashes, so the 8, 12 and 16 byte answers share no prefix.
A wrong length is therefore not a length error at the first record — it
is a different static IV, and a peer that disagrees about every nonce.
`tools/src/bin/diff_tls13_keys.rs` sweeps all three lengths against both key
lengths, because the two are independent and deriving one from the other
is a mistake that only shows on the wire.

### The record key is not the traffic key

RFC 8446 derives one write key per epoch and varies only the nonce. RFC
9367 section 4.1 derives `TLSTREE(sender_write_key, seqnum)` — a fresh
key for **every record**, from three chained KDF steps over the sequence
number masked three ways. The masks are the suite's, they are different
from RFC 9189's two sets, and **at sequence number 0 every masked value
is zero, whatever the constant** — so a suite using another suite's
constants agrees
on the first record of a connection and diverges later, which is the
worst shape a bug can have. All six sets are read back out of the two
RFCs by `kdf::gost::document_tests`.

The `_S` suites re-key far harder than the `_L` ones: Magma MGM S has
`C_3 = 0xFFFFFFFFFFFFFFFF`, so its third level changes on every single
record. That looks like a transcription error and is not, which is why a
test asserts it.

### The nonce's top bit is cleared, one layer above MGM

    MGMnonce = STR_1(nonce[1] & 0x7f) | nonce[2..IVlen]

MGM's initial counter nonce is `n-1` bits; the missing bit is the domain
separator between its two counter chains. The masking belongs to the TLS
profile, and `block_ciphers::mgm` **refuses** a nonce carrying that bit
rather than masking it quietly — because an implementation that masked
silently would turn two nonces differing only there into one nonce.

### The CertificateVerify signature is not encoded like the certificate's

RFC 9215 writes a GOST signature as `s || r`, big endian. RFC 9367
section 5.3 writes this one as `str_l(r) | str_l(s)`, and `str_l` is the
**little endian** form — so it differs in two ways at once: the
components are the other way round *and* each is reversed.

Neither change is visible on its own. Swapping the order alone, or
reversing the bytes alone, each gives a signature of exactly the right
length that verifies against nothing — and two implementations making
the same mistake interoperate perfectly. Only a signature somebody else
produced can settle it, which is what appendix A.1's `sgn` is;
`test_the_certificate_verify_signature` verifies it against the
document's own certificate and requires all three wrong readings to
fail.

RFC 9367 section 5.2 also binds each of the seven schemes to exactly one
curve, and **the naming is shifted**: `gostr34102012_256a` is the TC 26
parameter set, while `256b`, `256c` and `256d` are CryptoPro A, B and C.
A table written from the letters is wrong in three places out of four —
the same trap `handshake::groups` already carries a note about.

### Streebog-256 is a TLS 1.3 PRF

RFC 9367 section 4.2 makes it the hash for the key schedule, the
Finished MACs, the transcript hash, the PSK binders and TLSTREE. "TLS
1.3 means SHA-256 or SHA-384" was written into two functions that had to
agree; they are one function now, because a pair that disagreed would
derive keys under one hash and check Finished under another.

### What the document gets wrong

Three things, each pinned by a test so that a refetched RFC fails loudly
rather than silently changing what is being checked:

- **Two record keys in A.1 carry the other direction's label** — a
  `---Client---` block labelled `server_write_key_ap` and a
  `---Server---` block labelled `client_write_key_ap`. In each case the
  heading, the printed key value and the printed nonce all agree against
  the label, and each label appears a second time on the right block
  with the right value.
- **Two of A.2's four IV labels say `"iv", "", 16`** where the printed
  value is eight bytes.
- Eight of A.1's seventeen records and four of A.2's nine have 16 KB
  payloads elided with `[...]`, so they cannot be replayed at all.
  Reconstructing them from the elision's convention would be inventing a
  test vector; the counts are asserted instead.

Same standing as RFC 5831's transposed `K[1]` in §7p: the document
contradicts itself rather than being consistently wrong, which is what
makes each of these a misprint rather than a reading this library has
backwards.

---

## 7t. What three live GOST certificates found

**Status: mitigated.** Three bugs, all fixed; the third, in the Python
surface, has no test of its own. The first certificates in
this repository that this library did not produce. They came off the
wire from CryptoPro's public GOST TLS endpoints via
`scripts/fetch_chain.py`, and they are checked offline by
`tests/test_live_gost_certificates.rs`.

Every other certificate the verifier is tested against was written by
`x509::builder` or by OpenSSL, and the ways those get written are the
ways we already thought of. That is the whole reason these are worth
1.4 KB each in the repository.

### The embedded-NUL check refused every BMPString

Two of the three were **refused outright**, with
*"Name attribute contains an embedded NUL"*. The check was
`value.contains(&0)` on the **encoded** bytes, in `Name::parse`.

A `BMPString` is UTF-16, so every ASCII character in one is `00 xx`.
The check therefore refused every certificate carrying a `BMPString`
anywhere in a name — and `BMPString` is a common encoding for Cyrillic,
so it refused exactly the certificates this library exists to read. The
decoder five lines away was already doing UTF-16 correctly; the check
simply ran before it.

It was also a **parse** error, where the rule here is that
`Certificate::parse` reads and `verify` judges. A NUL in an
organisation name is not a reason to make the whole certificate
unreadable. It is now in `Attribute::text`, on the decoded string, and
it refuses that one attribute: a CN carrying a NUL comes back as
`None`, so it cannot match a hostname — which is the only place the
null-prefix attack lives.

Nothing offline could have found this. It is the same shape as the
UTCTime-versus-GeneralizedTime bug in §6: our reader and our writer
agreed, so only handing a certificate to somebody else — or being
handed one — could see it.

### "an EC key on unsupported curve" named the wrong table

The third failed with *"needs a GOST R 34.10-2012 certificate; this one
carries an EC key on unsupported curve 1.2.643.2.2.36.0"*. That OID is
`id-GostR3410-2001-CryptoPro-XchA-ParamSet`: CryptoPro-A's curve, which
this library has always had, under an exchange OID it did not yet map
(see *Three namings for two curves* in §7o). It maps it now, to
`gost256-a`, with a test asserting it.

`PublicKey::UnsupportedCurve` printed "an EC key" whichever branch
produced it, and both `id-ecPublicKey` and the GOST algorithms name
their curve in the algorithm parameters and end up there. So the
message sent whoever read it to the EC curve table, when the gap was
in the GOST parameter-set one. It
carries a `family` now: *"a GOST R 34.10-2001 key on unsupported
parameter set …"* against *"an EC key on …"*.

Third time this document has recorded the same lesson — `TrustStore::
skipped` and `ct_check.py`'s report counts are the other two. **A value
with its reason discarded cannot tell two opposite remedies apart.**

### And the Python surface called a 2001 key a 2012 one

`api::CertificateInfo` formatted every `PublicKey::Gost` as
`GOST R 34.10-2012`, ignoring `legacy`. `main.rs` was already careful
about exactly this — *"which generation, not just GOST"* — which is
what a second copy of a rule costs. Which generation a box has decides
whether 0x0081 or 0xC102 is the suite to offer it.

### The check that is worth the most

RFC 9215 section 4.3 writes a GOST public key as an OCTET STRING inside
a BIT STRING with the coordinates **little endian**. Nothing about that
is visible from a certificate we generated, because our reader and our
writer agree by construction.

These came from somebody else's CA, so reading them the wrong way round
gives two numbers that are not a point on the curve — and `y² = x³ +
ax + b` says so. `test_every_public_key_is_a_point_on_its_curve` checks
that, and checks that the **reversed** reading is *not* on the curve,
so it cannot pass on an implementation that had the byte order
backwards. There was no other independent check of that encoding.

### What they cannot check

All three servers sent the **leaf alone** — no issuer, which RFC 8446
4.4.2 permits — so there is no key here to verify the signatures with.

A server may also send a different certificate for a different suite,
which is why `fetch_chain.py` prints the negotiated suite beside the
chain and takes a single suite by name.

---

## 7u. SLH-DSA (FIPS 205), where the address is the security

Key generation, signing and verification, through both interfaces, with
all twelve pre-hash functions.

### The address structure is the entire separation between subtrees

Every hash call in SLH-DSA is keyed by a 32 byte `ADRS` saying which
layer, which tree, which key pair, which chain and which step it belongs
to. That keying is not decoration - it is what stops a hash computed in
one subtree being replayed as a hash in another, which is the attack the
whole construction is built to prevent. A wrong field offset, or a field
left over from a previous call, gives a **self-consistent** scheme: it
generates keys, it would sign and verify against itself, it matches no
other implementation, and it has silently lost its security argument.

**Mitigated by construction rather than by care.** FIPS 205's
`setTypeAndClear` zeroes the last twelve bytes as it sets the type,
precisely because those twelve bytes mean different things under
different types. Code that sets a type and then forgets one of the three
words that follow inherits the previous type's value there. So
`src/pq/slh_dsa.rs` has **no way to set a type on its own**: the setters
are one per type - `set_wots`, `set_wots_public_key`, `set_tree`,
`set_fors_tree`, `set_fors_secret`, `set_fors_roots` - and each takes
every word that type uses. A stale field is unrepresentable,
not merely unlikely.

Covered by `test_a_type_change_cannot_leave_another_type_s_values_behind`
and `test_the_address_fields_land_where_the_standard_puts_them`, which
check the layout byte by byte rather than trusting the 120 vectors to
notice - the vectors would only report that a root is wrong.

### Two words, four names, one slot

Bytes 24..28 are the *chain address* under the WOTS+ types and the *tree
height* under `TREE`; bytes 28..32 are the *hash address* or the *tree
index*. FIPS 205's pseudocode uses all four names, and a reader who
believes they are four fields will look for sixteen bytes where there are
eight. `test_the_two_reused_words_really_are_the_same_bytes` states the
aliasing as a test so that nobody has to infer it.

### The SHA-2 family drops bytes that must be zero

SHA-2 hashes a 22 byte compressed address -
`ADRS[3] ‖ ADRS[8..16] ‖ ADRS[19] ‖ ADRS[20..32]` - throwing away the
high three bytes of the layer, tree and type fields. That is lossless
only because those bytes are always zero, and if they ever were not,
**two distinct addresses would compress to the same 22 bytes**, which is
exactly the collision the addresses exist to prevent.

**Mitigated:** `Adrs::compressed` returns `Result` and refuses an
address with anything in those bytes, and `set_tree_address` takes a
`u64` so a tree index too large for the compressed form cannot be
expressed in the first place.
`test_compressing_refuses_an_address_that_would_not_fit` covers both.

### The SHA-2 family uses two hash functions and the choice depends on `n`

At `n = 16` every one of `PRF`, `F`, `H` and `T_l` is SHA-256. At
`n = 24` and `n = 32`, `PRF` and `F` stay SHA-256 while `H` and `T_l`
become **SHA-512** - and the zero padding after `PK.seed` changes with
them, from `64 - n` bytes to `128 - n`.

This is the most likely way to write a version of this file that looks
correct: one hash function throughout passes every 128 bit parameter set
and fails 192 and 256, and 128 is what anyone tests first. Covered
directly by `test_f_and_h_part_company_above_the_smallest_parameter_set`,
which checks the split by construction, and then by the 80 vectors at
`n = 24` and `n = 32`.

Note also that the SHAKE family is **SHAKE256 at every security level**,
including the 128 bit sets. SHAKE128 appears nowhere in FIPS 205.

### A WOTS+ key signs once, and this is a total break rather than a leak

Two signatures under one WOTS+ key let anyone forge a third message. The
stateless design exists to make that impossible to reach by accident: the
leaf is chosen pseudo-randomly from the message rather than by a counter,
and FORS tolerates the collisions that follow. **Any future change that
makes leaf choice depend on a counter reintroduces the statefulness the
scheme was designed to remove**, and the failure would not show up in any
test that signs one message.

**Mitigated** as the code stands: `sign_internal` takes the tree and
leaf indices from `H_msg`'s output (`digest_split`, `index_from`) and
from nothing else, and the 72 deterministic `sigGen` vectors would fail
under any other choice. The hazard is a future change, which is why it
stays on this list.

### Not constant time, and the reasons differ per function

- `chain` runs a data-dependent number of steps when signing. That is in
  the standard and it is fine: the number of steps is a digit of the
  message hash, which is public.
- `PRF` over `SK.seed` is a fixed-length hash with no data-dependent
  path.
- Key generation as implemented has **no secret-dependent branch at
  all** - it walks every leaf of the tree unconditionally, which is why
  it is slow.

**Accepted**, consistent with the library's stated position that constant
time is desirable and not the first concern. No `scripts/ct_check.py` row
is claimed for this yet.

### Key generation is slow and that is the algorithm

A key is the root of a Merkle tree over `2^h'` one-time keys, and a root
cannot be computed without every leaf: about 270,000 hash calls at
`SLH-DSA-SHA2-128s`. Not a pitfall in the security sense, but it is the
reason `tests/test_slh_dsa.rs` runs 114 of the 264 vectors by default -
66 of the 120 key generations and 48 of the 144 signatures - and keeps
the full sweep behind `--ignored`, and the reason anyone profiling
this library will find it at the top.

### Signing: the message digest decides everything, so H_msg is load bearing

`H_msg` produces `m` bytes and they are cut into three: the FORS
indices, the hypertree tree index and the leaf index. So a fault in
`H_msg` does not corrupt a signature, it makes a **different leaf** sign
the message - and every downstream step then works perfectly on the
wrong tree. There is no internal inconsistency to notice.

Two specific traps in it:

* **`H_msg` is MGF1 in the SHA-2 family, not a hash.** `m` is 30 to 49
  bytes and no SHA-2 output is that length, so FIPS 205 hashes
  everything and then runs MGF1 over `R ‖ PK.seed ‖ that hash` to reach
  `m`. `R` and `PK.seed` therefore appear **twice** in the construction,
  once inside the inner hash and once in MGF1's seed. Dropping the outer
  copy looks like removing a redundancy. It is the same MGF1 as
  RSA-OAEP and PSS, so `rsa.rs`'s is `pub(crate)` and shared rather than
  copied.
* **`PRF_msg` is HMAC, where the other five are bare hashes.** Its first
  argument `SK.prf` is secret and the message follows it, so a bare
  `SHA-256(SK.prf ‖ opt_rand ‖ M)` would be length-extendable. The
  SHAKE family needs no HMAC because a sponge is not length-extendable,
  which is why the two families differ in *shape* here and not only in
  which hash they call.

### The digest's three fields are not all the same width

The leaf index is **two bytes at `h' = 9`** - the four `128s` and `192s`
sets, SHA-2 and SHAKE alike - and one byte everywhere else, while the
tree index reaches eight bytes. Two consequences: `1u64 << bits` is
undefined at `bits = 64`, which `SLH-DSA-SHAKE-256f` reaches exactly,
so the reduction is a branch rather than a mask; and the extra bits in
a partially used field **must be discarded**, or the index exceeds the
tree. Both are checked by
`test_the_index_arithmetic_masks_without_overflowing`, and the width
table by `test_the_leaf_index_is_two_bytes_only_where_h_prime_is_nine` -
directly, because the parameter sets that would otherwise catch it are
the slowest ones in the file.

### A WOTS+ key signs once, and the checksum is what makes forgery hard

Revealing the chain at depth `d` lets anyone walk it further, so without
the checksum an attacker could *raise* every message digit and forge.
The checksum sums `w - 1 - digit`, so raising a digit lowers the
checksum, and lowering a checksum digit is exactly what an attacker
cannot do. Two ways to get it wrong quietly:

* **Summing the digits instead of `w - 1 - digit`** gives a checksum that
  moves the same way as the message, which is a scheme that signs,
  verifies and is forgeable.
* **The checksum is shifted before it is split.** `len2 * lg_w` is 12
  bits written into 2 bytes, so FIPS 205 shifts it up by four first.
  Without the shift the digits are `0, high, low` instead of
  `high, mid, low` - a self-consistent checksum nobody else computes.

Both are pinned by `test_the_wots_checksum_is_shifted_before_it_is_split`,
which also asserts the anti-forgery property directly: lowering a message
digit must raise the checksum.

### `base_2b`'s bit order, and the two jobs it does

It reads digits from the **top** of each byte, and it is used with two
different widths for two different purposes: `lg_w` bits to cut a message
into WOTS+ digits, and `a` bits to cut the message digest into FORS
indices. A little-endian reading produces a perfectly good set of digits
and a signature over a different message, which is why
`test_base_2b_reads_the_high_bits_first` asserts the wrong reading gives
a *different* answer rather than only that the right one works.

### FORS leaf indices are global across the k trees

Tree `i`'s leaf `j` is index `i * 2^a + j`, not `j`. Using a per-tree
index makes all `k` trees derive the same secrets from the same
addresses - so the signature is `k` copies of one tree's work, which
collapses the security to a single FORS tree and looks entirely normal.

### Verification is not the inverse of signing, and the signer uses it

`fors_pkFromSig` (`fors_public_key_from_signature` in the code) is
called by the **signer** as well as the verifier: `slh_sign_internal`
(`sign_internal`) uses it to find the value the hypertree has to sign,
rather than recomputing the FORS roots a second way. That is a deliberate
choice with a consequence worth knowing - a fault there breaks signing
and verification *together* rather than making them disagree, so a
round-trip test cannot see it and only NIST's bytes can.

The same holds for `xmss_pkFromSig` (`xmss_public_key_from_signature`),
which `ht_sign` uses to get each layer's root.

### The external interface is three domain separators, and each one matters

`slh_sign` does not sign the message. It signs

```text
pure:      toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
pre-hash:  toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M)
```

and every part of that prefix is there to stop a signature being valid
somewhere it was not meant to be. Leave any of them out and signing and
verification still agree with each other perfectly:

* **The leading byte** separates the two forms. Without it a pure
  signature over bytes that happen to look like a wrapped digest is a
  valid pre-hash signature.
* **The context's length, in front of the context.** Without it
  `ctx = "ab", M = "c"` and `ctx = "a", M = "bc"` wrap to identical bytes,
  so one signature serves for both - and the two are different claims.
  This is the same class of bug as any unlengthed concatenation of
  attacker-influenced fields.
* **The OID in front of the digest.** SHA2-256, SHA2-512/256, SHA3-256 and
  SHAKE-128 all produce 32 bytes, so without the OID a signature over one
  verifies as a signature over any of them - a chosen-prefix attack on the
  weakest of the four becomes an attack on all of them.
  `test_the_wrapping_separates_the_domains_it_is_supposed_to` checks all
  sixteen combinations of those four.

**A context is at most 255 bytes and a longer one is refused, not
truncated.** The length is one byte, so `context.len() as u8` would wrap -
a 256 byte context would be written as length 0 and two different contexts
would share a signature.

**The OID is written as DER**, tag and length included, and through
`asn1::Writer` rather than assembled by hand. The twelve OIDs come from
`x509::oids`, which builds them from their dotted forms at compile time and
whose numbers `scripts/diff_check.py` checks against OpenSSL's object
table. Nine of the twelve were added for this; six of those nine are in no
vendored RFC, so OpenSSL's table is their only independent check.

### SHA-512/224 is not SHA-224, and the SHAKEs have chosen lengths

Two traps in the pre-hash table specifically:

* `SHA2-512/224` and `SHA2-512/256` are SHA-512 with a **different initial
  value** derived from the output length, not SHA-512 truncated and not
  SHA-224/256. `SHA512::new`'s second argument is what selects it.
* `SHAKE-128` and `SHAKE-256` produce **32 and 64 bytes** here. That is
  FIPS 205's choice, not a property of SHAKE, which will produce any
  length - so there is nothing in the algorithm to catch a wrong one.

Both are caught by the vectors, and both were confirmed by deliberately
breaking them.

### What checks it, and what that is worth

All 264 of NIST's ACVP vectors - 120 `keyGen` and 144 `sigGen`, the
latter covering both signing variants across both interfaces and all
twelve pre-hash functions, for all twelve parameter sets - in
`vectors/slh_dsa.vec`. **There is no differential test**:
python-cryptography has no SLH-DSA, and OpenSSL 3.5, which has it, is
not used as a witness for it. So a disagreement would have nothing to
bisect against, and the vectors' count assertion is load-bearing rather
than belt-and-braces: a parser that found nothing would turn the whole
test into an empty loop that passes.

What stands in for the differential sweep is breakage: **48 deliberate
faults, all 48 caught** - 15 in key generation, 21 in signing and 12 in
the external interface.

Verification's check is indirect and worth stating precisely. The
vendored signatures are stored as a SHA-256 digest rather than bytes, for
size; for a deterministic signature there is one right answer, so a
matching digest means our signature *is* NIST's, and the test then feeds
it to our own verifier. So verification is checked against NIST's bytes.
Rejection of signatures NIST says are invalid is checked too, by
`vectors/slh_dsa_sigver.vec`: 36 refusals from ACVP's `sigVer` file, one
per reason per group at two parameter sets, each with ACVP's reason -
modified message, modified `R`, modified FORS signature, modified
hypertree signature, one byte short, one byte long. **Mitigated** for
those two sets, `SLH-DSA-SHA2-128s` and `SLH-DSA-SHAKE-128s`; the other
ten are checked for acceptance only. A wrong-length signature is
`Ok(false)`, not `Err` - the doc comment on `verify_internal` used to say
otherwise while the code did this, and now says what the code does.

The Python bindings expose the external interface and not the internal
one, deliberately: a signature made with the internal interface is not one
another implementation's default verifier accepts, so the obvious thing to
reach for should not be that one. `pytests/test_slh_dsa.py` reads NIST's
vectors itself rather than round tripping, and skips the internal and
hedged sections with a note saying why at the skip.

---

## 7v. ML-KEM, where a round trip proves nothing

The ring - `Z_q[X]/(X^256+1)` with `q = 3329` - the NTT,
`Compress`/`Decompress`, the byte encodings, both samplers, key
generation, and `encapsulate_internal`/`decapsulate_internal` with the
Fujisaki-Okamoto transform, in `src/pq/ml_kem/`, with `api::MlKemKey` and
the Python `MlKemKey` over it. `scripts/ct_check.py` has rows for
encapsulation and both decapsulation paths, all clean, and a disassembly
scan that fails on any division in ML-KEM.

### The twiddle table is its own inverse

`intt(ntt(f)) == f` holds for **any** consistent pair of tables, a wrong
one included, so it is close to worthless as a test. Two faults that
survive it untouched were confirmed by deliberately introducing them:

* resetting the twiddle index at the start of each layer instead of
  letting it run 1..127 across the whole transform;
* leaving out the final scaling by `128^-1` in the inverse.

Both give a transform that inverts perfectly and multiplies wrongly.
**Mitigated** by `test_the_ntt_multiplies_the_same_way_the_schoolbook_does`,
which checks `intt(ntt(f) * ntt(g))` against a schoolbook negacyclic
convolution written separately - the same shape as `diff_check.py`'s
Kuznyechik, fast path against slow path. That test and a 13-fault sweep
are the whole verdict here, because **no published vector covers the NTT**:
it is internal to ML-KEM, and ACVP states only keys and ciphertexts.

### `X^256 = -1`, and the sign is the whole difference

A product term landing at or past degree 256 wraps round and **changes
sign**. Wrapping without it is the cyclic convolution - a different ring,
and a perfectly self-consistent wrong answer. The danger is specific: if
both the NTT path and the schoolbook path made that mistake the
differential test above would pass, so
`test_the_schoolbook_multiply_wraps_with_a_sign_change` pins the
convention on its own, by multiplying `X^255` by `X` and requiring `-1`.

### `BitRev7` is seven bits, and there are two tables not one

The twiddles are `17^BitRev7(i)` for `i` in `0..128`; the base-case
multiply's moduli are `17^(2*BitRev7(i)+1)`, a *different* exponent.
Reversing eight bits instead of seven gives a permutation of the same
numbers - a table that looks entirely plausible - and deriving one table
from the other at the call site is where the two get confused. Both are
`const fn`-computed from 17 rather than typed, because 128 hand-copied
constants is 128 chances at a self-consistent error.

**Three claims in the tests here were wrong and the tests caught them**,
which is worth recording because all three were plausible:

* that the two tables are disjoint as *sets of values* - they are not,
  since the twiddle exponents `0..128` include odd numbers, so those
  powers appear in both;
* that each `gamma` is the square root of a twiddle - it is not;
  `gamma_i^2 = 17^(4*BitRev7(i)+2)`, whose exponent is usually outside
  `0..128`;
* that the compression error reaches its bound at every width - it does
  not at `d = 12`, where `2^12 > q` makes the encoding a bijection and the
  error exactly zero.

What replaced the first two is the property that does hold and that the
factorisation actually rests on: **every `gamma` is a primitive 256th root
of unity**, because the odd powers of a generator of a cyclic group of
order 256 are exactly its generators. The even-exponent twiddles are not.

### The rounding in `Compress` is round-half, which integer division is not

`Compress_d(x) = round(2^d/q * x) mod 2^d`, and truncation is wrong by up
to one everywhere. The numerator carries `+ q` over a doubled denominator
rather than `+ q/2` over `q`, because dividing `q` by two would itself
truncate.

`test_compression_loses_no_more_than_the_standard_allows` asserts the error
**reaches** `ceil(q / 2^(d+1))` rather than merely respecting it: a
truncating implementation exceeds the bound, and a bound computed too
generously is never approached, so checking only `<=` would pass on both
mistakes.

### Coefficients are `[0, q)` and nothing here is centred

Some implementations keep a centred representative in `[-q/2, q/2]`
internally. FIPS 203's `Compress` is defined on the non-negative one, and
mixing the conventions is silent: every operation still works and the
compressed output differs. `Poly::is_reduced` is what the tests check it
with, and `Poly::from_coefficients` refuses an out-of-range coefficient
rather than reducing it - FIPS 203's `ByteDecode_12` has the same check,
for the separate reason that a non-canonical encoding is a malleability.

### `SampleNTT` must consume exactly three bytes per attempt

Two twelve bit values come out of three bytes, sharing the middle one:
`d1 = C0 + 256*(C1 mod 16)` and `d2 = (C1 div 16) + 16*C2`. A sampler
reading two bytes per coefficient, or three per coefficient, produces a
perfectly uniform polynomial and a **different matrix `A`** - so two
implementations disagree about `A`, nothing interoperates, and there is no
error anywhere to say so.

**Rejection is per value, not per triple.** `d1` is tested, kept or
dropped, and then `d2` is tested on its own. Discarding both when either
exceeds `q` changes which bytes feed the next coefficient and therefore
the whole polynomial. The second test also needs its own `j < 256` guard
or the last triple can write a 257th coefficient.

About 19% of twelve bit values are at or above `q` (4096 − 3329 = 767), so
rejection is not a rare path to be hand-waved; it happens several times
per polynomial.

### `A_hat[i][j]` comes from `XOF(rho, j, i)`, indices reversed

FIPS 203 orders them that way so the transpose can be generated by
swapping two bytes rather than transposing a matrix, which encapsulation
needs. Writing it the obvious way round gives `A` transposed - and then
key generation and encapsulation disagree, so **every decapsulation
returns the implicit-rejection secret rather than the right one**. That
looks like a correct implementation of the failure path rather than a bug,
which is the worst available shape.

`test_sample_ntt_is_reduced_and_depends_on_every_input` requires
`XOF(rho, 0, 1)` and `XOF(rho, 1, 0)` to differ, because if they did not
the mistake would be undetectable.

### `G` is fed `d ‖ k`, and the `k` was added late

The domain separator - the parameter set's `k` as one byte after the seed
- is in the final FIPS 203 and **absent from the round-three Kyber
submission**. An implementation written from the older document produces
different keys from the same seed, with nothing to say so. Caught by the
ACVP `keyGen` vectors, which is one of several things in key generation
that only a published vector can settle.

### `SamplePolyCBD` subtracts, and the difference is signed

Each coefficient is `x - y` where `x` and `y` are sums of `eta` bits, so
it lies in `[-eta, eta]` and is taken mod `q` - a negative value becomes
one just below `q`. Taking the absolute value, or clamping at zero, gives
a distribution that is not centred and secrets that are not small in the
way the security proof needs, while still producing small-looking numbers.

`test_sample_poly_cbd_is_small_and_centred` requires both signs to appear
in quantity, and `test_the_binomial_distribution_has_the_right_shape`
checks the 1/16, 4/16, 6/16, 4/16, 1/16 profile at `eta = 2` - a uniform
or one-sided distribution fails both.

The bit order is `BytesToBits`, little-endian within each byte, the same
convention as the encodings, and the stride is `2 * eta` per coefficient
because each one consumes two runs of `eta` bits.

### `ByteDecode_12` reduces mod `q` and the narrower widths do not

FIPS 203 decodes with modulus `2^d` below twelve bits and with modulus
`q` at twelve, because a twelve bit field can hold 4095 while a
coefficient must be below 3329. So a field holding 3400 decodes to 71,
and re-encoding gives different bytes.

**That asymmetry is the whole content of the encapsulation key check.** A
key whose coefficients are not canonical is rejected by decoding and
re-encoding and comparing; a `ByteDecode_12` without the reduction makes
that check compare a value with itself and **accept every key**, and the
malleability it exists to stop - two byte strings being one key - comes
back. See `modulus_check`, and
`test_twelve_bit_decoding_reduces_mod_q`, which requires the round trip
to *fail* on a non-canonical input.

The bit order is little-endian within each byte and integers run across
byte boundaries, so at twelve bits a coefficient's low eight bits are in
one byte and its high four in the low nibble of the next. Packing most
significant bit first round-trips against itself perfectly and matches
nothing; `test_the_bit_order_is_little_endian_within_each_byte` pins it on
hand-worked values rather than by round tripping.

### The two key checks cover different things, and one is not about authenticity

`modulus_check` covers the packed coefficients and **not** the 32 byte
seed `rho` that follows them - changing `rho` gives a different, perfectly
well-formed key. A test that expected the check to catch that would be
asserting the wrong property, so
`test_the_key_checks_accept_real_keys_and_refuse_altered_ones` requires
the modulus check to *pass* on a key with an altered seed.

`hash_check` is the other half: `dk` carries `H(ek)` inside it, so an
altered embedded `ek` or an altered embedded hash is detectable. Neither
check is a signature, and neither says the key was generated honestly.

A wrong length is `Ok(false)` from both rather than an error: the caller
asked whether this is a valid key and the answer is no.

### Reduction is `% Q` on a constant, deliberately

`Q` is a compile-time constant, so LLVM emits a multiply and a shift: no
division instruction, no data-dependent branch. **Accepted** rather than
mitigated with a hand-written Barrett or Montgomery reduction, which would
be new code to get wrong for no measured gain. What must not appear is `%`
by a modulus that is *not* a constant - and one did, in `ByteDecode_d`;
see "No division on a secret" below.

### Decapsulation must not report a mismatch - and a round trip cannot see whether it does

The FO transform decrypts, re-encrypts what it recovered, and compares
with the ciphertext it was given. On a mismatch FIPS 203 returns
`J(z ‖ c)` - pseudorandom, derived from a secret seed and the
ciphertext - and **not an error**. A decapsulation that returned `Err`,
or took observably longer, on a mismatch is a decryption oracle.

`decapsulate_internal` returns `Result`, but only for public facts
checked before anything secret is touched: the ciphertext length and
the decapsulation key's hash check. The comparison folds every byte's
difference into one word, turns it into a mask with
`bignum::ct::mask_is_zero`, and blends the two candidate secrets byte by
byte with `select`; both candidates are always computed.

Four ways to get this wrong, each of which round-trips perfectly, and the
test that catches it:

* **A comparison that always says "equal"** - no implicit rejection at
  all. Every honest round trip still works. Caught by NIST's
  decapsulation vectors, but only because they include rejected
  ciphertexts, which nothing guaranteed: `test_every_decapsulation_vector`
  **measures** that 5 of the 10 cases in each parameter set take each
  path - computing `J(z ‖ c)` itself from SHAKE-256 rather than through
  the module's helper - and fails if any set takes only one.
* **A comparison that always says "different"** - every decapsulation
  returns the rejection secret. Looks like a correct implementation of
  the failure path. Caught by the accepted half of the same cases.
* **A comparison over part of the ciphertext** - an altered byte past the
  part compared goes unnoticed. `test_round_trip_and_implicit_rejection`
  alters the first byte of `u`, the last byte of `u` and the last byte of
  `v`, the three places a short loop would stop before.
* **`J` fed `c ‖ z` rather than `z ‖ c`**. Self-consistent and wrong;
  only NIST's rejected cases see it.

**Mitigated, and measured**: `scripts/ct_check.py`'s `ml_kem_decaps` and
`ml_kem_decaps_reject` rows mark `dk_pke` and `z` secret and require no
report from either path - so the comparison, the select, and everything
in decryption and re-encryption are checked to reach no branch and no
index on a secret. `ml_kem_encaps` does the same for `m`.

### The range checks were the leak, not the arithmetic

The first valgrind run of decapsulation reported three sites, all of them
**validation**: `ByteEncode_d` refusing a coefficient that does not fit,
`Compress` refusing one at or above `q`, `Decompress` refusing one wider
than `d` bits. Each is a branch per coefficient, and on K-PKE's paths the
coefficients are secret. None of them ever fires - the inputs are in
range by construction - but a branch on a secret is a branch on a secret,
and memcheck is right to say so.

The public functions keep their checks, because a caller outside the
module can hand them anything. K-PKE calls `_unchecked` versions instead,
which check only the public width `d` and `debug_assert!` the range, so a
precondition broken by a future change still fails every test. The
`ml_kem_compress_checked` row is the control: the checked `compress` on a
secret polynomial, which must report - if it ever comes back clean, the
clean rows above it mean nothing.

### No division on a secret: KyberSlash

`ByteDecode_d` reduced with `value % modulus`, the modulus chosen at run
time from `d`. That compiles to a `div` instruction, and this function
decodes secrets - `s_hat` out of `dk`, and the message during
decapsulation. Division latency depends on the operands on many
processors; KyberSlash (2023-24) recovered Kyber secret keys from exactly
this class of instruction, in implementations whose compression step
divided a secret by `q`.

Valgrind cannot see it: a `div` is not a branch. **Found by disassembly**
and fixed by branching on the public `d` instead - `% Q` on the constant
at twelve bits, which compiles to a multiply, and nothing at all below
twelve, where the field is already below `2^d`. `Decompress`'s division by
`2^(d+1)` is now written as the shift it is rather than left for the
optimiser to recognise.

`scripts/ct_check.py` now disassembles the harness and fails on any `div`
in an ML-KEM function, or any call to the compiler's wide-division
routines. Its control is a function in the harness that does nothing but
divide, which the scan must find - because the first version of the
control looked for a division in `bignum` and found none (its 128 bit
divisions are calls, not instructions), which is exactly the vacuous
pass the control exists to stop.

What the scan does not cover: a compiler on another target, or at
another optimisation level, turning `% Q` back into a `div`. The scan
runs on the build in front of it, and on nothing else.

### The second ML-KEM is a second reading, not a second opinion

`scripts/diff_check.py`'s ML-KEM takes different routes from ours where
FIPS 203 allows - the NTT as residues modulo `X^2 - gamma_i` and its
inverse as interpolation, not butterflies - so a fault in the butterfly
network has nothing to hide behind there. But where the standard fixes
a choice, both were written from the same reading of it: the order of
`XOF`'s index bytes, the PRF counter, which `eta` goes where. A
misreading of those that NIST's 195 cases happened not to reach would be
in both, and the 600 differential cases would agree with it. It runs
NIST's cases itself before it checks ours, so a misreading would have to
get past those first.

### Encryption uses `A` transposed, by indexing rather than by a second sampler

Key generation computes `A_hat * s_hat`; encryption computes
`A_hat^T * y_hat`. FIPS 203 lets the transpose be sampled directly by
swapping `XOF`'s index bytes, but that is two samplers that must stay in
step. `sample_matrix` is called by both, and `kpke_encrypt` reads
`a_hat[j][i]`. Getting it the wrong way round gives ciphertexts that
**decapsulate to the rejection secret every time**, which is the
failure-path-shaped bug again; caught by the encapsulation vectors, whose
first 64 bytes are the start of `u` and localise it.

### One PRF counter runs across `y`, `e1` and `e2`

`N` is incremented after every `SamplePolyCBD` call in encryption and
never reset, so `e1` starts at `k` and `e2` is at `2k`. `y` uses `eta1`,
`e1` and `e2` use `eta2` - which are the same number at ML-KEM-768 and
-1024, so **only ML-KEM-512 can tell them apart**; a test run at one
parameter set would not.

### The message is decompressed with `d = 1`, which is `round(q/2)`

`mu = Decompress_1(ByteDecode_1(m))` puts each message bit at 0 or 1665.
Adding the raw bits instead gives noise-sized offsets that decryption
rounds away, so the message recovered is all zeros, and an honest round
trip fails - this one does not hide.

### Decryption's sign does not matter, and that is not a bug to look for

`Compress_1(q - x) == Compress_1(x)` for every `x` in `[0, q)` - checked
exhaustively - because `q` is odd and so there are no ties. Computing
`u·s - v` instead of `v - u·s` therefore recovers the same message. It
is recorded so that nobody spends time on it: a sweep that introduced
that change would report it missed, correctly.

### The key checks are called by the operations, not merely present

FIPS 203 sections 7.2 and 7.3 make the modulus check and the hash check
input checks on encapsulation and decapsulation. A correct check that
the operation forgot to call passes every test of the check.
`test_the_key_check_vectors` runs NIST's 60 key-check cases - 30 of them
keys that must be refused - through `modulus_check`/`hash_check` *and*
through `encapsulate_internal`/`decapsulate_internal`, and requires the
same verdict from both. Both checks refuse with an `Err`, which is safe
here because the keys are inputs whose validity is public.

## 7w. ML-DSA, where a valid signature can still be the wrong one

Key generation, signing and verification, in `src/pq/ml_dsa/`, checked
against every vendored ACVP case: 75 key generations, 72 signatures from
all 24 signing groups, 60 verifications of which 48 are refusals; with
an `api` type, Python bindings, a second reading in `diff_check.py`, and
a `ct_check.py` row for signing.

### A signer that skips a rejection still produces signatures that verify

Signing loops: draw a mask `y`, form `z = y + c*s1`, and discard the
attempt unless `z`, the low bits of `w - c*s2`, and `c*t0` are all small
enough, and the hint has at most `omega` ones. The checks exist because
an attempt that fails one of them **leaks information about `s1` or
`s2`**; the verifier re-checks only `z`'s bound. So a signer that skipped
the `r0` check, or compared against `gamma2` instead of `gamma2 - beta`,
would produce signatures every verifier accepts, and would give up the
key over enough of them.

**Mitigated** by the deterministic signing vectors - for two of the four
checks. A rejection skipped or mis-bounded changes which attempt is
returned, and with it every byte of the signature; the breakage sweep
made the `z` and `r0` changes and the vectors caught both.

**They did not catch the other two.** Skipping the `c*t0` check, or the
hint count, passed all 72 signing vectors, because those checks almost
never fire: `||c*t0||∞` is a sum of `tau` terms each below `2^12`, and
reaching `gamma2` needs most of 39 signs to line up at ML-DSA-44 and is
impossible at the other two sets. A check that never fires on any input
anyone has is a check nobody tests. So the decision is now one function,
`accepted`, tested at each bound - at the bound refused, one below
accepted - and the sweep's mutants of it are caught there.

### The verifier's bound on `z` needed a forbidden signature to test it

The same sweep removed verification's check that `||z||∞ < gamma1 - beta`
and nothing failed: NIST's "modified signature - z" cases alter `z` in a
way the commitment comparison already catches, and an honest signer never
produces a large `z`. The test now makes one. The signing loop takes its
rejection test as a parameter (`sign_with`, crate-private), and
`test_verification_refuses_z_past_its_bound` passes one that keeps *only*
attempts whose `z` is in `[gamma1 - beta, gamma1)` - a signature whose
commitment matches and whose only fault is `z`. The verifier refuses it;
an honest signature on the same `mu` is accepted.

### `UseHint` at `r0 = 0`

Zero is "not positive", so a hint moves the high part *down*. The sweep
changed `r0 > 0` to `r0 >= 0` and nothing failed - 20,000 random cases
never produce `r0 = 0` with a set hint, which needs `z = -gamma2`
exactly. `test_use_hint_treats_zero_as_not_positive` builds that case.

### `kappa` advances by `l`

`ExpandMask` derives the attempt's `l` mask polynomials from counters
`kappa .. kappa + l`. The next attempt starts at `kappa + l`. Advancing
by one reuses `l - 1` polynomials of the previous mask under a new
challenge - two signatures-in-waiting sharing most of their `y` - which
is the classic way a Fiat-Shamir-with-aborts signature leaks its key.
Caught by the deterministic vectors for the same reason as above, the
first time an attempt is rejected.

### Two centred reductions, both inclusive at the top

`r mod± a` lands in `(-a/2, a/2]`. `Power2Round` (with `2^13`) and
`Decompose` (with `2*gamma2`) both use it, and getting the upper end
wrong moves one value in `a`. `Decompose` has a further special case:
when `r - r0 = q - 1` the high part would be one past the largest `w1`
can encode, so FIPS 204 sets it to 0 and lowers `r0` by one. Both are
pinned by unit tests in `round.rs` on hand-chosen values, because a
random sample rarely lands on them.

### No division by a run-time `gamma2`

`Decompose` reduces and divides by `2*gamma2`, on secrets, every signing
attempt. `gamma2` is one of two values, so it is an enum - `Gamma2` -
and each value reaches the arithmetic through a const generic. Every
division in `round.rs` is by a compile-time constant and compiles to a
multiply. The ML-KEM lesson, applied before rather than after: see
"No division on a secret" in section 7v.

### `ExpandA` puts the column first, and `SampleInBall` takes all of `c-tilde`

`A[r][s]` comes from `rho ‖ s ‖ r`. And the final FIPS 204 hashes the
whole `lambda/4` byte commitment into the challenge, where the draft took
its first 32 bytes; at ML-DSA-44 those agree, at the other two sets they
do not. Both are settled by the vectors and both are in the sweep.

### The hint encoding refuses second encodings

`HintBitUnpack` returns "invalid" for positions that are not strictly
increasing within a polynomial, a cumulative count that falls or passes
`omega`, and a non-zero byte in the unused tail - each a second encoding
of the same hint, which would make signatures malleable. Each check has
its own case in `encode.rs`'s
`test_every_malformed_hint_encoding_is_refused`, and NIST's "modified
signature - hint" cases are refused.

### A wrong-length signature is `Ok(false)`

As for SLH-DSA, and for the same reason: ACVP expects it refused, and a
caller should not have to tell "too short" from "wrong". `Err` is for a
public key of the wrong length.

### Signing is a loop, and the loop is allowed to show; nothing else is

The number of attempts a signature took is visible to anyone timing it,
and FIPS 204 accepts that - it depends on the mask `y`, not on the key.
What must not show is anything finer: which bound rejected an attempt,
or the values the bounds were applied to. `scripts/ct_check.py`'s
`ml_dsa_sign` row marks `K`, `s1`, `s2` and `t0` secret and allows
reports in exactly three places:

* the one branch on whether an attempt is kept - `accepted` combines its
  four comparisons with `&` rather than `&&`, so short-circuiting does
  not reveal which one failed;
* `SampleInBall`, which rejection-samples from `c-tilde` and writes at
  positions it chooses. `c-tilde` hashes `mu` and the commitment's high
  bits, not the key, and for the returned attempt it is in the signature.
  For rejected attempts it is never published, and whether its timing
  then matters is **open** here - listed, not argued away;
* `HintBitPack`, on the returned attempt's hint, which is published.

**The first valgrind run named four more**, all fixed: `Decompose`'s
top-value test, the centred reductions in `Decompose` and
`Power2Round`, the infinity norms (a branchy `max` and `abs`), and the
hint count. They are arithmetic now. One came back once more after it
was rewritten - the optimiser turned `Decompose`'s mask back into a
conditional move - until the masks went through `bignum::ct::opaque`,
which exists for exactly that.

**What the row can and cannot see.** A five-fault sweep put branches
back: the `Decompose` top-value `if` and `&&` in `accepted` were caught.
The other three - an `if` in the centred reduction, `if bit { ones += 1 }`
for the hint count, and `greater` without `opaque` - were **not**, and
that is correct: this compiler emitted no branch for any of them, so the
binary under test was the same. valgrind judges the build in front of
it. The source is arithmetic anyway because a different compiler, or a
different optimisation level, is free to make the other choice - and
`Decompose` shows that this one sometimes does.

The division scan covers ML-DSA as well as ML-KEM, and finds none:
`gamma2` reaches every division as a compile-time constant.

## 7x. Hybrid post-quantum key exchange in TLS 1.3

RFC 10024's X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024,
in `src/tls/kex.rs`. The share and secret sizes are RFC 10024's table,
checked by `test_hybrid_sizes_are_what_rfc_10024_tabulates`.

### The concatenation order differs between the groups

X25519MLKEM768 is ML-KEM first - in the client's share, the server's
share and the shared secret. SecP256r1MLKEM768 and SecP384r1MLKEM1024 are
classical first, in all three. A single rule gets one kind wrong, and
**our client and our server agree with each other either way**, so no
loopback test can see it. **Mitigated**: the order lives in one table
(`groups::hybrid`), and
`test_the_secret_is_the_two_secrets_in_the_groups_order` builds a server
answer from the ML-KEM and X25519/P-256 primitives and checks the
client's secret against the RFC's order. What settles it is the
handshakes against independent implementations: OpenSSL 3.5, all three
groups in both directions (`scripts/check_pq_witness.py`), and
Cloudflare's and Google's public servers (`check_live.py --pq`).

### The server encapsulates; it does not exchange

A hybrid group is not Diffie-Hellman with a bigger key. The server never
generates an ML-KEM key pair: it encapsulates to the client's key and
returns the ciphertext. Treating it like DH - generate, then complete -
has nowhere to put the ciphertext. Hence `EphemeralKey::respond`, which
for a DH group is generate-then-complete and for a hybrid group is
encapsulate.

### The server must run FIPS 203's modulus check on the client's key

RFC 10024 4.2 requires it, and `MlKemPublicKey::from_public` does it: a
client share whose ML-KEM key has a coefficient encoded at or above `q`
is refused with `illegal_parameter`. Tested with a non-canonical key.

### Lengths are exact, both ways

The client splits the server's share at a fixed offset and requires the
remainder to be exactly the classical share's length; the server does the
same with the client's. A `<` instead of `!=` accepts a trailing byte
that one side ignores and the other might not. Tested one byte short and
one byte long.

### TLS 1.3 only, and a 1.2-capped client must not mention them

RFC 10024 defines no TLS 1.2 use and a ServerKeyExchange cannot carry a
ciphertext, so a 1.2 ServerKeyExchange naming one is refused by name.
And a ClientHello capped at 1.2 names no hybrid and sends no share: the
1.2 KB share is the part of this most likely to upset the old servers
this library is for, and a caller talking to one has already capped the
version.

## 7y. SSH

`src/ssh/`. Each module's header has its own list; these are the ones
that cost something to find, or would have.

### An `mpint` is two's complement and minimal

A positive number with its top bit set gets a leading zero byte; zero is
the empty string; nothing else may lead with `00` or `ff`. The exchange
hash takes the shared secret `K` as an mpint, so getting this wrong
fails one key exchange in two (the sign byte) or one in 256 (the zero
case) and works the rest of the time. **Mitigated**: `ssh::wire` reads
RFC 4251's own examples out of the document, and refuses every
non-minimal encoding on the way in.

### `ssh-rsa` blobs put `e` before `n`

Every other RSA encoding in this library leads with the modulus. Both
are mpints, so the wrong order parses. **Mitigated**: a test pins the
byte layout, and fingerprints of nine OpenSSH keys, RSA among them,
match `ssh-keygen -l`.

### `chacha20-poly1305@openssh.com` is not RFC 8439

Original ChaCha20 (64 bit nonce = the sequence number, 64 bit counter),
the 64 byte key split with the *second* half encrypting the length, and
Poly1305 over the ciphertext with no padding or length block. An RFC
8439 AEAD is wrong in four places at once. **Mitigated**: OpenSSH's
`chacha20-poly1305` key files decrypt, and ours are read by OpenSSH.
The packet layer uses the same `Cipher::crypt`, and the recorded
sessions cover it.

### An AEAD tag in a key file sits outside the string

In `openssh-key-v1`, the encrypted private section is a `string` whose
length counts the ciphertext only; GCM's and ChaCha20-Poly1305's tag
follows it with no length of its own. **Mitigated**: OpenSSH's files
under both read.

### bcrypt_pbkdf interleaves its output

Byte `i` of block `n` goes to `i * stride + n`. Concatenating, as PBKDF2
does, agrees with OpenSSH for keys of 32 bytes or less and for nothing
longer - and `aes256-ctr` wants 48. **Mitigated**: 83 encrypted OpenSSH
files - seventy from 10.0 and thirteen from 7.4 - under sixteen ciphers,
key and IV lengths from 16 to 64 bytes.

### A key file carries the public key twice

Once in the header and once inside the private section, and nothing in
the format makes them agree. A file whose halves differ signs as a key
other than the one it names. **Mitigated**: the public key is
recomputed from the private one on every read and must equal the
header's; RSA is rebuilt from `p`, `q` and `e`, and the file's `d` and
`iqmp` are not trusted.

### SSHSIG's RSA algorithm follows its hash

`ssh-keygen -Y sign -O hashalg=sha256` signs an RSA key with
`rsa-sha2-256`, not `rsa-sha2-512`. The first version always used 512,
verified fine, and matched OpenSSH byte for byte on every sha512 row and
no sha256 one - which only a byte comparison could see, since both
verify. **Mitigated**: Ed25519 and RSA SSHSIG output is compared with
OpenSSH's byte for byte, eight rows.

### `K` is an mpint for some methods and a string for others

Diffie-Hellman, ECDH and Curve25519 put the shared secret into the
exchange hash and the key derivation as an mpint; the post-quantum
hybrid puts its (already hashed) secret in as a string. For a 32 byte
secret the two encodings are **the same bytes unless the top bit is
set**, so a session tells them apart only half the time, and a test
built on one recorded session may never have. **Mitigated**: 57 live
sessions against sshd, and the recorded sessions the gate replays were
re-recorded until at least two Curve25519 and two hybrid secrets had
the top bit set - checked by instrumenting the secret's first byte and
by confirming that swapping the two encodings then fails the replay. A
re-recording has to be checked the same way; `docs/building.md` says
how.

### Strict key exchange, and the sequence numbers it resets

Without `kex-strict-*-v00@openssh.com`, an attacker on the path can add
an IGNORE before NEWKEYS and delete the server's first encrypted
packet, and the shifted sequence numbers hide it (Terrapin,
CVE-2023-48795). With it, the initial exchange admits nothing but key
exchange messages, KEXINIT must be the first packet, and the sequence
numbers restart at each NEWKEYS. **Mitigated**: the client advertises it
and enforces all three when the server does too; every recorded session
ran with it on.

### An RSA host key negotiated as `rsa-sha2-512` must sign as that

The signature blob names its algorithm, and an RSA key can produce
three. A server that signs the exchange hash as `ssh-rsa` after
`rsa-sha2-512` was negotiated is downgrading to SHA-1. **Mitigated**:
the client requires the name to be the negotiated one.

### RSA user authentication depends on EXT_INFO

`ssh-rsa` (SHA-1) is all an old server knows, and OpenSSH 8.8 and later
refuse it. A server that sends `server-sig-algs` gets `rsa-sha2-512`; one
that sends no EXT_INFO is assumed old and gets `ssh-rsa` - which is
OpenSSH's own client's rule. A modern server that omits EXT_INFO would
refuse that signature; none known does.

### DSA's `k` is the private key, one signature away

`publickey_ciphers::dsa`, for `ssh-dss` and the certificates and TLS
servers of the same era. Whoever learns one signature's `k` computes
`x`; two signatures sharing `k` reveal it by subtraction - the PS3 and
Android Bitcoin wallets. **Mitigated**: `k` comes from RFC 6979's HMAC
DRBG, the generator ECDSA here already used, and all twenty of RFC
6979's DSA signatures (two groups, five hashes, two messages) are read
out of the RFC and reproduced, `k` included - one of them only after
the generator's first candidate is rejected as `>= q`, which is the
retry path's only test. The same document's P-256, P-384 and P-521
signatures now check ECDSA the same way.

### `ssh-dss` signatures are 40 bytes, not mpints

`r` and `s` are 20 bytes each, padded, concatenated (RFC 4253 6.6). A
signature whose `r` happened to be short is still 40 bytes; reading two
mpints instead fails one signature in 128. **Mitigated** by OpenSSH 7.4
accepting ours: as user keys in `scripts/check_ssh_client.py` (28
sessions) and as host keys in `scripts/check_ssh_server.py` (39
sessions).

### RC4 throws away its first 1536 bytes - or not

`arcfour` (RFC 4253) uses RC4 from its first byte; `arcfour128` and
`arcfour256` (RFC 4345) discard 1536 bytes of keystream first, because
RC4's early output is biased. The three are different ciphers under the
same name stem. **Mitigated**: all three against OpenSSH 7.4.

### The namespace is the point of SSHSIG

A signature made for `git` must not verify as one for `file`. The
namespace is inside what is signed; a verifier that does not insist on
the one it expects has thrown that away. `sshsig_verify` takes the
expected namespace as an argument and refuses any other.

### Old SSH is most of SSH's installed base

Not a bug but the reason for scope: switches, UPS cards and storage
controllers run SSH servers frozen at `diffie-hellman-group1-sha1`,
`ssh-dss`, `3des-cbc` or `arcfour` and `hmac-md5`, which current OpenSSH
refuses or has removed. Each is implemented here, left out of the
default offer, and reachable by naming it, as in TLS.

## 7z. Streamlined NTRU Prime

`src/pq/sntrup.rs`, for SSH's `sntrup761x25519-sha512`.

### The random source's call pattern is part of the test vectors

NIST's KAT DRBG discards the unused end of the last block of every call.
The reference calls it for four bytes per `urandom32` and for 191 bytes
of `rho`; drawing the same total in other pieces gives different bytes,
and an implementation that is entirely correct then matches no vector.
**Mitigated**: `Fill` is called in the reference's pieces, and the
draft's two vectors pass through a reimplementation of NIST's DRBG.

### Sorting and inversion run on secrets

`Short_fromlist` sorts random words to place the nonzero coefficients,
and key generation inverts secret polynomials. A sort that branches on
comparisons, or Euclid's algorithm, leaks the secret's shape.
**Mitigated** in the source: a sorting network of masked min/max
(checked against the standard sort), and inversion by a fixed 2p - 1
division steps (checked by multiplying back). Not yet measured under
`ct_check.py`, so whether the compiled code keeps that shape is
**open**.

### Decapsulation selects, it does not fail

A ciphertext that does not re-encrypt to itself yields
`Hash(0, Hash3(rho), C)` instead of an error, and a decrypted `r` of the
wrong weight is replaced by a fixed one. Both choices are masks.

### `K` in SSH is a 64 byte string

`sntrup761x25519-sha512` hashes the two secrets with SHA-512 and puts
the result into the exchange hash as a string, like the ML-KEM hybrid
does with SHA-256. The recorded sessions cover it the same way: at least
one with the top bit set, checked when recorded.

## 7za. UMAC

`src/mac/umac.rs` (RFC 4418), for OpenSSH's `umac-64@openssh.com` and
`umac-128@openssh.com`.

### RFC 4418's longest test vector is misprinted

The appendix's `'a' * 2^25` row - the only one long enough to reach
POLY's 128 bit stage - gives tags nobody computes. Verified erratum 3507
corrects all three. An implementation tested against the printed table
has two choices, both wrong: chase a bug that is not there, or drop the
one row that tests the 128 bit stage. **Mitigated**: the test applies the
erratum to that exact printed line only, and Nettle's tags agree with
the correction (`vectors/umac_nettle.vec`).

### OpenSSH's UMAC stops at 16 MB

OpenSSH's `umac.c` leaves out the 128 bit polynomial, so its own comment
says it is wrong past 2^24 bytes. An SSH packet never gets close, so it
interoperates; it is not a reference for long messages. Nettle is.

### The message is little endian and everything else is big

NH reads the message as little-endian 32 bit words (RFC 4418's
ENDIAN-SWAP); keys, pads, the length added to each chunk's NH and the
tag are big endian. A mistake in either direction is self-consistent.
**Mitigated** by RFC 4418's intermediate values, read out of the document.

### The nonce is the sequence number, and it must not repeat

SSH passes the packet sequence number as an eight byte big-endian nonce
and MACs the packet without it. The tag is the hash xor a pad chosen by
the nonce; one nonce under one key twice leaks the xor of two hashes.
The sequence number repeats only after 2^32 packets, and SSH rekeys far
sooner. For 4 and 8 byte tags, consecutive nonces share one AES block,
indexed by the nonce's low bits. **Mitigated**: four names against
OpenSSH 10.0 and two against 7.4, and the `[ssh]` rows in Nettle's file.

## 7zb. ML-DSA in certificates and TLS 1.3

`src/x509` (RFC 9881) and `src/tls` (draft-ietf-tls-mldsa).

### Two contexts, and only one of them is FIPS 204's

A TLS 1.3 CertificateVerify signs 64 spaces, a context *string*
("TLS 1.3, server CertificateVerify"), a zero byte and the transcript
hash. FIPS 204's ML-DSA.Sign takes a separate *context* argument, and the
draft says it MUST be empty. Passing the TLS string as FIPS 204's context
too gives a signature that both ends of this library agree on and
nobody else accepts. **Mitigated**: OpenSSL 3.5's CertificateVerify from
three real handshakes checks here (`tests/test_ml_dsa_openssl.rs`), ours
checks there (`scripts/check_mldsa_witness.py`), and a test signs with
the TLS string as context and requires it to fail.

### The message, not a digest

As with EdDSA, the scheme hashes internally (SHAKE256), so there is no
`hash_name` for 0x0904-0x0906 and every path that hashes first has to
branch before it does. Those early branches have to carry the state
transition *and* everything the normal path records: the EdDSA branch
set the next state and forgot `peer_signature_scheme`, so an Ed25519
handshake reported no scheme. Found by the first ML-DSA test that
asked; `test_the_peer_scheme_is_recorded_on_the_eddsa_path_too`.

### A private key is a CHOICE, told apart by its tag

`[0]` (0x80) is the 32 byte seed, an OCTET STRING is the expanded key,
a SEQUENCE is both (RFC 9881 section 6, which says not to decide by
length). Every form can be inconsistent - a seed and an expanded key
from different keys, an expanded key whose `tr` is not the hash of its
public key, or whose `t0` is not what `s1` and `s2` give - and RFC 9881
appendix C.4 has one of each. **Mitigated**: the seed is re-expanded
and compared, the expanded key's public half is recomputed, and all
three examples are refused by name.

### keyEncipherment on an ML-DSA certificate

RFC 9881 section 5 forbids it: the key cannot encrypt. A CA that gives
every leaf `digitalSignature | keyEncipherment` - which is what
`CertificateAuthority` did for EC and EdDSA leaves - writes a certificate
a strict verifier refuses. **Mitigated** for ML-DSA leaves; checked by
`test_the_ca_writes_rfc_9881_certificates`.

### `openssl pkeyutl` cannot sign an empty message

`pkeyutl -sign -rawin` on an empty file fails in OpenSSL 3.5.4 with
"Could not allocate 0 bytes for oneshot sign/verify buffer", so the
OpenSSL signature vectors start at one byte. ML-DSA over the empty
message is covered by NIST's ACVP cases instead. **Accepted**.

### Not at TLS 1.2

The draft forbids the schemes there. A server holding only an ML-DSA key
authenticates no 1.2 suite and a 1.2 client gets `handshake_failure`; a
client's ML-DSA certificate is withheld from a 1.2 server (an empty
Certificate, which is legal) rather than signed under a construction
that does not exist.

## 7zc. DSA in certificates and TLS

`src/x509` (RFC 3279, RFC 5758) and the TLS client's DHE_DSS suites.

### Before TLS 1.2 a DSA signature is over SHA-1 alone

RSA's pre-1.2 ServerKeyExchange signature is over MD5 and SHA-1
concatenated; DSA's, like ECDSA's, is over SHA-1 only (RFC 4346 7.4.3).
The default scheme for an absent SignatureAndHashAlgorithm follows the
suite's key exchange, so a DHE_DSS suite must default to DSA-SHA1, not
to the RSA pair. **Mitigated**: OpenSSL DHE_DSS servers at TLS 1.0, 1.1
and 1.2 in `pytests/test_tls_dss.py`.

### The group size is the security, and it is usually 1024 bits

DSA keys in the field are overwhelmingly 1024 bit groups with a 160 bit
`q`. The group is held to `min_rsa_bits` (both are finite-field
problems), which defaults to 2048 - so an old box is reached by lowering
that number, exactly as for RSA, and refused with a message naming it
otherwise. **Accepted** as a policy decision.

### A DSA key can leave its group out

RFC 3279 2.3.2 lets the AlgorithmIdentifier's parameters be absent, the
key then using its issuer's group. Rare and confusing; the key is
carried (`PublicKey::Dsa { parameters: None, .. }`) and verification
refuses it by name rather than as a parse failure. **Open** - nobody has
reported one.

### Two DSA OIDs have no name in python-cryptography

`dsa-with-sha384` and `dsa-with-sha512` (NIST's sigAlgs arc) are known
there by number only, so `signature_hash_algorithm` raises on a
certificate using one. `diff_check.py x509` maps them by dotted string
and has OpenSSL verify our certificates under all five hashes.

### python-cryptography will not sign with SHA-1

So the SHA-1 DSA certificate in the tests is made with the `openssl`
tool, which still will. The old boxes have `dsaWithSHA1`; a test suite
that could only produce SHA-2 would never have seen one.

### The server does no finite-field DHE

This library's TLS server does ECDHE and RSA key transport only, so it
neither offers DHE_RSA nor DHE_DSS. The DSA work is on the client side,
which is the side that needs to reach old equipment.

## 7zd. The SSH server

`src/ssh/server.rs`, with `src/ssh/negotiate.rs` shared with the
client. The module header has the full list.

### The client's order decides the algorithms - on both ends

RFC 4253 7.1 picks, in every category, the first algorithm on the
*client's* list that the server also lists. A server that chose its
own favourite from the overlap would compute a different answer from
the same two KEXINITs than the client does, and the connection would
fail at the first encrypted packet - or only with clients whose order
differs from the developer's. **Mitigated**: one function,
`negotiate::negotiate`, serves both ends; a unit test lists the same
algorithms in opposite orders, and `tests/test_ssh_server.rs` gives the
server its lists reversed.

### A public key query is not a login

RFC 4252 7: a `publickey` request without a signature asks whether the
key would do, and gets `USERAUTH_PK_OK`. OpenSSH's `ssh` always asks
first, so a server that marked the user authenticated there would pass
every test with OpenSSH and accept anybody holding a public key.
**Mitigated**: only the signed request authenticates, and
`test_a_signature_by_another_key_is_refused` presents an authorized
public key with somebody else's signature.

### The signature is over the request as received, under the name it gives

What the user signs is the session identifier and the request bytes; the
server checks the bytes it received rather than an encoding of its own,
and refuses a signature whose algorithm (`ssh-rsa`, SHA-1) is not the
one the request names (`rsa-sha2-512`). **Mitigated**: a unit test signs
under each RSA hash and offers it under another.

### EXT_INFO decides which hash RSA users sign with

Without `server-sig-algs`, a client cannot know the server takes
`rsa-sha2-512` and falls back to `ssh-rsa` - which OpenSSH 8.8 and later
will not send at all. It goes right after the server's first NEWKEYS,
and only if the client's KEXINIT carried `ext-info-c`; earlier would
break strict key exchange. **Mitigated**: OpenSSH 10.0 and 7.4 both
authenticate RSA users as `rsa-sha2-512`, and the in-memory test fails
if EXT_INFO is not sent.

### Nothing but key exchange during a key exchange

Once a side has sent KEXINIT it may send only key exchange messages
until its NEWKEYS. Output the caller writes in that interval is held and
goes out under the new keys. **Mitigated**: a 3 MB echo with a
re-exchange the server starts mid-stream, and OpenSSH's `ssh` re-keying
every megabyte (`RekeyLimit`) through 5 MB.

### The window is opened only as input is taken

Re-opening the client's window as data arrives would let a client make
the server buffer without bound while the caller is busy. The window is
re-opened by `take_stdin`. **Accepted** consequence: a caller that never
takes standard input stalls a client that sends more than 2 MiB.

### `ssh -tt` closes the session if its terminal is refused

With a forced terminal, OpenSSH treats a refused `pty-req` as fatal and
exits 255 without running the command. The server accepts the request
and records it (`terminal()`) without making a pty; what a terminal
means for the command is the caller's to decide. **Mitigated**: `ssh -tt`
rows against 10.0 and 7.4, one recorded.

### Passwords are compared through a hash, all of them

Each configured password is hashed with SHA-256 and compared without an
early exit, and every entry is compared whatever the user, so the time
taken says neither how far a guess matched nor which users have
passwords. **Accepted**: the user name lookup for keys is an ordinary
comparison; user names are not secrets SSH protects.

### Signatures are deterministic, which the replay relies on

Ed25519, RFC 6979 ECDSA and DSA, and RSA PKCS#1 v1.5 involve no
randomness, and every other random byte - cookie, padding, ephemeral
keys, the ML-KEM encapsulation's `m` - comes from the server's random
source. That is what lets `tests/test_ssh_server_sessions.rs` feed
OpenSSH's recorded bytes to a seeded server and require identical
output. The ML-KEM encapsulation drew from the operating system before
this; a server built on `MlKemPublicKey::encapsulate` could not be
replayed.

## 7ze. LRW

`src/block_ciphers/lrw.rs`, the disk mode IEEE P1619 drafted before
XTS: dm-crypt's `lrw-*` and TrueCrypt 4's volumes.

### Three fields, one polynomial

LRW, XTS and GCM all multiply in GF(2^128) modulo
`x^128 + x^7 + x^2 + x + 1`, and each writes field elements differently:
LRW as big endian integers (bit `k` is `x^k`), XTS little endian, GCM
bit-reflected. A multiplication borrowed from either of the others
passes the first IEEE vector, whose index is 1, and nothing after it.
**Mitigated**: all nine of IEEE P1619's vectors as the kernel carries
them, including a counter that wraps from all ones; and a LUKS1 volume
the kernel wrote in `lrw-plain64` decrypts to its filesystem.

### The index counts blocks

`T = K2 * I` with `I` the index of the block, not the sector. dm-crypt
hands LRW its IV as the first block's index; with `plain64` that is
the sector number's little endian bytes read as a big endian number -
odd, and what is on the disk. `benbi` gives the true block index.

## 7zf. The LUKS example

`examples/products/luks`. Not the library's API; a product format built
on it, with the product's own tool as judge.

### A 4096 byte sector's IV is still counted in 512 byte sectors

dm-crypt's `iv_large_sectors` counts IVs in the sector size, and
cryptsetup sets it for BitLocker only. A LUKS2 volume with 4096 byte
sectors gives sector `n` the IV `8n`. Counting in the sector size
decrypts the first sector and garbles the rest. **Mitigated**: data
cryptsetup encrypted with 4096 byte sectors, in the fixtures.

### ESSIV hashes the whole key, XTS's two halves together

ESSIV's IV key is the hash of the key the data cipher was given; under
XTS that is both halves. And the result goes through XTS's own tweak
encryption as well, so an XTS-ESSIV sector's IV is encrypted twice.
**Mitigated**: the kernel-written `aes-xts-essiv:wp256` test volume.

### The anti-forensic splitter's counter is big endian

Each digest-sized piece is hashed with its index in front as a big
endian u32. Index 0 is the same either way, so little endian merges
correctly whenever the key fits in one digest - a 32 byte key under
SHA-256 - and fails as soon as it does not. **Mitigated**: a fixture
with a 32 byte key under SHA-1, whose digest is 20 bytes; and 64 byte
keys under SHA-512 against cryptsetup in the hand-run check.

### cryptsetup fills unused keyslot space with random bytes

So an image's size is mostly noise that nothing reads. The fixtures keep
only the headers, the active keyslots' material and the data recorded;
`scripts/check_luks.py` says so in the file it writes.

## 7zg. The TrueCrypt and VeraCrypt example

`examples/products/veracrypt`.

### TrueCrypt's Blowfish is little endian

TrueCrypt reads Blowfish's block as two little-endian words, where the
cipher's own definition is big endian. Ordinary Blowfish opens no
TrueCrypt volume, and its self-consistent round trip says nothing about
which reading is right. **Mitigated**: the library's `blowfish-le`;
its unit test pins it as Blowfish with each half's bytes reversed, and
`scripts/check_veracrypt.py` opens TrueCrypt's own Blowfish volumes
with it. No offline test has a Blowfish volume, so the sweep that read
the block big endian was caught by the unit test alone.

### Cascade names run backwards

VeraCrypt's `AES-Twofish-Serpent` encrypts with Serpent first, and its
key area holds Serpent's key first. The name is the ciphers from last
applied to first. cryptsetup's test volumes are named the VeraCrypt way
but for the Camellia and Kuznyechik cascades, which are named in the
order applied. **Mitigated**: the check accepts either, and the
filesystem inside decides.

### Three data unit numberings

XTS numbers 512 byte data units from the start of the volume - the
first data sector of a normal volume is unit 256, not 0. LRW numbers
from the start of the data area, as block index `32n + 1`. TrueCrypt's
CBC numbers from the header's data offset field, which is empty (so
512) in a legacy hidden volume - its IVs start at sector 1 wherever its
data lies, which a legacy hidden test volume showed by refusing to
give up its filesystem until the rule was right. **Mitigated** for all
three by cryptsetup's test volumes in `scripts/check_veracrypt.py`,
which is run by hand; the offline fixtures are XTS volumes only.

### A system volume can use the ordinary key derivations

VeraCrypt has pre-boot iteration counts for SHA-256, BLAKE2s and
RIPEMD-160 only; a system volume under SHA-512 or Whirlpool uses the
ordinary count. Trying pre-boot counts alone for a system volume opened
the MBR test drives and not the GPT one.

### A long password changes the keyfile pool

VeraCrypt passwords may be 128 bytes; with keyfiles, a password over
64 bytes makes the pool 128 bytes, and TrueCrypt's 64 byte pool cannot
hold it. A search that treats "too long for TrueCrypt" as an error
rather than skipping TrueCrypt's derivations never reaches VeraCrypt's.

### Data the example refuses to guess

TrueCrypt 1.0's Blowfish, and the CBC cascades of TrueCrypt before 4.1,
decrypt their headers here but not their data: the IV and whitening
that work for CAST5 and Triple DES give noise under Blowfish, and no
program at hand reads those volumes' data to compare with. The example
says so rather than returning bytes. **Open.**

## 7zh. The age example

`examples/products/age`.

### A full final chunk looks like an ordinary one

The last chunk of the payload may be a full 64 KiB, so its length does
not say it is last; age's reader tries a full chunk as ordinary first
and as final second, and a final chunk followed by anything is an
error after its plaintext has been released. A reader that calls the
last-by-length chunk final fails the same files and releases a chunk
less before failing - which the test vectors' `payload` hashes catch,
and eight of them did.

### The nonce belongs to the header

A file that ends within the 16 byte payload nonce fails as a malformed
header, not a payload failure, in age's taxonomy; and an scrypt work
factor past the reader's limit is a header failure too, not a stanza
that is someone else's.

### X-Wing's combiner order

SHA3-256 over the ML-KEM secret, the X25519 secret, the X25519
ciphertext, the X25519 public key and then the six byte label - the
label last; and of SHAKE256's 96 bytes from the seed, ML-KEM's 64
come first and X25519's 32 after. **Mitigated**: the hybrid test
vectors, and age 1.3.2 both ways.

## 7zi. OCB

`src/block_ciphers/ocb.rs`, RFC 7253.

### A shorter tag is a different mode

The nonce block's top seven bits are `TAGLEN mod 128`, so a 96 bit tag
is not the first twelve bytes of the 128 bit one and the ciphertext
differs too - unlike EAX, where truncation is a prefix. Code that
truncates a 16 byte OCB tag to fit a field produces tags nobody else
accepts. **Mitigated**: the RFC's 96 bit sample and its iterated
vectors at 96 and 64 bits; `test_a_shorter_tag_is_a_different_mode`.

### `Offset_0` is a window into 192 bits

`Ktop` is shared by sixty-four consecutive nonces, and the low six bits
choose where a 128 bit window starts in `Ktop || (Ktop[1..64] ^
Ktop[9..72])`. A shift by the wrong amount, or the tail taken from the
wrong byte, is right whenever `bottom` is 0 - a nonce ending in a
multiple of 64. **Mitigated**: the RFC's internal values at
`bottom = 15`, and the `ocb` differential corpus asserts it reached all
64 values against OpenSSL.

### `double` is big endian

The same polynomial as XTS and GHASH and the same convention as LRW and
MGM: shift left across the block, `0x87` into the last byte. An `L`
table built with XTS's doubling gives a mode that round-trips.
**Mitigated**: the RFC's `L_*`, `L_$`, `L_0`, `L_1`.

### 128 bit blocks only

There is a 64 bit OCB in the literature with its own constants; RFC
7253 does not define it, so the 64 bit ciphers are refused rather than
run with the 128 bit polynomial.

## 7zj. The OpenPGP example

`examples/products/openpgp`.

### Two CFBs, one byte apart

The Symmetrically Encrypted Data packet (tag 9) resynchronises after its
random prefix: the rest is CFB under the IV formed from ciphertext bytes
2 to block+2. SEIPD version 1 does not; it is one CFB from a zero IV over
prefix, data and MDC. Reading one as the other gives the right prefix
check bytes and garbage after them. **Mitigated**: GnuPG's tag 9 and
SEIPD messages, both in the fixtures and both directions live.

### The nonce and the associated data differ between the two AEAD packets

LibrePGP's OCB packet XORs the chunk index into the low eight bytes of
its IV and puts the index into the associated data as well; RFC 9580's
SEIPD v2 appends the index to an HKDF-derived IV and leaves it out of
the associated data. Both put the total length into the final tag's
associated data, and both count the final tag as the next index. An
empty message has no chunks, only the final tag at index 0.
**Mitigated**: LibrePGP's A.3 and RFC 9580's A.9 to A.11, GnuPG's OCB
packets of 0 bytes and in 64 byte chunks, go-crypto's v2 SEIPD.

### A version 4 SKESK may be the session key

With no encrypted session key, the S2K output is the session key, under
the SKESK's cipher; `gpg -c` writes exactly that. Several passphrases,
or a passphrase and a public key, need the encrypted form, since one
S2K output cannot be every passphrase's. **Mitigated**:
`test_a_single_passphrase_is_the_session_key` and GnuPG decrypting
both forms.

### GnuPG reads an S2K count of 1024 as "use the agent's"

`--s2k-count 1024` is the documented minimum and is turned into "auto
calibrate", which gives the maximum, 65 MB of hashing; 2048 is
honoured. Not a problem of ours, but it decides how fast the recorded
fixtures are to test.

### GnuPG's version 5 keys put a 20 byte fingerprint into the ECDH KDF

RFC 6637's KDF parameters end with the recipient's fingerprint, written
for 20 byte ones. RFC 9580 puts a version 6 key's whole 32 bytes there;
GnuPG puts the first 20 of a version 5 key's. Each is right for its own
key version and wrong for the other, and the symptom is only a key
unwrap failure. **Mitigated**: GnuPG's Ed448/X448 key both ways, and
go-crypto's version 6 keys both ways.

### Usage 253 means two things for a version 4 key

RFC 9580 protects a secret key with AEAD under an HKDF of the S2K
output, with the packet tag and the public key as associated data;
LibrePGP uses the S2K output itself and puts the cipher and mode into
the associated data as well. A version 6 key is the first, a version 5
the second, and a version 4 key may be either - the reader tries both,
which is safe because both are authenticated. **Accepted**, with
RFC 9580's A.5 and GnuPG's keys behind the two readings.

### Ed448 and X448 points have no prefix in GnuPG's keys

RFC 9580 writes an EdDSA or Curve25519 point as `0x40 || native`;
LibrePGP's Ed448 and X448 (and the RFC 8410 OIDs for the 25519 pair)
write the native string bare, as an MPI - so a leading zero byte is
dropped and has to be put back to the curve's length. Their X448
secret is native little endian, where Curve25519Legacy's is the
reverse. **Mitigated**: GnuPG's version 5 key both ways.

### A secret key that opens is not necessarily its public key's

The two byte checksum of usage 255 and of unprotected keys passes a
wrong passphrase one time in 65536, and nothing in the format ties the
secret numbers to the public ones. Every unlocked key is checked
against its public half (p·q = n, g^x = y, d·G = Q, the X and Ed
public keys recomputed).

### A text literal is stored in its CR LF form

A text signature covers the document with CR LF line endings, and GnuPG
stores a `t` literal packet with those endings already in it and hashes
it as stored. Storing the original LF text and signing its canonical
form verifies here and fails in GnuPG. **Mitigated**: text-mode
signatures both ways with every key.

### LibrePGP's version 5 signatures hash more than the document

A version 5 document signature also hashes the literal packet's format,
file name and date before its trailer (six zeros for a detached
signature, `t` and five zeros for a cleartext one), and its trailer's
length is eight bytes. Reading a cleartext signature with the detached
rule fails only for version 5 keys. **Mitigated**: GnuPG's Ed448 key,
cleartext both ways.

### GnuPG's Ed448 values keep their leading zero

Signature halves and X448 points are written at their full length (an
"SOS"): a leading zero byte stays, with the bit count of the whole
string. Stripped like an MPI, GnuPG refuses the signature ("Invalid
length") one time in about 128. **Mitigated**:
`test_sos_keeps_a_leading_zero`, and `scripts/check_openpgp.py`'s
signature rows against GnuPG, which found it.

### A subkey is not a certificate's until the primary key says so

Any key can be appended to a certificate. A subkey is used only with a
binding signature from the primary key that verifies, and a signing
subkey also needs its own signature back over the primary key
(embedded in the binding), or somebody else's signing key could be
claimed. **Mitigated**: RFC 9580 A.3 with its binding removed has no
key to encrypt to (`test_rfc9580_signatures`).

### OpenPGP's RSA wants p < q

The secret key stores d, p, q and u = p⁻¹ mod q, with p the smaller
prime; a library that generates p > q gives a u that is the inverse the
other way round, which some readers check and some use. The generator
swaps the primes and recomputes u. **Mitigated**: GnuPG imports and
uses our RSA keys.

### A version 6 key's flags are on the direct key signature

Version 4 keys carry key flags and preferences on the user ID's
self-certification; version 6 keys on a direct key signature over the
primary key alone, and a version 6 key may have no user ID at all.
Looking only at the user ID's certification finds no flags on a version
6 key. **Mitigated**: RFC 9580's A.3, and go-crypto reading our version
6 keys.

## 7zk. XEdDSA

`src/ec/xeddsa.rs`: Ed25519 signatures by an X25519 key, which is how
Signal signs prekeys and group messages.

### The sign of the point is not in the key

`u` names two Edwards points, `P` and `-P`. libsignal's signer uses its
own point and stores the sign bit in the top bit of `S`; the XEdDSA
document's signer forces the bit to zero and negates the scalar when its
point was negative. Both verify their own output, so a round trip tests
neither choice. A Signal-form signature by a negative key fails the
specification's verifier, and the generator of `vectors/xeddsa.vec`
refuses to write a file in which the two verifiers never disagree.
**Mitigated**: libsignal-protocol-c's bytes for both signers and the
verdicts of both verifiers, `tests/test_xeddsa_vectors.rs`.

### libsignal's nonce is not the document's

The document hashes `a = k mod q` into the nonce. libsignal-protocol-c
hashes the clamped key bytes unreduced, except after a negation, which
reduces. Both are valid signatures, so only a byte comparison sees it;
this library follows libsignal. **Accepted**: the comparison is to
libsignal because libsignal is what a signature has to match.

### `S + L` verifies

Both libsignal implementations check only that `S`'s top three bits are
clear, and the document bounds `S` by `2^253`, not by `L`. Anybody can
therefore turn one valid signature into a second. It forges nothing, but
"this signature is the one that was sent" is not a property a caller can
rely on, which RFC 8032's `S < L` exists to give and `eddsa::verify`
enforces. **Accepted**, to verify what libsignal verifies;
`test_s_plus_l_verifies_and_s_above_2_to_253_does_not` pins it.

### A key with bit 255 set

X25519 ignores bit 255 of `u`. The Signal verifier does too, through
`fe_frombytes`; the specification's refuses a `u` that is not reduced.
So one public key can be accepted by one verifier and refused by the
other. **Mitigated**: both readings, each matched to its libsignal
counterpart by twelve vector rows.

### Signing was variable time

It went through the `BigUint` double-and-add `multiply` that section 2c
describes (now `eddsa::reference`, test-only), and the specification
form chose between the key and its negation with an `if` on the sign of
the secret point's `x`.

**Mitigated**, with 2c: signing runs on `ec::edwards` and
`eddsa::Order`, and the choice is a mask. `scripts/ct_check.py`'s
`xeddsa_sign` row runs both forms and is expected clean. The Signal form still publishes that sign
bit in the top bit of `S`, which is the form's design rather than a
leak.

---

## 7zl. The Signal example

`examples/products/signal`. Every entry here is invisible between two
copies of the same code and was settled by libsignal-protocol-c's bytes:
`scripts/check_signal.py` runs each conversation with libsignal on both
sides and with ours, and requires the replies to be identical.

### The initial state is lopsided

Bob starts with the X3DH chain as his *sending* chain under his signed
prekey; Alice starts with it as a *receiving* chain under the same key,
and sends on a chain from a root step she takes at once with a fresh
ratchet key. Mirroring either side gives a session that works in one
direction. **Mitigated**: every conversation starts this way.

### The MAC's identities are sender then receiver

So the receiver checks remote-then-local. Reversed at both ends it
still works, and fails against anybody else. **Mitigated**:
`test_the_mac_binds_both_identities_in_order`, and every message in the
transcripts.

### The group derivation is IV first

`WhisperGroup` gives 48 bytes, IV then key; the pairwise
`WhisperMessageKeys` gives key, MAC key, then IV. **Mitigated**: the
sweep that swapped them failed the replay.

### Randomness is drawn on attempts that fail

A message under a ratchet key the session has not seen triggers a DH
ratchet step - including a fresh key pair - before its MAC is checked.
If the MAC fails the step is discarded, but the random bytes were
drawn; so is every attempt against an archived session. Byte-for-byte
agreement depends on drawing them too, and the replay is what sees it.
**Mitigated**: the archive is searched in libsignal's order (newest
first) because of this; appending instead of prepending failed the
replay.

### `previous_counter` cannot tell one from none

It is the old sending chain's index less one, floored at zero, so a
chain that sent one message and a chain that sent none both say 0.
Nothing reads it on receipt - late messages derive their keys from
their own counter - so this is harmless, but it is in every message's
bytes. **Accepted**, as libsignal does it.

### X25519 outputs are not checked for zero

libsignal's `curve_calculate_agreement` cannot fail, so a low-order
public key gives an all-zero agreement and the session proceeds. The
example uses the raw function rather than `x25519::exchange`, which
refuses, because refusing would refuse sessions libsignal completes. In
X3DH the other agreements still contribute, so one zero is not a known
key. **Accepted**, to match.

### Limits that only show when exceeded

Five receiving chains, 2000 skipped keys per chain, a skip of at most
2000, forty archived sessions, five sender keys per sender. Each looks
like an arbitrary constant and each changes which late message
decrypts. **Mitigated** for the first three: late messages on seven old
chains (two refused, five decrypted), and 2001 messages ahead (refused)
against 2000 (decrypted) live. The last two are as libsignal's source
states them and no conversation reaches them.

### A re-announced sender key passes its own late messages

A second distribution message from the same sender goes in front of
the first, with the same key id. A message sent before it is looked up
in the newer state, which is already past its iteration: a duplicate,
not a decryption. **Accepted**, as libsignal does it; the group
conversation records it.

### libsignal's errors are not always the obvious ones

A group message with no sender key to send with is "no session", not
"invalid key id"; an unknown key id on receipt is "invalid message"; a
prekey message's version above 3 is "invalid version" where a signal
message's is "invalid message"; and protobuf-c treats field number 0 as
an unknown field, so bytes of zeros are a message missing its fields
rather than not a protobuf. **Mitigated**: the conversations compare
error codes as well as plaintexts.

---

## 7zm. The KeePass example

`examples/products/keepass`.

### Protected values are one stream, in document order

Every `Protected="True"` element is XORed with the next bytes of a
single keystream, history entries and old-style protected attachments
included. Skipping one, or visiting the history after the entry's own
fields when it comes before them, leaves every later value under the
wrong keystream - and the symptom is garbage in an unrelated field.
**Mitigated**: `test_protected_values_are_decrypted_in_document_order`,
and fixtures with protected values in history.

### KDBX 3.1 authenticates its header through the XML

3.1 has no header MAC; a change to the header that leaves decryption
working - an inserted comment field - is caught only by comparing
`Meta/HeaderHash` with the header's SHA-256, *after* decryption.
**Mitigated**: `test_a_changed_kdbx3_header_is_refused_by_its_hash`.
A file without a `HeaderHash` (older writers) gets no such check, and
`dump` says when it ran.

### Flags that do not mean what they say

KeePass never compresses a protected attachment and ignores
`Compressed="True"` on one; kdbxweb sets it. KeePass writes an empty
attachment as `<Binary ID="0" Compressed="True"/>`, empty rather than
a gzip stream of nothing. And a KDBX 4 attachment's "protected" flag
asks the reader to guard it in memory: it is not under the inner
stream. **Mitigated**: unit tests for the first two
(`test_a_protected_attachment_ignores_its_compressed_flag`,
`test_an_empty_compressed_attachment_is_empty`), and kdbxweb's
fixtures (`go-kdbx3-protected-binary`, `go-kdbx4-protected-binary`)
for the first and the third.

### gokeepasslib's KDBX 3.1 attachments lose their gzip trailer

It gzips into a base64 encoder it never closes, so the final one or two
bytes of the trailer are not written, and it reads its own back by
ignoring the error. Ours accepts a trailer cut short after a deflate
stream that ended properly - the deflate stream carries its own end
marker, so it is a check that is lost, not data - and still checks a
whole trailer's CRC. **Accepted**, so as to read what it writes; found
by the check script, the first time a gokeepasslib 3.1 database had an
attachment.

### Key files are tried in order

XML first, then exactly 32 bytes, then exactly 64 hex digits, then a
hash of the whole file. A 64-byte file that is not hex is hashed, and
an XML key file of version 2.0 has its hash checked. **Mitigated**:
`test_key_files_of_each_kind`,
`test_a_version_2_key_file_with_a_wrong_hash_is_refused`, and one
fixture per kind.

---

## 7zn. The ZIP example

`examples/products/zip`; the cipher is the library's
`stream_ciphers::zipcrypto`.

### ZipCrypto has no keystream

Its keys absorb each byte of *plaintext*, so decryption must XOR first
and feed the result back, and encryption feeds back its input. Feeding
back the ciphertext instead decrypts the first byte correctly and
nothing after it; and since every ciphertext decrypts to something,
nothing fails except a comparison. It is why ZipCrypto is not a
`StreamCipher` and why the facade's `update`, which has no direction,
refuses it. **Mitigated**: `scripts/diff_check.py hash` checks both
directions against CPython's `zipfile`, as does
`pytests/test_allcrypt.py`; a sweep that fed back the wrong byte in
either direction was caught.

### ZipCrypto is broken

Twelve bytes of known plaintext give the three keys (Biham and Kocher,
1994; bkcrack implements it), and a ZIP entry's own header or a file's
predictable start usually supplies them. **Accepted**: it is kept
because most password-protected archives use it. `from_keys` opens an
entry with keys such an attack recovered, without the password.

### ZipCrypto's check byte is not always the CRC's

The last byte of the 12-byte header decrypts to the CRC's top byte -
unless the entry has a data descriptor (flag bit 3), when the CRC was
not known as the header was written and the check is the modification
time's top byte instead. Reading every entry with the CRC's byte works
on everything written to a file and fails on everything written to a
pipe. **Mitigated**: Info-ZIP's archives written to a pipe are among
the fixtures, and the sweep that dropped the rule failed them.

### One wrong password in 256 passes the check

The check is one byte. A wrong password that passes it decrypts to
noise that the CRC then refuses - except for an empty entry, where
there is nothing for the CRC to cover, so the wrong password opens it.
Found by the recorded archives, and pinned by
`test_an_empty_zipcrypto_entry_cannot_refuse_every_wrong_password`.
**Accepted**: it is the format. WinZip AES's 16-bit verifier and HMAC
leave no such gap, which the same test checks.

### WinZip AES counts little endian, from one

Brian Gladman's `fileenc`, which the format took, increments a 16-byte
little-endian counter that starts at 1 - not AES-CTR as NIST or
OpenSSL write it. Either mistake decrypts our own archives and nobody
else's. **Mitigated**: every AES archive 7-Zip and libarchive wrote.

### AE-2 has no CRC

AE-2 leaves the CRC field zero, because a CRC of the plaintext leaks
information about it; the HMAC is the only check. A reader that checks
the CRC refuses every AE-2 entry; one that never checks it loses AE-1's
second check. **Mitigated**: fixtures of both.

### Not every entry in an encrypted archive is encrypted

libarchive writes an empty file unencrypted inside an archive whose
other entries are. A reader must take the flag per entry rather than
per archive. **Mitigated**: libarchive's archives in the fixtures.

### A name can point outside the destination

`../` or an absolute path in an entry's name writes wherever it says
("zip slip"). `extract` refuses such a name rather than rewriting it.
**Mitigated**: `test_a_name_that_leaves_the_destination_is_refused`.

## 7zo. The PDF example

`examples/products/pdf`.

### A password that is both is the owner's

The empty password is commonly the user password and, when the writer
was given no owner password, the owner password too. ISO 32000-2's
Algorithm 2.A tests the owner password first, and so does qpdf; a
reader that tries the user password first opens the same file with the
same key and reports the wrong password - which matters, because the
owner password lifts every restriction in `/P`. **Mitigated**:
`test_a_password_that_is_both_is_the_owners`, and every fixture records
which password qpdf said it was.

### Revision 4's key is 128 bits whatever `/Length` says

At V 4 the key length is the crypt filter's business and writers put
anything in the dictionary's `/Length`; qpdf ignores it there, and at V
2 and 3 takes a `/Length` that is not a whole number of bytes from 40 to
128 bits as 128 rather than refusing the file. Revision 3 at 40 bits is
the case that matters most: the fifty extra MD5 rounds hash the key
*cut to its length*, not the whole digest. **Mitigated**: qpdf's
40-bit revision 3 file and its file whose `/Length` is misspelled, and
`test_the_key_length_is_read_as_qpdf_reads_it`.

### A stream can name its own crypt filter

From revision 4 a stream may carry `/Crypt` in its `/Filter` with a
`/Name` in its `/DecodeParms`, overriding `/StmF` - Acrobat encrypts
attachments only by writing `/StmF /Identity` and naming `StdCF` on
each embedded file. A reader that applies `/StmF` everywhere returns
those attachments still encrypted. The decrypted file must then lose
the `/Crypt` filter and its parameters, or a reader of it looks for a
crypt filter that no longer exists; qpdf's writer removes them, and so
does `decrypt`. **Mitigated**: qpdf's encrypted-attachments and
crypt-filter files, `test_a_stream_is_encrypted_under_the_method_that_applies_to_it`
and `test_decrypting_removes_the_crypt_filter`.

### `/EFF` is followed here and not by qpdf

`/EFF` names the method for embedded files that name none of their
own. qpdf records it and never applies it when decrypting; ISO 32000-2
table 20 says it applies, and that is followed here. No file in qpdf's
test suite tells the two apart - their attachments all carry their own
filter. **Accepted**, with the difference stated in `file.rs`.

### Some strings are never encrypted

A signature dictionary's `/Contents` is written in the clear, because
the signature covers the file's bytes and cannot cover its own
ciphertext. Decrypting it anyway turns a valid signature into noise -
or, under AES, fails outright on a length that is not whole blocks,
which is how qpdf's signed test file found it. Likewise the `/Encrypt`
dictionary, cross-reference streams, metadata under `/EncryptMetadata
false`, and objects inside an object stream, which is decrypted whole
and must not be decrypted again. **Mitigated**: each is in the
fixtures, and the sweep's break of each failed them.

### An empty string under AES has no IV

Several producers write an empty string as zero bytes rather than an
IV and a padding block, so a reader that requires 32 bytes refuses the
file. **Mitigated**: such strings are in qpdf's test files.

### Offsets count from the header

A PDF with junk before `%PDF-` (a mail or HTTP wrapper) has offsets
relative to the header, not to the first byte of the file. **Mitigated**:
qpdf's leading-junk file.

### Revisions 2 to 5 are weak, and revision 6 skips SASLprep

40-bit RC4 is exhaustible, RC4's keystream is biased, `/U` is known
plaintext under the file key, and revision 5's single SHA-256 made
guessing fast enough that Adobe withdrew it. All are written on request
because the files exist. Revision 6 passwords are meant to pass through
SASLprep first; this does not, so a password that SASLprep would change
does not open a file whose writer applied it. **Accepted** (the
formats) and **open** (SASLprep).

## 7zp. The Office example

`examples/products/office`; XOR obfuscation is the library's
`stream_ciphers::office_xor`.

### XOR obfuscation's array index is the format's choice

Which of the 16 array bytes a byte of data meets is not its position:
an Excel record starts at the stream position just past its own end,
and a BoundSheet8 four bytes later still. The library takes the
starting index from the caller rather than assuming one. **Mitigated**:
an XOR-protected workbook Excel wrote is among the fixtures, and
`vectors/office_xor.vec` holds msoffcrypto-tool's answers starting at
five different indices.

### A compound file's mini stream is chosen by size alone

A reader decides whether a stream is in the mini stream from its size:
under 4096 bytes it is, from 4096 it is not, and nothing else records
it. A writer that puts a 4096-byte stream in the mini stream writes a
file every reader misreads. **Mitigated**: `test_the_mini_stream_cutoff`.

### The DIFAT's last entry is a link

Each DIFAT sector holds 127 FAT sector numbers and, last, the number of
the next DIFAT sector. Reading all 128 as FAT sectors is harmless until
a file needs two DIFAT sectors - about 15 MB - and then corrupts it.
**Mitigated**: a 16 MB round trip, after a sweep found an 8 MB one
could not tell.

### Agile encryption's padding is on both sides of the hash

A derived key or IV shorter than the cipher wants is padded with 0x36,
never with zeros; a value encrypted in whole blocks (the HMAC key and
value, the verifier hash, a 192-bit key) is padded, and a reader takes
only the meaningful bytes back. msoffcrypto-tool takes them whole: it
reads an AES-192 key as AES-256, does not pad a key longer than the
hash, and checks a SHA-1 HMAC with its padding still on the key - each
wrong only where Office's own defaults never go. **Mitigated** where a
witness reads it; the padding of a key longer than its hash is
**accepted** on the specification's word and LibreOffice's IV code,
with `test_short_keys_and_ivs_are_padded_with_0x36`.

### Standard encryption authenticates nothing

ECB over the package and a verifier for the password: the ciphertext
can be cut, reordered or replaced block by block, and nothing notices
until the ZIP inside fails to parse - or does not fail. **Accepted**:
it is the format, and `encrypt` writes agile unless asked.

### Office 97's RC4 key has 40 bits whatever its length

The key chain cuts MD5 to five bytes twice before the per-block hash
makes 16 of them, so every key is one of 2^40, and the verifier lets a
guess be checked against block 0 alone. CryptoAPI's 40-bit option is
the same five bytes padded with zeros. LibreOffice still writes the
first for `.doc` and `.xls`. **Accepted**: it is the format; decrypting
it is the point.

### The keystream belongs to the position, not to the bytes encrypted

A Word document's first 68 bytes and every workbook record header are
in the clear, and still use up their keystream; a BoundSheet8 record's
first four bytes are clear and its rest is not; the key changes every
512 bytes of a Word stream and every 1024 of a workbook. Each mistake
decrypts the first record or block and garbles the rest. **Mitigated**:
the Office- and LibreOffice-written fixtures, which the sweep's break
of each failed.

### Decrypting must not move anything

A workbook records stream positions (each sheet's in BoundSheet8, and
more in Index records), so FilePass cannot simply be dropped: it
becomes a record of type 0, all zeros, in place - as msoffcrypto-tool
writes it. A Word document's encryption header sits at the start of
its table stream, which nothing points into once the FIB says the file
is plain; it is zeroed rather than decrypted into noise. **Mitigated**:
LibreOffice reads every decrypted file with no password and finds the
content it finds in the original.

### The data spaces are invisible to every witness here

[MS-OFFCRYPTO] requires the `\x06DataSpaces` storage beside the
encrypted package, and Office writes it; LibreOffice and
msoffcrypto-tool neither need it nor look at it, so a writer checked
only against them can get it wrong, or leave it out, unnoticed. Its
`TransformInfo` header's length counts the type and ID and not the name
after them. **Mitigated**: `test_the_data_spaces_are_the_ones_office_writes`
compares with an Office-written file stream for stream, and found the
length.

## 7zq. The OpenDocument example

`examples/products/odf`.

### The password check is a hash of plaintext

AES-CBC and Blowfish packages carry, for every file, a SHA-256 or SHA-1
of the first kilobyte of its deflated, not yet encrypted, data. It is
the only way to tell a wrong password, it lets a guess be tested
against one file's first kilobyte, and it hashes plaintext that is
mostly predictable XML. Nothing at all covers the rest of a file: a
change past the first kilobyte decrypts to garbage that the inflater
may or may not refuse. **Accepted**: it is the format; the whole-package
scheme's GCM tag covers everything, and its test flips bits to show it.

### The key derivation's password is a hash

PBKDF2 and Argon2id are given the SHA-1 or SHA-256 of the password's
UTF-8, not the password, so the "start key" hash is a step a reader can
leave out and still derive a key - the wrong one. **Mitigated**: every
LibreOffice fixture, and the sweep's break of it.

### Blowfish's key is 16 bytes by default, and its CFB is 64-bit

ODF 1.2 says a missing `key-size` means 16 bytes, which only ODF 1.0
and 1.1 packages - Blowfish - leave out; and LibreOffice's "Blowfish
CFB" is full-block CFB, not CFB-8, despite its internal name
`BLOWFISH_CFB_8`. **Mitigated**: LibreOffice's Blowfish fixture.

### W3C padding is not PKCS#7

The AES-CBC padding of XML Encryption fixes only the last byte - the
count - and leaves the others arbitrary; LibreOffice fills them with
random bytes. A reader that checks every byte of the padding refuses
every LibreOffice file. **Mitigated**: LibreOffice's fixtures, which
have random padding; ours writes PKCS#7, which is one valid instance.

### The GCM IV is written twice

LibreOffice puts the IV in the manifest and again in front of the
ciphertext, as XML Encryption 1.1 does. A reader that takes the
ciphertext from byte 0 fails every tag; one that ignores the copy
cannot see a package whose two disagree. **Mitigated**: such a package
is refused, `test_a_gcm_iv_that_disagrees_with_the_manifest_is_refused`.

## 7zr. The key store example

`examples/products/keystore`; the two key protectors are the library's
(`x509::encrypted_key`), so `private_key` also opens a key one of them
protects.

### JCEKS has no integrity check of its own

PBEWithMD5AndTripleDES is 3DES-CBC with PKCS#5 padding and nothing
else, so a wrong password gets through the padding about once in 256.
Java then fails to parse the key; so does the example
(`test_a_jceks_wrong_password_with_good_padding_is_refused`), and so
does `private_key`. A caller of `encrypted_key::decrypt` alone gets
random bytes in that case. **Accepted** for `encrypted_key::decrypt`
on its own: it is the scheme; the example and `private_key` are
mitigated as below. JKS's protector does carry a SHA-1 check.

### The empty password has two hashes

RFC 7292's BMPString of a password ends in a two-byte NUL, so the empty
password is those two bytes - which is what the `openssl` command, Java
and python-cryptography hash. OpenSSL's API given a NULL password
hashes no bytes at all, and its own reader tries that first. A reader
that knows one form refuses the other's files as a wrong password.
**Mitigated**: both are tried, for the MAC here and for decryption in
`x509::encrypted_key`; fixtures of each (`openssl-empty-*`,
`openssl-null-*`, written through OpenSSL's API by ctypes), and the
sweep's break of the second form.

### Without a MAC, a wrong password is right one time in 256

A store with no MAC, and a JCEKS key always, have only CBC padding to
say the password was wrong, and a wrong one leaves valid padding about
once in 256 tries; what comes out is noise in the place of a key.
**Mitigated**: a decrypted key must parse as a PrivateKeyInfo, as Java
and OpenSSL require -
`test_a_wrong_password_with_good_padding_is_refused` (PKCS#12, each
scheme) and `test_a_jceks_wrong_password_with_good_padding_is_refused`
search for such passwords. Found when a round-trip test failed one run
in four.

### A safe is a document of its own

The authenticated safe and each safe inside it are OCTET STRINGs whose
content is DER - or BER - in its own right, so converting the PFX from
BER to DER leaves them as they were. NSS writes the PFX in BER but its
safes in DER, so its files never reach the inner conversion.
**Mitigated**: each layer is converted where it is opened;
`test_ber_inside_the_safes_is_read` writes the BER no witness here
wrote.

### PBMAC1 ignores the MacData's salt and count

RFC 9579's MAC key comes from PBKDF2's own parameters; the MacData's
salt and iteration count are still present and unused. OpenSSL 3.5
writes the same salt in both places, so reading the wrong one agrees
with every file it writes. **Mitigated**:
`test_pbmac1_ignores_the_mac_data_salt_and_count` changes them and
expects a PBMAC1 file to stay valid and a classic one not to.

### Java serialization shares by identity

`ObjectOutputStream` writes a back-reference for an object it has
written before - the same object, not an equal one. A sealed key's two
algorithm names are equal strings and Java writes both; a field's type
string is one object and Java refers back to it. Deduplicating by
equality writes a stream Java still reads but that is not Java's.
**Mitigated**: `test_the_serialised_secret_key_is_javas` compares both
layers with keytool's bytes, which is also what checks byte[]'s
serialVersionUID, declared in no source file.

### The JKS store digest is an extensible hash

It is SHA-1 over the password, "Mighty Aphrodite" and the store - a
secret prefix, which length extension carries past the end without the
password. **Mitigated** by the format rather than the digest: the entry
count comes first and nothing may follow the last entry,
`test_bytes_after_the_last_entry_are_refused`. The key protector, a
SHA-1 keystream with a SHA-1 check, and JCEKS's PBEWithMD5AndTripleDES
are what Java writes. **Accepted**: kept, like RC2-40 and SHA-1 MACs in
PKCS#12, because files exist in them.

### A trusted certificate is a Java attribute

PKCS#12 has no notion of a trusted certificate. Java marks one with an
Oracle attribute (`2.16.840.1.113894.746875.1.1`) and drops a
certificate bag without it or a key, silently. **Mitigated**: written
for every trusted entry converted from JKS or JCEKS, checked by keytool
listing it, and offline by
`test_java_entries_become_the_bags_java_writes`.

## 7zs. The JOSE example

`examples/products/jose`.

### The algorithm is the attacker's to name

A JWS or JWE names its own algorithm, so a verifier that picks the
check from the header can be told to use a public key as an HMAC
secret, or `none`. **Mitigated**: the algorithm and the key's type must
match - an RSA key cannot be handed to HS256 - and `none` is accepted
only when the caller says so and gives no key at all;
`test_every_jws_algorithm_round_trips` offers each signature to a key
of another type, and RFC 7515 A.5's unsecured example is refused
without `--allow-none` and with a key.

### `crit` is a promise to understand

RFC 7515 4.1.11: a header listed in `crit` must be understood, present
and protected, or the JWS is invalid. The only one understood here is
RFC 7797's `b64`, which in turn must be listed. **Mitigated**: appendix
E's negative example is refused, and so is every way of getting `crit`
or `b64` wrong (`test_the_header_rules_are_enforced`,
`test_more_jws_rules`). With one understood name, requiring `crit` to
be protected is covered twice over and a sweep cannot isolate it.

### Signatures must agree on `b64`

Every signature in a JWS reads the payload the same way (RFC 7797 3).
Checking that only for the signatures tried accepted a JWS whose first
signature verified and whose second said the payload was encoded
differently. **Mitigated**: every signature's headers are checked
before any is verified, `test_more_jws_rules`; found by that test,
written after a breakage sweep had missed it.

### RSA1_5 must not say why it failed

RFC 7516 11.5: a padding failure in RSA1_5 continues with a random
content key, so it fails at the tag like a wrong key - otherwise the
decryptor is Bleichenbacher's oracle. **Mitigated**:
`test_an_rsa1_5_padding_failure_looks_like_a_wrong_key` compares the
two errors. Timing is the library's RSA decryption, section 1.

### The sender sets PBES2's cost

`p2c` is in the header, so a JWE can ask its reader for billions of
PBKDF2 iterations. **Mitigated**: refused over a cap, 10,000,000 by
default; jwcrypto's is 16,384, which is why `check_jose.py` writes
2,048 where ours writes 600,000 unless told otherwise. A `zip`
plaintext is likewise inflated to at most 64 MiB.

### A key that is not what it says

An EC JWK whose point is off its curve is the invalid-curve attack on
ECDH-ES; one whose `d` is not the private key of its `x` and `y` signs
for somebody else. **Mitigated**: points are validated by the library,
private halves recomputed and compared, and an RSA private key built
from its primes with `n` and `d` checked against them - `d` modulo
each prime, because RFC 7516's A.1 key writes it modulo (p-1)(q-1)
where this library computes it modulo lcm(p-1, q-1), and both are
right. An `epk` carrying a private key is refused. The EC coordinate
width check is covered by the point decoding as well, and a sweep
cannot isolate it.

### Headers are three objects and one namespace

A JWE's protected header, shared unprotected header and per-recipient
header are joined, and a name in two of them is an error rather than
an override (RFC 7516 7.2.1); `zip` changes what the plaintext means
and must be protected. **Mitigated**: `test_more_jwe_rules`.

## 7zt. The 7z example

`examples/products/sevenzip`.

### 7zAES has no MAC

A 7z archive's encryption is AES-256-CBC with nothing authenticating
it, so a wrong password decrypts to noise and the first thing to notice
is whatever reads the noise: the decompressor, the header parser, or a
CRC-32 - which is linear and keyless, so not a defence against anyone
editing the ciphertext on purpose. **Accepted**, as the format; what is
**mitigated** is the report: every failure after a decryption says the
password may be wrong (`test_7_zips_archives_extract_byte_for_byte`,
`test_a_wrong_password_is_named_when_the_header_has_no_crc`). Without
`--encrypt-header` the names and sizes are in the clear.

### The archive sets the key derivation's cost

2^n rounds of SHA-256 with n in the archive. **Accepted** up to 24, as
7-Zip accepts it - about 16 million rounds, seconds - and refused
above. The raw-key setting (0x3F) is no derivation at all: salt and
UTF-16LE password copied into the key and cut at 32 bytes, so without
a salt only the first sixteen characters count. Read because 7-Zip
reads it; written only when asked for with `--cycles 63`. The 32 most
recently derived keys are kept for the life of the process, as 7-Zip
keeps them.

### Sizes are declared, and believed only so far

A folder's unpacked size is in the header, and the decoders allocate
it up front: **mitigated** by a 1 GiB limit on any stream or header,
and by every decoder checking that it produced exactly the declared
length, with no match or stored chunk allowed to run past it
(`test_a_match_may_not_run_past_the_declared_size`,
`test_a_stream_shorter_or_longer_than_declared_is_refused`).

### LZMA2 resets

The whole output is held in memory, so a distance reaching before a
dictionary reset, or further than the declared dictionary, finds real
bytes rather than failing. **Mitigated**: both are refused
(`test_a_distance_past_the_declared_dictionary_is_refused`,
`test_a_stored_chunk_that_resets_the_dictionary_starts_it_again`), as
are chunks without the resets `Lzma2Dec.c` requires and a chunk whose
range coder does not end exactly at its packed size. Positions count
from the last reset as `LzmaDec.c` counts them; measuring them from the
start of the output instead is an equivalent mutant, because every
reset comes with fresh probabilities and a constant offset into fresh
tables only relabels the contexts.

### Names

**Mitigated**: an absolute name or a `..` component, with `/` or `\`
between components, is refused before anything is written
(`test_a_name_that_leaves_the_destination_is_refused`). On Windows a
drive prefix is refused too; elsewhere `C:` is an ordinary name inside
the destination. The test has no drive-prefix case.

### Equivalent mutants

The x86 filter's `gap > 3` (a mask shifted by three is zero anyway),
the ARM Thumb filter's step after a converted pair (the second half of
a BL can never be the first half of another) and a file's CRC falling
back to its folder's (the folder's is checked first) all survive a
sweep without being holes.

## 7zu. The CMS and S/MIME example

`examples/products/cms`; its key wraps are the library's
`block_ciphers::cms_wrap`.

### RFC 3217's RC2 example is at 40 effective bits

Section 4 requires a 128-bit RC2 key-encryption key, and the example in
4.4 has one - but its result comes out only with RC2 at **40 effective
bits** (tried: 8, 32, 40, 64, 128, 256, 1024), the default of Microsoft's
CryptoAPI. The checksum, which involves no RC2, matches either way. The
effective length is a separate input to RC2's key schedule (section 7),
so `wrap_rc2` takes it, and the test pins the example at 40 and checks
that 64 and 128 give something else.

### Three checks, one error

The Triple-DES unwrap checks the checksum and the key's parity; the RC2
unwrap the checksum, the length byte and at most seven bytes of padding;
the password wrap its three check bytes and the length. Each fails with
the same words, so the error does not say which check a forgery passed.
**Mitigated**: a test builds a wrapping that passes all but one, for
each.

### What a signature covers, and what it does not

With signed attributes the signature covers the attributes, and the
attributes carry the content's type and digest: both are checked, or a
message relabelled as another content type, or with other content under
the same attributes, verifies. Without attributes nothing signed names
the content type, so RFC 5652 5.3 allows it for data only. **Mitigated**:
`test_the_signed_content_type_must_match` and
`test_unattributed_content_must_be_data` edit OpenSSL's messages to do
exactly that. A signer's digest algorithm and its RSA-PSS parameters
must name one hash (`test_pss_parameters_must_agree_with_the_digest`);
the same agreement for a PKCS#1 v1.5 or ECDSA algorithm that names its
hash is checked too, and is an equivalent mutant there - the signature
fails under the other hash anyway.

### Content encryption is not authenticated

EnvelopedData is CBC with no MAC, so a damaged or chosen ciphertext is
noticed only by its padding, and about once in 256 a wrong key passes
that. **Accepted**, as the format; AES-GCM AuthEnvelopedData is the
alternative, and an AuthEnvelopedData with a cipher that does not
authenticate is refused (`test_auth_enveloped_data_needs_an_aead`), as
is a MAC shorter than its parameters say
(`test_a_shortened_gcm_tag_is_refused`) - GCM itself checks any tag from
12 bytes.

### Bleichenbacher, and which recipient is ours

A PKCS#1 v1.5 key transport failure continues with a random content key
(RFC 3218), so it fails at the content like a wrong key
(`test_a_key_transport_failure_looks_like_a_wrong_key`); the library's
RSA is not constant time, so this reduces the oracle rather than
removing it (section 1). With no certificate to say which recipient is
the key's, every key transport recipient is tried strictly first and the
random key used only if none decrypts: otherwise a wrong recipient's
random key would be taken for the content about once in 256. That
ordering is invisible to any test that is not itself probabilistic.

### Password recipients

The sender sets PBKDF2's count. **Mitigated**: capped on reading,
10,000,000 by default (`--max-iterations`). RFC 3211's check value covers
the length and three bytes of the key, nothing else, so a damaged wrap
can unwrap to another key; the content's padding then refuses it. An RC2
key-encryption key's length is in no identifier: ours writes PBKDF2's
`keyLength`, and reads its absence as OpenSSL does, from the effective
key bits.

### Equivalent mutants

The odd parity set on a generated Triple-DES content key (the RFC 3217
wrap sets it on its own copy, and DES ignores the bits); the order in
which recipients are tried when no certificate is given (see above).

## 7zv. The Kerberos example

`examples/products/kerberos`.

### Unauthenticated and short keys, kept

Single DES (56-bit keys, its CRC-32 inside the encryption no MAC at
all), RC4-HMAC (an unsalted MD4 of the password: the key *is* the NT
hash, so a keytab or a captured hash authenticates without the
password) and the export variant (40 bits of RC4 key) are all here and
all correct. **Accepted**: that is the project; MIT 1.21 still has
everything but single DES. A des-cbc-crc ciphertext uses the key as its
IV and checks it with a linear CRC, so it can be altered without the
key; nothing here pretends otherwise.

### What the integrity check covers

The derived-key types MAC the plaintext (RFC 3961) and RFC 8009's MAC
the ciphertext and IV; either way every bit of a ciphertext is checked
(`every_bit_of_a_ciphertext_is_checked`, every type), the comparison is
constant time for every type but single DES, whose checksum has no
key, and every failure is one message. RFC 8009's MAC is
checked before decrypting. **Mitigated**.

### Key usage separation

A usage is part of every derived key, so a ticket cannot be replayed as
an authenticator. **Mitigated**, except where the format merges usages:
single DES has none, and RC4-HMAC maps the AS-REP's 3 onto the
TGS-REP's 8 (`a_different_usage_is_a_different_key`). RFC 4757 also maps
9 onto 8; MIT and Heimdal do not, and ours follows them, because a
TGS-REP written the RFC's way decrypts under neither.

### The DES MACs and zero padding

DES-MAC and DES-MAC-K pad with zeros and carry no length, so a message
and the same message with zeros added up to a block have one MAC.
**Accepted**, as the construction (`the_des_macs_cannot_see_zero_padding`).
The same holds for decrypting single DES and Triple DES: the plaintext
comes back zero-padded to a block, and only the ASN.1 inside says where
it ends.

### Weak DES keys

RFC 3961 corrects a weak or semi-weak key by XORing 0xF0 into its last
byte, in DES string-to-key and in Triple DES's random-to-key (6.3.1).
No published vector reaches the second - a random 56 bits is weak about
once in 2^52 - so `des3_random_to_key_corrects_weak_keys` builds the
input that makes one. RFC 3961 A.2's last two vectors reach the first.

### Equivalent mutants

`derive_random` n-folding a constant that is already one block (n-fold
of a block to a block is the identity); the length check before
`constant_eq`, whose callers always split at the MAC's length; Triple
DES's whole-block check before decrypting, which the CBC decryption
makes anyway.

## 7zw. The wallet example

`examples/products/wallet`.

### Unnormalized passphrases

BIP-39 hashes NFKD text and BIP-38 NFC. A passphrase typed with a
precomposed é is a different wallet from the same passphrase decomposed,
and both hash to valid-looking keys; nothing fails. **Mitigated**:
`wallet/unicode.rs` normalizes from Unicode 16.0's tables before
hashing, and the command line hands BIP-38 its passphrase through
`bip38::passphrase` (`test_normalization_test_txt`,
`a_wrong_word_or_count_is_refused`,
`recorded_bip39_in_other_languages_and_unnormalized`,
`bip38_the_command_line_normalizes_the_password`). The other side:
a key made by software that hashed its passphrase without normalizing
does not open here unless that text was already in the form the BIP
names, because nothing here hashes text as typed.

### Normalization that agrees with itself

NFD followed by NFC returns what it was given for most text, so an
implementation can be wrong and round-trip. Three of its mistakes
passed every test until the sweep: a starter that combines with nothing
not clearing the class of the mark before it (`x\u{301}e\u{301}` kept
its second acute), U+11A7 read as a Hangul trailing consonant of index
zero (one below the first, and absorbed into the syllable), and an
unstable sort in canonical ordering, which a run of fewer than about
twenty marks cannot tell from a stable one. `test_a_few_by_hand` and
`test_reordering_is_stable` hold them; NormalizationTest.txt has none
of the three.

### Variable-time arithmetic on private keys

Public keys come from the constant-time ladder, and so do BIP-38's
products of secret scalars and points. BIP-32's child key (`IL + k mod
n`), BIP-38's `passfactor * factorb mod n` and ECDSA's normalization use
`BigUint`, which is not constant time (section 1). **Accepted** for an
example that runs once per command on a machine the user controls.

### Malleable signatures

ECDSA's (r, s) and (r, n - s) both verify. Ours always writes the lower
s, as Bitcoin Core and EIP-2 require; Ethereum recovery refuses the upper
half (`recorded_signed_messages`), and Bitcoin message verification
accepts it, as Core's does.

### Keystore costs an attacker sets

A keystore file names its own scrypt N and r, and N = 2^26, r = 8 is
64 GiB. **Mitigated**: above 2 GiB is refused
(`a_keystore_round_trips_and_states_its_address`). A version 3 file's MAC
covers only the ciphertext, not the parameters or the stated address,
so the address is checked against the key after decrypting.

### BIP-38's single check

A BIP-38 key has no MAC: the four-byte address hash is the only sign the
passphrase was right, so one wrong passphrase in 2^32 decrypts to a key
that passes it. **Accepted**, as the format.

### Equivalent mutants

BIP-32's refusal of a child whose IL is at least n, and signature
recovery's x = r + n for recovery ids 2 and 3: each happens about once
in 2^127, so no input reaches them, and removing either fails no test.
Both are kept because the specifications require them.

## 7zx. The DNSSEC example

`examples/products/dnssec`.

### Signing with algorithms RFC 8624 retired

RSAMD5, DSA, DSA-NSEC3-SHA1 and ECC-GOST are "MUST NOT" for signing in
RFC 8624, and SHA-1 DS digests and GOST R 34.11-94 ones are too. The
example signs and digests with all of them, because zones signed with
them still exist and this library keeps old algorithms. Refusing them is
a validator's policy, not a signer's: dnspython's default policy refuses
RSAMD5 and DSA, which is why `scripts/check_dnssec.py` passes its
`allow_all_policy`. **Accepted**, as the purpose of the example.

### A zone checked against its own keys

`verify` checks every signature against the DNSKEY RRset at the apex,
which the zone itself supplies. Nothing ties those keys to a parent: a
zone re-signed by anybody verifies. Validation from a trust anchor down
DS records is a resolver's job and is not here. **Accepted**; the
output says what was checked, not that the zone is authentic.

### Wildcard expansion is not checked

An RRSIG's label count matters when a wildcard answer is expanded
(RFC 4035 section 5.3.2). A zone file has no expansions, so `verify`
checks only that the count is not more than the owner has.
**Accepted.**

### NSEC3 iteration counts a zone sets

A zone names its own NSEC3 iteration count, up to 65,535, and checking
the chain hashes every name that many times. RFC 9276 asks for zero and
lets a validator treat counts above 100 as insecure; the example hashes
what it is given. **Accepted** for a command run on a file the user
chose.

### Variable-time arithmetic on private keys

ECDSA, GOST and SM2 public keys and signatures use the library's
constant-time ladder, EdDSA the fixed-limb Edwards arithmetic of
section 2c, and RSA signing its fixed-width path. DSA's exponentiation
runs a fixed number of steps, but its nonce, the nonce's inverse and
`x*r mod q` are `BigUint`s, which are not constant time (section 1).
**Accepted** for an example that signs a zone on a machine the user
controls.

### Documents that disagree with themselves

RFC 8080's four RRSIG examples leave out the algorithm field and open a
second parenthesis they never close. The signatures turn out to cover a
label count of 3 for the two-label `example.com.`, which a validator
would refuse; only a search over the plausible headers found what was
signed. RFC 9563's example prints the private key of a key-signing key
whose DNSKEY it omits: the DS's key tag, 27215, is that key's with the
SEP flag set, but its digest is not SM3 of that key; the
DNSKEY RRSIG covers an RRset including the omitted key; and the
NSEC3PARAM signature is 27 bytes. Its NSEC3 RRSIG verifies under GB/T
32918's default identity, which is the one piece of evidence that the
identity is the default. `tests.rs` pins each of these.

### Refusals nothing reached

`verify` was first tested only on good zones. A sweep found 22 of 66
breaks missed, most of them its refusals: inception, label count,
signer, an algorithm missing from an RRset, and every NSEC and NSEC3
chain check. Each now has a test that damages a signed zone and looks
for its own message. A second group were canonical-form rules that the
signer and the verifier share, which no round trip between them can
see. The fixes were a DS over a mixed-case owner, and dnspython's
signatures over a zone with capitals inside NS, SOA, MX, CNAME, SRV and
PTR records (`fixtures/dnssec/`).

### Equivalent mutants

RRSIG's signer lowercased inside `canonical_rdata`: RFC 4034 lists
RRSIG among the types whose RDATA names are lowercased, but RRSIGs are
never themselves signed, so that form only orders the output. Kept
because the RFC says it.

## 7zy. The WireGuard example

`examples/products/wireguard`.

### Which transport key is which

Both sides derive the same pair from the final chaining key, and the
initiator sends with the first while the responder sends with the
second. Two copies of one implementation that swap them agree with each
other and with nobody. The replayed conversations catch it; a handshake
between two of ours does not.

### Padding past the MTU

A packet is padded to 16 bytes but not past the MTU. A packet longer
than the MTU is padded by its remainder modulo the MTU, so 1,430 bytes
at an MTU of 1,420 becomes 1,436, not 1,430. The first version left
such packets alone, and wireguard-go's `open` of a 1,430-byte message
showed the difference.

### Replay

A transport counter is accepted once, within 2,048 of the highest seen,
and the window moves only after the tag verifies: a forged counter must
not move it. An initiation's TAI64N timestamp must be newer than the
last accepted for that peer, which a file-based state keeps between
runs. **Mitigated** for the example's single session, and a session
neither sends nor accepts past WireGuard's limit of 2^64 - 2^13 - 1
messages (`REJECT_AFTER_MESSAGES`, `test_the_replay_window`); the
timers that start a new handshake after two minutes or 2^60 messages,
and retire keys after three minutes, are not here.

### Cookies

MAC1 is checked before any Curve25519, which is the point of it: a
forged initiation costs one BLAKE2s. MAC2 and the cookie reply exist
for a responder under load, which this example is only when asked. The
secret is the caller's to rotate every two minutes. **Accepted.**

## 7zz. The git signing example

`examples/products/gitsign`.

### `G` and `U`

git reports a good OpenPGP signature as `U`, good but of unknown
validity, unless gpg's status output carries a trust level of marginal
or above, and `verify-commit` still succeeds either way. The `gpg`
stand-in has no trust database. The keys `GITSIGN_KEYRING` names are the
caller's statement of whom to trust, so a good signature by one is
reported `TRUST_FULLY`. The first version said nothing, and the check
script's `%G?` assertion found it. **Accepted**, as a policy the keyring
expresses.

### Validity dates at signing time

git passes `ssh-keygen` the commit's time as `verify-time`, so an
allowed signers line is judged when the commit was made, not when it is
checked: a key that expired since still verifies its old commits. The
times are read as UTC; ssh-keygen reads them as local time unless they
end in `Z`. **Accepted**, and stated in `ssh.rs`.

### A key in a file, not an agent

`-Y sign -U`, signing through ssh-agent, is refused, and a signing key
given as its `.pub` is signed with by the private key beside it. The
private key is read from disk for each signature. **Accepted** for an
example.

### Where the signature is

A tag's signature starts at the last line that begins one. A message can
quote an armour line at the start of a line, and splitting at the first
would hand the verifier half the message as signature
(`test_a_tag_quoting_a_signature_splits_at_the_last`, from the sweep).

---

## 7zza. Ciphertext stealing, the little-endian counter, CBC-HMAC and CBC-MAC

`block_ciphers::modes` (`CtsState`, `CtrState::new_little_endian`),
`block_ciphers::cbc_hmac` and `mac::cbc_mac`.

### Three ciphertext stealings, one name

"CBC-CTS" is three modes. CS1 keeps CBC's order of the last two
pieces, CS2 swaps them only when the last block is partial, CS3 always
swaps - so the three agree on some lengths and not others, and two
implementations disagreeing on which they meant interoperate on whole
blocks for CS1 and CS2 and nowhere else. **Mitigated**: the mode names
say which (`cbc-cs1` to `cbc-cs3`), there is no bare `cts`, and
`scripts/diff_check.py block` checks all three, both directions, against
OpenSSL's `cts_mode`, for AES and Camellia, at every length from 16 to
136 and at 255 to 257, 511 to 513, 1023 and 1024; RFC 3962's six
vectors pin CS3.

### Ciphertext stealing cannot stream to the end

Which of the last two blocks goes where is known only when the message
ends, so `CtsState` holds back up to two blocks and `finish` writes
them. A caller that ignores `finalize`'s return value loses the end of
the message. **Mitigated**: `finish` is where those bytes come from in
every interface, and a test streams in pieces and compares with one call.

### A counter that counts the other way

WinZip AES counts the whole 16-byte block as one little-endian integer
from 1. Ordinary CTR (big endian) agrees with it on no block at all, and
a little-endian increment of the last eight bytes only - the other
common reading - agrees for 2^64 blocks and then not. **Mitigated**:
`ctr-le` is its own mode with a test whose counter carries into the
ninth byte, and the zip example's archives from 7-Zip and libarchive.

### CBC-HMAC's associated data length is in bits

RFC 7518's tag covers `AL`, the associated data's length as 64 bits -
in **bits**, not bytes. A byte count gives a tag that agrees with itself
and with nobody. **Mitigated**: RFC 7518 appendix B's three cases, read
out of the document, and jwcrypto through the JOSE example. The tag is
checked before decryption, so the padding is never an oracle.

### CBC-MAC is forgeable across lengths

The MAC of a one-block `M` is also the MAC of `M || (M XOR tag)`.
**Accepted**: it is the algorithm, kept for DES-MAC and Kerberos's
checksums; `test_the_length_extension_forgery` states it, and the docs
point to CMAC.

## 7zzb. SP 800-108, the Concat and X9.63 KDFs, and RFC 3961

`kdf::nist` and `kdf::kerberos`.

### Where the counter goes

The Concat KDF hashes `[i]_32 || Z || OtherInfo` and X9.63 hashes
`Z || [i]_32 || SharedInfo`. Either one with the counter moved is the
other, and both sides of a protocol written by one hand agree with each
other. **Mitigated**: `scripts/diff_check.py mackdf` checks both against
python-cryptography's `ConcatKDFHash` and `X963KDF` over SHA-1 and
SHA-2 at lengths from one byte to several blocks (1, 20, 32, 33, 64, 65
and 129), and `test_concat_and_x963_differ_only_in_the_counter_s_place`
pins which is which.

### SP 800-108's fixed data is a choice

The standard leaves the encoding of the fixed data, the counter's width
and its position to the protocol. Here it is `label || 00 || context ||
[L]_32` after a 32-bit counter, which is RFC 8009's and RFC 6803's.
`L` is in every block's input, so a shorter request is not a prefix of
a longer one. **Accepted**: other layouts are other functions, not
options on this one. The counter and feedback modes are checked against
OpenSSL's `KBKDF` (feedback through libcrypto, in `diff_check.py` only)
and python-cryptography's `KBKDFHMAC` and `KBKDFCMAC`.

### n-fold is easy to get almost right

Each copy is rotated 13 bits further *right* than the last, and the
copies are summed in ones' complement, with the carry out of the top
going back in at the bottom. RFC 3961 5.1 notes that the sample vector
in the paper that defined it appears to be wrong, so a reading checked
only against the paper is checked against nothing. **Mitigated**: RFC
3961 A.1's eleven n-folds, read out of the document in the Rust and
the Python tests, and `test_nfold_against_its_definition`, which
computes n-fold on whole bit strings rather than byte by byte, for 24
input lengths into 9 output lengths.

### DES string-to-key corrects a weak key twice

Once on the fan-folded intermediate key and once on the CBC checksum
that follows. Two of RFC 3961 A.2's six vectors reach the first; the
RFC says it has none that reach the second, and finding a password that
does is a search. **Mitigated**: all six vectors, read out of the
document, and `test_the_checksum_output_is_corrected_when_weak`, which
chooses the checksum's input block so that its output is a weak key.

## 7zzc. OpenPGP's S2K, 7-Zip's key, KeePass's AES-KDF, LUKS's AF splitter

`kdf::password` and `kdf::luks_af`.

### The S2K count is octets, not iterations

An iterated S2K hashes `count` octets of `salt || passphrase` repeated,
the last copy cut wherever the count falls - not `count` copies, and
not whole copies. The repetition is built 64 KiB at a time, so a count
that is not a multiple of the unit has to continue the repetition
across the buffer's boundary. **Mitigated**: `test_openpgp_s2k_by_hand`
hashes 65,581 octets of a 6-octet unit, and `diff_check.py mackdf`
compares counts on both sides of 65,536 with the definition built in
one piece.

### An empty passphrase with no salt

Repeating nothing never reaches a count, and the first version looped
waiting for it. No OpenPGP packet reaches the case - an iterated S2K
always has a salt - but the library function does. **Mitigated**:
nothing is hashed, and a test says so.

### 7-Zip's cost has no ceiling here

The cycle count is a six-bit field the archive sets; 7-Zip reads at
most 2^24 rounds and refuses more. **Accepted**: the library computes
what it is asked, and the example keeps 7-Zip's ceiling.

### LUKS names hashes the kernel's way

`wp256` is Whirlpool cut to 32 bytes, and the AF splitter's diffusion
then works in 32-byte pieces, not 64. **Mitigated**:
`test_the_last_piece_is_cut_and_indexed`, and cryptsetup's images in
the LUKS example.

## 7zzd. Writing encrypted private keys

`x509::encrypted_key::encrypt`.

### Three encodings a round trip cannot check

PBKDF2's PRF is DEFAULT hmacWithSHA1, so DER leaves it out for SHA-1 and
a writer that always includes it writes a file only lenient readers
take. `keyLength` is optional and OpenSSL writes it for RC2 alone. RC2's
effective key length is a parameter version from a table, not the
number of bits. Our reader accepts every variant, so encrypting and
decrypting here agrees whatever the writer chose. **Mitigated**:
`test_reencrypting_openssls_files_reproduces_them` hands each of the 21
pinned OpenSSL files' salt, count and IV back to `encrypt` and requires
the same bytes; python-cryptography reads what is written for the
schemes it still reads.

### The empty PKCS#12 password, written

Reading tries both forms (above). Writing has to pick one, and the
`openssl` command's file was reproduced only with the two NULs - the
first draft followed a comment saying OpenSSL hashed no bytes, and the
byte comparison refused it. **Mitigated**: the two NULs, pinned by the
same test.

## 7zze. BitLocker

`block_ciphers::bitlocker` and the BitLocker example.

### Two IVs from two different numbers

The CBC methods take their IV from the sector's byte offset; XTS takes
its tweak from the sector number in sector-size units. Using the same
number for both reads 512-byte XTS volumes and nothing else.
**Mitigated**: Windows's volumes at both sector sizes and both modes,
whole-volume SHA-256 against cryptsetup's.

### The relocated header is decrypted at its own position

The filesystem's first sectors are stored, encrypted, at the volume
header offset, and must be decrypted with that position's IV, not with
the IV of where they appear. Either choice gives a plausible boot sector
for one sector size or another. **Mitigated**: the same volumes.

### Elephant 128's stored key has gaps

The volume key of an Elephant-128 volume is stored as 64 bytes - the
CBC key, 16 unused, the tweak key, 16 unused - where Elephant-256's is
the two 32-byte keys back to back. **Mitigated**: Windows's volumes of
both, and the volume key compared with cryptsetup's.

### The diffusers are easy to get almost right

Two loops of add-XOR-rotate over 32-bit words, run in opposite orders
for the two directions; a wrong rotation, offset or cycle count gives a
cipher that round-trips with itself. **Mitigated**: the diffusers are
compared with dm-crypt's loop shape in the unit tests and in
`scripts/diff_check.py bitlocker` (with OpenSSL's AES), and Windows's
Elephant volumes decrypt.

### Metadata that only its CRC protects

Three copies of the metadata, each with a CRC-32, which anybody can
recompute. The SHA-256 of the block, sealed with the volume master key,
is what says the metadata is what Windows wrote. **Mitigated**: it is
checked after the VMK opens, and
`test_damaged_and_altered_metadata` changes a byte, redoes the CRC and
requires the refusal.

### A clear key is no protection

A suspended volume carries the key that opens its VMK beside it.
**Accepted**: it is the format; the example opens it as Windows and
cryptsetup do, and the example's documentation of `format --clear-key`
says it writes a suspended volume.

## 7zzf. Wi-Fi: WEP, TKIP, Michael and the WPA handshake

`stream_ciphers::wep`, `stream_ciphers::tkip`, `mac::michael`,
`kdf::ieee80211`, and the `wifi` example.

### TKIP's S-box is the AES S-box doubled

TKIP mixes with a 16-bit S-box whose entries are `2*S(i)` and `3*S(i)`
in AES's field, and the substitution XORs the low byte's entry with the
high byte's byte-swapped. Typing a 512-entry table is the usual way and
a chance to mistype; it is built here from the AES S-box's definition
and pinned to the kernel's shipped table by `vectors/tkip.vec`.
**Mitigated**: the kernel's mixing vectors, and `diff_check.py wifi`.

### Michael is invertible and weak by design

Its block function can be run backwards, so a known-plaintext MIC gives
the key; it has about 20 bits of forgery resistance. 802.11 relies on
countermeasures, not on Michael. **Accepted**: it is the algorithm, kept
because TKIP is; the module comment says so, and the ICV, not Michael,
is the example's per-frame check, matching `airdecap-ng`.

### A captured frame may carry a trailing FCS

Some captures keep the 802.11 FCS (the whole frame's CRC-32) and some
strip it. Left on, it is four extra bytes that make the WEP/TKIP ICV
check fail on every frame. **Mitigated**: the example removes a trailing
FCS when its CRC matches, as `airdecap-ng` does; without it, the WPA
captures decrypted nothing.

### The EAPOL key MIC sits at a fixed offset

The key MIC is 81 bytes into the EAPOL-Key frame, after the nonce, key
IV, RSC and key ID; reading it from the wrong offset gives a MIC that
never verifies and a handshake that never completes. The MIC is computed
over the frame with those 16 bytes zeroed, under HMAC-MD5 for TKIP and
HMAC-SHA1 for CCMP. **Mitigated**: the example derives the key only when
the MIC verifies, and the recorded captures decrypt.

### Counts match only with the retransmit skip

`airdecap-ng` skips a frame whose body CRC equals the last in its
direction, so a capture with retransmissions decrypts fewer frames than
it holds. A reader that does not skip reports more. **Mitigated**: the
example skips the same way, and the counts equal `airdecap-ng`'s.

## 7zzg. The smart card example

`examples/products/smartcard` drives PIV, the OpenPGP card, OATH and the
YubiKey OTP application over PC/SC. Every check here ran against a
virtual card - CanoKey's - with yubikit reading back what the example
wrote; see `examples/products/README.md`.

### No physical card has run it

**Status: accepted.** The virtual card implements the same
specifications, and several of the traps below are its behaviour rather
than the specification's. A real card may differ in each of them, and
in ways nothing here can see. The example's own documentation says so.

### A card that wants an expected length

**Status: mitigated.** ISO 7816-4 lets a command omit Le, and the
virtual card refuses OATH's LIST without one (`6986`). So every command
that reads data sends `Le = 00`, meaning "as much as there is". The OTP
application's commands do not, because yubikit sends them without and a
card written for yubikit expects that. `test_recorded_conversations_replay_byte_for_byte`
holds every command to the bytes the card accepted.

### An answer in pieces, and an answer to a different question

**Status: mitigated.** `61xx` means more data is waiting and is
fetched with GET RESPONSE (OATH's own instruction for it is SEND
REMAINING), and a continuation can itself say `61xx`; `6Cxx` means the
expected length was wrong and the command is sent again with the right
one. `test_continued_answers_are_fetched_and_joined` and
`test_a_wrong_expected_length_is_asked_again`. A long command is split
by command chaining, and a refusal part-way stops the chain:
`test_long_commands_are_chained`.

### ECDSA on a card takes the digest at the key's width

**Status: mitigated.** A P-256 key asked to sign a SHA-384 digest
answered `6700`, wrong length. ECDSA uses the digest's leftmost bits as
wide as the group (SEC 1 4.1.3), so the example cuts a longer digest
and widens a shorter one with leading zeros, which leaves its value
alone. The recorded `piv sign 9a sha384` conversation fails without it.

### The same RSA key, written two ways

**Status: mitigated.** A card may return a modulus with a leading zero
byte where a certificate has none, so comparing the two as bytes calls
one key two different keys - and the example refuses to write a
certificate for a key the slot does not hold.
`test_an_rsa_key_compares_equal_however_it_was_padded`.

### X25519 is little endian, and the OpenPGP card is not

**Status: mitigated.** RFC 7748 writes a Curve25519 scalar little
endian; the OpenPGP card, following OpenPGP's older convention, stores
it big endian. The scalar is reversed on the way into an OpenPGP slot
and not into a PIV one, and the recorded imports pin both.

### A stored secret is checked, where checking is free

**Status: mitigated for TOTP, accepted for HOTP.** `oath add` asks the
card for a TOTP code after storing a credential and compares it with
the code the secret gives here, so a secret mangled on the way in - a
truncation, the wrong hash - is reported at once.
`test_oath_add_refuses_a_card_whose_code_disagrees` changes one digit
of a recorded answer, since no honest card can reach that branch. An
HOTP credential is not checked that way, because asking for a code
advances its counter, and a touch credential would wait for a finger.

### Resetting PIV means blocking it first

**Status: mitigated.** The card refuses PIV's reset until both the PIN
and the PUK are blocked, so the example spends their remaining tries
with wrong values and then resets. Like the OpenPGP reset, it is
destructive by design, and the recorded `piv reset` conversation pins
the order.

### The version number lies

**Status: accepted.** The virtual card reports version 0.0.0, and
yubikit reads that as "a YubiKey older than 5.4" and assumes a Triple-DES
management key. The example reads the key's type from the card's
metadata where the card offers it, and falls back to the certificate
for the public key where it does not; the check script tells yubikit
the key type rather than letting it guess.

## 7zzh. The C interface

`include/allcrypt.h` and `src/capi.rs`, behind the `c-api` feature.
[c.md](c.md) has the conventions.

### A verifier's result is not a boolean

**Status: mitigated by design.** The verifiers return `ALLCRYPT_OK`,
`ALLCRYPT_INVALID` or `ALLCRYPT_ERROR`, and only `ALLCRYPT_OK` is zero.
A caller who writes `if (allcrypt_ec_verify(...))` therefore treats a
*good* signature as the failure - wrong in the direction that is
noticed, rather than a bad signature accepted. The header and
[c.md](c.md) say to compare with `ALLCRYPT_OK`.

### A header the compiler cannot check against the library

**Status: mitigated.** A prototype that says `size_t` where the library
takes `uint32_t` compiles, links and passes the wrong argument, and no
C compiler can see it: the header is the only description of the
library it has. `scripts/check_c_api.py` compares every exported
function with its prototype - parameter names and types in order, the
return type, and the constants - and fails if either side has a
function the other lacks.

### A type and a function with one name

**Status: mitigated.** The first header named the hash object
`allcrypt_hash`, which is also the one-shot function's name; C keeps
typedef names and function names in one namespace, so that is an error
in C as well as C++. The objects are `allcrypt_hash_state` and
`allcrypt_hmac_state`, and the check script compiles the header as C++
too, which is what caught it.

### No password and an empty password

**Status: mitigated.** A NULL password means the file is not encrypted;
a non-NULL password of length zero is the empty password, and a key
encrypted under it is a real file OpenSSL writes. Merging the two makes
that file unreadable. The check script has OpenSSL write one and the C
test reads it both ways. python-cryptography cannot write it: it reads
`b""` as no password.

### Freed memory is zeroed, and nothing can show it

**Status: accepted.** `allcrypt_buffer_free` overwrites the bytes with
volatile writes before releasing them, so a key or a plaintext does not
outlive its buffer in the allocator's free list. No test can observe
that from C without reading freed memory, which is undefined behaviour,
so it is held by reading the code rather than by a test.

### A panic is caught, and nothing makes one

**Status: accepted.** Every function runs its body inside
`catch_unwind` and turns a panic into `ALLCRYPT_ERROR`, because a panic
leaving an `extern "C"` function aborts the caller's process. No input
the tests know of makes the library panic, so the path that turns one
into an error has no test of its own.

### The pointer contract cannot be checked

**Status: accepted.** NULL is checked everywhere and refused with a
message. A pointer to too little memory, a length that overstates the
buffer, or an object used after its `_free` cannot be detected from
inside the library, as in any C interface.

### Built and run on Linux only

**Status: open.** The C test runs against the shared and the static
library on Linux. The Windows and macOS file names in [c.md](c.md) are
cargo's conventions; neither build has been compiled and linked here.

## 7zzi. NaCl and libsodium

`src/nacl.rs`: secretbox, box, sealed boxes, `crypto_kx`, `crypto_auth`,
combined signatures, and Ed25519 to X25519 keys. `vectors/nacl.vec` is
NaCl's own examples and libsodium 1.0.18's answers, with Go's
`x/crypto/nacl` agreeing where it can; `tests/test_nacl.rs` reads it.

### Two constructions called XChaCha20-Poly1305

**Status: mitigated.** libsodium's `crypto_secretbox_xchacha20poly1305`
and the AEAD `xchacha20-poly1305` share a key size, a nonce size and
nearly a name, and differ in three ways: Poly1305 covers the ciphertext
alone (no additional data, padding or lengths), the payload starts at
keystream byte 32 rather than 64, and the stream is the 8 byte nonce,
64 bit counter ChaCha20. Either way round, the result encrypts and
opens its own boxes. `test_the_secretbox_is_not_the_aead` shows the two
disagreeing, and `Construction::from_name` refuses the AEAD's spelling
with a message that names the difference.

### The payload starts in block zero

**Status: mitigated.** The Poly1305 key is the first 32 bytes of the
keystream and the message is encrypted from byte 32, so the rest of
block zero is payload keystream. Discarding it, as the IETF AEAD does,
gives a box that opens itself and nothing else.
`test_the_payload_starts_at_byte_32` checks every length across the end
of the block, and the vectors run from 0 to 4,096 bytes.

### A low-order peer key

**Status: mitigated.** NaCl's `crypto_box` boxed under whatever X25519
returned, so a peer key of small order gave a box key anybody could
compute. libsodium refuses the seven u values of its list, and so does
`box_beforenm`; `vectors/nacl.vec` has all seven for both
constructions, each marked refused.

### A sealed box authenticates nobody

**Status: accepted.** `box_seal` uses a fresh key pair per message, so
the recipient learns that the box was not altered but not who made it:
anybody with the public key can make one. That is the construction's
purpose. A caller that needs the sender wants `box_encrypt`.

### A sealed box's nonce is a function of the keys

**Status: accepted.** The nonce is `BLAKE2b-192(ephemeral_pk ||
recipient_pk)`, so two messages sealed with one ephemeral key to one
recipient share a key and a nonce. `box_seal` draws the ephemeral key
itself. `box_seal_with_ephemeral` takes one, for known-answer tests; it
is public in `nacl` and not in `api` or the bindings, and its comment
says why.

### A 64 byte secret key with two halves that disagree

**Status: mitigated.** libsodium's Ed25519 secret key is the seed
followed by the public key, and it signs with the stored public half as
it stands. With a wrong public half, two signatures of one message give
away the private scalar. `nacl::sign` derives the public key from the
seed and refuses a 64 byte key whose second half differs;
`test_signed_messages_and_both_key_forms` flips a byte of it.

### One seed, two key pairs

**Status: mitigated.** `crypto_box_seed_keypair` takes the first half of
SHA-512 of the seed and `crypto_kx_seed_keypair` takes BLAKE2b-256 of
it, so the same seed gives different keys through the two. Both are
reproduced as libsodium has them, and a test asserts that they differ.

### Converting a public key with a torsion component

**Status: mitigated.** Ed25519 verification accepts a public key with a
small-order component, and that key's Montgomery u is a different key.
`ed25519_public_to_x25519` refuses, as libsodium does, bytes that are not
a point, the small-order points and any point outside the prime-order
subgroup. The vectors include keys with an order-8 component, made by
libsodium's own point addition, and the refusals match libsodium's.

### One key for signing and for exchange

**Status: accepted.** The conversions exist so that one Ed25519 identity
can also receive boxes, which libsodium supports and some protocols use.
Using one key for two schemes ties their security together; nothing here
prevents it, and separate keys are the simpler choice where there is one.

---

## 8. What to do with this document

- When implementing something on this list, link the test that covers it.
- When accepting a pitfall, say so here rather than leaving it unsaid.
- When something moves from **open** to **mitigated**, the commit that does it
  should say so.
- New algorithm, product example or interface, new section.
  `docs/extending.md` has the testing checklist; this is the
  security-specific companion to it.
