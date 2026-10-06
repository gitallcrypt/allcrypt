# Post-quantum: what is built and what is next

**SLH-DSA is complete and matches all 264 of NIST's ACVP vectors** - key
generation, signing and verification, through both the internal and
the external interface, with all twelve pre-hash functions, across all
twelve parameter sets. See `src/pq/slh_dsa.rs` and
`tests/test_slh_dsa.rs`. ML-KEM and ML-DSA are complete too, in
`src/pq/ml_kem/` and `src/pq/ml_dsa/`, and so is Streamlined NTRU Prime
for SSH.

The state of it, in one table:

| | Built | Checked against |
|---|---|---|
| SLH-DSA key generation | yes | 120/120 ACVP `keyGen` vectors |
| SLH-DSA internal signing | yes | 72/72 ACVP `sigGen` `internal` cases, deterministic and hedged |
| SLH-DSA internal verification | yes | the same 72, since a matching digest means the signature *is* NIST's |
| SLH-DSA external interface, pure and pre-hash | yes | 72/72 ACVP `sigGen` external cases, all twelve pre-hash functions |
| SLH-DSA Python bindings, external interface | yes | NIST's vectors read from `pytests/test_slh_dsa.py` |
| SLH-DSA negative verification cases | yes | 36/36 ACVP `sigVer` refusals and 6/6 acceptances, at `SHA2-128s` and `SHAKE-128s`, every interface, every reason; from Python too |
| ML-KEM's ring, NTT and compression | yes | the NTT against a schoolbook convolution; 13/13 breakage faults caught |
| ML-KEM encodings, samplers and key generation | yes | 75/75 ACVP `keyGen` vectors, all three parameter sets; 17/17 faults caught |
| ML-KEM encapsulation, decapsulation and the FO transform | yes | 30/30 ACVP `encapsulation`, 30/30 `decapsulation` (half of them implicit rejections, measured), 60/60 key checks (30 negative); 22/22 faults caught |
| ML-KEM `api` and Python bindings | yes | `from_seed` gives NIST's keys; both imports refuse exactly NIST's 30 invalid keys; NIST's decapsulations read from `pytests/test_ml_kem.py` |
| ML-KEM constant time | yes | `ct_check.py`: encapsulation and both decapsulation paths clean under valgrind; no division instruction anywhere in ML-KEM; 4/4 timing faults caught |
| ML-KEM differential check | yes | `diff_check.py mlkem`: 600 random cases against a second ML-KEM written there from FIPS 203, itself checked against all 195 NIST cases first |
| ML-DSA key generation, signing and verification | yes | 75/75 ACVP `keyGen`, 72/72 `sigGen` across all 24 groups (deterministic and hedged; internal, external `mu`, pure, all twelve pre-hashes), 60/60 `sigVer` with 48 refusals; 25/25 faults caught, three of them only after new tests |
| ML-DSA differential check | yes | `diff_check.py mldsa`: 126 random cases (key pairs, deterministic and hedged signatures, verifications both ways) against a second ML-DSA written there from FIPS 204, multiplying by Kronecker substitution rather than the NTT; itself checked against all 207 NIST cases first |
| ML-DSA `api` and Python bindings | yes | `from_seed` gives NIST's keys, `from_private` recomputes NIST's public keys and signs NIST's deterministic signatures, the public key refuses NIST's external refusals; from Python too |

Verification deserves a note, because "checked against NIST" means
something slightly indirect there. The vendored `sigGen` cases store each
signature's SHA-256 rather than its bytes, for size reasons the generator
script explains. For a *deterministic* signature there is one right
answer, so a matching digest establishes that our signature is NIST's
byte for byte - and the test then hands that signature to our own
verifier. So verification is checked against bytes NIST produced, at no
storage cost. Rejection of signatures NIST says are invalid is the
`sigVer` file's job, and 42 of its cases are vendored in
`vectors/slh_dsa_sigver.vec` - see the table.

The three NIST standards published in August 2024 are ML-KEM (FIPS 203),
ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). They are the ones that will be
in TLS, in SSH, in code signing and in certificates, and they are the
ones a library called "all crypt" will eventually be asked for.

They are also, for this library, a **different kind of work** from
everything in it so far, and that is the first thing to be clear about.

## Why these are unlike the rest of the library

Every public-key algorithm here rests on `bignum`: RSA, finite-field
Diffie-Hellman, the Weierstrass curves, X25519, EdDSA. One arbitrary
precision integer type, one Montgomery context, one set of pitfalls.

None of the three lattice or hash standards uses a big integer anywhere.

* **ML-KEM and ML-DSA** are arithmetic on polynomials with small
  coefficients - 12 bits for ML-KEM, 23 for ML-DSA - in a ring
  `Z_q[X]/(X^256 + 1)`. The multiply is an NTT, a number-theoretic
  transform, which is an FFT over a finite field. Everything is
  `i32`/`u32` arrays of length 256. A `BigUint` would be actively wrong
  here: it is variable-width and normalised, and these coefficients are
  fixed-width by construction.
* **SLH-DSA** is nothing but hashing. No arithmetic at all: Merkle trees,
  one-time signatures and a hypertree, built out of SHA-2 or SHAKE. It is
  the one this library is best equipped for today, because
  `hash_functions/keccak.rs` and `hash_functions/sha2.rs` already exist
  and are the whole dependency.

So the order below is not the order of importance. It is the order of
what this library can already check.

## What is next, in order

### 1. SLH-DSA (FIPS 205) first, though it is wanted least

**It is done.** What follows is why it went first, and then what is
left of it.

Nothing new underneath it. SHAKE256 and SHA-256 are here, tested against
hashlib over tens of thousands of cases, and FIPS 205 is a construction
on top of them. If a mistake is made it will be in the tree walking and
the address encoding, not in a primitive.

It is also the slowest and largest of the three by a wide margin - a
signature is 7856 bytes at the smallest parameter set - which is why
nothing wants it first, and why getting it wrong is cheap to discover:
the intermediate values are all hashes, and every one of them can be
printed and compared.

What it needed, and how much of it is there:

* the parameter sets (`SLH-DSA-SHA2-128s` through `SLH-DSA-SHAKE-256f`) -
  twelve of them, and they differ in more than numbers. **Done**, and the
  difference turned out to be worse than "different `H_msg`": above
  `n = 16` the SHA-2 family uses SHA-256 for `PRF` and `F` and *SHA-512*
  for `H` and `T_l`, with a different amount of zero padding for each.
  One hash function throughout passes at 128 bits and fails at 192 and
  256, which is the sort of mistake that looks like a working library.
* WOTS+, FORS, the XMSS layer and the hypertree. **Done.** WOTS+ public
  keys and the XMSS tree came first, because they are what a key is; key
  generation only ever builds the top tree's root. FORS and the
  hypertree's signing path followed with signing, below.
* the `ADRS` address structure, which is 32 bytes for SHAKE and a
  compressed 22 for SHA-2, and is the thing most likely to be wrong in a
  way that is self-consistent. **Done**, and handled by making the
  dangerous thing unrepresentable rather than by being careful: there is
  no way to set an address's type without also writing every word that
  type uses, because the setters are one-per-type and take all of them.
  The three `FORS_*` types have setters of their own on the same rule.

Done since, in this order:

1. `H_msg` and `PRF_msg`. These are the two that are not a bare keyed
   hash: `PRF_msg` is HMAC in the SHA-2 family, because its first
   argument is a secret and a bare `SHA-256(SK.prf ‖ ...)` would be
   length-extendable, and `H_msg` is **MGF1** over the family's hash,
   because `m` is 30 to 49 bytes and no SHA-2 output is that length. MGF1
   is the same function RSA-OAEP and PSS use, so `rsa.rs`'s was made
   `pub(crate)` rather than copied.
2. WOTS+ signing and public-key recovery, FORS, the XMSS layer and the
   hypertree - where the other `d - 1` layers finally do something.
3. `slh_sign_internal` and `slh_verify_internal`.

The external interface came next and is done: `slh_sign` wraps the message
in a domain separator byte, the context string with its length, and - in
the pre-hash form - the hash function's DER OID in front of the digest.
All three parts are domain separation rather than framing, and the twelve
pre-hash OIDs were added to `x509::oids` rather than written out here, so
`scripts/diff_check.py` checks them against OpenSSL's object table.

Python bindings followed: `allcrypt.SlhDsaKey`, over the external
interface only. `pytests/test_slh_dsa.py` reads NIST's vectors itself
rather than round tripping, so the bindings are checked against the same
numbers by a second route - and it skips the internal and hedged sections
explicitly, because neither is reachable from Python by design.

What is left:

1. **`sigVer`, for the negative cases** - done for two parameter sets of
   twelve, `SLH-DSA-SHA2-128s` and `SLH-DSA-SHAKE-128s`: every group and
   every one of ACVP's seven reasons. Signatures are inputs there, so they
   cannot be stored as digests, and the full file is 30 MB; the two kept
   are the smallest signature in each hash family.
2. **A file format.** There is no PEM, DER or certificate support for
   these keys - only the FIPS 205 byte strings, which is what every
   implementation agrees on.
3. ML-KEM, then ML-DSA - both done.

Two numbers to keep in view, both measured rather than estimated.

A key at the `s` parameter sets costs about a quarter of a million hash
calls, because the root of a tree over `2^h'` one-time keys needs every
leaf. **A signature costs more, not less** - roughly `d` times a key -
because every authentication path node at height `j` is itself the root of
a subtree with `2^j` leaves, and there are `d` layers. So:

| | release | debug | ratio |
|---|---|---|---|
| 120 `keyGen` cases | 17 s | ~7 min | 24x |
| 36 fast `sigGen` cases | 7 s | 212 s | 29x |
| 12 small `sigGen` cases | 33 s | ~16 min | - |
| 72 external cases | 99 s | - | - |
| all 264 | 217 s | - | - |

`tests/test_slh_dsa.rs` therefore runs a subset on every build and keeps
the full sweep behind `--ignored`; that file's own comments say exactly
which combinations each covers, and the one structural difference the slow
sets have - a two byte leaf index where `h' = 9` - is checked directly by
a test that costs nothing rather than being left to the slow ones.

Reference to check against: **NIST's ACVP vectors** - see "What would
have to exist first" below, which used to say this was unsolved and was
wrong. No second implementation is used as a check:
python-cryptography 46 has no SLH-DSA, and OpenSSL 3.5, which added it,
is not used as a witness for it. So the vectors are the whole of the
independent opinion here rather than a supplement to one, which raises
the bar on the parser: a vector file that silently parses to nothing turns every
loop into a pass. The count assertion that `src/ec/eddsa.rs` and
`src/block_ciphers/keywrap.rs` both carry is not optional here.

### 2. ML-KEM (FIPS 203)

The one that is actually being deployed: `X25519MLKEM768` is already in
Chrome and in OpenSSL 3.5, and it is what a TLS 1.3 `key_share` will
carry.

What it needs, in order, because each piece is testable on its own.
**The first three are done**, in `src/pq/ml_kem/ring.rs`:

1. **`Z_q[X]/(X^256+1)` with q = 3329** - done. Reduction is `% Q` on a
   compile-time constant, which LLVM turns into a multiply and a shift, so
   there is no division and no data-dependent branch. The Barrett and
   Montgomery reductions this used to call for were not written: they are
   an optimisation, and hand-rolling one would be new code to get wrong
   for no measured gain. If profiling ever asks, it arrives with its own
   tests.
2. **The NTT and its inverse** - done, with the twiddle table *computed*
   from `17^BitRev7(i)` by a `const fn` rather than typed. The prediction
   this document made held exactly: the round trip is worth almost
   nothing, and what carries the verdict is
   `intt(ntt(f) * ntt(g)) == f * g` against a schoolbook negacyclic
   convolution written separately. A sweep confirmed it - 13 deliberate
   faults, 13 caught, including a twiddle index reset per layer and a
   missing final scaling, both of which survive a round trip untouched.
3. **Compression and decompression** - done, and the rounding was the
   whole difficulty as predicted. The test asserts the error *reaches*
   FIPS 203's bound rather than merely respecting it, because a truncating
   implementation exceeds the bound while a bound computed too generously
   is never approached.
4. **The byte encodings and the two samplers** - done. `ByteEncode_d`
   and `ByteDecode_d`, `SampleNTT`'s rejection loop and `SamplePolyCBD`.
5. **K-PKE key generation and ML-KEM's key wrapper** - done, and this is
   where published vectors finally bite: all 75 of ACVP's `keyGen` cases
   pass across the three parameter sets. That one test covers a
   surprising amount at once, because `ek` depends on `SampleNTT` (its
   rejection loop, its twelve bit split and the order of its two index
   bytes), on `SamplePolyCBD`, on the NTT and the base-case multiply, on
   `ByteEncode_12`, and on `G` being fed the `k` domain separator. A
   mistake in any of them changes every byte.
6. **Encapsulation, decapsulation and the FO transform** - done.
   `vectors/ml_kem.vec` now carries 120 more ACVP cases: 30
   encapsulations, 30 decapsulations, and 60 key checks of which **30
   are keys NIST says must be refused** - the thing SLH-DSA's vendored
   set lacks entirely. All pass. Two measurements make that mean more
   than it might:
   * NIST's decapsulation cases take **both** FO paths, 5 and 5 per
     parameter set. The test computes `J(z ‖ c)` itself to classify each
     case and fails if a set takes only one - otherwise "always equal"
     or "always different" could pass on whichever path the cases
     happened to use.
   * The key-check verdicts are required from the operations as well as
     from the check functions, so a check that encapsulation forgot to
     call is caught.

   A 22-fault sweep - the transpose of `A`, the PRF counter, `eta1`
   against `eta2`, `e2`, the message decompression, both FO paths, a
   partial comparison, `J`'s input order, both key checks, the rounding
   in `Compress` and `Decompress` - caught all 22.
7. **`api::MlKemKey` and Python bindings** - done. Both imports run the
   FIPS 203 key check, so NIST's invalid keys are refused at the door,
   and the Python tests reach NIST's numbers through their own parser.
8. **The differential check** - done. `scripts/diff_check.py` has its
   own ML-KEM, written from FIPS 203 by different routes wherever the
   standard leaves room: the NTT straight from its definition (the
   residue of `f` modulo each `X^2 - gamma_i`, as two polynomial
   evaluations) and its inverse as interpolation at the 128 roots of
   `Y^128 + 1`, rather than butterflies; `Compress` by exact rational
   rounding; the encodings through an explicit bit list; hashlib's SHA-3
   and SHAKE. It runs all 195 NIST cases before it is trusted, then
   checks `tools/src/bin/diff_ml_kem.rs`'s 600 rows. It is a second reading
   by the same reader, so it adds breadth over inputs nobody chose rather
   than a second opinion on the standard.

The pitfalls worth writing down before starting:

* **ML-KEM's decapsulation must not branch on failure.** The FO
  transform re-encrypts and compares; on a mismatch it returns a
  *deterministic pseudorandom* key derived from the ciphertext and a
  stored secret `z`, not an error. Returning an error is a decryption
  oracle, and it is the single most important thing about implementing
  this correctly. `decapsulate_internal` returns `Result` only for the
  public input checks - lengths and the key's hash check - and the
  comparison is a mask and a `select`, the same shape as
  `ServerConnection::decrypt_premaster` here, which cannot fail for
  exactly the same reason. `docs/pitfalls.md` section 7v has the four
  ways this goes wrong while round-tripping perfectly.
* **The encapsulation key must be checked on input**: FIPS 203 requires
  that the 12-bit-packed coefficients round-trip, which rejects keys
  that are not canonical. Skipping it is a known
  malleability.
* **Everything is fixed size and the sizes are the type.** 768 is not a
  parameter to pass around: `ML-KEM-512`, `-768` and `-1024` have
  different `k`, different `eta`, different compression widths, and a
  function that takes them as numbers will eventually be called with a
  mixed set.
* **The seed expansion is SHAKE-128 with a two byte suffix**, and the
  rejection sampling that reads it must consume exactly the bytes the
  specification says. A sampler that reads three bytes where the
  standard reads twelve bits produces a perfectly good uniform
  distribution and a different key.

Reference: python-cryptography 46 has no KEM module at all, so there is
no Python implementation to differ against. OpenSSL 3.5 has ML-KEM and
is the independent check at the protocol level: the hybrid TLS 1.3
groups complete handshakes with it in both directions
(`scripts/check_pq_witness.py`), and `mlkem768x25519-sha256` runs
against OpenSSH 10.0's sshd.

For the arithmetic itself, the ACVP files, vendored, carry the verdict,
as for SLH-DSA. With one difference worth noting - for the ring and the
NTT there are no published vectors at all, not even ACVP ones, because
they are internal to the scheme. Those rest on structural properties and
on the sweep, and the ACVP vectors cover them indirectly through K-PKE.

### 3. ML-DSA (FIPS 204)

**The scheme is done**, in `src/pq/ml_dsa/`: key generation, signing
and verification, internal and external, with an external `mu` and all
twelve pre-hash functions - the pre-hash wrapping now lives in
`pq::prehash` and is shared with SLH-DSA, since FIPS 204 and FIPS 205
build `M'` identically. All of NIST's vendored cases pass: 75 key
generations, 72 signatures (every one of the 24 `sigGen` groups), and 60
verifications of which 48 must be refused - for a modified message,
commitment, `z` or hint, each named in the test that reads them.

It did not share as much with ML-KEM as this section used to predict.
The ring is a different ring - 23 bit coefficients and a full eight
layer NTT that multiplies coefficient by coefficient, where ML-KEM's
stops at seven and multiplies pairs - so it got its own module rather
than a parameter on ML-KEM's, and the samplers have different byte
disciplines throughout. What carried over is the method: compute the
tables, test the NTT against a schoolbook product, and let the vectors
settle every byte order.

New on top of ML-KEM's machinery: `q = 8380417` rather than 3329, which
changes every reduction constant; `Power2Round`, `Decompose`,
`HighBits`, `LowBits` and `MakeHint`/`UseHint`; and the rejection loop in
signing, which **repeats until the signature is in range** and is
therefore variable time in a way that is deliberate and must not be
"fixed".

The pitfall to write down first: **ML-DSA signing is randomised by
default and has a deterministic ("hedged" off) mode**, and the two
produce different signatures from the same key and message. Both are
valid. A test that asserts determinism would be asserting the wrong
thing - unlike EdDSA, where determinism *is* the specification.

`api::MlDsaKey` and the Python `MlDsaKey` are the external interface
over it, and `scripts/diff_check.py` has a second reading of it.
`scripts/ct_check.py`'s `ml_dsa_sign` row measures signing under
valgrind and allows exactly three named places - the rejection decision,
`SampleInBall` on the commitment's hash, and the packing of the
published hint - after four others were made branchless.

**In certificates and in TLS 1.3, too.** RFC 9881's encoding is in
`x509` - the three OIDs as both key and signature algorithm, absent
parameters, the BIT STRING as FIPS 204's raw key, pure ML-DSA with an
empty context over the TBS - with the private key in all three of its
section 6 forms, each checked for consistency on the way in. The
certificate builder and `CertificateAuthority` issue them
(`key_type="ML-DSA-65"`), and draft-ietf-tls-mldsa's three schemes are
offered, signed and verified at TLS 1.3, for servers and for client
certificates. Checked against:

* **RFC 9881's appendix**, read out of the vendored document
  (`src/x509/rfc9881_tests.rs`): nine private keys, three public keys,
  three self-signed certificates, and the three deliberately
  inconsistent keys, all refused.
* **OpenSSL 3.5.4, offline** (`tests/test_ml_dsa_openssl.rs`): its keys
  in all three forms, its certificates and a chain whose every link
  crosses parameter sets, 24 `pkeyutl` signatures with and without a
  context, and three recorded TLS 1.3 handshakes whose CertificateVerify
  is checked here. Regenerated by `scripts/capture_mldsa.py`.
* **OpenSSL 3.5.4, live, 9 of 9** (`scripts/check_mldsa_witness.py`):
  for each parameter set, our client against `s_server` with OpenSSL's
  certificate; `openssl verify -x509_strict` on our CA's chain; and
  `s_client -verify_return_error` against our server with our CA's
  certificate, reporting `Signature type: mldsa44` (`65`, `87`),
  `Verification: OK`, and the group X25519MLKEM768 - a handshake with
  no classical-only step in it.

## What would have to exist first

* **An offline source of test vectors that is not us.** This was
  written as the blocker for all three, and **it is not one** - checked
  rather than assumed, and the assumption was wrong. NIST publishes the
  ACVP vectors as JSON in `usnistgov/ACVP-Server`, and they can be
  fetched:

  ```text
  ML-KEM-keyGen-FIPS203/prompt.json             16 KB
  ML-KEM-keyGen-FIPS203/expectedResults.json   531 KB
  ML-DSA-sigGen-FIPS204/prompt.json            4.8 MB
  ```

  The shape is a list of `testGroups`, each with a `parameterSet`
  (`ML-KEM-512` and the rest) and its `tests`; `keyGen`'s inputs are the
  two seeds `d` and `z`, and `expectedResults.json` carries the answers
  by `tcId`. One parser serves all three standards, and the files are
  vendored and read at test time exactly as `rfcs/` already is - so this
  is the same arrangement rather than a new one.

  The sizes mean the choice is which parameter sets to vendor rather
  than whether to. `ML-DSA-sigGen` at 4.8 MB is the largest and can be
  trimmed to the groups actually exercised, with the trimming done by a
  committed script so it is re-runnable rather than a one-off edit.
* **A small fixed-width polynomial type**, with its own `ct` discipline.
  `bignum::Secret` is the model - no `Ord`, no `Debug`, fixed width -
  but the type is different enough that it should not try to reuse it.
* **`scripts/ct_check.py` rows for all of it.** Both lattice schemes
  have secret-dependent arithmetic throughout, and the rejection
  sampling in ML-DSA is a timing signal by construction. The existing
  valgrind harness extends to this directly, and the table's "named
  leaks rather than counted ones" rule applies unchanged. **Done for
  ML-KEM and for ML-DSA signing** (section 3 has the `ml_dsa_sign`
  row). For ML-KEM, encapsulation and both decapsulation paths are clean
  rows, after the per-coefficient range checks on K-PKE's paths were moved
  out of them, and a disassembly scan fails on any division in ML-KEM -
  which found one, in `ByteDecode_d`, of the KyberSlash kind. Section 7v
  of `docs/pitfalls.md` has both.

### 4. Streamlined NTRU Prime (sntrup761) - done, for SSH

Not a NIST standard: NTRU Prime was an alternate in round 3 and went no
further. It is here because OpenSSH made `sntrup761x25519-sha512` its
default key exchange in 9.0 (2022) and kept it until 9.9 replaced it
with ML-KEM - so every OpenSSH from 9.0 to 9.8, which is a great many
servers, offers it first. A library meant to talk to the servers that
exist needs it, standard or not.

`pq::sntrup` follows the round 3 definition as the Sage reference in
draft-josefsson-ntruprime-streamlined-00 gives it, and that draft's two
test vectors are read out of the vendored document: key generation,
encapsulation and decapsulation from a NIST CTR_DRBG seed, all matching
to the byte. Then `sntrup761x25519-sha512` runs against OpenSSH 10.0's
sshd, and three recorded sessions replay in the gate.

The pitfall worth naming: the test vectors depend on **how the random
source is called**, not only on what it returns. NIST's DRBG throws away
the unused end of each call's last block, and the reference draws four
bytes at a time; an implementation that draws the same bytes in larger
calls is correct and matches no vector. The `Fill` here is called in the
reference's pieces.

Like ML-KEM, decapsulation never fails: a ciphertext that does not
re-encrypt to itself gives a key derived from the secret `rho`, chosen by
a mask, and the weight check substitutes rather than rejects.

## What is deliberately not on this list

* **Hybrid key exchange in TLS** - now done, in `src/tls/kex.rs`
  rather than here, since it is TLS work: X25519MLKEM768 and
  the two NIST-curve hybrids of RFC 10024, at TLS 1.3. It waited, as this
  bullet said it would, until ML-KEM had an opinion other than its own
  behind it - NIST's vectors and the second reading. It has since been
  checked against OpenSSL 3.5 in both directions
  (`scripts/check_pq_witness.py`), and against Cloudflare's and Google's
  public servers (`scripts/check_live.py --pq`), all of which negotiate
  X25519MLKEM768 with it.
* **The NIST round 4 alternates** (HQC, BIKE, Classic McEliece) and the
  additional signature candidates. If one is standardised it comes here
  then. Implementing a candidate that does not become a standard is the
  one kind of work this library has no appetite for, because the point
  of it is that nothing gets removed - and something that was never
  standardised is the one thing that could reasonably be.
* **SLH-DSA in a certificate or a handshake.** ML-DSA's are done (see
  section 3); SLH-DSA has RFC 9909 for certificates and no TLS
  codepoint, and its signatures are 8 to 50 KB.

## Honest summary

This is a large piece of work - considerably larger than everything in
`src/ec/` put together. It was written here as blocked on getting a set
of vectors that somebody else produced; that turned out
to be wrong, and the correction is above: NIST's ACVP JSON fetches
today and covers all three standards.

So the first step was code, and it has been taken. SLH-DSA key
generation went first because nothing new sits underneath it, and it
matched NIST's answers for all twelve parameter sets - which is worth
recording precisely, because it is a narrower claim than "SLH-DSA
works": no message has been signed by this library, and the four hash
functions key generation uses are four of the six the scheme needs.

What has not changed is why the vectors matter. Writing any of the three
against nothing but itself would produce something self-consistent, which
is the failure this repository has spent most of its testing effort
learning to avoid - and SLH-DSA is the case where that risk is highest,
because no second implementation is used to disagree with it. The 120
vectors are the entire independent opinion, and the test
that reads them asserts their count before it uses them for exactly that
reason.

Since then: SLH-DSA is complete, and so is ML-KEM, each with an `api`
and a Python surface, and ML-KEM has a second reading in
`diff_check.py`. ML-DSA is done too, with an `api` and a Python
surface, passes every vendored NIST case, has a second reading in
`diff_check.py`, and a measured `ct_check.py` row for signing.
