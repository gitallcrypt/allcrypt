# Vendored test vectors

Unmodified test-vector files from other projects, here so the test suite
can read somebody else's numbers back **with no network access** — the
same rule `rfcs/` follows, and for the same reason. See
[docs/extending.md](../docs/extending.md#where-test-vectors-come-from):
a vector transcribed into a source file is a vector that was typed, and
this repository has been bitten by that twice.

## Why these are not in `rfcs/`

`rfcs/` holds unmodified standards texts. These are test data from a
different implementation, which is a different kind of claim: an RFC is
the authority for what an algorithm *is*, and a vector file is evidence
that somebody else's code agrees. Mixing them would blur that, and the
`rfc_oids.py` check walks `rfcs/` expecting documents.

## What is here

| file | from | covers |
|---|---|---|
| `twofish.vec` | Botan, `src/tests/data/block/twofish.vec` | 723 Twofish vectors across all three key sizes |
| `serpent.vec` | Botan, `src/tests/data/block/serpent.vec` | 1047 Serpent vectors across all three key sizes |
| `eax.vec` | Botan, `src/tests/data/aead/eax.vec` | EAX over AES-128/192/256, Blowfish, DES, 3DES and Twofish, with and without associated data, and a truncated-tag section |
| `whirlpool.vec` | Botan, `src/tests/data/hash/whirlpool.vec` | 11 Whirlpool vectors, the longest several blocks long |
| `xtea.vec` | Botan **2.19.5**, `src/tests/data/block/xtea.vec` | 68 XTEA vectors, several of them several blocks long |
| `cryptopp_tea.txt` | Crypto++, `TestVectors/tea.txt` | 64 TEA vectors and 64 XTEA vectors — the latter at **every** round count from 1 to 64. A different project and a different format, so `block_ciphers::cryptopp_vector_file` reads it rather than `vector_file` |
| `slh_dsa.vec` | **generated here** from NIST's ACVP JSON by `scripts/make_slh_dsa_vectors.py` | SLH-DSA key generation (120) and signing (144), all twelve parameter sets; signatures as length, 256 byte prefix and SHA-256 |
| `slh_dsa_sigver.vec` | **generated here** from NIST's ACVP JSON by `scripts/make_slh_dsa_sigver_vectors.py` | SLH-DSA verification: 42 cases at two parameter sets, 36 of them signatures that must be refused, each with ACVP's reason |
| `ml_kem.vec` | **generated here** from NIST's ACVP JSON by `scripts/make_ml_kem_vectors.py` | ML-KEM key generation (75), encapsulation (30), decapsulation (30) and both key checks (60, half of them keys that must be refused) |
| `ml_dsa.vec` | **generated here** from NIST's ACVP JSON by `scripts/make_ml_dsa_vectors.py` | ML-DSA key generation (75) and signing (72, three from each of the 24 groups, all twelve pre-hash functions); keys and signatures as length, prefix and SHA-256 |
| `ml_dsa_sigver.vec` | **generated here**, same script | ML-DSA verification: 60 cases, 48 of them signatures that must be refused, each with ACVP's reason |
| `gost_engine.vec` | **generated here** from OpenSSL's gost-engine — see below | Kuznyechik and Magma in every mode, GOST 28147-89 under two parameter sets, CTR-ACPKM across its section boundary, three digests, MGM, OMAC, the 28147-89 MAC, KExp15, TLSTREE, VKO on all nine curves, and GOST R 34.10-2012 signatures |
| `ssh_keys.vec` | **generated here** from OpenSSH 10.0's `ssh-keygen` by `scripts/make_ssh_vectors.py` | Seven keys (Ed25519, ECDSA P-256/384/521, RSA 1024/2048/3072): `.pub` line, bits, SHA-256 and MD5 fingerprints, the private key file; each re-encrypted under all ten ciphers OpenSSH writes keys with (70 files, bcrypt_pbkdf); and 14 SSHSIG signatures verified by `ssh-keygen -Y verify` before being recorded |
| `umac_nettle.vec` | **generated here** from Nettle 3.9 (`libnettle.so.8`, through `ctypes`) by `scripts/make_umac_vectors.py` | 812 UMAC tags at all four tag lengths over 203 message lengths from 0 to 2^25 + 11 bytes - every NH padding case, the 1024 byte L1 boundary, and both sides of the 2^24 byte switch to POLY's 128 bit stage - plus 22 with SSH's sequence-number nonces. Messages are described by length and seed rather than stored |
| `lrw_aes.vec` | Linux, `crypto/testmgr.h` (`aes_lrw_tv_template`), which takes them from IEEE P1619's LRW draft | 9 LRW-AES vectors: AES-128, -192 and -256, a counter that wraps from all ones, and a 512 byte data unit |
| `ml_dsa_openssl.vec` | **generated here** from OpenSSL 3.5.4 by `scripts/capture_mldsa.py` | One ML-DSA key per parameter set in RFC 9881's three private key forms and its public key; a self-signed certificate per set and a chain crossing all three; 24 `pkeyutl` signatures over four lengths, with and without a FIPS 204 context string. PEM bodies on one line. Its companion `tests/transcripts/mldsa_handshakes.txt` holds three TLS 1.3 handshakes with the key log |
| `rsa_oaep.vec` | **generated here** from Wycheproof (`C2SP/wycheproof`, `testvectors_v1/rsa_oaep_*_test.json`) by `scripts/make_oaep_vectors.py` | 898 RSA-OAEP decryption tests over 86 two-prime keys from 1024 to 4096 bits: every hash with MGF1 under itself, SHA-1 to SHA-512 each under every other, labels, the longest message, and 389 ciphertexts to refuse. Each reduced ciphertext also carries `em = c^d mod n`, computed by the script with Python's integers - derived, not Wycheproof's, and checked against the private operation where the test runs it |
| `xeddsa.vec` | **generated here** from libsignal-protocol-c 2.3.3 by `scripts/make_xeddsa_vectors.py` | 40 XEdDSA signatures, 20 by each of `curve25519_sign` and `xed25519_sign`, with the key, message and random input that reproduce them; and 77 signatures each with the verdict of both `curve25519_verify` and `xed25519_verify` - `S + L`, high bits of `S`, flipped bits of `R`, `u` with bit 255 set, `u` at `p + 9`, and each form under the other's verifier. Inputs come from a fixed seed, so regenerating writes the same file |
| `xchacha.vec` | **generated here** from golang.org/x/crypto v0.37.0 by `scripts/make_xchacha_vectors.py`, through `scripts/witness/xchachawitness` | 12 HChaCha20 subkeys, 8 XChaCha20 keystreams at block counters 0, 1 and 2^32 - 1, and 18 XChaCha20-Poly1305 seals at lengths either side of the 16- and 64-byte blocks, with and without associated data. Inputs come from a fixed seed |
| `office_xor.vec` | **generated here** from msoffcrypto-tool v6.0.0's `xor_obfuscation.py` by `scripts/make_office_xor_vectors.py` | The [MS-OFFCRYPTO] method 1 verifier, XOR key and array for a password of every length from 1 to 15 and Excel's default, and 80 decryptions starting at five array indices |

Fetched from `https://raw.githubusercontent.com/randombit/botan/master/src/tests/data/block/`,
except `xtea.vec`, which current Botan no longer carries — **it comes
from the `2.19.5` tag**, and the URL has to say so. Crypto++'s file is
from `https://raw.githubusercontent.com/weidai11/cryptopp/master/TestVectors/`.

A vector file that has been *removed* from its upstream is worth keeping
rather than dropping: the numbers did not stop being right, and this
library exists for exactly the algorithms other projects stop shipping.

Crypto++'s file carries David Wheeler's own published set — its
`Source:` line names `teavect.htm`, the page the TEA authors put the
vectors on — and its XTEA chain builds each row's key and plaintext from
the previous row's answer, so one wrong bit anywhere wrecks the rest of
the chain rather than a single row.

**Botan is not the author of most of these numbers** — they are the
original submissions' own vectors, collected. That matters: it means
agreeing with this file is agreeing with the designers, not merely with
Botan. Where a file carries vectors Botan generated itself, it says so
in the file.

## The format

```text
[Twofish]

Key = 00000000000000000000000000000000
In  = 0000000000000000000000000000000
Out = 9F589F5CF6122C32B6BFEC2F2AE8C35A
```

A `[Name]` section heading, then `Key`/`In`/`Out` triples separated by
blank lines, with `#` comments. `In` and `Out` may be several blocks, in
which case the test is ECB over the whole thing.

`src/block_ciphers/twofish.rs` and its neighbours parse this at compile
time through `include_str!`, and **each asserts the number of vectors it
expects** before using them. A parser that silently finds nothing turns
every loop into a pass, which has happened here three times in different
documents.

## `gost_engine.vec` — generated, not fetched

The others are files somebody else published. This one is different:
**it is generated here**, by `scripts/make_gost_vectors.py`, from
OpenSSL's gost-engine running on this machine. The rule in
[docs/extending.md](../docs/extending.md#where-test-vectors-come-from)
allows exactly that where no published vector exists — generate one with
a reference implementation and say where it came from — and requires the
generator to be committed so the claim is re-runnable rather than a
sentence in a commit message.

It exists because GOST was the one family here with no independent
opinion at all. Every other algorithm is compared against somebody
else's code; GOST was compared against a second reading of the same
standards by the same reader, which agrees about the same mistakes. The
published vectors cover a handful of lengths and none of the boundaries
that matter — CTR-ACPKM's re-keying section, MGM's two counters, the
GOST MAC's minimum length.

```
python3 scripts/make_gost_vectors.py --engines ~/gost-engine/build/bin
```

Four routes, because no one of them reaches everything: `openssl enc`
for the cipher modes, `openssl dgst` **through stdin** for the digests,
`openssl genpkey`/`pkeyutl`/`dgst -sign` for VKO and the signatures, and
`scripts/gost_engine_probe.c` — built by the generator with `cc` — for
MGM, OMAC, KExp15 and TLSTREE, which the command line cannot express or
gets wrong. The last two have no EVP surface at all and are reached by
`dlsym` on the already-mapped `gost.so`; both take only plain types, so
the probe still compiles against an installed libcrypto and needs none
of the engine's private headers. `keyWrapCryptoPro`,
`keyDiversifyCryptoPro` and `cryptopro_key_meshing` are exported too and
are **not** here: they take a `gost_ctx`, which would mean compiling
against the engine's source tree and a generator that stops working on
the next version bump. Those stay on RFC 9189 Appendix A, which is the
only vector any of them has. `docs/pitfalls.md` §7b has the four separate ways the command
line lies about these algorithms, including the one where
`dgst -mac kuznyechik-mac` prints Magma's answer followed by eight bytes
of stack.

`tests/test_gost_engine_vectors.rs` reads it, **offline** — no engine,
no OpenSSL, no network — and the library's own implementations are
unchanged by any of this. The engine is a witness, not a dependency:
nothing in the build or the test gate links it.

Everything in the cipher, digest, MGM, OMAC and KExp15 sections is
derived from a counter, so regenerating and diffing shows exactly the
rows where the engine's answer changed and nothing else. **The `vko-*`
and `sign-*` sections are not deterministic**: `openssl pkey` cannot be
handed a chosen scalar, so their keys are fresh each run, and a GOST
signature is randomised anyway. The header says so, and records the
OpenSSL and gost-engine versions; if a deterministic section moves,
those should say why.

It is the only file in this directory that may be regenerated rather
than refetched, and **it must never be edited by hand** — a hand edit
makes the numbers ours again, which is the one thing it exists not to
be.

The `vko-tca-256` and `vko-c-512` rows earned their keep immediately:
they are on the two curves with cofactor four, and they showed that this
library's TLS key exchange was using a VKO reading nothing implements.
See `docs/pitfalls.md` §7o.

## `live/` — certificates off the wire

`vectors/live/` holds something different from everything above: not
test data another project published, but **certificates real servers
served**, saved by `scripts/fetch_chain.py`.

| file | from | why it is here |
|---|---|---|
| `tlsgost-256.cryptopro.ru-0.der` | CryptoPro's public GOST TLS endpoint | a `BMPString` in a name, a GOST R 34.10-2012 256 bit key, IPv4 and IPv6 SANs |
| `tlsgost-512.cryptopro.ru-0.der` | the same, 512 bit | a 512 bit key signed with the **256 bit** algorithm |
| `www.cryptopro.ru-0.der` | CryptoPro's own site | a Cyrillic subject, a five-RDN name, a wildcard SAN, a 256 bit key signed with the **512 bit** algorithm |

They are worth keeping because of what they are, not what they contain:
**the only certificates in this repository that this library did not
produce.** Everything the verifier is otherwise tested against was
written by `x509::builder` or by OpenSSL, and the ways those get written
are the ways we already thought of. Two of these three were refused
outright when they arrived — see `docs/pitfalls.md` §7t — by a check
that read `BMPString` bytes as a null-prefix attack.

`tests/test_live_gost_certificates.rs` reads them. The check that
matters most is that each public key is **a point on its curve**, and
that the byte-reversed reading is not: RFC 9215 section 4.3's
little-endian coordinates are invisible from a certificate we generated,
because our reader and our writer agree by construction.

These are public server certificates from a test CA. Refetch with
`python3 scripts/fetch_chain.py <host>`; they expire, and a refetch is a
commit that says so.

## Updating one

Refetch it whole and unmodified, and expect the count assertion to fail
if the file grew. Raise the count in the same commit, and say in the
message that the file was refetched — a count that drifts quietly is the
thing the assertion exists to prevent.
