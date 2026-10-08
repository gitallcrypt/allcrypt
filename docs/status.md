# Status

What is implemented, and what checked it.

**How to read the tables.** *Implemented* means the code is here and
passes its unit tests. *Tested* says what else checked it:

| In the Tested column | means |
|---|---|
| ✓ | compared with an independent implementation across many input lengths, not only a handful of vectors - OpenSSL through python-cryptography for the ciphers, `hashlib` for the hashes, Python's integers for the arithmetic. `scripts/diff_check.py` re-runs it; see [building.md](building.md#differential-testing) |
| text | what checked it instead, when no such implementation is available - the specification's own vectors, NIST's ACVP data, or another program's files read back |
| spec reference | no implementation was available to compare with, so it is checked against a second one written from the specification by a different route, in `scripts/diff_check.py`, plus the specification's vectors; see [Where the reference was written here](#where-the-reference-was-written-here) |
| empty | unit tests only |

A row with neither column ticked is wanted and not yet written.
Contributions are welcome: a description and test vectors are the most
useful start.

Formats other software writes - LUKS, VeraCrypt, OpenPGP, KeePass, ZIP,
PDF, Office, PKCS#12, JOSE, CMS, Kerberos, smart cards and more - are
in [the product examples](../examples/products/README.md), each checked
against that software's own tools.

**Contents**

- [Block ciphers](#block-ciphers) and [modes](#modes)
- [Stream ciphers](#stream-ciphers)
- [MACs](#macs) and [key derivation](#key-derivation)
- [Hashes](#hashes)
- [Public key](#public-key), [NaCl and libsodium](#nacl-and-libsodium) and [post-quantum](#post-quantum)
- [Certificates and keys](#certificates-and-keys)
- [TLS](#tls), [GOST TLS](#gost-tls) and [SSH](#ssh)
- [Interfaces and tools](#interfaces-and-tools)
- [Where the reference was written here](#where-the-reference-was-written-here)

## Block ciphers

|Algorithm|Implemented|Tested|
|---|---|---|
|AES|✓|✓|
|ARIA (RFC 5794)|✓|✓|
|Blowfish|✓|✓|
|Blowfish, little-endian words (TrueCrypt's)|✓|TrueCrypt's volumes, by hand|
|Camellia (RFC 3713)|✓|✓|
|CAST5 / CAST-128 (RFC 2144)|✓|✓|
|CAST-256 / CAST6 (RFC 2612)|✓|RFC 2612's Appendix A, every quad-round; Bouncy Castle 1.77 agrees on 410 inputs over all five key lengths, `vectors/cast256.vec`|
|DES|✓|✓|
|3DES (EDE2, EDE3)|✓|✓|
|GOST 28147-89|✓|✓|
|IDEA|✓|✓|
|Kuznyechik (GOST R 34.12-2015)|✓|✓|
|Magma (GOST R 34.12-2015)|✓|✓|
|RC2 (RFC 2268)|✓|✓|
|RC5 (RFC 2040)|✓|spec reference; RFC 2040's vectors|
|RC6 (RC6-32/20/b, AES finalist)|✓|Bouncy Castle 1.77 agrees on 513 inputs, every key length from 1 to 64 bytes and 41 more to 255; the submission's six vectors; `vectors/rc6.vec`|
|SEED (RFC 4269)|✓|✓|
|Serpent|✓|Botan's vectors; VeraCrypt, LUKS and KeePass files, by hand|
|SM4 (GB/T 32907-2016)|✓|✓|
|TEA|✓|spec reference; published vectors|
|Twofish|✓|Botan's vectors; VeraCrypt, LUKS and KeePass files, by hand|
|XTEA|✓|spec reference; published vectors|
|Threefish|||
|XXTEA|||

XXTEA is not a 64-bit block cipher - it works on a whole message of two
or more words at once - so when it comes it will be a module of its own
rather than a `BlockCipher` that the chaining modes would accept and
could not use.

**SM1 and SM7 cannot be here.** Their specifications were never
published: they exist only inside certified hardware, so there is no
document to implement from and nothing to check against. SM9 is
published and is listed under public key as not yet implemented.

## Modes

|Mode|Implemented|Tested|
|---|---|---|
|ECB|✓|✓|
|CBC|✓|✓|
|PCBC (Kerberos 4)|✓||
|CFB|✓|✓|
|OFB|✓|✓|
|CTR|✓|✓|
|CTR with a little-endian counter (WinZip AES, Gladman's fileenc)|✓|✓|
|CBC with ciphertext stealing, CS1/CS2/CS3 (SP 800-38A addendum; RFC 3962)|✓|✓|
|GCM, and GHASH|✓|✓|
|CCM|✓|✓|
|EAX|✓|Botan's vectors|
|OCB (RFC 7253)|✓|✓|
|MGM (RFC 9058)|✓|✓|
|AES-CBC-HMAC-SHA2 AEAD (RFC 7518 §5.2)|✓|RFC 7518's vectors; jwcrypto, by hand|
|XTS (IEEE 1619, SP 800-38E)|✓|✓|
|LRW (IEEE P1619 draft; dm-crypt, TrueCrypt 4)|✓|IEEE P1619's vectors; dm-crypt and TrueCrypt volumes, by hand|
|BitLocker sector encryption: AES-CBC with the Elephant diffuser, AES-CBC with an encrypted-offset IV, AES-XTS|✓|✓|
|AES Key Wrap (RFC 3394)|✓|✓|
|Key Wrap with padding (RFC 5649)|✓|✓|
|CMS Triple-DES and RC2 key wraps (RFC 3217)|✓|RFC 3217's examples; OpenSSL, by hand|
|CMS password recipient key wrap (RFC 3211)|✓|RFC 3211's example; OpenSSL, by hand|

**The modes are generic.** A block cipher implements three methods and
gets every mode, which is why Camellia-XTS and SM4 key wrap exist here
and almost nowhere else. [extending.md](extending.md) says how.

**Some modes are 128-bit only, and refuse the 64-bit ciphers** rather
than improvise: GHASH and OCB's offsets live in GF(2^128), CCM's counter
and length share one 16-byte block, XTS's tweak is a GF(2^128) element,
and key wrap's registers are the two halves of a 128-bit block. **MGM is
the exception**: RFC 9058 gives it a field for 64-bit blocks too, so
`magma-mgm` and `kuznyechik-mgm` are two different modes sharing a name.
EAX works on 64-bit ciphers, and its tag is then 8 bytes.

**CCM cannot stream**, because its MAC begins with the message's length.
The one-shot calls work; the streaming calls refuse rather than buffer
the whole message behind an `update` that promises constant memory.

**XTS is not authenticated and cannot be**: a disk sector has no room
for a tag. Key wrap authenticates without one. Both are in
[pitfalls.md](pitfalls.md).

## Stream ciphers

|Algorithm|Implemented|Tested|
|---|---|---|
|ChaCha20|✓|✓|
|ChaCha12, ChaCha8|✓||
|XChaCha20 and HChaCha20 (draft-irtf-cfrg-xchacha)|✓|✓|
|ChaCha20-Poly1305 (RFC 8439), XChaCha20-Poly1305|✓|✓|
|RC4|✓|spec reference; RFC 6229's vectors|
|Salsa20 (20, 12 and 8 rounds)|✓|spec reference|
|XSalsa20 and HSalsa20 ("Extending the Salsa20 nonce")|✓|NaCl's own values; libsodium 1.0.18 and golang.org/x/crypto, `vectors/nacl.vec`|
|ZipCrypto (PKWARE traditional ZIP encryption)|✓|✓|
|WEP (RC4 with the per-frame IV; IEEE 802.11)|✓|spec reference|
|TKIP per-packet key mixing (WPA; IEEE 802.11)|✓|spec reference|
|Office XOR obfuscation (MS-OFFCRYPTO, method 1)|✓|msoffcrypto-tool's answers|
|A5/1|||
|Crypto-1|||
|Enigma|||

## MACs

|Algorithm|Implemented|Tested|
|---|---|---|
|HMAC|✓|✓|
|CMAC / OMAC (SP 800-38B, RFC 4493)|✓|✓|
|CBC-MAC (ISO/IEC 9797-1 algorithm 1; DES-MAC, X9.9)|✓|✓|
|Poly1305|✓|✓|
|UMAC (RFC 4418), 32 to 128 bit tags|✓|✓|
|Michael (TKIP's MIC; IEEE 802.11)|✓|spec reference; the Linux kernel's vectors|
|ACPKM re-keying, CTR-ACPKM (RFC 8645)|✓|✓|

## Key derivation

|KDF|Implemented|Tested|
|---|---|---|
|PBKDF2 (RFC 8018 §5.2)|✓|✓|
|PBKDF1 (RFC 8018 §5.1)|✓|OpenSSL's encrypted key files, both ways|
|scrypt (RFC 7914)|✓|✓|
|Argon2id (RFC 9106)|✓|✓|
|Argon2d, Argon2i (RFC 9106)|✓|RFC 9106's vectors|
|HKDF (RFC 5869)|✓|✓|
|SP 800-108 KBKDF, counter and feedback modes, HMAC or CMAC|✓|✓|
|SP 800-56C one-step (Concat KDF) and ANSI X9.63 KDF|✓|✓|
|PKCS#12 KDF (RFC 7292 appendix B)|✓|OpenSSL's encrypted key files, both ways|
|PBEWithMD5AndTripleDES (the JDK's)|✓|keytool's JCEKS files|
|OpenPGP S2K: simple, salted, iterated and salted (RFC 9580 §3.7.1)|✓|✓|
|RFC 3961 n-fold, DR/DK, DES string-to-key, DES/3DES random-to-key|✓|RFC 3961 appendix A; MIT Kerberos, through the Kerberos example|
|7-Zip's AES key (7zAES)|✓|✓|
|KeePass AES-KDF|✓|✓|
|LUKS anti-forensic splitter (AFsplit, AFmerge)|✓|✓|
|BitLocker key stretching (password, recovery password)|✓|Windows's volumes, through the BitLocker example|
|Unix `crypt(3)`: DES, BSDi, bigcrypt, md5crypt, SHA-256/512-crypt, bcrypt ($2a/$2b/$2x/$2y), NT, sha1crypt, Sun MD5|✓|Passlib's answers (libxcrypt's `ka-table`) and the system libcrypt, `vectors/unix_crypt.vec`|
|NT hash and LM hash (MS-NLMP §3.3.1, NTOWFv1 and LMOWFv1)|✓|NT ✓; LM: Samba's and impacket's answers (`vectors/windows_hashes.vec`) and spec reference|
|IEEE 802.11 PSK, PRF, PTK and PMKID (WPA/WPA2/WPA3)|✓|IEEE 802.11i vectors; aircrack-ng, through the Wi-Fi example|
|TLS 1.2 PRF (RFC 5246)|✓|✓|
|TLS 1.0/1.1 PRF (RFC 2246)|✓|✓|
|KDF_GOSTR3411_2012_256 and KDF_TREE (RFC 7836)|✓|spec reference|
|TLSTREE (RFC 9189)|✓|✓|
|KEG, KExp15/KImp15 (RFC 9189)|✓|spec reference; gost-engine's KExp15; RFC 9189 appendix A|
|KEG_28147, KExp28147/KImp28147 (RFC 9189)|✓|spec reference; RFC 9189 appendix A|
|CryptoPro key meshing and KEK diversification (RFC 4357)|✓|spec reference; RFC 9189 appendix A|

## Hashes

|Algorithm|Implemented|Tested|
|---|---|---|
|MD2 (RFC 1319)|✓|spec reference; RFC 1319's vectors|
|MD4 (RFC 1320)|✓|✓|
|MD5|✓|✓|
|SHA-0|✓|published vectors|
|SHA-1|✓|✓|
|SHA-224, SHA-256, SHA-384, SHA-512|✓|✓|
|SHA-512/224, SHA-512/256|✓|✓|
|SHA3-224/256/384/512 (FIPS 202)|✓|✓|
|SHAKE128, SHAKE256 (FIPS 202)|✓|✓|
|Keccak-224/256/384/512 (pre-standard)|✓|spec reference; Ethereum's function selectors|
|BLAKE2b, BLAKE2s (RFC 7693)|✓|✓|
|RIPEMD-160|✓|✓|
|SM3 (GB/T 32905-2016)|✓|✓|
|Whirlpool (ISO/IEC 10118-3)|✓|✓|
|Streebog-256 and -512 (GOST R 34.11-2012)|✓|✓|
|GOST R 34.11-94 (RFC 5831, RFC 4357 parameters)|✓|✓|
|RIPEMD-128, RIPEMD-256, RIPEMD-320|✓|libtomcrypt, Bouncy Castle, Crypto++ and RustCrypto (and GNU Crypto for RIPEMD-128), agreeing on 317 inputs: `vectors/legacy_hashes.vec`|
|HAS-160 (TTA.KO-12.0011/R2)|✓|RHash, Botan 1.10 and GNU Crypto, agreeing on 317 inputs: `vectors/legacy_hashes.vec`|
|Whirlpool-0, Whirlpool-T|✓|sphlib and GNU Crypto (and Crypto++ 5.2.1 for Whirlpool-T), agreeing on 317 inputs: `vectors/legacy_hashes.vec`|
|LM hash, NT hash|✓|see [key derivation](#key-derivation)|
|MD6 (unkeyed, default mode, whole-byte sizes to 512 bits)|✓|the MIT reference implementation and Jacksum's Java port of it, agreeing on 317 inputs at nine sizes: `vectors/legacy_hashes.vec`. The port is a translation of the reference, not a second design|
|ssdeep / CTPH fuzzy hashing|||

## Public key

|Component|Implemented|Tested|
|---|---|---|
|OS randomness (`random`)|✓||
|Linear congruential generators (`prng::lcg`), generic and eleven named ones, not for keys|✓|libstdc++, musl 1.2.5, newlib 4.4.0 and Wine 9.0 from source, PCG, glibc and JDK 21 agree, `vectors/lcg.vec`; RANDU by its three-term relation only|
|Dual_EC_DRBG (SP 800-90A, withdrawn 2015), not for keys|✓|OpenSSL FIPS 2.0.5 and Bouncy Castle 1.78.1 agree, `vectors/dual_ec.vec`|
|Arbitrary-precision integers (`BigUint`)|✓|✓|
|Montgomery multiplication|✓|✓|
|Fixed-width secrets (`bignum::ct`) and fixed-size arithmetic (`bignum::fixed`)|✓|✓|
|Constant-time point arithmetic (`ec::fixed`, `ec::ct`)|✓|✓|
|Fixed-limb Curve25519 and Curve448 fields, Edwards arithmetic|✓|✓|
|Miller-Rabin primality|✓|✓|

|Algorithm|Implemented|Tested|
|---|---|---|
|RSA PKCS#1 v1.5, encryption and signatures|✓|✓|
|RSA-OAEP and RSA-PSS (RFC 8017)|✓|✓|
|DSA (FIPS 186-4, RFC 6979 nonces)|✓|RFC 6979's vectors; OpenSSL, in TLS|
|Diffie-Hellman (finite field)|✓|✓|
|ElGamal encryption (OpenPGP algorithm 16) and signatures|✓|✓|
|ECDH|✓|✓|
|ECDSA (RFC 6979)|✓|✓|
|X25519, X448 (RFC 7748)|✓|✓|
|Ed25519, Ed448 (RFC 8032)|✓|✓|
|XEdDSA, both forms (Signal's identity-key signatures)|✓|libsignal-protocol-c's bytes and verdicts; OpenSSL verifies|
|GOST R 34.10-2012 signatures|✓|✓|
|VKO key agreement (RFC 7836)|✓|✓|
|SM2 signatures (GB/T 32918.2)|✓|✓|
|SM2 public key encryption (GB/T 32918.4)|✓|✓|
|SM2 key exchange (GB/T 32918.3)|||
|SM9 (GB/T 38635, identity-based)|||

**Curves:** P-256, P-384, P-521, secp256k1, sm2p256v1 (GB/T 32918.5),
the seven GOST curves of RFC 4357 and RFC 7836, Curve25519 and
Curve448 for X25519 and X448, and edwards25519 and edwards448 for EdDSA.
The Weierstrass parameters are not trusted on sight: a unit test checks
that G is on the curve and that n*G is the identity, which pins down
every parameter, and `scripts/diff_check.py` compares scalar
multiplication and ECDH with OpenSSL - or, for the GOST curves OpenSSL
does not have, with arithmetic written out in that script. One GOST
curve has `p = 1 mod 4`, so compressed points cannot be decoded on it
(`Curve::supports_compression()`).

**EdDSA is Ed25519 and Ed448 in their pure forms.** Ed25519ctx,
Ed25519ph and Ed448ph are different schemes over the same curves and are
refused by name rather than aliased to the pure ones. The tests read RFC
8032's vectors out of `rfcs/rfc8032.txt`, and `pytests/test_eddsa.py`
compares several hundred signatures with OpenSSL byte for byte - EdDSA is
deterministic, so that is a comparison of bytes rather than only of
acceptance.

## NaCl and libsodium

Byte for byte with libsodium 1.0.18. `vectors/nacl.vec` holds NaCl's
own examples ("Cryptography in NaCl", read out of libsodium's tests) and
libsodium's answers over many lengths and keys;
`scripts/make_nacl_vectors.py` writes it and requires golang.org/x/crypto
v0.37.0 to agree wherever it implements the function, and with `--ours`
has both open boxes and sealed boxes made here.

|Function|Implemented|Tested|
|---|---|---|
|secretbox, XSalsa20-Poly1305 (`crypto_secretbox`), combined and detached|✓|NaCl's values; libsodium and Go agree|
|secretbox, XChaCha20-Poly1305 (`crypto_secretbox_xchacha20poly1305`)|✓|libsodium|
|box, Curve25519-XSalsa20-Poly1305 (`crypto_box`, `_beforenm`)|✓|NaCl's values; libsodium and Go agree; ours opened by both|
|box, Curve25519-XChaCha20-Poly1305|✓|libsodium; ours opened by libsodium|
|Sealed boxes (`crypto_box_seal`), both constructions|✓|libsodium and Go open the rows' and ours|
|Seed key pairs (`crypto_box_seed_keypair`, `crypto_kx_seed_keypair`)|✓|libsodium|
|Session keys (`crypto_kx`)|✓|libsodium|
|`crypto_auth` (HMAC-SHA-512-256)|✓|libsodium and Go agree|
|`crypto_sign`, combined form|✓|libsodium and Go agree|
|Ed25519 to X25519 keys (`crypto_sign_ed25519_pk_to_curve25519`, `_sk_`)|✓|libsodium, refusals included|
|Secret streams (`crypto_secretstream_xchacha20poly1305`)|||

## Post-quantum

|Algorithm|Implemented|Tested|
|---|---|---|
|ML-KEM (FIPS 203): key generation, encapsulation, decapsulation|✓|ACVP, and a second reading|
|ML-KEM's ring, NTT and compression|✓|structural; no vectors exist|
|ML-DSA (FIPS 204)|✓|ACVP, and a second reading|
|ML-DSA certificates and private keys (RFC 9881)|✓|RFC 9881's examples; OpenSSL 3.5 both ways|
|SLH-DSA (FIPS 205): key generation, signing and verification, internal and external interfaces, pure and pre-hash|✓|ACVP, no differential|
|Streamlined NTRU Prime, sntrup761 (OpenSSH 9.0 to 9.8's default)|✓|the draft's vectors, and against sshd|
|Hybrid TLS groups: X25519MLKEM768 and the NIST hybrids (RFC 10024)|✓|OpenSSL 3.5 both ways; Cloudflare and Google live|

**"ACVP"** is NIST's own validation data, vendored into `vectors/`:
every key generation, signing and verification case for all parameter
sets, including the cases NIST says must be refused. That is a strong
check and not the same check as a differential one - fixed inputs rather
than a sweep. **"A second reading"** is an implementation in
`scripts/diff_check.py`, written from the standard by different routes
(ML-KEM's NTT as residues modulo quadratics rather than butterflies;
ML-DSA's ring multiplication by Kronecker substitution), checked against
every NIST case first and then compared with ours over hundreds of
random cases. It is breadth rather than independence: the same reader
of the same standard could share a misreading NIST's cases do not
reach. **"No differential"**: nothing used by these tests implements
SLH-DSA, so its ACVP vectors are the whole independent opinion.

SLH-DSA and ML-KEM keys have no PEM or DER encoding here yet; ML-DSA's
do. [post-quantum.md](post-quantum.md) has the detail.

## Certificates and keys

|Component|Implemented|Tested|
|---|---|---|
|ASN.1 / DER (strict)|✓|✓|
|X.509 parsing|✓|✓|
|X.509 chain verification|✓|✓|
|Hostname matching (RFC 6125)|✓|✓|
|Name constraints (RFC 5280 §4.2.1.10)|✓|✓|
|CRL revocation (RFC 5280 §5)|✓|✓|
|OCSP (RFC 6960), and stapling in TLS|✓|✓|
|Key identifiers (RFC 5280 §4.2.1.1, §4.2.1.2)|✓|✓|
|Certificate building and signing, including by an external signer|✓|✓|
|GOST certificates and signatures (RFC 9215)|✓|spec reference; gost-engine's certificates, by hand|
|Ed25519 and Ed448 certificates (RFC 8410)|✓|✓|
|DSA certificates and private keys (RFC 3279, RFC 5758)|✓|✓|
|PEM and base64|✓|✓|
|Private keys: PKCS#8, SEC1, PKCS#1; X25519 and X448 (RFC 8410)|✓|✓|
|Encrypted private keys (PBES2, PBES1, PKCS#12 PBE), reading and writing|✓|✓|
|Java's key protectors (JKS, JCEKS)|✓|keytool's files|
|The operating system's trust store|✓|✓|

## TLS

The client speaks SSLv3 to TLS 1.3, and the server TLS 1.0 to 1.3. Old
versions and weak suites are refused by default and reached by naming
them; the default floor is TLS 1.2, and SSLv3 needs to be asked for
explicitly even in the legacy selection, because POODLE is a property of
the version rather than of a suite.

|Component|Implemented|Tested|
|---|---|---|
|Record layer, CBC with MAC-then-encrypt and encrypt-then-MAC (RFC 7366)|✓|✓|
|AEAD record layer: AES-GCM, AES-CCM, ChaCha20-Poly1305 (RFC 7905)|✓|✓|
|RC4 and NULL record protection|✓|✓|
|Cipher suite registry|✓|✓|
|Key schedules: SSLv3, TLS 1.0 to 1.2, TLS 1.3 (RFC 8446 §7.1)|✓|SSLv3: spec reference; the rest ✓|
|Client, TLS 1.2: RSA, DHE_RSA, DHE_DSS, ECDHE_RSA, ECDHE_ECDSA, X25519|✓|✓|
|Client, TLS 1.0 and 1.1|✓|✓|
|Client, SSLv3 (RFC 6101)|✓|spec reference|
|Export-grade suites (RC2_40, DES40, RC4_40)|✓|spec reference|
|Client, TLS 1.3, with HelloRetryRequest, resumption, 0-RTT and KeyUpdate|✓|✓|
|Server, TLS 1.2: RSA, ECDHE_RSA, ECDHE_ECDSA|✓|✓|
|Server, TLS 1.3, with HelloRetryRequest, session tickets and 0-RTT|✓|✓|
|Client certificates, TLS 1.0 to 1.3, both ends|✓|✓|
|ALPN (RFC 7301), both ends|✓|✓|
|OCSP stapling, both ends|✓|✓|
|Ed25519 and Ed448 signature schemes, TLS 1.2 and 1.3|✓|✓|
|ML-DSA signature schemes, TLS 1.3 (0x0904 to 0x0906)|✓|OpenSSL 3.5 both ways|
|Hybrid post-quantum key exchange, TLS 1.3|✓|✓|
|SSLKEYLOGFILE / Wireshark key log|✓|✓|
|Naming an unknown OID at run time (`register_oid`)|✓|✓|
|Server: DHE key exchange, and RFC 9189's GOST suites|||
|Camellia, SEED and IDEA suites; static DH and ECDH; anonymous and PSK suites|||
|TLS 1.2 session resumption|||
|Post-handshake authentication|||
|Client certificates over SSLv3|||

Renegotiation is refused, by design: a HelloRequest is answered with
`no_renegotiation`, and the hello carries RFC 5746's signal.

## GOST TLS

RFC 9189's three TLS 1.2 suites and RFC 9367's four TLS 1.3 suites on
all seven GOST curves, and the 2001 suite on the three CryptoPro
curves its keys can be on. The TLS 1.2 suites are client side.

|Component|Implemented|Tested|
|---|---|---|
|CTR_OMAC record protection (RFC 9189 §4.1.1)|✓|✓|
|CNT_IMIT record protection (RFC 9189 §4.1.2)|✓|✓|
|CTR_OMAC and CNT_IMIT key exchange (RFC 9189 §4.2)|✓|spec reference; gost-engine's handshakes|
|TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC|✓|spec reference; gost-engine's handshakes|
|TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC|✓|spec reference; gost-engine's handshakes|
|TLS_GOSTR341112_256_WITH_28147_CNT_IMIT, and under its CryptoPro code point 0xff85|✓|spec reference; gost-engine's handshakes|
|TLS_GOSTR341001_WITH_28147_CNT_IMIT (0x0081), with VKO 2001 and CryptoPro key wrap (RFC 4357)|✓|spec reference; gost-engine's handshakes|
|MGM record protection at TLS 1.3 (RFC 9367 §4.1)|✓RFC 9367's handshakes, replayed|
|TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L and _S|✓RFC 9367's handshakes, replayed|
|TLS_GOSTR341112_256_WITH_MAGMA_MGM_L and _S|✓RFC 9367's handshakes, replayed|
|TLS13_GOST signature schemes, verifying (RFC 9367 §5)|✓RFC 9367's handshakes, replayed|

RFC 9367's appendix prints two complete handshakes with every intermediate value, and
`tests/test_rfc9367_flight.rs` replays both offline: the key schedule
value by value, TLSTREE at every sequence number, both Finished MACs,
the PSK binder, the CertificateVerify against the document's own
certificate, and every fully printed record decrypted and re-encrypted
byte for byte. It also found four misprints in the document - two
record keys under the other direction's label, and two IV lengths -
pinned by two tests.

## SSH

|Component|Implemented|Tested|
|---|---|---|
|Wire encoding (RFC 4251)|✓|✓|
|Public keys, `authorized_keys`, fingerprints|✓|✓|
|OpenSSH private keys (`openssh-key-v1`, bcrypt_pbkdf)|✓|✓|
|Signatures: Ed25519, ECDSA P-256/384/521, RSA including SHA-1|✓|✓|
|SSHSIG (`ssh-keygen -Y sign`)|✓|✓|
|Key exchange: ML-KEM-768+X25519, sntrup761x25519, Curve25519, ECDH P-256/384/521, DH groups 1, 14, 16, 18 and group exchange|✓|✓|
|Packet layer: ChaCha20-Poly1305, AES-GCM/CTR/CBC, 3DES-CBC; HMAC SHA-2, SHA-1 and MD5, ETM and -96; UMAC-64 and -128|✓|✓|
|Old algorithms: `ssh-dss`, arcfour (and RFC 4345's 128 and 256), blowfish-cbc, cast128-cbc, hmac-ripemd160|✓|✓|
|Client: publickey and password authentication, exec, strict key exchange|✓|✓|
|Server: publickey and password authentication, one session channel, re-keying|✓|✓|

The SSH rows are checked against OpenSSH 10.0 and 7.4 in both
directions, and recorded sessions replay offline byte for byte.

## Interfaces and tools

|Component|Implemented|Tested|
|---|---|---|
|Python bindings (`allcrypt`)|✓|✓|
|`ssl`-compatible module (`allcrypt_ssl`)|✓|✓|
|C interface (`include/allcrypt.h`, the `c-api` feature)|✓|✓|
|OpenSSL `LD_PRELOAD` shim for curl, wget and git (Unix only)|✓|✓|
|`allcrypt-proxy`, with certificate mirroring|✓|✓|
|Constant-time checks: valgrind rows and division scan (`ct_check.py`), timing on the machine (`dudect`)|✓|controls in both that must report|

The Python bindings' tests compare with hashlib, python-cryptography and
the standard `ssl` module; `scripts/check_c_api.py` compares the C
interface's answers with hashlib and python-cryptography; the shim and
the proxy are tested by running the real `curl`, `wget` and OpenSSL
against them. [python.md](python.md), [c.md](c.md), [shim.md](shim.md)
and [proxy.md](proxy.md) describe each.

## Where the reference was written here

The rows marked *spec reference* all mean the same thing: **none of the
implementations the tests use has it**, so `scripts/diff_check.py`
holds a reference written from the specification, in Python, by a
different route, and the corpus is compared with that. It catches a
transcription error and would not catch a misreading both
transcriptions shared, which is why it is labelled differently from ✓.
Each is also pinned to its standard's own vectors where there are any.

- **Algorithms other libraries have, but not the ones used here** - MD2,
  Keccak, Salsa20, RC4 and WEP, RC5, TEA, XTEA, Michael and TKIP. Botan
  or Crypto++ have most of them, and OpenSSL's legacy provider some; a
  differential check against one of those would move the row to ✓.
- **SSLv3.** Every current TLS library has removed it, and the OpenSSL
  builds in use have it compiled out (`ssl.HAS_SSLv3` is False).
- **The export suites** - RC2_40, DES40, RC4_40 - were deleted from
  every library years ago; their key expansion is checked against RFC
  2246 §6.3.1. RC2 itself is fully tested, and so is the FREAK defence,
  which is a decision rather than a construction.
- **The GOST composites** - KDF_GOSTR3411_2012_256 and KDF_TREE, KEG,
  KExp28147/KImp28147, CryptoPro key meshing and diversification, and
  RFC 9367's TLSTREE constant sets that gost-engine does not have - and
  the GOST TLS 1.2 key exchange. These are also pinned to **RFC 9189
  appendix A reproduced byte for byte** - the TLSTREE levels, the record
  examples for all three suites, and both worked handshakes - and the
  key exchange to real handshakes between OpenSSL and gost-engine, below.

**The GOST primitives do have a second implementation**: OpenSSL's
gost-engine, built from source as a witness. `vectors/gost_engine.vec`
holds its answers - both block ciphers in every mode, GOST 28147-89
under two parameter sets, CTR-ACPKM past its re-keying boundary, all
three digests, MGM, OMAC, the 28147-89 MAC, KExp15, TLSTREE, VKO on
every parameter set, and signatures the engine made - and
`tests/test_gost_engine_vectors.rs` reads it offline. It found two real
bugs: a one-block GOST MAC that was a block short, and VKO without the
cofactor RFC 7836 specifies, which on the two cofactor-four curves
derived a key no peer shares. `tests/transcripts/gost_handshakes.txt`
holds seven real TLS 1.2 handshakes between OpenSSL and gost-engine at
both ends, and `tests/test_gost_transcript.rs` decrypts records the
engine encrypted, which is the only thing that can settle the byte
orders: our own client and server agree with each other whichever way
round any of them is. [pitfalls.md](pitfalls.md) §7b and §7o have the
detail.
