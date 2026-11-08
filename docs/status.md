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
|FEAL-N (`feal`, FEAL-4 and FEAL-8 among them) and FEAL-NX (`feal-nx`), any even round count from 2 to 1024, constant time|✓|zilijonas/FEAL-NX's Java and Donaldduck8's Python reproduce NTT's FEAL-NX test data, 40,960 blocks under ten keys at 32 rounds, `vectors/feal_nx_ntt.txt`, and agree on 1,664 blocks and 32 iterated runs, FEAL-N at 4, 8, 16 and 32 rounds and FEAL-NX at 2, 8, 32 and 64: every single-bit key and block, repeated bytes, random blocks; `vectors/feal.vec`|
|GOST 28147-89|✓|✓|
|GOST 28147-89 under the DSTU 4145 default DKE (DSTU GOST 28147:2009, `dstu4145-default-dke`)|✓|Bouncy Castle 1.77, gost89 and cryptonite agree on ECB, CFB and the MAC, and on the table itself; counter mode Bouncy Castle's and cryptonite's; `vectors/dstu_gost.vec`|
|GOST 28147-89 under Ukraine's other nine tables, DKE No. 1 from supplements 2 to 10 to instruction 114 (`dstu-dke-2` to `dstu-dke-10`; `dstu-dke-1` is the default)|✓|cryptonite and li0ard agree on the ten tables; under each of the nine, Bouncy Castle 1.77, gost89 and cryptonite agree on ECB, CFB and the MAC, Bouncy Castle and cryptonite on the counter mode; `vectors/dstu_dke.vec`|
|HIGHT (TTAS.KO-12.0040/R1, ISO/IEC 18033-3), constant time|✓|Crypto++ 8.9.0 and go-krypto agree on 737 blocks and 17 iterated runs: KISA's known-answer tests, the standard's examples and Crypto++'s vectors, 225 blocks, every single-bit key and block, every byte repeated; the subkey constants and F0 and F1 computed from their definitions; `vectors/hight.vec`|
|IDEA|✓|✓|
|Kalyna (DSTU 7624:2014), all five variants (`kalyna-128`, `kalyna-256`, `kalyna-512`)|✓|the standard's ten examples; the authors' reference implementation and Bouncy Castle 1.77 agree on 75 more inputs and on the S-boxes; `vectors/kalyna.vec`|
|Kalyna's DSTU 7624 GCM, GMAC, CCM and XTS (`kalyna-128-gcm` to `kalyna-512-ccm`, `kalyna_gmac`, `kalyna_ccm_*`, `kalyna_xts_*`)|✓|the standard's examples, which Bouncy Castle 1.77 and cryptonite both reproduce, and six more with short blocks from cryptonite's tests; 357 rows on which the two agree, all whole blocks; then each alone: Bouncy Castle for GCM and GMAC with a short last block, which the two pad differently, and CCM past 255 bytes; cryptonite for CCM with short or empty parts and XTS's ciphertext stealing; `vectors/kalyna_aead.vec`|
|Kalyna's DSTU 7624 counter mode (`ctr` on a `kalyna-` name), MAC and key wrap|✓|the standard's examples, which Bouncy Castle 1.77 and cryptonite both reproduce; 165 rows on which they agree, and each alone where the other stops (short MACs, padded and long wraps); `vectors/kalyna_modes.vec`|
|Kuznyechik (GOST R 34.12-2015)|✓|✓|
|Magma (GOST R 34.12-2015)|✓|✓|
|Anubis (NESSIE submission, tweaked), constant time|✓|libtomcrypt 1.18.2, the Linux kernel's `crypto/anubis.c` and the designers' reference code agree on 2,090 blocks at all seven key lengths, 16 to 40 bytes, and 14 iterated runs: the published tests libtomcrypt and the kernel carry, every single-bit key at every length; `vectors/anubis.vec`|
|SHACAL-1 (NESSIE submission), constant time|✓|Crypto++ 8.9.0's and OpenSSL 3.0's SHA-1 compression functions, less their feed-forward, agree on 1,254 blocks and 13 iterated runs at every key length from 16 to 64 bytes: Project Nayuki's two published tests, every single-bit key at 64 and 16 bytes and block, every byte repeated, random blocks; both encrypt only, and every row's decryption must give its block back; `vectors/shacal1.vec`|
|SHACAL-2 (NESSIE selection), constant time|✓|Crypto++ 8.9.0 and Bouncy Castle 1.77 agree on 1,367 blocks and 10 iterated runs at every key length from 16 to 64 bytes, among them the NESSIE submission's 1,024 vectors and Botan's tests; `vectors/shacal2.vec`|
|Noekeon (NESSIE submission), direct and indirect key modes, constant time|✓|direct: libtomcrypt 1.18.2 and Bouncy Castle 1.77 agree on 584 blocks and 16 iterated runs, with libtomcrypt's published tests; indirect: Botan 1.10.17 and Bouncy Castle under the mode's definition agree on 587, with Botan's from the NESSIE reference code; `vectors/noekeon.vec`|
|Chaskey-LTS block cipher, `pi(x ^ K) ^ K` over Chaskey-LTS's permutation, constant time|✓|sacundim's chaskey crate and volexity's chaskey-lts agree on 577 blocks and 17 iterated runs, each decrypting every one back: the FELIX block in sacundim's tests, every single-bit key and block, every byte repeated, random blocks; `vectors/chaskey_lts.vec`|
|KASUMI (3GPP TS 35.202)|✓|libtomcrypt 1.18.2 and Botan 1.10.17 agree on 520 blocks and 17 iterated runs: the 3GPP tests both carry, every single-bit key and block, every byte repeated; S7, S9 and the key schedule's constants read out of both; `vectors/kasumi.vec`|
|Khazad (NESSIE finalist, tweaked), constant time|✓|libtomcrypt 1.18.2 and the Linux kernel's `crypto/khazad.c` agree on 523 blocks and 17 iterated runs: the published tests both carry, every single-bit key and block, every byte repeated; the S-box built from its mini boxes; `vectors/khazad.vec`|
|MARS (AES finalist, tweaked key schedule)|✓|Crypto++ 8.9.0 and Botan 1.10.17 agree on 682 blocks over all eleven key lengths, 16 to 56 bytes, and on Monte Carlo tests of four million blocks at each length and direction; Crypto++'s published vectors and Monte Carlo tests; the S-box derived from its SHA-1 construction; `vectors/mars.vec`|
|LEA (KS X 3246), constant time|✓|Crypto++ 8.9.0 and go-krypto agree on 2,241 blocks and 27 iterated runs at all three key lengths: KISA's 1,020 known-answer tests and Crypto++'s published vectors, 1,185 blocks, every single-bit key and block, every byte repeated; the key schedule's constants read out of both and computed from their definition; `vectors/lea.vec`|
|LOKI97 (AES candidate), as submitted (`loki97`) and as libmcrypt computes it, its words byte-swapped and its key zero-padded to 32 bytes (`loki97-mcrypt`)|✓|32 byte keys and `loki97-mcrypt` at every length: the designers' reference C, as Crypt::Loki97 1.0.1 carries it and built with 32-bit word halves, and libmcrypt 2.5.8 agree on every row once libmcrypt's form is accounted for, both directions. **16 and 24 byte keys: the reference alone**, which no second implementation here computes - with the module's five published 128 bit tests. Those lengths differ from 32 only in deriving the missing key words with the round function, the 16 byte schedule both of them, the 24 byte one the second, which the published tests cover. 1,160 blocks - 1,062 as submitted, 98 in libmcrypt's form - and 54 iterated runs; the S-boxes computed from their definition; `vectors/loki97.vec`, its single-witness rows marked|
|MISTY1 (RFC 2994)|✓|RFC 2994's ECB and CBC examples, read out of the document; Botan 1.10.17 and Crypt::Misty1 1.1.3 agree on 543 blocks and 17 iterated runs: Botan's published tests, every single-bit key and block, every byte repeated; S7 and S9 parsed out of the RFC at compile time, and both witnesses' tables checked against it; `vectors/misty1.vec`|
|PRESENT (CHES 2007, ISO/IEC 29192-2), 80 and 128 bit keys|✓|Nirusu/PRESENT.go, kurtfu/present and OpenTitan's Python PRESENT agree on 601 blocks and 18 iterated runs at both key lengths: the paper's four tests and PRESENT.go's five at 128 bits, every single-bit key and block, every byte repeated, random blocks; the S-box read out of all three; `vectors/present.vec`|
|RC2 (RFC 2268)|✓|✓|
|RC5 (RFC 2040)|✓|spec reference; RFC 2040's vectors|
|Rijndael, 160 to 256 bit blocks (`rijndael-160` to `rijndael-256`)|✓|Bouncy Castle 1.77 and phpseclib 1.0.23 agree on 275 inputs, eleven for each of the 25 block and key sizes; `vectors/rijndael.vec`|
|RC6 (RC6-32/20/b, AES finalist)|✓|Bouncy Castle 1.77 agrees on 513 inputs, every key length from 1 to 64 bytes and 41 more to 255; the submission's six vectors; `vectors/rc6.vec`|
|SAFER K-64, K-128, SK-64 and SK-128 (`safer-k64`, `safer-k128`, `safer-sk64`, `safer-sk128`), 1 to 13 rounds|✓|libtomcrypt 1.18.2 and Crypto++ 8.9.0 agree on every row from 6 to 13 rounds, and Botan 1.10.17 with them on SK-128, from 1 round with Crypto++: the published tests the three carry at the round counts their projects run them, every single-bit key and block and every byte repeated at each variant's usual count, random blocks at every other, and 44 iterated runs - 2,615 blocks; `vectors/safer.vec`|
|SAFER+ (AES candidate), in the submission's byte order (`saferplus`) and in libmcrypt's, the 32-bit words reversed (`saferplus-reversed-words`)|✓|libtomcrypt 1.18.2 and libmcrypt 2.5.8 agree on every row once libmcrypt's word order is accounted for, both directions: 1,059 blocks and 27 iterated runs at all three key lengths - libtomcrypt's published tests, every single-bit key and block, every byte repeated, random blocks - and the published tests, random blocks and iterated runs again in libmcrypt's order; `vectors/saferplus.vec`|
|SEED (RFC 4269)|✓|✓|
|Serpent|✓|Botan's vectors; VeraCrypt, LUKS and KeePass files, by hand|
|Simon at every size: Simon32/64 (`simon32`), Simon48/72, /96 (`simon48`), Simon64/96, /128 (`simon64`), Simon96/96, /144 (`simon96`) and Simon128/128, /192, /256 (`simon128`), constant time|✓|3,285 blocks and 90 iterated runs at every key length, each agreed by every witness that takes its key, two at least: Crypto++ 8.9.0 at 64 and 128 bits, jedisct1/rust-lwbc at 64/128, 32/64, 48/96 and 96/144, and inmcm's Python reference and cryptography-rs 0.8.0 at every size. Crypto++'s and the paper's published tests, every single-bit key and block, every byte repeated; the five z sequences read out of the three, each from two at least; `vectors/simon_speck.vec`|
|Speck at every size: Speck32/64 (`speck32`), Speck48/72, /96 (`speck48`), Speck64/96, /128 (`speck64`), Speck96/96, /144 (`speck96`) and Speck128/128, /192, /256 (`speck128`), constant time|✓|3,285 blocks and 90 iterated runs at every key length, each agreed by every witness that takes its key, three at least: Crypto++ 8.9.0 and the Linux kernel's Speck (v4.19) at 64 and 128 bits, jedisct1/rust-lwbc at 64/128, 32/64, 48/96 and 96/144, and inmcm's Python reference, cryptography-rs 0.8.0 and RustCrypto's speck-cipher 0.1.0 at every size. Crypto++'s and the paper's published tests, every single-bit key and block, every byte repeated; `vectors/simon_speck.vec`|
|Skipjack, in the specification's byte order (`skipjack`) and in Crypto++'s and Botan's, every string reversed (`skipjack-reversed`)|✓|libtomcrypt 1.18.2 and Bouncy Castle 1.77 agree on 496 blocks and 17 iterated runs in the specification's order, Crypto++ 8.9.0 and Botan 1.10.17 on the same in the reversed order, and all four on every row: the published tests the four carry, every single-bit key and block, every byte repeated; the F-table read out of all four; `vectors/skipjack.vec`|
|SM4 (GB/T 32907-2016)|✓|✓|
|Square (Rijndael's predecessor)|✓|Crypto++ 8.9.0 and Botan 1.10.17 agree on 596 blocks and 17 iterated runs: the published tests both carry, every single-bit key and block, every byte repeated; the S-box read out of both, with each one's inverse table checked against it; `vectors/square.vec`|
|3-Way (`threeway`, also `3way` and `3-way`), constant time|✓|Crypto++ 8.9.0 and libmcrypt 2.5.8 agree on 517 blocks and 17 iterated runs: Crypto++'s published tests and libmcrypt's self-test, every single-bit key and block, every byte repeated; `vectors/threeway.vec`|
|Threefish-256, -512 and -1024 as tweakable block ciphers (`threefish256`, `threefish512`, `threefish1024`), the key alone or followed by the 16 byte tweak, constant time|✓|Crypto++ 8.9.0, Bouncy Castle 1.77 and Skein3Fish's C agree on 1,082 blocks and 21 iterated runs, with and without a tweak: Crypto++'s published tests - the Skein team's known answers and Botan's - a single bit through every byte of the key and the block and through every bit of the tweak, repeated bytes and random blocks; Skein's known answers run through the same code; `vectors/threefish.vec`|
|TEA|✓|spec reference; published vectors|
|Twofish|✓|Botan's vectors; VeraCrypt, LUKS and KeePass files, by hand|
|XTEA|✓|spec reference; published vectors|
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
|GCM, GHASH and GMAC|✓|✓|
|CCM|✓|✓|
|GCM and CCM over Camellia, SM4 and ARIA, and at every tag length SP 800-38D and RFC 3610 allow|✓|RFC 8998's SM4 examples; SP 800-38D and RFC 3610 in Python over python-cryptography's Camellia and SM4, the same code held to OpenSSL's AES-GCM and AES-CCM|
|EAX|✓|Botan's vectors; over the 160 to 1024 bit blocks, Botan 3.6.1, Crypto++ 8.9.0 and Bouncy Castle 1.77, each where it has the cipher: `vectors/cmac_eax_wide.vec`|
|OCB (RFC 7253)|✓|✓|
|MGM (RFC 9058)|✓|✓|
|AES-CBC-HMAC-SHA2 AEAD (RFC 7518 §5.2)|✓|RFC 7518's vectors; jwcrypto, by hand|
|XTS (IEEE 1619, SP 800-38E)|✓|✓|
|LRW (IEEE P1619 draft; dm-crypt, TrueCrypt 4)|✓|IEEE P1619's vectors; dm-crypt and TrueCrypt volumes, by hand|
|BitLocker sector encryption: AES-CBC with the Elephant diffuser, AES-CBC with an encrypted-offset IV, AES-XTS|✓|✓|
|AES Key Wrap (RFC 3394)|✓|✓|
|Key Wrap with padding (RFC 5649)|✓|✓|
|CMS Triple-DES and RC2 key wraps (RFC 3217)|✓|RFC 3217's examples; OpenSSL, by hand|
|DSTU GOST key wrap (Ukraine; RFC 3217's shape with GOST CFB and MAC)|✓|gost89's wrap and unwrap of 11 keys; its CFB and MAC are also Bouncy Castle's; `vectors/dstu_gost.vec`|
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
EAX works on 64-bit ciphers, and its tag is then 8 bytes, and on the
wider ones - Rijndael's 160 to 256 bits, SHACAL-2, Kalyna and Threefish
up to 1024 - where its tag is the whole block, up to 128 bytes.
A tag length can follow GCM, CCM, EAX, MGM and OCB in a name
(`aes-gcm-8`), within each mode's own set.

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
|Grain-128AEADv2 (NIST lightweight finalist, round 3 tweak), `grain128aeadv2`|✓|the NIST final round's 1,089 known answers; lwc-finalists and the grain-128aeadv2 crate agree on 158 more, associated data across every DER length form to 65,536 bytes, and Bouncy Castle 1.77 on the 120 of them where its length encoding is DER's: `vectors/grain128aead.vec`|
|Grain-128AEAD v1 (NIST lightweight rounds 1 and 2, before the tweak), `grain128aeadv1`|✓|the designers' 1,089 known answers; the designers' reference and optimised implementations and lightweight-crypto agree on 158 more, across the same DER length forms: `vectors/grain128aead_v1.vec`|
|RC4|✓|spec reference; RFC 6229's vectors|
|Salsa20 (20, 12 and 8 rounds)|✓|spec reference|
|XSalsa20 and HSalsa20 ("Extending the Salsa20 nonce")|✓|NaCl's own values; libsodium 1.0.18 and golang.org/x/crypto, `vectors/nacl.vec`|
|Strumok (DSTU 8845:2019), 256 and 512-bit keys, `strumok`|✓|the standard's eight Annex D examples, UAPKI's self-test and the conformance letter's two; UAPKI's `dstu8845.c` and uacrypt's `hazmat/strumok.rs` agree on every single-bit key and IV at both key lengths, 30 random keystreams and two of 1 MiB; `vectors/strumok.vec`. Not constant time: table lookups, as in the standard|
|Rabbit (RFC 4503), with and without an IV, `rabbit`|✓|RFC 4503's vectors and its debugging states, read out of `rfcs/rfc4503.txt` with erratum 2504 applied; the eSTREAM submission, Crypto++ 8.9.0, libtomcrypt and RustCrypto agree: `vectors/estream.vec`|
|HC-128 and HC-256, `hc128`, `hc256`|✓|HC-128: the eSTREAM submission's three versions, Crypto++ 8.9.0 and Bouncy Castle 1.77 agree; HC-256: the submission's two versions, Bouncy Castle and RustCrypto 0.6.0 agree, with the designer's three vectors - Crypto++'s HC-256 reads key and IV words rotated and is not a witness for it: `vectors/estream.vec`|
|SOSEMANUK, keys of 1 to 32 bytes, `sosemanuk`|✓|the submission's own vector; the submission, Crypto++ 8.9.0 and libtomcrypt agree at every key length: `vectors/estream.vec`|
|Trivium, 32, 48, 64 and 80 bit IVs, `trivium`|✓|the eSTREAM project's 246 vectors at 32, 64 and 80 bit IVs, every byte through their digests: `vectors/estream/`; the eSTREAM submission, pedroalbanese/trivium and the trivium crate agree, a short IV checked as the long one with zero bytes in front: `vectors/trivium_grain.vec`. The submission's bit order, not the specification's|
|Grain v1, `grainv1`|✓|the eSTREAM project's 83 vectors; the reference implementation, gSTREAM's word-wide Grain v1 and Bouncy Castle 1.77 agree: `vectors/estream/`, `vectors/trivium_grain.vec`|
|Grain-128, `grain128`|✓|the eSTREAM project's 92 vectors; the grain128 crate (a port of the reference) and Bouncy Castle 1.77 agree - Bouncy Castle 1.86 and later use Grain-128a's output function and are not a witness: `vectors/estream/`, `vectors/trivium_grain.vec`|
|ISAAC and ISAAC-64 (Jenkins, 1996), keys up to the seed array, `isaac`, `isaac64`; Bouncy Castle's reading, `isaac-bouncycastle`|✓|the values rand_isaac's tests give as the reference's; Jenkins's rand.c (randport.c) and isaac64.c (as Math::Int64 carries it), coreutils's rand-isaac.c at both sizes, rand_isaac 0.3.0 and Bouncy Castle 1.77 agree on every key length class, the empty key and single-bit keys, two blocks and block 40 - Bouncy Castle on its own reading and the keys it takes: `vectors/isaac.vec`|
|SNOW 3G, `snow3g`|✓|ETSI/SAGE's implementors' test data, read out of `rfcs/Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.txt`: four keystreams, the fourth to word 2500; the reference code as CryptoMobile carries it, intel-ipsec-mb 2.0.3, free5gc and oxirush-security agree: `vectors/snow3g_zuc.vec`|
|ZUC-128, `zuc128`|✓|ETSI/SAGE's implementors' test data, read out of `rfcs/eea3eia3testdatav11.txt`: four keystreams, the fourth to word 2000; the reference code as CryptoMobile carries it, intel-ipsec-mb, GmSSL, free5gc, Bouncy Castle 1.77, the zuc crate and oxirush-security agree: `vectors/snow3g_zuc.vec`|
|ZUC-256 (the ZUC design team's 2018 paper), 25 or 23 byte IVs, `zuc256`|✓|Intel's ten ZUC-256 keystream tests as intel-ipsec-mb 2.0.3 carries them (`vectors/zuc256/`); intel-ipsec-mb, GmSSL, Bouncy Castle 1.77 and the zuc crate agree: `vectors/snow3g_zuc.vec`. The paper is not vendored; its loading constants are read out of GmSSL and intel-ipsec-mb, which agree|
|3GPP's ZUC-256 (TS 35.246 V20.0.0), a 16 byte IV, `zuc256-3gpp`|✓|TS 35.247's three traces, read out of `rfcs/35247-k00.txt`: the state as loaded, after each printed set-up clock and 32 keystream words; the loading constants are read out of TS 35.246's text. No second implementation exists beyond the specification's Annex A, which agrees through 256-NEA6 (below)|
|UEA1 and UIA1, KASUMI's f8 and f9 (3GPP TS 35.201), any bit length|✓|Intel's 34 UEA1 and 15 UIA1 tests as intel-ipsec-mb 2.0.3 carries them, the 3GPP test sets among them; the reference implementation from the specification's annex, as CryptoMobile carries it, and intel-ipsec-mb agree on 210 more at lengths either side of the byte and block steps to 20,000 bits, both directions and every bearer: `vectors/uea1_uia1.vec`|
|256-NEA6 (3GPP's ZUC-256), any bit length, 32 or 16 byte keys|✓|TS 35.248's twelve conformance sets, with their IVs; TS 35.246 Annex A's reference code agrees at every length from 0 to 600 bits, both key sizes, with and without EXTRA_IV: `vectors/zuc256_3gpp.vec`|
|UEA2 = 128-EEA1 = 128-NEA1 (SNOW 3G), and 128-EEA3 = 128-NEA3 (ZUC), any bit length|✓|the test data's five UEA2 and five 128-EEA3 sets; the reference code, intel-ipsec-mb, free5gc and oxirush-security agree, and GmSSL and the zuc crate on EEA3, over every bearer and both directions: `vectors/snow3g_zuc.vec`|
|ZipCrypto (PKWARE traditional ZIP encryption)|✓|✓|
|WEP (RC4 with the per-frame IV; IEEE 802.11)|✓|spec reference|
|TKIP per-packet key mixing and frame encryption (WPA; IEEE 802.11)|✓|spec reference; frames against python-cryptography's RC4 and zlib's CRC-32|
|Kerberos RC4-HMAC (RFC 4757): types 23 and 24, checksum -138, PRF, string-to-key|✓|MIT Kerberos 1.21.3 and Apache Kerby made 364 ciphertexts under their own confounders and opened each other's, impacket remaking type 23's; checksums, PRF and keys agreed by all three: `vectors/rc4_hmac.vec`|
|Office XOR obfuscation (MS-OFFCRYPTO, method 1)|✓|msoffcrypto-tool's answers|
|A5/1|||
|Crypto-1|||
|Enigma|||

## MACs

|Algorithm|Implemented|Tested|
|---|---|---|
|HMAC|✓|✓|
|CMAC / OMAC (SP 800-38B, RFC 4493)|✓|✓|
|CMAC over 160 to 1024 bit blocks: Threefish, SHACAL-2, Kalyna-256 and -512, Rijndael-160 to -256|✓|Botan 3.6.1, Crypto++ 8.9.0 and Bouncy Castle 1.77, each where it has the cipher - the Rijndaels Bouncy Castle alone - and Botan's published CMAC(Threefish-512) test: `vectors/cmac_eax_wide.vec`. The field polynomials are computed from their rule and checked against all three libraries' tables|
|CBC-MAC (ISO/IEC 9797-1 algorithm 1; DES-MAC, X9.9)|✓|✓|
|PMAC (Black and Rogaway), over 64 and 128 bit block ciphers|✓|Rogaway's fourteen published PMAC-AES tests; libtomcrypt 1.18.2, RustCrypto's `pmac` 0.7.1 and miscreant.go agree over AES, DES, 3DES and Blowfish, each where it has the cipher: `vectors/pmac.vec`|
|Poly1305|✓|✓|
|UMAC (RFC 4418), 32 to 128 bit tags|✓|✓|
|VMAC (draft-krovetz-vmac-01), 64 and 128 bit tags, over any 128 bit block cipher|✓|the draft's own vectors, read out of `rfcs/draft-krovetz-vmac-01.txt`; Crypto++ 8.9.0 over AES, Twofish, Serpent, Camellia, ARIA, SEED and SM4, and the Linux kernel's `vmac64` over AES-128 with the 64 bit tag, agree: `vectors/vmac.vec`|
|SipHash at any round counts, 64 and 128 bit; HalfSipHash, 32 and 64 bit|✓|the designers' 256 vectors (`rfcs/siphash-vectors.h`); their reference, OpenSSL 3.5 and Bouncy Castle 1.77 agree on SipHash at 1-3, 2-4, 3-5 and 4-8 over 46 messages and two keys; HalfSipHash at the same counts from the reference alone: `vectors/siphash.vec`|
|Chaskey, Chaskey-12 and Chaskey-LTS (8, 12 and 16 rounds)|✓|the 64 tags at each of 8 and 12 rounds that dgryski/go-chaskey publishes; go-chaskey's assembly and portable builds and sacundim's Rust crate agree at 8 and 12 rounds and sacundim's crate alone gives the 16 round MAC, whose permutation volexity's Chaskey-LTS block cipher and sacundim's agree on, the FELIX block among the rows: `vectors/chaskey.vec`|
|Michael (TKIP's MIC; IEEE 802.11)|✓|spec reference; the Linux kernel's vectors|
|UIA2 and 128-EIA1 = 128-NIA1 (SNOW 3G), any bit length|✓|the test data's six UIA2 sets, the longest 16448 bits; the reference code and intel-ipsec-mb agree on UIA2, and free5gc and oxirush-security on 128-EIA1 as well: `vectors/snow3g_zuc.vec`|
|128-EIA3 = 128-NIA3 (ZUC), any bit length|✓|the test data's five sets; the reference code, intel-ipsec-mb, GmSSL, free5gc, the zuc crate and oxirush-security agree: `vectors/snow3g_zuc.vec`|
|256-NIA6 and 256-NCA6 (3GPP's ZUC-256 with Mac5G, POLYVAL's polynomial), any bit length, MACs of 4 to 16 bytes|✓|TS 35.248's twelve sets of each, with their IVs and H, Q and P; TS 35.247's six POLYVAL dot products; TS 35.246 Annex A's reference code agrees on 401 NIA6 rows at every length to 400 bits, 300 NCA6 rows with partial AAD and data, and 700 decryptions - refused MACs, and junk past the last bit ignored: `vectors/zuc256_3gpp.vec`. Annex A is the only implementation besides this one; the specification's authors wrote it|
|ZUC-128's MAC over a raw IV; ZUC-256's MAC at 32, 64 and 128 bits|✓|Intel's 36 ZUC-256 MAC tests (`vectors/zuc256/`); intel-ipsec-mb, GmSSL, Bouncy Castle 1.77 and the zuc crate agree: `vectors/snow3g_zuc.vec`|
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
|PKCS#12 KDF (RFC 7292 appendix B)|✓|OpenSSL's encrypted key files, both ways; OpenSSL's PKCS12KDF over five hashes, `vectors/pkcs12_kdf.vec`; OpenSSL with dstu-engine over GOST 34.311, whose 32-byte block is `v`, `vectors/pkcs12_kdf_gost.vec`|
|PBEWithMD5AndTripleDES (the JDK's)|✓|keytool's JCEKS files|
|OpenPGP S2K: simple, salted, iterated and salted (RFC 9580 §3.7.1)|✓|✓|
|RFC 3961 n-fold, DR/DK, DES string-to-key, DES/3DES random-to-key|✓|RFC 3961 appendix A; MIT Kerberos, through the Kerberos example|
|7-Zip's AES key (7zAES)|✓|✓|
|KeePass AES-KDF|✓|✓|
|LUKS anti-forensic splitter (AFsplit, AFmerge)|✓|✓|
|BitLocker key stretching (password, recovery password)|✓|Windows's volumes, through the BitLocker example|
|Unix `crypt(3)`: DES, BSDi, bigcrypt, md5crypt, SHA-256/512-crypt, bcrypt ($2a/$2b/$2x/$2y), NT, sha1crypt, Sun MD5|✓|Passlib's answers (libxcrypt's `ka-table`) and the system libcrypt, `vectors/unix_crypt.vec`|
|NT hash and LM hash (MS-NLMP §3.3.1, NTOWFv1 and LMOWFv1)|✓|NT ✓; LM: Samba's and impacket's answers (`vectors/windows_hashes.vec`) and spec reference|
|Database and forum hashes: MySQL `OLD_PASSWORD`/`PASSWORD`, PostgreSQL `md5`, phpass (`$P$`/`$H$`), vBulletin/MyBB|✓|MariaDB's `hash_password`, WordPress's `class-phpass.php`, and PHP's md5/sha1, `vectors/app_passwords.vec`|
|IEEE 802.11 PSK, PRF, PTK and PMKID (WPA/WPA2/WPA3)|✓|IEEE 802.11i vectors; aircrack-ng and Wireshark's tshark, through the Wi-Fi example|
|IEEE 802.11 KDF-SHA384/512, Suite B 192-bit's PTK, and fast BSS transition's PMK-R0, PMK-R1 and PTK (802.11r)|✓|hostapd 2.11 and Wireshark 4.6's dot11decrypt, `vectors/ieee80211_ft.vec` (names under SHA-384 and SHA-512, and Suite B's PTK, hostapd alone)|
|TLS 1.2 PRF (RFC 5246)|✓|✓|
|TLS 1.0/1.1 PRF (RFC 2246)|✓|✓|
|KDF_GOSTR3411_2012_256 and KDF_TREE (RFC 7836)|✓|spec reference|
|TLSTREE (RFC 9189)|✓|✓|
|KEG, KExp15/KImp15 (RFC 9189)|✓|spec reference; gost-engine's KExp15; RFC 9189 appendix A|
|KEG_28147, KExp28147/KImp28147 (RFC 9189)|✓|spec reference; RFC 9189 appendix A; gost-engine's `keyWrapCryptoPro` under all six GOST 28147-89 parameter sets: `vectors/gost_keywrap.vec`|
|CryptoPro key meshing and KEK diversification (RFC 4357)|✓|spec reference; RFC 9189 appendix A; gost-engine's `keyDiversifyCryptoPro` under all six GOST 28147-89 parameter sets: `vectors/gost_keywrap.vec`|

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
|TurboSHAKE128, TurboSHAKE256 (RFC 9861), every domain byte from 0x01 to 0x7F|✓|RFC 9861's 31 vectors, read out of `rfcs/rfc9861.txt`; XKCP's K12 (the Keccak team's code) and pycryptodome 3.24.1 agree on 1056 more, every message length to 400 bytes and every domain byte, outputs across the rate: `vectors/turboshake_k12.vec`|
|KangarooTwelve, KT128 and KT256 (RFC 9861), with customization strings|✓|RFC 9861's 36 vectors; XKCP's K12 on 722 more, either side of every chunk boundary to five chunks and with customization strings that cross one alone, and pycryptodome 3.24.1 on the KT128 half (it has no KT256): `vectors/turboshake_k12.vec`. pycryptodome 3.23.0 got an empty message with a customization string of 8190 bytes or more wrong; 3.24.0 fixed it|
|Keccak-224/256/384/512 (pre-standard)|✓|spec reference; Ethereum's function selectors|
|BLAKE2b, BLAKE2s (RFC 7693), keyed, salted and personalised, and the named lengths BLAKE2b-128, -160, -256, -384 and BLAKE2s-128, -160|✓|✓; the parameter block against hashlib; the named lengths against hashlib, OpenSSL 3.5 and, for BLAKE2b, b2sum, `vectors/blake2_named.vec`|
|RIPEMD-160|✓|✓|
|SM3 (GB/T 32905-2016)|✓|✓|
|Kupyna's MAC (DSTU 7564:2014), 256, 384 and 512 bits, `kupyna_mac`|✓|the standard's three examples and Bouncy Castle's three more, up to 1024 bytes; Bouncy Castle 1.77, cryptonite and the authors' reference implementation agree on 27 inputs, the first two on 108 more over other key lengths and messages of several blocks, and Bouncy Castle alone on keys past one block; `vectors/kupyna_mac.vec`|
|Kupyna (DSTU 7564:2014), any multiple of 8 bits to 512; `kupyna256`, `kupyna384`, `kupyna512`|✓|the standard's 15 byte-aligned examples; the authors' reference implementation and Bouncy Castle 1.77 agree on 19 messages at each of the three named sizes; the reference alone at ten other sizes; `vectors/kupyna.vec`|
|Whirlpool (ISO/IEC 10118-3)|✓|✓|
|Streebog-256 and -512 (GOST R 34.11-2012)|✓|✓|
|GOST R 34.11-94 (RFC 5831, RFC 4357 parameters)|✓|✓|
|GOST 34.311-95 (Ukraine; GOST R 34.11-94 under the DSTU 4145 default DKE)|✓|Bouncy Castle 1.77, gost89 and cryptonite agree on 14 messages, `vectors/dstu_gost.vec`; the empty message is cryptonite's and gost-engine's reading, `vectors/gost94_readings.vec`|
|GOST 34.311-95 under the other nine tables, `gost34311_dke2` to `gost34311_dke10`|✓|Bouncy Castle 1.77, gost89 and cryptonite agree on three messages under each, `vectors/dstu_dke.vec`|
|GOST R 34.11-94 and GOST 34.311-95 with the other reading of the empty message (`_bc` names)|✓|Bouncy Castle 1.77 and gost89 under all three S-boxes, the empty message included, with cryptonite on every message but the empty one, `vectors/gost94_readings.vec`; see [pitfalls 7zzo](pitfalls.md#7zzo-ukraines-gost)|
|RIPEMD-128, RIPEMD-256, RIPEMD-320|✓|libtomcrypt, Bouncy Castle, Crypto++ and RustCrypto (and GNU Crypto for RIPEMD-128), agreeing on 317 inputs: `vectors/legacy_hashes.vec`|
|HAS-160 (TTA.KO-12.0011/R2)|✓|RHash, Botan 1.10 and GNU Crypto, agreeing on 317 inputs: `vectors/legacy_hashes.vec`|
|Whirlpool-0, Whirlpool-T|✓|sphlib and GNU Crypto (and Crypto++ 5.2.1 for Whirlpool-T), agreeing on 317 inputs: `vectors/legacy_hashes.vec`|
|LM hash, NT hash|✓|see [key derivation](#key-derivation)|
|MD6 (unkeyed, default mode, whole-byte sizes to 512 bits)|✓|the MIT reference implementation and Jacksum's Java port of it, agreeing on 317 inputs at nine sizes: `vectors/legacy_hashes.vec`. The port is a translation of the reference, not a second design|
|Tiger at 128, 160 and 192 bits after three or more passes, `tiger` and PHP's `tiger128_3` to `tiger192_4`; Tiger2|✓|PHP, sphlib, RHash and Botan 1.10.17 agree on `tiger` over 30 messages; PHP and Botan on PHP's five other lengths and pass counts; sphlib and RHash on `tiger2`; Botan alone at five and six passes: `vectors/tiger_haval_snefru.vec`. mhash writes Tiger's words the other way round; see [pitfalls 7zzzd](pitfalls.md#7zzzd-tiger-haval-and-snefru)|
|HAVAL, all fifteen: `haval128_3` to `haval256_5`|✓|PHP, sphlib and mhash agree on 30 messages at each: `vectors/tiger_haval_snefru.vec`|
|Snefru-128 and Snefru-256, eight passes|✓|RHash and mhash, and PHP on Snefru-256, agree on 30 messages: `vectors/tiger_haval_snefru.vec`. The S-boxes come from RHash, PHP and mhash, which agree on every word|
|BLAKE-224, -256, -384 and -512, the SHA-3 finalist as finally submitted (not BLAKE2); `blake224` to `blake512`|✓|sphlib and dchest's Go, and the BLAKE team's reference at 256 and 512 bits, agree on 34 messages; sphlib and the reference on the counter past 32 bits, at lengths no message reaches, through a context told it has taken them: `vectors/sha3_finalists.vec`|
|Grøstl-224, -256, -384 and -512, the SHA-3 finalist as finally submitted (the tweaked round-3 version); `groestl224` to `groestl512`|✓|sphlib and the Grøstl team's 32 bit code agree on 34 messages: `vectors/sha3_finalists.vec`|
|JH-224, -256, -384 and -512, the SHA-3 finalist as finally submitted (42 rounds); `jh224` to `jh512`|✓|sphlib and the designer's bitsliced code (as SUPERCOP carries it, with the starting values for 224 and 384 bits derived as the specification says and checked against the code's own for 256 and 512) agree on 34 messages: `vectors/sha3_finalists.vec`|
|Skein 1.3, the SHA-3 finalist as finally submitted, on Threefish-256, -512 and -1024 at any whole number of bytes out; `skein256_128` to `skein1024_1024` as the submission names its sizes, `skeinSTATE_BITS` for any other|✓|the Skein team's code and Bouncy Castle 1.77 agree on 34 messages at the 13 named sizes and at three more - one byte, and outputs of several blocks - and sphlib on Skein-512 from 224 bits: `vectors/sha3_finalists.vec`|
|BLAKE3: hash, keyed and key derivation modes, any length of output from any offset; `blake3`|✓|the BLAKE3 team's 35 test vectors in all three modes (`rfcs/blake3-test-vectors.json`); their C and reference implementations and Bouncy Castle 1.77 agree on 504 outputs over 28 messages to 129 KB, around every chunk and tree boundary; offsets past 2^32 output blocks from the C implementation alone: `vectors/blake3.vec`|
|LSH (KS X 3262), LSH-256 and LSH-512 at any whole number of bytes out; `lsh256_224`, `lsh256_256`, `lsh512_224` to `lsh512_512` as the standard names them, `lshWIDTH_BITS` for any other|✓|KISA's reference implementation and Crypto++ 8.9.0 agree on 23 messages to 1000 bytes at the six named sizes and five others, and RyuaNerin's go-krypto at the six: `vectors/lsh.vec`. The step constants come from KISA's reference and Crypto++, which agree on every one|
|ssdeep, digests (libfuzzy 2.14.1's streaming form) and scores|✓|libfuzzy and ppdeep agree on 56 digests, among them inputs to 3 MB and every edge of the block size; libfuzzy's scores, which ppdeep's unit-cost edit distance matches on 139 of 184: `vectors/ssdeep.vec`|
|CTPH, as ctph.js 0.0.5 and CyberChef compute it, and its similarity|✓|ctph.js, which defines it and has no second implementation, on the same 56 inputs and 175 comparisons: `vectors/ssdeep.vec`|
|CRC-32 (IEEE 802.3, zlib's) and CRC-32C (Castagnoli), as numbers that continue across calls and by name as `crc32` and `crc32c`, outside the hash catalogue|✓|PHP, Go, java.util.zip, and zlib on CRC-32 and the SSE 4.2 instruction on CRC-32C, agree on 31 messages to 100 KB, among them the CRC catalogue's check input: `vectors/checksums.vec`|
|Any CRC from its six parameters (Williams's model, the CRC catalogue's notation), at widths 1 to 128, streaming; the 112 entries of the catalogue of parametrised CRC algorithms by name, as `crc-16/arc` to `crc-82/darc`, and any other by its model line, outside the hash catalogue|✓|pycrc 0.10.0's three algorithms, crccheck 1.3.0, crcmod 1.7 and the crc 3.4.0 crate agree, each on the rows it takes, on all of 4,960: every catalogue entry over 26 messages to 1000 bytes, and two random parameter sets at every width from 1 to 128 over eight: `vectors/crc.vec`. The catalogue is generated from crc-catalog 2.5.0's and crccheck's transcriptions of it, which agree on every entry written; CRC-64/NVME, in one of them only, is left out|
|Adler-32 (RFC 1950, zlib's), as a number that continues across calls and by name as `adler32`, outside the hash catalogue|✓|PHP, Go, java.util.zip and zlib agree on 31 messages, among them runs of 0xff either side of the 5552 bytes its sums can take between reductions and one of 100 KB: `vectors/checksums.vec`|
|Fletcher-16, -32 and -64, on bytes and on 16 and 32 bit little endian words with the last padded with zeros; `fletcher16`, `fletcher32`, `fletcher64`, outside the hash catalogue|✓|the C of the R package fletcher, hashlib-additional and the fletcher crate agree on 31 messages, among them every length modulo the word and a run of 100 KB of 0xff: `vectors/checksums.vec`|
|xxHash: XXH32, XXH64, XXH3-64 and XXH3-128, seeded and, for XXH3, with a secret of 136 bytes or more; streaming, and by name as `xxh32`, `xxh64`, `xxh3` and `xxh128`, outside the hash catalogue|✓|PHP, the reference C 0.8.3 and twox-hash agree on all of 2,185 rows over 59 messages to 100 KB, with OneOfOne/xxhash and pierrec/xxHash on XXH32 and XXH64, cespare/xxhash on XXH64 and zeebo/xxh3 on seeded XXH3; every witness that takes a secret refuses one of 135 bytes: `vectors/xxhash.vec`. The primes and the default secret are read out of three implementations that agree|
|MurmurHash3: x86_32, x86_128 and x64_128, seeded; streaming, and by name as `murmur3_32`, `murmur3_x86_128` and `murmur3_x64_128` or PHP's `murmur3a`, `murmur3c` and `murmur3f`, outside the hash catalogue|✓|PHP (PMurHash), SMHasher's reference, the murmur3 crate and murmurhash3js agree on all of 900 rows over 50 messages to 100 KB under six seeds, with spaolacci/murmur3 and twmb/murmur3 on x86_32 and x64_128: `vectors/murmur3.vec`|
|Jenkins's one-at-a-time, from zero (PHP's `joaat`) or from a seed, whole or as a bare state to continue; by name as `joaat`, `one_at_a_time` or `oaat`, outside the hash catalogue|✓|PHP, Perl 5.24's and gVisor's agree on 28 messages to 100 KB from zero, and Perl's and gVisor's under four seeds more: `vectors/joaat.vec`|
|FNV-0, FNV-1 and FNV-1a (RFC 9923) at 32, 64, 128, 256, 512 and 1024 bits; `fnv0_32` to `fnv1a_1024`, and PHP's `fnv132` to `fnv1a64`, outside the hash catalogue|✓|fnv-es and fnv-plus agree on FNV-1 and FNV-1a over 31 messages at every size, with PHP and Go where they have it and hashlib-additional except at 512 bits; fnv-es and hashlib-additional on FNV-0: `vectors/checksums.vec`. The primes are found by the rule that defines them, and Landon Curt Noll's C, libfnv and fnv-es carry the same|

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
|Binary fields GF(2^m) in a polynomial basis (`ec::gf2m`), masked throughout|✓|through DSTU 4145, below|
|Fixed-limb Curve25519 and Curve448 fields, Edwards arithmetic|✓|✓|
|Miller-Rabin primality|✓|✓|

|Algorithm|Implemented|Tested|
|---|---|---|
|RSA PKCS#1 v1.5, encryption and signatures|✓|✓|
|RSA-OAEP and RSA-PSS (RFC 8017)|✓|✓|
|RSA without padding (RSAEP/RSADP)|✓|Wycheproof's OAEP ciphertexts; Python's `pow`|
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
|DSTU 4145-2002 signatures, the ten named curves and curves given whole|✓|the standard's worked example; Bouncy Castle 1.77 signs with a given `e` and it and cryptonite verify, over 32-byte hashes on all ten curves and four more, `vectors/dstu4145.vec`; other hash lengths Bouncy Castle's alone|
|DSTU 4145-2002 public keys and point compression|✓|Bouncy Castle 1.77 and cryptonite agree, both directions, `vectors/dstu4145.vec`|
|DSTU 4145-2002 Diffie-Hellman, with and without the cofactor|✓|cryptonite's whole point, Bouncy Castle's x, `vectors/dstu4145.vec`|
|DSTU 4145-2002 on the five curves in an optimal normal basis (`dstu4145-m173-onb` to `dstu4145-m431-onb`): keys, compression, signatures, Diffie-Hellman|✓|parameters from cryptonite and li0ard, which agree; on every curve cryptonite and li0ard agree on six public keys and their compressions, li0ard signs with a given `e` and both verify (li0ard alone for a hash that is not 32 bytes), both refuse changed signatures, and cryptonite's shared point has li0ard's x; `vectors/dstu4145_onb.vec`. Not in key containers, whose parameters are in a polynomial basis|
|DSTU 4145-2002 key containers (`dstu4145_keys_open`, `dstu4145_key6`) and certificates|✓|under "Certificates and keys" below|
|DSTU 9041:2020 encryption over twisted Edwards curves, E256/1 and E512/1 (`dstu9041-e256-1`, `dstu9041-e512-1`)|✓|the standard's worked examples Г.1 and Г.3; uacrypt and li0ard agree on 24 public keys and 86 ciphertexts, every whole number of bytes on both curves, and each decrypts the other's; 14 messages counted in bits, uacrypt's ciphertexts and li0ard's decryptions; 20 ciphertexts both refuse; curve parameters from both, `vectors/dstu9041.vec`. The 384 and 768-bit curves are not here|
|SM2 signatures (GB/T 32918.2)|✓|✓|
|SM2 public key encryption (GB/T 32918.4)|✓|✓|
|HPKE (RFC 9180, `publickey_ciphers::hpke`): DHKEM over P-256, P-384, P-521, X25519 and X448 in all four modes (base, PSK, auth, auth-PSK); HKDF-SHA256, -SHA384 and -SHA512; AES-128-GCM, AES-256-GCM, ChaCha20Poly1305 and export only; contexts, sequence numbers and exports|✓|RFC 9180's appendix A read out of the document (28 vectors); the CFRG's vector file the appendix was printed from (128, X448 among them), `vectors/hpke.vec`; pyhpke 0.6.5 on every DHKEM, HKDF and AEAD in all four modes, 240 suites, the same ciphertext byte for byte from the same ephemeral input and each opening the other's; filippo.io/hpke v0.4.0 in base mode; `vectors/hpke_witness.vec`. The post-quantum KEMs are under "Post-quantum"|
|SM2 key exchange (GB/T 32918.3)|||
|SM9 (GB/T 38635, identity-based)|||

**Curves:** P-256, P-384, P-521, secp256k1, sm2p256v1 (GB/T 32918.5),
the seven GOST curves of RFC 4357 and RFC 7836, Curve25519 and
Curve448 for X25519 and X448, and edwards25519 and edwards448 for EdDSA.
DSTU 4145-2002's ten binary curves, `dstu4145-m163` to `dstu4145-m431`,
in a polynomial basis; the standard's optimal-normal-basis forms are not
here.
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
|Writing post-quantum keys: PKCS#8 for ML-DSA and ML-KEM in all three of their forms and for SLH-DSA, and SubjectPublicKeyInfo for all three|✓|RFC 9881's, RFC 9935's and RFC 9909's examples, OpenSSL 3.5's keys in every form and the IETF hackathon's SLH-DSA keys from four implementations, written again byte for byte; OpenSSL 3.5 reads, signs and decapsulates with ours, encrypted ones too, live|
|ML-KEM certificates, public keys and private keys (RFC 9935), all three private key forms checked as section 8 says; `CertificateAuthority.issue_ml_kem`|✓|RFC 9935's examples, the four bad keys refused; OpenSSL 3.5 both ways: its keys, 9 encapsulations decapsulated here and certificates offline, and ours decapsulated and verified by it live|
|SLH-DSA (FIPS 205): key generation, signing and verification, internal and external interfaces, pure and pre-hash|✓|ACVP; four other implementations' signatures through RFC 9909 below|
|LMS and HSS (RFC 8554, RFC 9858, SP 800-208): all twenty LMS and sixteen LM-OTS parameter sets, keys from a SEED and I (RFC 8554 Appendix A), stateful signing, verification, one to eight levels|✓|RFC 8554's and RFC 9858's worked examples signed again from their seeds; hash-sigs, Bouncy Castle 1.77 and pyhsslms agree on 88 trees, and hash-sigs and Bouncy Castle on 37 hierarchies, which those and hbs-lms verify; all refuse 162 changed signatures but one: `vectors/lms.vec`|
|XMSS and XMSS^MT (RFC 8391, SP 800-208): all 21 XMSS and 56 XMSS^MT parameter sets, keys from three seeds with SP 800-208's WOTS+ derivation, stateful signing, verification|✓|the reference implementation's seven keys in Botan's tests made again from their seeds, and the 90 signatures of Botan's signing and verification tests verified; the reference implementation and Botan 3.6.1 agree on every XMSS set at height 10, and the reference on XMSS^MT across tree boundaries at 20/2, 20/4, 40/8 and 60/12, which Bouncy Castle 1.77 verifies; Bouncy Castle's signatures under RFC 8391's derivation verify; all refuse 54 changed signatures but one: `vectors/xmss.vec`. SP 800-208's XMSS^MT sets have no second implementation here|
|SLH-DSA certificates, public keys and private keys (RFC 9909), pure and HashSLH-DSA, each key held to its own form as section 8 says|✓|RFC 9909's example; the IETF hackathon's certificates and keys from OpenSSL 3.5, Bouncy Castle, Botan and Redhound offline; ours verified by OpenSSL 3.5 live at all twelve sets|
|Streamlined NTRU Prime, sntrup761 (OpenSSH 9.0 to 9.8's default)|✓|the draft's vectors, and against sshd|
|Hybrid TLS groups: X25519MLKEM768 and the NIST hybrids (RFC 10024)|✓|OpenSSL 3.5 both ways; Cloudflare and Google live|
|HPKE with post-quantum KEMs (draft-ietf-hpke-pq-05): ML-KEM-512, -768 and -1024, the hybrids MLKEM768-P256, MLKEM1024-P384 and MLKEM768-X25519 (X-Wing), and the one-stage SHAKE128, SHAKE256, TurboSHAKE128 and TurboSHAKE256 KDFs|✓|the draft's vectors, made by its reference implementation and, for the HKDF suites, checked by Cloudflare's CIRCL, `vectors/hpke.vec`; filippo.io/hpke v0.4.0 both ways on every suite with these but ML-KEM-512 and TurboSHAKE, 180 of them, the same key pair from the same `ikm`, `vectors/hpke_witness.vec`; ML-KEM-512 by the draft's vectors alone. The TurboSHAKE KDFs by the draft's three vectors alone - no second implementation has them - over a TurboSHAKE that XKCP and pycryptodome check and the one-stage key schedule the SHAKE KDFs share|

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
reach. For SLH-DSA no second implementation runs in the tests, but
four have signed certificates they read: OpenSSL 3.5's, Bouncy Castle's,
Botan's and Redhound's, at every parameter set between them, and
OpenSSL 3.5 verifies this library's live.
[post-quantum.md](post-quantum.md) has the detail.

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
|HSS, XMSS and XMSS^MT certificates (RFC 9802, RFC 9708): reading, verifying, and issuing with a stateful key|✓|RFC 9802's three appendix certificates; Bouncy Castle 1.85's twelve, every HSS hash family and the RFC 8391 XMSS and XMSS^MT families, verified here, and fifteen of ours verified by it and made again byte for byte, `vectors/hbs_x509.vec`. Not SP 800-208's 192 bit XMSS sets, on which Bouncy Castle 1.85 disagrees with the XMSS reference, Botan and this library|
|DSA certificates and private keys (RFC 3279, RFC 5758)|✓|✓|
|PEM and base64|✓|✓|
|Private keys: PKCS#8, SEC1, PKCS#1; X25519 and X448 (RFC 8410)|✓|✓|
|Encrypted private keys (PBES2, PBES1, PKCS#12 PBE), reading and writing|✓|✓|
|Java's key protectors (JKS, JCEKS)|✓|keytool's files|
|DSTU 4145-2002 certificates: keys in either byte order with the curve named or given whole and the DKE, signatures over GOST 34.311-95 under the issuer's DKE and over Kupyna-256, -384 and -512, reading, verifying and issuing|✓|three root certificates of Ukraine's central certifying authority (GOST 34.311-95, under the default DKE and under its own; Kupyna-256); dstu-engine and li0ard verify ours on all ten curves and in chains, dstu-engine reads every key, `vectors/dstu4145_x509.vec`|
|Ukrainian private keys and containers: DSTU 4145 PKCS#8 with the second key in the attributes, IIT's `Key-6.dat`, PBES2 under GOST 28147 CFB and HMAC-GOST 34.311, reading and writing|✓|dstu-engine's keylib reads the same keys from IIT's and jkurwa's files and from ours, on all ten curves; the certificates' subject key identifiers; `vectors/ua_keys.vec`. PrivatBank's cryptonite reads the same keys from every PKCS#8, PBES2 and PKCS#12 among them it can read, and from a PKCS#12 IIT wrote; `vectors/ua_keys_cryptonite.vec`|
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
|Server, TLS 1.3, with HelloRetryRequest, session tickets, 0-RTT and KeyUpdate|✓|✓|
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
holds fifteen real TLS 1.2 handshakes between OpenSSL and gost-engine at
both ends, and `tests/test_gost_transcript.rs` decrypts records the
engine encrypted, which is the only thing that can settle the byte
orders: our own client and server agree with each other whichever way
round any of them is. `tests/test_gost_key_transport.rs` unwraps the
engine's ClientKeyExchange under the recorded server key, which settles
the key exchange the same way - including 0xC102 and 0xFF85 on a GOST R
34.10-2001 certificate, where the UKM's hash follows the suite and the
VKO and S-box follow the key. Four are on RFC 4357's and TC 26's test
curves, which this library reaches only through `register_oid`. [pitfalls.md](pitfalls.md) §7b and §7o have the
detail.
