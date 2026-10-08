# Vendored RFC texts

These are unmodified RFC texts, fetched from `https://www.rfc-editor.org/rfc/rfcNNNN.txt`.
They are here so the test suite can read a standard's own bytes back out
of it, **with no network access** — the same rule the rest of the suite
follows. Two things read them:

* `scripts/rfc_oids.py`, for the object identifiers in `src/x509/oids.rs`;
* the test modules that parse a document's own vectors at compile time
  through `include_str!` rather than carrying a copy of them —
  `src/ec/eddsa.rs` (RFC 8032 section 7), `src/block_ciphers/keywrap.rs`
  (RFC 3394 section 4 and RFC 5649 section 6),
  `src/hash_functions/sm3.rs` (the SM3 draft's appendices A and B) and
  `src/hash_functions/md2.rs` and `md4.rs` (RFC 1319 and RFC 1320);
* `src/hash_functions/md2.rs` and `md4.rs` again, for something more
  than vectors: the **algorithm constants themselves** — MD2's π
  permutation and MD4's three round schedules — are parsed out of the
  documents by `const fn` and never appear as literals. Both tables are
  split across a page break in their document, so a transcription would
  have had to step over a running header and a page number by hand.

The second is the more general pattern, and the one to reach for next
time: a vector transcribed into a source file is a vector that was typed,
and this repository has been bitten by that twice — see docs/extending.md,
"Where test vectors come from".

## Why these

Ten of them are the smallest set that defines every OID in `oids.rs` that
any RFC defines; the rest are here for their vectors and their
parameters — `rfc4357.txt` and `rfc7836.txt` are also read by
`ec::curves::document_tests`, which checks every GOST curve constant
against the document that defines it rather than against arithmetic
alone. Adding a document is fine; removing one will make
`scripts/diff_check.py oids` fail with the names it can no longer find,
which is the point. Several are here for their **vectors** rather than
their OIDs - `rfc8032.txt`, `rfc7748.txt`, `rfc3394.txt`, `rfc5649.txt`,
`rfc5831.txt`, `rfc7253.txt`, `rfc9058.txt`, `rfc9189.txt` and `rfc9367.txt` - and the
table below says what reads each one.

| | defines |
|---|---|
| `rfc4055.txt` | RSASSA-PSS, and the bare SHA OIDs used in a DigestInfo |
| `rfc4357.txt` | the CryptoPro GOST parameter sets, which is what certificates in the wild carry, and the 2001-era algorithm OIDs (`id-GostR3410-2001`, `id-GostR3411-94`, and the signature OID that names both). Also read at test time for their *values*: section 11.4's five elliptic curve parameter sets (`ec::curves::document_tests`), and sections 11.1 and 11.2's **seven S-box tables**, packed two substitutions to a byte — `block_ciphers::gost::document_tests` unpacks all seven and compares them against the tables in `src/block_ciphers/gost.rs`, which is the only thing standing behind those thousand numbers besides somebody having typed them correctly. `scripts/diff_check.py` reads the same tables out of the same file, so its reference and the Rust cannot agree about an algorithm while disagreeing about which table it runs on |
| `rfc4519.txt` | `street`, `uid` and `dc`, stated in LDAP's schema syntax rather than ASN.1 |
| `rfc7292.txt` | the six PKCS#12 password-based encryption schemes — including the one the document itself spells `pbewithSHAAnd40BitRC2-CBC`, with a lowercase `w` |
| `rfc8018.txt` | PKCS#5: PBES1's six schemes, PBKDF2 and PBES2, the HMAC PRFs, and the ciphers PBES2 names |
| `rfc5280.txt` | the certificate extensions, the DN attributes, the extended key usages |
| `rfc5480.txt` | the named curves, and `id-ecPublicKey` |
| `rfc7836.txt` | the TC 26 GOST arc that RFC 9215's parameter sets hang off |
| `rfc6960.txt` | OCSP's own arc — `id-pkix-ocsp` and everything under it. Note that it defines `id-pkix-ocsp` as `{ id-ad-ocsp }`, a brace-less alias resolved out of RFC 5280, which is why both documents are needed for one OID |
| `rfc9215.txt` | the GOST R 34.10-2012 key, signature and parameter set OIDs |
| `rfc5831.txt` | no OIDs — GOST R 34.11-94, the hash Streebog replaced and the one the 0x0081 TLS suite uses. `src/hash_functions/gost94.rs` reads three things out of it: appendix 7.1's S-box table (printed transposed, with its columns running 8 to 1 left to right), appendix 7.3's two worked examples *with every intermediate* — the four keys and the cipher outputs of each compression, not only the final digest — and the key generation constant `C[3]`, which the document writes as an expression in runs of bits rather than as hex, so the expression is parsed instead of the hex being typed. It is also the document that disagrees with itself: `K[1]` of the first example is printed with two of its eight 32-bit words transposed, while the `S` two lines below it, the `KSI` after that, and both final digests are right |
| `rfc9189.txt` | no OIDs — the GOST TLS 1.2 suites. Two things read it: `tests/test_gost_rfc9189_flight.rs` parses appendix A.2.2's thirteen records out of it and replays the server's flight at our client, and `tls::suites` checks that section 10 still says what the 0xFF85 row is for. The appendix prints a whole handshake in hex, including a server certificate on a curve this library did not have when the file was vendored — which is how that gap was found |
| `draft-chudov-cryptopro-cptls-04.txt` | no OIDs, and not an RFC — the CryptoPro TLS draft, which is where the 0x0080 to 0x0083 cipher suites come from. It expired in 2009 and was never published, and `TLS_GOSTR341001_WITH_28147_CNT_IMIT` (0x0081) is what a box installed before 2012 speaks; OpenSSL's GOST engine still carries it as `GOST2001-GOST89-GOST89`. Fetched from `https://www.ietf.org/archive/id/`. It is the authority for four things this library could not get anywhere else: that the PRF and the transcript hash are GOST R 34.11-94, that `shared_ukm` is the first eight bytes of that hash over the two randoms, that the key exchange is VKO GOST R 34.10-2001 followed by CryptoPro Key Wrap, and that the record layer's S-box is `id-Gost28147-89-CryptoPro-A-ParamSet` rather than RFC 9189's param-Z |
| `rfc9367.txt` | no OIDs — the GOST TLS 1.3 suites, 0xC103 to 0xC106. Two things read it. `src/kdf/gost.rs`'s `document_tests` reads section 4.1.2's table of TLSTREE constants — twelve masks over four suites, none repeating an RFC 9189 set — with the same parser reading RFC 9189's table, since both print it identically. And `tests/test_rfc9367_flight.rs` replays **both** worked handshakes out of appendix A: the key schedule value by value under Streebog-256, TLSTREE at every sequence number printed, both Finished MACs, the external PSK binder, the CertificateVerify signature against the document's own certificate, and every fully-printed record decrypted *and* re-encrypted. It is the only independent opinion these suites have. The document is also wrong in three places, each pinned by a test: two record keys in A.1 carry the other direction's label, and two of A.2's four IV labels say `"iv", "", 16` where the printed value is eight bytes. Twelve of its twenty-six records have 16 KB payloads elided with `[...]` and cannot be replayed at all |
| `rfc9058.txt` | no OIDs — MGM, the AEAD those four suites use. `src/block_ciphers/mgm.rs` reads appendix A's four worked examples out of it at test time, and takes the *intermediates* as well as the answers: every `Y_i` and `Z_i` of both counter chains, every `H_i`, the running sum, and the `len(A) || len(C)` block. The tag alone would not separate `incr_l` from `incr_r`, which is the mistake the document's own section 6 says the mode is shaped to avoid |
| `rfc7748.txt` | no OIDs — here for section 5.2's and 6.2's X25519 and X448 test vectors, which `src/ec/x448_vectors.rs` parses out of this file at test time. **`X448:` appears three times in it** — once inside section 5's `<CODE BEGINS>` reference implementation, once over the vectors and once over the iterated results — so the parser is anchored at the section heading. A search from the top lands in the pseudocode and finds nothing, which is what the first version did and what the count assertion caught |
| `rfc8032.txt` | no OIDs — it is here for section 7's EdDSA test vectors, which `src/ec/eddsa.rs` parses out of this file at test time |
| `rfc8410.txt` | the four OIDs of the Edwards arc, `1.3.101.110` to `113`, stated as `id-Ed25519 OBJECT IDENTIFIER ::= { 1 3 101 112 }` — the arc-list shape `rfc_oids.py` already reads. It is also the authority for the two things about this encoding that a parser gets wrong from its neighbours: the subjectPublicKey *is* the key, and the AlgorithmIdentifier's parameters are absent rather than NULL |
| `rfc9580.txt` | no OIDs — OpenPGP. `examples/products/openpgp` reads appendix A at test time: the hex dumps and armored messages of A.9 to A.12 and every intermediate value A.9 to A.11 print, found by their labels within each section |
| `draft-koch-librepgp-04.txt` | not an RFC — LibrePGP, the OpenPGP dialect GnuPG 2.3 and later write, fetched from `https://www.ietf.org/archive/id/`. It defines the OCB Encrypted Data packet (tag 20) and SKESK version 5, which RFC 9580 does not; `examples/products/openpgp` reads its appendix A.3 sample at test time |
| `rfc5639.txt` | the Brainpool curves. The library does not carry them; `examples/products/openpgp` reads section 3's domain parameters for brainpoolP256r1, P384r1 and P512r1 out of the text at run time and registers them, so that GnuPG's Brainpool keys work, and its tests check that the parameters make curves the library accepts |
| `rfc7253.txt` | no OIDs — OCB. `src/block_ciphers/ocb.rs` reads all of appendix A at test time: the seventeen samples (a value continues on unlabelled lines, and both keys and both tag lengths are taken from the text), the internal values of the sixteenth (`L_*`, `L_$`, `L_0`, `L_1`, the offsets, `bottom`), and the nine iterated results, rebuilding each parameter set's key and tag length from its printed name |
| `rfc3394.txt` | no OIDs — section 4's six AES Key Wrap vectors. It writes its labels four different ways, which is why the parser in `keywrap.rs` asserts the count it found |
| `rfc5649.txt` | no OIDs — section 6's two key-wrap-with-padding vectors |
| `rfc5794.txt` | no OIDs in `oids.rs` — ARIA. `src/block_ciphers/aria.rs` parses the four S-box tables (1024 bytes), the sixteen diffusion equations (112 term indices) and the three key-schedule constants out of it at **compile time**, plus Appendix A's vectors, round keys and intermediate values at test time. Nothing about ARIA is typed anywhere in the crate. Note that SB4's first row prints one entry as ` 9` rather than `09`, alone in the document |
| `rfc2040.txt` | no OIDs — RC5, RC5-CBC, RC5-CBC-Pad and RC5-CTS. `src/block_ciphers/rc5.rs` parses section 9's 29 vectors out of it, which sweep rounds 0, 1, 2, 8, 12 and 16 against key lengths of 1, 4, 5, 8 and 16 bytes. They are *CBC* vectors, which is better than it sounds: CBC with an all-zero IV over one block is ECB of that block, so the zero-IV rows pin the primitive and the rest pin the primitive and the mode together |
| `rfc2612.txt` | no OIDs — CAST-256. `src/block_ciphers/cast256.rs` reads the S-boxes it reprints from CAST-128 (and requires them to equal `cast5`'s, read from RFC 2144) and Appendix A: three keys, 128, 192 and 256 bits, each with all twelve quad-rounds' rotation keys, masking keys and outputs, encrypting and decrypting |
| `rfc1319.txt` | no OIDs — MD2. Two things are read out of it: appendix A's 256-byte π permutation, which `src/hash_functions/md2.rs` parses into a table at **compile time**, and A.5's seven test vectors. It is also the document that disagrees with itself: section 3.2's prose assigns where the appendix's code XOR-assigns, and the vectors follow the code (RFC 6149) |
| `rfc2409.txt` | no OIDs — IKE, here for section 6.2's 1024 bit MODP group (Oakley group 2), which SSH calls `diffie-hellman-group1-sha1`. `publickey_ciphers::dh`'s `rfc_modp_tests` reads both forms the document prints - the hex and the formula over pi - and checks each against the other and against the constant. Its table of contents carries the same section title, so the heading is matched as a whole line |
| `rfc3526.txt` | no OIDs — the six MODP groups from 1536 to 8192 bits, read the same way as RFC 2409's. The 8192 bit prime runs across a page break |
| `draft-josefsson-ntruprime-streamlined-00.txt` | no OIDs — Streamlined NTRU Prime. `src/pq/sntrup.rs` reads section 7's two test vectors out of it (NIST KAT records: a CTR_DRBG seed, then the keys, ciphertext and shared key it produces), which pins key generation, encapsulation and decapsulation to the byte. The section title also appears in the table of contents, so the parser starts from the second |
| `rfc6979.txt` | no OIDs — deterministic DSA and ECDSA. Appendix A.2's vectors are read out of it by `publickey_ciphers::dsa::rfc6979`: both DSA groups (twenty signatures, `k` included, one of them reached only after the first candidate is rejected) and the P-256, P-384 and P-521 sections for ECDSA (thirty more). Its table of contents repeats the section titles, so a heading is matched as a whole line |
| `rfc4251.txt` | no OIDs — SSH's architecture, here for section 5's data types. `src/ssh/wire.rs` reads its `mpint` and `name-list` example tables out of it; one mpint value is printed with an odd number of hex digits (`9a378f9b2e332a7`), which a parser that pairs digits from the left gets wrong |
| `rfc5903.txt` | no OIDs — the three NIST curves as IKE prints them. `src/ec/curves.rs`'s `rfc5903_tests` reads section 3's parameters for P-256, P-384 and P-521 and compares them with the constants in the source, and replays section 8's exchange on each. P-521's constants were generated from this file by script after a hand-typed first attempt came out with a 529 bit `p` |
| `rfc1320.txt` | no OIDs — MD4. `src/hash_functions/md4.rs` parses the three round tables, the two additive constants and A.5's seven vectors out of it, so nothing about MD4 is typed anywhere in the crate. Round 3's message order is the most mistyped table in the MD family, which is the whole reason |
| `rfc9881.txt` | `id-ml-dsa-44`, `-65` and `-87`, read by `rfc_oids.py`. Also read by `src/x509/rfc9881_tests.rs` for Appendix C: the PEM blocks are cut out of the text page breaks and all, giving nine private keys in three forms, three public keys, three self-signed certificates and three inconsistent keys that must be refused |
| `draft-ietf-tls-mldsa-06.txt` | no OIDs, and not an RFC - the Internet-Draft assigning TLS 1.3's `mldsa44`, `mldsa65` and `mldsa87` (0x0904 to 0x0906). `tls::handshake13`'s tests read the IANA table's rows and check the constants, names and parameter sets against them |
| `rfc7515.txt` | no OIDs — JWS. `examples/products/jose/rfc.rs` reads appendix A at test time: the HMAC, RSA and both ECDSA examples (the first two are deterministic and are reproduced byte for byte), the unsecured JWS, both JSON serializations, and appendix E's `crit` example that must be refused. Its display blocks run across page breaks, which the reader joins when both sides are indented and treats as a paragraph break otherwise |
| `rfc7516.txt` | no OIDs — JWE. The same module decrypts appendix A.1 to A.3 (RSA-OAEP with A256GCM, RSA1_5 and A128KW with A128CBC-HS256) to their plaintexts, given as JSON arrays of octets, and A.4's two-recipient general serialization with each recipient's key |
| `rfc7518.txt` | no OIDs — JWA. Appendix B's three CBC-HMAC test cases (`K`, `P`, `IV`, `A` to `E` and `T`) and appendix C's ECDH-ES computation, from both parties' keys through the Concat KDF to the derived key |
| `rfc7638.txt` | no OIDs — the JWK thumbprint; section 3.1's RSA example |
| `rfc7797.txt` | no OIDs — the unencoded JWS payload; section 4's two examples, the second detached because its payload contains a '.' |
| `rfc8037.txt` | no OIDs — EdDSA, X25519 and X448 in JOSE. Its examples are printed at the indentation of its prose, so they are found by paragraph; A.4's Ed25519 signature is reproduced, and A.6 and A.7's ephemeral keys and shared secrets are recomputed |
| `rfc4134.txt` | no OIDs — "Examples of S/MIME Messages". `examples/products/cms` extracts appendix A's forty files at test time, the way the document's own Perl program does (`|>` opens a file, `|<` closes it, every other `|` line is base64): the keys and certificates of Alice, Bob, Carl and Diane, and the signed, enveloped, digested and encrypted messages of sections 3 to 7. Every signature verifies - DSA with SHA-1 and RSA, detached content, two signers one of whose DSA keys inherits its group from its issuer, a key identifier, S/MIME both ways - and every enveloped message opens with Bob's key. Sections 7.1 and 7.2 are EncryptedData under a key the document never gives, so they are only parsed |
| `rfc3211.txt` | no OIDs — the CMS password recipient. Its section 3 has two vectors, PBKDF2 into DES and into Triple DES and then the double CBC key wrap with the padding bytes the document used; `examples/products/cms` reads both, value by value, and wraps and unwraps them byte for byte |
| `rfc3217.txt` | no OIDs — the Triple-DES and RC2 key wraps. Section 3.4's Triple-DES example is read by `examples/products/cms`, whose EC recipients use that wrap for Triple-DES content, as OpenSSL does |
| `rfc8419.txt` | no OIDs in `oids.rs` — EdDSA in CMS. `scripts/check_cms.py` reads its ASN.1 module for `id-shake256-len`, the one identifier the CMS example uses that OpenSSL cannot name |
| `rfc3961.txt` | no OIDs - Kerberos's encryption and checksum framework. `examples/products/kerberos` reads appendix A at test time: n-fold, DES string-to-key, Triple DES's DR and DK and string-to-key, and the modified CRC-32. A.4 names its last password U+1011E where the UTF-8 printed for the same password in A.2 is U+1D11E's; the test substitutes the code point on that one line, asserting the misprint is still there |
| `rfc3962.txt` | no OIDs - AES for Kerberos. Appendix B's PBKDF2 string-to-key vectors and its six ciphertext-stealing ones are read by `examples/products/kerberos` |
| `rfc4757.txt` | no OIDs - RC4-HMAC. No vectors; `examples/products/kerberos` follows its text, except usage 9, which MIT Kerberos and Heimdal keep as 9 where the document maps it to 8 |
| `rfc6803.txt` | no OIDs - Camellia for Kerberos. Section 10's string-to-key, key derivation, encryption and checksum vectors are read by `examples/products/kerberos`; the encryptions give no key usage, and are 0 to 4 in the order printed |
| `rfc8009.txt` | no OIDs - AES with HMAC-SHA2 for Kerberos. Appendix A's string-to-key, key derivation, encryption, checksum and PRF vectors are read by `examples/products/kerberos` |
| `bip-0032.mediawiki` | not an RFC - BIP-32, hierarchical deterministic keys, from `bitcoin/bips` at 927b6de9915c9262615a6399de51b200f81e5aa4, like the BIPs below. `examples/products/wallet` reads its five test vectors: the chains of vectors 1 to 4, and every invalid key of vector 5 |
| `bip-0038.mediawiki` | not an RFC - BIP-38, passphrase-protected keys. Its nine vectors are read by `examples/products/wallet`; test 3's passphrase is taken in the NFC form the document's note prints |
| `bip-0039.mediawiki`, `bip-0039/english.txt` | not an RFC - BIP-39 and its English word list, which `examples/products/wallet` compiles in; its vectors are python-mnemonic's, in `examples/products/fixtures/wallet/` |
| `bip-0049.mediawiki`, `bip-0084.mediawiki`, `bip-0086.mediawiki` | not RFCs - the derivation paths and address types of P2SH-P2WPKH, P2WPKH and key-path P2TR wallets. Their test vectors are read by `examples/products/wallet` |
| `bip-0173.mediawiki`, `bip-0350.mediawiki` | not RFCs - Bech32 and Bech32m. BIP-350's segwit address vectors, which replace BIP-173's for witness versions above 0, are read by `examples/products/wallet` |
| `erc-55.md`, `erc-191.md` | not RFCs - Ethereum's mixed-case address checksum and signed data, from `ethereum/ercs` at 365b4c02879f3e882b91281d42b4f57b406205e9. ERC-55's test cases are read by `examples/products/wallet` |
| `rfc4034.txt`, `rfc4035.txt` | no OIDs in `oids.rs` - DNSSEC's records and its protocol. `examples/products/dnssec` reads RFC 4034 section 5.4's DNSKEY and DS and checks its key tag and digest, and verifies RFC 4035 appendix A's whole signed zone (RSASHA1, NSEC, a secure and an insecure delegation, a wildcard) at a time inside its signatures' window |
| `rfc4509.txt` | no OIDs - SHA-256 DS records; section 2.3's DS of RFC 4034's key is checked by `examples/products/dnssec` |
| `rfc5155.txt` | no OIDs - NSEC3. `examples/products/dnssec` checks appendix A's twelve owner name hashes and verifies its signed zone, opt-out included; one hash is printed across two lines |
| `rfc5702.txt`, `rfc6605.txt`, `rfc8080.txt` | no OIDs - RSA/SHA-2, ECDSA and EdDSA in DNSSEC. `examples/products/dnssec` reads each example's private key, DNSKEY, DS and RRSIG, and reproduces the deterministic signatures. RFC 8080's RRSIGs leave out the algorithm field and open a parenthesis they never close; the test restores what the signatures cover |
| `rfc5933.txt`, `rfc9558.txt` | GOST in DNSSEC; both print the key's PKCS#8 with its OIDs. `examples/products/dnssec` reads the private keys, DNSKEYs, RRSIGs and DS records, and reproduces RFC 9558's signature from the nonce it gives |
| `rfc9563.txt` | no OIDs - SM2 in DNSSEC. `examples/products/dnssec` reads its example, which is inconsistent in ways the test names (`examples/products/README.md`) |
| `rfc2536.txt`, `rfc3110.txt`, `rfc6840.txt` | no OIDs - DSA and RSA key and signature encodings in DNS, and the DNSSEC clarifications (NSEC's next name keeps its case). Read by people, for `examples/products/dnssec` |
| `rfc3279.txt` | `id-dsa` and `id-dsa-with-sha1`, with the Dss-Parms, DSAPublicKey and Dss-Sig-Value encodings that `x509` reads and writes |
| `rfc5758.txt` | `id-dsa-with-sha224` and `id-dsa-with-sha256` |
| `rfc4418.txt` | no OIDs — UMAC. `src/mac/umac.rs` reads the appendix's tag table (eight messages at three tag lengths) and the intermediate values for `'abc' * 500` (NH, L2 and L3 keys, the pad, the UHASH) out of it. **The 2^25 row is misprinted**: verified erratum 3507 gives its corrected tags, and the test substitutes them only for that exact printed line, which it asserts is still present. Nettle agrees with the correction (`vectors/umac_nettle.vec`) |
| `draft-sca-cfrg-sm3-02.txt` | no OIDs, and not an RFC — an expired Internet-Draft, kept because it is the only English text that states both GB/T 32905-2016's own two SM3 vectors and the eighteen from the GB/T 32918 SM2 documents. Fetched from `https://www.ietf.org/archive/id/`. `src/hash_functions/sm3.rs` parses appendices A and B out of it; `src/ec/sm2.rs` will want B.1 through B.4, which are SM2's own `Z_A` and `e` intermediates |
| `draft-irtf-cfrg-xchacha-03.txt` | no OIDs, and not an RFC - XChaCha20 and AEAD_XChaCha20_Poly1305, an expired draft that libsodium, Go's x/crypto and WireGuard's cookie replies follow. Fetched from `https://www.ietf.org/archive/id/`. `src/stream_ciphers/chacha.rs` reads section 2.2.1's HChaCha20 vector (key and nonce as colon-separated bytes, the subkey as two rows of words) and appendix A.3.2's two XChaCha20 keystreams, and `chacha20poly1305.rs` reads appendix A.3.1's AEAD vector |
| `rfc4226.txt`, `rfc6238.txt` | no OIDs - HOTP and TOTP. `examples/products/smartcard` reads RFC 4226's appendix D table and RFC 6238's appendix B table out of them, with RFC 6238's three seeds taken from its appendix A source rather than its table: the table says every mode used the 20-byte seed, the source (and erratum 2866) gives 32 bytes for SHA-256 and 64 for SHA-512, and the printed values are the source's |

`secp256k1` is in none of them and in no RFC: it comes from SEC 2, and
it is in this library because certificates using it exist.
`_OID_IN_RFCS` in `scripts/diff_check.py` says so, and
python-cryptography covers it instead.

## Why whole documents

Extracting the OID-bearing lines into something smaller would make the
extraction an unchecked step, and an unchecked step between the standard
and the check is the thing this whole arrangement exists to remove. They
are plain text and compress well.

## Updating one

Refetch it whole, unmodified. If an RFC is obsoleted, add the new one
rather than editing the old: a certificate signed in 2009 was signed
against the document that was current then, and this library's reason to
exist is that those certificates are still out there.
