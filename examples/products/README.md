# Product examples

Formats that other software writes, built from this library's
primitives: the library's ciphers, modes, hashes and key derivations
doing the job they do inside a real product, and the product's own
tools as the judge of whether the bytes are right.

Each example is one program with a command line and its own tests.
`cargo test` runs the tests (they are offline, reading fixtures in
`fixtures/` that the product's tools made); a script in `scripts/`
checks the example against the real tools by hand.

```console
$ cargo run --release --example luks -- open disk.img "passphrase" --volume-key
$ cargo test --example luks
$ python3 scripts/check_luks.py --cryptsetup-tests ~/src/cryptsetup/tests
```

A passphrase given as an argument is visible to every user of the
machine in the process list, and stays in the shell's history. Every
example that takes one can read it from standard input instead:
`--passphrase-stdin` (LUKS, age and OpenPGP), `--password-stdin`
(VeraCrypt, KeePass, ZIP, 7z, CMS, Kerberos, PDF, Office, OpenDocument,
the key stores and the wallet example, which also takes
`--passphrase-stdin`; PDF's `encrypt` takes both of its
passwords, a line each, with `--passwords-stdin`), and
`password-stdin` for the SSH examples `ssh_exec` and `ssh_serve`. From a terminal they prompt with echo off; from a pipe or
a file they take the first line, without its line ending. LUKS also
takes `--key-file -`, which reads all of standard input as the key,
line endings included.

```console
$ cargo run --release --example luks -- open disk.img --passphrase-stdin --volume-key
Passphrase:
$ printf '%s\n' "$PW" | cargo run --release --example age -- decrypt in.age out --passphrase-stdin
```

| Product | Example | What it does | Checked against |
|---|---|---|---|
| LUKS1, LUKS2 (Linux disk encryption) | `luks/` | `dump`, `open` (passphrase or key file to volume key, data decrypted), `format` (new image with data) | cryptsetup 2.8.8, both directions: 13 of its images opened by ours, data included; 7 of ours opened by it; 3 compatibility images and 12 kernel-written LUKS1 test volumes from cryptsetup's test suite, whose FAT serial DEAD-BABE ours decrypts |
| age (file encryption) | `age/` | `keygen` (X25519 and post-quantum), `encrypt` (recipients, passphrase, armor), `decrypt` | all 147 of the format's test vectors (C2SP CCTV); age 1.1.1 and 1.3.2 both directions, 116 of 116, the post-quantum `age1pq` recipients included |
| OpenPGP (GnuPG, RFC 9580, LibrePGP) | `openpgp/` | `encrypt` and `decrypt` with passphrases and with keys, `sign` and `verify` (inline, detached, text, cleartext), `gen-key`: SKESK v4, v5 and v6, PKESK v3 and v6; SED, SEIPD v1 and v2, and the OCB packet; keys of versions 4, 5 and 6 in RSA, DSA/ElGamal, ECDSA/ECDH on nine curves, EdDSA, X25519/X448 and Ed25519/Ed448; signatures of versions 3 to 6; every cipher, EAX, OCB and GCM, ZIP, ZLIB and BZip2; `list-keys`, `list-packets` | RFC 9580's appendix samples and LibrePGP's, intermediates included; GnuPG 2.4.4 and go-crypto both directions, 577 of 577 |
| TrueCrypt, VeraCrypt | `veracrypt/` | `open` (password, keyfiles, PIM, hidden volumes; master key, data decrypted), `format` (new XTS volume, VeraCrypt or TrueCrypt) | 104 volumes TrueCrypt 1.0 to 7.1 and VeraCrypt to 1.26 wrote (hidden volumes counted apart from their outer ones), from cryptsetup's test suite: every one opens, 93 decrypt to their filesystem, and 35 master keys equal cryptsetup's; 9 of ours opened by cryptsetup with the same master key |
| BitLocker (Windows full-volume encryption, version 2; BitLocker To Go) | `bitlocker/` | `dump` (metadata, protectors), `open` (password, recovery password, startup key file, clear key or volume key to volume key; the volume decrypted as a reader sees it), `format` (new volume with data, any method, password, recovery password and clear key protectors) | cryptsetup 2.8.8 and the 21 volumes Windows made in its test suite: every dump, every secret's volume key and 19 decrypted volumes' SHA-256 equal cryptsetup's, 2 unfinished volumes refused as cryptsetup refuses them; 13 of ours read by cryptsetup, the volume key equal: 115 of 115; 21 volumes replayed offline |
| Wi-Fi (WEP, WPA, WPA2; IEEE 802.11) | `wifi/` | `decrypt` a capture: WEP with a shared key, or WPA/WPA2 with the passphrase and ESSID, taking the pairwise key from the capture's 4-way handshake; a tally and, with `--out`, the decrypted frames as Ethernet | aircrack-ng's `airdecap-ng` 1.7 and its capture files (WEP, WPA-TKIP, WPA2-CCMP): the decrypted frames identical packet for packet and the counts equal, 5 of 5; 3 captures replayed offline |
| KeePass (KDBX 3.1, 4.0, 4.1) | `keepass/` | `dump` (groups, entries, attachments; `--canonical` for comparison), `create` (a sample database in any format): AES, Twofish and ChaCha20; AES-KDF, Argon2d and Argon2id; key files of every kind; protected values under Salsa20 and ChaCha20; gzip; the KDBX 4 HMAC block stream and the 3.1 hashed blocks and header hash | gokeepasslib (master, 4fa52e4) both directions, and the 25 test databases of gokeepasslib and pykeepass, which other KeePass applications wrote: 82 of 82 identical listings; 28 replayed offline |
| ZIP with a password (PKWARE ZipCrypto, WinZip AES AE-1/AE-2) | `zip/` | `list`, `extract` (stored, deflate, bzip2; ZIP64; refuses names that leave the destination), `create` (stored; none, ZipCrypto, AES-128/192/256, AE-1 or AE-2) | Info-ZIP 3.0/6.0, libarchive 3.8.1 and 7-Zip 26.03 writing, ours extracting; ours writing, 7-Zip, libarchive, Info-ZIP and Python's zipfile extracting: 119 of 119; 23 of their archives replayed offline |
| 7z (7-Zip) | `sevenzip/` | `list`, `extract` (LZMA, LZMA2, Deflate, BZip2, Copy; the BCJ, ARM, ARMT, ARM64, PPC, SPARC and Delta filters; 7zAES, the header encrypted or not; solid and not; refuses names that leave the destination), `create` (stored, one solid folder; 7zAES at 2^0 to 2^24 rounds or the raw key, header encryption) | 7-Zip 26.03 writing every method and filter, ours extracting; ours writing, 7-Zip and libarchive 3.8.1 extracting; liblzma's LZMA2 from XZ Utils 5.4.5: 211 of 211; 38 archives replayed offline |
| PDF (the standard security handler, revisions 2 to 6) | `pdf/` | `info`, `decrypt`, `encrypt` (40 and 128-bit RC4, AES-128, AES-256 at revisions 5 and 6): user and owner passwords, crypt filters, object and cross-reference streams | qpdf 11.9.0 and pdftk-java 3.3.3: 41 of qpdf's test files decrypted as qpdf decrypts them, files qpdf and pdftk encrypted decrypted, ours opened by both, and qpdf's test files re-encrypted under every scheme, 425 of 425; 72 documents replayed offline |
| Office documents (`.docx`, `.xlsx`, `.pptx`, `.doc`, `.xls`; [MS-OFFCRYPTO]) | `office/` | `info`, `decrypt`, `encrypt`: agile encryption (AES-128/192/256, SHA-1/256/384/512, the data-integrity HMAC) and standard encryption (AES-128/192/256), in a compound file the example reads and writes; `.doc` and `.xls` decrypted from RC4, RC4 CryptoAPI and (`.xls`) XOR obfuscation | Office's own documents, LibreOffice 24.2 and msoffcrypto-tool, both directions for OOXML: 134 of 134; 23 documents replayed offline |
| OpenDocument (`.odt`, `.ods`, `.odp`; ODF 1.2 part 3, LibreOffice's ODF 1.4 extension) | `odf/` | `info`, `decrypt`, `encrypt`: AES-256-CBC with PBKDF2 (ODF 1.2 on), Blowfish CFB (ODF 1.0 and 1.1), and AES-256-GCM over the whole package under Argon2id | LibreOffice 24.2 both directions, all three schemes, with a second decryption written from the manifest: 85 of 85; 6 documents replayed offline |
| Key stores (PKCS#12 `.p12`/`.pfx`, Java's JKS and JCEKS) | `keystore/` | `list` (`--canonical` for comparison), `convert` between the three: PKCS#12 with PBES2/PBKDF2 AES-256, PBE-SHA1-3DES and 40-bit RC2, MACs HMAC-SHA-1/256 and PBMAC1, plain and shrouded keys, certificates, CRLs and Java's secret keys; BER as NSS writes it; JKS's key protector and JCEKS's PBEWithMD5AndTripleDES, with a JCEKS secret key's Java serialization | OpenSSL 3.0 and 3.5 (command line and, for a NULL password, its API), python-cryptography, NSS's pk12util, keytool and Java's KeyStore API (JDK 21), both directions: 121 of 121; 27 stores replayed offline |
| JOSE (JWK, JWS, JWE: RFC 7515 to 7518, 7638, 7797, 8037, 8812) | `jose/` | `keygen`, `public`, `thumbprint`, `sign`, `verify`, `encrypt`, `decrypt`: every JWS algorithm of RFC 7518 with ES256K, EdDSA and the fully-specified `Ed25519` and `Ed448`, `none` on request; every JWE key management algorithm (RSA1_5, RSA-OAEP, RSA-OAEP-256, AES key wrap, AES-GCM key wrap, PBES2, `dir`, ECDH-ES and ECDH-ES with key wrap over P-256/384/521, X25519 and X448) with every content encryption; compact, general and flattened JSON, several signers and recipients, unencoded payloads, `zip`, AAD | jwcrypto 1.6.1 both directions, every algorithm and serialization, and PyJWT 2.12.1 for compact JWS: 802 of 802; the examples of RFC 7515, 7516, 7518, 7638, 7797 and 8037 read out of the documents; 137 jwcrypto outputs replayed offline |
| CMS and S/MIME (RFC 5652, RFC 8551; PKCS#7) | `cms/` | `sign`, `verify` (chain to given roots), `encrypt`, `decrypt`, `info`: SignedData with RSA PKCS#1 v1.5 and PSS, ECDSA, DSA, Ed25519 and Ed448, with or without signed attributes, attached or detached, by issuer and serial or key identifier, several signers; EnvelopedData to RSA (PKCS#1 v1.5, OAEP), EC (ECDH with every X9.63 KDF), password (PWRI) and shared-key recipients, with AES, 3DES, DES and RC2; AES-GCM AuthEnvelopedData; EncryptedData, DigestedData, CompressedData; BER, PEM and S/MIME in both forms | OpenSSL 3.0 and 3.5, python-cryptography 46 and NSS's cmsutil both directions: 552 of 552; RFC 4134's examples and RFC 3211's and RFC 3217's vectors read out of the documents; 121 messages replayed offline |
| Kerberos 5 (MIT keytabs and credential caches; RFC 3961, 3962, 4757, 6803, 8009) | `kerberos/` | `string2key`, `encrypt`, `decrypt`, `checksum`, `prf` for all twelve encryption types - single DES (CRC, MD4, MD5), Triple DES, AES with HMAC-SHA1 and with HMAC-SHA2, RC4-HMAC and its 40-bit export variant, Camellia - and every DES checksum; `keytab list`, `keytab add`; `ccache list`; `ticket` (every ticket in a cache opened with the service's keys, its session key checked against the cache's) | MIT Kerberos 1.21.3 and 1.17.2 (single DES) both directions through libk5crypto, `ktutil`, `klist` and a KDC on loopback for every type, credential caches of versions 3 and 4: 34,383 of 34,383; RFC 3961, 3962, 6803 and 8009's vectors read out of the documents; 342 answers, 2 keytabs and 6 caches replayed offline |
| Cryptocurrency wallets (BIP-32, -38, -39, -49, -84, -86; Ethereum keystores, ERC-55, EIP-191) | `wallet/` | `mnemonic` (BIP-39, NFKD-normalized), `derive` (BIP-32 in every version prefix: extended keys, WIF, P2PKH, P2SH-P2WPKH, P2WPKH, P2TR and Ethereum addresses), `address`, `check-address`, `sign-message`/`verify-message` (Bitcoin's, every BIP-137 header), `bip38` (encrypt, decrypt, intermediate codes, EC-multiply generation and confirmation codes), `eth` (address, keystore v3 under scrypt or PBKDF2, v1 and presale files, EIP-191 signing and recovery) | python-mnemonic (the BIP-39 reference) and pycoin, with OpenSSL 3.5's Keccak-256, both directions, signatures byte for byte, passphrases unnormalized in every word list: 2,081 of 2,081; BIP-32's, -38's, -49's, -84's, -86's and -350's vectors and ERC-55's read out of the documents; python-mnemonic's vectors, go-ethereum's keystore test files and Unicode 16.0's NormalizationTest.txt replayed offline |
| DNSSEC (RFC 4033 to 4035, NSEC3 RFC 5155) | `dnssec/` | `keygen` (BIND's `.key` and `.private` files), `ds`, `key-tag`, `sign` (RRSIGs, NSEC or NSEC3, KSK and ZSK roles, delegations and glue), `verify` (every signature, every algorithm present, the NSEC or NSEC3 chain, opt-out), `nsec3-hash`: algorithms 1, 3, 5, 6, 7, 8, 10, 12 (GOST R 34.10-2001), 13, 14, 15, 16, 17 (SM2) and 23 (GOST R 34.10-2012), DS digests 1 to 6 | dnspython 2.7.0 both directions for its eleven algorithms, keys, DS records, signed zones and NSEC3 chains: 1,679 of 1,679; the examples of RFC 4034, 4035, 4509, 5155, 5702, 5933, 6605, 8080, 9558 and 9563 read out of the documents, GOST R 34.10-2012's signature reproduced from the document's nonce; 11 dnspython-signed zones replayed offline |
| WireGuard (the whitepaper's protocol, as wireguard-go and the Linux module run it) | `wireguard/` | `genkey`, `pubkey`, `genpsk` (`wg`'s base64 keys), `initiate`, `respond`, `complete` (Noise_IKpsk2 over Curve25519, ChaCha20-Poly1305 and BLAKE2s, MAC1, TAI64N replay refusal), `seal`, `open` (transport messages, the kernel's padding, a 2,048-message replay window), `cookie-reply`, `cookie`, `check-mac2` (the cookie under XChaCha20-Poly1305 and MAC2); keys from `wg` configuration files | wireguard-go (golang.zx2c4.com/wireguard, its own handshake, cookie and transport code through `scripts/witness/wgwitness`) both directions: 368 of 368; 16 conversations replayed offline byte for byte |
| Signed git commits and tags (SSH and OpenPGP) | `gitsign/` | `sign`, `verify`, `payload` on the objects `git cat-file` prints (the `gpgsig` header, the tag's tail); `ssh-keygen -Y sign`, `verify`, `find-principals`, `check-novalidate` as git calls `gpg.ssh.program`, with allowed signers files (principal patterns, namespaces, validity dates at the commit's time) and revocation; `gpg -bsau` and `--verify` as git calls `gpg.program`, with its status lines | git 2.43 with OpenSSH 10.0's `ssh-keygen` and GnuPG 2.4.4, both directions: every SSH key type and six OpenPGP key algorithms, commits and tags, Ed25519 and RSA SSHSIG identical byte for byte, the allowed signers file's refusals in both programs: 147 of 147; 24 objects and an OpenSSH signature replayed offline |
| Smart cards and YubiKeys (PIV, OpenPGP card 3.4, YKOATH, YubiKey OTP challenge-response; PC/SC) | `smartcard/` | `readers`, `info`; `piv`: `generate` (RSA 1024-4096, P-256, P-384, Ed25519, X25519; a self-signed certificate the card signs), `import`, `sign`, `decrypt`, `ecdh`, `read-cert`, `write-cert`, `attest`, PIN, PUK and management key changes, `reset`; `openpgp`: `generate`, `import`, `export` (the public key as GnuPG reads it, self-signatures made by the card), `sign` (detached), PIN changes, `reset`; `oath`: TOTP and HOTP credentials, codes, the access password; `otp`: program an HMAC-SHA1 slot, challenge-response. Its own PC/SC binding, loaded at run time | a virtual card (CanoKey's PIV, OpenPGP and OATH, canokey-core e558d5c, with an emulated OTP application), over TCP and through pcsc-lite 2.3.0's `pcscd`; OpenSSL 3.0, python-cryptography 46, GnuPG 2.4.4 and yubikit 5.9 judging the results: 166 of 166; 86 conversations replayed offline byte for byte. **No physical card or YubiKey has run it** |
| Signal (libsignal, protocol version 3) | `signal/` | `demo` (two parties, pairwise and group messages), `agent` (the witness's line protocol): X3DH with and without a one-time prekey, the Double Ratchet with out-of-order and late messages, archived sessions, sender-key groups, XEdDSA-signed prekeys | libsignal-protocol-c 2.3.3: twelve conversations run four ways - libsignal on both sides, ours on both, and mixed - with every reply identical, 48 of 48; eleven of them replayed offline byte for byte |

## LUKS

`luks/main.rs`, with `luks/json.rs` for the LUKS2 header.

- **Headers**: LUKS1 (the 592 byte header, eight keyslots) and LUKS2
  (binary header and JSON, both copies, SHA-256 checksum; the secondary
  copy is used when the primary is damaged).
- **Key derivation**: PBKDF2 with SHA-1, SHA-256, SHA-512, RIPEMD-160
  and Whirlpool; Argon2i and Argon2id (LUKS2).
- **The anti-forensic splitter**, 4000 stripes (the library's
  `kdf::luks_af`).
- **Sector encryption**: any of the library's 128 bit block ciphers in
  XTS or LRW, and any block cipher in CBC or ECB; IVs `plain`,
  `plain64`, `plain64be`, `benbi`, `essiv:HASH` (with the kernel's
  `wp256` and `wp384`, which are Whirlpool cut short) and `null`; 512 to
  4096 byte sectors.

Checked (`scripts/check_luks.py`, cryptsetup 2.8.8 built from source,
no root):

- cryptsetup's `luksFormat` images - LUKS1 with XTS, CBC-ESSIV and
  `xts-plain` under four hashes; LUKS2 with Argon2id, Argon2i on two
  lanes, PBKDF2-SHA512 and CBC-ESSIV - opened by ours with the volume
  key `cryptsetup luksDump --dump-volume-key` prints.
- Data cryptsetup encrypted (`cryptsetup reencrypt --encrypt`, which
  runs in userspace) in 512 and 4096 byte sectors, XTS and CBC-ESSIV,
  LUKS2 and - through `cryptsetup convert` - LUKS1, decrypted by ours.
- Our images, LUKS1 and LUKS2 under the same spread of parameters,
  unlocked by cryptsetup with the same volume key, and refused by it
  with a wrong passphrase.
- cryptsetup's test suite's images: the compatibility images, and
  LUKS1 volumes written through the kernel's dm-crypt - AES, Serpent
  and Twofish in XTS, AES in LRW and in CBC-ESSIV, XTS with ESSIV over
  truncated Whirlpool - each holding a FAT filesystem whose serial is
  DEAD-BABE, which our decryption of the first data sector shows.

What cryptsetup could not judge here: ciphers other than AES on its
side (without root it checks a cipher by activating it), and data in
modes its userspace code lacks. Our Serpent, Twofish and Camellia
volumes are checked only by the kernel-written test images above, and
by round trip.

Not implemented: LUKS2 tokens (they hold no key material this library
could use without the token's own plugin), online reencryption state,
dm-integrity, and hardware OPAL segments.

## TrueCrypt and VeraCrypt

`veracrypt/main.rs`, with the library's CRC-32 for the header checksums
and the keyfile pool.

- **Key derivation**, tried in turn as VeraCrypt does: PBKDF2 with
  SHA-512, SHA-256, Whirlpool, BLAKE2s-256, RIPEMD-160 and Streebog at
  VeraCrypt's counts or a PIM's, TrueCrypt's counts (and SHA-1 for
  TrueCrypt 1.0 to 4.x), and Argon2id with VeraCrypt's PIM-dependent
  cost. Keyfiles through TrueCrypt's CRC-32 pool, 64 bytes or - for a
  VeraCrypt password over 64 - 128.
- **Ciphers**: AES, Serpent, Twofish, Camellia and Kuznyechik in XTS,
  and the ten cascades; LRW (TrueCrypt 4.1 to 4.3) with its cascades;
  CBC (TrueCrypt 1.0 to 4.0) with AES, Serpent, Twofish, CAST5, Triple
  DES and TrueCrypt's little-endian Blowfish, singly and in the "outer
  CBC" and per-cipher cascades.
- **Volumes**: normal, hidden (both the current layout and TrueCrypt's
  before 6.0), the backup header, and system encryption (the header at
  sector 62 of the drive, MBR or GPT, with its pre-boot key
  derivations).

Checked (`scripts/check_veracrypt.py`):

- cryptsetup's test suite's TrueCrypt and VeraCrypt volumes, made by
  those programs, each holding a FAT filesystem with serial DEAD-BABE
  (CAFE-BABE in a hidden volume): 104 volumes, hidden ones counted
  apart, from TrueCrypt 1.0 to VeraCrypt 1.26 - every hash, cipher,
  cascade and mode, keyfiles, a 72 character password, PIMs including
  Argon2id's, and three system-encrypted drives (MBR whole drive, MBR
  partition, GPT). Every one opens with the algorithm its name gives;
  93 decrypt to their filesystem; the other 11, the legacy cascades
  and Blowfish, give their header and master keys; and for the 35 in
  AES-XTS the master key equals `cryptsetup tcryptDump
  --dump-master-key`'s.
- Our volumes, VeraCrypt and TrueCrypt, under SHA-512, SHA-256,
  Whirlpool, BLAKE2s and RIPEMD-160, opened by cryptsetup with our
  master key, and our data decrypted by python-cryptography's AES-XTS
  under it.

Not checked here: our own Streebog and Argon2id volumes by another
program (cryptsetup 2.8.8 with OpenSSL 3.0 opens neither; the
VeraCrypt-made test volumes check our reading of both), and data in
the legacy cascades and TrueCrypt 1.0's Blowfish, which nothing here can
read either - their headers and master keys are read, their data is
refused rather than guessed.

## BitLocker

`bitlocker/main.rs` (the command line, the volume as a reader sees
it), `bitlocker/fve.rs` (the metadata and how each secret opens the
volume master key) and `bitlocker/write.rs` (`format`), with the
library's `block_ciphers::bitlocker` for the sectors,
`kdf::password::bitlocker_stretch` for passwords, AES-CCM for the
sealed keys and CRC-32 for the metadata's checksum.

- **Methods**: AES-CBC with the Elephant diffuser (Windows Vista and
  7), AES-CBC (8), AES-XTS (10 and 11), each at 128 and 256 bits;
  512- and 4096-byte sectors; BitLocker To Go on FAT.
- **Protectors**: a password and a recovery password (SHA-256 2^20
  times over the salt), a startup key file (`.BEK`, matched to its
  protector by GUID and to the volume by its GUID), and a clear key, as
  a suspended volume has. TPM and smart-card protectors are listed and
  not opened: their keys are not on the disk.
- **Metadata**: the first of the three copies whose signature,
  version, CRC-32 and own position check; the validation hash, sealed
  with the volume master key, must equal the block's SHA-256, so
  metadata changed after Windows wrote it is refused even when its
  CRC-32 was redone.
- **The volume** as dm-crypt presents it: the three metadata areas and
  the relocated volume header's area read as zeros, the first sectors
  decrypted from the relocated header at that header's own IV. Volumes
  still being encrypted, or encrypted on write, are dumped and opened
  but not decrypted, as cryptsetup refuses to activate them.
- **`format`** writes the layout the reader reads, with its metadata
  and relocated header in the volume's last 200 KiB. Only the datums
  this reader and cryptsetup use are written; nothing here has shown
  Windows accepting such a volume.

```console
$ cargo run --release --example bitlocker -- dump volume.img
$ cargo run --release --example bitlocker -- open volume.img --password-stdin --decrypt plain.img
$ cargo run --release --example bitlocker -- open volume.img --startup-key 4381F759-C4F8-4DE0-BB61-FC33A831BDA5.BEK
$ cargo run --release --example bitlocker -- format ours.img --size 104857600 --data fs.img --method aes-cbc-elephant-128 --password-stdin --new-recovery-password
$ cargo test --example bitlocker
$ python3 scripts/check_bitlocker.py --cryptsetup-tests ~/src/cryptsetup/tests
```

Checked (`scripts/check_bitlocker.py`, cryptsetup 2.8.8):

- The 21 volumes Windows made in cryptsetup's test suite: every
  method, 4096-byte sectors, To Go, two startup keys (each refused by
  the other volume), a clear key, two recovery passwords, a non-ASCII
  password, a smart-card volume opened by its recovery password, a
  volume still being encrypted and one encrypted on write. Ours dumps
  what `cryptsetup bitlkDump` dumps; each secret gives the volume key
  `--dump-volume-key` gives; the 19 complete volumes decrypt to the
  SHA-256 cryptsetup's `images.conf` gives for the device dm-crypt
  presents, and the other two are refused.
- Ours, every method at both sector sizes with a password and a
  recovery password protector, and one with a clear key alone:
  `bitlkDump` reads the same metadata and dumps our volume key with
  each secret, and refuses a wrong one. cryptsetup cannot decrypt data
  without device-mapper, so our data is read back by our reader, which
  is the one that matched Windows's.

Not implemented: BitLocker version 1 (Windows Vista before SP1), TPM
and smart-card protectors, and the volume key's backup copy.

## Wi-Fi

`wifi/main.rs`, with `wifi/pcap.rs` for the capture format, on the
library's `stream_ciphers::wep` and `tkip`, `mac::michael`,
`block_ciphers::ccm` and `kdf::ieee80211`. The 802.11 framing - the
header lengths, which address is the transmitter, where the sequence
counter and the CCMP nonce and additional data come from - is here.

- **WEP**: the 3-byte IV from the frame and the shared key, RC4, the
  CRC-32 ICV checked.
- **WPA/WPA2**: the pairwise key comes from the 4-way handshake in the
  capture - the two nonces and an EAPOL frame whose MIC (HMAC-MD5 for
  TKIP, HMAC-SHA1 for CCMP) verifies under a key stretched from the
  passphrase and ESSID by PBKDF2. TKIP then mixes a per-packet RC4 key
  and checks the ICV; CCMP is AES-CCM with the nonce and additional data
  built from the header. A frame retransmitted in the same direction is
  skipped, as `airdecap-ng` skips it.
- The decrypted frames are written as `airdecap-ng` writes them: each an
  Ethernet frame, the 802.11 and LLC/SNAP headers replaced by a 14-byte
  Ethernet header.

```console
$ cargo run --release --example wifi -- decrypt capture.cap --wep-key 1F:1F:1F:1F:1F
$ cargo run --release --example wifi -- decrypt capture.cap --essid linksys --password-stdin --out plain.pcap
$ cargo test --example wifi
$ python3 scripts/check_wifi.py --airdecap ~/src/aircrack-ng/airdecap-ng --captures ~/src/aircrack-ng/test
```

Checked (`scripts/check_wifi.py`, aircrack-ng's `airdecap-ng` 1.7): the
WEP, WPA-TKIP and WPA2-CCMP capture files in aircrack-ng's test suite.
For each, our decrypted records and `airdecap-ng`'s are identical packet
for packet (the pcap timestamps aside), and our count of decrypted
frames equals the number it reports. Michael is **computed and could be
verified** but, like `airdecap-ng`, the example does not drop a frame on
a Michael failure; the TKIP ICV is the per-frame check.

Not implemented: WPA3-SAE's dragonfly handshake (the example takes a
PMK or a PSK, so a WPA3 capture opens only with `--pmk`), management
frame protection, and cracking - the passphrase or key is an input, not
something this searches for.

## age

`age/main.rs`, with `shared/inflate.rs` for the test vectors that are
stored compressed.

- **Recipients**: X25519 (`age1...`), the post-quantum hybrid
  MLKEM768-X25519 (`age1pq1...`: X-Wing - ML-KEM-768 and X25519 with
  a SHA3-256 combiner - through RFC 9180 HPKE with HKDF-SHA256 and
  ChaCha20-Poly1305), and passphrases through scrypt. Unknown stanza
  types are passed over, as the format requires.
- **The header** parsed to the letter of the ABNF: canonical base64
  only, 64 column body lines ending in a shorter one, an scrypt stanza
  alone; and its HMAC-SHA-256.
- **The payload**: 64 KiB ChaCha20-Poly1305 chunks whose nonce counts
  them and marks the last, read the way age's own reader reads them -
  a full chunk is tried as ordinary and then as final - so that a
  damaged file releases exactly what age would before failing.
- **ASCII armor**, strict, with whitespace around it and CRLF line ends
  allowed. Bech32 keys of any length (a post-quantum recipient is
  nearly two thousand characters).

Checked:

- The format's test vectors - C2SP's CCTV suite, which age's authors
  generated from the reference implementation (vendored under
  `fixtures/age/testkit/`, 0BSD): all 147, each with the outcome its
  `expect` line names (success, or a failure of the armor, the header,
  the match, the MAC or the payload) and the plaintext released before
  any failure hashing to its `payload` line - the hybrid post-quantum
  vectors included. In `cargo test`.
- `scripts/check_age.py` against age 1.1.1 and age 1.3.2 (built from
  source with post-quantum support): files from 0 bytes to past three
  chunks, binary and armored, each age encrypting for ours and ours for
  each age, to recipients either generated, X25519 and `age1pq`; and
  passphrases both ways, typed into age's terminal prompt, and ours
  taking its passphrase from a pipe. 116 of 116.

Not implemented: the SSH recipient types (`ssh-ed25519`, `ssh-rsa`)
and the hardware-key tagged types (`p256tag`, `mlkem768p256tag`), and
age plugins.

## OpenPGP

`openpgp/`: `main.rs` (the command line and the tests), `armor.rs`,
`packet.rs` (framing), `s2k.rs`, `algo.rs` (the algorithm numbers, and
OpenPGP's CFB and AEAD calls) and `message.rs`; with `shared/inflate.rs`
and `shared/bunzip2.rs` for compressed data.

Messages under passphrases and to keys, signatures, and keys made
here.

- **Session keys**: SKESK version 4 (the S2K output as the session key,
  or a session key encrypted under it in CFB), version 5 (LibrePGP:
  AEAD under the S2K output) and version 6 (RFC 9580: AEAD under an
  HKDF of it); `--session-key` takes one outright, in the form `gpg
  --show-session-key` prints.
- **S2K**: simple, salted, iterated and salted (with every hash here:
  MD5, SHA-1, RIPEMD-160, SHA-2, SHA3-256 and SHA3-512; the library's
  `kdf::password::openpgp_s2k`), and Argon2id.
- **Containers**: Symmetrically Encrypted Data (tag 9: CFB with the
  resynchronisation, no integrity protection, read and written - the
  reader says so), SEIPD version 1 (CFB with the SHA-1 MDC), LibrePGP's
  OCB Encrypted Data packet (tag 20, EAX or OCB, the chunk index in the
  nonce and the associated data) and SEIPD version 2 (EAX, OCB or GCM
  under an HKDF of the session key and a salt).
- **Ciphers**: IDEA, Triple DES, CAST5, Blowfish, AES-128/192/256,
  Twofish and Camellia-128/192/256, the 64 bit ones in CFB only.
- **Keys**: public and secret key packets of versions 4, 6 and
  LibrePGP's 5 (and version 3 RSA public keys); fingerprints and key
  IDs of each; transferable keys with their user IDs, subkeys and
  signatures, armored or not. Secret parts unprotected, under CFB with
  the SHA-1 or the old checksum (and the pre-RFC 2440 cipher-number
  form with MD5), or under AEAD - in RFC 9580's form and in LibrePGP's,
  which differ - and checked against the public part once unlocked.
- **Public key encryption**: PKESK version 3 and 6 to RSA, ElGamal,
  ECDH (NIST P-256/384/521, Brainpool P-256/384/512, secp256k1,
  Curve25519, and LibrePGP's X448), X25519 and X448. The Brainpool
  curves are not in the library: the example registers them at run
  time, their parameters read out of RFC 5639 (vendored).
- **Signatures**: versions 3, 4, 6 and LibrePGP's 5 (whose document
  signatures also hash the literal packet's metadata, and a cleartext
  signature `t` and five zeros), by RSA, DSA, ElGamal, ECDSA, EdDSA
  (Ed25519 and GnuPG's Ed448), Ed25519 and Ed448; binary and text
  documents, inline (one-pass, literal, signature), detached and in the
  cleartext framework with its dash-escaping; signed-then-encrypted
  messages. `sign` writes the key's own version.
- **Which keys may be used**: a subkey counts only with a binding
  signature from the primary key that verifies, a signing subkey only
  with the primary key binding signature it embeds, and each only with
  the key flags, expiry and revocations those signatures carry. The key
  `encrypt --recipient` picks and the keys `verify` accepts are both
  decided that way; `list-keys` shows the flags and why a key is not
  usable.
- **Key generation** (`gen-key`): version 4 keys in RSA, DSA with
  ElGamal (an RFC 3526 group rather than a fresh prime), ECDSA with
  ECDH on the NIST, Brainpool and secp256k1 curves, GnuPG's EdDSA with
  Curve25519, and RFC 9580's Ed25519/X25519 and Ed448/X448; version 6
  keys in all but DSA, secp256k1 and the legacy 25519 pair, which RFC
  9580 does not allow there. A primary key that certifies and signs,
  a user ID with its positive certification (and for version 6 a
  direct key signature) carrying the preferences, and an encryption
  subkey with its binding; an optional expiry. Secret parts under CFB
  with SHA-1 and an iterated S2K for version 4 (what GnuPG reads), and
  AEAD (OCB) with Argon2 for version 6.
- **Packets**: both header formats, all four length encodings including
  partial body lengths, marker and padding packets; ZIP, ZLIB and BZip2
  decompression (and ZIP and ZLIB written as stored blocks); literal
  data; ASCII armor with its CRC-24.

Checked:

- RFC 9580's appendix A.9 to A.12, parsed out of the vendored document:
  the EAX, OCB and GCM messages with every intermediate it prints (the
  S2K output, the HKDF input and output, the session key, the message
  key and IV), and the three Argon2 messages with the session keys
  their armor comments state. LibrePGP's A.3, its OCB sample, the same
  way. In `cargo test`, the costly derivations in release builds.
- Fifteen messages GnuPG 2.4.4 wrote (`fixtures/openpgp/`): IDEA, CAST5,
  Twofish, Camellia, BZip2 and ZLIB, simple and RIPEMD-160 S2K, the
  unprotected tag 9, OCB packets in 64 byte chunks, partial body
  lengths, armor - each opened by its passphrase and by the session key
  GnuPG printed. In `cargo test`.
- `scripts/check_openpgp.py`, 577 of 577 in all: GnuPG encrypting under every
  cipher, compression, S2K mode and hash and in all three of its
  containers, from files and pipes, and ours decrypting by passphrase
  and by session key; ours encrypting in its `v4`, `no-mdc` and
  `librepgp` formats under every cipher, EAX and OCB, and GnuPG
  decrypting; and go-crypto both ways for SKESK v6 and SEIPD v2 under
  OCB, EAX and GCM at three key sizes, and Argon2 in v4 and v6.

- Keys: RFC 9580's A.1 (a version 4 EdDSA key's fingerprint), A.3 to
  A.5 (the version 6 certificate and secret key, unlocked and locked
  with AEAD and Argon2, with A.5.1's and A.5.2's S2K output, HKDF key
  and associated data) and A.8 (a message to the X25519 subkey, with
  the X25519 values it prints); the curve OIDs against RFC 9580's table
  19 and LibrePGP's table 7. In `cargo test`.
- Fourteen keys GnuPG made and exported (`fixtures/openpgp/keys/`), each
  with a message GnuPG encrypted to it: our fingerprints are GnuPG's
  and the messages open. In `cargo test`.
- `scripts/check_openpgp.py`'s key rows: GnuPG's fourteen kinds of key
  both ways, in its OCB packet and SEIPD v1, and our `v4` and
  `librepgp`; go-crypto's version 4 and 6 keys (RSA, Ed25519/X25519,
  Ed448/X448, EdDSA with Curve25519, the NIST curves, Brainpool P-256)
  both ways, its v6 PKESK with SEIPD v2 included.

- Signatures: RFC 9580's A.2 (a version 4 EdDSA signature, with the
  hash input and digest it prints), A.3.1 (the data the version 6
  self-signatures cover, hashed to their digests), A.6 and A.7 (a
  version 6 text signature as cleartext and inline); GnuPG's inline,
  detached, text-mode and cleartext signatures with each of its fourteen
  keys (`fixtures/openpgp/keys/`). In `cargo test`.
- `scripts/check_openpgp.py`'s signature rows: GnuPG and go-crypto
  signing in each mode and ours verifying, ours signing and each of them
  verifying, and signed-and-encrypted messages both ways, with every key
  above.

- Keys made here: in `cargo test`, every algorithm quick to generate
  unoptimised (RSA and DSA in release builds), read back, checked
  usable with the flags given and expiring when they should, and used
  to sign and to encrypt. In `scripts/check_openpgp.py`, imported by
  GnuPG (eleven kinds) and read by go-crypto (ten, version 6 among
  them, our AEAD- and Argon2-protected secret keys included), each
  encrypted to and signed with both ways.

What GnuPG 2.4 cannot read, and so only go-crypto and the RFC check:
SKESK v6 and SEIPD v2, Argon2, GCM, and the algorithms RFC 9580 added
(X25519, X448, Ed25519, Ed448) and version 6 keys and signatures.
go-crypto does not read SKESK v5 or GnuPG's version 5 keys, which GnuPG
checks.

## Smart cards and YubiKeys

`smartcard/card.rs` (ISO 7816-4: APDUs, chaining, `61xx` and `6Cxx`,
the transports), `pcsc.rs` (the system's PC/SC library loaded at run
time - `winscard.dll`, the macOS framework, `libpcsclite.so.1` - and
the example's only `unsafe`), `tlv.rs` (BER-TLV), and one file per
application: `piv.rs`, `openpgp.rs`, `oath.rs`, `otp.rs`. The card
holds the keys; hashing, padding, certificates, OpenPGP packets and the
check of every signature the card returns are the library's.

- **PIV** (NIST SP 800-73-4, with YubiKey's extensions): the management
  key's mutual authentication in 3DES or AES, key generation and import
  with PIN and touch policies, signatures (PKCS#1 v1.5 blocks built here,
  ECDSA over the digest cut to the group's width, Ed25519 over the
  message), RSA decryption, ECDH and X25519, certificate objects
  (compressed ones too), attestation checked against the card's F9
  certificate. A self-signed certificate is built by `x509::builder` and
  signed by the card through `SigningKey::External`. A slot's key type
  comes from the card's metadata or, on a card without it, from the
  slot's certificate; a certificate for another key is refused.
- **OpenPGP card**: algorithm attributes, generation and import (RSA
  with CRT, NIST and secp256k1 curves, Ed25519, X25519), the fingerprint
  and creation time written back so the card describes the key `export`
  then writes as version 4 packets, signed by the card.
- **OATH** (YKOATH): credentials named as yubikit names them, codes for
  one or all, a period other than 30 seconds asked for separately (the
  card computes "all" at 30), the access password by PBKDF2-SHA1 and a
  mutual HMAC challenge. A TOTP credential is checked as it is stored:
  the card's code against RFC 6238 computed here.
- **YubiKey OTP**: the 52-byte HMAC-SHA1 configuration with its CRC,
  challenges padded as the key expects.

```console
$ cargo run --release --example smartcard -- readers
$ cargo run --release --example smartcard -- info
$ cargo run --release --example smartcard -- piv generate 9a p256 --self-sign "me" --pin -
$ cargo run --release --example smartcard -- openpgp export --user-id "Me <me@example.org>" --pin - --out me.asc
$ cargo run --release --example smartcard -- oath code
$ cargo test --example smartcard
$ python3 scripts/check_smartcard.py --pcsc /opt/pcsclite
```

Checked (`scripts/check_smartcard.py`, against the virtual card in
`scripts/witness/cardsim.py`):

- PIV: certificates for P-256, P-384, RSA-2048 and Ed25519 keys signed by
  the card and verified by OpenSSL with the validity asked for;
  signatures under four hashes verified by python-cryptography; RSA
  decryption of what python-cryptography encrypted; P-384 ECDH and X25519
  against python-cryptography; keys OpenSSL wrote, imported, signing (or,
  for X25519, agreeing) as their files' keys; PINs counted down, changed, blocked and unblocked;
  yubikit reading the certificate and accepting the PIN and the AES-192
  management key the example set.
- OpenPGP: two sets of three keys, generated and imported (the second's
  decryption key an X25519 key OpenSSL wrote), exported and
  imported by GnuPG, which checks every self-signature and computes the
  fingerprints the card holds; detached signatures GnuPG verifies;
  yubikit's parser reading the fingerprints and creation times the
  example registered.
- OATH: SHA-1, SHA-256 and SHA-512 codes against RFC 6238 computed in
  the script, at 30 and 60 seconds; HOTP in order; the password set by
  the example unlocked by yubikit, which lists the same credentials.
- OTP: responses against HMAC-SHA1 computed in the script, and the
  configuration and challenge commands the same as yubikit's, data field
  for data field.
- With `--pcsc`, the same card behind `pcscd` and
  `scripts/witness/ifd-tcpcard`: listed, read and signing through the
  example's PC/SC binding. GnuPG decrypting with the card's key through
  the same reader runs where the machine has `scdaemon`; this one did
  not. 166 of 166.
- `cargo test` replays the 86 conversations (`fixtures/smartcard.vec`),
  the host's challenges from a recorded seed, so every command must be
  the one sent before; parses RFC 4226's and RFC 6238's tables out of the
  documents; and checks the chaining, continuation and CRC rules alone.

What the virtual card does not settle. CanoKey reports version 0.0.0
and lacks the OTP application, attestation and RSA-3072 metadata; it
counts HOTP before computing (its first code is RFC 4226's count 1, a
YubiKey's count 0) and answers a wrong OpenPGP PIN with `69 82`. The OTP
application is emulated from yubikit's reading, so the OTP rows check
that the example and yubikit agree, not that a YubiKey does. Nothing here
has run against a physical card or YubiKey, nor been built for Windows
or macOS, whose PC/SC types `pcsc.rs` declares separately.

## Signal

`signal/main.rs`, with `session.rs` (X3DH and the Double Ratchet),
`group.rs` (sender keys), `wire.rs` (keys and the four message
formats), `proto.rs` (the protobuf subset they use) and `agent.rs` (the
line protocol).

- **X3DH**: bundles with an XEdDSA-signed prekey and an optional
  one-time prekey; three or four X25519 agreements behind the 32 `FF`
  bytes, HKDF-SHA256 with `WhisperText`.
- **The Double Ratchet**: root steps with `WhisperRatchet`, chain steps
  by HMAC with `01` and `02`, message keys by HKDF with
  `WhisperMessageKeys` into AES-256-CBC, HMAC-SHA256 and an IV; up to
  2000 skipped message keys per chain, five receiving chains, forty
  archived sessions, as libsignal keeps them.
- **Messages**: `SignalMessage` with its eight-byte MAC over both
  identities, `PreKeySignalMessage` until the peer answers,
  `SenderKeyMessage` signed with XEdDSA, and
  `SenderKeyDistributionMessage`.
- **Groups**: one sender key per (group, sender), a chain with no DH
  ratchet, `WhisperGroup` keys, and several keys per sender so that a
  re-announced one leaves the old one usable.

```console
$ cargo run --release --example signal -- demo
$ cargo test --example signal
$ python3 scripts/check_signal.py
```

Checked (`scripts/check_signal.py`, against libsignal-protocol-c 2.3.3
built from source, `scripts/witness/signalwitness`):

- Both implementations take their randomness from a stream named by a
  seed, so a conversation - a script of commands to each party - is
  deterministic. Each of twelve is run with libsignal on both sides,
  ours on both, and each mixed pairing, and every reply must be the same
  in all four: 2,474 replies per pairing, bundles, signatures,
  ciphertexts, plaintexts and error codes. That shows more than
  interoperating does: ours draws the same random bytes in the same
  order and writes every field the same way.
- The conversations: X3DH with and without a one-time prekey; messages
  out of order across ratchet steps, duplicates, and late messages on
  each of seven old chains (libsignal keeps five); a long run of
  turns; both parties starting a session at once; sessions replaced
  while messages on the old ones are in flight; groups, with a sender
  key announced twice; a changed identity, a reused one-time prekey, a
  bad prekey signature, an unknown prekey id, and every malformed
  version, protobuf and MAC; a seeded random walk; and 2001 messages
  ahead, to reach the skipped-key limit.
- `cargo test` replays eleven of the twelve from libsignal's own
  transcripts, `fixtures/signal.vec` (`--record` writes it), with this
  implementation on both sides: 463 replies, byte for byte.
- XEdDSA itself is the library's `ec::xeddsa`, checked separately
  against libsignal's signers and verifiers (`vectors/xeddsa.vec`) and
  against OpenSSL's Ed25519 verifier.

Not here: the Sealed Sender envelope, PQXDH's ML-KEM prekey
(libsignal-protocol-c predates it), and the Signal service's own
framing. The
witness is the C library, which Signal's apps have replaced with a Rust
one; the wire format and the derivations are the same.

## KeePass

`keepass/main.rs`, with `kdbx.rs` (the container: header, key
derivation, encryption, block streams, compression, inner header),
`database.rs` (the XML: groups, entries, protected values,
attachments) and `xml.rs` (the XML reader and writer).

- **Formats**: KDBX 3.1 (KeePass before 2.35) and KDBX 4.0 and 4.1, read
  and written.
- **Ciphers**: AES-256-CBC, Twofish-CBC and ChaCha20.
- **Key derivation**: AES-KDF (in both formats; the library's
  `kdf::password::keepass_aes_kdf`), Argon2d and Argon2id
  with their salt, memory, iterations, lanes, secret and associated
  data; Argon2 version 1.3 only.
- **Keys**: a password, a key file, or both. Key files of every kind
  KeePass reads: XML version 1.0 (base64) and 2.0 (hex with a check
  hash), 32 raw bytes, 64 hex digits, and anything else hashed.
- **Integrity**: KDBX 4's header SHA-256 and HMAC and its HMAC-SHA256
  block stream; KDBX 3.1's stream start bytes, SHA-256 block stream and
  `Meta/HeaderHash`.
- **Protected values**: decrypted in document order with the inner
  stream, Salsa20 (3.1) or ChaCha20 (4.x).
- **Attachments**: in the KDBX 4 inner header, or in KDBX 3.1's
  `Meta/Binaries`, gzipped or not, protected or not.

```console
$ cargo run --release --example keepass -- dump Passwords.kdbx --password-stdin
$ cargo run --release --example keepass -- create new.kdbx --password-stdin --format 41 --kdf argon2id
$ cargo test --example keepass
$ python3 scripts/check_keepass.py --gokeepasslib-tests ~/src/gokeepasslib/tests \
      --pykeepass-tests ~/src/pykeepass/tests
```

`create` writes gzip with stored blocks: a valid gzip stream every
reader takes, without a compressor.

Checked (`scripts/check_keepass.py`, against gokeepasslib built from
source, `scripts/witness/kdbxwitness`; both sides print a database in
one canonical listing, every field and attachment as hex, and the
listings must be identical):

- The 25 test databases of gokeepasslib and pykeepass, written by
  other KeePass applications (kdbxweb, by gokeepasslib's account, for
  three of them): every format, all three ciphers, AES-KDF
  and Argon2d, uncompressed, key files of each kind, a blank password,
  history entries and protected attachments. gokeepasslib cannot open
  two of them - the Argon2id one, and one with an empty attachment - and
  ours opens them, the HMACs and the header
  hash checking.
- gokeepasslib writes every format, cipher and key derivation it has,
  under a password and each kind of key file, and ours lists them; ours
  writes the same set plus Argon2id, and gokeepasslib lists all but the
  Argon2id ones. Wrong passwords are refused by both. 82 of 82.
- `cargo test` lists 28 of those databases - gokeepasslib's test files
  and databases gokeepasslib wrote - and compares each with
  gokeepasslib's listing (`fixtures/keepass.vec`).

Not here: KeePass 1.x `.kdb` files, KDBX 3.1's ArcFour inner stream
(KeePass 2.0's), Argon2 version 1.0, YubiKey challenge-response, and
custom icons, auto-type and the other fields that do not hold secrets.

## ZIP

`zip/main.rs` (the archive: central directory, ZIP64, local headers,
reading and writing) with `zip/crypto.rs` (the two encryptions).

- **Traditional PKWARE encryption** ("ZipCrypto"): the library's
  `stream_ciphers::zipcrypto`, with ZIP's 12-byte header and its check
  byte - the CRC's top byte, or the time's when the CRC follows in a
  data descriptor.
- **WinZip AES**, AE-1 and AE-2: PBKDF2-HMAC-SHA1 with 1000 iterations,
  AES-128/192/256 in counter mode with a little-endian counter from 1
  (the library's `ctr-le`),
  the two-byte password verifier and the 10-byte HMAC-SHA1 code.
- **Archives**: stored, deflate and bzip2 entries; data descriptors;
  ZIP64 sizes and offsets; UTF-8 names. Writing stores entries
  uncompressed.

```console
$ cargo run --release --example zip -- create out.zip a.txt b.txt --encryption aes256 --password-stdin
$ cargo run --release --example zip -- extract out.zip dir --password-stdin
$ cargo test --example zip
$ python3 scripts/check_zip.py
```

Checked (`scripts/check_zip.py`, every file compared byte for byte):

- Info-ZIP's `zip` (ZipCrypto; stored and deflated; to a file, to a pipe
  - data descriptors - and with ZIP64 forced), libarchive's `bsdtar`
  (ZipCrypto, AES-128 and AES-256; stored and deflated) and 7-Zip's
  `7zz` (ZipCrypto and AES-128/192/256; stored, deflate and bzip2)
  write; ours extracts, and refuses a wrong password.
- Ours writes each encryption - none, ZipCrypto, AES-128/192/256 as
  AE-1 and AE-2 - and 7-Zip and libarchive extract all of them
  (libarchive reads AES-192, though it does not write it), Info-ZIP's `unzip` and Python's
  `zipfile` the ZipCrypto and plain ones; 7-Zip refuses a wrong
  password. 119 of 119.
- `cargo test` extracts 23 of the witnesses' archives
  (`fixtures/zip/`) and compares every file's SHA-256.

Not here: PKWARE's strong encryption (SES, flag bit 6, written only by
SecureZIP), compressing on write, and split archives.

## 7z

`sevenzip/main.rs` (the command line), `sevenzip/archive.rs` (the
container: signature header, property-tagged header, folders, substreams,
files; reading and writing), `sevenzip/coders.rs` (the methods and
7zAES) and `sevenzip/lzma.rs` (LZMA and LZMA2 decoding), with the shared
inflate, bunzip2 and CRC-32.

- **7zAES**: AES-256-CBC under SHA-256 over 2^n copies of salt, UTF-16LE
  password and a 64-bit round counter - n is 19 in what 7-Zip writes,
  and 0x3F means no hashing at all, the salt and password copied into
  the key and cut at 32 bytes (the library's
  `kdf::password::sevenzip_aes_key`). There is no MAC: a wrong password shows
  as a decompression error or a CRC that does not match. The 32 most
  recently derived keys are kept, as 7-Zip keeps them, because an
  archive stored with Copy has a folder per file under one key.
- **Methods**: LZMA (any lc, lp, pb, with or without an end marker),
  LZMA2 (stored and LZMA chunks, dictionary and state resets), Deflate,
  BZip2, Copy; the branch filters x86 (BCJ), ARM, ARM Thumb, ARM64,
  PowerPC and SPARC, and Delta; coders chained through the folder's
  binds. PPMd, BCJ2 (four inputs) and IA64 are refused by name.
- **Archives**: a packed and possibly encrypted header (EncodedHeader),
  several folders or one solid one, empty files, empty directories,
  anti-items, CRCs per file and per folder. Writing stores the files in
  one solid folder, under 7zAES when there is a password, and can
  encrypt the header so that the names need the password too.

```console
$ cargo run --release --example sevenzip -- create out.7z dir a.txt --password-stdin --encrypt-header
$ cargo run --release --example sevenzip -- list out.7z --password-stdin
$ cargo run --release --example sevenzip -- extract out.7z target --password-stdin
$ cargo test --example sevenzip
$ python3 scripts/check_sevenzip.py
```

Checked (`scripts/check_sevenzip.py`, every file and the empty
directory compared byte for byte):

- 7-Zip writes Copy; LZMA at five lc/lp/pb settings, a 4 KiB
  dictionary and with an end marker; LZMA2 at three settings,
  multi-threaded, in 4 KiB blocks (a dictionary reset every few chunks)
  and at `-mx=9`; Deflate; BZip2; each branch filter over synthetic code
  in which it converts several hundred bytes - checked separately, since
  a filter that converts nothing round-trips whatever the decoder does -
  and Delta at three distances; non-solid and solid by extension; the
  header uncompressed; creation and access times; 7zAES over Copy,
  LZMA2 and BCJ+Deflate, with and without the header encrypted. The
  password is not ASCII. Ours extracts everything, refuses a wrong
  password and no password, and refuses PPMd and BCJ2 by name.
- XZ Utils' `xz --format=raw` writes LZMA2, which the script puts in a
  7z container by hand and 7-Zip reads: liblzma resets the LZMA state
  after a stored chunk (control 0xA0), which 7-Zip's encoder never
  does, and a second stream opens with a stored chunk that resets the
  dictionary.
- Ours writes stored and under 7zAES at 2^19, 2^0 and 2^1 rounds, with
  the raw key, and with the header encrypted; 7-Zip extracts and tests
  all of them and libarchive's `bsdtar` the unencrypted one; 7-Zip
  refuses a wrong password, and lists the names without one only when
  the header is not encrypted. 211 of 211.
- `cargo test` extracts 38 of the archives (`fixtures/sevenzip/`) and
  compares every file's SHA-256, and edits the recorded LZMA and LZMA2
  streams into the malformed ones a decoder has to refuse: a distance
  past the dictionary or past a reset, a chunk longer than its data, a
  chunk without the resets it needs, an early end marker, a match past
  the declared size.

Not here: compressing on write, PPMd, BCJ2, multi-volume archives, and
the 7z "additional streams" that nothing writes.

## PDF

`pdf/main.rs` (the command line, and a document decrypted or encrypted
whole), `pdf/security.rs` (the standard security handler),
`pdf/file.rs` (cross-reference tables and streams, object streams, the
writer) and `pdf/object.rs` (the object syntax).

- **Revisions 2 to 4**: the password padded with the standard's 32
  bytes, the file key from MD5 of it with `/O`, `/P` and the first
  `/ID` (fifty more MD5 rounds from revision 3), `/U` checked against
  it, and the owner password recovered through `/O`; each object
  encrypted under `MD5(key, object number, generation)` with RC4, or
  with AES-128 in CBC (`sAlT` appended) through revision 4's crypt
  filters.
- **Revisions 5 and 6**: AES-256 with the file key wrapped in `/UE` and
  `/OE`, the password hashed with SHA-256 (5, withdrawn) or ISO
  32000-2's Algorithm 2.B (6), and `/Perms` checked against `/P` - a
  mismatch is reported, as qpdf reports it, not refused.
- **What is not encrypted**: the `/Encrypt` dictionary, cross-reference
  streams, a signature's `/Contents`, metadata streams under
  `/EncryptMetadata false`, objects inside object streams (the stream is
  encrypted whole), and anything a stream's own `/Crypt` filter or
  `/EFF` names as Identity.
- **Which password**: the owner password is tried first, as ISO 32000-2
  and qpdf do, so a password that is both is reported as the owner's.

```console
$ cargo run --release --example pdf -- info in.pdf --password-stdin
$ cargo run --release --example pdf -- decrypt in.pdf plain.pdf --password-stdin
$ cargo run --release --example pdf -- encrypt plain.pdf out.pdf --passwords-stdin --scheme aes-256
$ cargo test --example pdf
$ python3 scripts/check_pdf.py --qpdf-tests ~/src/qpdf/qpdf/qtest/qpdf
```

Both commands write a classic cross-reference table, with objects that
were in object streams written on their own and their numbers kept.

Checked (`scripts/check_pdf.py`, qpdf's `--json=2` listing of every
object as the judge):

- 41 of qpdf's test files - Acrobat XI's revision 6, revisions 2 and 3
  with every combination of empty, equal and different passwords,
  revision 4 with RC4 and AES and cleartext metadata, crypt filters
  named per stream, encrypted attachments with `/StmF` Identity, a
  signed document, a 40-bit key at revision 3, a `/Length` that is not
  a whole number of bytes, short `/O` and `/U`, a positive `/P`, junk
  before the header, passwords longer than each revision reads -
  decrypted by ours with every password they have, listing exactly as
  qpdf lists them and passing `qpdf --check`.
- qpdf (revisions 2 to 6, with and without object streams, cleartext
  metadata) and pdftk (40 and 128-bit RC4, AES-128) encrypt a document
  the script writes; ours decrypts it.
- Ours encrypts that document under all six schemes, and re-encrypts
  each of qpdf's test files; qpdf opens every one with either password
  and lists it as the original, and pdftk opens those up to revision 4
  (it reads no further). 425 of 425.
- `cargo test` decrypts 72 of those documents (`fixtures/pdf/`) with
  each of their passwords and compares every string and the SHA-256 of
  every stream with what qpdf decrypted.

Not here: public-key security handlers (`/Adobe.PubSec`), SASLprep of
revision 6 passwords (a password it would change does not open a file
whose writer applied it), incremental updates on write, and repairing a
damaged cross-reference table.

## Office

`office/main.rs` (the command line), `office/ooxml.rs` (the two OOXML
encryptions and the data spaces around them), `office/binary.rs` (the
`.doc` and `.xls` schemes) and `office/cfb.rs` (the compound file, read
and written).

- **Agile encryption** (Office 2010 on): a random key stored under a key
  from the password - the salt and password hashed, then hashed again
  with a counter 100,000 times - with a verifier that checks the
  password; the package in 4096-byte segments, each in AES-CBC under
  the hash of the salt and the segment number; and an HMAC over the
  encrypted stream, its key and value encrypted, that is checked on
  every decryption.
- **Standard encryption** (Office 2007, LibreOffice): AES in ECB over
  the whole package under a key from SHA-1 iterated 50,000 times and
  CryptoAPI's key derivation, with a verifier and nothing to
  authenticate the package.
- **The binary formats**, decrypted: Office 97's RC4 (an MD5 chain with
  40 bits of entropy, LibreOffice still writes it), RC4 CryptoAPI
  (SHA-1, 40 to 128-bit keys) and, for `.xls`, XOR obfuscation (the
  library's `stream_ciphers::office_xor`) - a key
  every 512 bytes of a Word stream and every 1024 of a workbook, with
  the FIB's first 68 bytes and every workbook record header in the
  clear. The output is the same compound file with its streams
  decrypted and the encryption marked off: the FIB's flags cleared, the
  workbook's FilePass record turned to zeros in place so that no
  stream position moves.
- **Compound files**: versions 3 and 4, the DIFAT past the header, the
  mini stream, and every chain bounded; written as version 3 with the
  directory as balanced red-black trees, and with the
  `\x06DataSpaces` storage the specification requires, byte for byte
  the one Office writes.

```console
$ cargo run --release --example office -- info secret.docx --password-stdin
$ cargo run --release --example office -- decrypt secret.docx plain.docx --password-stdin
$ cargo run --release --example office -- encrypt plain.xlsx secret.xlsx --password-stdin
$ cargo test --example office
$ python3 scripts/check_office.py --msoffcrypto ~/src/msoffcrypto-tool --olefile ~/src/olefile
```

Checked (`scripts/check_office.py`, LibreOffice driven through UNO):

- msoffcrypto-tool's test documents, which Office wrote - agile AES-256
  with SHA-512 and standard AES-128 - decrypt to exactly the packages
  its tests expect; LibreOffice's encrypted `.docx`, `.xlsx` and
  `.pptx` (standard AES-128) and msoffcrypto-tool's (agile) decrypt to
  the bytes msoffcrypto-tool finds.
- Ours encrypts each of those three documents under agile AES-128, 192
  and 256 with SHA-1, 256, 384 and 512, and under standard AES-128,
  192 and 256. LibreOffice 24.2 opens with the password, finds the
  content and refuses a wrong password, for every combination it reads
  (agile AES-128 with SHA-1 or SHA-384, AES-256 with SHA-512; standard
  AES-128); msoffcrypto-tool decrypts the rest it can byte for byte.
- An agile package with one bit changed is refused for its HMAC.
- Office's `.doc` and `.xls` under RC4 CryptoAPI and its `.xls` under
  XOR obfuscation, and LibreOffice's `.doc` (with and without a picture
  in its Data stream) and `.xls` under RC4, decrypt stream for stream
  as msoffcrypto-tool decrypts them, and LibreOffice reads ours with no
  password as it reads the original with one. 134 of 134 in all.
- `cargo test` decrypts 23 of those documents (`fixtures/office/`) and
  compares each package's SHA-256, or each stream's.

No witness here reads agile AES-192, or AES-256 under SHA-1: those keys
are longer than the hash, padded with 0x36 as the specification says,
which only a unit test checks. msoffcrypto-tool reads neither, and
LibreOffice 24.2 refuses both.

No witness here wrote a 40-bit CryptoAPI key; its eleven zero bytes of
padding are checked only by a unit test.

Not here: extensible encryption (a third-party provider), keys
encrypted to a certificate rather than a password (read past, not
used), ciphers other than AES in agile encryption, encrypting `.doc`
and `.xls` (the encryption header has to be made room for, which moves
every offset the file records), XOR-obfuscated Word documents, and
PowerPoint 97-2003 presentations, whose persist objects are each
encrypted under their own identifier.

## OpenDocument

`odf/main.rs` (the command line) and `odf/package.rs` (the manifest and
the three schemes), with `shared/ziparchive.rs` (the ZIP container,
read and written; it encrypts nothing).

- **Per file** (ODF 1.0 to 1.3): each file is deflated, then encrypted
  on its own with its own salt and IV, under a key from PBKDF2-HMAC-SHA1
  over the hash of the password - SHA-1 and Blowfish in 64-bit CFB for
  ODF 1.0 and 1.1, SHA-256 and AES-256-CBC with W3C padding from 1.2.
  The manifest carries, for each file, a hash of its first kilobyte of
  deflated data, which is all that checks the password.
- **Whole package** (LibreOffice's ODF 1.4 extension, written in its
  experimental mode): the complete plain package, deflated, as one
  file `encrypted-package` under AES-256-GCM, its key from Argon2id
  over the SHA-256 of the password; the IV is in the manifest and again
  in front of the ciphertext, and the two must agree.
- `decrypt` stores each decrypted file still deflated, as it was before
  encryption, and removes the encryption data from the manifest; a
  whole-package file gives back the package inside it.

```console
$ cargo run --release --example odf -- info secret.odt
$ cargo run --release --example odf -- decrypt secret.odt plain.odt --password-stdin
$ cargo run --release --example odf -- encrypt plain.ods secret.ods --password-stdin --scheme gcm
$ cargo test --example odf
$ python3 scripts/check_odf.py
```

Checked (`scripts/check_odf.py`, LibreOffice through UNO, configured in
a profile of its own to write each scheme):

- LibreOffice encrypts a text document (and one with a picture), a
  spreadsheet and a presentation under each of the three schemes; ours
  decrypts each to files that are, byte for byte, what a second
  decryption in the script - python-cryptography, straight from the
  manifest - gives, and LibreOffice reads ours with no password as it
  reads the original with one. A wrong password is refused.
- Ours encrypts the same documents, plain, under each scheme;
  LibreOffice opens every one with the password, finds the content,
  and refuses a wrong password, and the second decryption gives back
  every file. 85 of 85.
- `cargo test` decrypts six of those documents (`fixtures/odf/`) and
  compares every file's SHA-256, and checks that the manifest ours
  writes names every attribute as LibreOffice's does, scheme by scheme.

Not here: GPG-encrypted documents (the key comes from an OpenPGP
message in the manifest), signatures, and StarOffice's broken SHA-1,
which LibreOffice still tries as a fallback when reading very old
files.

## Key stores

`keystore/main.rs` (the command line and the conversions between the
formats), `keystore/pkcs12.rs` (PKCS#12, RFC 7292, read and written),
`keystore/jks.rs` (Java's JKS and JCEKS), `keystore/javaser.rs` (as
much Java serialization as a JCEKS secret key needs) and
`keystore/ber.rs` (BER rewritten as DER, for NSS and older writers).

- **PKCS#12**: an authenticated safe of safes - plain, or encrypted
  whole - holding bags: keys plain or shrouded (an
  EncryptedPrivateKeyInfo), certificates, CRLs, secrets and nested
  safes, each with a friendly name and a local key ID. Decryption goes
  through the library's `x509::encrypted_key` (PBES2 with PBKDF2, the
  PKCS#12 PBEs); the MAC is the PKCS#12 KDF and HMAC over the safe, or
  RFC 9579's PBMAC1. `convert` writes the keys in one plain safe of
  shrouded bags and everything else in a second, encrypted, safe - the
  layout OpenSSL writes - under `--key-scheme` and `--cert-scheme`
  (`aes-256`, `3des`, `rc2-40` or `none`) and `--mac` (`sha256`,
  `sha1`, `pbmac1` or `none`).
- **JKS**: each key protected by Sun's own SHA-1 keystream with a
  SHA-1 check, the store by a SHA-1 over the password, the words
  "Mighty Aphrodite" and the store. **JCEKS**: the same frame, keys
  under PBEWithMD5AndTripleDES, and secret keys as a serialized
  `SealedObjectForKeyProtector` around a serialized `SecretKeySpec`.
  Both protectors are the library's (`x509::encrypted_key`).
- **Between them**: a Java key becomes a shrouded key bag and its
  certificates bags tied to it by a `Time ...` local key ID, a trusted
  certificate a certificate bag with Oracle's trusted-key-usage
  attribute, a secret key Java's PrivateKeyInfo-shaped secret bag -
  each as keytool writes it. The other way, a key takes the
  certificates that share its ID as its chain, and every other
  certificate becomes a trusted one.

```console
$ cargo run --release --example keystore -- list server.p12 --password-stdin
$ cargo run --release --example keystore -- convert server.p12 server.jks --password-stdin --format jks
$ cargo run --release --example keystore -- convert old.p12 new.p12 --password-stdin --format pkcs12 --key-scheme aes-256 --mac pbmac1
$ cargo test --example keystore
$ python3 scripts/check_keystore.py
```

Checked (`scripts/check_keystore.py`), with RSA, P-256, P-384, Ed25519
and DSA keys:

- OpenSSL 3.0 writes under AES-256, PBE-SHA1-3DES with a SHA-1 MAC,
  `-legacy`, no encryption, no MAC, one iteration, and the empty
  password; OpenSSL 3.5 with PBMAC1 over SHA-256 and SHA-512; OpenSSL's
  API with a NULL password, which hashes differently from the empty
  one; python-cryptography under AES and 3DES; NSS's `pk12util` under
  its default, AES and legacy ciphers, in BER; keytool writing JKS,
  JCEKS and PKCS#12 with two keys, a trusted certificate and an AES
  secret key; and Java's KeyStore API under the empty password with
  its legacy algorithms. Ours lists every key and certificate the
  writer was given, and refuses a wrong password.
- Ours converts to PKCS#12 under every combination of key and
  certificate scheme, and every MAC for two of them; OpenSSL,
  python-cryptography and keytool read each where they can (OpenSSL 3.0
  needs `-legacy` for RC2; python-cryptography has no RC2 or PBMAC1;
  JDK 21 has no PBMAC1 and skips a plain key bag). Ours writes JKS and
  JCEKS that keytool lists and moves to PKCS#12 with the same keys, and
  a JCEKS and a PKCS#12 secret key that keytool unseals to the same key
  - the PKCS#12 one byte for byte the bag keytool writes. 121 of 121.
- `cargo test` opens 27 of those stores (`fixtures/keystore/`) to the
  entries the witnesses agreed on, refuses a wrong password, converts
  each to every format and back, and holds two things to keytool's own
  bytes: the serialized `SealedObjectForKeyProtector` and
  `SecretKeySpec` of its JCEKS secret key, and its PKCS#12 secret bag.
  The PKCS#12 identifiers are read out of `rfcs/rfc7292.txt` and
  `rfcs/rfc8018.txt`.

Not here: PKCS#12 protected by a public key (a signed authenticated
safe or an enveloped one), Java's BCFKS and Bouncy Castle's UBER, and
keys whose JKS or JCEKS key password differs from entry to entry.

## CMS and S/MIME

`cms/main.rs` (the command line and the dispatch on content type),
`cms/signed.rs` (SignedData), `cms/enveloped.rs` (EnvelopedData,
AuthEnvelopedData, EncryptedData and the four kinds of recipient),
`cms/smime.rs` (the MIME around it), `cms/asn.rs` (identifiers and the
shared ASN.1) and `cms/keys.rs`, with `shared/ber.rs`, which is also the
key store example's.

- **Signing**: the signature covers the signed attributes' DER - re-tagged
  from `[0]` to `SET OF` - and they carry the content type and digest,
  both checked on verifying; without attributes it covers the content,
  which RFC 5652 then allows only for data. RSA PKCS#1 v1.5 and PSS (RFC
  4056, one hash throughout), ECDSA, DSA - a key that inherits its group
  takes it from its issuer - and EdDSA, where RFC 8419 digests with
  SHA-512 or SHAKE256 at 512 bits. What is written is DER: attributes and
  certificates sorted, the signing time a UTCTime until 2050.
- **Recipients**: RSA key transport, PKCS#1 v1.5 or OAEP; EC key
  agreement - an ephemeral key, ECDH, the X9.63 KDF (the library's
  `kdf::nist::x963_kdf`) over ECC-CMS-SharedInfo (RFC 5753), AES key wrap, or RFC 3217's Triple-DES
  wrap for Triple-DES content as OpenSSL does it; a shared key under AES
  key wrap; a password through PBKDF2 and RFC 3211's double CBC wrap
  (both wraps the library's `block_ciphers::cms_wrap`),
  whose iteration count is capped on reading (`--max-iterations`). A
  PKCS#1 v1.5 failure goes on with a random key (RFC 3218), so it fails
  where a wrong key does; with no certificate to say which recipient is
  the key's, those recipients are tried strictly first.
- **Content**: AES-128/192/256, Triple DES, DES and RC2 at 40, 64 and 128
  bits in CBC; AES-GCM in AuthEnvelopedData, the MAC as long as its
  parameters say; DigestedData; CompressedData through the shared zlib
  reader. BER from a streaming writer is rewritten to DER first.
- **S/MIME**: `application/pkcs7-mime` and `multipart/signed`, the
  clear-signed content verified in canonical form (CRLF) unless
  `--binary`.

```console
$ cargo run --release --example cms -- sign letter.txt letter.eml --signer me.crt me.key --smime --detached
$ cargo run --release --example cms -- verify letter.eml letter.txt --roots ca.crt
$ cargo run --release --example cms -- encrypt data.bin data.p7m --recipient alice.crt --recipient bob.crt --cipher aes-256-gcm
$ cargo run --release --example cms -- decrypt data.p7m data.bin --key alice.key --cert alice.crt
$ cargo run --release --example cms -- encrypt data.bin data.p7m --password-stdin
$ cargo test --example cms
$ python3 scripts/check_cms.py
```

Checked (`scripts/check_cms.py`, every content compared byte for byte):

- Every identifier the example uses is named by OpenSSL as the example
  names it, except `id-shake256-len`, which OpenSSL does not know and
  which is checked against RFC 8419's ASN.1 module.
- OpenSSL 3.0 and 3.5 sign with RSA, PSS, ECDSA on P-256 and P-384, DSA
  and - 3.5 - Ed25519 and Ed448, attached, detached, without attributes,
  by key identifier, over SHA-1 to SHA-512, and as S/MIME clear and
  opaque; python-cryptography signs with RSA and ECDSA in DER, PEM and
  S/MIME; NSS signs with RSA and ECDSA. Ours verifies all 102, chains
  included.
- OpenSSL encrypts under every cipher to RSA, P-256 and P-384, with
  OAEP over three hashes, every ECDH KDF and the cofactor variant, to a
  password (with RC2 KEKs, whose key length it takes from the effective
  bits), to AES shared keys of all three sizes, as EncryptedData, as
  AuthEnvelopedData and as S/MIME; python-cryptography and NSS encrypt to
  RSA. Ours decrypts all 83 and refuses each under the wrong key.
- Ours signs with every key type and option, and OpenSSL 3.0 and 3.5
  verify what each has the algorithm for, NSS the RSA and ECDSA ones;
  ours encrypts under every cipher to every kind of recipient and OpenSSL
  decrypts all of it, python-cryptography and NSS the RSA PKCS#1 v1.5
  ones. 552 of 552.
- `cargo test` reads RFC 4134's examples and RFC 3211's and RFC 3217's
  vectors out of `rfcs/`, replays 121 messages the witnesses wrote
  (`fixtures/cms/`), and builds the malformed messages a reader must
  refuse by editing real ones.

Where the witnesses differ from the documents: OpenSSL 3.5 writes Ed448
with signed attributes under plain `id-shake256`, digesting to 64 bytes,
where RFC 8419 says `id-shake256-len`; ours reads both and writes the
RFC's, which OpenSSL cannot read. OpenSSL 3.0 has no EdDSA in CMS, and
3.5 none without signed attributes. OpenSSL's `-binary` reading of a
clear-signed message keeps the CR of the CRLF that RFC 2046 gives to the
boundary, so it verifies one written to the RFC only without `-binary`.

Not here: AuthenticatedData (MAC recipients), static-static ECDH
(an originator certificate rather than an ephemeral key), X25519 and
X448 recipients (RFC 8418, which neither OpenSSL implements),
counter-signatures, the emailProtection key usage, and ML-DSA and ML-KEM
in CMS.

## Kerberos

`kerberos/crypto.rs` (the encryption and checksum types and the
pseudo-random function), `kerberos/files.rs` (keytabs, credential
caches, and the tickets inside them) and `kerberos/main.rs`. The
derivations are the library's: n-fold, DR, random-to-key and DES
string-to-key from `kdf::kerberos`, SP 800-108 from `kdf::nist`, and the
CRC-32 from `checksum`.

- **Encryption types**: RFC 3961's simplified profile - DR and DK over
  n-fold, a usage's three keys from the constants 0x99, 0xAA and 0x55 -
  for Triple DES, AES with HMAC-SHA1-96 (RFC 3962) and Camellia with
  CMAC (RFC 6803, its keys from SP 800-108 in feedback mode); RFC 8009's
  AES with HMAC-SHA-256/384, which keys by KDF-HMAC-SHA2 and MACs the
  ciphertext rather than the plaintext; RC4-HMAC and the export variant
  (RFC 4757), whose RC4 key is cut to 40 bits; and single DES with the
  CRC-32, MD4 or MD5 inside the encryption. CBC with ciphertext stealing
  (the library's `cbc-cs3`) swaps the last two blocks even when the
  plaintext fills them, and the DES checksums are the library's CBC-MAC.
- **String-to-key**: DES's fan-fold with its weak-key correction, Triple
  DES through n-fold, PBKDF2 with SHA-1 for AES-SHA1 and Camellia and
  with the type's own hash for AES-SHA2 (with the type's name in front of
  the salt), and RC4's NT hash. An iteration count of zero, which RFC
  3962 reads as 2^32, is refused, as MIT refuses it.
- **Checksums**: each type's mandatory one, and the DES ones by number -
  RSA-MD4-DES and RSA-MD5-DES (confounded, so random, and checked by
  decrypting), DES-MAC, DES-MAC-K and RSA-MD4-DES-K - and the unkeyed
  CRC-32, MD4, MD5 and SHA-1.
- **Files**: keytabs of version 0x0502, holes skipped and the 32-bit key
  version honoured; credential caches of versions 3 and 4, configuration
  entries skipped; a Ticket and its EncTicketPart.

```console
$ cargo run --release --example kerberos -- string2key --enctype aes256-cts-hmac-sha1-96 --principal user@EXAMPLE.COM --password-stdin
$ cargo run --release --example kerberos -- keytab add http.keytab --principal HTTP/www.example.com@EXAMPLE.COM --kvno 2 --password-stdin
$ cargo run --release --example kerberos -- keytab list http.keytab --keys
$ cargo run --release --example kerberos -- ticket /tmp/krb5cc_1000 --keytab http.keytab
$ cargo test --example kerberos
$ python3 scripts/check_kerberos.py
```

Checked (`scripts/check_kerberos.py`, against MIT Kerberos through
`scripts/witness/krb5witness`, a line protocol over libk5crypto; 1.17.2
for single DES, which 1.21 no longer has, and both versions for
everything else):

- String-to-key for every type over ASCII, UTF-8, empty and 64- and
  65-character passwords and five salts, at the default count and at 1,
  2 and 1,200: 2,280 keys identical.
- Every type encrypting 0 to 40, 63 to 65, 100, 1,000 and 4,096 bytes
  under eleven key usages: MIT decrypts all 9,723 of ours and ours all
  9,723 of MIT's, at the same length.
- Every mandatory checksum byte for byte where it is deterministic, and
  RSA-MD4-DES and RSA-MD5-DES verified each way, an altered one refused;
  the unkeyed ones; the PRF at 0 to 40 bytes for every type. DES-MAC,
  DES-MAC-K and RSA-MD4-DES-K, which MIT has not or has otherwise, and
  the two it has, against values built from RFC 3961's formulas with
  OpenSSL's DES, MD4 and MD5.
- `ktutil` writes every type from a password and ours lists the same
  keys, which are ours from the same password; ours writes every type
  and `klist -k` lists it.
- For each type, a KDC on loopback with every key of that type: `kinit
  -k` with a keytab ours wrote, `kvno` for a service, and ours opens the
  TGT and the service ticket from the cache, version 4 and version 3,
  with the keys `kadmin.local ktadd -norandkey` exported, and refuses
  them with the user's keytab. 34,383 of 34,383.
- `cargo test` reads RFC 3961's, 3962's, 6803's and 8009's vectors out
  of `rfcs/`, and replays MIT's and OpenSSL's answers
  (`fixtures/kerberos.vec`), two
  `ktutil` keytabs, byte for byte, and six caches with their service
  keys (`fixtures/kerberos/`).

Where the documents and MIT differ: RFC 4757 gives the TGS-REP
encrypted under a subkey (usage 9) RC4 usage 8, and MIT and Heimdal
keep it 9; ours follows them. RFC 3961 names the G clef of its last
Triple-DES vector U+1011E where its UTF-8 and its key are U+1D11E's.
MIT's checksum number 4 is not RFC 3961's DES-MAC - it is eight bytes
and refuses a message that is not whole blocks - and its 9 is SHA-1
where the RFC lists RSA-MD5-DES3; ours has the RFC's DES-MAC, DES-MAC-K
and RSA-MD4-DES-K, checked against the RFC's formulas computed with
OpenSSL. MIT's KDC issues no des-cbc-md5 session key,
so that realm's tickets carry des-cbc-crc ones.

Not here: the protocol itself (AS and TGS exchanges, AP-REQ and
authenticators, PA-ENC-TIMESTAMP, FAST, PKINIT), GSS-API tokens, the AFS
variant of DES string-to-key, and keytab version 0x0501.

## Wallets

`wallet/main.rs` (the command line), `wallet/bip39.rs`, `wallet/bip32.rs`,
`wallet/bitcoin.rs` (WIF, addresses, signed messages),
`wallet/bip38.rs`, `wallet/ethereum.rs`, `wallet/keys.rs` (secp256k1 and
recoverable signatures), `wallet/encoding.rs` (Base58Check, Bech32 and
Bech32m), `wallet/hash.rs`, and `wallet/unicode.rs` (normalization, from
the tables `scripts/make_unicode_tables.py` writes into
`wallet/unicode_tables.rs`).

- **BIP-39**: entropy to words with the SHA-256 checksum, the English
  list, and the seed by PBKDF2-HMAC-SHA512, 2048 rounds.
- **BIP-32**: the master key from HMAC-SHA512 keyed "Bitcoin seed",
  private and public child derivation, and the 78-byte serialization
  under xprv, yprv, zprv and their testnet tprv, uprv and vprv, read with
  every check BIP-32's fifth vector asks for.
- **Bitcoin**: WIF, P2PKH, P2SH-wrapped and native P2WPKH, BIP-86
  key-path P2TR (the internal key's TapTweak); signed messages with
  RFC 6979 nonces and s in the lower half, as Bitcoin Core signs, under
  every BIP-137 header, a segwit address also verified under the P2PKH
  header Electrum and Core write.
- **BIP-38**: scrypt and AES-256 over the key, checked by the address
  hash; EC multiply, in which the owner of a passphrase gives out an
  intermediate code (with a lot and sequence number or without) and
  anybody can make keys from it that only the owner can open, and the
  confirmation code that proves an address came from the passphrase.
- **Ethereum**: the address and ERC-55's checksum, Web3 Secret Storage
  version 3 under scrypt or PBKDF2-HMAC-SHA256 with AES-128-CTR and the
  Keccak-256 MAC, early geth's version 1 files (AES-128-CBC), the 2014
  presale wallet, and EIP-191 messages signed and recovered.

BIP-39 hashes its mnemonic and passphrase normalized to Unicode NFKD
and BIP-38 its passphrase to NFC, so a precomposed é and an e followed by
a combining acute are one passphrase and one wallet. `wallet/unicode.rs`
does all four forms of UAX #15 from Unicode 16.0's character database,
Hangul by its arithmetic. An Ethereum keystore's password is hashed as
typed, as geth hashes it. Only the English word list is here; `mnemonic
seed --unchecked` skips the checksum, which BIP-39 does not require of a
seed, and makes the seed of a mnemonic in any other list.

```console
$ cargo run --release --example wallet -- mnemonic new --words 24
$ cargo run --release --example wallet -- derive --mnemonic "abandon ... about" --path "m/84'/0'/0'/0/0" --version zprv
$ cargo run --release --example wallet -- sign-message L1... "hello"
$ cargo run --release --example wallet -- bip38 encrypt 5K... --password-stdin
$ cargo run --release --example wallet -- eth keystore-decrypt UTC--2016-... --password-stdin
$ cargo test --example wallet
$ python3 scripts/check_wallet.py
```

Checked (`scripts/check_wallet.py`):

- python-mnemonic, BIP-39's reference implementation: 200 mnemonics from
  random entropy of all five lengths, their entropy back, their seeds
  under four passphrases, and a changed last word refused exactly when
  python-mnemonic refuses it; and 48 mnemonics in its twelve word lists,
  half given to ours in NFC rather than the list's own form, under
  passphrases with decomposed accents, compatibility characters,
  full-width and half-width forms, Hangul syllables and jamo, an
  ideographic space and a NUL, read from standard input.
- pycoin, whose secp256k1 is its own Python: 72 random seeds and paths
  in all six version prefixes - every extended key, WIF and address
  identical - and public derivation from the parent's xpub; P2TR from
  pycoin's point arithmetic and hashlib's tagged hashes; Ethereum
  addresses and ERC-55 from pycoin's keys and OpenSSL 3.5's Keccak-256.
- Signed messages: ours and pycoin's Bitcoin signatures identical once
  pycoin's s is in the lower half, each verifying the other's;
  Ethereum's identical to pycoin's ECDSA over OpenSSL's Keccak, and
  recovered by ours.
- Keystores and BIP-38 keys written by ours and opened by a reading of
  each specification in the script (hashlib's scrypt and PBKDF2,
  python-cryptography's AES, OpenSSL's Keccak, pycoin's arithmetic), and
  written there and opened by ours, EC multiply and confirmation codes
  included; BIP-38 under the same passphrases, NFC-normalized by
  Python's `unicodedata` for the reading there and given to ours as
  typed. 2,081 of 2,081.
- `cargo test` reads BIP-32's five vectors, BIP-38's nine, BIP-49's,
  BIP-84's and BIP-86's, BIP-350's segwit addresses (valid and invalid)
  and ERC-55's out of `rfcs/`; python-mnemonic's 24 English vectors with
  their master keys; go-ethereum's keystore test files, the presale
  wallet among them (`fixtures/wallet/`); the script's recorded
  answers; and Unicode 16.0's NormalizationTest.txt, all 19,965 cases
  in all four forms, with every code point it does not list left alone
  (`fixtures/wallet/NormalizationTest.zlib`). BIP-38's third vector is
  read from the document's escapes, unnormalized, and its NFC form
  must equal the bytes the document's note gives. BIP-38's scrypt is about ten seconds a derivation in a debug
  build, so one vector of each kind runs every time and all nine, with
  every operation, are `--ignored`.

Not here: the checksum of other BIP-39 word lists, Electrum's seeds, P2TR script paths,
transactions and their signatures, and the EIP-712 typed data.

## DNSSEC

`dnssec/main.rs` (the command line), `dnssec/name.rs` (names, their wire
form and canonical order), `dnssec/rr.rs` (record types between text and
wire form, canonical RDATA), `dnssec/zone.rs` (master files),
`dnssec/keys.rs` (the algorithms, key files, key tags, DS digests, NSEC3
hashing) and `dnssec/sign.rs` (signing and checking a zone).

- **Algorithms**: RSA with MD5, SHA-1, SHA-256 and SHA-512 (RFC 3110's
  key encoding, RSAMD5's key tag from the modulus); DSA as RFC 2536 packs
  it, `T` and 20-byte `R` and `S`; ECDSA P-256 and P-384, `r | s`;
  Ed25519 and Ed448 over the data itself; GOST R 34.10-2001 on
  CryptoPro-A with GOST R 34.11-94 (RFC 5933) and GOST R 34.10-2012 on
  paramSetA with Streebog-256 (RFC 9558), keys little endian and
  signatures `s | r`; SM2 with SM3 under GB/T 32918's default identity
  (RFC 9563). The NSEC3 aliases (6, 7) are their parents' signatures.
- **DS digests**: SHA-1, SHA-256, GOST R 34.11-94, SHA-384, Streebog-256
  and SM3.
- **Signing**: canonical names and RDATA (RFC 4034 section 6, with RFC
  6840's correction that NSEC's next name keeps its case), RRsets sorted
  by canonical RDATA, wildcard label counts; the SEP keys sign the
  DNSKEY RRset and the others the rest; at a delegation only DS and the
  denial record are signed, and glue not at all; NSEC, or NSEC3 with the
  empty non-terminals hashed in; the negative TTL RFC 9077 asks for.
- **Checking**: every RRSIG against the apex keys and its validity
  window, every RRset signed by every algorithm the DNSKEY RRset has
  (RFC 4035 section 2.2), and the NSEC or NSEC3 chain: order, coverage,
  type maps, NSEC3 opt-out.
- **Key files**: BIND's `Private-key-format` v1.3, read and written;
  GOST's keys as the PKCS#8 the RFCs print.

```console
$ cargo run --release --example dnssec -- keygen example.com. --algorithm ECDSAP256SHA256 --ksk
$ cargo run --release --example dnssec -- keygen example.com. --algorithm ECDSAP256SHA256
$ cargo run --release --example dnssec -- sign example.com.zone --origin example.com. --key Kexample.com.+013+12345.private --key Kexample.com.+013+54321.private --nsec3 - 0 --out signed.zone
$ cargo run --release --example dnssec -- verify signed.zone --origin example.com.
$ cargo run --release --example dnssec -- ds Kexample.com.+013+12345.key --digest 2 --digest 4
$ cargo test --example dnssec
$ python3 scripts/check_dnssec.py
```

Checked (`scripts/check_dnssec.py`, against dnspython 2.7.0 with
python-cryptography, for the eleven algorithms dnspython has):

- Ours generating keys: dnspython's key tags, and its DS records under
  SHA-1, SHA-256 and SHA-384.
- Ours signing a zone with a secure and an insecure delegation, glue, a
  wildcard, a mixed-case name, names in capitals inside NS, SOA, MX,
  CNAME, SRV and PTR records, and an empty non-terminal, under NSEC and
  NSEC3 with and without salt and iterations: dnspython validates every
  RRset ours signed, finds the delegation's NS and the glue unsigned, and
  agrees on the NSEC chain's order and every NSEC3 owner.
- Keys python-cryptography made, written in BIND's format by the script,
  read and signed with by ours, and validated by dnspython.
- dnspython's `sign_zone` output checked by ours; NSEC3 hashes of random
  names, salts and iteration counts. 1,679 of 1,679.
- `cargo test` reads the examples of RFC 4034 and 4509 (DS), 5702
  (RSA/SHA-2, signatures reproduced), 6605 (ECDSA), 8080 (EdDSA,
  reproduced), 5933 and 9558 (GOST, 9558's signature reproduced from the
  nonce it gives), 9563 (SM2) out of `rfcs/`, and verifies the signed
  zones of RFC 4035 appendix A (RSASHA1, NSEC) and RFC 5155 appendix A
  (NSEC3 with opt-out), whose NSEC3 hashes it also checks; it replays the
  eleven zones dnspython signed and its key tags, DS records and NSEC3
  hashes (`fixtures/dnssec/`).

Where the documents are wrong: RFC 8080's four RRSIG examples leave out
the algorithm field and open a parenthesis they never close; the
signatures cover a label count of 3 for the two-label example.com. RFC
9563's example gives the private key of a key-signing key whose DNSKEY it
leaves out (the DS's key tag, 27215, is that key's), a DS digest that is
not SM3 of that key, an RRSIG over a DNSKEY RRset that includes the
missing key, a 27-byte NSEC3PARAM signature, and two records broken over
lines before their parentheses open. Its NSEC3 RRSIG verifies.

Not here: zone transfers and the wire protocol, validation from a trust
anchor down a chain of delegations, wildcard expansion in answers, key
rollover timing, NSEC3 opt-out when signing, and CDS/CDNSKEY management.

## WireGuard

`wireguard/noise.rs` (the handshake, the MACs and cookies, transport
messages and the replay window) and `wireguard/main.rs` (keys, `wg`
configurations, and the state each step leaves in a file).

- **Handshake**: Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s with WireGuard's
  identifier, the initiation (148 bytes: ephemeral key, encrypted static
  key and TAI64N timestamp) and the response (92 bytes, the preshared
  key mixed in last), each side's transport keys from the final chaining
  key. A responder refuses an initiation whose MAC1 is not for its key,
  from a peer it was not told of, or with a timestamp no newer than the
  last one it took.
- **MAC1, MAC2 and cookies**: keyed BLAKE2s-128 over the message, MAC1
  under the receiver's public key and MAC2 under a cookie; the cookie a
  loaded responder derives from a secret and the source address, sealed
  with XChaCha20-Poly1305 under a key from its public key, against the
  MAC1 it answers.
- **Transport**: ChaCha20-Poly1305 with the 64-bit counter as nonce;
  padding to 16 bytes, capped at the MTU and applied to the remainder of
  a longer packet, as the Linux module's `calculate_skb_padding` does;
  the receiver's sliding window over 2,048 counters, and the message
  limit.

```console
$ cargo run --release --example wireguard -- genkey > a.key
$ cargo run --release --example wireguard -- pubkey < a.key
$ cargo run --release --example wireguard -- initiate --state a.state --config wg0.conf
$ cargo run --release --example wireguard -- respond 0100... --state b.state --private ... --peer ...
$ cargo run --release --example wireguard -- complete 0200... --state a.state
$ cargo run --release --example wireguard -- seal 45000054... --state a.state
$ cargo test --example wireguard
$ python3 scripts/check_wireguard.py
```

Checked (`scripts/check_wireguard.py`, against wireguard-go through
`scripts/witness/wgwitness`, which drives its unexported
`CreateMessageInitiation`, `ConsumeMessageResponse`, cookie checker and
keypairs):

- Twenty handshakes each way, with zero and random preshared keys:
  wireguard-go names our static key from our initiation and completes
  with our response; ours completes with its. Six transport messages
  each way per session, from empty to 1,500 bytes, padded alike and each
  opened by the other side; a replayed transport message and a replayed
  initiation refused by ours.
- A mismatched preshared key refused at the response; a MAC1 made for
  another key refused before any Curve25519.
- Cookies both ways: wireguard-go's reply opened by ours, whose retry
  carries a MAC2 wireguard-go accepts, from that source only; ours's
  reply taken by wireguard-go, whose retry carries a MAC2 ours accepts
  under that secret only. 368 of 368.
- `cargo test` replays twelve handshakes, with their transport messages,
  and four cookie exchanges recorded with wireguard-go
  (`fixtures/wireguard.vec`), ours's random parts fixed so its messages
  come out byte for byte; and reads `wg(8)`'s example configuration.

Not here: the timers and rekeying (`REKEY_AFTER_TIME` and the rest), the
roaming of endpoints, AllowedIPs routing, the UDP socket and a TUN
device - this example is the cryptography, run a message at a time.

## Signed git commits and tags

`gitsign/object.rs` (where git puts a signature in a commit and a tag,
and what it signs), `gitsign/ssh.rs` (SSHSIG under the `git` namespace,
allowed signers files), `gitsign/pgp.rs` (detached OpenPGP signatures,
with the OpenPGP example's packets, keys and signatures compiled in) and
`gitsign/main.rs`.

- **Objects**: a commit's signature as its last header, `gpgsig` (or
  `gpgsig-sha256`) with each further line indented by a space; a tag's
  after its message, found as git finds it, from the last line that
  starts a signature. The payload is the object without it.
- **`ssh-keygen` as git calls it**: `-Y sign -n git -f KEY FILE` writing
  `FILE.sig`; `-Y find-principals`; `-Y verify -I PRINCIPAL` with
  `-Overify-time` and `-r REVOCATIONS`; `-Y check-novalidate`; and the
  lines git reads back (`Good "git" signature for ... with ED25519 key
  SHA256:...`). Allowed signers lines with quoted principal patterns
  (`*`, `?`, `!`), `namespaces`, `valid-after` and `valid-before`;
  `cert-authority` lines are read and trust nothing, since certificates
  are not.
- **`gpg` as git calls it**: `--status-fd=N -bsau KEY` signing standard
  input with `SIG_CREATED`, and `--verify SIG -` with `GOODSIG`,
  `VALIDSIG` and `TRUST_FULLY` - so git's `%G?` reads `G` - against the
  keys `GITSIGN_KEYRING` names. A key under a passphrase takes it from
  `GITSIGN_PASSPHRASE_FILE`, because git uses standard input for the
  payload.

```console
$ printf '#!/bin/sh\nexec /path/to/gitsign ssh-keygen "$@"\n' > ~/bin/gitsign-ssh; chmod +x ~/bin/gitsign-ssh
$ git config gpg.format ssh
$ git config gpg.ssh.program ~/bin/gitsign-ssh
$ git config user.signingkey ~/.ssh/id_ed25519
$ git commit -S -m "signed"
$ git cat-file commit HEAD | cargo run --release --example gitsign -- verify - --allowed-signers allowed_signers
$ cargo test --example gitsign
$ python3 scripts/check_gitsign.py
```

Checked (`scripts/check_gitsign.py`, git 2.43 with OpenSSH 10.0's
`ssh-keygen` in `/opt/openssh` and GnuPG 2.4.4):

- Ed25519, ECDSA P-256, P-384 and P-521, RSA 2048 and 3072 SSH keys:
  commits and tags git signed through ours, verified through
  `ssh-keygen`, and the reverse, `%G?` reading `G` each time; Ed25519 and
  RSA signatures byte for byte the same as `ssh-keygen`'s. An allowed
  signers file with another namespace, a validity that starts after or
  ended before the commit, or another key, and a revocation file holding
  the key: refused by both programs.
- GnuPG's Ed25519, RSA 2048 and 3072, NIST P-256 and P-384 and
  brainpoolP256r1 keys: commits and tags git signed through ours and
  verified through GnuPG, and the reverse; an unknown key refused; a key
  under a passphrase used with the right passphrase and refused with a
  wrong one.
- `gitsign sign` on an unsigned commit, stored with `git hash-object -w`
  and verified by git through `ssh-keygen`. 147 of 147.
- `cargo test` replays the commits and tags OpenSSH and GnuPG signed
  through git, with the keys that check them (`fixtures/gitsign/`),
  reassembles each byte for byte from its payload and signature, and
  reproduces an Ed25519 SSHSIG `ssh-keygen` made.

Not here: X.509 signatures (`gpg.format x509`, through `gpgsm`), SSH
certificates and signing through an agent (`-U`), and gpg's keyring,
trust database and pinentry.

## JOSE

`jose/main.rs` (the command line), `jose/jwk.rs` (keys: RSA, EC on
P-256, P-384, P-521 and secp256k1, OKP on Ed25519, Ed448, X25519 and
X448, and symmetric keys; RFC 7638 thumbprints and JWK Sets),
`jose/jws.rs` and `jose/jwe.rs`, with `shared/json.rs` (JSON read and
written, member order kept, duplicate names refused).

- **JWS**: HMAC, RSA PKCS#1 v1.5 and PSS, ECDSA as `r || s` - ES512 is
  P-521 - EdDSA by the key's curve, and `none`, which `verify` takes
  only with `--allow-none` and no key. `crit` must be protected and
  name only what is understood here, which is RFC 7797's `b64`; an
  unencoded payload has to be listed in it.
- **JWE**: the content key wrapped, agreed or given, then AES-CBC with
  HMAC (RFC 7518 5.2, the library's `aes-*-cbc-hmac-*` AEADs) or AES-GCM over the
  protected header and any AAD. RSA-OAEP is the library's own, added
  for this. RSA1_5's padding failure carries on with a random key, so
  it fails at the tag exactly as a wrong key does (RFC 7516 11.5).
  ECDH-ES derives with the Concat KDF (the library's
  `kdf::nist::concat_kdf`); PBES2's iteration count is
  capped on reading, 10,000,000 by default (`--max-p2c`), because the
  sender sets it. `zip` must be protected and inflates to at most 64
  MiB.
- **Keys are checked on the way in**: an EC point on its curve, an EC
  or OKP private key whose public half is the one given, an RSA private
  key built from its primes - this library makes keys from `p` and `q`
  - with `n` and `d` agreeing with them modulo each prime.

```console
$ cargo run --release --example jose -- keygen --kty EC --param P-256 --kid k1 > key.jwk
$ cargo run --release --example jose -- sign message.txt --key key.jwk --alg ES256 > message.jws
$ cargo run --release --example jose -- verify message.jws --key key.jwk
$ cargo run --release --example jose -- encrypt secret.txt --alg ECDH-ES+A256KW --enc A256GCM --key key.jwk --zip
$ cargo run --release --example jose -- encrypt secret.txt --alg PBES2-HS512+A256KW --enc A256CBC-HS512 --password-stdin --p2c 8192
$ cargo test --example jose
$ python3 scripts/check_jose.py --jwcrypto ~/src/jwcrypto
```

Checked (`scripts/check_jose.py`):

- Keys: ours generates every type and jwcrypto imports it with the same
  thumbprint; jwcrypto generates every type and ours reads it, with the
  same thumbprint and the same public JWK.
- JWS: seventeen algorithm and key pairings, jwcrypto signing and ours
  verifying and the reverse, in each serialization, unencoded payloads
  both ways, a changed signature refused; PyJWT signing and verifying
  compact tokens with ours for all but EdDSA, which it has under
  another key format.
- JWE: thirteen key management algorithms with all six content
  encryptions, and the four ECDH-ES algorithms on five curves, jwcrypto
  encrypting and ours decrypting and the reverse, a changed tag, IV and
  ciphertext refused; two recipients with `zip` and AAD both ways. 802
  of 802. jwcrypto refuses PBES2 counts over 16,384, so the check uses
  2,048; ours writes 600,000 unless told otherwise.
- `cargo test` replays 17 JWS and 120 JWE that jwcrypto wrote, checks
  ten thumbprints against jwcrypto's, and reads the worked examples out
  of `rfcs/`: RFC 7515's (the HMAC and RSA signatures reproduced byte
  for byte), RFC 7516's RSA-OAEP, RSA1_5, AES key wrap and two-recipient
  JWEs, RFC 7518's CBC-HMAC test cases and ECDH-ES computation, RFC
  7638's thumbprint, RFC 7797's unencoded payloads and RFC 8037's
  Ed25519, X25519 and X448 examples.

Not here: JWTs as such (their claims are a payload like any other),
`x5c` and `jku` (certificate chains and key URLs are carried, not
followed), and JWS and JWE ML-DSA, which jwcrypto offers only where its
python-cryptography does.
