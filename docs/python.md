# Using allcrypt from Python

Build it with `python3 scripts/build_python.py` (see
[building.md](building.md)). That is cargo plus a rename; maturin is
not needed unless you want a wheel.

The API follows the shapes Python already has: hashes behave like `hashlib`
objects, ciphers like the encryptor/decryptor pattern in `cryptography`.
Everything raises `allcrypt.CryptoError`, a subclass of `ValueError`.

## Bytes in, bytes out

**Every argument that takes bytes accepts any buffer**: `bytes`,
`bytearray`, `memoryview`, `array("B")`, a NumPy `uint8` array, an
`mmap` — anything contiguous holding single bytes. Working with data
usually means working with mutable buffers, and writing `bytes(buf)` at
each call is both noise and a copy you cannot see.

```python
import array

import allcrypt

buf = bytearray(b"abc")
assert (allcrypt.sha256(buf).hexdigest()
        == allcrypt.sha256(memoryview(buf)).hexdigest()
        == allcrypt.sha256(array.array("B", buf)).hexdigest()
        == allcrypt.sha256(b"abc").hexdigest())

# Keys, nonces, associated data, certificates - all of them.
aead = allcrypt.Aead(bytearray(16), "aes-gcm")
sealed = aead.encrypt(bytearray(12), memoryview(b"message"), bytearray(b"ad"))
assert aead.decrypt(bytes(12), sealed, b"ad") == b"message"
```

Return values are always `bytes`.

Two kinds of buffer are refused rather than guessed at, both with a
message that names the remedy.

A **non-contiguous** buffer is not a byte string. `memoryview(x)[::2]` is
a view of every other byte, and flattening it produces bytes that are
nowhere in your memory:

```python
import allcrypt

view = memoryview(bytearray(b"abcdef"))[::2]
try:
    allcrypt.sha256(view)
except BufferError as refused:
    assert "not C-contiguous" in str(refused)

# `bytes(view)` is how you say you meant the bytes it selects.
assert allcrypt.sha256(bytes(view)).hexdigest() == \
       allcrypt.sha256(b"ace").hexdigest()
```

That is `hashlib`'s behaviour too, and the same exception.

A buffer of **multi-byte items** is refused, and here this is stricter
than `hashlib`, which would hash the machine's own bytes for an
`array("I")`. A hash of arbitrary memory can afford that; a key or a
nonce cannot, because its value would then depend on the byte order of
the machine it ran on and the code works until somebody moves it:

```python
import array

import allcrypt

words = array.array("I", [1, 2, 3])
try:
    allcrypt.sha256(words)
except TypeError as refused:
    assert "single bytes" in str(refused)

assert allcrypt.sha256(words.tobytes()).digest_size == 32
```

A wrong type raises `TypeError`, as in `hashlib` — `CryptoError` stays a
`ValueError` and means a bad key length, an unknown algorithm name or a
failed authentication.

One method takes a `bytearray` specifically rather than any buffer:
`Encryptor.update_into`, which writes into it. That is the other side of
the same rule, and [the note below](#in-place-encryption) says why.

## Hashing

```python
import allcrypt

allcrypt.sha256(b"abc").hexdigest()
# 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

h = allcrypt.new("sha512_256")
h.update(b"chunk one")
h.update(b"chunk two")
digest = h.digest()
assert len(digest) == h.digest_size == 32
```

Constructors exist for each algorithm (`md5`, `sha0`, `sha1`, `sha224`,
`sha256`, `sha384`, `sha512`, `sha512_224`, `sha512_256`) and `new(name)`
mirrors `hashlib.new`. `allcrypt.algorithms_available` lists them.

`new("sm3")` is GB/T 32905-2016, the Chinese national hash. This OpenSSL
provides it, so it can be compared with `hashlib.new("sm3")` directly:

```python
import hashlib

import allcrypt

assert allcrypt.new("sm3", b"abc").hexdigest() == \
       hashlib.new("sm3", b"abc").hexdigest()
assert allcrypt.new("sm3").digest_size == 32
```

It is also what `Hmac(..., "sm3")` and `pbkdf2_hmac("sm3", ...)` take,
which is the form RFC 8998's TLS 1.3 suites need.

`new("whirlpool")` is ISO/IEC 10118-3's 512 bit hash. `hashlib` has
never had it and OpenSSL 3 moved it to the `legacy` provider, but
**TrueCrypt and VeraCrypt derive their header keys with
PBKDF2-HMAC-Whirlpool** — so a volume made with that option needs it.

```python
import allcrypt

assert allcrypt.new("whirlpool", b"abc").hexdigest().startswith("4e2448a4")
assert allcrypt.new("whirlpool").digest_size == 64

# Which is the shape a VeraCrypt header key derivation has.
key = allcrypt.pbkdf2_hmac("whirlpool", b"passphrase", bytes(64), 1000, 64)
assert len(key) == 64
```

It is the one hash here whose digest is as wide as its block, both 64
bytes — so HMAC's `B >= L` holds with equality, as it does for MD2.

Its two earlier versions are `whirlpool_0` (2000) and `whirlpool_t`
(2001, also called Whirlpool-1), for software that hashed with them
before the final one; RIPEMD-160's relatives are `ripemd128`,
`ripemd256` and `ripemd320`, Korea's KCDSA hash is `has160`, and MD6 is
`md6_128` to `md6_512` - or `md6_` with any whole-byte size up to 512
bits. None of them is in `hashlib`.

```python
import allcrypt

sizes = {"ripemd128": 16, "ripemd256": 32, "ripemd320": 40, "has160": 20,
         "whirlpool_0": 64, "whirlpool_t": 64, "md6_256": 32, "md6_200": 25}
for name, size in sizes.items():
    assert allcrypt.new(name, b"abc").digest_size == size
# Three different functions, not three spellings of one.
assert len({allcrypt.new(n, b"abc").digest() for n in
            ("whirlpool", "whirlpool_t", "whirlpool_0")}) == 3
```

`new("md2")` and `new("md4")` are RFC 1319 and RFC 1320. Neither is in
`hashlib` - OpenSSL moved MD4 to its legacy provider and dropped MD2
entirely - and both are here for what still speaks them rather than for
what they protect. MD2 signs old root certificates as
`md2WithRSAEncryption`; MD4 is the NT hash, so it is NTLM, NTLMv2, CHAP
and MS-CHAPv2.

```python
import allcrypt

assert allcrypt.new("md2", b"abc").hexdigest() == \
       "da853b0d3f88d99b30283a69e6ded6bb"

# The NT hash of a password is MD4 of its UTF-16LE encoding.
nt = allcrypt.new("md4", "password".encode("utf-16-le")).hexdigest()
assert nt == "8846f7eaee8fb117ad06bdd830b7586c"
```

**MD2's `block_size` is 16**, where every other hash here reports 64 or
more. That is its real compression block, and it is what `Hmac` and
`pbkdf2_hmac` need - but code that sizes a buffer from `block_size` and
assumed 64 will get a surprise.

`new("streebog256")` and `new("streebog512")` are GOST R 34.11-2012, which
`hashlib` does not have. The 256 bit one is **not** the 512 bit one
truncated: its IV differs, so the two diverge from the first block. And
the standard prints its test vectors as 512 bit numbers, most significant
byte first, which is backwards from what every implementation emits — see
[pitfalls.md](pitfalls.md) before comparing against a published vector.

Objects carry `digest_size`, `block_size` and `name`, and `copy()` forks the
state, exactly as `hashlib` does:

```python
import allcrypt

h = allcrypt.sha256(b"hello ")
forked = h.copy()
h.update(b"world")
forked.update(b"there")
assert h.hexdigest() != forked.hexdigest()
```

This is a drop-in shape, so swapping `hashlib` for `allcrypt` in existing code
usually works unchanged — with the caveat that these are from-scratch
implementations, not OpenSSL.

## Names as enumerations

Every catalogue is also an enumeration, so an editor can complete the
name and a typo is visible before it runs:

```python
import allcrypt

cipher = allcrypt.Cipher(allcrypt.BlockCipher.AES, bytes(16))
out = cipher.encrypt(allcrypt.Mode.CBC, b"sixteen byte blk", iv=bytes(16))
assert out == allcrypt.Cipher("aes", bytes(16)).encrypt(
    "cbc", b"sixteen byte blk", iv=bytes(16))
```

**The members are strings**, so nothing has to change to use them and
nothing has to be converted at a boundary:

```python
import allcrypt

assert allcrypt.Mode.CBC == "cbc"
assert isinstance(allcrypt.Mode.CBC, str)
assert f"{allcrypt.Mode.CBC}" == "cbc"
assert allcrypt.Mode("ctr") is allcrypt.Mode.CTR
```

There are six: `Mode`, `BlockCipher`, `CurveName`, `HashName`,
`StreamCipherName` and `AeadName`. The last three carry a `Name` suffix
because `Hash`, `StreamCipher` and `Aead` are already classes here, and
shadowing a class is a breakage that happens at import.

They are **generated at module init from the same Rust constants** the
`*_available` lists come from, which is the point: a hand-written enum
would be a second place to add an algorithm, and the two would disagree
the first time somebody added one and forgot.
`pytests/test_name_enums.py` asserts each enum holds exactly its
catalogue, so drift is a test failure rather than a surprise.

```python
import allcrypt

assert [m.value for m in allcrypt.Mode] == allcrypt.modes_available
assert [m.value for m in allcrypt.HashName] == allcrypt.algorithms_available
```

## Block ciphers

A `Cipher` is just a key. It holds no mode state, so one instance can spawn as
many independent streams as you like.

```python
import allcrypt

key = bytes(range(16))
iv = bytes(16)

c = allcrypt.Cipher("aes", key)
ciphertext = c.encrypt("cbc", bytes(32), iv)
assert c.decrypt("cbc", ciphertext, iv) == bytes(32)
assert c.block_size == 16
```

For data that arrives in pieces, take an encryptor or decryptor:

```python
import allcrypt

c = allcrypt.Cipher("aes", bytes(16))
enc = c.encryptor("ctr", bytes(16))
out = enc.update(b"first ") + enc.update(b"second") + enc.finalize()

dec = c.decryptor("ctr", bytes(16))
assert dec.update(out) + dec.finalize() == b"first second"
```

Splitting the input differently gives byte-identical output. `finalize()`
ends the stream and raises if a partial block was left dangling — which is
the only way ECB and CBC can tell you the input was not block aligned:

```python
import allcrypt

enc = allcrypt.Cipher("aes", bytes(16)).encryptor("cbc", bytes(16))
assert len(enc.update(bytes(20))) == 16      # only the whole block emerges
try:
    enc.finalize()
    raise AssertionError("should have raised")
except allcrypt.CryptoError:
    pass
```

`allcrypt.block_ciphers_available` is the list, and `allcrypt.modes_available`
is the modes — `ecb`, `cbc`, `pcbc`, `cfb`, `ofb`, `ctr`, `ctr-le` and
`cbc-cs1`, `cbc-cs2`, `cbc-cs3`. ECB takes no IV and raises if given one.

`ctr-le` counts the whole block as one little-endian integer, starting at
the IV: WinZip's AES encryption, which starts at 1. The `cbc-cs` modes are
CBC with ciphertext stealing - any length of at least one block, no
padding, the ciphertext exactly as long as the plaintext - in NIST's three
orderings of the last two blocks. CS3 is Kerberos's (RFC 3962). The last
two blocks are decided only at the end, so an encryptor holds them back
and `finalize` returns them:

```python
import allcrypt

c = allcrypt.Cipher("aes", bytes(16))
ct = c.encrypt("cbc-cs3", b"seventeen bytes!!", bytes(16))
assert len(ct) == 17
assert c.decrypt("cbc-cs3", ct, bytes(16)) == b"seventeen bytes!!"
```

The **third argument** is the one cipher-specific setting this surface
carries, and it means something different for each cipher that has one:

- GOST takes an S-box parameter set:
  `allcrypt.Cipher("gost", key, "id-Gost28147-89-TestParamSet")`.
- RC2 takes its *effective key length in bits*, which is part of the key
  schedule rather than a length check.
- TEA and XTEA take a round count.
- RC5 takes a round count too, and it means something slightly
  different — see below.

```python
import allcrypt

# TEA and XTEA: 16 byte key, 8 byte block, and the round count as the
# third argument. One round here is what the papers call a cycle, and
# the published cipher is 32 of them - which is what you get by leaving
# it out.
assert allcrypt.Cipher("tea", bytes(16)).encrypt("ecb", bytes(8)).hex() \
    == "41ea3a0a94baa940"

reduced = allcrypt.Cipher("xtea", bytes(16), "1")
assert reduced.encrypt("ecb", bytes(8)).hex() == "000000009e3779b9"

# Zero is refused rather than silently being the identity function.
try:
    allcrypt.Cipher("tea", bytes(16), "0")
    raise AssertionError("zero rounds should be refused")
except allcrypt.CryptoError as refused:
    assert "identity" in str(refused)
```

`aria` is RFC 5794, the Korean national block cipher, with AES's block
and key sizes and neither AES's diffusion nor AES's key schedule.
OpenSSL has it and `cryptography` does not, so it is one of the few
algorithms here where a reference exists to check against and the
standard Python stack still cannot reach it.

```python
import allcrypt

# RFC 5794 Appendix A.1.
key = bytes(range(16))
block = bytes.fromhex("00112233445566778899aabbccddeeff")
assert allcrypt.Cipher("aria", key).encrypt("ecb", block).hex() \
    == "d718fbd6ab644c739da95f3be6451778"
assert allcrypt.Cipher("aria", bytes(32)).block_size == 16
```

CAST-256 (`"cast256"`, or `"cast6"` as RFC 2612 also names it) is a
128 bit block built from CAST5's round functions, with a key of 16, 20,
24, 28 or 32 bytes. The key is zero-padded to 32 bytes first, so a
16 byte key and the same key with sixteen zero bytes after it are the
same key.

RC6 is the AES finalist from the same family as RC5: a 128 bit block, twenty
rounds and a key of 1 to 255 bytes. It takes every mode a 128 bit
cipher takes, including `rc6-eax`, `rc6-mgm` and `rc6-ocb`:

```python
import allcrypt

assert allcrypt.Cipher("rc6", bytes(16)).encrypt("ecb", bytes(16)).hex() \
    == "8fc3a53656b1f778c129df4e9848a41e"
```

RC5 (RFC 2040) is `RC5-32/r/b`: a 64 bit block, a round count, and a key
of 1 to 255 bytes. **Zero rounds is a legal RC5 and not the identity** —
the two halves are still summed with the first two subkeys, so RFC 2040
publishes vectors for it. That is the opposite of TEA, where zero rounds
*is* the identity and is refused, so the two ciphers disagree about zero
on purpose.

```python
import allcrypt

# RFC 2040's first published vector.
assert allcrypt.Cipher("rc5", bytes(1), "0").encrypt("ecb", bytes(8)).hex() \
    == "7a7bba4d79111d1e"

# Leaving the round count out means RFC 2040's nominal twelve.
assert allcrypt.Cipher("rc5", bytes(16)).block_size == 8

# An empty key is refused: RFC 2040's own key expansion divides by the
# number of key words, which is zero.
try:
    allcrypt.Cipher("rc5", b"")
    raise AssertionError("an empty RC5 key should be refused")
except allcrypt.CryptoError:
    pass
```

**TEA has equivalent keys**: flipping the top bit of the first and second
key words together gives a key that encrypts identically, so every key
has three others equivalent to it and the effective length is 126 bits.
That is a practical break wherever TEA is used to build a hash, and it is
what broke the original Xbox. XTEA exists to remove it, and does not fix
the related-key attacks. Neither is a cipher to choose today; both are
here because firmware that uses them is not ours to upgrade.

`kuznyechik` and `magma` are GOST R 34.12-2015, both with 256 bit keys.
Magma is `gost` with a fixed S-box read **big endian**, so the same key and
plaintext give a different answer under the two — each correct under its
own standard, which is why both are here.

### Which AES this is

```python
import allcrypt

allcrypt.hardware_aes()   # True only in a module built with --features aes-ni,
                          # on a processor with AES-NI
```

The portable build's AES is bitsliced and constant time in the modes that
encrypt several blocks at once (ECB, CTR, GCM, XTS, CBC decryption), and
table-driven - fast, but leaking through the cache - in the ones that can
only ever encrypt one block (CBC encryption, CFB, OFB, CMAC). A module
built with `python3 scripts/build_python.py --features aes-ni` uses the
processor's AES instructions where it has them, which is faster and
constant time in every mode. "Building for speed" in `docs/building.md`
has the numbers and the reasons it is opt-in.

### In-place encryption

`update_into` applies the keystream to a `bytearray` without copying, which
matters for large buffers. CTR, OFB and CFB support it; ECB and CBC raise,
because they work a block at a time.

It is the one place a `bytearray` specifically is wanted rather than any
buffer, and it is the other half of the rule at the top of this file.
Everything else releases the GIL while it works, so it must not hold a
borrow into a `bytearray` — another thread could resize it and the buffer
would move; that is why a mutable source is copied. `update_into` makes
the opposite trade: it keeps the GIL and writes in place, so there is no
copy at all.

```python
import allcrypt

buf = bytearray(b"transform me in place!!")
allcrypt.Cipher("aes", bytes(16)).encryptor("ctr", bytes(16)).update_into(buf)
assert bytes(buf) != b"transform me in place!!"
```

### PCBC

Propagating CBC, as used by Kerberos 4. It chains the previous plaintext
**XOR** the previous ciphertext, so a corrupted block ruins everything
after it rather than just the next one.

```python
import allcrypt

cipher = allcrypt.Cipher("aes", bytes(16))
out = cipher.encrypt(allcrypt.Mode.PCBC, bytes(48), iv=bytes(16))
assert cipher.decrypt("pcbc", out, iv=bytes(16)) == bytes(48)
```

**It does not do what it was meant to.** Propagation was chosen as a
poor man's integrity check, and swapping two adjacent ciphertext blocks
leaves everything after them intact, because the two `P ^ C` terms
cancel. That is why Kerberos 5 dropped it. It is here because Kerberos 4
traffic and files encrypted by it still exist - which is what this
library is for - and not because you should use it. Use an AEAD.

## Authenticated encryption

`allcrypt.Aead` is AES-GCM, AES-CCM or ChaCha20-Poly1305, shaped like
`AESGCM`, `AESCCM` and `ChaCha20Poly1305` in `cryptography`: the tag is
appended to the ciphertext, so code written against those moves across
unchanged.

```python
import allcrypt

# Membership, not equality: this list grows, and a doc example that
# pinned it would fail every time it did - which is how a document
# starts getting edited to match rather than read.
for name in ("aes-gcm", "aes-ccm", "aes-ccm-8", "chacha20-poly1305",
             "xchacha20-poly1305", "aes-eax"):
    assert name in allcrypt.aeads_available

key, nonce = bytes(range(32)), bytes(12)
sealed = allcrypt.Aead(key, "chacha20-poly1305").encrypt(nonce, b"payload")
assert allcrypt.Aead(key, "chacha20-poly1305").decrypt(nonce, sealed) == b"payload"
```

ChaCha20-Poly1305 is the one to reach for where there is no AES
instruction: it is built from 32 bit adds, XORs and rotations, so it is
fast in software and constant time without effort, where software AES
needs either lookup tables, which leak through the cache, or bitslicing,
which is slower (`docs/pitfalls.md` section 1). It takes a 256 bit key and a 96 bit nonce,
and only those. `xchacha20-poly1305` is the same AEAD under a subkey
HChaCha20 derives from the first 16 bytes of a 192 bit nonce, which is
long enough to draw at random for every message:

```python
import os

import allcrypt

key, nonce = bytes(range(32)), os.urandom(24)
sealed = allcrypt.Aead(key, "xchacha20-poly1305").encrypt(nonce, b"payload")
assert allcrypt.Aead(key, "xchacha20-poly1305").decrypt(nonce, sealed) == b"payload"
```

The default is AES-GCM:

```python
import allcrypt

key = bytes(range(32))
nonce = bytes(12)                      # see the warning below
aead = allcrypt.Aead(key)

sealed = aead.encrypt(nonce, b"the payload", b"headers in the clear")
assert aead.decrypt(nonce, sealed, b"headers in the clear") == b"the payload"
assert len(sealed) == len(b"the payload") + aead.tag_size
```

The additional data is authenticated but not encrypted - it travels in the
clear and cannot be changed without the tag failing. Changing anything at
all raises:

```python
import allcrypt

aead = allcrypt.Aead(bytes(16))
sealed = aead.encrypt(bytes(12), b"message", b"aad")

for bad in [sealed[:-1],                          # truncated
            sealed[:-1] + bytes([sealed[-1] ^ 1]),  # a flipped tag bit
            ]:
    try:
        aead.decrypt(bytes(12), bad, b"aad")
        raise AssertionError("a forgery was accepted")
    except allcrypt.CryptoError:
        pass

# And the same ciphertext under different additional data is a forgery too.
try:
    aead.decrypt(bytes(12), sealed, b"different")
    raise AssertionError("a forgery was accepted")
except allcrypt.CryptoError:
    pass
```

A failed decryption raises and returns nothing. There is no partial result
to inspect, because unverified plaintext is not a result.

### AES-CCM, and the one thing it cannot do

CCM (RFC 3610) is the older AEAD: a CBC-MAC and a CTR keystream under one
key, which is what constrained hardware can do cheaply. `"aes-ccm-8"` is
the same thing with an eight byte tag — a real trade rather than a free
saving, since a blind forgery then succeeds once in 2^64 attempts instead
of once in 2^128.

```python
import allcrypt

key, nonce = bytes(range(16)), bytes(12)
sealed = allcrypt.Aead(key, "aes-ccm").encrypt(nonce, b"payload", b"headers")
assert allcrypt.Aead(key, "aes-ccm").decrypt(nonce, sealed, b"headers") == b"payload"
assert allcrypt.Aead(key, "aes-ccm").tag_size == 16
assert allcrypt.Aead(key, "aes-ccm-8").tag_size == 8
```

It cannot stream. Its MAC begins with the message's length, so nothing can
be processed until all of it has arrived, and the streaming constructors
refuse rather than buffering behind an `update` that would promise
constant memory and not deliver it. `cryptography` draws the same line —
its `AESCCM` has no streaming pair either.

```python
import allcrypt

aead = allcrypt.Aead(bytes(16), "aes-ccm")
try:
    aead.encryptor(bytes(12))
    raise AssertionError("CCM should not offer a streaming encryptor")
except allcrypt.CryptoError:
    pass
```

### The nonce

**A nonce must never repeat under one key.** This is the one rule GCM does
not forgive. Two messages encrypted under the same key and nonce give away
their XOR *and* allow the authentication key to be recovered from the two
tags, after which anything can be forged under that key - not just those
two messages. There is no warning and no recovery.

Nothing in this library can check it, because only the caller knows what
was used before. The two ways that work:

```python,ignore
import os, itertools, allcrypt

# A counter, when you have somewhere to keep it that survives a restart.
counters = itertools.count()
nonce = next(counters).to_bytes(12, "big")

# Or 96 random bits, which is the usual answer when you do not.
nonce = os.urandom(12)
```

12 bytes is the size to use: GCM treats it directly as the counter, and
anything else goes through an extra derivation for no benefit. Other
lengths work, including ones `cryptography` refuses - this library accepts
any non-empty nonce, because something out there is already using one.

### Streaming

For data too large to hold twice:

```python
import allcrypt

aead = allcrypt.Aead(bytes(16))
nonce = bytes(12)

stream = aead.encryptor(nonce, b"aad")
sealed = stream.update(b"first part ") + stream.update(b"second part")
tag = stream.tag()

opening = aead.decryptor(nonce, b"aad")
opened = opening.update(sealed)
opening.verify(tag)              # raises if it does not match
assert opened == b"first part second part"
```

`verify` is a separate, mandatory step: a streaming decryption hands back
bytes before it can know whether they are genuine, so nothing `update`
returns should be used until `verify` has not raised.

## Decrypting your own traffic in Wireshark

A TLS connection is opaque in a capture, which is exactly when you need to
see it. The way every other stack solves this is the NSS key log format,
and so does this one:

```python,ignore
import allcrypt_ssl

context = allcrypt_ssl.create_default_context()
context.keylog_filename = "/tmp/keys.log"
```

Or, without touching the code at all, set the environment variable that
OpenSSL, curl and every browser already honour:

```console
$ SSLKEYLOGFILE=/tmp/keys.log python your_program.py
```

Then point Wireshark at the file — *Preferences → Protocols → TLS →
(Pre)-Master Secret log filename* — or:

```console
$ tshark -o tls.keylog_file:/tmp/keys.log -r capture.pcap
```

The file accumulates one line per session, which is how Wireshark expects
it: sessions are matched by client random, so a file holding many is
normal and each new run appends.

`keylog_filename` is the standard library's own attribute and behaves the
same way. Setting it explicitly beats the environment variable; setting it
to `""` means off whatever the environment says.

For a single session without a file, the line is on the connection:

```python,ignore
sock.key_log_line()
# 'CLIENT_RANDOM 4f3c... 9a1b...'
```

**This writes your session keys to disk in plain text.** Anyone who reads
that file can decrypt every connection it covers, from a capture taken at
any time, forever. Nothing here writes it unless you ask — there is no
default path — and a file holding these deserves more care than a private
key, since a private key is usually encrypted at rest and this is not.

### EAX

EAX is CTR plus OMAC over **any** block cipher here, so there is one
entry per cipher rather than a single `eax` taking a cipher argument -
the catalogue is what a caller picks from, and `eax` alone does not say
what it will be built on.

```python
import allcrypt

for name in ("aes-eax", "twofish-eax", "sm4-eax", "des-eax"):
    key = bytes(8) if name == "des-eax" else bytes(16)
    aead = allcrypt.Aead(key, name)
    sealed = aead.encrypt(b"a nonce", b"the message", b"header")
    assert allcrypt.Aead(key, name).decrypt(
        b"a nonce", sealed, b"header") == b"the message"
```

Two things it has over CCM: **the nonce may be any length** (CCM's is
7..13 bytes and trades off against the maximum message size), and the
mode is online in both passes rather than needing the message's length
up front.

**Its tag is one block**, so EAX over a 64 bit block cipher - DES, 3DES,
Blowfish - has an 8 byte tag and half the forgery resistance of the
rest. That is a property of the cipher, not a truncation. Ask rather
than assume:

```python
import allcrypt

assert allcrypt.Aead(bytes(16), "aes-eax").tag_size == 16
assert allcrypt.Aead(bytes(8), "des-eax").tag_size == 8
assert allcrypt.Aead(bytes(16), "aes-ccm-8").tag_size == 8
```

### MGM

Multilinear Galois Mode, RFC 9058: a counter mode for confidentiality
and a multilinear function over GF(2^n) for authenticity. It is the AEAD
the GOST TLS 1.3 cipher suites are built on, and it is named per cipher
the same way EAX is.

```python
import allcrypt

key = bytes(range(32))
# **The nonce is one block, with the top bit clear.** Kuznyechik's block
# is 16 bytes and Magma's is 8, so the nonce is not one size.
for name, nonce_len in (("kuznyechik-mgm", 16), ("magma-mgm", 8)):
    nonce = bytes([0x11] * nonce_len)
    aead = allcrypt.Aead(key, name)
    sealed = aead.encrypt(nonce, b"the message", b"header")
    assert allcrypt.Aead(key, name).decrypt(
        nonce, sealed, b"header") == b"the message"

assert allcrypt.Aead(key, "kuznyechik-mgm").tag_size == 16
assert allcrypt.Aead(key, "magma-mgm").tag_size == 8
```

Three things about it that are not like the other AEADs here.

**The nonce is one block with its top bit clear**, and a nonce with that
bit set is refused rather than masked. MGM runs two counter chains and
that bit is what keeps them apart - `0 || ICN` starts the keystream's
and `1 || ICN` starts the authentication's. Masking quietly would make
two nonces differing only there into one nonce, which is the single
thing the mode says must never happen.

```python
import allcrypt

aead = allcrypt.Aead(bytes(32), "magma-mgm")
try:
    aead.encrypt(bytes([0x80] + [0] * 7), b"message", b"header")
    raise AssertionError("a full-width nonce was accepted")
except allcrypt.CryptoError:
    pass
```

**Empty associated data and an empty message together are refused.** RFC
9058 section 6: with nothing to authenticate the tag stops depending on
the nonce, so one captured tag forges every such message under that key.
Either one alone is fine.

**It works on 64 bit block ciphers**, which GCM, CCM, XTS and key wrap
all refuse - RFC 9058 gives a field polynomial for both block sizes. The
two sizes really are two different modes: the tag is the block, so
`magma-mgm` has an 8 byte tag and half the forgery resistance of
`kuznyechik-mgm`.

### OCB

OCB3 (RFC 7253), named per cipher like EAX and MGM, over the 128 bit
block ciphers only: `aes-ocb`, `camellia-ocb`, `twofish-ocb` and the
rest of `aeads_available`. The nonce is up to 15 bytes and the tag is
16. `aes-ocb` gives the same bytes as OpenSSL's AES-OCB.

```python
import allcrypt

key = bytes(range(16))
nonce = b"fifteen bytes.."
sealed = allcrypt.Aead(key, "aes-ocb").encrypt(nonce, b"the message", b"header")
assert len(sealed) == len(b"the message") + 16
assert allcrypt.Aead(key, "aes-ocb").decrypt(nonce, sealed, b"header") == b"the message"
assert "des-ocb" not in allcrypt.aeads_available
```

### AES-CBC with HMAC-SHA-2

RFC 7518's encrypt-then-MAC AEADs, JWE's `A128CBC-HS256` and its two
siblings: `aes-128-cbc-hmac-sha256`, `aes-192-cbc-hmac-sha384` and
`aes-256-cbc-hmac-sha512`. The key is the MAC key and the AES key
together (32, 48 or 64 bytes), the nonce is the 16-byte CBC IV, the
ciphertext is padded to whole blocks, and the tag is half the key.

```python
import allcrypt

key, iv = bytes(range(32)), bytes(16)
sealed = allcrypt.Aead(key, "aes-128-cbc-hmac-sha256").encrypt(iv, b"the message", b"header")
assert len(sealed) == 16 + 16                  # one padded block, a 16-byte tag
assert allcrypt.Aead(key, "aes-128-cbc-hmac-sha256").decrypt(iv, sealed, b"header") \
    == b"the message"
```

The tag is checked before anything is decrypted, so the padding is never
an oracle; and the IV must be unpredictable, as for any CBC.

## Stream ciphers

```python
import allcrypt

c = allcrypt.StreamCipher("chacha20", bytes(32), bytes(12))
assert c.update(bytes(3)).hex() == "76b8e0"

rc4 = allcrypt.StreamCipher("rc4", bytes.fromhex("0102030405"))
assert rc4.update(bytes(16)).hex() == "b2396305f03dc027ccc3524a0a1118a8"
```

Names are `chacha20`, `chacha12`, `chacha8`, `xchacha20`, `salsa20`,
`salsa12`, `salsa8`, `rc4` and `zipcrypto`
(`allcrypt.stream_ciphers_available`). ChaCha takes an 8 or 12 byte nonce,
XChaCha20 a 24 byte one, Salsa20 an 8 byte one; RC4 and ZipCrypto take
none. Keystream position carries across calls.

`update` XORs the keystream onto the data, which encrypts and decrypts
alike. ZipCrypto, PKWARE's traditional ZIP encryption, has no such
keystream - its keys absorb each byte of plaintext - so for it `update`
raises and `encrypt` and `decrypt` are the way in. Every stream cipher
has those two, and `keystream` says whether `update` works:

```python
import allcrypt

z = allcrypt.StreamCipher("zipcrypto", b"secret")   # the key is the password
assert not z.keystream
ct = z.encrypt(b"hello, world")
assert ct.hex() == "a0254d7b73bee67c15583a7e"
assert allcrypt.StreamCipher("zipcrypto", b"secret").decrypt(ct) == b"hello, world"
```

## CMAC and CBC-MAC

```python
import allcrypt

tag = allcrypt.cmac("aes", bytes(16), b"message")
assert len(tag) == 16
# CBC-MAC: the last CBC block. Whole blocks, or zero padding with zero_pad.
mac = allcrypt.cbc_mac("des", bytes.fromhex("0123456789abcdef"), b"7 bytes", zero_pad=True)
assert len(mac) == 8
```

CBC-MAC is forgeable over messages of different lengths - the MAC of
`M` is also the MAC of `M || (M XOR tag)` - which is what CMAC fixes. It
is here for DES-MAC, Kerberos's DES checksums and the banking MACs that
are CBC-MACs.

## Office XOR obfuscation

The binary Office formats' oldest password protection, which an `.xls`
saved with "XOR" protection still carries. The password - 1 to 15
single-byte characters - gives a 16-byte array; the data is XORed with
it, repeating, and each byte rotated. `index` is the array index the
first byte meets, which the format decides.

```python
import allcrypt

# Excel's default password, and the 16-bit verifier it stores.
assert allcrypt.office_xor_verifier(b"VelvetSweatshop") == 0x9a0a
ct = allcrypt.office_xor_encrypt(b"secret", b"sheet data", index=3)
assert allcrypt.office_xor_decrypt(b"secret", ct, index=3) == b"sheet data"
```

The verifier is also the 16-bit hash Excel keeps for a protected sheet.
None of it is encryption: one 16-byte stretch of known plaintext gives
the array, and the array is the key.

## HMAC and key derivation

`allcrypt.Hmac` mirrors Python's `hmac` objects:

```python
import allcrypt

tag = allcrypt.Hmac(b"Jefe", b"what do ya want for nothing?", "sha256")
assert tag.hexdigest() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

streamed = allcrypt.Hmac(b"key", digestmod="sha512")
streamed.update(b"first ")
streamed.update(b"second")
assert streamed.digest_size == 64
```

`allcrypt.umac` is RFC 4418's UMAC, one shot. The nonce must never
repeat under one key; the value is the RFC's own example:

```python
import allcrypt

tag = allcrypt.umac(b"abcdefghijklmnop", b"bcdefghi", b"abc" * 500, tag_len=8)
assert tag.hex() == "d4cf26ddefd5c01a"
```

The key derivation functions return bytes directly:

```python
import allcrypt

okm = allcrypt.hkdf(bytes([0x0b]) * 22, 42,
                    salt=bytes(range(13)), info=bytes(range(0xf0, 0xfa)))
assert okm.hex().startswith("3cb25f25faacd57a90434f64d0362f2a")

master = allcrypt.tls12_prf(b"pre master secret", b"master secret", b"randoms", 48)
legacy = allcrypt.tls10_prf(b"pre master secret", b"master secret", b"randoms", 48)
assert len(master) == len(legacy) == 48
```

`salt=None` means the all-zero salt from RFC 5869, not "no salt".

NIST SP 800-108's KBKDF takes its PRF by name, `hmac-<hash>` or
`cmac-<block cipher>`. The fixed data is `label || 00 || context ||
[L]_32` with a 32-bit counter before it, which is the layout
python-cryptography's `KBKDFHMAC` gives with `rlen=4, llen=4` and the
counter `BeforeFixed`. Feedback mode chains each block on the last,
starting from `iv`:

```python
import allcrypt

k = allcrypt.kbkdf_counter("hmac-sha256", b"key", 32, label=b"L", context=b"C")
f = allcrypt.kbkdf_feedback("cmac-aes", bytes(16), 32, iv=bytes(16), label=b"L")
assert len(k) == len(f) == 32
```

The Concat KDF (SP 800-56C's one-step KDF over a hash; JWE's ECDH-ES,
OpenPGP's ECDH) and ANSI X9.63's (CMS's ECDH) differ only in where the
counter goes - before the secret, or after it:

```python
import allcrypt

z = bytes(32)
assert allcrypt.concat_kdf(z, 16, other_info=b"info") != \
    allcrypt.x963_kdf(z, 16, shared_info=b"info")
```

RFC 3961's pieces, which the older Kerberos encryption types are made
of, are there separately: `kerberos_nfold`, `kerberos_derive_random`
(DR, over `"des"`, `"3des"` or any block cipher by name),
`kerberos_random_to_key` for `"des"` and `"3des"`, and DES's
string-to-key. The value is RFC 3961's own:

```python
import allcrypt

assert allcrypt.kerberos_nfold(b"012345", 8).hex() == "be072631276b1955"
key = allcrypt.kerberos_des_string_to_key(b"password", b"ATHENA.MIT.EDUraeburn")
assert key.hex() == "cbc22fae235298e3"
```

### From a password

`allcrypt.pbkdf2_hmac` takes the same arguments in the same order as
`hashlib.pbkdf2_hmac`, so it is a drop-in for it:

```python
import allcrypt, hashlib

key = allcrypt.pbkdf2_hmac("sha256", b"correct horse", b"some salt", 1000, 32)
assert key == hashlib.pbkdf2_hmac("sha256", b"correct horse", b"some salt", 1000, 32)

# dklen=None gives the hash's own output length, as hashlib does
assert len(allcrypt.pbkdf2_hmac("sha512", b"pw", b"salt", 10)) == 64
```

**No minimum iteration count is enforced.** RFC 8018 suggested 1000 in
2000; OWASP now says 600,000 for HMAC-SHA-256. A file written in 2009
with 1000 iterations still has to be readable, and a library that
refuses to compute it cannot open the file.
`allcrypt.pbkdf2_recommended_iterations(name)` answers the question for
*new* work; nothing consults it when reading, where the count comes from
the file.

```python
import allcrypt

assert allcrypt.pbkdf2_recommended_iterations("sha256") == 600_000
# an unknown name gets the most conservative answer, never a weak one
assert allcrypt.pbkdf2_recommended_iterations("something else") >= 600_000
```

For new work prefer one of the memory-hard two, which `hashlib` has one
of and `cryptography` the other:

```python
import allcrypt, hashlib

# scrypt: same arguments as hashlib.scrypt, no maxmem ceiling
key = allcrypt.scrypt(b"correct horse", salt=b"some salt", n=16384, r=8, p=1, dklen=32)
assert key == hashlib.scrypt(b"correct horse", salt=b"some salt",
                             n=16384, r=8, p=1, dklen=32, maxmem=1 << 26)

# Argon2id, the RFC 9106 recommendation and the default here
tag = allcrypt.argon2(b"correct horse", b"a sixteen  byte!",
                      memory_kib=1024, passes=1, lanes=1, dklen=32)
assert len(tag) == 32

# and the other two, which are not deprecated - they are different
# trade-offs, not worse ones
d = allcrypt.argon2(b"pw", b"a sixteen  byte!", variant="argon2d",
                    memory_kib=64, passes=1, lanes=1)
i = allcrypt.argon2(b"pw", b"a sixteen  byte!", variant="argon2i",
                    memory_kib=64, passes=1, lanes=1)
assert d != i
```

`secret=` is Argon2's `K`, sometimes called a pepper: held by the
application rather than stored beside the hash, so a stolen database on
its own does not allow guessing.

BLAKE2 is registered like any other hash, and its output length is part
of the function rather than a truncation — so `blake2b_256` is not the
first 32 bytes of `blake2b`:

```python
import allcrypt, hashlib

assert allcrypt.new("blake2b", b"abc").digest() == hashlib.blake2b(b"abc").digest()
assert (allcrypt.new("blake2b_256", b"abc").digest()
        == hashlib.blake2b(b"abc", digest_size=32).digest())
assert allcrypt.new("blake2b_256", b"abc").digest() \
    != allcrypt.new("blake2b", b"abc").digest()[:32]
```

### Windows password hashes

`nt_hash` and `lm_hash` are the two hashes Windows stores (MS-NLMP
3.3.1), as found in a SAM database or `ntds.dit`:

```python
import allcrypt

assert allcrypt.nt_hash("Password").hex() == "a4f49c406510bdcab6824ee7c30fd852"

# LM takes bytes in the OEM code page; ASCII letters are uppercased, and
# anything else is the caller's to uppercase in that code page.
assert allcrypt.lm_hash(b"Password").hex() == "e52cac67419a9a224a3b108f3fa6cb6d"
assert allcrypt.lm_hash("\xe9t\xe9".upper().encode("cp850")) == allcrypt.lm_hash(b"\x90T\x90")
```

A password over fourteen bytes has no LM hash, and `lm_hash` raises
`ValueError` for one rather than hashing its first fourteen bytes.

### Unix `crypt(3)`

`unix_crypt` is a drop-in for the standard library's deprecated
`crypt.crypt`: the setting's prefix chooses the method and carries the
salt, and the full hash string comes back.

```python
import allcrypt

hash = allcrypt.unix_crypt(b"correct horse", "$6$rounds=5000$usesomesalt")
assert hash.startswith("$6$rounds=5000$usesomesalt$")
assert allcrypt.unix_crypt_verify(b"correct horse", hash)
assert not allcrypt.unix_crypt_verify(b"wrong", hash)

# bcrypt, and the NT hash in crypt clothing ($3$, salt ignored).
assert allcrypt.unix_crypt(b"pw", "$2b$08$abcdefghijklmnopqrstuu").startswith("$2b$08$")
assert allcrypt.unix_crypt(b"pw", "$3$") == "$3$$" + allcrypt.nt_hash("pw").hex()
```

To make a new hash without writing the setting by hand, each method has
its own function taking the cost and salt as arguments; leave `salt` out
for a fresh one. They return what `unix_crypt` would for the setting they
build, and raise `ValueError` for a cost out of range or a salt that is
too long or outside `./0-9A-Za-z`, where `unix_crypt` would clamp or cut.

```python
import allcrypt

shadow = allcrypt.unix_crypt_sha512(b"correct horse", rounds=10_000)
assert shadow.startswith("$6$rounds=10000$")
assert allcrypt.unix_crypt_verify(b"correct horse", shadow)

bc = allcrypt.unix_crypt_bcrypt(b"correct horse", cost=8, salt=bytes(16), variant="2b")
assert bc.startswith("$2b$08$......................")

assert allcrypt.unix_crypt_md5(b"pw", salt="abcdefgh").startswith("$1$abcdefgh$")
assert allcrypt.unix_crypt_des(b"pw", salt="ab")[:2] == "ab"
assert allcrypt.unix_crypt_bsdi(b"pw", rounds=725, salt="rasm").startswith("_J9..rasm")
```

The others are `unix_crypt_bigcrypt`, `unix_crypt_sha256`,
`unix_crypt_nt`, `unix_crypt_sha1(password, rounds)` and
`unix_crypt_sun_md5(password, extra_rounds=0)`.

It covers traditional DES, BSDi, bigcrypt, md5crypt, the SHA-crypts,
bcrypt (`$2a`/`$2b`/`$2x`/`$2y`), the NT hash, sha1crypt and Sun's MD5,
matching the system `libcrypt` on all of them. These read the hashes that
already exist; new work wants Argon2 or a high-cost bcrypt.

### The file formats' own derivations

OpenPGP's string-to-key, 7-Zip's AES key, KeePass's AES-KDF and LUKS's
anti-forensic splitter are each one program's construction, kept because
every file that program wrote needs them:

```python
import allcrypt

# Iterated and salted S2K: the count is decoded from the packet's byte.
count = allcrypt.openpgp_s2k_count(0x60)            # 65,536 octets
key = allcrypt.openpgp_s2k("sha1", b"passphrase", b"8 bytes!", count, 16)

# 7-Zip hashes the UTF-16LE password; 0x3f is "no hashing at all".
key = allcrypt.sevenzip_aes_key("pw".encode("utf-16-le"), b"", 4)

key = allcrypt.keepass_aes_kdf(bytes(32), bytes(range(32)), 1000)

# 4000 stripes and SHA-256 are LUKS's defaults.
material = allcrypt.luks_af_split(bytes(32))
assert allcrypt.luks_af_merge(material, 32) == bytes(32)
```

### SHA-3, SHAKE, and the Keccak that is not SHA-3

```python
import allcrypt, hashlib

assert allcrypt.new("sha3_256", b"abc").digest() == hashlib.sha3_256(b"abc").digest()

# SHAKE gives any length you ask for, and a longer ask extends a shorter
assert allcrypt.shake("shake_128", b"abc", 64) == hashlib.shake_128(b"abc").digest(64)
assert allcrypt.shake("shake_128", b"abc", 1000)[:64] == allcrypt.shake("shake_128", b"abc", 64)
```

**`keccak_256` is not `sha3_256`.** They differ in one byte of padding —
`0x01` against `0x06` — and in every bit of their output. The
pre-standard one is what Ethereum means by `keccak256`: every address,
every transaction hash and Solidity's `keccak256()`. Almost no library
ships both, which is the entire reason this one does.

```python
import allcrypt

# an Ethereum function selector is keccak256(signature)[:4]
assert allcrypt.new("keccak_256", b"transfer(address,uint256)").hexdigest()[:8] == "a9059cbb"

# SHA-3 of the same string is something else entirely
assert allcrypt.new("sha3_256", b"transfer(address,uint256)").hexdigest()[:8] != "a9059cbb"
```

## Elliptic curves

`allcrypt.EcKey` is a key pair on a named curve. `allcrypt.curves_available`
lists the names.

```python
import allcrypt

assert "P-256" in allcrypt.curves_available

mine = allcrypt.EcKey.generate("P-256")
theirs = allcrypt.EcKey.generate("P-256")

# SEC1 encoding, which is what goes on the wire: 0x04 || X || Y, or
# 0x02/0x03 || X compressed.
assert len(mine.public_bytes()) == 65
assert len(mine.public_bytes(compressed=True)) == 33
assert mine.curve == "P-256" and mine.key_size == 256

shared = mine.exchange(theirs.public_bytes())
assert shared == theirs.exchange(mine.public_bytes(compressed=True))
assert len(shared) == 32
```

The peer's point is validated before any arithmetic touches it, so a point
that is not on the curve raises rather than producing a secret an attacker
can use to recover the private scalar:

```python
import allcrypt

mine = allcrypt.EcKey.generate("P-256")
bogus = bytearray(allcrypt.EcKey.generate("P-256").public_bytes())
bogus[-1] ^= 1

try:
    mine.exchange(bytes(bogus))
    raise AssertionError("should have raised")
except allcrypt.CryptoError:
    pass
```

An existing scalar can be imported, big endian; anything outside `[1, n)` is
refused:

```python
import allcrypt

original = allcrypt.EcKey.generate("secp256k1")
again = allcrypt.EcKey.from_private("secp256k1", original.private_bytes())
assert again.public_bytes() == original.public_bytes()
```

Keys interoperate with OpenSSL in both directions — `pytests/test_ec.py`
runs ECDH against `cryptography` on every curve.

## X25519

Four functions rather than a key type, because that is the shape RFC 7748
defines: 32 bytes in, 32 bytes out, and no encoding to agree on.

```python
import allcrypt

my_private, my_public = allcrypt.x25519_generate()
their_private, their_public = allcrypt.x25519_generate()

mine = allcrypt.x25519_exchange(my_private, their_public)
assert mine == allcrypt.x25519_exchange(their_private, my_public)
assert len(mine) == 32
assert allcrypt.x25519_public_key(my_private) == my_public
```

The scalar is clamped inside, so it cannot be forgotten, and every 32 byte
string is a valid public key — there is nothing to validate, which is a
property of the curve rather than an omission. What is checked is the
result: a shared secret of all zeros means the peer sent a low-order point
and the secret is a constant anybody can compute, so it raises.

```python
import allcrypt

private, _public = allcrypt.x25519_generate()
low_order = bytes([1] + [0] * 31)

try:
    allcrypt.x25519_exchange(private, low_order)
    raise AssertionError("a low-order point was accepted")
except allcrypt.CryptoError:
    pass

# `x25519_raw` is the primitive without that refusal, which is what the
# RFC's own test vectors are stated in terms of.
assert allcrypt.x25519_raw(private, low_order) == bytes(32)
```

Keys interoperate with OpenSSL in both directions — `pytests/test_x25519.py`
runs the exchange against `cryptography` and pins the RFC 7748 vectors.
A key in a file (RFC 8410's PKCS#8, as `openssl genpkey -algorithm x25519`
writes it) is read by `private_key()`, which hands back the curve's name
and these 32 bytes, since there is no key object to return:

```python
import allcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

pem = x25519.X25519PrivateKey.generate().private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption())
curve, private = allcrypt.private_key(pem)
assert curve == "x25519" and len(private) == 32
_, their_public = allcrypt.x25519_generate()
assert len(allcrypt.x25519_exchange(private, their_public)) == 32
```

An X448 key comes back the same way, as `("x448", private)`.

## X448

The same four functions over Curve448. **Every value is 56 bytes, not
32**, and that is the smaller of the differences:

```python
import allcrypt

my_private, my_public = allcrypt.x448_generate()
their_private, their_public = allcrypt.x448_generate()

mine = allcrypt.x448_exchange(my_private, their_public)
assert mine == allcrypt.x448_exchange(their_private, my_public)
assert len(mine) == 56
assert allcrypt.x448_public_key(my_private) == my_public
```

A key of the wrong width raises rather than being padded, and the error
names the algorithm that wanted 56 — an X25519 key passed to an X448
function is the likeliest mistake here:

```python
import allcrypt

try:
    allcrypt.x448_public_key(bytes(32))
    raise AssertionError("a 32 byte key was accepted")
except allcrypt.CryptoError as reason:
    assert "56 bytes" in str(reason)
```

The rest matches X25519: the scalar is clamped inside (two low bits and
bit 447, which is *not* X25519's rule), every 56 byte string is a valid
public key, and a shared secret of all zeros raises because it means the
peer sent a low-order point.

```python
import allcrypt

private, _public = allcrypt.x448_generate()
low_order = bytes([1] + [0] * 55)

try:
    allcrypt.x448_exchange(private, low_order)
    raise AssertionError("a low-order point was accepted")
except allcrypt.CryptoError:
    pass

assert allcrypt.x448_raw(private, low_order) == bytes(56)
```

`pytests/test_x448.py` runs the exchange against `cryptography` in both
directions, pins RFC 7748's vectors, and checks that a coordinate above
the prime is reduced the way OpenSSL reduces it.

It is also a TLS group, so nothing above is needed to use it over TLS:
`allcrypt_ssl` offers supported group 30 at TLS 1.2 and 1.3, and
`getattr(connection, "named_group")` reports `"x448"` when it was the one
negotiated. No key share is sent for it unsolicited — a server that
prefers it asks, which costs one round trip and no key generation on the
connections where nobody wants it.

## EdDSA: Ed25519 and Ed448

Five functions rather than a key type, for the same reason X25519 has
four: RFC 8032 defines byte strings, not objects.

```python
import allcrypt

assert allcrypt.eddsa_curves() == ["ed25519", "ed448"]

private, public = allcrypt.eddsa_generate("ed25519")
assert len(private) == 32 and len(public) == 32
assert allcrypt.eddsa_public_key("ed25519", private) == public

signature = allcrypt.eddsa_sign("ed25519", private, b"a message")
assert len(signature) == 64
assert allcrypt.eddsa_verify("ed25519", public, b"a message", signature)
assert not allcrypt.eddsa_verify("ed25519", public, b"other", signature)
```

`eddsa_verify` returns `False` for a well-formed signature that is wrong
and raises for something that is not a signature at all — the wrong
length, or a public key that is not a point. Collapsing the two is how a
configuration mistake gets reported as a forgery.

**Signing is deterministic**, which is the design rather than a
limitation: there is no nonce to reuse, and ECDSA's requirement for a
fresh random one per signature is what gives up the private key when it is
reused.

```python
import allcrypt

private, _public = allcrypt.eddsa_generate("ed448")
assert (allcrypt.eddsa_sign("ed448", private, b"same")
        == allcrypt.eddsa_sign("ed448", private, b"same"))
```

Ed448 takes a **context** of up to 255 bytes, which separates domains: the
same key and message under two contexts give unrelated signatures, and
neither verifies under the other. Ed25519 has no context in its pure form
and raises rather than ignoring one.

```python
import allcrypt

private, public = allcrypt.eddsa_generate("ed448")
signature = allcrypt.eddsa_sign("ed448", private, b"a message", b"my app")
assert allcrypt.eddsa_verify("ed448", public, b"a message", signature, b"my app")
assert not allcrypt.eddsa_verify("ed448", public, b"a message", signature)

private, _public = allcrypt.eddsa_generate("ed25519")
try:
    allcrypt.eddsa_sign("ed25519", private, b"x", b"ctx")
    raise AssertionError("Ed25519 took a context")
except allcrypt.CryptoError:
    pass
```

`ed25519ctx`, `ed25519ph` and `ed448ph` are refused **by name**, with an
error saying they are different schemes rather than unknown curves — an
alias to the pure variant would produce signatures that verify here and
nowhere else.

Keys and signatures interoperate with OpenSSL in both directions —
`pytests/test_eddsa.py` compares several hundred of them with
`cryptography`, byte for byte rather than merely mutually, which only a
deterministic scheme allows.

## XEdDSA: signing with an X25519 key

Signal's identity key both agrees keys and signs. `xeddsa_sign` takes an
X25519 private key and `xeddsa_verify` its public key; the form is
`signal` (libsignal's, the one Signal uses) or `xeddsa` (the
specification's).

```python
import allcrypt

private, public = allcrypt.x25519_generate()
signature = allcrypt.xeddsa_sign("signal", private, b"a message")
assert allcrypt.xeddsa_verify("signal", public, b"a message", signature)
assert not allcrypt.xeddsa_verify("signal", public, b"another", signature)

# 64 bytes of randomness go into the nonce; passing them reproduces a
# signature, which only a test should do.
z = bytes(64)
assert allcrypt.xeddsa_sign("xeddsa", private, b"m", z) == \
       allcrypt.xeddsa_sign("xeddsa", private, b"m", z)
```

## NaCl: secretbox, box and sealed boxes

NaCl's constructions and libsodium's additions, byte for byte with
libsodium. Every function takes the construction last:
`"xsalsa20poly1305"` (NaCl's, the default) or `"xchacha20poly1305"`
(libsodium's). Both use a 24 byte nonce, long enough to draw at random
for every message.

```python
import allcrypt

key = allcrypt.random_bytes(32)
nonce = allcrypt.random_bytes(24)
boxed = allcrypt.secretbox_encrypt(key, nonce, b"attack at dawn")
assert len(boxed) == 16 + 14          # the tag, then the ciphertext
assert allcrypt.secretbox_decrypt(key, nonce, boxed) == b"attack at dawn"

tampered = boxed[:-1] + bytes([boxed[-1] ^ 1])
try:
    allcrypt.secretbox_decrypt(key, nonce, tampered)
    raise AssertionError("a tampered box opened")
except allcrypt.CryptoError:
    pass
```

A box is the same thing under a key two X25519 key pairs agree on.
`box_beforenm` is that key, for a session of many boxes without an
exchange per message:

```python
import allcrypt

alice, alice_public = allcrypt.box_keypair()
bob, bob_public = allcrypt.box_keypair()
nonce = allcrypt.random_bytes(24)

boxed = allcrypt.box_encrypt(bob_public, alice, nonce, b"hi bob", "xchacha20poly1305")
assert allcrypt.box_decrypt(alice_public, bob, nonce, boxed, "xchacha20poly1305") == b"hi bob"

key = allcrypt.box_beforenm(alice_public, bob, "xchacha20poly1305")
assert key == allcrypt.box_beforenm(bob_public, alice, "xchacha20poly1305")
assert allcrypt.secretbox_decrypt(key, nonce, boxed, "xchacha20poly1305") == b"hi bob"
```

A sealed box needs only the recipient's public key. It carries a fresh
ephemeral key, so anybody can make one; it says nothing about the sender.

```python
import allcrypt

private, public = allcrypt.box_seed_keypair(bytes(range(32)))
sealed = allcrypt.box_seal(public, b"anonymous")
assert len(sealed) == 48 + 9
assert allcrypt.box_seal_open(public, private, sealed) == b"anonymous"
```

**`"xchacha20poly1305"` here is not the AEAD `"xchacha20-poly1305"`.**
The box authenticates the ciphertext alone, with no additional data and
no lengths, and starts the payload at keystream byte 32. Asking a box for
the AEAD's name raises and says so.

The rest of libsodium's set: `kx_seed_keypair` and
`kx_client_session_keys` / `kx_server_session_keys` (two session keys,
one per direction), `nacl_auth` (HMAC-SHA-512-256), `nacl_sign` and
`nacl_sign_open` (the signature followed by the message), and
`ed25519_public_to_x25519` / `ed25519_private_to_x25519`:

```python
import allcrypt

client, client_public = allcrypt.kx_seed_keypair(bytes(32))
server, server_public = allcrypt.kx_seed_keypair(bytes([1] * 32))
rx, tx = allcrypt.kx_client_session_keys(client_public, client, server_public)
assert allcrypt.kx_server_session_keys(server_public, server, client_public) == (tx, rx)

seed, ed_public = allcrypt.eddsa_generate("ed25519")
signed = allcrypt.nacl_sign(seed, b"message")
assert allcrypt.nacl_sign_open(ed_public, signed) == b"message"
x_private = allcrypt.ed25519_private_to_x25519(seed)
assert allcrypt.x25519_public_key(x_private) == allcrypt.ed25519_public_to_x25519(ed_public)
```

## Finite-field Diffie-Hellman

`allcrypt.DhGroup` is the other Diffie-Hellman: a prime modulus and a
generator, which is what a server too old for elliptic curves sends. Two
standard groups are built in, and any group can be given as bytes.

```python
import allcrypt

group = allcrypt.DhGroup.modp(2048)          # RFC 3526 group 14
assert group.bits == 2048

my_private, my_public = group.generate_key_pair()
their_private, their_public = group.generate_key_pair()

mine = group.shared_secret(my_private, their_public)
assert mine == group.shared_secret(their_private, my_public)
assert len(mine) == 256                      # padded to the width of p
```

Every value is big-endian bytes padded to the width of the modulus, which
is what OpenSSL produces and what makes the two directly comparable. TLS
1.0-1.2 then strip the leading zeros again for the premaster secret, so
that rule has a method of its own rather than being the default:

```python
import allcrypt

# A group small enough that short secrets are common. Do not use one.
p = (2 ** 128 - 159).to_bytes(16, "big")
group = allcrypt.DhGroup(p, b"\x02")

peer = group.public_key((12345).to_bytes(16, "big"))
for exponent in range(2, 4000):
    private = exponent.to_bytes(16, "big")
    secret = group.shared_secret(private, peer)
    if secret[0] == 0:
        assert group.tls_premaster(private, peer) == secret.lstrip(b"\x00")
        break
```

Three peer public values are always refused, because each one makes the
shared secret something the other side already knows — and each completes
a key exchange in an implementation that does not check:

```python
import allcrypt

group = allcrypt.DhGroup.modp(1024)
p = int.from_bytes(group.p, "big")

for bad in (0, 1, p - 1):
    try:
        group.validate_peer(bad.to_bytes(128, "big"))
        raise AssertionError(f"{bad} was accepted")
    except allcrypt.CryptoError:
        pass
```

`check_prime(rounds)` raises if the modulus is composite. It costs several
full-width exponentiations, which is why nothing calls it for you — but a
composite modulus makes the shared secret computable by whoever chose it
while every other check passes. See [pitfalls.md](pitfalls.md) §3b.

## ElGamal

`allcrypt.ElGamalKey` is OpenPGP algorithm 16 — the `elg` half of the
`dsa/elg` keypairs GnuPG made by default for years. Those keys are still
in keyrings and those messages are still in archives, and **OpenSSL
dropped ElGamal while `cryptography` never had it**, so this is the only
way to read them from Python.

```python
import allcrypt

group = allcrypt.DhGroup.modp(1024)
key = allcrypt.ElGamalKey.generate(group)

# OpenPGP's framing: PKCS#1 v1.5 inside the raw scheme. A ciphertext is
# `c1 || c2`, so twice the modulus width.
sealed = key.public_key().encrypt(b"from an old keyring")
assert len(sealed) == 2 * key.size
assert key.decrypt(sealed) == b"from an old keyring"

# A secret key file carries the private exponent; the public value is
# recomputed rather than trusted.
same = allcrypt.ElGamalKey.from_private(group, key.private_bytes)
assert same.public_bytes == key.public_bytes
assert same.decrypt(sealed) == b"from an old keyring"
```

Signing is available and comes with a warning. **GnuPG withdrew ElGamal
signing in 2003**: to make it fast it used a short nonce, and a short
nonce in the signature equation recovers the private key. That was one
implementation's choice of nonce rather than a flaw in the equation, and
signing is here because old signatures still need verifying.

```python
import allcrypt

group = allcrypt.DhGroup.modp(1024)
key = allcrypt.ElGamalKey.generate(group)
digest = allcrypt.new("sha256", b"a message").digest()

signature = key.sign(digest)                 # r || s
assert key.public_key().verify(digest, signature)
assert not key.public_key().verify(bytes(32), signature)
```

Every decryption failure raises the same message, deliberately — saying
which check failed turns the key into a decryption oracle. That is
Bleichenbacher's attack, and it is about the padding check rather than
about the trapdoor underneath it, so ElGamal is as exposed to it as RSA.

## ECDSA

Signing takes an already computed digest, which is the shape protocols need,
and `digestmod` names the hash that produced it:

```python
import allcrypt

key = allcrypt.EcKey.generate("P-256")
digest = allcrypt.sha256(b"the message").digest()

signature = key.sign(digest, digestmod="sha256")
assert len(signature) == 64                      # r || s
assert key.verify(digest, signature)

# Deterministic (RFC 6979): the same digest gives the same bytes, every time,
# with no random source involved.
assert key.sign(digest, digestmod="sha256") == signature
```

A verifier only needs the public point:

```python
import allcrypt

key = allcrypt.EcKey.generate("P-256")
digest = allcrypt.sha256(b"the message").digest()
signature = key.sign(digest)

public = allcrypt.EcPublicKey("P-256", key.public_bytes())
assert public.verify(digest, signature)
assert not public.verify(allcrypt.sha256(b"something else").digest(), signature)
```

`verify` returns False for a signature that is well formed and wrong, and
raises for one that is not a signature at all — the wrong length, say. Both
mean do not trust it, but they are different bugs, and a caller that catches
`CryptoError` and treats it as valid has written the second one.

Signatures interoperate with OpenSSL in both directions:
`pytests/test_ec.py` has OpenSSL verify ours across five hashes and every
curve, and verifies OpenSSL's with ours.

## Ed25519 keys and certificates

`EddsaKey` is the key pair. **It signs messages, not digests**: EdDSA
hashes internally, so there is nothing to compute in advance.

```python
import allcrypt

key = allcrypt.EddsaKey.generate("ed25519")
signature = key.sign(b"a message")
assert len(signature) == 64
assert key.verify(b"a message", signature)
assert key.curve == "ed25519"
```

`private_key()` returns one for an RFC 8410 PEM or DER key, alongside
the `EcKey` and `RsaKey` it already returned:

```python
import allcrypt

generated = allcrypt.EddsaKey.generate("ed25519")
assert isinstance(generated, allcrypt.EddsaKey)
assert len(generated.private_bytes()) == 32
```

A CA can issue Ed25519 certificates, and a `TlsServer` can present one.
A `TlsClient` takes an `EddsaKey` as `client_key` too:

```python
import allcrypt

ca = allcrypt.CertificateAuthority("my CA", "20260101000000Z",
                                   "20270101000000Z", key_type="ed25519")
assert ca.key_type == "ed25519"
certificate, private = ca.issue("example.test",
                                "20260101000000Z", "20270101000000Z")
key = allcrypt.EddsaKey.from_private("ed25519", private)
allcrypt.verify_chain([certificate], [ca.certificate], 1780000000)
```

**An EdDSA key works at TLS 1.3 and 1.2**, as a server or a client
certificate. At 1.2 a server with one negotiates an ECDHE_ECDSA suite
(RFC 8422 section 2 covers EdDSA there); a client offering only
RSA-authenticated suites gets `handshake_failure`. Before 1.2 there is
no EdDSA: a server refuses, and a client answers a certificate request
with an empty Certificate.

`tls_signature_schemes()` lists what the client offers. Both `ed25519`
and `ed448` are there:

```python
import allcrypt

offered = allcrypt.tls_signature_schemes()
assert "ed25519" in offered
assert "ed448" in offered
```

## VKO — the GOST key agreement

RFC 7836 section 4.3, on the GOST curves. It is **not** ECDH with a hash
on the end: a nonce both sides know goes into the scalar, and the output
is Streebog over *both* coordinates written little endian.

```python
import allcrypt

mine = allcrypt.EcKey.generate("gost256-a")
theirs = allcrypt.EcKey.generate("gost256-a")
ukm = b"a nonce both sides know"

key = mine.vko(theirs.public_bytes(), ukm, 256)
assert key == theirs.vko(mine.public_bytes(), ukm, 256)
assert len(key) == 32
assert key != mine.exchange(theirs.public_bytes())    # not ECDH
```

`digest_bits` is 256 or 512 and follows the **key size**, not the curve.
A zero or empty UKM is refused: it makes the scalar zero and the point
the identity, which every pair of keys agrees on.

### The cofactor, on two curves

There is one place where two implementations that are each correct
disagree, and it has to be chosen rather than defaulted.

RFC 7836 writes the scalar as `m/q · UKM · x mod q`, where `m/q` is the
cofactor. **OpenSSL's GOST engine leaves it out** — `VKO_compute_key`
computes `BN_mod_mul(X, ukm, priv, order)` and nothing else. On the seven
curves with a cofactor of one the two are the same number; on
`gost256-tc26-a` and `gost512-c`, where it is four, they are different
points, and no published vector settles which is right.

```python
import allcrypt

mine = allcrypt.EcKey.generate("gost512-c")
theirs = allcrypt.EcKey.generate("gost512-c")
ukm = b"a nonce both sides know"

spec = mine.vko(theirs.public_bytes(), ukm, 512, "as-specified")
other = mine.vko(theirs.public_bytes(), ukm, 512, "without-cofactor")
assert spec != other                      # cofactor four, so they differ
assert mine.vko(theirs.public_bytes(), ukm, 512) == spec   # the default

# On a curve with cofactor one - which is every other one - the choice
# changes nothing at all.
a = allcrypt.EcKey.generate("gost256-a")
b = allcrypt.EcKey.generate("gost256-a")
assert (a.vko(b.public_bytes(), ukm, 256, "as-specified")
        == a.vko(b.public_bytes(), ukm, 256, "without-cofactor"))
```

**Use the default.** `"as-specified"` is RFC 7836's reading and it is
also what OpenSSL's GOST engine computes, which this library's own TLS
key exchange now uses too. `"without-cofactor"` matches no
implementation known here; it exists because the distinction is real on
those two curves, and it is what the tests use to show the difference is
being measured rather than assumed.

That was not always the answer. The engine appeared to omit the
cofactor, a `"as-deployed"` reading was added to match it, and the TLS
key exchange was pointed at it — which would have derived a key no peer
shares on `gost256-tc26-a` and `gost512-c`. Asking the engine rather
than reading it settled the matter; see [pitfalls.md](pitfalls.md) §7o.
The old name is refused with an error saying so rather than aliased,
because it meant "what the equipment does" and named the one reading the
equipment does not.

## SM2

GB/T 32918, over `sm2p256v1`. `EcKey` and `EcPublicKey` grow four
methods; everything else about them is unchanged.

**They take the message, not a digest.** SM2 signs `SM3(Z_A || M)` where
`Z_A` binds the signer's identity and the curve, so there is no digest a
caller could compute in advance.

```python
import allcrypt

key = allcrypt.EcKey.generate("sm2p256v1")
signature = key.sm2_sign(b"message digest")
assert len(signature) == 64                       # r || s
assert key.sm2_verify(b"message digest", signature)
assert key.public_key().sm2_verify(b"message digest", signature)

ciphertext = key.public_key().sm2_encrypt(b"sixteen byte msg")
assert len(ciphertext) == 65 + 32 + 16            # C1 || C3 || C2
assert key.sm2_decrypt(ciphertext) == b"sixteen byte msg"
```

The identity defaults to GB/T 32918.2's `1234567812345678`. Pass a
different one and the signature is over that identity instead:

```python
import allcrypt

key = allcrypt.EcKey.generate("sm2p256v1")
signature = key.sm2_sign(b"hello", b"ALICE123@YAHOO.COM")
assert key.sm2_verify(b"hello", signature, b"ALICE123@YAHOO.COM")
assert not key.sm2_verify(b"hello", signature)     # the default ID
```

### Talking to OpenSSL

`sm2_encrypt_der` and `sm2_decrypt_der` use the
`SEQUENCE { x1, y1, C3, C2 }` form `openssl pkeyutl` reads and writes.
Signatures are `r || s` here and a `SEQUENCE { r, s }` there;
`pytests/test_sm2.py` has the twelve lines that convert between them.

**Pass `distid` explicitly on the OpenSSL side.** Its command line
defaults to an *empty* identity where the standard's default is
`1234567812345678`, so `openssl pkeyutl -sign ... -rawin -digest sm3`
with no `-pkeyopt distid:` produces a signature that fails here unless
you verify with `id=b""`. That is a real interoperability trap and not a
bug on either side; the test file asserts it in both directions so it
stays visible.

## DSA

`allcrypt.DsaKey` is FIPS 186-4's DSA with RFC 6979's deterministic
nonces. Signatures are DER, over the message hashed with `hash`, which
is what a certificate or a TLS ServerKeyExchange carries:

```python
import allcrypt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa

# A DSA key file, read and used. Both PKCS#8 and the traditional
# "DSA PRIVATE KEY" are read.
theirs = dsa.generate_private_key(2048)
pem = theirs.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption())
key = allcrypt.private_key(pem)
assert isinstance(key, allcrypt.DsaKey) and key.key_size == 2048

signature = key.sign(b"to an old switch", "sha256")
theirs.public_key().verify(signature, b"to an old switch", hashes.SHA256())
assert key.verify(b"to an old switch", signature, "sha256")
```

DSA certificates are verified by `verify_chain` and by `TlsClient`,
which reaches DHE_DSS servers at TLS 1.0 to 1.2. **The group is held to
`min_rsa_bits`**, which defaults to 2048, and most DSA keys in the field
are 1024 bit: pass `min_rsa_bits=1024` to reach one, as for an old RSA
key. `DsaKey.generate(l=2048, n=256)` makes a fresh group, which takes
seconds.

## RSA

```python,ignore
import allcrypt

# Slow and of unpredictable duration - it searches for primes. Do it in
# advance rather than inside a request.
key = allcrypt.RsaKey.generate(2048)
public = key.public_key()

ciphertext = public.encrypt(b"a short message")
assert key.decrypt(ciphertext) == b"a short message"

digest = allcrypt.sha256(b"a message").digest()
signature = key.sign(digest, digestmod="sha256")
assert public.verify(digest, signature, digestmod="sha256")
assert len(signature) == key.size
```

That block is `,ignore` because generating a key on every documentation
check would make the build slow; `pytests/test_rsa.py` runs the same code.

Encryption is randomised, so the same message gives different bytes each
time. Signing is not — PKCS#1 v1.5 signature padding has no randomness in
it — so the same digest always gives the same signature, and OpenSSL
produces byte-identical output for the same key.

`key.decrypt` raises the same `CryptoError` for every kind of failure, on
purpose: telling the peer whether it was the padding or the length that was
wrong is Bleichenbacher's attack. Do not catch it and report the difference.

OAEP (RFC 8017 7.1) takes the hash that sets the seed and hashes the
label, and MGF1's hash, which defaults to the same one; JOSE's
`RSA-OAEP` is SHA-1 for both and `RSA-OAEP-256` SHA-256 for both:

```python,ignore
ciphertext = public.encrypt_oaep(b"a short message", "sha256", label=b"context")
assert key.decrypt_oaep(ciphertext, "sha256", label=b"context") == b"a short message"
sha1 = public.encrypt_oaep(b"for RSA-OAEP", "sha1", "sha1")
```

A wrong label, a wrong hash and a corrupted ciphertext all raise the one
message, for the same reason as above and more so: Manger's attack
needs only to learn whether the decrypted block began with a zero, and
takes about a thousand queries.

Until there is an ASN.1 encoder, keys move as raw numbers:

```python,ignore
import allcrypt

key = allcrypt.RsaKey.generate(1024)
numbers = key.numbers                      # n, e, d, p, q, dp, dq, qinv
same = allcrypt.RsaKey.from_primes(numbers["p"], numbers["q"])
assert same.numbers == numbers

public = allcrypt.RsaPublicKey(numbers["n"])      # e defaults to 65537
assert public.key_size == 1024
```

`from_primes` derives the CRT parameters rather than accepting them, so a
key file with inconsistent parameters cannot be loaded into a state that
leaks. It also refuses a composite where a prime should be — it checks that
the key round trips before returning it.

## Certificates

```python,ignore
import allcrypt, time

certificate = allcrypt.Certificate(der)
print(certificate.subject)              # 'CN=example.test'
print(certificate.to_dict()["subjectAltName"])
assert certificate.matches_hostname("example.test")

# Leaf first, as a TLS peer sends it. Raises with the reason on any failure.
allcrypt.verify_chain([leaf_der, intermediate_der], [root_der],
                      now=int(time.time()), hostname="example.test")
```

`to_dict()` is shaped like `ssl.getpeercert()` where the fields line up —
`subject`, `issuer`, `subjectAltName`, `version`, `serialNumber`,
`notBefore`, `notAfter` — with the rest of what a certificate carries added:
`isCA`, `pathLen`, `keyUsage`, `extendedKeyUsage`, `publicKeyType` and
`unrecognisedCritical`.

`verify_chain` raises rather than returning False, and the message says
which check failed. "certificate verify failed" with no reason is the
hardest error in the ecosystem to debug, and there is no reason to
reproduce it.

`now` is a parameter rather than read from the clock, so verification is
reproducible and a test can sit at any point in time.

The knobs exist because talking to old servers is the point of this
library. They are off by default:

```python,ignore
import allcrypt, time

allcrypt.verify_chain(chain, roots, now=int(time.time()),
                      hostname="old.example.test",
                      allow_sha1=True,          # SHA-1 signatures
                      allow_md5=True,           # MD5 signatures
                      min_rsa_bits=1024)        # a small key
```

Parsing is strict, and deliberately stricter than some other libraries: a
duplicate extension, a non-minimal DER length, or a name with an embedded
NUL all raise. Those are the shapes an attacker uses to make two parsers
disagree about what a certificate says.

### Revocation

`verify_chain` takes CRLs as DER. Nothing here fetches one — no socket is
opened anywhere in this library — so get the bytes yourself and pass
them in.

```python,ignore
import allcrypt, time

for uri in allcrypt.crl_distribution_points(leaf_der):
    print(uri)                      # fetch these yourself

allcrypt.verify_chain([leaf_der, intermediate_der], [root_der],
                      now=int(time.time()), hostname="example.test",
                      crls=[crl_der],
                      require_revocation=False)
```

Every certificate in the chain is checked, not only the leaf: a revoked
*intermediate* is the case revocation exists for.

`crl_status` answers about one certificate on its own, and returns
**three** values rather than a boolean:

```python,ignore
status, detail = allcrypt.crl_status(leaf_der, issuer_der, [crl_der],
                                     int(time.time()))
# status is "revoked", "not_revoked" or "unknown"
```

`"unknown"` is not `"not_revoked"`. No CRL, a stale one, one from the
wrong signer, one covering the wrong part of the space — all of those
are unknown, and every way of getting a revocation check wrong turns one
into the other, always in the direction of a revoked certificate looking
clean. A boolean cannot say this, which is why there is not one.

`require_revocation=True` makes unknown a failure. It is off by default,
because with it on and no CRLs supplied every chain fails — right for a
machine issuing money, wrong for one that has to reach a box whose
distribution point stopped answering in 2014. A revoked certificate is
refused either way.

### OCSP

An OCSP response answers about one certificate, where a CRL lists
everything. `verify_chain` takes both, and consults OCSP first because
it is normally fresher.

```python,ignore
import allcrypt, os, time

for url in allcrypt.ocsp_responders(leaf_der):
    print(url)                      # POST the request here yourself

nonce = os.urandom(16)
request = allcrypt.ocsp_request(leaf_der, intermediate_der, "sha1", nonce)

# ... send `request`, get `response_der` ...

allcrypt.verify_chain([leaf_der, intermediate_der], [root_der],
                      now=int(time.time()), hostname="example.test",
                      ocsp=[response_der], ocsp_nonce=nonce,
                      crls=[crl_der])
```

Responses need no labelling: each is matched to a certificate by its
CertID, so a stapled one and a fetched one can go in together.

**Send a nonce if you can.** It is the only defence against a replayed
response — without one, a captured "good" stays valid until its
nextUpdate, which is how a revoked certificate stays usable.

`ocsp_status` answers about one certificate on its own, with the same
three values `crl_status` gives:

```python,ignore
status, detail = allcrypt.ocsp_status(leaf_der, intermediate_der,
                                      response_der, int(time.time()),
                                      nonce=nonce)
# status is "revoked", "not_revoked" or "unknown"
```

The responder answering `unknown` is not the certificate being fine: it
means the responder cannot speak for it, which is what a responder for
a different CA says about yours. It comes back as `"unknown"`.

**Name constraints are enforced and have no knob.** A CA carrying a
nameConstraints extension may only issue for the names it says, and
`verify_chain` refuses a chain that leaves the subtree — naming the
offending name in the message. This is what makes adding a private root
safe: without it, trusting a company's internal CA means trusting it for
every name on the internet. There is no flag to turn it off, because a
CA that says what it may issue for is making a promise the relying party
is the only one who can keep.

## Trusted roots

```python,ignore
import allcrypt, time

store = allcrypt.TrustStore.system()
print(len(store), "roots from", store.source)

allcrypt.verify_chain([leaf_der, intermediate_der], store.roots,
                      now=int(time.time()), hostname="example.test")
```

`TrustStore.system()` reads the platform's own store: the CA bundle files on
unix, the ROOT certificate store on Windows. Nothing is bundled in the
library, so the roots follow the system's updates.

It raises if nothing usable was found, rather than returning an empty store.
An empty store silently becomes "trust nothing" two calls later, and that
looks like a network problem rather than a configuration one.

`store.skipped` is how many entries were found but could not be parsed. It
should be zero; a store that quietly dropped most of its roots looks exactly
like one that worked. `store.skipped_reasons` says *why*, for the first
sixteen — the count on its own cannot distinguish a malformed certificate
from a parser that is too strict, and those have opposite remedies. Each
reason names the entry by DER length and the head of its SHA-256, since a
certificate that did not parse has no subject to quote.

For a pinned deployment or a test, load roots explicitly:

```python,ignore
import allcrypt

store = allcrypt.TrustStore.from_file("/etc/ssl/certs/ca-certificates.crt")
store = allcrypt.TrustStore.from_directory("/etc/ssl/certs")

store = allcrypt.TrustStore()
store.add_der(root_der)
store.add_pem(open("our-ca.pem").read())
```

PEM is available on its own:

```python
import allcrypt

text = allcrypt.pem_wrap(b"\x01\x02\x03")
assert allcrypt.pem_certificates(text) == [b"\x01\x02\x03"]
assert allcrypt.pem_certificates(allcrypt.pem_wrap(b"x", label="PRIVATE KEY")) == []
```

## TLS

`allcrypt.TlsClient` is a TLS 1.2 client. It holds no socket: you feed it
the bytes that arrived and send the bytes it produces, which is what lets
Python own the connection while the protocol lives in Rust.

Key exchange is static RSA or ephemeral ECDH over P-256, P-384 and P-521, with an
RSA or ECDSA certificate; the record layer does AES-CBC with HMAC or
AES-GCM. The default selection prefers the GCM suites, which is what a
server built this decade will choose.

```python,ignore
import allcrypt, socket, time

roots = allcrypt.TrustStore.system()
client = allcrypt.TlsClient("example.test", roots, now=int(time.time()))

sock = socket.create_connection(("example.test", 443))
while client.handshaking:
    data = client.take_outgoing()
    if data:
        sock.sendall(data)
    client.push_incoming(sock.recv(16384))
    client.process()          # raises with the reason on any failure

print(client.version(), client.cipher())
client.write(b"GET / HTTP/1.0\r\n\r\n")
sock.sendall(client.take_outgoing())
```

`process()` raises `CryptoError` with the reason rather than returning a
status, and the connection stays failed afterwards. A connection that
failed and then carried on is the bug the state machine is written against.

Afterwards the connection says what actually happened, so a caller does not
have to remember what it configured:

```python,ignore
client.version()                    # 'TLSv1.3'
client.cipher()                     # ('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'modern', 256)
client.named_group                  # 'secp256r1', or None for a static RSA exchange
client.certificate_verified         # True
client.encrypt_then_mac             # True on a CBC suite; AEAD suites carry no separate MAC
client.extended_master_secret       # True - RFC 7627 was negotiated
client.peer_certificates            # the chain, leaf first, as DER
```

`named_group` is worth asking for: the suite name says ECDHE but not which
curve, and the curve is the part that decides the strength. P-256 and P-384
are offered, strongest first, and P-521 after them for a server that has
nothing else; the server chooses.

The default range is TLS 1.2 to TLS 1.3, and the version is negotiated the
way each end understands. A TLS 1.3 hello says 1.2 in its own version
field forever — middleboxes drop anything higher — and offers 1.3 in the
`supported_versions` extension, so a 1.2 server sees a hello it
understands and answers normally. To pin one end:

```python,ignore
allcrypt.TlsClient(host, roots, now=now, max_version="TLSv1.2")
allcrypt.TlsClient(host, roots, now=now, min_version="TLSv1.3")
```

### Session resumption

A TLS 1.3 server hands out session tickets after the handshake. Keep
them and hand them back, and the next connection skips the certificate,
the signature and a round trip.

```python,ignore
import allcrypt

client = allcrypt.TlsClient("example.test", roots, now=now)
# ... handshake, then read: the tickets arrive under the application
# keys, so they come with or after the first data.
tickets = client.take_tickets()

later = allcrypt.TlsClient("example.test", roots, now=now,
                           tickets=tickets[:1])
# ... handshake ...
assert later.resumed
assert later.peer_certificates == []    # the PSK authenticates instead
```

**A ticket is key material.** Anybody with one can resume the
connection it came from, and anybody who can rewrite one chooses the
key for a connection that will then appear to have resumed. Store them
where only the owner can read.

**Offer each ticket once.** `take_tickets` takes rather than copies for
that reason: offering one twice lets a passive observer link the two
connections, which is exactly what the ticket's obfuscated age exists
to prevent.

A resumed connection has **no certificate** — the pre-shared key
authenticates the server, because only the peer that ran the original
handshake could derive the same key. So an empty `peer_certificates` on
a resumed connection is normal rather than a failure, and `resumed`
is what to ask first.

Tickets that cannot be used are dropped silently: one for another host,
one past its lifetime, one from a suite whose hash no offered 1.3 suite
uses. One that will not *decode* is an error, because that means the
storage is wrong and quietly not resuming would look like a server
declining.

### Early data (0-RTT)

If a ticket allows it, the first bytes can go out with the ClientHello,
before the handshake finishes:

```python,ignore
client = allcrypt.TlsClient("example.test", roots, now=now,
                            tickets=tickets[:1],
                            early_data=b"GET / HTTP/1.1\r\n\r\n")
# ... handshake ...
if not client.early_data_accepted:
    client.write(b"GET / HTTP/1.1\r\n\r\n")   # your decision, not ours
```

**Read that `if` before using any of this.** Early data is unlike every
other byte on the connection in two ways, and neither is a detail:

* It is **not forward secret.** It is encrypted under a key derived from
  a PSK that has been sitting in the caller's storage since the previous
  connection. Anyone who later obtains that ticket reads the early data
  from a capture; nothing sent after the handshake has that property.
* It can be **replayed.** It is sent before the server has said a word,
  so there is nothing fresh from the server in the keys. A captured
  flight, resent byte for byte, is as valid the second time. `ReplayGuard`
  below bounds how often that works and cannot make it impossible —
  RFC 8446 8.2 says so plainly, and so does this library.

So the rule is the one the RFC gives: put in early data only what may
happen twice. A `GET` of a static page, yes. Anything that changes
something, no.

The bytes are **not resent automatically** when the server declines,
because resending them is the same decision as sending them in the first
place. `early_data_accepted` is how to tell, and it is false both when
the server declined and when no ticket allowed the attempt.

On the server side it is off by default and needs two things together:

```python,ignore
guard = allcrypt.ReplayGuard()          # ONE, shared by every connection

server = allcrypt.TlsServer(chain, key,
                            now=int(time.time()),
                            session_tickets=2,
                            ticket_key=configured_40_bytes,
                            max_early_data=16384,
                            replay_guard=guard)
```

`max_early_data` without `replay_guard` raises. There is no default for
it: a register built per connection has seen nothing and would refuse
nothing, and that is exactly the mistake a default would hide. Pass one
object and keep it for the life of the process.

What arrived is read separately:

```python,ignore
server.accepted_early_data      # whether any was accepted at all
server.take_early_data()        # the bytes, and *not* in take_incoming()
```

The separation is the point. A caller reading these out of the same
buffer as everything else has no way to tell which bytes were the
replayable, non-forward-secret ones — and that distinction is the only
thing that makes 0-RTT a decision rather than a free round trip.

A server refuses early data, quietly and with a full handshake instead,
when the ticket was not the client's first identity, when the ticket
allows none, when the server name differs from the one the ticket was
issued under, after a HelloRetryRequest, or when the register has seen
that exact flight. None of those is reported: every reason is something
about the ticket, and telling the client which one is telling an
attacker how close they got.

### Authenticating with a client certificate

If the server asks, at TLS 1.2 or 1.3, hand the client an identity:
a chain leaf first as DER, and the key that goes with it.

```python,ignore
client = allcrypt.TlsClient("example.test", roots, now=now,
                            client_certificate=[leaf_der],
                            client_key=allcrypt.EcKey.from_private(
                                "P-256", scalar_bytes))
```

The two go together; either alone raises, because a chain with no key
cannot sign and a key with no chain has nothing to send — and both
would otherwise surface much later as a handshake failure.

A client that has one **does not volunteer it**: nothing is sent unless
the server asks, which is the reason the request exists at all. A
client that was asked and has nothing sends an *empty* certificate
rather than staying silent, because the server is waiting for the
message either way; what happens next is then the server's decision.

The knobs for talking to something old are named arguments, all of them off
by default:

```python,ignore
import allcrypt, time

client = allcrypt.TlsClient(
    "old.example.test", roots, now=int(time.time()),
    ciphers="legacy",          # adds RC4, 3DES and the rest
    min_rsa_bits=1024,         # a key nobody would issue today
    allow_sha1=True,           # a certificate signed with SHA-1
    verify=False)              # no certificate check at all
```

### Accepting a certificate the default refuses

Four ways, narrowest first. Reach for the first that works, not the one
that always works.

**1. Trust that certificate.** For a box with a self-signed certificate
this is not a relaxation at all — it is authentication, against a
certificate you chose, and a man in the middle still fails because it does
not have that key. It is what people usually reach for `verify=False` to
do:

```python,ignore
import allcrypt, allcrypt_ssl

roots = allcrypt.TrustStore()
roots.add_pem(open("device-cert.pem").read())

# or, through the ssl-shaped interface
context = allcrypt_ssl.create_default_context(cafile="device-cert.pem")
```

**2. `allow_expired`** — the dates, and nothing else. The most common
reason a box that has sat in a rack since 2011 cannot be reached is that
its certificate ran out and there is nobody left to reissue it. The chain,
the signatures and the name are all still checked:

```python,ignore
context = allcrypt_ssl.create_default_context(cafile="device-cert.pem")
context.allow_expired = True
```

**3. `check_hostname = False`** — the name, and nothing else. The chain is
still verified. This is what you want when connecting by IP address, or to
a box whose certificate names something it no longer answers to:

```python,ignore
context = allcrypt_ssl.create_default_context(cafile="device-cert.pem")
context.check_hostname = False
```

**4. `verify_mode = CERT_NONE`** — nothing is checked at all:

```python,ignore
context = allcrypt_ssl.create_default_context()
context.check_hostname = False      # required before verify_mode, as in `ssl`
context.verify_mode = allcrypt_ssl.CERT_NONE
```

`verify=False` is sometimes the only way to reach something, and this
library will not pretend otherwise — but `certificate_verified` reports it
afterwards, and the certificate is still there to look at through
`getpeercertchain()`. Not verifying is different from not caring, and the
three narrower options above exist so that "I could not connect" rarely
has to become "I check nothing".

`create_legacy_context()` sets `allow_sha1`, `allow_md5`, `allow_expired`
and a 1024-bit RSA floor together, since a box old enough to need one
usually needs the rest.

### Three accessors `ssl` does not have

On a connected socket or `SSLObject`:

- `cipher_strength()` — `"modern"`, `"weak"`, `"broken"` or `"insecure"`.
  This library keeps suites others have deleted, so a caller that enabled
  one should be able to ask what it got.
- `getpeercertchain()` — the whole chain rather than the leaf, which is
  what somebody needs when a connection failed and the question is why.
- `named_group()` — the key exchange group that was negotiated, as this
  library names it: `"x25519"`, `"x448"`, `"secp256r1"`, the hybrid
  post-quantum `"X25519MLKEM768"` and so on, or `None` for a key
  exchange that has no group. RSA key transport has
  none, and neither do the GOST suites, which is why
  `check_live.py --gost` prints `group=None`.

`named_group()` is the only way to tell an X448 connection from an X25519
one after the fact, since both are offered - or a post-quantum connection
from a classical one. A client allowed TLS 1.3 offers X25519MLKEM768
first (RFC 10024: ML-KEM-768 combined with X25519); one capped at
`TLSv1.2` offers no hybrid group at all.

### A certificate authority, for the proxy

`allcrypt.CertificateAuthority` issues leaf certificates on demand.
This is the other half of a terminating proxy: it reads the host out of
the client's SNI, issues a certificate for that host on the spot, and
presents it — so the browser is talking to something it trusts while
the proxy talks to the old box behind it however it has to.

**Which means the whole thing rests on a browser trusting this CA.**
That is a decision somebody makes deliberately, once, by installing
`certificate_pem`. There is no way to make it less serious than it is:
anything holding this key can impersonate any site to anyone who
installed it. Generate it on the machine that will use it, keep the key
there, and remove the certificate from the store when you are done.

```python,ignore
import allcrypt, time

def stamp(offset):
    return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(time.time() + offset))

ca = allcrypt.CertificateAuthority("allcrypt proxy CA",
                                   stamp(-86400), stamp(365 * 86400))
open("proxy-ca.pem", "w").write(ca.certificate_pem)   # install this
open("proxy-ca.key", "wb").write(ca.private_bytes)    # and guard this

# Then, per connection, once SNI has said which host:
leaf, key = ca.issue(server.server_name, stamp(-86400), stamp(86400))
connection = allcrypt.TlsServer([leaf], allcrypt.EcKey.from_private("P-256", key))
```

The validity window is required rather than defaulted, because a proxy
CA that outlives its usefulness is a key somebody forgot they installed.

A fresh key per issuance, not one reused across hosts: the cost is one
P-256 generation, which is microseconds, and the alternative is a single
key whose compromise is every site the proxy ever served. Serial numbers
are sixteen random bytes for a related reason — a counter is state that
has to survive restarts, and a repeated serial from one issuer is what a
browser caches and then refuses.

`host` may be a name or an IP address and they take different forms of
subjectAltName. A verifier asked about an address looks only at
`iPAddress` entries, so an address written as a `dNSName` matches
nothing and says nothing about why; `issue` decides from the string.

To keep a CA between runs, store the two halves and put them back:

```python,ignore
ca = allcrypt.CertificateAuthority.from_parts(
    open("proxy-ca.key", "rb").read(), open("proxy-ca.der", "rb").read())
```

The certificate is not derived from the key, and a mismatched pair is
**refused**: a CA signing with a key its certificate does not name
issues chains that verify against nothing, with both halves looking
correct on their own.

### The server side

`allcrypt.TlsServer` is the mirror of `TlsClient`: TLS 1.2 and 1.3,
sans-I/O, bytes in and bytes out. It exists because of a shape this library keeps
running into — a box on the network that only speaks something old, and
a browser that will not speak to it. Nothing can be interposed inside
Chromium, which links BoringSSL statically, so the way across is a local
proxy that terminates TLS on the browser's side and speaks the old
thing on the other. This is the termination half.

It takes a certificate chain as DER, leaf first, and the matching key:

```python,ignore
import allcrypt

key = allcrypt.EcKey.generate("P-256")      # or allcrypt.RsaKey.generate(2048)
server = allcrypt.TlsServer([leaf_der, intermediate_der], key)

while server.handshaking:
    server.push_incoming(sock.recv(16384))
    server.process()                        # raises with the reason
    data = server.take_outgoing()
    if data:
        sock.sendall(data)

print(server.version(), server.cipher())
```

**At TLS 1.2** the key decides which suites are reachable: an EC key can
only authenticate `ECDHE_ECDSA`, an RSA key can do `ECDHE_RSA` and RSA
key transport. A suite the key cannot authenticate is never chosen, so a
client offering both gets the one that will work rather than a handshake
that fails at the signature.

**At TLS 1.3 a suite names neither.** It is an AEAD and a hash, nothing
more, and what authenticates is the signature scheme — so all three 1.3
suites work with either kind of key. An RSA key signs with PSS there,
because RFC 8446 forbids PKCS#1 v1.5 in a CertificateVerify, and an EC
key signs with the scheme that names its own curve.

The ceiling is 1.3 and the floor is 1.2. A server that has to reach
something older lowers the floor deliberately:

```python,ignore
server = allcrypt.TlsServer(chain, key, min_version="TLSv1.0",
                            ciphers="legacy")
```

**Session tickets** are off by default and need two things together — a
clock, and a key to seal them under:

```python,ignore
server = allcrypt.TlsServer(chain, key,
                            now=int(time.time()),
                            session_tickets=2,
                            ticket_key=configured_40_bytes)
```

`now` is supplied rather than read, the same way `TlsClient` takes it:
nothing below the command line calls the system clock, so a handshake is
reproducible in a test. A server needs it *only* for tickets — to stamp
them and to refuse them once they expire — which is why `session_tickets`
defaults to zero. A server that does not know the time cannot expire a
ticket, and one that issues tickets it will honour forever is worse than
one that issues none.

`ticket_key` is forty bytes: eight of key name, thirty-two of key. Leave it
out and each connection generates its own, which seals tickets nothing else
can open — safe, and useless for resumption, which is between *two*
connections. A deployment that wants tickets to survive a restart, or to
work across a fleet behind a load balancer, generates forty bytes out of
band and configures the same ones everywhere. It is a key: protect it like
a private key, and rotating it is the only way to end the sessions it has
sealed.

Two tickets is the usual number, and not for redundancy: a client opening
several connections at once would otherwise offer one ticket twice, and a
PSK offered twice is linkable across those connections.

**Client certificates** are two decisions rather
than one:

```python,ignore
server = allcrypt.TlsServer(chain, key,
                            now=int(time.time()),
                            request_client_certificate=True,
                            require_client_certificate=True,
                            client_roots=client_ca_store)
```

`request_client_certificate` asks. On its own that is *optional* client
authentication: a client with nothing suitable answers with an **empty**
certificate — which is the correct answer, not a failure — and the
handshake completes. So "we asked" is not "we got", and the only thing
that says which happened is:

```python,ignore
server.peer_certificates            # [] when nothing arrived
server.client_certificate_verified  # False when no roots were configured
```

`require_client_certificate` refuses the empty answer. It needs
`request_client_certificate`; requiring without asking is a
contradiction rather than a stricter setting, so it raises.

`client_roots` is a **separate trust store** from the one a client would
use to judge a server, and deliberately so: the set of CAs allowed to
issue identities for a service is almost never the public web PKI, and
reusing the system store here would let anything holding a certificate
from any public CA authenticate. Leave it out and the chain is not
judged at all — the client's signature over the transcript is still
checked, so it does hold the key for the certificate it sent, and
recognising that key is left to the application. Setting it needs `now`,
since at zero every certificate is outside its validity window.

The leaf must permit client authentication: a certificate whose
`extendedKeyUsage` says `serverAuth` only is refused. Without that
check, a service could authenticate *as a client* to any peer trusting
the same CA, using the key it already holds.

Client certificates work at **TLS 1.2 as well as 1.3**, through the same
three arguments — but they are a different message and a different
signature underneath rather than a version flag: at 1.2 the
CertificateVerify signs the raw concatenation of every handshake
message, RSA signs it with PKCS#1 v1.5 rather than PSS, and the order is
reversed.

They work at **TLS 1.0 and 1.1** as well, which is a third
construction again: no signature-algorithm list to negotiate, a bare
signature with no algorithm field, RSA over 36 bytes of MD5 and SHA-1
with no DigestInfo, and ECDSA over the SHA-1 half alone.

What is **not** there yet: post-handshake authentication. Early data and
OCSP stapling have their own sections above.

**`ciphers` is in the server's own order of preference.** The first
suite in it that the client also offered is the one chosen. A server
that should honour the client's order passes a different list; there is
no flag, because "whose order decides" is a property of the list and a
boolean beside it would be a second place to look.

```python,ignore
server = allcrypt.TlsServer(chain, key,
                            ciphers="ECDHE-ECDSA-AES128-GCM-SHA256,"
                                    "ECDHE-ECDSA-AES128-SHA")
```

Afterwards, and during, it says what happened:

```python,ignore
server.server_name              # 'example.test', from SNI - or None
server.offered_alpn             # ['h2', 'http/1.1'] - everything offered
server.selected_alpn_protocol() # 'h2', or None
server.version()                # 'TLSv1.2'
server.cipher()                 # (name, strength, key bits)
server.encrypt_then_mac         # RFC 7366 was agreed
server.extended_master_secret   # RFC 7627 was agreed
```

`server_name` is the one a proxy is here for. It is the only thing in a
TLS handshake that says which host the client thinks it is reaching, and
it arrives before anything has to be decided — so a proxy reads it,
issues a certificate for that name, and only then answers. A client
connecting by IP address sends none, and `None` is an answer rather than
a failure.

**ALPN is negotiated only if you give the server a list**, and the list
is **in the server's own order of preference**:

```python,ignore
server = allcrypt.TlsServer(chain, key, alpn=["h2", "http/1.1"])
```

The first protocol in *that* list which the client also offered is the
one chosen. There is no flag to prefer the client's order, for the same
reason there is none for `ciphers`: whose order decides is a property of
the list.

Empty — the default — answers nothing, and a client that offered `h2`
falls back to HTTP/1.1. That is the safe default for a proxy, where
answering `h2` would promise a protocol the thing behind it may not
speak: the list is what the *application* can do, not what this code can
parse.

With nothing in common the handshake goes on without the extension,
which is what RFC 7301 3.1 allows and what is right when the protocol is
settled some other way — a URL scheme, a port. `require_alpn=True`
makes it a `no_application_protocol` alert instead, for an application
that has no other way to tell. It is ignored when the client offered no
ALPN at all: a client that did not ask has not disagreed with anybody.

A client offers protocols the same way, and the server chooses:

```python,ignore
client = allcrypt.TlsClient("example.test", roots, now=now,
                            alpn=["h2", "http/1.1"])
# ... handshake ...
client.selected_alpn_protocol()     # 'h2', or None
```

The server may choose against the client's order — the order is a
preference, not an instruction. What the client does enforce is that the
answer is one of the protocols it offered, and that it names exactly one
(RFC 7301 4.2); either is otherwise an application speaking a protocol
it never agreed to.

**What is not there:** post-handshake authentication. That is absent
rather than half-done, and `max_version` is a limit the server applies
rather than a description of what it happens to implement — pinning it
to `"TLSv1.2"` really does refuse a 1.3-only client.

## OCSP stapling

A server hands out a cached OCSP response about its own certificate, so
the client does not have to ask a responder (RFC 6066 §8). Nothing here
fetches one — the operator does that out of band, on a schedule, and
hands over the DER:

```python,ignore
server = allcrypt.TlsServer(chain, key,
                            ocsp_response=cached_der)
```

It goes out **only if the client asked**, and it is not checked on the
way out: a server judging a statement about its own certificate would be
checking its own homework, and a response the server disliked is one the
client still has to judge for itself.

On the client it is requested by default, and what arrived is readable:

```python,ignore
client = allcrypt.TlsClient("example.test", roots, now=now)
# ... handshake ...
client.stapled_ocsp            # the DER, or None
```

**What it is allowed to decide is asymmetric, and that asymmetry is the
whole of revocation.** A staple that says *revoked* fails the handshake
whatever else is configured — that is an answer, signed by somebody the
certificate's own issuer delegated to. A staple that settles nothing —
absent, unreadable, about another certificate, signed by nobody we trust
— costs nothing unless you ask for it to:

```python,ignore
client = allcrypt.TlsClient("example.test", roots, now=now,
                            require_stapled_ocsp=True)
```

Off by default, because most servers staple nothing and hard-failing
would refuse most of the web. It is **separate from the CRL policy**:
nothing here fetches a CRL, so requiring one would refuse every chain,
while this one is satisfied by a response the server stapled.

No nonce is sent and none is required. A stapled response is cached by
the server and shared between connections, so demanding a fresh nonce
would defeat stapling rather than add freshness; what bounds a replayed
staple is its own `nextUpdate`.

## Private keys

`allcrypt.private_key` reads one from PEM text or DER bytes and hands
back an `EcKey` or an `RsaKey`, whichever the file holds:

```python,ignore
import allcrypt

key = allcrypt.private_key(open("server.key", "rb").read())
server = allcrypt.TlsServer(chain, key)
```

PKCS#8 (`PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`) and PKCS#1 (`RSA PRIVATE
KEY`) are all read, and **the bytes decide rather than the label**:
`openssl` will put a SEC1 body under a `PRIVATE KEY` header if asked the
wrong way, and a file that works everywhere else has to work here. A file
holding a certificate and a key together — the usual deployment shape —
is fine; the certificate is skipped.

### Encrypted keys

Most private keys on a disk are encrypted. Pass the passphrase:

```python,ignore
key = allcrypt.private_key(open("server.key", "rb").read(), b"hunter2")
```

Three families are understood, which between them cover everything
`openssl pkcs8 -topk8` has ever written, and Java's two:

| Family | Where | What it is |
|---|---|---|
| **PBES2** | RFC 8018 A.4 | PBKDF2 and a named cipher in CBC — AES-128/192/256, 3DES, DES, RC2. The PRF may be any of HMAC-SHA-1 through SHA-512; **absent means SHA-1**, which is how older files are written |
| **PBES1** | RFC 8018 A.3 | PBKDF1 and a 64-bit cipher, in six MD2/MD5/SHA-1 × DES/RC2 combinations |
| **PKCS#12** | RFC 7292 B | A third key derivation entirely, with 3DES, RC2 or RC4. This is what every `.p12` holds and what `-v1` still writes by default |
| **JKS** | Sun, 1.3.6.1.4.1.42.2.17.1.1 | A 20-byte salt and a keystream of chained SHA-1 digests over the password (UTF-16 big endian), with a SHA-1 check: what `keytool` puts in a `.jks` |
| **JCEKS** | Sun, 1.3.6.1.4.1.42.2.19.1 | `PBEWithMD5AndTripleDES`: two iterated MD5 chains over the halves of an 8-byte salt give 3DES's key and IV. The password is printable ASCII |

That list is longer than what the machine writing this can still
*produce*. On OpenSSL 3.0.13, five of the PBES1 and PKCS#12 schemes plus
`-v2 des-cbc` and `-v2 rc2-cbc` need `-provider legacy` and silently
write an empty file without it; `python-cryptography` 46 refuses
`pbeWithSHA1AndDES-CBC` and `pbeWithMD5AndRC2-CBC` outright with
"Unknown key encryption algorithm". The keys did not become unreadable —
the readers did. `tests/keys/` holds a pinned fixture for every scheme
for exactly that reason.

Without a password an encrypted key is refused **by name** rather than
as "unsupported", because the remedy is a passphrase and not a different
file. With the wrong password the PKCS#7 padding check refuses it: none
of these schemes is authenticated, so a wrong key decrypts to random
bytes and that check is the only thing between a wrong password and a
confident wrong answer. It catches one about 255 times in 256, and the
DER parse that follows catches almost all of the rest.

A password given for a key that is *not* encrypted is ignored, so a
caller need not know which of its files used one.

One encoding trap worth knowing, because it only shows up outside
ASCII: PBES1 and PBES2 hash the password **bytes**, while the PKCS#12
schemes hash a **BMPString** — UTF-16 big endian with a terminating NUL.
Pass the password as UTF-8 bytes and the library does the conversion
where it applies. The empty password is genuinely ambiguous in the
PKCS#12 family (OpenSSL's API given no password hashes zero bytes; the
`openssl` command and others hash the two NUL bytes of an empty
string), so both are tried.

Writing goes the other way. `encrypt_private_key` takes a PKCS#8 key
(DER or `PRIVATE KEY` PEM) and any of the schemes above but Java's:
a PBES2 cipher by name, or `pbe-...` for PBES1 and the PKCS#12 PBEs.
`encryption_schemes()` lists them, and `private_key_encryption` reads
a file's scheme, salt, count and IV without the password. Given those,
the same key encrypts to the same file - which is how the tests check
the writer against OpenSSL's files.

```python
import allcrypt

key = allcrypt.encrypt_private_key(
    b"-----BEGIN PRIVATE KEY-----\n"
    b"MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n"
    b"-----END PRIVATE KEY-----\n",
    b"hunter2", "aes-256-cbc", iterations=1000, pem=True)
assert key.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
assert allcrypt.private_key_encryption(key)["scheme"] == "aes-256-cbc"
assert allcrypt.private_key(key, b"hunter2").private_bytes()[:2] == bytes.fromhex("d4ee")
```

PBES2's PRF defaults to SHA-256 and its count to
`pbkdf2_recommended_iterations`; the older schemes default to OpenSSL's
2048. The salt is random (16 bytes for PBES2, 8 for the rest) unless
given, and so is PBES2's IV.

The CRT parameters in an RSA file (`dP`, `dQ`, `qInv`) are **derived from
the primes rather than read**. A file whose stored `dP` disagrees with
`d mod (p-1)` would otherwise sign wrongly in a way nothing here checks.

An EC key naming two different curves — one in the PKCS#8 algorithm
identifier and another inside the key — is malformed (RFC 5915 §3 says
the inner one must be omitted there) and is an error rather than a guess
about which half the writer meant.

## The `ssl` module shim

`allcrypt_ssl` is `TlsClient` in the shape of the standard library's `ssl`
module, so code that already speaks `SSLContext` can reach a server through
this stack without being rewritten. `http.client`, `urllib3` and `asyncio`
all work unchanged.

```python,ignore
import allcrypt_ssl, http.client

context = allcrypt_ssl.create_default_context()
connection = http.client.HTTPSConnection("example.test", context=context)
connection.request("GET", "/")
print(connection.getresponse().status)
```

`wrap_socket` and `wrap_bio` are both there — the second is the memory-BIO
path asyncio drives, and the one the sans-I/O core plugs into directly:

```python,ignore
import allcrypt_ssl, ssl, socket

context = allcrypt_ssl.create_default_context(cafile="root.pem")

raw = socket.create_connection(("example.test", 443))
with context.wrap_socket(raw, server_hostname="example.test") as sock:
    print(sock.version(), sock.cipher())

incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
obj = context.wrap_bio(incoming, outgoing, server_hostname="example.test")
```

### Using it as `ssl`

`allcrypt_ssl` carries every name the standard library's `ssl` exports,
so it can stand in for it wholesale:

```python,ignore
import sys
import allcrypt_ssl
sys.modules["ssl"] = allcrypt_ssl

import requests                       # and urllib3, http.client, smtplib...
requests.get("https://example.test/")
```

That is measured rather than asserted: `test_every_name_the_standard_
library_exports_is_here` compares `dir()` on both modules, and
`pytests/test_ssl_dropin.py` drives `http.client`, `urllib3` and
`requests` against a real server while checking `backend_in_use` stays
`"allcrypt"` - because a shim that quietly fell back to OpenSSL would
pass every other assertion.

Most of those names are facts about TLS and are re-exported unchanged.
A few are answered differently, and each would be a lie the other way
round:

| | `ssl` | here | why |
|---|---|---|---|
| `HAS_SSLv3` | `False` | `True` | this Python's OpenSSL has no SSLv3; our record layer does |
| `HAS_SSLv2` | `False` | `False` | not implemented, and not coming |
| `HAS_NPN` | varies | `False` | replaced by ALPN and removed |
| `OPENSSL_VERSION` | `"OpenSSL 3.0.13 …"` | `"allcrypt 0.1.0"` | see below |
| `CHANNEL_BINDING_TYPES` | `["tls-unique"]` | `+ "tls-exporter"` | RFC 9266, which 1.3 needs |

`OPENSSL_VERSION` not looking like an OpenSSL version is deliberate and
load bearing: urllib3 checks `OPENSSL_VERSION.startswith("OpenSSL ")`
before relying on OpenSSL-specific behaviour, so telling the truth is
also what stops it assuming things about this stack.

### Options and verify flags are honoured, not stored

`OP_*` and `VERIFY_*` are not data. A caller sets one expecting
behaviour, so a flag that is accepted and ignored turns "I asked for no
session tickets" into "I got session tickets". Every flag here either
changes what this stack does, is already true of it, or raises - and
two methods say which:

```python,ignore
import allcrypt_ssl

context = allcrypt_ssl.create_default_context()
context.options |= allcrypt_ssl.OP_NO_TICKET

context.option_report()
# {'OP_NO_TICKET': 'acted on',
#  'OP_NO_COMPRESSION': 'already true',      # nothing here compresses
#  'OP_ENABLE_MIDDLEBOX_COMPAT': 'already true',
#  'OP_CIPHER_SERVER_PREFERENCE': 'acted on',
#  'OP_NO_SSLv3': 'acted on',
#  'OP_ALL': 'not applicable'}               # workarounds for other stacks

context.verify_flags_report()
# {'VERIFY_X509_TRUSTED_FIRST': 'already true'}
```

The `OP_NO_*` version flags describe a *set* while this stack offers a
*range*, so narrowing at either end works and a hole in the middle is
refused by name rather than approximated:

```python,ignore
import allcrypt_ssl

context = allcrypt_ssl.create_default_context()
context.minimum_version = allcrypt_ssl.TLSVersion.TLSv1
context.options |= allcrypt_ssl.OP_NO_TLSv1_2      # ValueError: gap in the middle
```

Three flags cannot be honoured at all and raise when set:
`VERIFY_CRL_CHECK_LEAF` and `VERIFY_CRL_CHECK_CHAIN`, because nothing in
this library fetches a CRL - pass what you fetched to
`allcrypt.verify_chain` instead, where *unknown* is a third answer
rather than a silent pass - and `VERIFY_ALLOW_PROXY_CERTS`, because
proxy certificates are not parsed here.

### Channel binding

What SCRAM and the other SASL mechanisms mix into their exchange so an
authentication cannot be relayed onto a different TLS connection - the
reason LDAP, PostgreSQL and IMAP clients ask for it.

```python,ignore
import allcrypt_ssl, socket

context = allcrypt_ssl.create_default_context()
raw = socket.create_connection(("example.test", 443))
with context.wrap_socket(raw, server_hostname="example.test") as tls:
    binding = tls.get_channel_binding("tls-exporter")   # 32 bytes at TLS 1.3
```

`tls-unique` (RFC 5929) and `tls-exporter` (RFC 9266) belong to
different versions and **neither is a fallback for the other**:
`tls-exporter` is `None` below TLS 1.3, where RFC 9266 does not define
it. Both are checked against OpenSSL's own values for the same
connection rather than against ourselves.

### Connecting without a hostname

`server_hostname` is required only while something is going to check it,
which is the rule `ssl` itself has. Turn `check_hostname` off and there
is nothing to check a name against, so `None` is allowed and **no SNI is
sent** — which is how you reach a box by its address, or something whose
certificate you are not going to judge:

```python,ignore
import allcrypt_ssl, socket

context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = allcrypt_ssl.CERT_NONE

raw = socket.create_connection(("192.0.2.10", 443))
with context.wrap_socket(raw, server_hostname=None) as sock:
    print(sock.version())           # and sock.server_hostname is None
```

With `check_hostname` left on it is still refused, with the standard
library's own message — `check_hostname requires server_hostname`.

The extension is **absent** rather than present and empty. RFC 6066
section 3 defines its body as a non-empty list of names and forbids a
literal address in one, so an empty `server_name` is malformed; servers
split between answering with an alert and answering with their default
certificate, and from the client both look like the server's choice.

A socket may also be wrapped before it is connected, as with `ssl`:

```python,ignore
import allcrypt_ssl, socket

context = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = allcrypt_ssl.CERT_NONE

sock = context.wrap_socket(socket.socket(), server_hostname=None)
sock.connect(("192.0.2.10", 443))   # the handshake happens here
```

### Which stack you are actually on

A shim that quietly is not the thing it claims to be is worse than no shim,
so this one says which backend it used, on the context and on the
connection:

```python,ignore
import allcrypt_ssl

allcrypt_ssl.BACKEND                # 'allcrypt', or 'stdlib' if the module is missing
context.backend_in_use              # 'allcrypt' after a connection, or 'stdlib'
getattr(sock, "backend_in_use", "stdlib")
```

The connection-level attribute is the one that survives being handed to
`http.client`, where the context is out of reach. A standard library socket
has no such attribute, which is why the `getattr` default is the answer.

Client connections from SSLv3 to TLS 1.3 go through allcrypt. **The
server side** falls back to the standard library, and says so rather than
failing.

That fallback is a gap in **this shim**, not in the library —
`allcrypt.TlsServer` speaks 1.2 and 1.3 — and the thing in the way is not
TLS at all: `load_cert_chain` reads a private key out of a PEM file, and
this library has no private-key parser yet.

### Resumption and ALPN

TLS 1.3 brings the two attributes a 1.3 context is expected to have:

```python,ignore
import allcrypt_ssl, socket

context = allcrypt_ssl.create_default_context(cafile="root.pem")

raw = socket.create_connection(("example.test", 443))
with context.wrap_socket(raw, server_hostname="example.test") as sock:
    sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
    while sock.recv(65536):
        pass
    session = sock.session          # read it when the connection is done

raw = socket.create_connection(("example.test", 443))
with context.wrap_socket(raw, server_hostname="example.test",
                         session=session) as sock:
    assert sock.session_reused
```

**Read the session at the end, not at the handshake.** A TLS 1.3
NewSessionTicket arrives under the *application* keys, so one read
immediately after the handshake is usually empty. The object fills in as
the tickets arrive, so holding on to it works too — it is the
connection's own session, not a snapshot.

`allcrypt_ssl.SSLSession` is **not** an `ssl.SSLSession`. That type has no
public constructor — it is handed out by OpenSSL and belongs to OpenSSL's
connection state — so a shim could not return one, and passing one here is
a `TypeError` rather than a silent full handshake.

**It holds key material.** Each ticket inside is enough to resume the
connection it came from. Each is also offered **once**: resumption takes a
ticket out of the session rather than copying it, because a PSK offered
twice lets a passive observer link the two connections.

A resumed 1.3 connection sends **no certificate** — the pre-shared key
authenticates the server — so `getpeercert()` coming back empty on one is
normal rather than a failure, and `session_reused` is what to ask first.

ALPN works through `set_alpn_protocols`, which sets both backends because
which one a connection will use is not settled until `wrap_socket`:

```python,ignore
context.set_alpn_protocols(["h2", "http/1.1"])
# ... connect ...
sock.selected_alpn_protocol()       # 'h2', or None
```

### Reaching something old

The knobs from `TlsClient` are attributes on the context, all named and all
defaulting to the strict value:

```python,ignore
import allcrypt_ssl

context = allcrypt_ssl.create_legacy_context()
context.set_ciphers("legacy")       # RC4, 3DES and the rest, by name
context.min_rsa_bits = 1024
context.allow_sha1 = True
context.min_dh_bits = 512           # export-grade DH, on purpose
```

SSLv3 is reachable and is not on this list, because it is not a knob:

```python,ignore
import ssl, allcrypt_ssl

context = allcrypt_ssl.create_legacy_context()
context.minimum_version = ssl.TLSVersion.SSLv3     # a decision, not a floor
```

Nothing lowers the floor to SSLv3 for you — not `create_legacy_context`,
which lowers almost everything else. POODLE is a property of the version
rather than of a suite: SSLv3's CBC padding bytes are unspecified, so a
receiver may not check them, and there is no fix inside the protocol. The
standard library cannot speak it at all on a modern build, so this is the
one place where the shim reaches something the fallback cannot.

`set_ciphers` takes three set names and a list:

| | |
|---|---|
| `"modern"` | nothing broken. The default. |
| `"legacy"` | everything implemented down to `Broken` — RC4, 3DES, single DES, the export grades. |
| `"all"` | that, plus the NULL ciphers. Every suite this library can complete. |
| a comma-separated list | exactly those, in that order, including ones no set offers. |

`"all"` is the widest and is only reachable by asking for it. It used to
be an alias for `"legacy"`, which meant a caller asking for everything
quietly got a set with the NULL ciphers removed — so it now means what it
says. The anonymous key exchanges are still absent from every set, and
that is not a policy: `DH_anon` and `ECDH_anon` are not implemented, and a
selection must not offer a handshake the client cannot finish.

`get_ciphers` says what a selection actually got you, in hello order,
and `tls_suite_names` answers the same question without a context:

```python
import allcrypt, allcrypt_ssl

context = allcrypt_ssl.create_default_context()
modern = [entry["name"] for entry in context.get_ciphers()]
assert modern == allcrypt.tls_suite_names("modern")

context.set_ciphers("legacy")
legacy = [entry["name"] for entry in context.get_ciphers()]
assert set(modern) < set(legacy)

# The registry is wider than any selection: it is the catalogue of what
# TLS has, rather than of what this library has.
assert set(legacy) < set(allcrypt.tls_suites_available)
```

The `name` is this library's registry name, not OpenSSL's, because
several of these suites have no OpenSSL name at all - which is the point
of the library. An unknown name in the list form raises rather than
returning an empty list: an empty list reads as "this selection offers
nothing", and a typo reads as neither.

The export suites need no knob at all — they are `Broken`, so
`set_ciphers("legacy")` reaches them and the default never does. RC2 is
available as an ordinary cipher too, with the one parameter it has:

```python
import allcrypt

key, iv = bytes(range(16)), bytes(8)
ordinary = allcrypt.Cipher("rc2", key).encrypt("cbc", b"12345678", iv)
weakened = allcrypt.Cipher("rc2", key, "40").encrypt("cbc", b"12345678", iv)
assert ordinary != weakened          # a different cipher, not a shorter key
```

That second argument is RC2's effective key length in bits, and it exists
to make a key *weaker* than the key you supplied — 1990s export paperwork,
preserved. TLS's `RC2_CBC_40` is a 16 byte key with 40 effective bits.

`min_dh_bits` is the one knob here that is not about certificates. A DHE
server picks the Diffie-Hellman group by itself and the client's only say
is to accept it or hang up, so this is that say: 2048 by default, lowered
to 512 by `create_legacy_context`. Logjam is the reason there is a floor at
all, and reaching a box that has not been reconfigured since 2003 is the
reason the floor moves. `check_dh_prime = True` adds a primality test of
the server's modulus, which costs more than the key exchange itself and
catches the one attack nothing else would notice.

## XTS, the disk mode

IEEE 1619, adopted by NIST as SP 800-38E. A sector is encrypted under
its own number, and the ciphertext is exactly as long as the plaintext —
which is the constraint the whole design is built around, because a disk
sector has nowhere to put an IV or a tag.

```python
import allcrypt

key = bytes(range(32))                 # two AES-128 keys, end to end
plaintext = b"a sector's worth of bytes, and then some more"

ciphertext = allcrypt.xts_encrypt(key, 1234, plaintext)
assert len(ciphertext) == len(plaintext)
assert allcrypt.xts_decrypt(key, 1234, ciphertext) == plaintext

# The same bytes in another sector encrypt differently. That is the
# entire reason the mode exists.
assert allcrypt.xts_encrypt(key, 1235, plaintext) != ciphertext
```

**It is not authenticated and cannot be.** Anyone who can write to the
storage can replace any block with bytes of their choosing, and
`xts_decrypt` will return plaintext rather than raising. It also leaks
equality: the same plaintext written to the same sector twice gives the
same ciphertext.

Lengths that are not a multiple of sixteen use ciphertext stealing, so
nothing needs padding; under one block there is nothing to steal from
and it raises. The two halves of the key must differ.

```python
import allcrypt

key = bytes(range(64))                 # two AES-256 keys
for length in (16, 17, 31, 32, 33):
    data = bytes(length)
    assert len(allcrypt.xts_encrypt(key, 0, data)) == length

try:
    allcrypt.xts_encrypt(key, 0, bytes(15))
    raise AssertionError("a short data unit was accepted")
except allcrypt.CryptoError:
    pass

try:
    allcrypt.xts_encrypt(bytes(16) * 2, 0, bytes(32))
    raise AssertionError("equal key halves were accepted")
except allcrypt.CryptoError:
    pass
```

Any 128 bit block cipher works — `cipher="camellia"` and
`cipher="sm4"` are XTS modes that exist nowhere else — and the 64 bit
ciphers are refused with an error naming the block size.

`lrw_encrypt` and `lrw_decrypt` are LRW, the mode IEEE P1619 drafted
before XTS, which dm-crypt and TrueCrypt 4 used. The key is the cipher
key and then a 16 byte tweak key; the index counts 16 byte blocks, so a
512 byte sector `n` under dm-crypt's `lrw-benbi` starts at `32 * n + 1`:

```python
import allcrypt

key = bytes(range(32))                 # AES-128, then the tweak key
ciphertext = allcrypt.lrw_encrypt(key, 32 * 7 + 1, bytes(512))
assert allcrypt.lrw_decrypt(key, 32 * 7 + 1, ciphertext) == bytes(512)
```

BitLocker's sectors are `bitlocker_encrypt_sector` and
`bitlocker_decrypt_sector`, by method name - `aes-cbc-elephant-128`,
`aes-cbc-elephant-256`, `aes-cbc-128`, `aes-cbc-256`, `aes-xts-128`,
`aes-xts-256` - with the volume key as dm-crypt takes it (Elephant's CBC
key then its tweak key) and the sector's **byte offset**:

```python
import allcrypt

key = bytes(32)                        # AES-128 CBC key, then the tweak key
sealed = allcrypt.bitlocker_encrypt_sector("aes-cbc-elephant-128", key, 1 << 20, bytes(512))
assert allcrypt.bitlocker_decrypt_sector("aes-cbc-elephant-128", key, 1 << 20,
                                         sealed) == bytes(512)
```

`bitlocker_password_key(password, salt)` and
`bitlocker_recovery_password_key(recovery, salt)` give the key that opens
a protector's copy of the volume master key: 2^20 rounds of SHA-256,
under a second in a release build.

### Wi-Fi

WEP, TKIP and the WPA key hierarchy are here too. `wep_encrypt` /
`wep_decrypt` take the 3-byte IV and the shared key; `tkip_rc4_key`
mixes TKIP's per-frame RC4 key; `michael` is TKIP's MIC; `wpa_psk`,
`wpa_ptk` and `wpa_pmkid` are the key derivations.

```python
import allcrypt

pmk = allcrypt.wpa_psk(b"password", b"IEEE")
assert pmk.hex().startswith("f42c6fc52df0ebef")      # IEEE 802.11i H.4.2
ptk = allcrypt.wpa_ptk("sha1", pmk, bytes(6), bytes([1] * 6), bytes(32), bytes(32), 384)
assert len(ptk) == 48

sealed = allcrypt.wep_encrypt(b"ABCDE", bytes([1, 2, 3]), b"hi")
assert allcrypt.wep_decrypt(b"ABCDE", bytes([1, 2, 3]), sealed) == b"hi"
```

The `wifi` product example opens real captures with these.

## Key wrap

RFC 3394 and RFC 5649: encrypting a key with a key. No IV, no nonce,
nothing random; the same key data under the same key-encryption key
always gives the same bytes, so a wrapped key can be stored, copied and
compared.

```python
import allcrypt

kek = bytes(range(32))
key_to_protect = bytes(range(32, 64))

wrapped = allcrypt.key_wrap(kek, key_to_protect)
assert len(wrapped) == len(key_to_protect) + 8
assert allcrypt.key_unwrap(kek, wrapped) == key_to_protect
assert allcrypt.key_wrap(kek, key_to_protect) == wrapped     # deterministic
```

What replaces the randomness is integrity: a wrapping cannot be altered
undetectably, which is why key wrap needs no MAC beside it.

```python
import allcrypt

kek = bytes(range(32))
wrapped = allcrypt.key_wrap(kek, bytes(32))

altered = bytearray(wrapped)
altered[9] ^= 1
try:
    allcrypt.key_unwrap(kek, bytes(altered))
    raise AssertionError("an altered wrapping unwrapped")
except allcrypt.CryptoError:
    pass
```

RFC 3394 takes whole 64 bit blocks, at least two of them. RFC 5649 takes
any length from one byte up, and is a different algorithm rather than an
option on the first — eight bytes or fewer skips the six passes
entirely.

```python
import allcrypt

kek = bytes(range(24))
try:
    allcrypt.key_wrap(kek, bytes(20))
    raise AssertionError("20 bytes was wrapped by the unpadded form")
except allcrypt.CryptoError:
    pass

wrapped = allcrypt.key_wrap_with_padding(kek, bytes(20))
assert len(wrapped) == 32
assert allcrypt.key_unwrap_with_padding(kek, wrapped) == bytes(20)
assert len(allcrypt.key_wrap_with_padding(kek, b"a key")) == 16
```

CMS's older wraps are here too. RFC 3217's Triple-DES and RC2 wraps
append a SHA-1 checksum, encrypt in CBC under a random IV, reverse
everything and encrypt again; RFC 3211's password recipient wrap formats
the key with its length and check bytes and encrypts it in CBC twice.
Both take randomness, drawn here unless given:

```python
import allcrypt

kek, cek = bytes(range(24)), bytes(range(1, 25))
wrapped = allcrypt.cms_3des_key_wrap(kek, cek)
assert len(wrapped) == 40
# What comes back has DES parity set: each byte's low bit makes its count of ones odd.
with_parity = bytes(b ^ (bin(b).count("1") % 2 == 0) for b in cek)
assert allcrypt.cms_3des_key_unwrap(kek, wrapped) == with_parity
w = allcrypt.pwri_key_wrap("aes", bytes(16), bytes(16), b"a content key")
assert allcrypt.pwri_key_unwrap("aes", bytes(16), bytes(16), w) == b"a content key"
```

The Triple-DES wrap sets DES parity on the key, so what comes back may
differ from what went in by the low bit of some bytes. The RC2 wrap
takes the key-encryption key's effective length; RFC 3217's own example
uses 40 bits, which its text does not say.

## Padding

```python
import allcrypt

c = allcrypt.Cipher("aes", bytes(16))
message = b"a message of awkward length"
ciphertext = c.encrypt("cbc", allcrypt.pad_pkcs7(message, c.block_size), bytes(16))
assert allcrypt.unpad_pkcs7(c.decrypt("cbc", ciphertext, bytes(16)), c.block_size) == message
```

## Telling it what an OID means

Old equipment names things by object identifier, and not always by one
this library carries: a digest from a national standard nobody
vendored, a GOST parameter set on an organisation's own arc, a curve
under a third name. The alternative to editing `src/x509/oids.rs` and
rebuilding is to say what the OID means.

```python
import allcrypt

# A digest, by an OID from a private arc.
allcrypt.register_oid("1.3.6.1.4.1.99999.1.1", hash="gost94")
assert (allcrypt.Hash("1.3.6.1.4.1.99999.1.1", b"abc").hexdigest()
        == allcrypt.Hash("gost94", b"abc").hexdigest())

# A curve parameter set, so a certificate carrying it is readable.
allcrypt.register_oid("1.3.6.1.4.1.99999.3.1", curve="gost256-a")

print(allcrypt.registered_oids())
for name in ["1.3.6.1.4.1.99999.1.1", "1.3.6.1.4.1.99999.3.1"]:
    allcrypt.forget_oid(name)
```

Exactly one of `hash=`, `curve=`, `gost_sbox=` or `curve_parameters=`,
because an OID names one thing.

### A curve this library does not carry

`curve=` above moves a *name*. `curve_parameters=` supplies the curve:

```python
import allcrypt

# Brainpool P-256r1, from RFC 5639 section 3.4. Hex as the document
# prints it; an int works just as well.
allcrypt.register_oid("1.3.36.3.3.2.8.1.1.7", curve_parameters=dict(
    name="brainpoolP256r1",
    p="A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377",
    a="7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9",
    b="26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6",
    gx="8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262",
    gy="547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997",
    n="A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7",
    cofactor=1))

# It is now a curve like any other: by name, and for the OID a
# certificate carries.
key = allcrypt.EcKey.generate("brainpoolP256r1")
assert key.key_size == 256
signature = key.sign(b"\x01" * 32, "sha256")
assert key.public_key().verify(b"\x01" * 32, signature)

allcrypt.forget_oid("1.3.36.3.3.2.8.1.1.7")
```

All eight keys are required, including `cofactor` — a caller who does not
know it does not know the curve, and a guessed `1` turns every cofactor
check into a check of the guess. Numbers may be `int` or hex `str`; in a
string, `0x`, whitespace and `:` are ignored, so a value pasted out of a
specification works. A negative `int` is refused: `a = -3` is how the
documents *describe* these curves and is not what the field element is,
and reducing it would need `p` and silently accept something the caller
may have meant differently.

**The parameters are checked, and every check is one a plausible mistake
passes without:**

| check | what it catches |
| --- | --- |
| `p` prime | over a composite modulus the inverse in the addition formula does not always exist, so most arithmetic works and some silently does not |
| `p` odd, ≥ 5 | `y² = x³ + ax + b` is not the general form in characteristic 2 or 3 |
| `4a³ + 27b² ≠ 0` | a singular curve's points are not a group and its discrete log is easy — every other check here passes on one |
| `G` on the curve | a mistyped coordinate |
| `n` prime **and** `n·G = 0` | `n·G = 0` alone holds for any multiple of the order, so a caller who passed `2·ord(G)` would have a cofactor wrong by two, quietly |
| `n·h` within Hasse's bound | a cofactor that was guessed rather than known |
| `n ≠ p` | an anomalous curve, whose discrete log is efficiently computable |

**What is not checked**, said out loud rather than left as a gap: the
embedding degree, so a curve broken by the MOV/Frey–Rück reduction is
accepted. Establishing a bound on it is not something this can do for a
caller, who is trusting the curve's provenance for that property anyway.
The twist's security is not checked either.

#### Byte order, in one place

The three places a number crosses this boundary, because they are not all
the same and only one of them is a surprise:

| | order |
| --- | --- |
| `curve_parameters=` and `curve_parameters()` | **hex, big-endian**, no `0x`, even number of digits. An `int` is accepted too |
| `public_bytes(False)`, a SEC1 point | `04 \|\| X \|\| Y`, each coordinate **big-endian**, padded to the field width |
| a GOST key in a certificate | **little-endian** coordinates, RFC 9215 §4.3 — the exception, handled inside |
| `gost_sbox=` | 8 rows × 16 **nibble values**, not packed bytes, in the table's own row order |

Hex rather than `int` in the dictionary is deliberate: an integer has no
byte order until something serialises it, and this is the boundary where
that is easiest to get wrong. `int` is accepted for the caller who
computed the values.

#### Reading a parameter set back out

`curve_parameters(name)` is the counterpart of `gost_sbox(name)`: the usual
way to register a parameter set is to read one out and change what differs.

```python
import allcrypt

# A curve, read out of the library and registered under another name, so
# the two can be compared. Registering it under the *same* name is refused
# - the compiled-in table is consulted first, so it would never be reached.
parameters = allcrypt.curve_parameters("secp256k1")
assert parameters["p"] == (
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
assert parameters["a"] == "00" and parameters["b"] == "07"
assert parameters["cofactor"] == "01"

parameters["name"] = "secp256k1-again"
allcrypt.register_oid("1.3.6.1.4.1.99999.8.1", curve_parameters=parameters)

# The same group: one scalar, the same public key.
scalar = bytes(range(1, 33))
assert (allcrypt.EcKey.from_private("secp256k1-again", scalar).public_bytes(False)
        == allcrypt.EcKey.from_private("secp256k1", scalar).public_bytes(False))
allcrypt.forget_oid("1.3.6.1.4.1.99999.8.1")

# An S-box, the same way. Eight rows of sixteen nibbles; each row is a
# permutation of 0..16 and the entries are values, so there is no byte
# order here - only row order.
rows = [list(row) for row in
        allcrypt.gost_sbox("id-Gost28147-89-CryptoPro-A-ParamSet")]
assert len(rows) == 8 and sorted(rows[0]) == list(range(16))

allcrypt.register_oid("1.3.6.1.4.1.99999.8.2", gost_sbox=rows)
key, block = bytes(range(32)), bytes(range(8))
built_in = allcrypt.Cipher("gost", key, "id-Gost28147-89-CryptoPro-A-ParamSet")
copied = allcrypt.Cipher("gost", key, "1.3.6.1.4.1.99999.8.2")
assert (copied.encryptor("ecb").update(block)
        == built_in.encryptor("ecb").update(block))
allcrypt.forget_oid("1.3.6.1.4.1.99999.8.2")
```

**Is the registration path really equivalent to being compiled in?** The
way to find out is to take a curve out of the library and put it back
through this interface. `secp256k1` was deleted from
`ec::curves::by_name`, the module rebuilt, and then:

```text
1. secp256k1 is gone from the library:
   Unknown curve "secp256k1". Known: P-256, P-384, sm2p256v1, gost256-a, ...
2. register it from the parameters read out beforehand:
   [('1.3.132.0.10', 'curve-parameters', 'secp256k1 (256 bit)')]
3. it works, and agrees with OpenSSL:
   public key matches OpenSSL: True
   OpenSSL verified our signature: True
   we verified OpenSSL's signature: True
   issued a certificate OpenSSL reads as: secp256k1
```

Key generation, ECDSA in both directions, and certificate issuance, all on
a curve the library no longer had. That check needs a source edit, so it is
not in the suite;
`test_a_built_in_curve_registered_under_another_name_behaves_identically`
is the part that runs every time, comparing a registered curve against the
built-in one by arithmetic rather than by the numbers matching.

A registered curve is a curve everywhere a built-in one is: by name,
reading a certificate that carries its OID, and **issuing one** —
`CertificateAuthority(..., "brainpoolP256r1")` works, and OpenSSL verifies
what comes out. Issuing refuses if the curve is registered under two OIDs,
because a certificate names one and picking would be choosing for you;
reading is unaffected, since each OID resolves to the same curve. The name
folds the way built-in names do, so case, `_` and spaces do not matter.

`pytests/test_registered_curve.py` registers Brainpool P-256r1 and checks
it against `cryptography` — the public key from the same scalar, ECDSA in
both directions, ECDH from both ends, and a certificate on that curve
becoming readable. That last one is what the registry is for: without the
registration the same certificate's key comes back as unsupported, naming
the OID.

### Your own GOST S-box

`gost_sbox=` is the one registration that carries cryptography rather
than a name, and it is there because **a GOST cipher is its S-box**.
GOST 28147-89 treats the tables as a parameter distributed separately,
so meeting a box with a set of its own is ordinary rather than exotic.

`allcrypt.gost_sbox(name)` reads a table back out, which is how a new
one usually starts:

```python
import allcrypt

rows = [list(row) for row in
        allcrypt.gost_sbox("id-Gost28147-89-CryptoPro-A-ParamSet")]
rows[0] = list(reversed(rows[0]))          # a different cipher now
allcrypt.register_oid("1.3.6.1.4.1.99999.2.1", gost_sbox=rows)

key, block = b"\x01" * 32, b"\x02" * 8
theirs = allcrypt.Cipher("gost", key, "id-Gost28147-89-CryptoPro-A-ParamSet")
ours = allcrypt.Cipher("gost", key, "1.3.6.1.4.1.99999.2.1")
assert ours.encryptor("ecb").update(block) != theirs.encryptor("ecb").update(block)
allcrypt.forget_oid("1.3.6.1.4.1.99999.2.1")
```

The table is checked at registration: eight rows of sixteen, each a
permutation of 0..16. A row that repeats a value is not a permutation -
the round function stops being a bijection and the cipher stops
inverting - and the output would still look like ciphertext, so it is
refused rather than accepted.

### What it will not do

* **It cannot invent an algorithm.** `hash=` names a hash this library
  already implements. What moves is the naming, which is where the
  incompatibilities actually are.
* **It cannot change what a standard OID means.** The compiled-in
  tables are consulted first, so a registration reaches only the OIDs
  this library would otherwise have refused. Registering SHA-256's OID
  as MD5 does nothing.
* It is process-wide and not persisted. A program that needs a
  registration makes it at startup.

## Post-quantum: SLH-DSA

FIPS 205's hash-based signature scheme, formerly SPHINCS+. Twelve parameter
sets; the `f` ones are the cheap ones to generate a key for.

```python
import allcrypt

key = allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")

signature = key.sign(b"a message")
assert key.verify(b"a message", signature)
assert not key.verify(b"a different message", signature)

# The signature is large, and that is the scheme rather than this library.
assert len(signature) == 17088
assert len(key.public_bytes()) == 32
```

`allcrypt.slh_dsa_parameter_sets()` lists all twelve.

### `sign` draws randomness; `sign_deterministic` does not

Both are standard. The hedged one is the default because the failure mode
of the other choice is worse — a *badly* randomised signature, one using a
counter or a timestamp, is worse than a deterministic one:

```python
import allcrypt

key = allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")

assert key.sign(b"m") != key.sign(b"m")                      # fresh each time
assert key.sign_deterministic(b"m") == key.sign_deterministic(b"m")
assert key.verify(b"m", key.sign_deterministic(b"m"))
```

### The context and the pre-hash are part of what gets signed

A **context** is a domain separator. Give one key two jobs and a signature
made for one does not verify for the other:

```python
import allcrypt

key = allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")

signature = key.sign(b"100.00", context=b"invoice")
assert key.verify(b"100.00", signature, context=b"invoice")
assert not key.verify(b"100.00", signature, context=b"refund")
```

A context is at most 255 bytes — its length is written in a single byte —
and a longer one raises rather than being quietly truncated.

**Pre-hashing** signs a digest of the message instead of the message. The
hash function is named in what gets signed, so a SHA-256 signature is not
a SHA3-256 one even though both digests are 32 bytes:

```python
import allcrypt

key = allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")

signature = key.sign(b"a message", prehash="SHA2-256")
assert key.verify(b"a message", signature, prehash="SHA2-256")
assert not key.verify(b"a message", signature, prehash="SHA3-256")
assert not key.verify(b"a message", signature)      # not the pure form either
```

`allcrypt.slh_dsa_pre_hashes()` lists the twelve approved names.

### Keys as bytes

```python
import allcrypt

key = allcrypt.SlhDsaKey.generate("SLH-DSA-SHAKE-128f")

# The public key is the *tail* of the private one, which matters if you are
# writing a key file.
assert key.private_bytes()[32:] == key.public_bytes()

again = allcrypt.SlhDsaKey.from_private("SLH-DSA-SHAKE-128f",
                                        key.private_bytes())
assert again.public_bytes() == key.public_bytes()

# Verifying needs no private half.
public = allcrypt.SlhDsaPublicKey.from_public("SLH-DSA-SHAKE-128f",
                                              key.public_bytes())
assert public.verify(b"m", key.sign(b"m"))
```

`from_private` checks only the length: every byte string of the right
length is a well formed SLH-DSA private key, so whether the public root
inside it matches its seeds is a separate and expensive question.
`recompute_public()` asks it, at the cost of a whole key generation —
worth doing once on a key from somewhere you do not control, pointless on
one this library generated.

### What is not here

There is no PEM or DER encoding for these keys, and no certificate
support: this library has the algorithm, not the not-yet-settled ways of
putting it in a file. `private_bytes()` and `public_bytes()` are the FIPS
205 byte strings, which is what every implementation agrees on.

None of the references the tests use implements SLH-DSA - not
`cryptography`, and not the OpenSSL 3.0 the differential checks run
against - so unlike every other algorithm here there is no second
opinion to compare against. What checks it is NIST's own ACVP validation
data: see [status.md](status.md#post-quantum).

## Post-quantum: ML-KEM

FIPS 203's key encapsulation mechanism: the lattice scheme in
`X25519MLKEM768`. One side publishes an encapsulation key; the other uses
it to make a 32 byte shared secret and a ciphertext, and sends the
ciphertext; the first side recovers the same secret from it.

```python
import allcrypt

# The receiving side.
key = allcrypt.MlKemKey.generate("ML-KEM-768")
published = key.public_bytes()                 # 1,184 bytes

# The sending side has only the published bytes.
their_key = allcrypt.MlKemPublicKey.from_public("ML-KEM-768", published)
shared, ciphertext = their_key.encapsulate()   # keep shared, send ciphertext
assert len(shared) == 32 and len(ciphertext) == 1088

# Back on the receiving side.
assert key.decapsulate(ciphertext) == shared
```

`allcrypt.ml_kem_parameter_sets()` lists the three sets: `ML-KEM-512`,
`ML-KEM-768` and `ML-KEM-1024`.

### A wrong ciphertext is not an exception

```python
import allcrypt

key = allcrypt.MlKemKey.generate("ML-KEM-768")
shared, ciphertext = key.public_key().encapsulate()

altered = bytearray(ciphertext)
altered[0] ^= 1
# No exception: a different secret, which the two sides will disagree on.
assert key.decapsulate(altered) != shared
```

This is FIPS 203's implicit rejection, and it is deliberate: an exception
on a mismatch would tell an attacker which altered ciphertexts decrypt to
the same message, and that is enough to recover the key. Find out whether
the secrets agree the way a protocol does — by using the secret, as a MAC
key or an AEAD key, and seeing whether the other side's message
authenticates. `decapsulate` raises only for a ciphertext of the wrong
length.

### Keys as bytes

```python
import os
import allcrypt

seed = os.urandom(64)                          # d || z
key = allcrypt.MlKemKey.from_seed("ML-KEM-512", seed)

# The same seed always gives the same key, so 64 bytes can be stored in
# place of the 1,632 byte decapsulation key - and is just as secret.
assert allcrypt.MlKemKey.from_seed("ML-KEM-512", seed).private_bytes() \
    == key.private_bytes()

# The encapsulation key is carried *inside* the decapsulation key.
assert key.public_bytes() in key.private_bytes()

again = allcrypt.MlKemKey.from_private("ML-KEM-512", key.private_bytes())
assert again.public_bytes() == key.public_bytes()
```

**Both imports check the key**, as FIPS 203 requires.
`MlKemPublicKey.from_public` refuses a coefficient encoded at or above
`q` — without that, two different byte strings would be the same key —
and `MlKemKey.from_private` refuses a key whose embedded `H(ek)` does not
match its embedded `ek`. Both raise `ValueError`. What no check can tell
is whether the secret part of an imported decapsulation key belongs to
its public part: a mismatched pair decapsulates everything to the
rejection secret. Storing the seed instead avoids the question.

There is no PEM, DER or certificate support for ML-KEM keys, and nothing
on this machine implements ML-KEM to compare against. What checks it is
NIST's ACVP data — 195 cases, 30 of them keys that must be refused — and
`pytests/test_ml_kem.py` reads those itself rather than trusting the Rust
tests' parse.

## Post-quantum: ML-DSA

FIPS 204's lattice signatures. Same shape as `SlhDsaKey` - the external
interface, hedged by default, with a context string and an optional
pre-hash - and a fraction of the size: 2,420 bytes per signature at
`ML-DSA-44` against SLH-DSA's 7,856 at its smallest.

```python
import allcrypt

key = allcrypt.MlDsaKey.generate("ML-DSA-65")
signature = key.sign(b"a message")                 # hedged
assert len(signature) == 3309

public = allcrypt.MlDsaPublicKey.from_public("ML-DSA-65", key.public_bytes())
assert public.verify(b"a message", signature)
assert not public.verify(b"another message", signature)

# Context and pre-hash are part of what is signed.
signed = key.sign(b"a message", b"my protocol v1", "SHA2-512")
assert public.verify(b"a message", signed, b"my protocol v1", "SHA2-512")
assert not public.verify(b"a message", signed, b"my protocol v1")
```

`allcrypt.ml_dsa_parameter_sets()` lists the three sets; the pre-hash
names are `allcrypt.slh_dsa_pre_hashes()`'s, because FIPS 204 and FIPS
205 approve the same twelve.

### Keys as bytes

```python
import os
import allcrypt

seed = os.urandom(32)
key = allcrypt.MlDsaKey.from_seed("ML-DSA-44", seed)
assert key.seed() == seed

# The expanded private key does not contain the public key, but contains
# what it is made from: importing recomputes it.
again = allcrypt.MlDsaKey.from_private("ML-DSA-44", key.private_bytes())
assert again.public_bytes() == key.public_bytes()
assert again.seed() is None
```

**Store the seed if you can.** It is 32 bytes against 2,560 to 4,896,
and it is what FIPS 204 suggests keeping. An expanded private key is
checked on import - its `t0` must be the one its `s1` and `s2` give, and
its `tr` must be the hash of the public key they give - so a key whose
parts were mixed up raises rather than signing as one key while
claiming to be another.

What checks the scheme is NIST's ACVP data, which
`pytests/test_ml_dsa.py` reads itself; what checks the certificates and
the TLS side below is OpenSSL 3.5 (see `docs/post-quantum.md`).

### In certificates and TLS 1.3

`CertificateAuthority` issues ML-DSA certificates (RFC 9881) when its
`key_type` is a parameter set, and `TlsServer` and `TlsClient`'s
`client_key` take an `MlDsaKey`. The TLS schemes are TLS 1.3 only:

```python
import time
import allcrypt

ca = allcrypt.CertificateAuthority("Example PQ CA", "20250101000000Z",
                                   "20350101000000Z", key_type="ML-DSA-65")
leaf, seed = ca.issue("localhost", "20250101000000Z", "20350101000000Z")
key = allcrypt.MlDsaKey.from_seed("ML-DSA-65", seed)

roots = allcrypt.TrustStore()
roots.add_pem(ca.certificate_pem)
now = int(time.time())
server = allcrypt.TlsServer([leaf], key, now=now)
client = allcrypt.TlsClient("localhost", roots, now=now, max_version="TLSv1.3")
for _ in range(10):
    server.push_incoming(client.take_outgoing())
    server.process()
    client.push_incoming(server.take_outgoing())
    client.process()
assert client.established and client.certificate_verified
assert allcrypt.Certificate(leaf).to_dict()["publicKeyType"] == "ML-DSA-65"
```

`allcrypt.private_key` reads an ML-DSA PKCS#8 file - in any of RFC 9881's
three forms, as OpenSSL 3.5 writes them - into an `MlDsaKey`, checking
that the seed and the expanded key, where both are present, belong
together.

## SSH keys and signatures

The key formats of SSH, checked both ways against OpenSSH 10.0's
`ssh-keygen`: `.pub` and `authorized_keys` lines, fingerprints,
OpenSSH's own private key files (plain, or encrypted under any cipher
OpenSSH uses), SSH signatures, and SSHSIG - what `ssh-keygen -Y sign`
makes for files and git commits. Ed25519, ECDSA on P-256, P-384 and
P-521, and RSA, including RSA's SHA-1 `ssh-rsa` signatures that
OpenSSH stopped accepting by default and old servers still need.

```python
import allcrypt

key = allcrypt.SshKey.generate("ed25519", comment="me@laptop")
line = key.public_key().to_line()          # "ssh-ed25519 AAAA... me@laptop"
print(key.public_key().fingerprint())      # "SHA256:...", as ssh-keygen -l
print(key.public_key().fingerprint("md5")) # "MD5:aa:bb:...", as older clients

# The private key file, encrypted as ssh-keygen does by default
# (aes256-ctr, 16 rounds of bcrypt_pbkdf). A wrong passphrase raises.
text = key.to_openssh(b"passphrase")
assert allcrypt.SshKey.from_openssh(text, b"passphrase").public_key() == key.public_key()

# authorized_keys lines keep their options, uninterpreted.
entry = allcrypt.SshPublicKey.from_line('no-pty,from="10.0.0.0/8" ' + line)
assert entry.options == 'no-pty,from="10.0.0.0/8"' and entry.comment == "me@laptop"

# An SSH signature blob, and SSHSIG for a file.
blob = key.sign(b"data")
assert entry.verify(b"data", blob)
signature = key.sshsig(b"release contents", namespace="file")
assert allcrypt.sshsig_verify(signature, b"release contents", "file") == key.public_key()
```

### Running a command

`allcrypt_ssh.run` connects, checks the host key, authenticates and runs
one command; `allcrypt.SshClient` underneath it is sans-I/O for callers
that own their sockets. The key exchange is `mlkem768x25519-sha256` -
post-quantum - against any server that has it (OpenSSH 9.9 and later),
with strict key exchange on.

```python,ignore
import allcrypt, allcrypt_ssh

key = allcrypt.SshKey.from_openssh(open("id_ed25519").read())
result = allcrypt_ssh.run("server.example", "uname -a", user="me", keys=[key],
                          host_key="SHA256:AbCd...")
print(result.exit_status, result.stdout.decode(), result.algorithms["kex"])

# An appliance frozen in 2008, reached by naming what it speaks:
allcrypt_ssh.run("ups.local", "status", user="admin", password="...",
                 kex=["diffie-hellman-group1-sha1"], ciphers=["3des-cbc"],
                 macs=["hmac-sha1"], host_key_algorithms=["ssh-rsa"])
```

Leaving `host_key` out accepts whatever the server presents and returns
it in `result.host_key` - pin its `fingerprint()` for every connection
after the first. Everything the client speaks has been run against
OpenSSH 10.0's `sshd`: thirteen key exchanges, ten ciphers, twelve MACs,
seven host key algorithms and every user key type.

### Serving

`allcrypt.SshServer` is the other end, sans-I/O as well, and
`allcrypt_ssh.serve` runs one connection over an accepted socket. What a
command does is a function you give it:

```python,ignore
import socket
import allcrypt, allcrypt_ssh

host = allcrypt.SshKey.from_openssh(open("ssh_host_ed25519_key").read())
alice = allcrypt.SshPublicKey.from_line(open("alice.pub").read())

def handler(command, stdin):          # command is None for a shell
    return f"you ran {command!r}\n".encode(), b"", 0

listener = socket.create_server(("127.0.0.1", 2222))
sock, _ = listener.accept()
server = allcrypt.SshServer([host], authorized=[("alice", alice), ("backup", "a passphrase")])
allcrypt_ssh.serve(sock, server, handler)
print(server.user, server.auth_method, server.algorithms()["kex"])
```

The defaults are the client's: post-quantum key exchange first, nothing
legacy unless named (`kex=[...]`, `host_key_algorithms=["ssh-rsa"]` and
the rest). `server.terminal` and `server.environment` hold what `ssh -t`
and `SendEnv` asked for; no terminal is made. OpenSSH 10.0's and 7.4's
`ssh` have been run against it with every algorithm each has.

### Keys in detail

`SshKey.generate` takes `ssh-keygen -t`'s names - `"ed25519"`,
`"ecdsa"` with `bits` 256, 384 or 521, `"rsa"` with the modulus
(3072 if not given), and `"dsa"`, which is always 1024 bits with a 160
bit `q` because that is all `ssh-dss` can carry. An RSA key's `sign` takes `algorithm`:
`"rsa-sha2-512"` (the default), `"rsa-sha2-256"`, or `"ssh-rsa"` for
SHA-1. `to_openssh` takes `cipher=` any of OpenSSH's ciphers and
`rounds=`; files OpenSSH wrote with any of them read back.

`sshsig_verify` returns the key that signed. Whether that key is one to
trust is a separate decision - the one an allowed-signers file makes -
and the function does not make it for you.

## Dual_EC_DRBG

The generator with the NSA back door (NIST SP 800-90A, withdrawn in 2015),
kept because it is the most instructive cautionary tale the field has.
`dual_ec_drbg` instantiates it and runs a list of `(nbytes,
additional_input)` requests:

```python
import allcrypt

entropy = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
nonce = bytes.fromhex("2021222324252627")
blocks = allcrypt.dual_ec_drbg("P-256", "SHA-256", entropy, nonce,
                               requests=[(60, b""), (60, b"")])
# Matches OpenSSL's FIPS module and Bouncy Castle byte for byte.
assert blocks[0].hex().startswith("ff5163c388f791e9")
```

It uses the standard's unexplained `Q`. Whoever chose that point can
recover the generator's state from a little of its output and predict the
rest; the Rust module comment in `prng/dual_ec.rs` shows why. **Do not
generate keys with it** — it is here to be recognised in the wild.

## Linear congruential generators

The `rand()` of old software, by name, for reproducing what a program saw
or for studying why these generators are predictable. **Not for keys.**
`lcg_names()` lists them; `Lcg(name, seed)` seeds one the way its library
does, and its outputs are what the library's function returned:

```python
import allcrypt

msvc = allcrypt.Lcg("msvc", 1)           # Microsoft C runtime, srand(1)
assert msvc.outputs(3) == [41, 18467, 6334]

java = allcrypt.JavaRandom(42)           # java.util.Random(42)
assert java.next_int() == -1170105035
die = java.next_int(6) + 1               # nextInt(bound), the JDK's way
assert 1 <= die <= 6

r = allcrypt.Rand48(42)                  # srand48(42)
values = (r.lrand48(), r.mrand48(), r.drand48())

# RANDU: every output is fixed by the two before it.
randu = allcrypt.Lcg("randu", 1)
x = [1] + randu.outputs(100)
assert all(x[k + 2] == (6 * x[k + 1] - 9 * x[k]) % 2**31 for k in range(99))

custom = allcrypt.Lcg.custom(a=69069, c=1, m=2**32, state=1)
assert custom.next() == 69070
```

`Lcg.step()` returns the whole new state, `get_bytes(n)` the low byte of
each of `n` outputs, and `seed(n)` reseeds by the generator's own rule.

## Threads

The bulk calls release the GIL, so hashing and encryption scale across
threads rather than serialising on the interpreter lock. Measured at 2.06x on
two cores, against `hashlib`'s 1.87x on the same machine.

```python
import allcrypt, threading

buf = bytes(1024 * 1024)
results = []
threads = [threading.Thread(target=lambda: results.append(allcrypt.sha256(buf).hexdigest()))
           for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
assert len(set(results)) == 1
```

`update_into` is the deliberate exception: it holds a mutable slice into a
`bytearray` that another thread could resize, so it keeps the GIL.

Passing a `bytearray` to anything else is safe under threads, because it
is copied while the GIL is still held — a resize from another thread
mid-call gives you the digest of one state or the other, never of
memory that moved. That is asserted, under an actual race, by
`pytests/test_byte_inputs.py`.

## Errors

Everything raises `allcrypt.CryptoError`, which subclasses `ValueError`, so
`except ValueError` catches it too.

```python
import allcrypt

for bad in (lambda: allcrypt.Cipher("aes", b"short"),
            lambda: allcrypt.Cipher("aes", bytes(16)).encryptor("cbc"),
            lambda: allcrypt.Cipher("aes", bytes(16)).encryptor("gcm", bytes(16)),
            lambda: allcrypt.new("md6")):
    try:
        bad()
        raise AssertionError("should have raised")
    except allcrypt.CryptoError:
        pass
```

## Type hints

Stubs ship in `python/allcrypt.pyi`, so editors and mypy see the full API
without importing the compiled module.
