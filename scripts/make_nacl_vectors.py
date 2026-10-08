#!/usr/bin/env python3
"""Write vectors/nacl.vec: NaCl's boxes as libsodium and Go compute them.

Three sources, and every row is one on which all that can compute it
agree:

  * **NaCl's own test values** - the box, secretbox, HSalsa20 and stream
    examples of "Cryptography in NaCl", as they are kept in libsodium's
    `test/default` (box.c, box2.c, secretbox.c, core1.c, core2.c and
    stream.c, with their `.exp` outputs). Fetched at tag 1.0.18, the
    arrays are read out of the C, the expected output out of the `.exp`,
    and libsodium is required to reproduce each one before it is written.
    These rows are `source=nacl`.
  * **libsodium 1.0.18**, the system's `libsodium.so.23` through
    `ctypes` (no headers or build), over many message lengths and keys.
  * **golang.org/x/crypto v0.37.0**'s `nacl/*` packages, through
    `scripts/witness/naclwitness`, for everything it implements: the
    XSalsa20 secretbox and box, sealed boxes, combined signatures,
    `crypto_auth` and HSalsa20. It has no XChaCha box, key exchange,
    seed key pairs or Ed25519 key conversion; those rows are libsodium's
    alone, and say so in the file's header.

With `--ours`, it also checks the other direction: boxes and sealed
boxes made by this library (the built Python module), with a fresh
random ephemeral key each, are opened by libsodium and by Go.

    python3 scripts/make_nacl_vectors.py [--ours]

**A development tool, not a test**: it fetches over the network and needs
libsodium and the Go witness; nothing in the build or the gate runs it,
and `tests/test_nacl.rs` reads the file with neither.

Rows are `kind field=hex ...`; `-` is empty. Message bytes are written
out. Keys come from SHA-256("nacl " || label || i), so re-running changes
nothing unless an implementation's answer changed.
"""

import argparse
import ctypes
import hashlib
import os
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "vectors", "nacl.vec")
GO = "/opt/wgwitness/naclwitness"
TESTS = "https://raw.githubusercontent.com/jedisct1/libsodium/1.0.18/test/default/"

LENGTHS = sorted(set(list(range(0, 70)) + [95, 96, 97, 127, 128, 129, 191, 192, 193,
                                             255, 256, 257, 511, 512, 513, 1000, 4096]))

sodium = ctypes.CDLL("libsodium.so.23")
if sodium.sodium_init() < 0:
    sys.exit("libsodium did not initialise")
U = ctypes.c_ulonglong


def buf(n):
    return ctypes.create_string_buffer(n)


def material(label, i, n):
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(b"nacl " + label.encode() + b" " + i.to_bytes(4, "big")
                              + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:n]


def message(i, n):
    return bytes((j * 131 + i * 7 + 29) & 0xFF for j in range(n))


def h(b):
    return b.hex() if b else "-"


# ------------------------------------------------------------ libsodium ---

PRIMS = {"xsalsa20poly1305": "crypto_box",
         "xchacha20poly1305": "crypto_box_curve25519xchacha20poly1305"}


def call(name, *args):
    return getattr(sodium, name)(*args)


def s_secretbox(c, key, nonce, m):
    out = buf(16 + len(m))
    fn = "crypto_secretbox_easy" if c == "xsalsa20poly1305" else \
        "crypto_secretbox_xchacha20poly1305_easy"
    assert call(fn, out, m, U(len(m)), nonce, key) == 0
    return out.raw


def s_secretbox_open(c, key, nonce, boxed):
    out = buf(max(len(boxed) - 16, 1))
    fn = "crypto_secretbox_open_easy" if c == "xsalsa20poly1305" else \
        "crypto_secretbox_xchacha20poly1305_open_easy"
    if call(fn, out, boxed, U(len(boxed)), nonce, key) != 0:
        return None
    return out.raw[:len(boxed) - 16]


def s_beforenm(c, pk, sk):
    out = buf(32)
    if call(PRIMS[c] + "_beforenm", out, pk, sk) != 0:
        return None
    return out.raw


def s_box(c, pk, sk, nonce, m):
    out = buf(16 + len(m))
    if call(PRIMS[c] + "_easy", out, m, U(len(m)), nonce, pk, sk) != 0:
        return None
    return out.raw


def s_box_open(c, pk, sk, nonce, boxed):
    out = buf(max(len(boxed) - 16, 1))
    if call(PRIMS[c] + "_open_easy", out, boxed, U(len(boxed)), nonce, pk, sk) != 0:
        return None
    return out.raw[:len(boxed) - 16]


def s_seal(c, pk, m):
    out = buf(48 + len(m))
    fn = "crypto_box_seal" if c == "xsalsa20poly1305" else PRIMS[c] + "_seal"
    assert call(fn, out, m, U(len(m)), pk) == 0
    return out.raw


def s_seal_from(c, pk, m, ephemeral_seed):
    """A sealed box with a chosen ephemeral key, assembled from
    libsodium's parts as `crypto_box_seal` assembles it, so that the row
    can be reproduced. libsodium's own `seal_open` and Go's are then
    required to open it, and libsodium's random `seal` is checked to
    have the same shape."""
    esk, epk = s_seed_keypair("crypto_box_seed_keypair", ephemeral_seed)
    nonce = buf(24)
    both = epk + pk
    assert call("crypto_generichash", nonce, ctypes.c_size_t(24), both, U(64), None,
                ctypes.c_size_t(0)) == 0
    return esk, epk + s_box(c, pk, esk, nonce.raw, m)


def s_seal_open(c, pk, sk, sealed):
    out = buf(max(len(sealed) - 48, 1))
    fn = "crypto_box_seal_open" if c == "xsalsa20poly1305" else PRIMS[c] + "_seal_open"
    if call(fn, out, sealed, U(len(sealed)), pk, sk) != 0:
        return None
    return out.raw[:len(sealed) - 48]


def s_seed_keypair(fn, seed):
    pk, sk = buf(32), buf(32)
    assert call(fn, pk, sk, seed) == 0
    return sk.raw, pk.raw


def s_kx(client_pk, client_sk, server_pk, server_sk):
    crx, ctx, srx, stx = buf(32), buf(32), buf(32), buf(32)
    if call("crypto_kx_client_session_keys", crx, ctx, client_pk, client_sk, server_pk) != 0:
        return None
    assert call("crypto_kx_server_session_keys", srx, stx, server_pk, server_sk,
                client_pk) == 0
    assert crx.raw == stx.raw and ctx.raw == srx.raw
    return crx.raw, ctx.raw


def s_auth(key, m):
    out = buf(32)
    assert call("crypto_auth", out, m, U(len(m)), key) == 0
    return out.raw


def s_sign(seed, m):
    pk, sk = buf(32), buf(64)
    assert call("crypto_sign_seed_keypair", pk, sk, seed) == 0
    out = buf(64 + len(m))
    n = U(0)
    assert call("crypto_sign", out, ctypes.byref(n), m, U(len(m)), sk) == 0
    return pk.raw, out.raw[:n.value]


def s_ed_pk_to_curve(edpk):
    out = buf(32)
    if call("crypto_sign_ed25519_pk_to_curve25519", out, edpk) != 0:
        return None
    return out.raw


def s_ed_sk_to_curve(seed):
    pk, sk = buf(32), buf(64)
    assert call("crypto_sign_seed_keypair", pk, sk, seed) == 0
    out = buf(32)
    assert call("crypto_sign_ed25519_sk_to_curve25519", out, sk) == 0
    return out.raw


def s_hsalsa(key, inp):
    out = buf(32)
    assert call("crypto_core_hsalsa20", out, inp, key, None) == 0
    return out.raw


def s_xsalsa_ic(key, nonce, n, ic):
    out = buf(n)
    assert call("crypto_stream_xsalsa20_xor_ic", out, bytes(n), U(n), nonce, U(ic), key) == 0
    return out.raw


def s_x25519_base(sk):
    out = buf(32)
    assert call("crypto_scalarmult_curve25519_base", out, sk) == 0
    return out.raw


# ------------------------------------------------------------------- Go ---

class Go:
    def __init__(self):
        self.requests = []

    def ask(self, *fields):
        self.requests.append(" ".join(h(f) if isinstance(f, bytes) else f for f in fields))
        return len(self.requests) - 1

    def run(self):
        text = "\n".join(self.requests) + "\n"
        result = subprocess.run([GO], input=text, capture_output=True, text=True, check=True)
        answers = result.stdout.split("\n")[:-1]
        assert len(answers) == len(self.requests), (len(answers), len(self.requests))
        return [None if a == "FAIL" else (b"" if a == "-" else bytes.fromhex(a))
                for a in answers]


# ------------------------------------------------------ NaCl's own values ---

def fetch(name):
    with urllib.request.urlopen(TESTS + name) as response:
        return response.read().decode()


def c_array(source, name, length):
    match = re.search(r"\b" + name + r"\[[^\]]*\]\s*=\s*\{([^}]*)\}", source)
    assert match, name
    values = [int(v, 0) for v in re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", match.group(1))]
    assert len(values) == length, (name, len(values))
    return bytes(values)


def exp_bytes(text, count):
    values = [int(v, 16) for v in re.findall(r"0x([0-9a-f]{2})", text)]
    assert len(values) == count, (len(values), count)
    return bytes(values)


def nacl_rows():
    rows = []
    core1, core2 = fetch("core1.c"), fetch("core2.c")
    shared = c_array(core1, "shared", 32)
    firstkey = exp_bytes(fetch("core1.exp"), 32)
    assert s_hsalsa(shared, bytes(16)) == firstkey
    rows.append(f"hsalsa20 source=nacl key={h(shared)} input={h(bytes(16))} out={h(firstkey)}")
    nonceprefix = c_array(core2, "nonceprefix", 16)
    assert c_array(core2, "firstkey", 32) == firstkey
    secondkey = exp_bytes(fetch("core2.exp"), 32)
    assert s_hsalsa(firstkey, nonceprefix) == secondkey
    rows.append(f"hsalsa20 source=nacl key={h(firstkey)} input={h(nonceprefix)} "
                f"out={h(secondkey)}")

    box_c = fetch("box.c")
    alicesk, bobpk = c_array(box_c, "alicesk", 32), c_array(box_c, "bobpk", 32)
    nonce, m = c_array(box_c, "nonce", 24), c_array(box_c, "m", 163)
    assert m[:32] == bytes(32)
    expected = exp_bytes(fetch("box.exp"), 2 * 147)
    assert expected[:147] == expected[147:]
    boxed = expected[:147]
    assert s_box("xsalsa20poly1305", bobpk, alicesk, nonce, m[32:]) == boxed
    rows.append(f"box source=nacl construction=xsalsa20poly1305 public={h(bobpk)} "
                f"private={h(alicesk)} nonce={h(nonce)} message={h(m[32:])} boxed={h(boxed)}")
    # The shared key the paper calls firstkey is this box's beforenm.
    assert s_beforenm("xsalsa20poly1305", bobpk, alicesk) == firstkey
    rows.append(f"beforenm source=nacl construction=xsalsa20poly1305 public={h(bobpk)} "
                f"private={h(alicesk)} key={h(firstkey)}")

    box2_c = fetch("box2.c")
    bobsk, alicepk = c_array(box2_c, "bobsk", 32), c_array(box2_c, "alicepk", 32)
    c = c_array(box2_c, "c", 163)
    assert c[:16] == bytes(16) and c[16:] == boxed
    opened = exp_bytes(fetch("box2.exp"), 2 * 131)
    assert opened[:131] == opened[131:] == m[32:]
    assert s_box_open("xsalsa20poly1305", alicepk, bobsk, nonce, boxed) == m[32:]
    rows.append(f"box_open source=nacl construction=xsalsa20poly1305 public={h(alicepk)} "
                f"private={h(bobsk)} nonce={h(nonce)} boxed={h(boxed)} message={h(m[32:])}")

    sb = fetch("secretbox.c")
    assert c_array(sb, "firstkey", 32) == firstkey
    assert c_array(sb, "nonce", 24) == nonce and c_array(sb, "m", 163) == m
    expected = exp_bytes(fetch("secretbox.exp"), 2 * 147)
    assert expected[:147] == expected[147:] == boxed
    rows.append(f"secretbox source=nacl construction=xsalsa20poly1305 key={h(firstkey)} "
                f"nonce={h(nonce)} message={h(m[32:])} boxed={h(boxed)}")

    stream_c = fetch("stream.c")
    assert c_array(stream_c, "firstkey", 32) == firstkey
    assert c_array(stream_c, "nonce", 24) == nonce
    digest = fetch("stream.exp").split("\n")[0]
    keystream = s_xsalsa_ic(firstkey, nonce, 4194304, 0)
    assert hashlib.sha256(keystream).hexdigest() == digest
    rows.append(f"xsalsa20_sha256 source=nacl key={h(firstkey)} nonce={h(nonce)} "
                f"block=0 length=4194304 sha256={digest}")
    return rows


# ------------------------------------------------------------ the rest ---

# --------------------------------------------------- Edwards, for inputs ---
#
# Enough Ed25519 arithmetic to *make* the awkward inputs below - a point
# of order 8, and the Montgomery u of the small-order points - rather
# than type them. Nothing here is an expected output: libsodium supplies
# every answer, and refuses or accepts each input itself.

P = 2**255 - 19
D = -121665 * pow(121666, -1, P) % P
L = 2**252 + 27742317777372353535851937790883648493


def ed_decode(b):
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if x * x % P != x2:
        x = x * pow(2, (P - 1) // 4, P) % P
    if x * x % P != x2:
        return None
    if x & 1 != b[31] >> 7:
        x = (P - x) % P
    return (x, y)


def ed_add(a, b):
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, P) % P,
            (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P)


def ed_mul(k, point):
    acc = (0, 1)
    while k:
        if k & 1:
            acc = ed_add(acc, point)
        point = ed_add(point, point)
        k >>= 1
    return acc


def ed_encode(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def order_eight_point():
    """L times a point that is not in the prime-order subgroup, chosen so
    the result has order exactly 8."""
    for i in range(100):
        point = ed_decode(material("torsion search", i, 32))
        if point is None:
            continue
        q = ed_mul(L, point)
        if ed_mul(4, q) != (0, 1):
            return q
    raise RuntimeError("no point of order 8 found")


def low_order_points(torsion):
    """The u coordinates libsodium refuses: 0 (order 4 on the curve's
    Montgomery form), 1 (u of the twist's order-4 point), the two u of the
    order-8 points, and p - 1, p, p + 1 - the first is order 2, the others
    non-canonical spellings of 0 and 1."""
    us = {0, 1, P - 1, P, P + 1}
    for k in (1, 3):
        x, y = ed_mul(k, torsion)
        us.add((1 + y) * pow(1 - y, -1, P) % P)
    return [u.to_bytes(32, "little") for u in sorted(us)]


def generated_rows(go, checks):
    rows = []

    def expect(index, want, what):
        checks.append((index, want, what))

    for i in range(24):
        key, inp = material("hsalsa key", i, 32), material("hsalsa input", i, 16)
        out = s_hsalsa(key, inp)
        expect(go.ask("hsalsa", key, inp), out, f"hsalsa {i}")
        rows.append(f"hsalsa20 key={h(key)} input={h(inp)} out={h(out)}")

    # The 64 bit counter across its low word, as stream.c's last check does.
    for i, block in enumerate([0, 1, (1 << 32) - 1, (1 << 32) + 5, (1 << 64) - 3]):
        key, nonce = material("ic key", i, 32), material("ic nonce", i, 24)
        out = s_xsalsa_ic(key, nonce, 192, block)
        rows.append(f"xsalsa20 key={h(key)} nonce={h(nonce)} block={block} out={h(out)}")

    for c in PRIMS:
        for n, length in enumerate(LENGTHS):
            key, nonce = material(c + " key", n, 32), material(c + " nonce", n, 24)
            m = message(n, length)
            boxed = s_secretbox(c, key, nonce, m)
            assert s_secretbox_open(c, key, nonce, boxed) == m
            if c == "xsalsa20poly1305":
                expect(go.ask("secretbox", key, nonce, m), boxed, f"secretbox {length}")
                expect(go.ask("secretbox_open", key, nonce, boxed), m, f"open {length}")
            rows.append(f"secretbox construction={c} key={h(key)} nonce={h(nonce)} "
                        f"message={h(m)} boxed={h(boxed)}")

        for i in range(16):
            seed_a, seed_b = material(c + " alice", i, 32), material(c + " bob", i, 32)
            alice, alice_pk = s_seed_keypair("crypto_box_seed_keypair", seed_a)
            bob, bob_pk = s_seed_keypair("crypto_box_seed_keypair", seed_b)
            if i % 4 == 3:
                # A peer key with the top bit set: X25519 ignores it.
                bob_pk = bob_pk[:31] + bytes([bob_pk[31] | 0x80])
            key = s_beforenm(c, bob_pk, alice)
            if c == "xsalsa20poly1305":
                expect(go.ask("beforenm", bob_pk, alice), key, f"beforenm {i}")
            rows.append(f"beforenm construction={c} public={h(bob_pk)} private={h(alice)} "
                        f"key={h(key)}")
            nonce = material(c + " box nonce", i, 24)
            m = message(i, [0, 1, 17, 32, 33, 64, 100, 300][i % 8])
            boxed = s_box(c, bob_pk, alice, nonce, m)
            assert s_box_open(c, alice_pk, bob, nonce, boxed) == m
            if c == "xsalsa20poly1305":
                expect(go.ask("box", bob_pk, alice, nonce, m), boxed, f"box {i}")
                expect(go.ask("box_open", alice_pk, bob, nonce, boxed), m, f"box_open {i}")
            rows.append(f"box construction={c} public={h(bob_pk)} private={h(alice)} "
                        f"nonce={h(nonce)} message={h(m)} boxed={h(boxed)}")

            random_sealed = s_seal(c, bob_pk, m)
            assert s_seal_open(c, bob_pk, bob, random_sealed) == m
            assert len(random_sealed) == 48 + len(m)
            esk, sealed = s_seal_from(c, bob_pk, m, material(c + " ephemeral", i, 32))
            assert s_seal_open(c, bob_pk, bob, sealed) == m
            if c == "xsalsa20poly1305":
                expect(go.ask("seal_open", bob_pk, bob, sealed), m, f"seal_open {i}")
            rows.append(f"seal construction={c} public={h(bob_pk)} private={h(bob)} "
                        f"ephemeral_private={h(esk)} message={h(m)} sealed={h(sealed)}")

        alice, _ = s_seed_keypair("crypto_box_seed_keypair", material("low", 0, 32))
        for point in low_order_points(order_eight_point()):
            assert s_beforenm(c, point, alice) is None
            rows.append(f"beforenm construction={c} public={h(point)} private={h(alice)} "
                        f"key=refused")

    for i in range(16):
        seed = material("box seed", i, 32)
        sk, pk = s_seed_keypair("crypto_box_seed_keypair", seed)
        assert s_x25519_base(sk) == pk
        rows.append(f"box_seed_keypair seed={h(seed)} private={h(sk)} public={h(pk)}")
        sk, pk = s_seed_keypair("crypto_kx_seed_keypair", seed)
        rows.append(f"kx_seed_keypair seed={h(seed)} private={h(sk)} public={h(pk)}")

    for i in range(16):
        csk, cpk = s_seed_keypair("crypto_kx_seed_keypair", material("kx client", i, 32))
        ssk, spk = s_seed_keypair("crypto_kx_seed_keypair", material("kx server", i, 32))
        rx, tx = s_kx(cpk, csk, spk, ssk)
        rows.append(f"kx client_public={h(cpk)} client_private={h(csk)} "
                    f"server_public={h(spk)} server_private={h(ssk)} "
                    f"client_rx={h(rx)} client_tx={h(tx)}")

    for i, length in enumerate([0, 1, 3, 64, 127, 128, 129, 1000]):
        key, m = material("auth key", i, 32), message(i, length)
        tag = s_auth(key, m)
        expect(go.ask("auth", key, m), tag, f"auth {i}")
        rows.append(f"auth key={h(key)} message={h(m)} tag={h(tag)}")

    for i, length in enumerate([0, 1, 31, 32, 64, 65, 200, 1023]):
        seed, m = material("sign seed", i, 32), message(i, length)
        pk, signed = s_sign(seed, m)
        expect(go.ask("sign", seed, m), signed, f"sign {i}")
        expect(go.ask("sign_open", pk, signed), m, f"sign_open {i}")
        rows.append(f"sign seed={h(seed)} public={h(pk)} message={h(m)} signed={h(signed)}")

    for i in range(16):
        seed = material("ed seed", i, 32)
        pk, _ = s_sign(seed, b"")
        curve_pk = s_ed_pk_to_curve(pk)
        curve_sk = s_ed_sk_to_curve(seed)
        assert s_x25519_base(curve_sk) == curve_pk
        rows.append(f"ed25519_to_x25519 seed={h(seed)} ed_public={h(pk)} "
                    f"x_private={h(curve_sk)} x_public={h(curve_pk)}")
    # Public keys libsodium refuses or accepts that are not ordinary keys:
    # random strings (about half are not points), the small-order points,
    # and points with a torsion component.
    candidates = [material("ed random", i, 32) for i in range(24)]
    candidates += [bytes([1] + [0] * 31),                          # the identity
                   bytes([0xEC] + [0xFF] * 30 + [0x7F]),            # y = -1, order 2
                   bytes(32),                                       # y = 0, order 4
                   bytes([0xEE] + [0xFF] * 30 + [0x7F])]            # y = p + 1 > p
    torsion = ed_encode(order_eight_point())
    assert call("crypto_core_ed25519_is_valid_point", torsion) == 0
    candidates.append(torsion)                                     # order 8
    for i, candidate in enumerate(candidates):
        out = s_ed_pk_to_curve(candidate)
        rows.append(f"ed25519_public_to_x25519 ed_public={h(candidate)} "
                    f"x_public={'refused' if out is None else h(out)}")
    # A key with a torsion component: a real public key plus the order 8
    # point, made by libsodium's own Edwards addition.
    for i in range(4):
        pk, _ = s_sign(material("ed torsion", i, 32), b"")
        mixed = buf(32)
        assert call("crypto_core_ed25519_add", mixed, pk, torsion) == 0
        out = s_ed_pk_to_curve(mixed.raw)
        rows.append(f"ed25519_public_to_x25519 ed_public={h(mixed.raw)} "
                    f"x_public={'refused' if out is None else h(out)}")
    return rows


def check_ours(go):
    """Our boxes, opened by libsodium and Go."""
    sys.path.insert(0, os.path.join(ROOT, "python"))
    import allcrypt
    count = 0
    for c in PRIMS:
        for i in range(32):
            seed_b = material("ours bob", i, 32)
            bob, bob_pk = s_seed_keypair("crypto_box_seed_keypair", seed_b)
            m = message(i, [0, 1, 33, 64, 300][i % 5])
            sealed = allcrypt.box_seal(bob_pk, m, c)
            assert s_seal_open(c, bob_pk, bob, sealed) == m, (c, i)
            alice, alice_pk = s_seed_keypair("crypto_box_seed_keypair",
                                             material("ours alice", i, 32))
            nonce = material("ours nonce", i, 24)
            boxed = allcrypt.box_encrypt(bob_pk, alice, nonce, m, c)
            assert s_box_open(c, alice_pk, bob, nonce, boxed) == m
            count += 2
            if c == "xsalsa20poly1305":
                go_seal = go.ask("seal_open", bob_pk, bob, sealed)
                go_box = go.ask("box_open", alice_pk, bob, nonce, boxed)
                answers = go.run()
                go.requests.clear()
                assert answers[go_seal] == m and answers[go_box] == m
                count += 2
    print(f"--ours: {count} boxes and sealed boxes made here opened elsewhere")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", action="store_true")
    args = parser.parse_args()
    sodium.sodium_version_string.restype = ctypes.c_char_p
    version = sodium.sodium_version_string()
    if version != b"1.0.18":
        sys.exit(f"expected libsodium 1.0.18, found {version!r}")

    go = Go()
    checks = []
    rows = nacl_rows()
    rows += generated_rows(go, checks)
    answers = go.run()
    for index, want, what in checks:
        if answers[index] != want:
            sys.exit(f"Go disagrees with libsodium: {what}")
    header = """# NaCl's boxes and libsodium's extensions. Written by
# scripts/make_nacl_vectors.py; do not edit.
#
# source=nacl rows are the examples in "Cryptography in NaCl", read out of
# libsodium 1.0.18's test/default and reproduced by libsodium. Every other
# row is libsodium 1.0.18's answer; golang.org/x/crypto v0.37.0 agrees on
# every hsalsa20, xsalsa20poly1305 secretbox, beforenm (not refused), box,
# seal, auth and sign row. A seal row's ephemeral key is chosen, so its box
# is assembled from libsodium's parts as crypto_box_seal does, and opened
# by libsodium's crypto_box_seal_open and by Go. The xsalsa20 counter rows, the
# xchacha20poly1305 rows, the key pairs, kx and the Ed25519 conversions
# are libsodium's alone.
"""
    with open(OUTPUT, "w") as out:
        out.write(header)
        for row in rows:
            out.write(row + "\n")
    print(f"{len(rows)} rows, {len(checks)} confirmed by Go, written to {OUTPUT}")
    if args.ours:
        check_ours(Go())


if __name__ == "__main__":
    main()
