#!/usr/bin/env python3
"""The wallet example (`examples/products/wallet`) against independent
implementations, both directions where the format has two.

  * **BIP-39** against python-mnemonic, the reference implementation
    (trezor/python-mnemonic): mnemonics from random entropy of every
    length, seeds under several passphrases, and checksums both refuse.
  * **BIP-32** against pycoin (richardkiss/pycoin, its own pure-Python
    secp256k1): random seeds and paths, hardened and not, in every
    version prefix, mainnet and testnet - extended keys, WIF, P2PKH,
    P2SH-P2WPKH and P2WPKH addresses byte for byte - and public
    derivation from an xpub.
  * **Signed messages**: Bitcoin's, signed by pycoin and by ours, each
    verifying the other's, and byte for byte once pycoin's s is brought
    to the lower half as Bitcoin Core's is; Ethereum's EIP-191 messages,
    signed with pycoin's ECDSA over OpenSSL 3.5's Keccak-256, compared
    the same way, and recovered by ours.
  * **Ethereum addresses** and EIP-55 from pycoin's public keys and
    OpenSSL 3.5's Keccak-256; **taproot** (BIP-86) output keys from
    pycoin's point arithmetic and hashlib's tagged hashes.
  * **Keystores** (Web3 Secret Storage v3, scrypt and PBKDF2): ours
    written, opened here from the specification with hashlib, OpenSSL's
    Keccak-256 and python-cryptography's AES-CTR, and the reverse.
  * **BIP-38**, with and without EC multiply: ours written and opened
    here from the specification with hashlib's scrypt,
    python-cryptography's AES and pycoin's arithmetic, and the reverse,
    confirmation codes included.

    python3 scripts/check_wallet.py [--ours PATH]
    python3 scripts/check_wallet.py --record

`--record` writes `examples/products/fixtures/wallet/wallet.vec` for the
offline tests.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example wallet`. pycoin and
python-mnemonic are git checkouts (`docs/building.md`).
"""

import argparse
import base64
import hashlib
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures", "wallet")
OURS = os.path.join(ROOT, "target", "release", "examples", "wallet")
WITNESS = "/opt/walletwitness"
OPENSSL35 = ["env", "LD_LIBRARY_PATH=/opt/openssl35/lib64:/opt/openssl35/lib",
             "/opt/openssl35/bin/openssl"]

sys.path.insert(0, os.path.join(WITNESS, "pycoin"))
sys.path.insert(0, os.path.join(WITNESS, "python-mnemonic", "src"))

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from mnemonic import Mnemonic  # noqa: E402
from pycoin.encoding.hash import hash160  # noqa: E402
from pycoin.symbols.btc import network as BTC  # noqa: E402
from pycoin.symbols.xtn import network as XTN  # noqa: E402

G = BTC.generator
N = G.order()
FAILURES = []
COUNTS = {}


def check(ok, what):
    key = what.split(":")[0]
    COUNTS[key] = COUNTS.get(key, 0) + 1
    if not ok:
        FAILURES.append(what)
        print("FAIL", what)


def ours(*args, check_ok=True, stdin=None):
    r = subprocess.run([OURS, *map(str, args)], capture_output=True, text=True, input=stdin)
    if check_ok and r.returncode != 0:
        raise RuntimeError(f"ours {' '.join(map(str, args))}: {r.stderr}")
    return r


def fields(text):
    return dict(line.split(": ", 1) for line in text.splitlines() if ": " in line)


def keccak256(data):
    out = subprocess.run([*OPENSSL35, "dgst", "-keccak-256", "-binary"], input=data,
                         capture_output=True, check=True).stdout
    assert len(out) == 32
    return out


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256d(data):
    return sha256(sha256(data))


def point_bytes(x, y, compressed=True):
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def eth_address(x, y):
    return keccak256(point_bytes(x, y, False)[1:])[12:]


def eip55(address):
    lower = address.hex()
    h = keccak256(lower.encode()).hex()
    return "0x" + "".join(c.upper() if c.isalpha() and int(h[i], 16) >= 8 else c
                          for i, c in enumerate(lower))


def tagged_hash(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)


def taproot_address(x, y, network):
    # BIP-86: the internal key with even y, tweaked by TapTweak(x).
    if y & 1:
        y = G.curve().p() - y
    t = int.from_bytes(tagged_hash("TapTweak", x.to_bytes(32, "big")), "big")
    q = G.Point(x, y) + t * G
    return network.address.for_p2tr(q[0].to_bytes(32, "big"))


# ------------------------------------------------------------------- BIP-39 --

def check_bip39(choose, record):
    m = Mnemonic("english")
    for strength in (128, 160, 192, 224, 256):
        for i in range(40):
            entropy = bytes(choose.randrange(256) for _ in range(strength // 8))
            theirs = m.to_mnemonic(entropy)
            mine = ours("mnemonic", "from-entropy", entropy.hex()).stdout.strip()
            check(mine == theirs, f"bip39 words: {entropy.hex()}")
            back = ours("mnemonic", "check", theirs).stdout
            check(entropy.hex() in back, f"bip39 entropy: {entropy.hex()}")
            passphrase = ["", "TREZOR", "correct horse battery staple", "x" * 200][i % 4]
            seed = m.to_seed(theirs, passphrase)
            args = ["mnemonic", "seed", theirs] + (["--passphrase", passphrase] if passphrase
                                                   else [])
            check(ours(*args).stdout.strip() == seed.hex(), f"bip39 seed: {entropy.hex()}")
            # A wrong last word: python-mnemonic and ours both refuse it,
            # unless it happens to carry the right checksum too.
            words = theirs.split()
            words[-1] = m.wordlist[(m.wordlist.index(words[-1]) + 1) % 2048]
            wrong = " ".join(words)
            refused = ours("mnemonic", "check", wrong, check_ok=False).returncode != 0
            check(refused == (not m.check(wrong)), f"bip39 checksum: {wrong}")
            if i < 2:
                record.setdefault("bip39", []).append(
                    [("name", f"{strength} {i}"), ("entropy", entropy.hex()),
                     ("mnemonic", theirs), ("passphrase", passphrase or "-"),
                     ("seed", seed.hex())])


# Passphrases written the ways a keyboard writes them: precomposed and
# decomposed accents, compatibility characters (a ligature, a Roman
# numeral, full-width and half-width forms), Hangul, and an ideographic
# space. BIP-39 hashes them in NFKD and BIP-38 in NFC, so two spellings of
# one text are one wallet.
UNICODE_PASSPHRASES = [
    "p\u00e4ssw\u00f6rd", "pa\u0308sswo\u0308rd", "\ufb01nance \u2163",
    "\uff30\uff21\uff33\uff33 \uff76\uff9e", "\ud55c\uad6d\uc5b4", "\u1112\u1161\u11ab",
    "\u65e5\u672c\u8a9e\u3000\u30d1\u30b9", "\u03d2\u0301\u0000\U00010400\U0001f4a9",
    "Caf\u00e9 \u212b \u2126",
]


def check_bip39_unicode(choose, record):
    """Mnemonics in every word list python-mnemonic has, with the
    passphrases above. Half are handed to ours in NFC rather than the
    list's own form, which for Spanish and French is NFKD."""
    import unicodedata
    for n, language in enumerate(sorted(Mnemonic.list_languages())):
        m = Mnemonic(language)
        for i in range(4):
            entropy = bytes(choose.randrange(256) for _ in range(16 + 4 * i))
            words = m.to_mnemonic(entropy)
            passphrase = UNICODE_PASSPHRASES[(n * 4 + i) % len(UNICODE_PASSPHRASES)]
            typed = unicodedata.normalize("NFC", words) if i % 2 else words
            seed = m.to_seed(words, passphrase)
            got = ours("mnemonic", "seed", typed, "--unchecked", "--passphrase-stdin",
                       stdin=passphrase + "\n").stdout.strip()
            check(got == seed.hex(), f"bip39 unicode: {language} {i}")
            if i < 2:
                record.setdefault("bip39-unicode", []).append(
                    [("name", f"{language} {i}"), ("mnemonic", typed.encode().hex()),
                     ("passphrase", passphrase.encode().hex()), ("seed", seed.hex())])


# ------------------------------------------------------------------- BIP-32 --

VERSIONS = [("xprv", "xpub", BTC, None), ("yprv", "ypub", BTC, "bip49"),
            ("zprv", "zpub", BTC, "bip84"), ("tprv", "tpub", XTN, None),
            ("uprv", "upub", XTN, "bip49"), ("vprv", "vpub", XTN, "bip84")]


def serialized(node, network, scheme, private):
    if scheme is None:
        return node.hwif(as_private=private)
    blob = node.serialize(as_private=private)
    return getattr(network, f"{scheme}_as_string")(blob, as_private=private)


def random_path(choose):
    path = []
    for _ in range(choose.randrange(0, 6)):
        index = choose.choice([0, 1, 2, 44, 84, choose.randrange(2 ** 31)])
        path.append((index, choose.random() < 0.5))
    return path


def path_text(path, hardened_mark="'"):
    return "/".join(["m"] + [f"{i}{hardened_mark if h else ''}" for i, h in path])


def pycoin_path(path):
    return "/".join(f"{i}{'H' if h else ''}" for i, h in path)


def check_bip32(choose, record):
    for i in range(72):
        seed = bytes(choose.randrange(256) for _ in range(choose.choice([16, 32, 64, 47])))
        prv_name, pub_name, network, scheme = VERSIONS[i % len(VERSIONS)]
        path = random_path(choose)
        node = network.keys.bip32_seed(seed)
        child = node.subkey_for_path(pycoin_path(path)) if path else node
        mine = fields(ours("derive", "--seed", seed.hex(), "--path",
                           path_text(path, choose.choice("'hH")), "--version", prv_name).stdout)
        what = f"{prv_name} {seed.hex()} {path_text(path)}"
        check(mine[prv_name] == serialized(child, network, scheme, True), f"bip32 prv: {what}")
        check(mine[pub_name] == serialized(child, network, scheme, False), f"bip32 pub: {what}")
        check(mine["WIF"] == child.wif(), f"bip32 wif: {what}")
        sec = child.sec()
        check(mine["public key"] == sec.hex(), f"bip32 pubkey: {what}")
        check(mine["P2PKH"] == child.address(), f"p2pkh: {what}")
        script = b"\x00\x14" + hash160(sec)
        check(mine["P2SH-P2WPKH"] == network.address.for_p2s(script), f"p2sh-p2wpkh: {what}")
        check(mine["P2WPKH"] == network.address.for_p2pkh_wit(hash160(sec)), f"p2wpkh: {what}")
        x, y = child.public_pair()
        check(mine["P2TR"] == taproot_address(x, y, network), f"p2tr: {what}")
        check(mine["Ethereum"] == eip55(eth_address(x, y)), f"eth address: {what}")
        # Public derivation, from the parent's xpub, for a last step that
        # is not hardened.
        if path and not path[-1][1]:
            parent = node.subkey_for_path(pycoin_path(path[:-1])) if len(path) > 1 else node
            public = serialized(parent, network, scheme, False)
            via = fields(ours("derive", "--key", public, "--path",
                              f"m/{path[-1][0]}").stdout)
            check(via[pub_name] == mine[pub_name] and prv_name not in via,
                  f"bip32 public derivation: {what}")
        if i < 12:
            record.setdefault("bip32", []).append(
                [("name", what), ("seed", seed.hex()), ("path", path_text(path)),
                 ("version", prv_name), ("prv", mine[prv_name]), ("pub", mine[pub_name]),
                 ("wif", child.wif()), ("p2pkh", child.address()),
                 ("p2sh-p2wpkh", network.address.for_p2s(script)),
                 ("p2wpkh", network.address.for_p2pkh_wit(hash160(sec))),
                 ("p2tr", taproot_address(x, y, network)),
                 ("ethereum", eip55(eth_address(x, y)))])
    # An uncompressed WIF's address.
    for _ in range(10):
        se = choose.randrange(1, N)
        key = BTC.keys.private(se, is_compressed=False)
        mine = fields(ours("address", "--wif", key.wif()).stdout)
        check(mine["P2PKH"] == key.address() and "P2WPKH" not in mine,
              f"uncompressed: {key.wif()}")


# ----------------------------------------------------------------- messages --

def low_s(r, s, recid):
    if s > N // 2:
        return r, N - s, recid ^ 1
    return r, s, recid


def check_messages(choose, record):
    for i in range(40):
        se = choose.randrange(1, N)
        compressed = i % 4 != 0
        key = BTC.keys.private(se, is_compressed=compressed)
        message = "".join(choose.choice("abc xyz\n1é") for _ in range(choose.randrange(0, 300)))
        # Theirs, low-S, is ours byte for byte.
        r, s, recid = G.sign_with_recid(se, BTC.msg.hash_for_signing(message))
        r, s, recid = low_s(r, s, recid)
        header = 27 + recid + (4 if compressed else 0)
        theirs = base64.b64encode(bytes([header]) + r.to_bytes(32, "big")
                                  + s.to_bytes(32, "big")).decode()
        mine = ours("sign-message", key.wif(), message).stdout.strip()
        check(mine == theirs, f"btc message: {i}")
        check(BTC.msg.verify(key.address(), mine, message), f"btc message verified: {i}")
        raw = BTC.msg.sign(key, message)
        good = ours("verify-message", key.address(), raw, message, check_ok=False)
        check(good.returncode == 0, f"btc message theirs: {i} {good.stderr}")
        bad = ours("verify-message", key.address(), raw, message + ".", check_ok=False)
        check(bad.returncode != 0, f"btc message altered: {i}")
        if compressed:
            sec = key.sec()
            for kind, addr in [("p2wpkh", BTC.address.for_p2pkh_wit(hash160(sec))),
                               ("p2sh-p2wpkh", BTC.address.for_p2s(b"\x00\x14"
                                                                   + hash160(sec)))]:
                sig = ours("sign-message", key.wif(), message, "--kind", kind).stdout.strip()
                check(ours("verify-message", addr, sig, message, check_ok=False).returncode
                      == 0, f"btc message {kind}: {i}")
                # Electrum and Core sign a segwit address under the P2PKH
                # header; that verifies against it too.
                check(ours("verify-message", addr, mine, message, check_ok=False).returncode
                      == 0, f"btc message {kind} under p2pkh header: {i}")
        if i < 8:
            record.setdefault("btc-message", []).append(
                [("name", str(i)), ("wif", key.wif()), ("address", key.address()),
                 ("message", message.encode().hex() or "-"), ("signature", theirs)])
        # Ethereum: EIP-191 over Keccak-256, the same ECDSA.
        data = message.encode()
        digest = keccak256(b"\x19Ethereum Signed Message:\n" + str(len(data)).encode() + data)
        r, s, recid = low_s(*G.sign_with_recid(se, int.from_bytes(digest, "big")))
        theirs_eth = (r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])).hex()
        mine_eth = ours("eth", "sign-message", "--key", f"{se:064x}", message).stdout.strip()
        check(mine_eth == theirs_eth, f"eth message: {i}")
        x, y = G * se
        signer = ours("eth", "recover", theirs_eth, message).stdout.strip()
        check(signer == eip55(eth_address(x, y)), f"eth recover: {i}")
        if i < 8:
            record.setdefault("eth-message", []).append(
                [("name", str(i)), ("key", f"{se:064x}"), ("address", eip55(eth_address(x, y))),
                 ("message", data.hex() or "-"), ("signature", theirs_eth)])


# ---------------------------------------------------------------- keystores --

def ctr(key, iv, data):
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def keystore_derive(crypto, password):
    p = crypto["kdfparams"]
    salt = bytes.fromhex(p["salt"])
    if crypto["kdf"] == "scrypt":
        return hashlib.scrypt(password, salt=salt, n=p["n"], r=p["r"], p=p["p"],
                              dklen=p["dklen"], maxmem=2 ** 31 - 1)
    assert p["prf"] == "hmac-sha256"
    return hashlib.pbkdf2_hmac("sha256", password, salt, p["c"], p["dklen"])


def open_keystore(text, password):
    j = json.loads(text)
    c = j["crypto"]
    derived = keystore_derive(c, password)
    ct = bytes.fromhex(c["ciphertext"])
    if keccak256(derived[16:32] + ct).hex() != c["mac"]:
        return None
    return ctr(derived[:16], bytes.fromhex(c["cipherparams"]["iv"]), ct)


def make_keystore(se, password, choose, kdf):
    salt = bytes(choose.randrange(256) for _ in range(32))
    iv = bytes(choose.randrange(256) for _ in range(16))
    if kdf == "scrypt":
        params = {"dklen": 32, "n": 1024, "p": 1, "r": 8, "salt": salt.hex()}
    else:
        params = {"c": 1000, "dklen": 32, "prf": "hmac-sha256", "salt": salt.hex()}
    crypto = {"cipher": "aes-128-ctr", "cipherparams": {"iv": iv.hex()}, "kdf": kdf,
              "kdfparams": params}
    derived = keystore_derive(crypto, password)
    ct = ctr(derived[:16], iv, se.to_bytes(32, "big"))
    crypto["ciphertext"] = ct.hex()
    crypto["mac"] = keccak256(derived[16:32] + ct).hex()
    x, y = G * se
    return json.dumps({"address": eth_address(x, y).hex(), "crypto": crypto,
                       "id": "3198bc9c-6672-5ab3-d995-4942343ae5b6", "version": 3})


def check_keystores(choose, record, tmp):
    for i in range(16):
        se = choose.randrange(1, N)
        password = ["", "testpassword", "pässwörd", "x" * 70][i % 4]
        kdf = "scrypt" if i % 2 else "pbkdf2"
        path = os.path.join(tmp, f"ours{i}.json")
        args = ["eth", "keystore-encrypt", path, "--key", f"{se:064x}", "--kdf", kdf,
                "--password", password] + (["--n", 1024] if kdf == "scrypt"
                                           else ["--iterations", 1000])
        ours(*args)
        text = open(path).read()
        plain = open_keystore(text, password.encode())
        check(plain == se.to_bytes(32, "big"), f"keystore ours: {kdf} {i}")
        x, y = G * se
        check(json.loads(text)["address"] == eth_address(x, y).hex(), f"keystore address: {i}")
        check(open_keystore(text, b"wrong") is None, f"keystore wrong password: {i}")
        theirs = make_keystore(se, password.encode(), choose, kdf)
        tpath = os.path.join(tmp, f"theirs{i}.json")
        with open(tpath, "w") as f:
            f.write(theirs)
        args = ["eth", "keystore-decrypt", tpath, "--password", password]
        got = ours(*args).stdout
        check(f"private key: {se:064x}" in got, f"keystore theirs: {kdf} {i}")
        if i < 4:
            record.setdefault("keystore", []).append(
                [("name", f"{kdf} {i}"), ("password", password.encode().hex() or "-"),
                 ("key", f"{se:064x}"), ("json", theirs)])


# ------------------------------------------------------------------- BIP-38 --

def aes_ecb(key, block, decrypt=False):
    c = Cipher(algorithms.AES(key), modes.ECB())
    op = c.decryptor() if decrypt else c.encryptor()
    return op.update(block) + op.finalize()


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def b58check_encode(data):
    from pycoin.encoding.b58 import b2a_hashed_base58
    return b2a_hashed_base58(data)


def b58check_decode(text):
    from pycoin.encoding.b58 import a2b_hashed_base58
    return a2b_hashed_base58(text)


def p2pkh_of(x, y, compressed):
    return BTC.address.for_p2pkh(hash160(point_bytes(x, y, compressed)))


def bip38_encrypt(se, compressed, passphrase):
    x, y = G * se
    ahash = sha256d(p2pkh_of(x, y, compressed).encode())[:4]
    d = hashlib.scrypt(passphrase, salt=ahash, n=16384, r=8, p=8, dklen=64)
    k = se.to_bytes(32, "big")
    e1 = aes_ecb(d[32:], xor(k[:16], d[:16]))
    e2 = aes_ecb(d[32:], xor(k[16:], d[16:32]))
    return b58check_encode(b"\x01\x42" + bytes([0xc0 | (0x20 if compressed else 0)]) + ahash
                           + e1 + e2)


def bip38_passfactor(passphrase, entropy, lot):
    pre = hashlib.scrypt(passphrase, salt=entropy[:4] if lot else entropy, n=16384, r=8, p=8,
                         dklen=32)
    return int.from_bytes(sha256d(pre + entropy) if lot else pre, "big")


def bip38_decrypt(text, passphrase):
    data = b58check_decode(text)
    flag = data[2]
    compressed = bool(flag & 0x20)
    ahash = data[3:7]
    if data[1] == 0x42:
        d = hashlib.scrypt(passphrase, salt=ahash, n=16384, r=8, p=8, dklen=64)
        k = xor(aes_ecb(d[32:], data[7:23], True), d[:16]) + \
            xor(aes_ecb(d[32:], data[23:39], True), d[16:32])
        se = int.from_bytes(k, "big")
    else:
        entropy = data[7:15]
        pf = bip38_passfactor(passphrase, entropy, bool(flag & 4))
        px, py = G * pf
        d = hashlib.scrypt(point_bytes(px, py), salt=ahash + entropy, n=1024, r=1, p=1,
                           dklen=64)
        b2 = xor(aes_ecb(d[32:], data[23:39], True), d[16:32])
        part1 = data[15:23] + b2[:8]
        seedb = xor(aes_ecb(d[32:], part1, True), d[:16]) + b2[8:]
        se = pf * int.from_bytes(sha256d(seedb), "big") % N
    x, y = G * se
    if sha256d(p2pkh_of(x, y, compressed).encode())[:4] != ahash:
        return None
    return se, compressed


def bip38_intermediate(passphrase, choose, lot):
    if lot:
        entropy = bytes(choose.randrange(256) for _ in range(4)) + \
            (lot[0] * 4096 + lot[1]).to_bytes(4, "big")
        magic = bytes.fromhex("2CE9B3E1FF39E251")
    else:
        entropy = bytes(choose.randrange(256) for _ in range(8))
        magic = bytes.fromhex("2CE9B3E1FF39E253")
    pf = bip38_passfactor(passphrase, entropy, bool(lot))
    px, py = G * pf
    return b58check_encode(magic + entropy + point_bytes(px, py))


def bip38_generate(intermediate, compressed, choose):
    data = b58check_decode(intermediate)
    lot = data[7] == 0x51
    entropy, passpoint = data[8:16], data[16:49]
    seedb = bytes(choose.randrange(256) for _ in range(24))
    factorb = int.from_bytes(sha256d(seedb), "big")
    from pycoin.encoding.sec import sec_to_public_pair
    px, py = sec_to_public_pair(passpoint, G)
    gx, gy = factorb * G.Point(px, py)
    address = p2pkh_of(gx, gy, compressed)
    ahash = sha256d(address.encode())[:4]
    d = hashlib.scrypt(passpoint, salt=ahash + entropy, n=1024, r=1, p=1, dklen=64)
    e1 = aes_ecb(d[32:], xor(seedb[:16], d[:16]))
    e2 = aes_ecb(d[32:], xor(e1[8:] + seedb[16:], d[16:32]))
    flag = (0x20 if compressed else 0) | (0x04 if lot else 0)
    # The confirmation code: pointb, its prefix masked by a bit of
    # derivedhalf2, its x under the same AES key.
    bx, by = factorb * G
    pointb = point_bytes(bx, by)
    cfrm = b58check_encode(bytes.fromhex("643BF6A89A") + bytes([flag]) + ahash + entropy
                           + bytes([pointb[0] ^ (d[63] & 1)])
                           + aes_ecb(d[32:], xor(pointb[1:17], d[:16]))
                           + aes_ecb(d[32:], xor(pointb[17:], d[16:32])))
    return (b58check_encode(b"\x01\x43" + bytes([flag]) + ahash + entropy + e1[:8] + e2),
            address, seedb, cfrm)


def check_bip38(choose, record, unicode_choose):
    import unicodedata
    plain = ["TestingOneTwoThree", "Satoshi", "", "a much longer passphrase " * 3]
    rounds = [(plain[i % 4], choose) for i in range(10)]
    rounds += [(p, unicode_choose) for p in UNICODE_PASSPHRASES]
    for i, (passphrase, draw) in enumerate(rounds):
        se = draw.randrange(1, N)
        compressed = i % 2 == 0
        key = BTC.keys.private(se, is_compressed=compressed)
        # BIP-38 hashes the passphrase in NFC; ours is handed it as typed.
        hashed = unicodedata.normalize("NFC", passphrase).encode()
        mine = ours("bip38", "encrypt", key.wif(), "--password-stdin",
                    stdin=passphrase + "\n").stdout.strip()
        theirs = bip38_encrypt(se, compressed, hashed)
        check(mine == theirs, f"bip38 encrypt: {i}")
        check(bip38_decrypt(mine, hashed) == (se, compressed),
              f"bip38 decrypt ours: {i}")
        got = fields(ours("bip38", "decrypt", theirs, "--password-stdin",
                          stdin=passphrase + "\n").stdout)
        check(got["WIF"] == key.wif() and got["address"] == key.address(),
              f"bip38 decrypt theirs: {i}")
        wrong = ours("bip38", "decrypt", theirs, "--password-stdin", stdin=passphrase + "x\n",
                     check_ok=False)
        check(wrong.returncode != 0, f"bip38 wrong passphrase: {i}")
    for i in range(8):
        passphrase = ["MOLON LABE", "TestingOneTwoThree", "Satoshi", "x"][i % 4]
        lot = (choose.randrange(1 << 20), choose.randrange(4096)) if i % 2 else None
        compressed = i % 4 >= 2
        # Ours makes the intermediate and the key; the reading here opens it.
        args = ["bip38", "intermediate", "--password", passphrase]
        if lot:
            args += ["--lot", lot[0], "--sequence", lot[1]]
        code = ours(*args).stdout.strip()
        gen = fields(ours("bip38", "generate", code,
                          *(["--compressed"] if compressed else [])).stdout)
        opened = bip38_decrypt(gen["encrypted key"], passphrase.encode())
        check(opened is not None and opened[1] == compressed, f"bip38 ec ours: {i}")
        if opened:
            x, y = G * opened[0]
            check(p2pkh_of(x, y, compressed) == gen["address"], f"bip38 ec address: {i}")
        conf = fields(ours("bip38", "confirm", gen["confirmation"], "--password",
                           passphrase).stdout)
        check(gen["address"] in conf.get("confirmed", ""), f"bip38 confirm: {i}")
        # The intermediate and key made here; ours opens them.
        code = bip38_intermediate(passphrase.encode(), choose, lot)
        key, address, seedb, cfrm = bip38_generate(code, compressed, choose)
        got = fields(ours("bip38", "decrypt", key, "--password", passphrase).stdout)
        check(got.get("address") == address, f"bip38 ec theirs: {i}")
        conf = fields(ours("bip38", "confirm", cfrm, "--password", passphrase).stdout)
        check(address in conf.get("confirmed", ""), f"bip38 confirm theirs: {i}")
        if lot:
            check(f"lot {lot[0]}, sequence {lot[1]}" in ours("bip38", "decrypt", key,
                  "--password", passphrase).stdout, f"bip38 lot: {i}")
        if i < 4:
            record.setdefault("bip38", []).append(
                [("name", f"ec {i}"), ("passphrase", passphrase), ("intermediate", code),
                 ("compressed", "yes" if compressed else "no"), ("seedb", seedb.hex()),
                 ("encrypted", key), ("address", address), ("confirmation", cfrm)])


def write_record(record):
    lines = ["# Answers from python-mnemonic, pycoin, OpenSSL 3.5's Keccak-256 and the",
             "# readings of Web3 Secret Storage and BIP-38 in scripts/check_wallet.py, kept",
             "# by its --record for the offline tests in examples/products/wallet. Hex",
             "# throughout unless named otherwise; - is empty.", ""]
    for section in ["bip39", "bip39-unicode", "bip32", "btc-message", "eth-message",
                    "keystore", "bip38"]:
        lines.append(f"[{section}]")
        for rec in record[section]:
            lines += [f"{k} = {v}" for k, v in rec]
        lines.append("")
    with open(os.path.join(FIXTURES, "wallet.vec"), "w") as f:
        f.write("\n".join(lines))


def main():
    global OURS
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--seed", type=int, default=32)
    args = parser.parse_args()
    OURS = args.ours
    choose = random.Random(args.seed)
    # The Unicode checks draw from their own generator, so that adding
    # them left every row recorded before them as it was.
    unicode_choose = random.Random(args.seed + 1)
    record = {}
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        check_bip39(choose, record)
        check_bip39_unicode(unicode_choose, record)
        check_bip32(choose, record)
        check_messages(choose, record)
        check_keystores(choose, record, tmp)
        check_bip38(choose, record, unicode_choose)
    if args.record:
        write_record(record)
    total = sum(COUNTS.values())
    print(", ".join(f"{k} {v}" for k, v in COUNTS.items()))
    print(f"{total - len(FAILURES)} of {total} passed")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
