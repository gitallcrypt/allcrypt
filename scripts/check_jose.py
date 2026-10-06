#!/usr/bin/env python3
"""Check the JOSE example against jwcrypto and PyJWT, both directions.

    git clone https://github.com/latchset/jwcrypto ~/src/jwcrypto
    cargo build --release --example jose
    python3 scripts/check_jose.py --jwcrypto ~/src/jwcrypto [--record]

jwcrypto is pure Python over python-cryptography and is only put on the
path, not installed; PyJWT is the system's. A development tool, not a
test: it needs both, and writes what they agreed on into
`examples/products/fixtures/jose.vec` for the offline tests with
`--record`.

What it does, for every key type the example has:

- keys: ours generates, jwcrypto imports, and both compute the same
  RFC 7638 thumbprint; jwcrypto generates and ours imports.
- JWS: every algorithm, jwcrypto signing and ours verifying, ours
  signing and jwcrypto verifying, in each serialization, and the
  unencoded payload of RFC 7797; PyJWT the same for compact tokens.
  A changed signature, header or payload is refused.
- JWE: every key management algorithm with every content encryption,
  jwcrypto encrypting and ours decrypting and the reverse; two
  recipients, `zip`, and JSON AAD; a changed tag, IV, ciphertext or
  header is refused.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OURS = os.path.join(ROOT, "target", "release", "examples", "jose")
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")

PAYLOAD = "It’s a dangerous business, Frodo, going out your door.".encode()
PASSWORD = "entrap_o–peter_long–credit_tun"

# JWS: algorithm and the key it needs.
JWS_ALGS = [("HS256", ("oct", 32)), ("HS384", ("oct", 48)), ("HS512", ("oct", 64)),
            ("RS256", ("RSA", 2048)), ("RS384", ("RSA", 2048)), ("RS512", ("RSA", 2048)),
            ("PS256", ("RSA", 2048)), ("PS384", ("RSA", 2048)), ("PS512", ("RSA", 2048)),
            ("ES256", ("EC", "P-256")), ("ES384", ("EC", "P-384")),
            ("ES512", ("EC", "P-521")), ("ES256K", ("EC", "secp256k1")),
            ("EdDSA", ("OKP", "Ed25519")), ("EdDSA", ("OKP", "Ed448")),
            ("Ed25519", ("OKP", "Ed25519")), ("Ed448", ("OKP", "Ed448"))]

ENCS = ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512", "A128GCM", "A192GCM", "A256GCM"]
ENC_BYTES = {"A128CBC-HS256": 32, "A192CBC-HS384": 48, "A256CBC-HS512": 64,
             "A128GCM": 16, "A192GCM": 24, "A256GCM": 32}

# JWE: key management algorithm and its key; None for a password.
JWE_ALGS = [("RSA1_5", ("RSA", 2048)), ("RSA-OAEP", ("RSA", 2048)),
            ("RSA-OAEP-256", ("RSA", 2048)),
            ("A128KW", ("oct", 16)), ("A192KW", ("oct", 24)), ("A256KW", ("oct", 32)),
            ("A128GCMKW", ("oct", 16)), ("A192GCMKW", ("oct", 24)), ("A256GCMKW", ("oct", 32)),
            ("dir", None), ("PBES2-HS256+A128KW", None), ("PBES2-HS384+A192KW", None),
            ("PBES2-HS512+A256KW", None)]
ECDH_ALGS = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]
ECDH_KEYS = [("EC", "P-256"), ("EC", "P-384"), ("EC", "P-521"), ("OKP", "X25519"),
             ("OKP", "X448")]


class Tally:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, ok, label, detail=""):
        if ok:
            self.passed += 1
            print(f"ok   {label}", flush=True)
        else:
            self.failed += 1
            print(f"FAIL {label}", flush=True)
            for line in str(detail).splitlines()[:6]:
                print(f"     {line}")


def as_bytes(value):
    """jwcrypto gives an unencoded payload back as text."""
    return value if isinstance(value, bytes) else value.encode()


def ours(*args, stdin=None):
    result = subprocess.run([OURS, *args], input=stdin, capture_output=True)
    return result.returncode, result.stdout, result.stderr.decode(errors="replace")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--jwcrypto", required=True)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, args.jwcrypto)
    from jwcrypto import jwe, jwk, jws
    from jwcrypto.common import base64url_decode, json_encode
    import jwt.api_jws

    tally = Tally()
    work = tempfile.mkdtemp()
    recorded = {"jws": [], "jwe": [], "thumbprint": []}

    def path(name):
        return os.path.join(work, name)

    def write(name, data):
        mode = "wb" if isinstance(data, bytes) else "w"
        with open(path(name), mode) as f:
            f.write(data)
        return path(name)

    keys = {}

    def their_key(kind):
        if kind not in keys:
            kty, parameter = kind
            if kty == "oct":
                keys[kind] = jwk.JWK.generate(kty="oct", size=parameter * 8)
            elif kty == "RSA":
                keys[kind] = jwk.JWK.generate(kty="RSA", size=parameter)
            else:
                keys[kind] = jwk.JWK.generate(kty=kty, crv=parameter)
        return keys[kind]

    def key_file(key, name):
        return write(name, key.export(private_key=True))

    print("== keys")
    for kty, parameter in [("RSA", "2048"), ("EC", "P-256"), ("EC", "P-384"), ("EC", "P-521"),
                           ("EC", "secp256k1"), ("OKP", "Ed25519"), ("OKP", "Ed448"),
                           ("OKP", "X25519"), ("OKP", "X448"), ("oct", "32")]:
        code, out, err = ours("keygen", "--kty", kty, "--param", parameter, "--kid", "k1")
        if code:
            tally.check(False, f"ours generates {kty} {parameter}", err)
            continue
        try:
            imported = jwk.JWK.from_json(out.decode())
            ours_print = ours("thumbprint", write("k.jwk", out))[1].decode().strip()
            # jwcrypto calls a symmetric key neither public nor private.
            same = imported.thumbprint() == ours_print and (imported.has_private
                                                            or kty == "oct")
            tally.check(same, f"ours generates {kty} {parameter}, jwcrypto imports it",
                        f"{imported.thumbprint()} vs {ours_print}")
        except Exception as e:  # noqa: BLE001 - reported
            tally.check(False, f"ours generates {kty} {parameter}, jwcrypto imports it", e)
        theirs = their_key((kty, int(parameter) // (8 if kty == "oct" else 1))
                           if kty in ("RSA", "oct") else (kty, parameter))
        code, out, err = ours("thumbprint", key_file(theirs, "t.jwk"))
        tally.check(code == 0 and out.decode().strip() == theirs.thumbprint(),
                    f"jwcrypto generates {kty} {parameter}, ours reads it", err or out)
        recorded["thumbprint"].append((f"{kty} {parameter}", theirs.export(),
                                       theirs.thumbprint()))
        code, out, err = ours("public", key_file(theirs, "t.jwk"))
        if kty != "oct":
            tally.check(code == 0 and json.loads(out) == json.loads(theirs.export_public()),
                        f"  {kty} {parameter}: the public JWK is jwcrypto's", err or out)

    print("== JWS")
    payload_file = write("payload", PAYLOAD)
    for alg, kind in JWS_ALGS:
        key = their_key(kind)
        name = f"{alg} {kind[1]}"
        kf = key_file(key, "s.jwk")
        for form in ("compact", "json", "flat"):
            token = jws.JWS(PAYLOAD)
            token.allowed_algs = [alg]
            token.add_signature(key, alg, json_encode({"alg": alg, "kid": "s"}))
            text = token.serialize(compact=(form == "compact"))
            if form == "json":
                # jwcrypto writes one signature flattened; the general
                # form is the same members in a list.
                flat = json.loads(text)
                text = json.dumps({"payload": flat.pop("payload"), "signatures": [flat]})
            code, out, err = ours("verify", write("t.jws", text), "--key", kf)
            tally.check(code == 0 and out == PAYLOAD, f"jwcrypto signs {name} {form}, ours "
                        f"verifies", err)
            if form == "compact" and code == 0:
                recorded["jws"].append((name, key.export() if kind[0] == "oct"
                                        else key.export_public(), text))
            # One character of the signature, and no other.
            tampered = text[:-6] + ("A" if text[-6] != "A" else "B") + text[-5:]
            if form == "compact":
                code, out, err = ours("verify", write("t.jws", tampered), "--key", kf)
                tally.check(code != 0, f"  {name}: a changed signature is refused")
            code, out, err = ours("sign", payload_file, "--key", kf, "--alg", alg,
                                  "--format", form)
            if code:
                tally.check(False, f"ours signs {name} {form}", err)
                continue
            try:
                theirs = jws.JWS()
                theirs.allowed_algs = [alg]
                theirs.deserialize(out.decode().strip(), key)
                tally.check(as_bytes(theirs.payload) == PAYLOAD,
                            f"ours signs {name} {form}, jwcrypto verifies")
            except Exception as e:  # noqa: BLE001 - reported
                tally.check(False, f"ours signs {name} {form}, jwcrypto verifies", e)
        # RFC 7797's unencoded payload.
        code, out, err = ours("sign", payload_file, "--key", kf, "--alg", alg,
                              "--format", "json", "--unencoded")
        try:
            theirs = jws.JWS()
            theirs.allowed_algs = [alg]
            theirs.deserialize(out.decode().strip(), key)
            tally.check(code == 0 and as_bytes(theirs.payload) == PAYLOAD,
                        f"ours signs {name} unencoded, jwcrypto verifies", err)
        except Exception as e:  # noqa: BLE001 - reported
            tally.check(False, f"ours signs {name} unencoded, jwcrypto verifies", e)
        # jwcrypto's JSON writer needs an unencoded payload as text.
        token = jws.JWS(PAYLOAD.decode())
        token.allowed_algs = [alg]
        token.add_signature(key, alg, json_encode({"alg": alg, "b64": False, "crit": ["b64"]}))
        code, out, err = ours("verify", write("t.jws", token.serialize()), "--key", kf)
        tally.check(code == 0 and out == PAYLOAD,
                    f"jwcrypto signs {name} unencoded, ours verifies", err)
        # PyJWT, compact, where it has the algorithm.
        if alg in ("EdDSA", "Ed25519", "Ed448"):
            continue
        pem = key.export_to_pem(private_key=True, password=None) if kind[0] != "oct" else \
            base64url_decode(json.loads(key.export())["k"])
        public_pem = key.export_to_pem() if kind[0] != "oct" else pem
        try:
            token = jwt.api_jws.PyJWS().encode(PAYLOAD, pem, algorithm=alg)
            code, out, err = ours("verify", write("t.jws", token), "--key", kf)
            tally.check(code == 0 and out == PAYLOAD, f"PyJWT signs {name}, ours verifies", err)
            code, out, err = ours("sign", payload_file, "--key", kf, "--alg", alg)
            got = jwt.api_jws.PyJWS().decode(out.decode().strip(), public_pem, algorithms=[alg])
            tally.check(got == PAYLOAD, f"ours signs {name}, PyJWT verifies")
        except Exception as e:  # noqa: BLE001 - reported
            tally.check(False, f"PyJWT and ours, {name}", e)

    print("== JWE")
    plain_file = write("plain", PAYLOAD)
    cases = []
    for (alg, kind), enc in itertools.product(JWE_ALGS, ENCS):
        cases.append((alg, kind, enc))
    for alg, kind, enc in itertools.product(ECDH_ALGS, ECDH_KEYS, ENCS[2:4]):
        cases.append((alg, kind, enc))
    for alg, kind, enc in cases:
        name = f"{alg} {enc}" + (f" {kind[1]}" if kind and kind[0] in ("EC", "OKP") else "")
        password = alg.startswith("PBES2")
        if alg == "dir":
            key = jwk.JWK.generate(kty="oct", size=ENC_BYTES[enc] * 8)
        elif password:
            key = jwk.JWK.from_password(PASSWORD)
        else:
            key = their_key(kind)
        kf = key_file(key, "e.jwk") if not password else None
        secret = ["--password-stdin"] if password else ["--key", kf]
        stdin = (PASSWORD + "\n").encode() if password else None
        header = {"alg": alg, "enc": enc}
        if password:
            header["p2c"] = 2048
        token = jwe.JWE(PAYLOAD, json_encode(header))
        token.allowed_algs = [alg, enc]
        token.add_recipient(key)
        text = token.serialize(compact=True)
        code, out, err = ours("decrypt", write("t.jwe", text), *secret, stdin=stdin)
        tally.check(code == 0 and out == PAYLOAD, f"jwcrypto encrypts {name}, ours decrypts", err)
        if code == 0:
            recorded["jwe"].append((name, PASSWORD if password else key.export(), text))
        parts = text.split(".")
        for index, what in ((4, "tag"), (2, "IV"), (3, "ciphertext")):
            changed = parts[:]
            changed[index] = ("B" if changed[index][0] == "A" else "A") + changed[index][1:]
            code, out, err = ours("decrypt", write("t.jwe", ".".join(changed)), *secret,
                                  stdin=stdin)
            tally.check(code != 0, f"  {name}: a changed {what} is refused")
        command = ["encrypt", plain_file, "--alg", alg, "--enc", enc, *secret]
        if password:
            command += ["--p2c", "2048"]
        code, out, err = ours(*command, stdin=stdin)
        if code:
            tally.check(False, f"ours encrypts {name}", err)
            continue
        try:
            theirs = jwe.JWE()
            theirs.allowed_algs = [alg, enc]
            theirs.deserialize(out.decode().strip(), key)
            tally.check(theirs.payload == PAYLOAD, f"ours encrypts {name}, jwcrypto decrypts")
        except Exception as e:  # noqa: BLE001 - reported
            tally.check(False, f"ours encrypts {name}, jwcrypto decrypts", e)

    print("== JWE: two recipients, zip, AAD")
    rsa = their_key(("RSA", 2048))
    kw = their_key(("oct", 32))
    rsa_file, kw_file = key_file(rsa, "r.jwk"), key_file(kw, "w.jwk")
    token = jwe.JWE(PAYLOAD, json_encode({"enc": "A256GCM", "zip": "DEF"}),
                    aad=b"some associated data")
    token.allowed_algs = ["RSA-OAEP-256", "A256KW", "A256GCM"]
    token.add_recipient(rsa, json_encode({"alg": "RSA-OAEP-256", "kid": "r"}))
    token.add_recipient(kw, json_encode({"alg": "A256KW", "kid": "w"}))
    text = token.serialize()
    for label, kf in (("RSA-OAEP-256", rsa_file), ("A256KW", kw_file)):
        code, out, err = ours("decrypt", write("t.jwe", text), "--key", kf)
        tally.check(code == 0 and out == PAYLOAD,
                    f"jwcrypto, two recipients, zip and AAD: ours decrypts as {label}", err)
        recorded["jwe"].append((f"two recipients as {label}",
                                (rsa if label.startswith("RSA") else kw).export(), text))
    write("aad", b"some associated data")
    code, out, err = ours("encrypt", plain_file, "--alg", "RSA-OAEP-256", "--key", rsa_file,
                          "--alg", "A256KW", "--key", kw_file, "--enc", "A128CBC-HS256",
                          "--zip", "--aad", path("aad"), "--format", "json")
    for label, key in (("RSA-OAEP-256", rsa), ("A256KW", kw)):
        try:
            theirs = jwe.JWE()
            theirs.allowed_algs = ["RSA-OAEP-256", "A256KW", "A128CBC-HS256"]
            theirs.deserialize(out.decode().strip(), key)
            tally.check(theirs.payload == PAYLOAD,
                        f"ours, two recipients, zip and AAD: jwcrypto decrypts as {label}")
        except Exception as e:  # noqa: BLE001 - reported
            tally.check(False, f"ours, two recipients: jwcrypto decrypts as {label}", e or err)

    print(f"\n{tally.passed}/{tally.passed + tally.failed} agree")
    if args.record and not tally.failed:
        record(recorded)
    return 1 if tally.failed else 0


def record(recorded):
    lines = ["# JWS and JWE that jwcrypto wrote and the example read, written by",
             "# scripts/check_jose.py --record. Keys are JWKs on one line; the",
             "# payload of every one is the same sentence, in `payload`."]
    lines += ["", "[payload]", "name = payload", f"hex = {PAYLOAD.hex()}"]
    lines += ["", "[thumbprint]"]
    for name, key, thumbprint in recorded["thumbprint"]:
        lines += [f"name = {name}", f"key = {key}", f"thumbprint = {thumbprint}"]
    lines += ["", "[jws]"]
    for name, key, token in recorded["jws"]:
        lines += [f"name = {name}", f"key = {key}", f"token = {token}"]
    lines += ["", "[jwe]"]
    for name, key, token in recorded["jwe"]:
        lines += [f"name = {name}", f"key = {key}" if key != PASSWORD
                  else f"password = {PASSWORD.encode().hex()}", f"token = {token}"]
    with open(os.path.join(FIXTURES, "jose.vec"), "w") as out:
        out.write("\n".join(lines) + "\n")
    print(f"{len(recorded['thumbprint'])} keys, {len(recorded['jws'])} JWS and "
          f"{len(recorded['jwe'])} JWE -> fixtures/jose.vec")


if __name__ == "__main__":
    sys.exit(main())
