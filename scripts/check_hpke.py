#!/usr/bin/env python3
"""HPKE (`publickey_ciphers::hpke`, through the Python module) against two
other implementations:

  * **pyhpke 0.6.5** (`pip install --target /opt/pyhpke pyhpke==0.6.5`, over
    python-cryptography): every DHKEM - P-256, P-384, P-521, X25519,
    X448 - with every HKDF and AEAD, in all four modes. pyhpke takes the
    ephemeral key pair as an argument, so both sides derive it from the
    same `ikmE` and must produce the same `enc` and the same ciphertext
    byte for byte; each must also open what the other sealed, and their
    exports must agree.
  * **filippo.io/hpke v0.4.0** (`scripts/witness/hpke/build.sh
    /opt/hpkewitness`), the HPKE behind Go's crypto/hpke: ML-KEM-768 and
    -1024, the three hybrid KEMs and the DHKEMs but X448, with every HKDF,
    both SHAKE KDFs and every AEAD, base mode, which is all it has. Its
    encapsulation draws its own randomness, so the check is that each
    side opens what the other sealed, exports agree, and both derive the
    same key pair from the same `ikm`.

    python3 scripts/build_python.py
    python3 scripts/check_hpke.py [--record]

`--record` writes `vectors/hpke_witness.vec`: for each witness, one
suite per KEM and mode (the KDF and AEAD turning over), with what the
witness sealed and exported for the library's tests to open, and what
the library sealed - from fixed randomness, so the test makes it again
byte for byte - which the witness opened.

**A development tool, not a test.**
"""

import argparse
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "python"))
sys.path.insert(0, "/opt/pyhpke")
import allcrypt  # noqa: E402
from pyhpke import AEADId, CipherSuite, KDFId, KEMId  # noqa: E402

GO = "/opt/hpkewitness/hpke-witness"
OUT = os.path.join(ROOT, "vectors", "hpke_witness.vec")
DHKEMS = [0x10, 0x11, 0x12, 0x20, 0x21]
GO_KEMS = [0x10, 0x11, 0x12, 0x20, 0x41, 0x42, 0x50, 0x51, 0x647A]
HKDFS = [1, 2, 3]
GO_KDFS = [1, 2, 3, 0x10, 0x11]
AEADS = [1, 2, 3, 0xFFFF]


def stream(label, length):
    """Fixed bytes, different for every label."""
    return hashlib.shake_256(label.encode()).digest(length)


def h(b):
    return b.hex() if b else "-"


class Go:
    def __init__(self):
        self.p = subprocess.Popen([GO], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def ask(self, *words):
        self.p.stdin.write(" ".join(w if isinstance(w, str) else h(w) for w in words) + "\n")
        self.p.stdin.flush()
        answer = self.p.stdout.readline().strip()
        if answer.startswith("error"):
            raise RuntimeError(answer)
        return [bytes.fromhex(x) if x != "-" else b"" for x in answer.split()]


class Report:
    def __init__(self):
        self.passed = self.failed = 0

    def __call__(self, ok, what):
        if ok:
            self.passed += 1
        else:
            self.failed += 1
            print(f"FAIL {what}")


def py_suite(kem, kdf, aead):
    return CipherSuite.new(KEMId(kem), KDFId(kdf), AEADId(aead))


def check_pyhpke(report, records):
    modes = ["base", "psk", "auth", "auth_psk"]
    for kem in DHKEMS:
        for kdf in HKDFS:
            for aead in AEADS:
                for mode in modes:
                    label = f"pyhpke {kem:#x} {kdf} {aead:#x} {mode}"
                    ours = allcrypt.HpkeSuite.from_ids(kem, kdf, aead)
                    theirs = py_suite(kem, kdf, aead)
                    ikm_r, ikm_s = (stream(f"{label} {x}", 66) for x in "rs")
                    ikm_e = stream(f"{label} e", ours.encap_randomness_len)
                    sk_r, pk_r = ours.derive_key_pair(ikm_r)
                    keys_r = theirs.kem.derive_key_pair(ikm_r)
                    report(keys_r.public_key.to_public_bytes() == pk_r, f"{label}: pkR")
                    psk = (stream(f"{label} psk", 32), b"psk id") if "psk" in mode else None
                    auth = mode.startswith("auth")
                    sk_s, pk_s = ours.derive_key_pair(ikm_s)
                    keys_s = theirs.kem.derive_key_pair(ikm_s)
                    info, aad = stream(f"{label} info", 20), stream(f"{label} aad", 9)
                    pt = stream(f"{label} pt", 45)
                    extra = {"psk": psk[0], "psk_id": psk[1]} if psk else {}
                    enc_t, ctx_t = theirs.create_sender_context(
                        theirs.kem.deserialize_public_key(pk_r), info,
                        sks=keys_s.private_key if auth else None,
                        eks=theirs.kem.derive_key_pair(ikm_e), **extra)
                    enc_o, ctx_o = ours.setup_sender(pk_r, info, psk, sk_s if auth else None,
                                                     ikm_e)
                    report(enc_t == enc_o, f"{label}: enc")
                    if aead != 0xFFFF:
                        ct_t, ct_o = ctx_t.seal(pt, aad), ctx_o.seal(pt, aad)
                        report(ct_t == ct_o, f"{label}: ciphertext")
                        opened = ours.open(enc_t, sk_r, ct_t, info, aad, psk,
                                           pk_s if auth else None)
                        report(opened == pt, f"{label}: ours opens theirs")
                        recipient = theirs.create_recipient_context(
                            enc_o, keys_r.private_key, info,
                            pks=keys_s.public_key if auth else None, **extra)
                        report(recipient.open(ct_o, aad) == pt, f"{label}: theirs opens ours")
                    else:
                        ct_t = ct_o = b""
                    export_t = ctx_t.export(b"exporter context", 41)
                    report(ctx_o.export(b"exporter context", 41) == export_t, f"{label}: export")
                    if kdf == HKDFS[(DHKEMS.index(kem) + modes.index(mode)) % 3] \
                            and aead == AEADS[(DHKEMS.index(kem) + modes.index(mode)) % 4]:
                        records.append(dict(
                            witness="pyhpke", kem=kem, kdf=kdf, aead=aead, mode=mode, ikmR=ikm_r,
                            ikmS=ikm_s if auth else b"", psk=psk[0] if psk else b"",
                            psk_id=psk[1] if psk else b"", info=info, aad=aad, pt=pt,
                            randomness=ikm_e, enc=enc_t, ct=ct_t,
                            export=export_t))


def check_go(report, records):
    go = Go()
    for kem in GO_KEMS:
        for kdf in GO_KDFS:
            for aead in AEADS:
                label = f"go {kem:#x} {kdf:#x} {aead:#x}"
                ours = allcrypt.HpkeSuite.from_ids(kem, kdf, aead)
                ikm = stream(f"{label} r", 64)
                sk_r, pk_r = ours.derive_key_pair(ikm)
                sk_t, pk_t = go.ask("derive", f"{kem:x}", ikm)
                # Go serializes an X25519 private key clamped; the public
                # keys, and its opening with the unclamped key, settle it.
                report(pk_t == pk_r and (sk_t == sk_r or kem == 0x20),
                       f"{label}: derived key pair")
                ids = (f"{kem:x}", f"{kdf:x}", f"{aead:x}")
                info, aad = stream(f"{label} info", 17), stream(f"{label} aad", 5)
                pt = stream(f"{label} pt", 33)
                randomness = stream(f"{label} e", ours.encap_randomness_len)
                enc_o, ctx_o = ours.setup_sender(pk_r, info, randomness=randomness)
                export_o = ctx_o.export(b"exporter context", 37)
                (export_t,) = go.ask("export", *ids, sk_r, enc_o, info, b"exporter context", "37")
                report(export_t == export_o, f"{label}: export")
                if aead == 0xFFFF:
                    enc_t, ct_t, ct_o = b"", b"", b""
                    try:
                        go.ask("seal", *ids, pk_r, info, aad, pt)
                        report(False, f"{label}: an export-only suite sealed")
                    except RuntimeError:
                        pass
                else:
                    ct_o = ctx_o.seal(pt, aad)
                    (opened,) = go.ask("open", *ids, sk_r, enc_o, info, aad, ct_o)
                    report(opened == pt, f"{label}: theirs opens ours")
                    enc_t, ct_t = go.ask("seal", *ids, pk_r, info, aad, pt)
                    report(ours.open(enc_t, sk_r, ct_t, info, aad) == pt,
                           f"{label}: ours opens theirs")
                theirs_enc = enc_t if aead != 0xFFFF else enc_o
                (export_theirs,) = go.ask("export", *ids, sk_r, theirs_enc, info,
                                          b"exporter context", "37")
                mine = ours.setup_receiver(theirs_enc, sk_r, info).export(b"exporter context", 37)
                report(mine == export_theirs, f"{label}: export of theirs")
                index = GO_KEMS.index(kem)
                if kdf == GO_KDFS[index % 5] and aead == AEADS[index % 4] \
                        or kdf == GO_KDFS[(index + 3) % 5] and aead == AEADS[(index + 1) % 4]:
                    records.append(dict(
                        witness="go", kem=kem, kdf=kdf, aead=aead, mode="base", ikmR=ikm,
                        ikmS=b"", psk=b"", psk_id=b"", info=info, aad=aad, pt=pt,
                        randomness=randomness, ours_enc=enc_o, ours_ct=ct_o, enc=theirs_enc,
                        ct=ct_t, export=export_theirs))


def write(records):
    with open(OUT, "w") as handle:
        handle.write(
            "# HPKE between this library and two others, written by scripts/check_hpke.py\n"
            "# --record; do not edit. witness=pyhpke (0.6.5): both sealed from the same\n"
            "# ikmE (`randomness`) and agreed byte for byte; enc and ct are theirs. witness=go\n"
            "# (filippo.io/hpke v0.4.0): enc and ct are what it sealed and export what it\n"
            "# exported for that enc; ours_enc and ours_ct are what this library sealed from\n"
            "# `randomness`, which it opened. Keys are derived from ikmR (and ikmS).\n")
        handle.write(f"# rows: {len(records)}\n")
        for r in records:
            fields = [f"witness={r['witness']}", f"kem={r['kem']:x}", f"kdf={r['kdf']:x}",
                      f"aead={r['aead']:x}", f"mode={r['mode']}"]
            for key in ("ikmR", "ikmS", "psk", "psk_id", "info", "aad", "pt", "randomness",
                        "enc", "ct", "export", "ours_enc", "ours_ct"):
                if key in r:
                    fields.append(f"{key}={h(r[key])}")
            handle.write(" ".join(fields) + "\n")
    print(f"wrote {OUT}: {len(records)} rows")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    report = Report()
    records = []
    check_pyhpke(report, records)
    check_go(report, records)
    print(f"{report.passed} passed, {report.failed} failed")
    if report.failed:
        sys.exit(1)
    if args.record:
        write(records)


if __name__ == "__main__":
    main()
