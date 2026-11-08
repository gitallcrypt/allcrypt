#!/usr/bin/env python3
"""Write vectors/ieee80211_ft.vec: IEEE 802.11's KDF-SHA256, -SHA384 and
-SHA512, Suite B 192-bit's PTK, and the fast BSS transition key
hierarchy (PMK-R0, PMK-R1 and their names, the FT PTK), answered by
hostapd (wpa_supplicant 2.11's src/common/wpa_common.c) and Wireshark
4.6 (epan/crypt/dot11decrypt_util.c), built by scripts/witness/ft80211.

    sh scripts/witness/ft80211/build.sh WPA_SRC WIRESHARK_SRC WIRESHARK_BUILD /opt/ftwitness
    python3 scripts/make_ieee80211_ft_vectors.py [--witness /opt/ftwitness]

Where both implement a value they must agree, and each row names who
gave it. Wireshark has no Suite B PTK function, computes PMKR0Name and
PMKR1Name with SHA-256 whatever the key's length (hostapd and 802.11
take the key's hash), and its KDF writes nothing for an output shorter
than an eighth of a hash and refuses one past 1024 bits' worth of
blocks; those rows carry hostapd's answer alone.

The inputs come from a fixed seed, so the file is the same each run.
Both witnesses also run under ASan and UBSan on misaligned buffers and
must agree with themselves. **A development tool, not a test.**
"""

import argparse
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "vectors", "ieee80211_ft.vec")


def hexor(data):
    return data.hex() if data else "-"


def cases(rng):
    rows = []
    labels = [b"FT-R0", b"FT-R1", b"FT-PTK", b"Pairwise key expansion"]
    for h in (256, 384, 512):
        for i in range(160):
            label = labels[i % 4] if i % 3 else bytes(rng.choice(b"abcdefgh -") for _ in
                                                      range(rng.randrange(0, 40)))
            out = rng.choice([1, 3, 7, 16, 24, 32, 48, 63, 64, 65, 88, 96, 128, 129, 200,
                              rng.randrange(1, 300)])
            rows.append(("kdf", dict(hash=h, key=rng.randbytes(rng.randrange(0, 150)),
                                     label=label,
                                     context=rng.randbytes(rng.randrange(0, 150)),
                                     bytes=out)))
    for _ in range(60):
        rows.append(("ptk384", dict(pmk=rng.randbytes(48), aa=rng.randbytes(6),
                                    spa=rng.randbytes(6), anonce=rng.randbytes(32),
                                    snonce=rng.randbytes(32))))
    for i in range(240):
        q = (32, 48, 64)[i % 3]
        ssid_len = i % 33 if i < 99 else rng.randrange(0, 33)
        r0kh_len = 1 + (i * 7) % 48
        rows.append(("r0", dict(xxkey=rng.randbytes(q), ssid=rng.randbytes(ssid_len),
                                mdid=rng.randbytes(2), r0kh=rng.randbytes(r0kh_len),
                                s0kh=rng.randbytes(6))))
    for i in range(120):
        q = (32, 48, 64)[i % 3]
        rows.append(("r1", dict(pmk_r0=rng.randbytes(q), pmk_r0_name=rng.randbytes(16),
                                r1kh=rng.randbytes(6), s1kh=rng.randbytes(6))))
    for i in range(120):
        q = (32, 48, 64)[i % 3]
        rows.append(("ftptk", dict(cipher=("ccmp", "gcmp256")[i // 3 % 2],
                                   pmk_r1=rng.randbytes(q), snonce=rng.randbytes(32),
                                   anonce=rng.randbytes(32), bssid=rng.randbytes(6),
                                   sta=rng.randbytes(6))))
    return rows


def request(kind, f):
    if kind == "kdf":
        return (f"kdf {f['hash']} {hexor(f['key'])} {hexor(f['label'])} {hexor(f['context'])} "
                f"{f['bytes']}")
    if kind == "ptk384":
        return "ptk384 " + " ".join(f[k].hex() for k in ("pmk", "aa", "spa", "anonce",
                                                         "snonce"))
    if kind == "r0":
        return "r0 " + " ".join(hexor(f[k]) for k in ("xxkey", "ssid", "mdid", "r0kh", "s0kh"))
    if kind == "r1":
        return "r1 " + " ".join(f[k].hex() for k in ("pmk_r0", "pmk_r0_name", "r1kh", "s1kh"))
    return f"ftptk {f['cipher']} " + " ".join(f[k].hex() for k in ("pmk_r1", "snonce", "anonce",
                                                                   "bssid", "sta"))


def run(binary, rows, misalign):
    env = dict(os.environ, MISALIGN="1" if misalign else "0",
               ASAN_OPTIONS="detect_leaks=0:abort_on_error=1")
    text = "\n".join(request(kind, f) for kind, f in rows) + "\n"
    result = subprocess.run([binary], input=text, capture_output=True, text=True, env=env)
    # Wireshark logs each refusal; anything else on stderr is a fault.
    stderr = [line for line in result.stderr.splitlines()
              if line.strip() and "dot11decrypt_kdf(): Invalid input sizes" not in line]
    if result.returncode != 0 or stderr:
        sys.exit(f"{binary}: {result.returncode} {result.stderr[-3000:]}")
    lines = result.stdout.split("\n")[:-1]
    if len(lines) != len(rows):
        sys.exit(f"{binary}: {len(lines)} answers to {len(rows)} requests")
    return lines


def wireshark_can(kind, f):
    """Whether Wireshark is asked at all: its KDF runs bytes * 8 /
    hash_bytes blocks, none below an eighth of a hash, and refuses past
    1024 bytes of blocks; and dot11decrypt_derive_pmk_r0's buffer holds
    a 48 byte key and its salt, so a SHA-512 key overflows the stack
    (its own caller only asks for SHA-256 and SHA-384)."""
    if kind == "ptk384":
        return False
    if kind == "kdf":
        hash_bytes = f["hash"] // 8
        blocks = f["bytes"] * 8 // hash_bytes
        return blocks >= 1 and blocks * hash_bytes <= 1024
    key = f.get("xxkey") or f.get("pmk_r0") or f.get("pmk_r1")
    return len(key) <= 48


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--witness", default="/opt/ftwitness")
    args = parser.parse_args()
    rows = cases(random.Random(0x80211))
    answers = {}
    for name, asked in (("hostapd-ft", rows),
                        ("wireshark-ft", [r for r in rows if wireshark_can(*r)])):
        plain = run(os.path.join(args.witness, name), asked, False)
        if run(os.path.join(args.witness, name + "-san"), asked, True) != plain:
            sys.exit(f"{name} disagrees with its sanitizer build on misaligned buffers")
        answers[name] = iter(plain)
    counts = {}
    with open(OUT, "w") as handle:
        handle.write(
            "# IEEE 802.11 KDF-SHA256/384/512, Suite B 192-bit's PTK and the fast BSS\n"
            "# transition key hierarchy, from hostapd (wpa_supplicant 2.11) and Wireshark\n"
            "# 4.6's dot11decrypt. Written by scripts/make_ieee80211_ft_vectors.py; do not\n"
            "# edit. Hex, - for empty. r0 and r1 answer the key then its name (name=);\n"
            "# ptk384 and ftptk answer KCK || KEK || TK. witnesses: who gave the answer,\n"
            "# name_witnesses: who gave the name.\n")
        for kind, f in rows:
            hostapd = next(answers["hostapd-ft"])
            if hostapd == "error":
                sys.exit(f"hostapd refused {kind} {f}")
            witnesses = ["hostapd"]
            name_witnesses = ["hostapd"]
            key, _, name = hostapd.partition(" ")
            if wireshark_can(kind, f):
                ws_key, _, ws_name = next(answers["wireshark-ft"]).partition(" ")
                if ws_key != key:
                    sys.exit(f"Wireshark and hostapd disagree: {kind} {f}\n{wireshark}\n{hostapd}")
                witnesses.append("wireshark")
                if name:
                    if ws_name == name:
                        name_witnesses.append("wireshark")
                    elif len(key) == 64:
                        sys.exit(f"Wireshark's SHA-256 name disagrees: {kind} {f}")
            fields = [f"{k}={v if isinstance(v, (int, str)) else hexor(v)}" for k, v in f.items()]
            fields.append(f"out={key}")
            if name:
                fields.append(f"name={name}")
                fields.append(f"name_witnesses={','.join(name_witnesses)}")
            fields.append(f"witnesses={','.join(witnesses)}")
            handle.write(f"{kind} {' '.join(fields)}\n")
            counts[kind] = counts.get(kind, 0) + 1
    print(f"wrote {OUT}: {counts}")


if __name__ == "__main__":
    main()
