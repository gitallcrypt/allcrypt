#!/usr/bin/env python3
"""The Wi-Fi example (`examples/products/wifi`) against aircrack-ng's
`airdecap-ng` and its capture files.

aircrack-ng's test suite ships packet captures with the keys to open
them (`test/*.cap`, and the passphrases in its `test-airdecap-ng-*.sh`):
WEP, and WPA/WPA2 with TKIP and with CCMP, each with the 4-way handshake
in the clear. For each one, our `decrypt` and `airdecap-ng` must agree,
packet for packet, on the decrypted record payloads (the Ethernet frames
both write; the pcap timestamps differ and are not compared), and our
tally of decrypted frames must match the "decrypted WPA/WEP" line
`airdecap-ng` prints.

    python3 scripts/check_wifi.py --airdecap ~/src/aircrack-ng/airdecap-ng \
        --captures ~/src/aircrack-ng/test
    python3 scripts/check_wifi.py --captures DIR --record

`--record` copies the smaller captures and what was decrypted into
`examples/products/fixtures/` for the example's offline tests.

**A development tool, not a test.** It needs an `airdecap-ng` build and
aircrack-ng's captures; the gate runs none of it.
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")

# Each capture, the key it opens with, and what to record offline.
# (name, essid, password, wep_key, record_offline)
CASES = [
    ("wpa.cap", "test", "biscotte", None, True),
    ("wpa2-psk-linksys.cap", "linksys", "dictionary", None, True),
    ("wpa-psk-linksys.cap", "linksys", "dictionary", None, True),
    ("wep_64_ptw.cap", None, None, "1F:1F:1F:1F:1F", False),
    ("wep.shared.key.authentication.cap", None, None, "1F:1F:1F:1F:1F", False),
]


def records(path):
    """The decrypted pcap's record payloads, timestamps dropped."""
    d = open(path, "rb").read()
    out, at = [], 24
    while at + 16 <= len(d):
        caplen = struct.unpack("<I", d[at + 8:at + 12])[0]
        out.append(d[at + 16:at + 16 + caplen])
        at += 16 + caplen
    return out


def ours(binary, capture, essid, password, wep_key, out):
    args = [binary, "decrypt", capture, "--out", out]
    stdin = None
    if wep_key:
        args += ["--wep-key", wep_key]
    else:
        args += ["--essid", essid, "--password-stdin"]
        stdin = (password + "\n").encode()
    run = subprocess.run(args, input=stdin, capture_output=True, text=stdin is None)
    stdout = run.stdout if isinstance(run.stdout, str) else run.stdout.decode()
    m = re.search(r"Decrypted W(?:EP|PA) frames:\s+(\d+)",
                  "\n".join(l for l in stdout.splitlines() if "Decrypted" in l and
                            l.split()[-1] != "0") or stdout)
    n = sum(int(x) for x in re.findall(r"Decrypted W(?:EP|PA) frames:\s+(\d+)", stdout))
    return n


def theirs(airdecap, capture, essid, password, wep_key, out, tmp):
    if wep_key:
        args = [airdecap, "-w", wep_key.replace(":", ""), capture, "-o", out, "-c", "/dev/null"]
    else:
        args = [airdecap, "-e", essid, "-p", password, capture, "-o", out, "-c", "/dev/null"]
    run = subprocess.run(args, capture_output=True, text=True)
    n = sum(int(x) for x in re.findall(r"Number of decrypted W(?:EP|PA)\s+packets\s+(\d+)",
                                       run.stdout))
    return n


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--airdecap", default="/tmp/airdecap-ng")
    parser.add_argument("--captures", required=True, metavar="DIR")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    subprocess.run(["cargo", "build", "--quiet", "--release", "--example", "wifi"],
                   cwd=ROOT, check=True)
    binary = os.path.join(ROOT, "target", "release", "examples", "wifi")
    failures = rows = 0
    records_vec = []

    def report(ok, label, detail=""):
        nonlocal failures, rows
        rows += 1
        failures += not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label:48} {'' if ok else detail}")

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        for name, essid, password, wep_key, record in CASES:
            capture = os.path.join(args.captures, name)
            if not os.path.exists(capture):
                report(False, name, "capture missing")
                continue
            our_out = os.path.join(d, "ours.pcap")
            their_out = os.path.join(d, "theirs.pcap")
            try:
                n_ours = ours(binary, capture, essid, password, wep_key, our_out)
                n_theirs = theirs(args.airdecap, capture, essid, password, wep_key, their_out, d)
                ro, rt = records(our_out), records(their_out)
                ok = ro == rt and n_ours == n_theirs and n_ours == len(ro)
                report(ok, name, f"ours {n_ours}/{len(ro)} recs, airdecap {n_theirs}/{len(rt)}")
                if ok and record and args.record:
                    os.makedirs(os.path.join(FIXTURES, "wifi"), exist_ok=True)
                    shutil.copy(capture, os.path.join(FIXTURES, "wifi", name))
                    payloads = b"".join(ro)
                    records_vec.append(dict(
                        name=name, capture=f"wifi/{name}", essid=essid or "",
                        password=password or "", wep_key=wep_key or "", decrypted=str(n_ours),
                        payload_sha256=hashlib.sha256(payloads).hexdigest()))
            except Exception as error:  # noqa: BLE001 - reported, not hidden
                report(False, name, str(error)[-200:])

    print(f"{rows - failures} of {rows} passed.")
    if args.record and not failures:
        banner = subprocess.run([args.airdecap], capture_output=True, text=True).stdout
        version = next((l.strip() for l in banner.splitlines() if "decap" in l.lower()),
                       "aircrack-ng")
        with open(os.path.join(FIXTURES, "wifi.vec"), "w") as f:
            f.write("# Wi-Fi captures from aircrack-ng's test suite, for\n"
                    "# examples/products/wifi's tests. Written by scripts/check_wifi.py\n"
                    "# --record. The capture is fixtures/wifi/NAME; payload_sha256 is the\n"
                    "# SHA-256 of the decrypted Ethernet records' payloads concatenated,\n"
                    f"# which equalled airdecap-ng's. Do not edit.\n#\n# {version}\n\n[captures]\n")
            for r in records_vec:
                f.write("\n")
                for key in ("name", "capture", "essid", "password", "wep_key", "decrypted",
                            "payload_sha256"):
                    f.write(f"{key} = {r[key] or '-'}\n")
        print(f"wrote {len(records_vec)} captures to {FIXTURES}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
