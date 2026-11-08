#!/usr/bin/env python3
"""The Wi-Fi example (`examples/products/wifi`) against Wireshark's
`tshark`, on the captures Wireshark's own decryption tests use.

Wireshark's source tree carries 802.11 captures for its decryption test
suite (`test/captures/`) and the keys that open them
(`test/config/80211_keys.tmpl`): WPA3-SAE and OWE (whose PMKs are
listed, since no capture reveals them), management frame protection,
GCMP-128 and -256, CCMP-256, TKIP group keys and their rekeying. For each
capture here, the example and `tshark -o wlan.enable_decryption:TRUE`
must decrypt the same frames to the same plaintext, frame by frame -
data frames to a station and to a group address, and protected
management frames. `tshark` prints each frame's decrypted bytes with
`--hexdump all`.

    git clone --depth 1 --branch v4.6.9 https://github.com/wireshark/wireshark ws46
    cmake -S ws46 -B ws46/build -G Ninja -DBUILD_wireshark=OFF \
        -DBUILD_stratoshark=OFF -DENABLE_LUA=OFF && ninja -C ws46/build tshark
    cargo build --release --example wifi
    python3 scripts/check_wifi_wireshark.py --wireshark ws46 \
        --tshark ws46/build/run/tshark [--record]

`tshark` 4.2.2, Ubuntu 24.04's, leaves the TKIP group frames of
`wpa2-psk-ccmp-tkip` encrypted, so that capture fails against it; 4.6.9
decrypts them.

The key for each capture is found by trying every passphrase and PMK in
Wireshark's list, the SSID taken from the capture.

None of those captures has a protected QoS frame of a priority other
than 0, a fragment, or an HT Control field, so two more are made here:
`wpa2-psk-ccmp-tkip` and `wpa-gcmp` with frames appended that have them,
sealed under the TK and GTK `tshark` itself reports for the capture
(`wlan.analysis.tk`, and the GTK from message 3's key data): CCMP and
GCMP with python-cryptography, TKIP group frames with this library's
TKIP and Michael. `tshark` decrypting them is what says they were built
right; the example must then decrypt the same frames to the same
plaintext.

A frame with four addresses (WDS, mesh, a four-address station) names
no BSSID, and `tshark` takes the larger of its two link addresses for
one. Every capture above has the access point at the smaller, so a
twelfth capture is made whole: a beacon and a WPA2-PSK 4-way handshake
with the access point at the larger address - the PTK, the MICs and the
wrapped GTK computed here from IEEE 802.11's key hierarchy, with hashlib and
python-cryptography - then CCMP frames with four addresses in both
directions. `tshark` derives its own keys from that handshake, so it
checks the handshake as well as the frames. `--record` copies the
captures (decompressed) into `examples/products/fixtures/wifi/wireshark/`
and writes `fixtures/wifi-wireshark.vec`, with the frames decrypted and
the SHA-256 of their plaintexts, for the example's offline tests.

**A development tool, not a test.**
"""

import argparse
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import sys
import struct
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "wifi")

# The captures, and what each shows.
CASES = [
    ("wpa-test-decode-mgmt.pcap.gz", "management frame protection: action and "
     "deauthentication frames"),
    ("wpa2-psk-mfp.pcapng.gz", "PSK-SHA256, management frame protection, a GTK"),
    ("wpa2-psk-ccmp-tkip.pcapng.gz", "CCMP pairwise, TKIP group"),
    ("wpa1-gtk-rekey.pcapng.gz", "WPA, TKIP, the group key rekeyed"),
    ("wpa-gcmp.pcapng.gz", "GCMP-128"),
    ("wpa-gcmp-256.pcapng.gz", "GCMP-256"),
    ("wpa-ccmp-256.pcapng.gz", "CCMP-256"),
    ("wpa3-sae.pcapng.gz", "WPA3-SAE, from its PMK"),
    ("owe.pcapng.gz", "OWE, from its PMK"),
]


# Captures to append synthesized frames to: (base, cipher, what).
SYNTHETIC = [
    ("wpa2-psk-ccmp-tkip.pcapng.gz", "ccmp", "QoS priorities, retry and power "
     "management bits, fragments, an HT Control field: CCMP pairwise, TKIP group"),
    ("wpa-gcmp.pcapng.gz", "gcmp", "QoS priorities, an HT Control field: GCMP"),
    ("wpa2-psk-mfp.pcapng.gz", "management", "protected action frames, one with an HT "
     "Control field and one with the retry bit"),
]


def mac(text):
    return bytes.fromhex(text.replace(":", ""))


def tshark_keys(capture, key, tmp, tshark):
    """The TK and the station's and access point's addresses from the
    first frame the station sent, and the GTK and its index, as `tshark`
    derived them."""
    config = os.path.join(tmp, "wireshark")
    os.makedirs(config, exist_ok=True)
    kind = "wpa-pwd" if key[0] == "password" else "wpa-psk"
    with open(os.path.join(config, "80211_keys"), "w") as handle:
        handle.write(f'"{kind}","{key[1]}"\n')
    result = subprocess.run([tshark, "-o", "wlan.enable_decryption:TRUE", "-r", capture,
                             "-T", "fields", "-E", "separator=|", "-e", "wlan.analysis.tk",
                             "-e", "wlan.fc.ds", "-e", "wlan.ta", "-e", "wlan.ra",
                             "-e", "wlan.rsn.ie.gtk_kde.key_id", "-e", "wlan.rsn.ie.gtk_kde.gtk"],
                            capture_output=True, text=True,
                            env={**os.environ, "WIRESHARK_CONFIG_DIR": config})
    out = {}
    for line in result.stdout.splitlines():
        tk, ds, ta, ra, key_id, gtk = (line.split("|") + [""] * 6)[:6]
        if tk and ds == "0x01" and "tk" not in out:
            out.update(tk=bytes.fromhex(tk), station=mac(ta), bssid=mac(ra))
        if gtk and "gtk" not in out:
            out.update(gtk=bytes.fromhex(gtk), gtk_index=int(key_id, 16))
    return out


def ccmp_aad(header, tid):
    """CCMP's and GCMP's additional data (IEEE 802.11-2020 12.5.3.3.3)
    for a QoS data frame: subtype, retry, power management, more data
    and, with a QoS Control field, order masked; the sequence number
    masked, the fragment number kept; the fourth address when both DS
    bits are set; the TID."""
    fc0 = header[0] & 0x8F
    fc1 = (header[1] & ~0x38 & ~0x80 & 0xFF) | 0x40
    a4 = header[24:30] if header[1] & 3 == 3 else b""
    return bytes([fc0, fc1]) + header[4:22] + bytes([header[22] & 0x0F, 0]) + a4 + bytes([tid, 0])


def qos_header(fc1, a1, a2, a3, seq, frag, tid, htc=None, a4=b""):
    """A QoS data frame's header (subtype 8), with a fourth address when
    `a4` is given (both DS bits then set), and the HT Control field after
    the QoS Control when `htc` is (the order bit set)."""
    if htc is not None:
        fc1 |= 0x80
    if a4:
        fc1 |= 0x03
    header = bytes([0x88, fc1, 0, 0]) + a1 + a2 + a3 + struct.pack("<H", seq << 4 | frag) + a4
    return header + bytes([tid, 0]) + (htc or b"")


def seal_aead(cipher, tk, header, tid, pn, plaintext):
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
    pn_bytes = pn.to_bytes(6, "big")
    a2 = header[10:16]
    aad = ccmp_aad(header, tid)
    if cipher == "ccmp":
        sealed = AESCCM(tk, tag_length=8).encrypt(bytes([tid]) + a2 + pn_bytes, plaintext, aad)
    else:
        sealed = AESGCM(tk).encrypt(a2 + pn_bytes, plaintext, aad)
    ext = bytes([pn_bytes[5], pn_bytes[4], 0, 0x20, pn_bytes[3], pn_bytes[2], pn_bytes[1],
                 pn_bytes[0]])
    return header + ext + sealed


def seal_management(tk, header, pn, plaintext):
    """CCMP over a management frame: the nonce's flags byte has bit 4
    set, and the additional data keeps the frame control's subtype and
    order bits."""
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    pn_bytes = pn.to_bytes(6, "big")
    fc1 = (header[1] & ~0x38 & 0xFF) | 0x40
    aad = bytes([header[0], fc1]) + header[4:22] + bytes([header[22] & 0x0F, 0])
    sealed = AESCCM(tk, tag_length=8).encrypt(bytes([0x10]) + header[10:16] + pn_bytes,
                                              plaintext, aad)
    ext = bytes([pn_bytes[5], pn_bytes[4], 0, 0x20, pn_bytes[3], pn_bytes[2], pn_bytes[1],
                 pn_bytes[0]])
    return header + ext + sealed


def seal_tkip_group(gtk, index, header, tid, tsc, plaintext):
    sys.path.insert(0, os.path.join(ROOT, "python"))
    import allcrypt
    da, sa = header[4:10], header[16:22]
    mic = allcrypt.tkip_msdu_mic(gtk[16:24], da, sa, tid, plaintext)
    t = tsc.to_bytes(6, "little")
    iv = bytes([t[1], (t[1] | 0x20) & 0x7F, t[0], 0x20 | index << 6, t[2], t[3], t[4], t[5]])
    return header + iv + allcrypt.tkip_encrypt(gtk[:16], header[10:16], tsc, plaintext + mic)


def synthesize(cipher, keys):
    """The frames appended: each direction at a non-zero priority, one
    with an HT Control field, one with retry and power management set,
    and for CCMP a frame sent in two fragments and a TKIP group frame."""
    ap, sta, tk = keys["bssid"], keys["station"], keys["tk"]
    from_ap, to_ap = 0x42, 0x41
    if cipher == "management":
        # Action frames (subtype 13): an SA Query request, then one with
        # the order bit and an HT Control field, and one retried.
        action = lambda fc1, seq, htc=b"": (bytes([0xD0, fc1, 0, 0]) + sta + ap + ap
                                            + struct.pack("<H", seq << 4) + htc)
        return [seal_management(tk, action(0x40, 0x600), 0x20001, b"\x08\x00\x12\x34"),
                seal_management(tk, action(0xC0, 0x601, b"\x0c\x00\x00\x00"), 0x20002,
                                b"\x08\x00\x56\x78"),
                seal_management(tk, action(0x48, 0x602), 0x20003, b"\x08\x00\x9a\xbc")]
    body = lambda n: b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(
        (n * 37 + i) & 0xFF for i in range(40 + n))
    frames = [
        seal_aead(cipher, tk, qos_header(from_ap, sta, ap, ap, 0x700, 0, 5), 5, 0x10001, body(1)),
        seal_aead(cipher, tk, qos_header(to_ap | 0x18, ap, sta, ap, 0x701, 0, 6), 6, 0x10002,
                  body(2)),
        seal_aead(cipher, tk, qos_header(from_ap, sta, ap, ap, 0x702, 0, 4,
                                         htc=b"\x0c\x00\x00\x00"), 4, 0x10003, body(3)),
    ]
    if cipher == "ccmp":
        whole = body(4) + bytes(range(60))
        frames.append(seal_aead(cipher, tk, qos_header(to_ap | 0x04, ap, sta, ap, 0x703, 0, 2),
                                2, 0x10004, whole[:50]))
        frames.append(seal_aead(cipher, tk, qos_header(to_ap, ap, sta, ap, 0x703, 1, 2),
                                2, 0x10005, whole[50:]))
        frames.append(seal_tkip_group(keys["gtk"], keys["gtk_index"],
                                      qos_header(from_ap, b"\xff" * 6, ap, ap, 0x704, 0, 3),
                                      3, 0x2001, body(5)))
    return frames


def prf(key, label, data, bits):
    """IEEE 802.11's PRF over HMAC-SHA1."""
    import hmac
    out = b""
    for i in range((bits + 159) // 160):
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), "sha1").digest()
    return out[:bits // 8]


def eapol_key(info, nonce, mic=bytes(16), data=b"", replay=1):
    """An EAPOL-Key frame (descriptor 2, the RSN one) after its LLC/SNAP
    header: key information, key length 16, the replay counter, the
    nonce, a zero key IV, RSC and ID, the MIC and the key data."""
    body = (bytes([2]) + struct.pack(">HH", info, 16) + struct.pack(">Q", replay) + nonce
            + bytes(16 + 8 + 8) + mic + struct.pack(">H", len(data)) + data)
    return (b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + bytes([2, 3])
            + struct.pack(">H", len(body)) + body)


def handshake_capture(out):
    """A whole capture, link type 105: a beacon, the 4-way handshake, and
    CCMP QoS frames with four addresses each way. Returns the SSID, the
    passphrase and how many frames precede the four-address ones."""
    import hashlib
    import hmac
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap
    ssid, password = "allcrypt-wds", "four addresses"
    ap, sta = b"\x02\x00\x00\x00\x09\x00", b"\x02\x00\x00\x00\x03\x00"
    anonce = hashlib.sha256(b"anonce").digest()
    snonce = hashlib.sha256(b"snonce").digest()
    gtk = hashlib.sha256(b"gtk").digest()[:16]
    pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), ssid.encode(), 4096, 32)
    ptk = prf(pmk, b"Pairwise key expansion", min(ap, sta) + max(ap, sta)
              + min(anonce, snonce) + max(anonce, snonce), 384)
    kck, kek, tk = ptk[:16], ptk[16:32], ptk[32:48]
    rsn = bytes.fromhex("30140100000fac040100000fac040100000fac020000")
    mic = lambda frame: hmac.new(kck, frame[8:], "sha1").digest()[:16]
    seq = iter(range(0x100, 0x200))
    header = lambda fc0, fc1, a1, a2, a3: (bytes([fc0, fc1, 0, 0]) + a1 + a2 + a3
                                           + struct.pack("<H", next(seq) << 4))
    beacon = (header(0x80, 0, b"\xff" * 6, ap, ap) + bytes(8) + struct.pack("<HH", 100, 0x0411)
              + bytes([0, len(ssid)]) + ssid.encode() + rsn)
    frames = [beacon]

    def signed(info, nonce, data=b"", replay=1):
        unsigned = eapol_key(info, nonce, data=data, replay=replay)
        return eapol_key(info, nonce, mic(unsigned), data, replay)
    # Key information: version 2 (HMAC-SHA1, AES key wrap), pairwise 0x08,
    # install 0x40, ack 0x80, MIC 0x100, secure 0x200, encrypted 0x1000.
    key_data = rsn + bytes([0xDD, 6 + len(gtk), 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00]) + gtk
    key_data += b"\xdd" + bytes(-(len(key_data) + 1) % 8)
    frames.append(header(0x08, 0x02, sta, ap, ap) + eapol_key(0x008A, anonce))
    frames.append(header(0x08, 0x01, ap, sta, ap) + signed(0x010A, snonce, rsn))
    frames.append(header(0x08, 0x02, sta, ap, ap)
                  + signed(0x13CA, anonce, aes_key_wrap(kek, key_data), replay=2))
    frames.append(header(0x08, 0x01, ap, sta, ap) + signed(0x030A, bytes(32), replay=2))
    before = len(frames)
    body = lambda n: b"\xaa\xaa\x03\x00\x00\x00\x08\x00" + bytes(
        (n * 53 + i) & 0xFF for i in range(30 + n))
    for n, (a1, a2, tid) in enumerate([(sta, ap, 0), (ap, sta, 5), (sta, ap, 6)]):
        frames.append(seal_aead("ccmp", tk, qos_header(0x40, a1, a2, b"\x0a" * 6, 0x300 + n, 0,
                                                       tid, a4=b"\x0b" * 6), tid, 0x100 + n,
                                body(n)))
    with open(out, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105))
        for i, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", 2000000000 + i, 0, len(frame), len(frame)))
            handle.write(frame)
    return ssid, password, before


def append_frames(capture, frames, out, tshark):
    """`capture` as classic pcap with `frames` after its own, behind a
    bare radiotap header when the capture's link type has one; returns
    how many frames the capture had."""
    subprocess.run([tshark, "-r", capture, "-w", out, "-F", "pcap"], check=True,
                   capture_output=True)
    data = open(out, "rb").read()
    if data[:4] != b"\xd4\xc3\xb2\xa1":
        sys.exit(f"{out}: tshark did not write little-endian pcap")
    linktype = struct.unpack("<I", data[20:24])[0]
    prefix = {105: b"", 127: b"\x00\x00\x08\x00\x00\x00\x00\x00"}.get(linktype)
    if prefix is None:
        sys.exit(f"{out}: link type {linktype}")
    count, at = 0, 24
    while at < len(data):
        count += 1
        at += 16 + struct.unpack("<I", data[at + 8:at + 12])[0]
    with open(out, "ab") as handle:
        for i, frame in enumerate(frames):
            record = prefix + frame
            handle.write(struct.pack("<IIII", 2000000000 + i, 0, len(record), len(record)))
            handle.write(record)
    return count


def keys(path):
    """Wireshark's key list: (kind, value) for every passphrase and
    32-byte PMK - the forms the example takes."""
    out = []
    for line in open(path):
        match = re.match(r'"([\w-]+)","([^"]*)"', line)
        if match and match[1] == "wpa-pwd":
            out.append(("password", match[2]))
        elif match and match[1] == "wpa-psk" and len(match[2]) == 64:
            out.append(("pmk", match[2]))
    return out


def ssid(capture, tshark):
    result = subprocess.run([tshark, "-r", capture, "-T", "fields", "-e", "wlan.ssid",
                             "-Y", "wlan.ssid"], capture_output=True, text=True)
    for line in result.stdout.split():
        if line:
            return bytes.fromhex(line).decode() if re.fullmatch(r"[0-9a-f]+", line) else line
    return None


def ours(capture, essid, key, tmp):
    """{frame number: plaintext} the example decrypted."""
    listing = os.path.join(tmp, "frames")
    args = [OURS, "decrypt", capture, "--frames", listing]
    stdin = None
    if key[0] == "pmk":
        args += ["--pmk", key[1]]
    else:
        args += ["--essid", essid, "--password-stdin"]
        stdin = key[1] + "\n"
    result = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if result.returncode != 0:
        return {}
    out = {}
    for line in open(listing):
        number, _kind, plaintext = line.split()
        out[int(number)] = bytes.fromhex(plaintext)
    return out


def theirs(capture, key, tmp, tshark):
    """{frame number: plaintext} tshark decrypted, from `-P --hexdump
    all`: each frame's summary line, which starts with its number, then
    its data sources - a "Decrypted CCMP data" (or GCMP, TKIP, WEP) one
    among them when it decrypted. Message 3's "Decrypted AES keydata" is
    not a frame's plaintext."""
    config = os.path.join(tmp, "wireshark")
    os.makedirs(config, exist_ok=True)
    kind = "wpa-pwd" if key[0] == "password" else "wpa-psk"
    with open(os.path.join(config, "80211_keys"), "w") as handle:
        handle.write(f'"{kind}","{key[1]}"\n')
    result = subprocess.run([tshark, "-o", "wlan.enable_decryption:TRUE", "-r", capture,
                             "-P", "--hexdump", "all"], capture_output=True, text=True,
                            env={**os.environ, "WIRESHARK_CONFIG_DIR": config})
    out, number, current = {}, 0, None
    for line in result.stdout.splitlines():
        summary = re.match(r"^\s*(\d+)\s+\d+\.\d+ ", line)
        if summary:
            number = int(summary[1])
            current = None
        elif re.match(r"^Decrypted (CCMP|GCMP|TKIP|WEP) data \(", line):
            current = bytearray()
            out[number] = current
        elif re.match(r"^[0-9a-f]{4}  ", line):
            if current is not None:
                current.extend(bytes.fromhex(line[6:54].replace(" ", "")))
        else:
            # A blank line, or another data source's heading - message 3's
            # key data follows the frame's own plaintext directly.
            current = None
    return {k: bytes(v) for k, v in out.items()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--wireshark", required=True, help="a Wireshark source tree")
    parser.add_argument("--tshark", default="tshark", help="the tshark to run")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    captures = os.path.join(args.wireshark, "test", "captures")
    candidates = keys(os.path.join(args.wireshark, "test", "config", "80211_keys.tmpl"))
    version = subprocess.run([args.tshark, "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    passed = failed = 0
    records = []
    used, cases = {}, []
    with tempfile.TemporaryDirectory() as tmp:
        for name, what in CASES:
            capture = os.path.join(tmp, name.removesuffix(".gz"))
            with gzip.open(os.path.join(captures, name)) as source, open(capture, "wb") as out:
                out.write(source.read())
            essid = ssid(capture, args.tshark)
            best = max(candidates, key=lambda k: len(ours(capture, essid, k, tmp)))
            used[name] = (capture, essid, best)
            cases.append((name.removesuffix(".gz"), capture, what, essid, best, 0, 0))
        for name, cipher, what in SYNTHETIC:
            capture, essid, best = used[name]
            keys_ = tshark_keys(capture, best, tmp, args.tshark)
            frames = synthesize(cipher, keys_)
            out = os.path.join(tmp, name.split(".")[0] + "+synthetic.pcap")
            base = append_frames(capture, frames, out, args.tshark)
            cases.append((os.path.basename(out), out, what, essid, best, len(frames), base))
        out = os.path.join(tmp, "wpa2-psk-4addr.pcap")
        essid, password, base = handshake_capture(out)
        cases.append((os.path.basename(out), out, "a WPA2-PSK handshake made here, the access "
                      "point at the larger address; CCMP with four addresses each way", essid,
                      ("password", password), 3, base))
        for name, capture, what, essid, best, added, base in cases:
            mine = ours(capture, essid, best, tmp)
            other = theirs(capture, best, tmp, args.tshark)
            # Every synthesized frame must have opened for tshark, or it
            # was built wrong rather than read wrong.
            appended = sum(1 for n in other if n > base) if added else 0
            ok = bool(mine) and mine == other and appended == added
            passed += ok
            failed += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name}: {what}; {len(mine)} frames ours, "
                  f"{len(other)} tshark's" + (f", {appended} of {added} synthesized" if added
                                             else ""))
            if not ok:
                for number in sorted(set(mine) | set(other)):
                    if mine.get(number) != other.get(number):
                        print(f"     frame {number}: ours {mine.get(number, b'').hex()[:40]} "
                              f"tshark {other.get(number, b'').hex()[:40]}")
                continue
            plaintexts = b"".join(mine[n] for n in sorted(mine))
            records.append({"name": name,
                            "capture": f"wifi/wireshark/{name}",
                            "shows": what, "essid": essid or "-",
                            "password": best[1] if best[0] == "password" else "-",
                            "pmk": best[1] if best[0] == "pmk" else "-",
                            "frames": ",".join(str(n) for n in sorted(mine)),
                            "plaintext_sha256": hashlib.sha256(plaintexts).hexdigest(),
                            "data": open(capture, "rb").read()})
    print(f"{passed} of {passed + failed} captures agree")
    if failed:
        sys.exit(1)
    if args.record:
        out_dir = os.path.join(FIXTURES, "wifi", "wireshark")
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir)
        os.makedirs(out_dir)
        with open(os.path.join(FIXTURES, "wifi-wireshark.vec"), "w") as handle:
            handle.write(
                "# Wi-Fi captures from Wireshark's decryption tests, for\n"
                "# examples/products/wifi's tests. Written by\n"
                "# scripts/check_wifi_wireshark.py --record; do not edit. frames are the\n"
                "# frame numbers (from 1) both decrypted; plaintext_sha256 is the SHA-256 of\n"
                "# their plaintexts in that order, which equalled tshark's.\n"
                f"#\n# {version}\n\n[captures]\n")
            blocks = []
            for record in records:
                with open(os.path.join(out_dir, record["name"]), "wb") as out:
                    out.write(record.pop("data"))
                blocks.append("".join(f"{k} = {v}\n" for k, v in record.items()))
            handle.write("\n".join(blocks))
        print(f"recorded {len(records)} captures")


if __name__ == "__main__":
    main()
