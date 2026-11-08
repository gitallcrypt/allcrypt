"""IEEE 802.11's KDF over SHA-256/384/512, Suite B 192-bit's PTK and the
fast BSS transition key hierarchy through the Python binding. The Rust
test holds every row of vectors/ieee80211_ft.vec, from hostapd and
Wireshark; this checks the binding on some of each kind, and the
refusals."""

import os

import pytest

import allcrypt

VECTORS = os.path.join(os.path.dirname(__file__), "..", "vectors", "ieee80211_ft.vec")


def b(v):
    return b"" if v == "-" else bytes.fromhex(v)


def test_witness_rows():
    seen = {}
    with open(VECTORS) as f:
        for line in f:
            if line.startswith("#"):
                continue
            kind, *fields = line.split()
            r = dict(w.split("=", 1) for w in fields)
            seen[kind] = seen.get(kind, 0) + 1
            if seen[kind] > 40:
                continue
            name = None
            if kind == "kdf":
                out = allcrypt.ieee80211_kdf(f"sha{r['hash']}", b(r["key"]),
                                             memoryview(b(r["label"])), bytearray(b(r["context"])),
                                             int(r["bytes"]) * 8)
            elif kind == "ptk384":
                out = allcrypt.wpa_ptk("sha384", b(r["pmk"]), b(r["aa"]), b(r["spa"]),
                                       b(r["anonce"]), b(r["snonce"]), 704)
            elif kind == "r0":
                out, name = allcrypt.wpa_ft_pmk_r0(b(r["xxkey"]), b(r["ssid"]), b(r["mdid"]),
                                                   b(r["r0kh"]), b(r["s0kh"]))
            elif kind == "r1":
                out, name = allcrypt.wpa_ft_pmk_r1(b(r["pmk_r0"]), b(r["pmk_r0_name"]),
                                                   b(r["r1kh"]), b(r["s1kh"]))
            else:
                pmk_r1 = b(r["pmk_r1"])
                kck_kek = {32: 32, 48: 56, 64: 64}[len(pmk_r1)]
                tk = 16 if r["cipher"] == "ccmp" else 32
                out = allcrypt.wpa_ft_ptk(pmk_r1, b(r["snonce"]), b(r["anonce"]), b(r["bssid"]),
                                          b(r["sta"]), (kck_kek + tk) * 8)
            assert out.hex() == r["out"], (kind, r)
            if name is not None:
                assert name.hex() == r["name"], (kind, r)
    assert set(seen) == {"kdf", "ptk384", "r0", "r1", "ftptk"}


def test_refusals():
    sta = bytes(6)
    with pytest.raises(ValueError, match="32, 48 or 64 bytes"):
        allcrypt.wpa_ft_pmk_r0(bytes(40), b"ssid", b"\x01\x02", b"r0kh", sta)
    with pytest.raises(ValueError, match="R0KH-ID"):
        allcrypt.wpa_ft_pmk_r0(bytes(32), b"ssid", b"\x01\x02", b"", sta)
    with pytest.raises(ValueError, match="mobility domain"):
        allcrypt.wpa_ft_pmk_r0(bytes(32), b"ssid", b"\x01", b"r0kh", sta)
    with pytest.raises(ValueError, match="PMKR0Name"):
        allcrypt.wpa_ft_pmk_r1(bytes(32), bytes(15), sta, sta)
    with pytest.raises(ValueError, match="sha512"):
        allcrypt.ieee80211_kdf("md5", b"k", b"l", b"c", 256)
    with pytest.raises(ValueError, match="sha384"):
        allcrypt.wpa_ptk("sha512", bytes(48), sta, sta, bytes(32), bytes(32), 704)
