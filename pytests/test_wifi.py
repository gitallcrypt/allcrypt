"""Wi-Fi primitives through the binding: WEP, TKIP's key mixing, Michael
and the WPA key derivations. The RC4 keystream and CRC the WEP and TKIP
tests need are written out here; the handshake values are IEEE 802.11's
own, from aircrack-ng's PTK unit test."""

import zlib

import pytest

import allcrypt


def _rc4(key, data):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out, i, j = bytearray(), 0, 0
    for b in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)


@pytest.mark.parametrize("n", [0, 1, 16, 100])
def test_wep_is_rc4_over_data_and_crc(n):
    key, iv, data = b"ABCDE", bytes([1, 2, 3]), bytes(range(n % 256)) * (n // 256 + 1)
    data = data[:n]
    sealed = allcrypt.wep_encrypt(key, iv, data)
    body = data + (zlib.crc32(data) & 0xffffffff).to_bytes(4, "little")
    assert sealed == _rc4(iv + key, body)
    assert allcrypt.wep_decrypt(key, iv, sealed) == data
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.wep_decrypt(b"WRONG", iv, sealed)


def test_michael_chain_from_ieee_80211():
    """IEEE 802.11's Michael test vectors (Linux crypto/testmgr.h): each
    tag keys the next."""
    key = bytes(8)
    for message, tag in [(b"", "82925c1ca1d130b8"), (b"M", "434721ca40639b3f"),
                         (b"Mi", "e8f9becae97e5d29"), (b"Mic", "90038fc6cf13c1db"),
                         (b"Mich", "d55e100510128986"), (b"Michael", "0a942b124ecaa546")]:
        assert allcrypt.michael(key, message).hex() == tag
        key = allcrypt.michael(key, message)
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.michael(b"short", b"x")


def test_tkip_key_first_three_bytes_are_the_wep_iv():
    tk, ta = bytes(range(16)), bytes([2, 0, 0, 0, 0, 1])
    key = allcrypt.tkip_rc4_key(tk, ta, 0x1234)
    assert key[:3] == bytes([0x12, 0x32, 0x34])
    assert len(key) == 16
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.tkip_rc4_key(bytes(15), ta, 0)


def test_wpa_psk_rfc_vectors():
    """IEEE 802.11i Annex H.4.2."""
    assert allcrypt.wpa_psk(b"password", b"IEEE").hex() == (
        "f42c6fc52df0ebef9ebb4b90b38a5f90"
        "2e83fe1b135a70e23aed762e9710a12e")
    assert allcrypt.wpa_psk(b"ThisIsAPassword", b"ThisIsASSID").hex() == (
        "0dc0d6eb90555ed6419756b9a15ec3e3"
        "209b63df707dd508d14581f8982721af")


def test_wpa_ptk_and_pmkid_from_aircrack_vector():
    """aircrack-ng's calc-ptk unit test (IEEE values)."""
    pmk = bytes.fromhex("ee51883793a6f68e9615fe73c80a3aa6f2dd0ea537bce627b929183cc6e57925")
    stmac = bytes.fromhex("001346fe320c")
    bssid = bytes.fromhex("00146c7e4080")
    snonce = bytes.fromhex("59168bc3a5df18d71efb6423f340088dab9e1ba2bbc58659e07b37"
                           "64b0de8570")
    anonce = bytes.fromhex("225854b0444de3af06d1492b852984f04cf6274c0e3218b86817"
                           "56864db7a055")
    ptk = allcrypt.wpa_ptk("sha1", pmk, bssid, stmac, anonce, snonce, 512)
    assert ptk.hex().startswith("ea0e404633c8024503028")
    assert len(ptk) == 64
    # PMKID is defined; just check length and determinism here.
    pmkid = allcrypt.wpa_pmkid(pmk, bssid, stmac)
    assert len(pmkid) == 16 and allcrypt.wpa_pmkid(pmk, bssid, stmac) == pmkid
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.wpa_ptk("md5", pmk, bssid, stmac, anonce, snonce, 512)
