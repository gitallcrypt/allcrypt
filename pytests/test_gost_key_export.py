"""RFC 9189's key exchange pieces through Python, against the RFC's own
worked handshakes, read out of the vendored document.

Appendix A.1.3 prints two CTR_OMAC handshakes and A.2.2 one CNT_IMIT
handshake with every value along the way: the server's key pair, the
client's ephemeral one, H, the export keys, the preliminary secret and
its export. KEG and KExp15 are checked on the first two, KEG_28147,
CryptoPro diversification and KExp28147 on the third - from both ends,
since KEG(d_eph, Q_s, H) and KEG(d_s, Q_eph, H) are the same keys.
"""

import pathlib
import re

import pytest

import allcrypt

TEXT = (pathlib.Path(__file__).resolve().parent.parent / "rfcs" / "rfc9189.txt") \
    .read_text(encoding="utf-8-sig")

#: The names the appendix gives its curves, as this library names them.
CURVES = {"1.2.643.2.2.35.1": "gost256-a", "1.2.643.7.1.2.1.2.3": "gost512-c",
          "1.2.643.7.1.2.1.2.1": "gost512-a"}


def example(heading, end):
    """From `heading` at the start of a line - the table of contents
    repeats each one, indented - to the next `end` likewise."""
    start = TEXT.index("\n" + heading)
    return TEXT[start:TEXT.index("\n" + end, start + len(heading))]


def number(section, label):
    """A `0x...` value after `label`, continued on lines of hex alone."""
    match = re.search(re.escape(label) + r"\s*0x([0-9A-F]+)((?:\n[ \t]+[0-9A-F]+(?=\n))*)",
                      section)
    return int(match.group(1) + re.sub(r"\s", "", match.group(2)), 16)


def octets(section, label):
    """The `00000:   A5 57 ...` dump after `label`."""
    start = re.search(label, section).end()
    out = b""
    for line in section[start:].splitlines()[1:]:
        dump = re.match(r"\s+[0-9A-F]{5}:\s+((?:[0-9A-F]{2} ?)+)$", line)
        if not dump:
            break
        out += bytes.fromhex(dump.group(1))
    return out


def point(section, label, size):
    sub = section[section.index(label):]
    return b"\x04" + number(sub, "x =").to_bytes(size, "big") + \
        number(sub, "y =").to_bytes(size, "big")


def handshake(heading, end):
    text = example(heading, end)
    oid = re.search(r'"([0-9.]+)"', text).group(1)
    curve = CURVES[oid]
    size = 32 if curve.startswith("gost256") else 64
    client = text[text.index("Random d_eph value:"):]
    return {
        "curve": curve,
        "size": size,
        "d_s": number(text, "Server private key d_s:").to_bytes(size, "big"),
        "q_s": point(text, "Server public key Q_s:", size),
        "d_eph": number(client, "Random d_eph value:").to_bytes(size, "big"),
        "q_eph": point(client, "Q_eph ephemeral key:", size),
        "h": octets(client, r"HASH ?\(r_c \| r_s\):"),
        "pms": octets(text, r"PMS(?: value)?:"),
        "iv": octets(client, r"\n   IV:"),
        "pmsexp": octets(client, r"PMSEXP:"),
        "text": client,
    }


@pytest.mark.parametrize("heading,end,cipher", [
    ("A.1.3.1.  TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "A.1.3.2.  ", "magma"),
    ("A.1.3.2.  TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "A.2.  ", "kuznyechik"),
])
def test_keg_and_kexp15_against_rfc_9189(heading, end, cipher):
    hs = handshake(heading + " Cipher Suite", end)
    export = octets(hs["text"], r"Export keys K_Exp_MAC \| K_Exp_ENC used in KExp15")
    assert (len(hs["h"]), len(export), len(hs["pms"])) == (32, 64, 32)

    server = allcrypt.EcKey.from_private(hs["curve"], hs["d_s"])
    client = allcrypt.EcKey.from_private(hs["curve"], hs["d_eph"])
    assert server.public_key().public_bytes() == hs["q_s"]
    assert client.public_key().public_bytes() == hs["q_eph"]
    assert client.gost_keg(hs["q_s"], hs["h"]) == export
    assert server.gost_keg(hs["q_eph"], hs["h"]) == export

    # IV = H[25..24 + n/2]: half Magma's block or half Kuznyechik's.
    assert hs["iv"] == hs["h"][24:24 + {"magma": 4, "kuznyechik": 8}[cipher]]
    wrapped = allcrypt.kexp15(cipher, hs["pms"], export[:32], export[32:], hs["iv"])
    assert wrapped == hs["pmsexp"]
    assert allcrypt.kimp15(cipher, wrapped, export[:32], export[32:], hs["iv"]) == hs["pms"]


def test_keg_28147_and_kexp28147_against_rfc_9189():
    hs = handshake("A.2.2.  Handshake Examples", "Authors' Addresses")
    assert hs["curve"] == "gost512-a"
    # The appendix labels VKO's output K_EXP; the export key is that
    # diversified under H[1..8], which is also the IV.
    vko = octets(hs["text"], r"K_EXP:")
    assert hs["iv"] == hs["h"][:8]
    key = allcrypt.cryptopro_kek_diversify(hs["iv"], vko, sbox="id-tc26-gost-28147-param-Z")

    server = allcrypt.EcKey.from_private(hs["curve"], hs["d_s"])
    client = allcrypt.EcKey.from_private(hs["curve"], hs["d_eph"])
    assert client.gost_keg_28147(hs["q_s"], hs["h"]) == key
    assert server.gost_keg_28147(hs["q_eph"], hs["h"]) == key

    wrapped = allcrypt.kexp28147(hs["pms"], key, hs["iv"], sbox="id-tc26-gost-28147-param-Z")
    assert wrapped == hs["pmsexp"]
    assert wrapped[8:40] == octets(hs["text"], r"CEK_ENC:")
    assert wrapped[40:] == octets(hs["text"], r"CEK_MAC:")
    assert allcrypt.kimp28147(wrapped, key, hs["iv"], sbox="id-tc26-gost-28147-param-Z") \
        == hs["pms"]
    tampered = bytearray(wrapped)
    tampered[20] ^= 1
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kimp28147(bytes(tampered), key, hs["iv"], sbox="id-tc26-gost-28147-param-Z")
    with pytest.raises(allcrypt.CryptoError):
        allcrypt.kimp28147(wrapped, key, bytes(8), sbox="id-tc26-gost-28147-param-Z")
    # The default S-box is CryptoPro-A, a different wrapping.
    assert allcrypt.kexp28147(hs["pms"], key, hs["iv"]) != wrapped
