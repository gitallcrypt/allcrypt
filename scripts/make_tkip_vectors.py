#!/usr/bin/env python3
"""Write `vectors/tkip.vec`: TKIP per-packet RC4 keys computed the way
Linux's mac80211 computes them (`net/mac80211/tkip.c`, v6.12), with the
S-box table parsed out of that file rather than typed - so the Rust,
which derives its S-box from AES's, is checked against the table as the
kernel ships it.

    python3 scripts/make_tkip_vectors.py LINUX_SOURCE_TREE

The TSCs cross the points where phase 1 changes (the upper 32 bits) and
where phase 2's 16-bit addition wraps.
"""

import os
import re
import sys


def main():
    tree = sys.argv[1]
    text = open(os.path.join(tree, "net", "mac80211", "tkip.c"), encoding="utf-8").read()
    start = text.index("tkip_sbox[256]")
    table = [int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{4})",
                                             text[start:text.index("};", start)])]
    assert len(table) == 256

    def s(v):
        hi = table[v >> 8]
        return table[v & 0xff] ^ (((hi & 0xff) << 8) | (hi >> 8))

    def le16(b, i):
        return b[i] | (b[i + 1] << 8)

    def ror1(v):
        return ((v >> 1) | (v << 15)) & 0xffff

    def phase1(tk, ta, iv32):
        p = [iv32 & 0xffff, iv32 >> 16, le16(ta, 0), le16(ta, 2), le16(ta, 4)]
        for i in range(8):
            j = 2 * (i & 1)
            p[0] = (p[0] + s(p[4] ^ le16(tk, 0 + j))) & 0xffff
            p[1] = (p[1] + s(p[0] ^ le16(tk, 4 + j))) & 0xffff
            p[2] = (p[2] + s(p[1] ^ le16(tk, 8 + j))) & 0xffff
            p[3] = (p[3] + s(p[2] ^ le16(tk, 12 + j))) & 0xffff
            p[4] = (p[4] + s(p[3] ^ le16(tk, 0 + j)) + i) & 0xffff
        return p

    def phase2(tk, p1k, iv16):
        p = p1k[:] + [(p1k[4] + iv16) & 0xffff]
        for i in range(6):
            p[i] = (p[i] + s(p[(i + 5) % 6] ^ le16(tk, 2 * i))) & 0xffff
        p[0] = (p[0] + ror1(p[5] ^ le16(tk, 12))) & 0xffff
        p[1] = (p[1] + ror1(p[0] ^ le16(tk, 14))) & 0xffff
        for i in range(2, 6):
            p[i] = (p[i] + ror1(p[i - 1])) & 0xffff
        key = bytes([iv16 >> 8, ((iv16 >> 8) | 0x20) & 0x7f, iv16 & 0xff,
                     ((p[5] ^ le16(tk, 0)) >> 1) & 0xff])
        return key + b"".join(w.to_bytes(2, "little") for w in p)

    rows = []
    for n, tsc in enumerate([0, 1, 0xffff, 0x10000, 0x10001, 0x1234_5678_9abc,
                             0xffff_ffff_ffff, 0x0000_0001_0000, 0xabcd_0000_ff00,
                             0x8000_0000_7fff, 0x00ff_00ff_00ff, 0x5a5a_5a5a_5a5a]):
        tk = bytes((i * 29 + 7 * n + 3) & 0xff for i in range(16))
        ta = bytes((i * 53 + n) & 0xff for i in range(6))
        rows.append((tk, ta, tsc, phase2(tk, phase1(tk, ta, tsc >> 16), tsc & 0xffff)))
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "vectors", "tkip.vec")
    with open(out, "w") as f:
        f.write("# TKIP per-packet RC4 keys, computed as Linux's net/mac80211/tkip.c\n"
                "# (v6.12) does, with its S-box table. Written by\n"
                "# scripts/make_tkip_vectors.py. Do not edit.\n")
        for tk, ta, tsc, key in rows:
            f.write(f"\ntk = {tk.hex()}\nta = {ta.hex()}\ntsc = {tsc:012x}\n"
                    f"rc4_key = {key.hex()}\n")
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
