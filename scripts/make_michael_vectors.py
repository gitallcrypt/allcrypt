#!/usr/bin/env python3
"""Write `vectors/michael.vec` from the Linux kernel's Michael test
vectors (`michael_mic_tv_template` in `crypto/testmgr.h`), which are
IEEE 802.11's own: six rows, each keyed with the previous row's tag.

    python3 scripts/make_michael_vectors.py LINUX_SOURCE_TREE

Written from v6.12. The values are parsed out of the C, not typed.
"""

import os
import re
import sys


def c_string(text):
    """A C string literal's bytes: \\xNN escapes and plain characters."""
    out = bytearray()
    for part in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
        i = 0
        while i < len(part):
            if part[i] == "\\" and part[i + 1] == "x":
                out.append(int(part[i + 2:i + 4], 16))
                i += 4
            else:
                out.append(ord(part[i]))
                i += 1
    return bytes(out)


def main():
    tree = sys.argv[1]
    text = open(os.path.join(tree, "crypto", "testmgr.h"), encoding="utf-8").read()
    start = text.index("michael_mic_tv_template[] = {")
    body = text[start:text.index("};", start)]
    rows = []
    for entry in re.findall(r"\{(.*?)\n\t\}", body, re.S):
        fields = dict(re.findall(r"\.(\w+)\s*=\s*(.*?),\n", entry + ",\n", re.S))
        key = c_string(fields["key"])
        size = int(fields["psize"])
        message = bytes(size) if fields["plaintext"].strip() == "zeroed_string" \
            else c_string(fields["plaintext"])[:size]
        rows.append((key, message, c_string(fields["digest"])))
    assert len(rows) == 6, rows
    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "vectors", "michael.vec")
    with open(out, "w") as f:
        f.write("# Michael (TKIP's MIC): the Linux kernel's crypto/testmgr.h\n"
                "# michael_mic_tv_template (v6.12), from IEEE 802.11. Written by\n"
                "# scripts/make_michael_vectors.py. Do not edit.\n")
        for key, message, tag in rows:
            f.write(f"\nkey = {key.hex()}\nmessage = {message.hex()}\ntag = {tag.hex()}\n")
    print(f"wrote {len(rows)} rows to {out}")


if __name__ == "__main__":
    main()
