#!/usr/bin/env python3
"""Write src/checksum/crc_catalogue.rs: the catalogue of parametrised CRC
algorithms.

    sh scripts/witness/crc/build.sh /opt/crcwitness
    python3 scripts/make_crc_catalogue.py [/opt/crcwitness]

**A development tool, not a test.**

The catalogue is Greg Cook's, the one reveng carries: each entry a name
and the parameters of Ross Williams's model - width, polynomial, init,
refin, refout and xorout - with the check value, the CRC of "123456789".
It is read from its two transcriptions in scripts/witness/crc, crc-catalog
2.5.0's algorithm.rs and crccheck 1.3.0's crc.py (catalogue.py there),
and an entry is written only where both carry it and agree on every
field. Before anything is written, every witness must reproduce every
written entry's check value (selftest.py there).
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUTPUT = os.path.join(ROOT, "src", "checksum", "crc_catalogue.rs")
WITNESS = os.path.join(HERE, "witness", "crc")
sys.path.insert(0, WITNESS)
from catalogue import entries  # noqa: E402


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/crcwitness"
    subprocess.run([sys.executable, os.path.join(WITNESS, "selftest.py"), out], check=True)
    agreed, missing = entries(out)
    if len(agreed) != 112:
        sys.exit(f"{len(agreed)} entries agreed, not 112; read the transcriptions again")
    names = [name.lower() for name, _ in agreed]
    if len(set(names)) != len(names):
        sys.exit("two entries share a name")

    def hexed(value, width):
        return f"0x{value:0{(width + 3) // 4}x}"
    lines = [
        "// The catalogue of parametrised CRC algorithms, as reveng carries it.",
        "// Written by scripts/make_crc_catalogue.py from crc-catalog 2.5.0's and",
        "// crccheck 1.3.0's transcriptions, which agree on every entry here;",
        f"// {', '.join(missing)} is in one of them only and is left out. Do not edit.",
        "",
        "use super::crc::{CatalogueEntry, CrcParams};",
        "",
        "/// Every entry, in crc-catalog's order: by width, then by name.",
        f"pub(super) const ENTRIES: [CatalogueEntry; {len(agreed)}] = [",
    ]
    for name, f in agreed:
        w = f["width"]
        lines += [
            f"    CatalogueEntry {{ name: {name!r}, check: {hexed(f['check'], w)},".replace("'", '"'),
            f"        params: CrcParams {{ width: {w}, poly: {hexed(f['poly'], w)}, "
            f"init: {hexed(f['init'], w)},",
            f"            refin: {str(f['refin']).lower()}, refout: {str(f['refout']).lower()}, "
            f"xorout: {hexed(f['xorout'], w)} }} }},",
        ]
    lines += [
        "];",
        "",
        "/// The entries' names, lowercase, as `Checksum` gives them.",
        f"pub(super) const NAMES: [&str; {len(names)}] = [",
    ]
    row = "   "
    for name in names:
        item = f' "{name}",'
        if len(row) + len(item) > 99:
            lines.append(row)
            row = "   "
        row += item
    lines += [row, "];"]
    with open(OUTPUT, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"wrote {OUTPUT}: {len(agreed)} entries")


if __name__ == "__main__":
    main()
