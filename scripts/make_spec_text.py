#!/usr/bin/env python3
"""Write the text of the vendored PDF and Word specifications in rfcs/.

    python3 scripts/make_spec_text.py           # write rfcs/<name>.txt
    python3 scripts/make_spec_text.py --check   # compare, write nothing

**A development tool, not a test.** The tests read the `.txt` files, which
are committed beside the PDFs, so neither `cargo test` nor the library's
build needs poppler. Each PDF is checked against its SHA-256 first, and the
text is `pdftotext -layout` (poppler-utils), which keeps the columns of a
table on one line - what the parsers in `src/stream_ciphers/snow3g.rs`,
`zuc.rs` and `scripts/witness/snow3g_zuc/published.py` rely on. The text
was written with pdftotext 24.02.0; `--check` says whether this one writes
the same bytes.

3GPP publishes its specifications as Word files. Their text is `pandoc
-t plain --wrap=none` (3.1.3), each paragraph a line: the parsers in
`src/stream_ciphers/zuc.rs` and `mobile.rs` read TS 35.246's constants
and TS 35.247's and 35.248's test data out of it, and
`scripts/witness/zuc256_3gpp` takes TS 35.246's Annex A reference code
from it.
"""

import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RFCS = os.path.join(ROOT, "rfcs")

#: PDF: its SHA-256
DOCUMENTS = {
    # ETSI/SAGE, UEA2 & UIA2 Document 2: SNOW 3G Specification, v1.1.
    "snow3gspec.pdf": "a4dc79f2dcf3a1d91a0c5efbae317ffc50cbf90a9bb53da0edb52b4e86b989b5",
    # ETSI/SAGE, UEA2 & UIA2 Document 3: Implementors' Test Data, v1.1.
    "Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.pdf":
        "fdf3281aacb8098f7cee4461851910aeff84f8c6cbdaadca95ee9a5d63d1c677",
    # ETSI/SAGE, 128-EEA3 & 128-EIA3 Document 2: ZUC Specification, v1.6.
    "eea3eia3zucv16.pdf": "07db149438c92b6931eb34708df81134c4fa9a89cb2e0802cb3dd2d59f8907ae",
    # ETSI/SAGE, 128-EEA3 & 128-EIA3 Document 3: Implementor's Test Data, v1.1.
    "eea3eia3testdatav11.pdf": "65b461c84daac4f9c7e831b739ca33792e25fdcbcf67e2e6befa60e4a58eea82",
    # 3GPP TS 35.246 V20.0.0 (2026-03): the ZUC based 256 bit algorithm set,
    # Document 1: 256-NEA6, 256-NIA6 and 256-NCA6, with ZUC-256.
    "35246-k00.docx": "dc07113c14fb7d1b9106e62f2109ae4b172ce0228e6cb6672cb09f93f6e18e14",
    # 3GPP TS 35.247 V20.0.0 (2026-03), Document 2: implementation test data.
    "35247-k00.docx": "64a3581c344dee90bae4d217f795d0dec1d2390be86358bb44345eddd657e92e",
    # 3GPP TS 35.248 V20.0.0 (2026-03), Document 3: design conformance test data.
    "35248-k00.docx": "485d2c0eba4060dccc46952a3fa9ffdd9826ce8ff255005824b6d900dface2d2",
}


def main():
    check = "--check" in sys.argv[1:]
    differ = []
    for name, digest in DOCUMENTS.items():
        pdf = os.path.join(RFCS, name)
        with open(pdf, "rb") as handle:
            got = hashlib.sha256(handle.read()).hexdigest()
        if got != digest:
            sys.exit(f"{name}: SHA-256 {got}, expected {digest}")
        if name.endswith(".docx"):
            text = subprocess.run(["pandoc", "-t", "plain", "--wrap=none", pdf],
                                  capture_output=True, check=True).stdout
        else:
            text = subprocess.run(["pdftotext", "-layout", "-enc", "UTF-8", pdf, "-"],
                                  capture_output=True, check=True).stdout
        target = os.path.join(RFCS, name.rsplit(".", 1)[0] + ".txt")
        if check:
            with open(target, "rb") as handle:
                if handle.read() != text:
                    differ.append(name)
            continue
        with open(target, "wb") as handle:
            handle.write(text)
        print(f"wrote {target}")
    if differ:
        sys.exit("this pdftotext or pandoc writes different text for: " + ", ".join(differ))
    if check:
        print("the text files are what this pdftotext and pandoc write")


if __name__ == "__main__":
    main()
