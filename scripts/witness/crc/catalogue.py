"""The catalogue of parametrised CRC algorithms (Greg Cook's, reveng's),
read from its two transcriptions in the witnesses: crc-catalog 2.5.0's
algorithm.rs and crccheck 1.3.0's crc.py. Each gives an entry's name,
width, polynomial, init, refin, refout, xorout and check value, the CRC of
"123456789"; crc-catalog gives the residue too. An entry is taken only
where both carry it and agree on every field."""

import os
import re


def crc_catalog(path):
    text = open(path).read()
    out = {}
    pattern = (r"/// # \[`([^`]+)`\]\[1\].*?pub const \w+: Algorithm<u\d+> = Algorithm "
               r"\{(.*?)\};")
    for m in re.finditer(pattern, text, re.S):
        fields = {}
        for part in m.group(2).split(","):
            if ":" in part:
                key, value = (s.strip() for s in part.split(":", 1))
                fields[key] = value == "true" if value in ("true", "false") else int(value, 0)
        out[m.group(1)] = fields
    return out


def crccheck(path):
    text = open(path).read()
    out = {}
    for m in re.finditer(r"\nclass Crc\w+\(\w+\):(.*?)(?=\nclass |\Z)", text, re.S):
        body = m.group(1)
        names = re.search(r"_names = \(([^)]*)\)", body)
        quoted = re.findall(r"'([^']+)'", names.group(1)) if names else []
        if not quoted:
            continue
        name = quoted[0]

        def get(key):
            return re.search(rf"\n\s*_{key} = (\S+)", body).group(1)
        out[name] = {"width": int(get("width"), 0), "poly": int(get("poly"), 0),
                     "init": int(get("initvalue"), 0),
                     "refin": get("reflect_input") == "True",
                     "refout": get("reflect_output") == "True",
                     "xorout": int(get("xor_output"), 0), "check": int(get("check_result"), 0)}
    return out


FIELDS = ("width", "poly", "init", "refin", "refout", "xorout", "check")


def entries(out):
    """[(name, fields)] in crc-catalog's order, the agreed entries only;
    and the names one transcription has and the other lacks."""
    a = crc_catalog(os.path.join(out, "src", "crc-catalog-algorithm.rs"))
    b = crccheck(os.path.join(out, "py", "crccheck", "crc.py"))
    if len(a) < 100 or len(b) < 100:
        raise SystemExit(f"read {len(a)} and {len(b)} entries; the parsers have broken")
    agreed, missing = [], sorted(set(a) ^ set(b))
    for name, fields in a.items():
        if name not in b:
            continue
        if any(fields[k] != b[name][k] for k in FIELDS):
            raise SystemExit(f"the transcriptions disagree on {name}: {fields} {b[name]}")
        agreed.append((name, fields))
    return agreed, missing


def request(fields, data):
    w = fields["width"]
    digits = (w + 3) // 4
    return (f"crc {w} {fields['poly']:0{digits}x} {fields['init']:0{digits}x} "
            f"{int(fields['refin'])} {int(fields['refout'])} {fields['xorout']:0{digits}x} "
            f"{data.hex() or '-'}")
