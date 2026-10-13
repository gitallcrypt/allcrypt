"""The published test vectors the NESSIE witnesses carry, read out of
their sources rather than copied: libtomcrypt's self-test arrays
(`static const struct test {...} tests[] = {...}` in each cipher's
`<name>_test`), the Linux kernel's `<name>_tv_template` arrays in
`crypto/testmgr.h`, the sections of Botan 1.10's `checks/validate.dat`
and Botan 3's `src/tests/data/block/*.vec`, and Crypto++'s
`TestVectors/*.txt`. Each project took them from the designers.

    libtomcrypt(text, function, defined) -> [{"key": b, "pt": b, "ct": b, ...}]
    testmgr(text, template)     -> [{"key": b, "pt": b, "ct": b}]
    botan(text, section)        -> [{"key": b, "pt": b, "ct": b}]
    botan3(text, section)       -> [{"key": b, "pt": b, "ct": b}]
    cryptopp(text)              -> [{"key": b, "pt": b, "ct": b}]

Used by build.sh, which requires every witness to reproduce them, and by
the scripts that write the vectors files.
"""

import re


def _tokens(text):
    """Numbers and braces, with comments and casts dropped."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return re.findall(r"0[xX][0-9a-fA-F]+|\d+|[{}]", text)


def _group(tokens, at):
    """The brace group starting at tokens[at]: (items, next index), each
    item a number or a list."""
    assert tokens[at] == "{"
    items, at = [], at + 1
    while tokens[at] != "}":
        if tokens[at] == "{":
            item, at = _group(tokens, at)
            items.append(item)
        else:
            items.append(int(tokens[at], 0))
            at += 1
    return items, at + 1


def preprocess(text, defined):
    """`text` with the conditional blocks the preprocessor would drop
    dropped, for `#ifdef`, `#ifndef`, `#if defined(...)`, `#if
    !defined(...)`, `#else` and `#endif` over the macros in `defined`.
    The only conditionals the cipher files use."""
    out, stack = [], []
    for line in text.split("\n"):
        directive = line.strip()
        match = re.match(r"#\s*(ifdef|ifndef|if|else|endif)\b\s*(.*)", directive)
        if not match:
            if all(stack):
                out.append(line)
            continue
        kind, rest = match.groups()
        if kind in ("ifdef", "ifndef", "if"):
            name = re.search(r"(\w+)\s*\)?\s*$", rest).group(1)
            truth = name in defined
            if kind == "ifndef" or (kind == "if" and rest.lstrip().startswith("!")):
                truth = not truth
            stack.append(truth)
        elif kind == "else":
            stack[-1] = not stack[-1]
        else:
            stack.pop()
    return "\n".join(out)


def libtomcrypt(text, function, defined=("LTC_TEST",)):
    """The tests in `function`'s array, each member by its name in the
    struct, arrays zero-filled to their declared size, the file read as
    compiled with `defined`."""
    text = preprocess(text, set(defined) | {"LTC_TEST"})
    body = text[text.index(f"int {function}(void)"):]
    struct = re.search(r"struct\s*(?:\w+\s*)?\{(.*?)\}\s*tests\s*\[\s*\]\s*=", body, re.S)
    members = []
    for declaration in struct.group(1).split(";"):
        declaration = declaration.strip()
        if not declaration:
            continue
        kind, names = declaration.split(None, 1) if not declaration.startswith(
            "unsigned char") else ("bytes", declaration[len("unsigned char"):])
        for name in names.split(","):
            match = re.fullmatch(r"\s*(\w+)\s*(?:\[\s*(\d+)\s*\])?\s*", name)
            members.append((match.group(1), int(match.group(2)) if match.group(2) else None))
    start = struct.end()
    tokens = _tokens(body[start:])
    tests, _ = _group(tokens, 0)
    out = []
    for test in tests:
        assert len(test) == len(members), (function, test)
        row = {}
        for (name, size), value in zip(members, test):
            if size is None:
                row[name] = value
            else:
                row[name] = bytes(value) + bytes(size - len(value))
        out.append(row)
    return out


def _c_string(literals):
    """Adjacent C string literals, joined and decoded."""
    out = bytearray()
    for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', literals):
        i = 0
        while i < len(literal):
            if literal[i] != "\\":
                out.append(ord(literal[i]))
                i += 1
            elif literal[i + 1] == "x":
                digits = re.match(r"[0-9a-fA-F]{1,2}", literal[i + 2:]).group(0)
                out.append(int(digits, 16))
                i += 2 + len(digits)
            else:
                out.append({"n": 10, "t": 9, "0": 0, "\\": 92, '"': 34}[literal[i + 1]])
                i += 2
    return bytes(out)


def testmgr(text, template):
    """The entries of `template[]`: key, plaintext and ciphertext."""
    body = text[text.index(f"{template}[] = {{"):]
    body = body[:body.index("\n};")]
    out = []
    for entry in re.split(r"\n\t\},\s*\{", body):
        fields = dict(re.findall(r"\.(\w+)\s*=\s*((?:\"(?:[^\"\\]|\\.)*\"\s*)+|\d+)", entry))
        key, pt, ct = (_c_string(fields[f]) for f in ("key", "ptext", "ctext"))
        assert len(key) == int(fields["klen"]) and len(pt) == len(ct) == int(fields["len"])
        out.append({"key": key, "pt": pt, "ct": ct})
    return out


def botan(text, section):
    """The `pt:ct:key` entries of `[section]` in Botan 1.10's
    validate.dat, a trailing backslash continuing a line."""
    body = text[text.index(f"\n[{section}]\n") + len(section) + 4:]
    body = body[:body.index("\n[")]
    out = []
    for entry in body.replace("\\\n", "").split("\n"):
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        pt, ct, key = (bytes.fromhex(f) for f in entry.split(":"))
        out.append({"key": key, "pt": pt, "ct": ct})
    return out


def botan3(text, section):
    """The `Key`, `In`, `Out` groups of `[section]` in a Botan 3 test file."""
    body = text[text.index(f"[{section}]"):]
    rows, current = [], {}
    for line in body.split("\n")[1:]:
        line = line.strip()
        if line.startswith("["):
            break
        match = re.match(r"(Key|In|Out)\s*=\s*([0-9A-Fa-f]*)$", line)
        if match:
            current[match.group(1)] = bytes.fromhex(match.group(2))
            if match.group(1) == "Out":
                rows.append({"key": current["Key"], "pt": current["In"], "ct": current["Out"]})
    return rows


def cryptopp(text):
    """The encryption tests of a Crypto++ TestVectors file: each `Key`,
    `Plaintext` and `Ciphertext` up to its `Test: Encrypt`."""
    rows, current = [], {}
    for line in text.split("\n"):
        match = re.match(r"(Key|Plaintext|Ciphertext|Test):\s*(\S*)", line.strip())
        if not match:
            continue
        name, value = match.groups()
        if name == "Test":
            if value == "Encrypt":
                rows.append({"key": current["Key"], "pt": current["Plaintext"],
                             "ct": current["Ciphertext"]})
        else:
            current[name] = bytes.fromhex(value)
    return rows
