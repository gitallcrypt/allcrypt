#!/usr/bin/env python3
"""Read object identifiers out of the RFC texts vendored in `rfcs/`.

`src/x509/oids.rs` generates its *bytes* from a dotted string, so the
encoding cannot be mistyped. The dotted strings themselves are still
typed by hand, and that is the half this reads back from the standards
that define them - a third opinion beside the two `diff_check.py`
already has (a second encoder, and python-cryptography's numbers).

Why it is worth a parser rather than a list. The dotted string and the
name in `oids.rs` were both taken from one glance at one document, so
they can agree with each other and disagree with the world. OpenSSL's
tables catch that for the fifty-odd OIDs it knows; the RFCs catch it for
seventy-three of seventy-four, including every GOST one, which OpenSSL
here has no name for at all.

## The four shapes

RFCs state an OID in at least four ways, and a parser that handles three
of them silently drops the fourth - which is the same failure this file
exists to prevent, moved somewhere harder to see. All four are handled
here and each has a test in `tests()`:

  1. ``name OBJECT IDENTIFIER ::= { iso(1) member-body(2) ... }``
  2. ``name AttributeType ::= { id-at 3 }`` — a type name where the
     keywords usually are, which RFC 5280 uses for every DN attribute.
  3. ``name OBJECT IDENTIFIER ::= id-other`` — a brace-less alias, which
     RFC 4357 uses for ``id-CryptoPro-algorithms``.
  4. ``( 0.9.2342.19200300.100.1.25 NAME 'dc' ... )`` — LDAP's schema
     syntax, which is how RFC 4519 states its attribute types and which
     shares nothing with ASN.1.

What stops a fifth shape being dropped silently is not this file: it is
`check_oids` in `diff_check.py`, which requires *every* constant to
resolve here or to be named with a reason it cannot. A parser that stops
finding things turns constants into "not found", which is an error.

## Two details that are easy to get backwards

**The name is the last lowercase identifier before `::=`.** Going
backwards from the operator you meet `IDENTIFIER`, `OBJECT`, or a type
name, and only then the name. ASN.1 convention is that value names start
lowercase and type names start uppercase, which separates them - and
also drops ``GostR3410-2001-ParamSetParameters ::= SEQUENCE {...}``,
a type definition that is not an OID at all.

**The backward window has to stop at the previous `::=`.** After a
brace-less alias there is no `}` and no blank line between one
assignment and the next, so a window that only stops at those reaches
back into the previous assignment's *body* and takes that as the name.
The symptom was `id-CryptoPro` resolving to `id-CryptoPro-modules`'s
value, and everything under the CryptoPro arc - which is every GOST
parameter set in the wild - silently disappearing.
"""

import argparse
import os
import re
import sys

#: Where the vendored documents live, relative to the repository root.
RFC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "rfcs")

_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9\-]*")
_LDAP = re.compile(r"\(\s*((?:\d+\.)+\d+)\s+NAME\s+'([A-Za-z][A-Za-z0-9\-]*)'")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9\-]*\(\d+\)|[A-Za-z][A-Za-z0-9\-]*|\d+")
_NAMED_ARC = re.compile(r"([A-Za-z][A-Za-z0-9\-]*)\((\d+)\)")

#: How far back to look for an assignment's name. Long enough for a name
#: wrapped onto its own line above `OBJECT IDENTIFIER ::=`, short enough
#: that the scan stays linear in the document's length.
_LOOKBEHIND = 200

#: How far forward to look for the body. A `{ ... }` list of arcs is
#: never longer than this; anything that is, is not an OID assignment.
_LOOKAHEAD = 400


def _strip_page_furniture(text):
    """Remove the footer/header pair that splits assignments across pages.

    An RFC page break is a footer line, a form feed, and a header line.
    Left in, it lands in the middle of a `{ ... }` and the assignment is
    lost - not reported, lost, which is the failure mode this whole file
    is written against.
    """
    return re.sub(r"\n[^\n]*\[Page \d+\]\s*\n\f?\n[^\n]*\n", "\n", text)


def assignments(text):
    """Yield `(name, body)` for every ASN.1 value assignment in `text`.

    Found by scanning for `::=` rather than by one regular expression:
    a pattern that spans line breaks and optional keywords backtracks
    catastrophically on 350 KB of RFC, which is a hang rather than a
    wrong answer but is no more use.
    """
    for operator in re.finditer(r"::=", text):
        window = text[max(0, operator.start() - _LOOKBEHIND):operator.start()]
        # Everything before the nearest of these belongs to something
        # else. `::=` is in the list because a brace-less alias leaves no
        # other boundary between two assignments.
        for boundary in ("}", "\n\n", "--", "::="):
            at = window.rfind(boundary)
            if at != -1:
                window = window[at + len(boundary):]

        names = [name for name in _IDENT.findall(window) if name[0].islower()]
        if not names:
            continue
        name = names[-1]

        rest = text[operator.end():operator.end() + _LOOKAHEAD]
        brace, close = rest.find("{"), rest.find("}")
        if brace != -1 and close > brace and not rest[:brace].strip():
            yield name, rest[brace + 1:close]
        else:
            alias = _IDENT.match(rest.strip())
            if alias and alias.group(0)[0].islower():
                yield name, alias.group(0)


def parse(text):
    """`{name: [definition, ...]}` for one document.

    A name can have more than one definition - RFC 4357 states some of
    its parameter sets twice - so they are collected rather than
    overwritten, and `resolve` takes the first that works out.
    """
    text = _strip_page_furniture(text)
    definitions = {}

    for name, body in assignments(text):
        tokens = []
        for token in _TOKEN.findall(" ".join(body.split())):
            named = _NAMED_ARC.fullmatch(token)
            if named:
                tokens.append(("arc", int(named.group(2))))
            elif token.isdigit():
                tokens.append(("arc", int(token)))
            else:
                tokens.append(("name", token))
        if tokens:
            definitions.setdefault(name, []).append(tokens)

    # LDAP's schema syntax, which is not ASN.1 and states the whole
    # number rather than a parent and an arc.
    for dotted, name in _LDAP.findall(text):
        definitions.setdefault(name, []).append(
            [("arc", int(arc)) for arc in dotted.split(".")])

    return definitions


def _resolve_arcs(definitions, name, seen=()):
    """`name`'s arcs as a list of integers, or None.

    Separate from `resolve` because the recursion extends a list, and a
    function that returned the dotted string would extend it with that
    string's *characters* - which produces "2...5...4.3" rather than an
    error. `tests()` below covers exactly that, because it happened.

    `seen` breaks the cycle a mutually recursive pair would otherwise
    make. A definition whose first token is a name is a parent reference
    and must be the only one; anything else is a list of arcs.
    """
    if name in seen:
        return None
    for tokens in definitions.get(name, []):
        arcs = []
        ok = True
        for kind, value in tokens:
            if kind == "arc":
                arcs.append(value)
            else:
                parent = _resolve_arcs(definitions, value, seen + (name,))
                if parent is None or arcs:
                    ok = False
                    break
                arcs.extend(parent)
        # Two arcs is the shortest real OID; anything shorter came from
        # a fragment rather than an assignment.
        if ok and len(arcs) >= 2:
            return arcs
    return None


def resolve(definitions, name):
    """The dotted form of `name`, or None."""
    arcs = _resolve_arcs(definitions, name)
    return None if arcs is None else ".".join(str(arc) for arc in arcs)


def load(directory=RFC_DIR):
    """Every name the vendored documents define, resolved.

    One namespace across all of them, because the arcs cross document
    boundaries: RFC 9215's parameter sets hang off `id-tc26` from RFC
    7836, and RFC 4357's off `id-CryptoPro`.

    Returns `(by_name, by_value)`, both needed: a check by name catches
    "we have a real OID, just not the one we think it is", which a check
    by value cannot see.
    """
    definitions = {}
    paths = sorted(f for f in os.listdir(directory) if f.endswith(".txt"))
    if not paths:
        raise SystemExit(f"no RFC texts in {directory}")
    for path in paths:
        with open(os.path.join(directory, path), encoding="utf-8",
                  errors="replace") as handle:
            for name, defs in parse(handle.read()).items():
                definitions.setdefault(name, []).extend(defs)

    by_name, by_value = {}, {}
    for name in definitions:
        dotted = resolve(definitions, name)
        # The root arc is 0, 1 or 2 by definition; anything else came
        # from a fragment that happened to look like an assignment.
        if dotted and int(dotted.split(".")[0]) <= 2:
            by_name[name] = dotted
            by_value.setdefault(dotted, []).append(name)
    return by_name, by_value


# ------------------------------------------------------------- tests ---

def tests():
    """One test per shape, and one for each detail that was wrong.

    These run from `diff_check.py` before the corpus, so a parser that
    has quietly stopped handling a shape fails with the shape's name
    rather than as a pile of missing constants.
    """
    def one(text):
        return load_text(text)

    def load_text(text):
        definitions = parse(text)
        return {name: resolve(definitions, name) for name in definitions}

    # 1. The ordinary form.
    got = one("id-x OBJECT IDENTIFIER ::= { iso(1) member-body(2) ru(643) }")
    assert got["id-x"] == "1.2.643", got

    # 2. A type name where the keywords usually are (RFC 5280's DN
    #    attributes), and a parent reference.
    got = one("id-at OBJECT IDENTIFIER ::= { joint-iso-ccitt(2) ds(5) 4 }\n"
              "id-at-commonName AttributeType ::= { id-at 3 }\n")
    assert got["id-at-commonName"] == "2.5.4.3", got

    # 3. A brace-less alias, and - the part that was wrong - the
    #    assignment after it. Without stopping the backward window at
    #    `::=`, the second name is read as `id-a` and the whole arc
    #    silently moves.
    got = one("id-a OBJECT IDENTIFIER ::=\n    { iso(1) member-body(2) ru(643) }\n"
              "id-b OBJECT IDENTIFIER ::=\n    id-a\n"
              "id-c OBJECT IDENTIFIER ::=\n    { id-b other(1) }\n")
    assert got["id-a"] == "1.2.643", got
    assert got["id-b"] == "1.2.643", got
    assert got["id-c"] == "1.2.643.1", got

    # 4. LDAP's schema syntax, which is not ASN.1.
    got = one("      ( 0.9.2342.19200300.100.1.25 NAME 'dc'\n"
              "        EQUALITY caseIgnoreIA5Match )\n")
    assert got["dc"] == "0.9.2342.19200300.100.1.25", got

    # A type definition is not an OID, and must not be picked up as one.
    got = one("GostR3410-2001-ParamSetParameters ::= SEQUENCE {\n"
              "    a INTEGER,\n    b INTEGER }\n")
    assert all(value is None for value in got.values()), got

    # A page break in the middle of an assignment must not lose it.
    got = one("id-x OBJECT IDENTIFIER ::= { iso(1)\n"
              "Author                    Informational           [Page 7]\n"
              "\f\n"
              "RFC 9999           Something              March 2020\n"
              "    member-body(2) ru(643) }\n")
    assert got["id-x"] == "1.2.643", got


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("name", nargs="*",
                        help="print these names' OIDs (default: all of them)")
    parser.add_argument("--dir", default=RFC_DIR)
    parser.add_argument("--value", help="print every name with this dotted value")
    arguments = parser.parse_args()

    tests()
    by_name, by_value = load(arguments.dir)

    if arguments.value:
        for name in by_value.get(arguments.value, []):
            print(name)
        return 0 if arguments.value in by_value else 1

    if arguments.name:
        missing = False
        for name in arguments.name:
            dotted = by_name.get(name)
            print(f"{name}\t{dotted or '(not found)'}")
            missing = missing or dotted is None
        return 1 if missing else 0

    for name in sorted(by_name):
        print(f"{name}\t{by_name[name]}")
    print(f"\n{len(by_name)} names, {len(by_value)} distinct values",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
