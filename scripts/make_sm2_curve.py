#!/usr/bin/env python3
"""Print the sm2p256v1 domain parameters as Rust, read out of OpenSSL.

Curve constants are the one kind of value where a typo produces something
that still works: arithmetic closes, points still look like points, and
the group is simply a different and possibly weak one. `curves.rs` says
so at the top, and its self-consistency test - G on the curve, n*G the
identity - is what pins every parameter down.

This script is the other half of that: the constants in `curves.rs::sm2`
were not typed, they were printed by this. Run it to check them, the
same way `scripts/make_xts_vectors.py` exists so that "verified against
OpenSSL" is re-runnable rather than a claim in a commit message.

    python3 scripts/make_sm2_curve.py

Needs the `openssl` binary and no network.
"""

import re
import subprocess
import sys


FIELDS = ("Prime", "A", "B", "Generator (uncompressed)", "Order", "Cofactor")


def openssl_parameters():
    """The explicit parameters OpenSSL holds for its SM2 curve."""
    proc = subprocess.run(
        ["openssl", "ecparam", "-name", "SM2", "-param_enc", "explicit",
         "-text", "-noout"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(
            "openssl could not produce the SM2 parameters. This OpenSSL may "
            "be built without SM2; 3.0 and later have it.")
    return proc.stdout


def parse(text):
    """Split the `-text` output into {field: hex string}.

    The values are indented continuation lines of colon-separated bytes.
    `Cofactor` is on its own line as a decimal, so it is handled apart.
    """
    values = {}
    current = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # The label is whatever precedes the first colon. `Cofactor` states
        # its value on the same line ("Cofactor:  1 (0x1)") where the others
        # put theirs on continuation lines, so stripping a trailing colon is
        # not enough to recognise it.
        heading = stripped.split(":", 1)[0].strip()
        if heading in FIELDS:
            if heading == "Cofactor":
                # "Cofactor:  1 (0x1)"
                match = re.search(r"(\d+)", stripped.split(":", 1)[1])
                values["Cofactor"] = match.group(1)
                current = None
            else:
                current = heading
                values[current] = ""
            continue
        if current and re.fullmatch(r"[0-9a-fA-F:]+", stripped):
            values[current] += stripped.replace(":", "")
    return values


def strip_leading_zero_byte(value):
    """OpenSSL prints these as signed integers, so a value whose top bit
    is set carries a leading `00`. Dropping it is safe only when what is
    left is still the full field width, which is asserted."""
    if len(value) == 66 and value.startswith("00"):
        return value[2:]
    return value


def main():
    values = parse(openssl_parameters())
    missing = [f for f in FIELDS if f not in values]
    if missing:
        raise SystemExit(f"openssl printed no {missing}; its output format "
                         f"may have changed.")

    p = strip_leading_zero_byte(values["Prime"])
    a = strip_leading_zero_byte(values["A"])
    b = strip_leading_zero_byte(values["B"])
    n = strip_leading_zero_byte(values["Order"])
    generator = values["Generator (uncompressed)"]

    if not generator.startswith("04"):
        raise SystemExit("the generator is not in uncompressed form")
    body = generator[2:]
    if len(body) != 128:
        raise SystemExit(f"the generator is {len(body) // 2} bytes, not 64")
    gx, gy = body[:64], body[64:]

    for name, value in (("p", p), ("a", a), ("b", b), ("n", n)):
        if len(value) != 64:
            raise SystemExit(f"{name} is {len(value) // 2} bytes, not 32")

    if values["Cofactor"] != "1":
        raise SystemExit(f"cofactor is {values['Cofactor']}, not 1 - "
                         "`curves.rs` assumes 1 for every curve it holds")

    # A cheap check that does not need this repository: the standard's own
    # relation between the parameters. If G is not on the curve these are
    # not the parameters, whatever they came from.
    P, A, B = int(p, 16), int(a, 16), int(b, 16)
    X, Y = int(gx, 16), int(gy, 16)
    if (Y * Y - (X * X * X + A * X + B)) % P != 0:
        raise SystemExit("the generator openssl printed is not on the curve "
                         "openssl printed")

    print("/// sm2p256v1, GB/T 32918.5-2017. `a = p - 3` as on the NIST")
    print("/// curves, so it shares their doubling path; what differs is")
    print("/// everything built on top - see `src/ec/sm2.rs`.")
    print("///")
    print("/// These constants were printed by `scripts/make_sm2_curve.py`")
    print("/// out of OpenSSL and were not typed.")
    print("pub fn sm2() -> Curve {")
    print(f'    let p = hex("{p.lower()}");')
    print("    Curve {")
    print('        name: "sm2p256v1",')
    print(f'        a: hex("{a.lower()}"), // p - 3')
    print(f'        b: hex("{b.lower()}"),')
    print("        g: Point::new(")
    print(f'            hex("{gx.lower()}"),')
    print(f'            hex("{gy.lower()}"),')
    print("        ),")
    print(f'        n: hex("{n.lower()}"),')
    print("        h: BigUint::one(),")
    print("        p,")
    print("    }")
    print("}")


if __name__ == "__main__":
    main()
