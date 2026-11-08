#!/usr/bin/env python3
"""Checks /opt/lmswitness before anything is written from it.

    python3 scripts/witness/lms/selftest.py [/opt/lmswitness]

Requests, one per line, hex fields, "-" for empty:

    lms <lms> <ots> <SEED||I> <q> <message>     -> <public key> <signature>
    hss <L> <lms> <ots> ... <SEED||I> <count> <message>
                                                -> <public key> <signature>
    verify <HSS public key> <message> <HSS signature>  -> ok | bad

Types are decimal type codes. `lms` is one tree from SEED and I at leaf q;
`hss` is a hierarchy whose top tree is SEED and I, the trees below derived
as hash-sigs derives them, after `count` signatures. A witness answers
"error unsupported" for what it does not do.

Every witness that signs must give RFC 9858's four worked examples, and
the two trees of RFC 8554's second, from the seeds the documents print -
those low enough to build; every verifier must accept every worked example
and refuse each with a byte changed.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
WITNESSES = ["hashsigs", "bc-lms", "pyhsslms", "hbs-lms"]
SIGNERS = {"lms": ["hashsigs", "bc-lms", "pyhsslms"], "hss": ["hashsigs", "bc-lms"]}
HEIGHTS = {5 + i: h for i, h in enumerate([5, 10, 15, 20, 25] * 4)}


def ask(out, witness, requests):
    done = subprocess.run([os.path.join(out, witness)],
                          input="".join(r + "\n" for r in requests),
                          capture_output=True, text=True, check=True)
    answers = done.stdout.splitlines()
    if len(answers) != len(requests):
        sys.exit(f"{witness} answered {len(answers)} of {len(requests)} requests")
    return answers


def _value(line):
    """(label, hex) from an indented line of a worked example."""
    if not line.startswith("   "):
        return None
    words = line.split("#")[0].split("|")[0].split()
    if not words:
        return None
    hexed = words[-1]
    if len(hexed) < 2 or len(hexed) % 2 or any(c not in "0123456789abcdef" for c in hexed):
        return None
    return " ".join(words[:-1]), bytes.fromhex(hexed)


def _examples(text, starts):
    out, block = [], None
    for line in text.splitlines():
        t = line.strip()
        if any(t.startswith(s) for s in starts) and not any(
                w in t for w in ("Private Key", "Public Key", "Message", "Signature")):
            out.append({"private": [], "public": b"", "message": b"", "signature": b""})
            block = None
            continue
        if not out:
            continue
        if t.startswith("(note: procedure"):
            block = "private"
        elif t == "HSS public key":
            block = "public"
        elif t == "HSS signature":
            block = "signature"
        elif t.startswith("Message "):
            block = "message"
        found = _value(line)
        if not found or block is None:
            continue
        label, value = found
        e = out[-1]
        if block == "private":
            if label:
                e["private"].append([label, value])
            else:
                e["private"][-1][1] += value
        else:
            e[block] += value
    return out


def worked_examples():
    """RFC 8554 Appendix F's two and RFC 9858 Appendix A's four."""
    a = open(os.path.join(ROOT, "rfcs", "rfc8554.txt")).read()
    a = a[a.rindex("Appendix F.  Test Cases"):]
    first = _examples("   X\n" + a[:a.index("Test Case 2")], ["X"])
    second = _examples("   X\n" + a[a.index("Test Case 2"):], ["X"])
    b = open(os.path.join(ROOT, "rfcs", "rfc9858.txt")).read()
    b = b[b.rindex("Appendix A.  Test Cases"):]
    b = b[:b.find("\nAcknowledgements")]
    later = _examples(b, ["A.1.", "A.2.", "A.3.", "A.4."])
    found = first + second + later
    if len(found) != 6 or any(not e["public"] or not e["signature"] for e in found):
        sys.exit("the worked examples did not parse")
    return found


def types(public):
    return int.from_bytes(public[:4], "big"), int.from_bytes(public[4:8], "big")


def lms_sig_len(sig):
    """The length of the LMS signature at the start of `sig`."""
    ots = int.from_bytes(sig[4:8], "big")
    n, w = (32 if ots in (1, 2, 3, 4, 9, 10, 11, 12) else 24), [1, 2, 4, 8][(ots - 1) % 4]
    p = {(32, 1): 265, (32, 2): 133, (32, 4): 67, (32, 8): 34,
         (24, 1): 200, (24, 2): 101, (24, 4): 51, (24, 8): 26}[n, w]
    at = 8 + n * (p + 1)
    lms = int.from_bytes(sig[at:at + 4], "big")
    m = 32 if lms in (5, 6, 7, 8, 9, 15, 16, 17, 18, 19) else 24
    return at + 4 + HEIGHTS[lms] * m


def signing_requests(examples):
    """(request, expected answer) for the trees low enough to build."""
    out = []
    second = examples[1]
    top = types(second["public"][4:])
    sig = second["signature"][4:]
    top_sig_len = lms_sig_len(sig)
    top_sig, rest = sig[:top_sig_len], sig[top_sig_len:]
    lower_type = types(rest)
    lower_pub_len = 24 + (32 if lower_type[0] < 10 or 15 <= lower_type[0] < 20 else 24)
    lower_pub, last = rest[:lower_pub_len], rest[lower_pub_len:]
    seeds = [v for _, v in second["private"]]
    for (lms, ots), seed, ident, message, public, signature in (
            (top, seeds[0], seeds[1], lower_pub, second["public"][4:], top_sig),
            (types(lower_pub), seeds[2], seeds[3], second["message"], lower_pub, last)):
        q = int.from_bytes(signature[:4], "big")
        out.append((f"lms {lms} {ots} {(seed + ident).hex()} {q} {message.hex()}",
                    f"{public.hex()} {signature.hex()}"))
    for e in examples[2:]:
        lms, ots = types(e["public"][4:])
        if HEIGHTS[lms] > 10:
            continue
        seed_i = e["private"][0][1] + e["private"][1][1]
        q = int.from_bytes(e["signature"][4:8], "big")
        out.append((f"lms {lms} {ots} {seed_i.hex()} {q} {e['message'].hex()}",
                    f"{e['public'][4:].hex()} {e['signature'][4:].hex()}"))
        out.append((f"hss 1 {lms} {ots} {seed_i.hex()} {q} {e['message'].hex()}",
                    f"{e['public'].hex()} {e['signature'].hex()}"))
    return out


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/opt/lmswitness"
    examples = worked_examples()
    signing = signing_requests(examples)
    counts = {}
    for w in WITNESSES:
        mine = [(r, a) for r, a in signing if w in SIGNERS[r.split()[0]]]
        for (request, want), got in zip(mine, ask(out, w, [r for r, _ in mine])):
            if got != want:
                sys.exit(f"{w} does not reproduce {request[:60]}: {got[:60]}")
        checks = []
        for e in examples:
            checks.append((f"verify {e['public'].hex()} {e['message'].hex()} "
                           f"{e['signature'].hex()}", "ok"))
            for at in (4, 12, len(e["signature"]) // 2, len(e["signature"]) - 1):
                bad = bytearray(e["signature"])
                bad[at] ^= 0x04
                checks.append((f"verify {e['public'].hex()} {e['message'].hex()} "
                               f"{bytes(bad).hex()}", "bad"))
        taken = 0
        for (request, want), got in zip(checks, ask(out, w, [r for r, _ in checks])):
            if got == "error unsupported" and w == "hbs-lms":
                continue
            if got != want:
                sys.exit(f"{w} answers {got} to {request[:70]}, not {want}")
            taken += 1
        counts[w] = (len(mine), taken)
    print("lms witnesses: worked examples signed again and verified: " + ", ".join(
        f"{w} {s} signed, {v} verified" for w, (s, v) in counts.items()))


if __name__ == "__main__":
    main()
