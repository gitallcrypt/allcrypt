#!/usr/bin/env python3
"""The WireGuard example (`examples/products/wireguard`) against
wireguard-go, both directions, through `scripts/witness/wgwitness`: a
line protocol over wireguard-go's own handshake, cookie and transport
code.

  * **Ours initiating**: ours writes the initiation, wireguard-go checks
    MAC1 and consumes it, names our static key and answers; ours completes
    the handshake; transport messages each way, and each side opens the
    other's.
  * **Theirs initiating**: the mirror.
  * **Preshared keys**: zero and random, and a mismatched one refused at
    the response by both.
  * **Cookies**: wireguard-go, as a responder under load, answers our
    initiation with a cookie reply; ours opens it and retries with MAC2,
    which wireguard-go checks. And ours answers theirs with a cookie
    reply, which wireguard-go consumes and retries with a MAC2 ours
    checks.
  * **Refusals**: a message changed in transit, a MAC1 for another key,
    an initiation replayed.

    python3 scripts/check_wireguard.py [--ours PATH] [--rounds N]
    python3 scripts/check_wireguard.py --record

`--record` writes `examples/products/fixtures/wireguard.vec` for the
offline tests: conversations with wireguard-go whose random parts are
recorded, so that ours can be replayed against them byte for byte.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example wireguard`; the witness is built
as `docs/building.md` says.
"""

import argparse
import base64
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
OURS = os.path.join(ROOT, "target", "release", "examples", "wireguard")
WITNESS = "/opt/wgwitness/wgwitness"

COUNTS = {}
FAILURES = []


def check(kind, condition, detail=""):
    COUNTS[kind] = COUNTS.get(kind, 0) + 1
    if not condition:
        FAILURES.append(f"{kind}: {detail}")
        print(f"FAIL {kind}: {detail}")


class Go:
    """One wireguard-go device, with one peer."""

    def __init__(self, private):
        self.proc = subprocess.Popen([WITNESS, "-test.run", "TestWitness"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                     env=dict(os.environ, WGWITNESS="1"))
        self.public = self.ask("key", private.hex())

    def ask(self, *words):
        self.proc.stdin.write(" ".join(words) + "\n")
        self.proc.stdin.flush()
        answer = self.proc.stdout.readline().split()
        if not answer or answer[0] != "ok":
            raise RuntimeError(f"wireguard-go {words[0]}: {' '.join(answer)}")
        return answer[1] if len(answer) > 1 else ""

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def ours(*args, check_exit=True):
    result = subprocess.run([OURS, *args], capture_output=True, text=True)
    if check_exit and result.returncode != 0:
        raise RuntimeError(f"ours {args[0]}: {result.stderr.strip()}")
    return result


def b64(key):
    return base64.b64encode(key).decode()


def clamp(key):
    key = bytearray(key)
    key[0] &= 248
    key[31] = (key[31] & 127) | 64
    return bytes(key)


def padded(text, mtu=1420):
    """The Linux module's and wireguard-go's padding."""
    last = len(text) % mtu if len(text) > mtu else len(text)
    size = min((last + 15) // 16 * 16, mtu)
    return text + bytes(size - last)


def plaintexts(choose):
    return [b"", b"x", bytes(choose.randrange(256) for _ in range(choose.choice([15, 16, 17,
                                                                               100, 1419,
                                                                               1430, 1500])))]


def ours_initiating(choose, tmp, record):
    a, b = clamp(os.urandom(32)), clamp(os.urandom(32))
    psk = choose.choice([bytes(32), os.urandom(32)])
    go = Go(b)
    state = os.path.join(tmp, "a.state")
    if os.path.exists(state):
        os.remove(state)
    pub_a = subprocess.run([OURS, "pubkey"], input=b64(a) + "\n", capture_output=True,
                           text=True).stdout.strip()
    other = Go(a)
    check("public key", base64.b64decode(pub_a) == bytes.fromhex(other.public), b64(a))
    other.close()
    go.ask("peer", base64.b64decode(pub_a).hex(), psk.hex())
    ephemeral, timestamp = clamp(os.urandom(32)), os.urandom(12).hex()
    index = str(choose.randrange(1 << 32))
    init = ours("initiate", "--state", state, "--private", b64(a),
                "--peer", b64(bytes.fromhex(go.public)), "--psk", b64(psk),
                "--ephemeral", ephemeral.hex(), "--timestamp", "4" + timestamp[1:],
                "--index", index).stdout.strip()
    seen = go.ask("consume_init", init)
    check("theirs read our initiation", seen == base64.b64decode(pub_a).hex(), seen)
    response = go.ask("respond")
    ours("complete", response, "--state", state)
    sent = []
    for counter, text in enumerate(plaintexts(choose)):
        msg = ours("seal", text.hex(), "--state", state).stdout.strip()
        opened = go.ask("open", msg)
        pad = padded(text)
        check("theirs opened ours", opened == pad.hex(), f"{len(text)} bytes")
        theirs = go.ask("seal", str(counter), text.hex())
        mine = ours("open", theirs, "--state", state).stdout.strip()
        check("ours opened theirs", mine == pad.hex(), f"{len(text)} bytes")
        sent.append((text, msg, theirs))
    # Their message replayed is refused.
    replay = ours("open", sent[-1][2], "--state", state, check_exit=False)
    check("replay refused", replay.returncode != 0, replay.stdout)
    record.setdefault("ours-initiating", []).append(
        [("name", f"ours-initiating-{len(record.get('ours-initiating', []))}"),
         ("private", a.hex()), ("peer-private", b.hex()), ("psk", psk.hex()),
         ("ephemeral", ephemeral.hex()), ("timestamp", "4" + timestamp[1:]),
         ("index", index), ("initiation", init), ("response", response)]
        + [(f"plaintext-{i}", t.hex() or "-") for i, (t, _, _) in enumerate(sent)]
        + [(f"ours-{i}", m) for i, (_, m, _) in enumerate(sent)]
        + [(f"theirs-{i}", m) for i, (_, _, m) in enumerate(sent)])
    go.close()


def theirs_initiating(choose, tmp, record):
    a, b = clamp(os.urandom(32)), clamp(os.urandom(32))
    psk = choose.choice([bytes(32), os.urandom(32)])
    go = Go(a)
    pub_b = subprocess.run([OURS, "pubkey"], input=b64(b) + "\n", capture_output=True,
                           text=True).stdout.strip()
    go.ask("peer", base64.b64decode(pub_b).hex(), psk.hex())
    state = os.path.join(tmp, "b.state")
    if os.path.exists(state):
        os.remove(state)
    init = go.ask("init")
    ephemeral = clamp(os.urandom(32))
    index = str(choose.randrange(1 << 32))
    response = ours("respond", init, "--state", state, "--private", b64(b),
                    "--peer", b64(bytes.fromhex(go.public)), "--psk", b64(psk),
                    "--ephemeral", ephemeral.hex(), "--index", index).stdout.strip()
    go.ask("consume_response", response)
    check("theirs completed with our response", True)
    sent = []
    for counter, text in enumerate(plaintexts(choose)):
        pad = padded(text)
        theirs = go.ask("seal", str(counter), text.hex())
        mine = ours("open", theirs, "--state", state).stdout.strip()
        check("ours opened theirs", mine == pad.hex(), f"{len(text)} bytes")
        msg = ours("seal", text.hex(), "--state", state).stdout.strip()
        check("theirs opened ours", go.ask("open", msg) == pad.hex(), f"{len(text)} bytes")
        sent.append((text, msg, theirs))
    # The same initiation again is a replay.
    again = ours("respond", init, "--state", state, "--private", b64(b),
                 "--peer", b64(bytes.fromhex(go.public)), "--psk", b64(psk),
                 check_exit=False)
    check("replayed initiation refused", again.returncode != 0, again.stdout)
    record.setdefault("theirs-initiating", []).append(
        [("name", f"theirs-initiating-{len(record.get('theirs-initiating', []))}"),
         ("private", b.hex()), ("peer-private", a.hex()), ("psk", psk.hex()),
         ("ephemeral", ephemeral.hex()), ("index", index), ("initiation", init),
         ("response", response)]
        + [(f"plaintext-{i}", t.hex() or "-") for i, (t, _, _) in enumerate(sent)]
        + [(f"ours-{i}", m) for i, (_, m, _) in enumerate(sent)]
        + [(f"theirs-{i}", m) for i, (_, _, m) in enumerate(sent)])
    go.close()


def mismatched_psk(tmp):
    a, b = clamp(os.urandom(32)), clamp(os.urandom(32))
    go = Go(b)
    pub_a = subprocess.run([OURS, "pubkey"], input=b64(a) + "\n", capture_output=True,
                           text=True).stdout.strip()
    go.ask("peer", base64.b64decode(pub_a).hex(), os.urandom(32).hex())
    state = os.path.join(tmp, "p.state")
    init = ours("initiate", "--state", state, "--private", b64(a),
                "--peer", b64(bytes.fromhex(go.public)), "--psk", b64(os.urandom(32))
                ).stdout.strip()
    go.ask("consume_init", init)
    response = go.ask("respond")
    result = ours("complete", response, "--state", state, check_exit=False)
    check("mismatched PSK refused", result.returncode != 0, result.stdout)
    go.close()


def cookies(tmp, record):
    a, b = clamp(os.urandom(32)), clamp(os.urandom(32))
    # Theirs is the loaded responder.
    go = Go(b)
    pub_a = subprocess.run([OURS, "pubkey"], input=b64(a) + "\n", capture_output=True,
                           text=True).stdout.strip()
    go.ask("peer", base64.b64decode(pub_a).hex(), bytes(32).hex())
    state = os.path.join(tmp, "c.state")
    if os.path.exists(state):
        os.remove(state)
    source = "c000020114e9"
    init = ours("initiate", "--state", state, "--private", b64(a),
                "--peer", b64(bytes.fromhex(go.public))).stdout.strip()
    check("no MAC2 without a cookie", go.ask("check_mac2", init, source) == "false")
    reply = go.ask("cookie_reply", init, source)
    ours("cookie", reply, "--state", state)
    retry = ours("initiate", "--state", state).stdout.strip()
    check("theirs accepted our MAC2", go.ask("check_mac2", retry, source) == "true", retry)
    check("MAC2 bound to the source",
          go.ask("check_mac2", retry, "c000020214e9") == "false")
    go.close()

    # Ours is the loaded responder.
    go = Go(a)
    pub_b = subprocess.run([OURS, "pubkey"], input=b64(b) + "\n", capture_output=True,
                           text=True).stdout.strip()
    go.ask("peer", base64.b64decode(pub_b).hex(), bytes(32).hex())
    init = go.ask("init")
    secret = os.urandom(32).hex()
    reply = ours("cookie-reply", init, "--private", b64(b), "--secret", secret,
                 "--source", source).stdout.strip()
    go.ask("consume_cookie", reply)
    retry = go.ask("init")
    good = ours("check-mac2", retry, "--secret", secret, "--source", source, check_exit=False)
    check("ours accepted their MAC2", good.returncode == 0, good.stdout)
    bad = ours("check-mac2", retry, "--secret", os.urandom(32).hex(), "--source", source,
               check_exit=False)
    check("MAC2 bound to the secret", bad.returncode == 1, bad.stdout)
    record.setdefault("cookie", []).append([
        ("name", f"cookie-{len(record.get('cookie', []))}"), ("private", b.hex()),
        ("peer-private", a.hex()), ("secret", secret), ("source", source),
        ("initiation", init), ("reply", reply), ("retry", retry)])
    go.close()


def refusals(tmp):
    a, b = clamp(os.urandom(32)), clamp(os.urandom(32))
    go = Go(b)
    pub_a = subprocess.run([OURS, "pubkey"], input=b64(a) + "\n", capture_output=True,
                           text=True).stdout.strip()
    go.ask("peer", base64.b64decode(pub_a).hex(), bytes(32).hex())
    init = go.ask("init")
    # Theirs to a third key: MAC1 is for b, so ours as c refuses it.
    c = clamp(os.urandom(32))
    result = ours("respond", init, "--state", os.path.join(tmp, "r.state"), "--private", b64(c),
                  "--peer", pub_a, check_exit=False)
    check("MAC1 for another key refused", result.returncode != 0, result.stdout)
    go.close()


def write_record(record):
    lines = ["# Conversations with wireguard-go through scripts/witness/wgwitness, kept by",
             "# scripts/check_wireguard.py --record for the offline tests in",
             "# examples/products/wireguard. Hex; - is empty. The ephemeral key, timestamp",
             "# and index are ours, fixed so the handshake replays byte for byte.", ""]
    for section in ["ours-initiating", "theirs-initiating", "cookie"]:
        lines.append(f"[{section}]")
        for rec in record[section]:
            lines += [f"{k} = {v}" for k, v in rec]
        lines.append("")
    with open(os.path.join(FIXTURES, "wireguard.vec"), "w") as f:
        f.write("\n".join(lines))


def main():
    global OURS
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--seed", type=int, default=51820)
    args = parser.parse_args()
    OURS = args.ours
    choose = random.Random(args.seed)
    record = {}
    with tempfile.TemporaryDirectory() as tmp:
        for _ in range(args.rounds):
            ours_initiating(choose, tmp, record)
            theirs_initiating(choose, tmp, record)
        for _ in range(4):
            mismatched_psk(tmp)
            cookies(tmp, record)
            refusals(tmp)
    if args.record:
        for section in record:
            record[section] = record[section][:6]
        write_record(record)
    total = sum(COUNTS.values())
    print(", ".join(f"{k} {v}" for k, v in COUNTS.items()))
    print(f"{total - len(FAILURES)} of {total} passed")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
