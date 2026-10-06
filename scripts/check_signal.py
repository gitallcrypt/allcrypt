#!/usr/bin/env python3
"""The Signal example (`examples/products/signal`) against
libsignal-protocol-c.

Both implementations answer the same line protocol (the witness's
header in `scripts/witness/signalwitness/main.c` lists it), and both
draw their randomness from a stream named by a seed. So a conversation
is a script of commands, and it is run four ways - libsignal on both
sides, ours on both sides, and each mixed pairing - with the same seeds.
**Every reply must be identical in all four**: bundles, signatures,
ciphertexts, plaintexts and error codes. A mixed pairing shows the two
interoperate; identical bytes show more, that ours draws the same random
bytes in the same order and serialises every field the same way, which
no amount of interoperating proves.

The conversations: X3DH with and without a one-time prekey, messages
out of order across ratchet steps, duplicates, a long run of turns,
sender-key groups, both parties starting a session at once, a session
replaced while messages on the old one are in flight, a third party
claiming a known peer's name, a one-time prekey used twice, late
messages on more old chains than are kept, a sender key announced
twice, every refusal the formats have, and a seeded random walk over
all of it. One more runs live only: 2001
messages, to reach the limit on skipped keys.

    python3 scripts/check_signal.py [--witness PATH] [--ours PATH]
    python3 scripts/check_signal.py --record

`--record` writes the libsignal-on-both-sides transcripts to
`examples/products/fixtures/signal.vec`, which the example's offline
tests replay against this implementation, byte for byte.

**A development tool, not a test.** The gate runs none of it. Build ours
first: `cargo build --release --example signal`.
"""

import argparse
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(ROOT, "examples", "products", "fixtures")
WITNESS = "/opt/signalwitness/signalwitness"
OURS = os.path.join(ROOT, "target", "release", "examples", "signal")


class Party:
    def __init__(self, program, label, seed, registration_id, name, peer, log):
        command = [program] if program == WITNESS_PATH[0] else [program, "agent"]
        self.process = subprocess.Popen(command + [seed, str(registration_id), name, peer],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        text=True)
        self.label = label
        self.log = log
        log.append(("party", f"{label} {seed} {registration_id} {name} {peer}"))

    def __call__(self, command):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        reply = self.process.stdout.readline().rstrip("\n")
        if not reply:
            raise SystemExit(f"{self.label} said nothing to: {command[:60]}")
        self.log.append(("send", f"{self.label} {command}"))
        self.log.append(("reply", reply))
        return reply

    def close(self):
        self.process.stdin.close()
        self.process.wait()


WITNESS_PATH = [WITNESS]


def rest(reply):
    """`message 3 HEX` -> `3 HEX`; `bundle ...` -> the fields."""
    return reply.split(" ", 1)[1]


def text(value):
    return value.encode().hex()


def expect(reply, wanted, what):
    if reply != wanted:
        raise AssertionError(f"{what}: {reply[:80]!r}, expected {wanted[:80]!r}")


def readable(reply, plaintext, what):
    expect(reply, "plaintext " + text(plaintext), what)


def message(reply):
    """The type and bytes of a `message T HEX` reply."""
    _, kind, data = reply.split(" ")
    return kind, data


def deliver(receiver, reply):
    return receiver("decrypt " + rest(reply))


def varint(value):
    out = bytearray()
    while value >= 0x80:
        out.append(value & 0x7F | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint(number << 3 | 2) + varint(len(value)) + value


def signal_message_shape():
    """A well-formed SignalMessage under no session's keys."""
    body = field(1, b"\x05" + bytes(32)) + field(2, 0) + field(3, 0) + field(4, bytes(16))
    return (b"\x33" + body + bytes(8)).hex()


def group_message_shape():
    """A well-formed SenderKeyMessage under nobody's key."""
    return (b"\x33" + field(1, 1) + field(2, 0) + field(3, bytes(16)) + bytes(64)).hex()


def start(alice, bob, pre_key=True):
    """Bob publishes, Alice builds the session."""
    bundle = rest(bob("prekeys 7 3"))
    if not pre_key:
        fields = bundle.split(" ")
        fields[2] = fields[3] = "-"
        bundle = " ".join(fields)
    expect(alice("process " + bundle), "ok", "process")


# ------------------------------------------------------------ scenarios --

def basic(party):
    alice = party("alice", "a1", 1001, "alice", "bob")
    bob = party("bob", "b1", 2002, "bob", "alice")
    alice("identity")
    bob("identity")
    start(alice, bob)
    first = alice("encrypt " + text("Hello, Bob."))
    second = alice("encrypt " + text("Are you there?"))
    assert first.startswith("message 3 ") and second.startswith("message 3 "), first
    readable(deliver(bob, first), "Hello, Bob.", "first prekey message")
    readable(deliver(bob, second), "Are you there?", "second prekey message")
    for turn in range(5):
        reply = bob("encrypt " + text(f"bob, turn {turn}"))
        assert reply.startswith("message 2 "), reply
        readable(deliver(alice, reply), f"bob, turn {turn}", "bob's turn")
        sent = alice("encrypt " + text(f"alice, turn {turn}" * (turn + 1)))
        assert sent.startswith("message 2 "), sent
        readable(deliver(bob, sent), f"alice, turn {turn}" * (turn + 1), "alice's turn")


def no_one_time_prekey(party):
    alice = party("alice", "a2", 11, "alice", "bob")
    bob = party("bob", "b2", 22, "bob", "alice")
    start(alice, bob, pre_key=False)
    sent = alice("encrypt " + text("three agreements, not four"))
    readable(deliver(bob, sent), "three agreements, not four", "no OPK")
    readable(deliver(alice, bob("encrypt " + text("answered"))), "answered", "reply")
    readable(deliver(bob, alice("encrypt " + text("and on"))), "and on", "after")


def out_of_order(party):
    alice = party("alice", "a3", 3, "alice", "bob")
    bob = party("bob", "b3", 4, "bob", "alice")
    start(alice, bob)
    readable(deliver(bob, alice("encrypt " + text("hello"))), "hello", "open")
    readable(deliver(alice, bob("encrypt " + text("hi"))), "hi", "answer")
    batch = [alice("encrypt " + text(f"m{i}" * (i + 1))) for i in range(6)]
    for i in (5, 0, 3, 1, 4, 2):
        readable(deliver(bob, batch[i]), f"m{i}" * (i + 1), f"m{i} out of order")
    expect(deliver(bob, batch[3]), "error -1001", "a duplicate")
    # Late messages from a chain that has since been ratcheted past.
    old = [alice("encrypt " + text(f"old{i}")) for i in range(3)]
    readable(deliver(bob, old[0]), "old0", "old0")
    readable(deliver(alice, bob("encrypt " + text("ratchet"))), "ratchet", "ratchet")
    new = alice("encrypt " + text("new"))
    readable(deliver(bob, new), "new", "on the new chain")
    readable(deliver(bob, old[2]), "old2", "old2, after the ratchet step")
    readable(deliver(bob, old[1]), "old1", "old1, after the ratchet step")
    expect(deliver(bob, old[1]), "error -1001", "a late duplicate")


def long_ratchet(party):
    alice = party("alice", "a4", 5, "alice", "bob")
    bob = party("bob", "b4", 6, "bob", "alice")
    start(alice, bob)
    choose = random.Random(4)
    for turn in range(24):
        sender, receiver = (alice, bob) if turn % 2 == 0 else (bob, alice)
        count = choose.randint(1, 3)
        for k in range(count):
            body = bytes(choose.randrange(256) for _ in range(choose.randint(1, 120))).hex()
            reply = sender("encrypt " + body)
            expect(deliver(receiver, reply), "plaintext " + body, f"turn {turn}.{k}")


def group(party):
    alice = party("alice", "a5", 7, "alice", "bob")
    bob = party("bob", "b5", 8, "bob", "alice")
    expect(alice("group-encrypt friends " + text("too early")), "error -1008", "no sender key")
    expect(bob("group-decrypt friends 33" + "00" * 70), "error -1005",
           "zeros: field 0 is an unknown field, so the required ones are missing")
    expect(bob("group-decrypt friends " + group_message_shape()), "error -1008",
           "no sender key held")
    distribution = alice("group-create friends")
    expect(alice("group-create friends"), distribution, "the same key, announced again")
    expect(bob("group-process friends " + rest(distribution)), "ok", "process")
    sent = [alice("group-encrypt friends " + text(f"g{i}")) for i in range(6)]
    for i in (1, 0, 5, 2, 4, 3):
        readable(bob("group-decrypt friends " + message(sent[i])[1]), f"g{i}", f"g{i}")
    expect(bob("group-decrypt friends " + message(sent[2])[1]), "error -1001", "duplicate")
    tampered = bytearray.fromhex(message(sent[0])[1])
    tampered[-1] ^= 1
    expect(bob("group-decrypt friends " + tampered.hex()), "error -1005", "bad signature")
    expect(bob("group-decrypt others " + message(sent[0])[1]), "error -1008", "other group")
    # Bob's own sender key, the other way.
    back = bob("group-create friends")
    expect(alice("group-process friends " + rest(back)), "ok", "bob's key")
    reply = bob("group-encrypt friends " + text("from bob"))
    readable(alice("group-decrypt friends " + message(reply)[1]), "from bob", "bob's message")
    # A key id that is not held is an invalid message.
    expect(alice("group-decrypt friends " + message(sent[0])[1]), "error -1005", "unknown id")
    # Alice announces her key again, further along its chain, and Bob
    # takes it as a second state in front of the first. A message sent
    # before the announcement is looked up in the newer state, which has
    # passed it.
    held = alice("group-encrypt friends " + text("sent before the announcement"))
    expect(bob("group-process friends " + rest(alice("group-create friends"))), "ok", "again")
    bob("group-decrypt friends " + message(held)[1])
    after = alice("group-encrypt friends " + text("after"))
    readable(bob("group-decrypt friends " + message(after)[1]), "after", "after re-announcing")


def simultaneous(party):
    alice = party("alice", "a6", 9, "alice", "bob")
    bob = party("bob", "b6", 10, "bob", "alice")
    alice_bundle = rest(alice("prekeys 1 1"))
    bob_bundle = rest(bob("prekeys 2 2"))
    expect(alice("process " + bob_bundle), "ok", "alice processes")
    expect(bob("process " + alice_bundle), "ok", "bob processes")
    from_alice = alice("encrypt " + text("alice first"))
    from_bob = bob("encrypt " + text("bob first"))
    readable(deliver(bob, from_alice), "alice first", "bob decrypts")
    readable(deliver(alice, from_bob), "bob first", "alice decrypts")
    for turn in range(4):
        readable(deliver(bob, alice("encrypt " + text(f"a{turn}"))), f"a{turn}", f"a{turn}")
        readable(deliver(alice, bob("encrypt " + text(f"b{turn}"))), f"b{turn}", f"b{turn}")


def archived_sessions(party):
    alice = party("alice", "a7", 12, "alice", "bob")
    bob = party("bob", "b7", 13, "bob", "alice")
    start(alice, bob)
    readable(deliver(bob, alice("encrypt " + text("session one"))), "session one", "one")
    in_flight = bob("encrypt " + text("sent on session one"))
    # Bob republishes and Alice starts over; Bob's reply is still on
    # the first session.
    expect(alice("process " + rest(bob("prekeys 8 4"))), "ok", "a second session")
    second = alice("encrypt " + text("session two"))
    assert second.startswith("message 3 "), second
    readable(deliver(bob, second), "session two", "bob builds session two")
    readable(deliver(alice, in_flight), "sent on session one", "an archived session")
    readable(deliver(bob, alice("encrypt " + text("which one now?"))), "which one now?", "after")
    readable(deliver(alice, bob("encrypt " + text("this one"))), "this one", "converged")


def chain_limit(party):
    """Late messages on each of seven old chains: libsignal keeps five
    receiving chains, and a message on a dropped one starts a ratchet
    step that its MAC then refuses."""
    alice = party("alice", "a11a", 21, "alice", "bob")
    bob = party("bob", "b11b", 22, "bob", "alice")
    start(alice, bob)
    held = []
    for round_ in range(7):
        readable(deliver(bob, alice("encrypt " + text(f"r{round_}"))), f"r{round_}", "now")
        held.append(alice("encrypt " + text(f"late {round_}")))
        readable(deliver(alice, bob("encrypt " + text(f"ack {round_}"))), f"ack {round_}", "ack")
    for round_, late in enumerate(held):
        deliver(bob, late)


def three_sessions(party):
    """Three sessions in turn, each answered on its own; the answers are
    delivered afterwards, oldest first, so the archive is searched."""
    alice = party("alice", "a12a", 23, "alice", "bob")
    bob = party("bob", "b12b", 24, "bob", "alice")
    answers = []
    for n in range(3):
        expect(alice("process " + rest(bob(f"prekeys {10 + n} {20 + n}"))), "ok", f"session {n}")
        readable(deliver(bob, alice("encrypt " + text(f"open {n}"))), f"open {n}", f"open {n}")
        answers.append(bob("encrypt " + text(f"answer {n}")))
    for n, answer in enumerate(answers):
        readable(deliver(alice, answer), f"answer {n}", f"answer {n}")
    readable(deliver(bob, alice("encrypt " + text("which session?"))), "which session?", "then")
    readable(deliver(alice, bob("encrypt " + text("this one"))), "this one", "and back")


def refusals(party):
    alice = party("alice", "a8", 14, "alice", "bob")
    bob = party("bob", "b8", 15, "bob", "alice")
    expect(alice("encrypt " + text("nobody")), "error -1000", "no session to encrypt with")
    bundle = rest(bob("prekeys 7 3")).split(" ")
    bad = list(bundle)
    signature = bytearray.fromhex(bad[6])
    signature[5] ^= 1
    bad[6] = signature.hex()
    expect(alice("process " + " ".join(bad)), "error -1002", "a bad prekey signature")
    expect(alice("process " + " ".join(bundle[:6] + [bundle[6][:-2]] + bundle[7:])),
           "error -22", "a short signature")
    # A signed prekey id Bob does not have: the signature covers the
    # key, not the id, so the bundle is accepted and the message refused.
    wrong = list(bundle)
    wrong[4] = "99"
    expect(alice("process " + " ".join(wrong)), "ok", "an unknown signed prekey id")
    unknown = alice("encrypt " + text("x"))
    expect(deliver(bob, unknown), "error -1003", "the unknown id")
    expect(alice("process " + " ".join(bundle)), "ok", "the real bundle")
    first = alice("encrypt " + text("hello"))
    kind, data = message(first)
    for version, code in (("13", "-1007"), ("23", "-1007"), ("43", "-1006")):
        expect(bob(f"decrypt 3 {version}{data[2:]}"), f"error {code}", f"prekey version {version}")
    expect(bob("decrypt 3 33ff"), "error -1100", "a prekey protobuf that is not one")
    expect(bob("decrypt 3 33"), "error -22", "a one-byte prekey message")
    expect(bob("decrypt 2 " + data), "error -1100", "a prekey message as a plain one")
    expect(bob("decrypt 2 " + signal_message_shape()), "error -1008", "no session yet")
    readable(deliver(bob, first), "hello", "the real one")
    reply = bob("encrypt " + text("answer"))
    kind, data = message(reply)
    raw = bytearray.fromhex(data)
    for at, what in ((len(raw) - 1, "the MAC"), (len(raw) - 12, "the ciphertext"),
                     (5, "the ratchet key")):
        bent = bytearray(raw)
        bent[at] ^= 0x04
        expect(alice(f"decrypt 2 {bent.hex()}"), "error -1005", f"a flipped bit in {what}")
    for version, code in (("13", "-1007"), ("43", "-1005"), ("23", "-1005")):
        expect(alice(f"decrypt 2 {version}{data[2:]}"), f"error {code}",
               f"message version {version}")
    expect(alice("decrypt 2 " + data[:18]), "error -22", "too short to hold a MAC")
    expect(alice("decrypt 2 33" + "ff" * 12), "error -1100", "a protobuf that is not one")
    expect(alice("decrypt 2 zz"), "error -22", "not hex")
    readable(deliver(alice, reply), "answer", "the real one")
    # Somebody else claiming to be alice: a different identity key.
    mallory = party("mallory", "c8", 16, "alice", "bob")
    expect(mallory("process " + rest(bob("prekeys 9 5"))), "ok", "mallory processes")
    expect(deliver(bob, mallory("encrypt " + text("it is me"))), "error -1010",
           "a changed identity")
    readable(deliver(bob, alice("encrypt " + text("still me"))), "still me", "alice is fine")
    # The one-time prekey was deleted when it was used, so a session
    # built from the same bundle again is refused at Bob's end.
    expect(alice("process " + " ".join(bundle)), "ok", "the used bundle again")
    expect(deliver(bob, alice("encrypt " + text("reused"))), "error -1003", "a used prekey")


def random_walk(party):
    alice = party("alice", "a9", 17, "alice", "bob")
    bob = party("bob", "b9", 18, "bob", "alice")
    start(alice, bob)
    choose = random.Random(9)
    queues = {"alice": [], "bob": []}
    delivered = {"alice": [], "bob": []}
    group_sent = []
    expect(bob("group-process walk " + rest(alice("group-create walk"))), "ok", "group")
    names = {"alice": alice, "bob": bob}
    for step in range(120):
        action = choose.random()
        who = choose.choice(["alice", "bob"])
        other = "bob" if who == "alice" else "alice"
        if action < 0.4:
            body = bytes(choose.randrange(256) for _ in range(choose.randint(1, 60))).hex()
            queues[other].append((names[who]("encrypt " + body), body))
        elif action < 0.8 and queues[who]:
            reply, body = queues[who].pop(choose.randrange(len(queues[who])))
            got = deliver(names[who], reply)
            # A message sent before the receiver had a session may arrive
            # after it has one, or be refused before: the reply is
            # whatever libsignal says, and identical across pairings.
            if got.startswith("plaintext "):
                expect(got, "plaintext " + body, f"step {step}")
                delivered[who].append(reply)
        elif action < 0.85 and delivered[who]:
            expect(deliver(names[who], choose.choice(delivered[who])), "error -1001",
                   f"step {step}, a duplicate")
        elif action < 0.95:
            body = bytes(choose.randrange(256) for _ in range(choose.randint(1, 40))).hex()
            group_sent.append((alice("group-encrypt walk " + body), body))
        elif group_sent:
            reply, body = group_sent.pop(choose.randrange(len(group_sent)))
            expect(bob("group-decrypt walk " + message(reply)[1]), "plaintext " + body,
                   f"step {step}, group")


def skip_limit(party):
    alice = party("alice", "aa10", 19, "alice", "bob")
    bob = party("bob", "bb10", 20, "bob", "alice")
    start(alice, bob)
    readable(deliver(bob, alice("encrypt " + text("open"))), "open", "open")
    readable(deliver(alice, bob("encrypt " + text("ok"))), "ok", "answer")
    sent = [alice("encrypt " + text(str(i))) for i in range(2002)]
    expect(deliver(bob, sent[2001]), "error -1005", "2001 ahead")
    readable(deliver(bob, sent[2000]), "2000", "2000 ahead")
    readable(deliver(bob, sent[0]), "0", "the first, from the 2000 kept")


RECORDED = [basic, no_one_time_prekey, out_of_order, long_ratchet, group, simultaneous,
            archived_sessions, three_sessions, chain_limit, refusals, random_walk]
LIVE_ONLY = [skip_limit]


def run(scenario, sides):
    """Run a scenario with `sides` choosing who plays whom; the log."""
    log = []
    parties = []

    def party(label, seed, registration_id, name, peer):
        program = sides.get(label, sides["default"])
        made = Party(program, label, seed, registration_id, name, peer, log)
        parties.append(made)
        return made

    try:
        scenario(party)
    finally:
        for made in parties:
            made.close()
    return log


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--witness", default=WITNESS)
    parser.add_argument("--ours", default=OURS)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    WITNESS_PATH[0] = args.witness
    w, o = args.witness, args.ours
    pairings = {
        "libsignal / libsignal": {"default": w},
        "ours / ours": {"default": o},
        "libsignal alice / ours bob": {"default": o, "alice": w},
        "ours alice / libsignal bob": {"default": w, "alice": o},
    }
    failures = 0
    total = 0
    recorded = []
    for scenario in RECORDED + LIVE_ONLY:
        reference = None
        for title, sides in pairings.items():
            total += 1
            try:
                log = run(scenario, sides)
            except AssertionError as error:
                print(f"FAIL {scenario.__name__}, {title}: {error}")
                failures += 1
                continue
            if reference is None:
                reference = log
                steps = sum(1 for kind, _ in log if kind == "reply")
                if scenario in RECORDED:
                    recorded.append((scenario.__name__.replace("_", "-"), log))
                print(f"ok   {scenario.__name__}, {title}: {steps} replies")
                continue
            for at, (mine, theirs) in enumerate(zip(log, reference)):
                if mine != theirs:
                    print(f"FAIL {scenario.__name__}, {title}: differs at entry {at}")
                    print(f"     libsignal: {theirs[1][:120]}")
                    print(f"     this one:  {mine[1][:120]}")
                    failures += 1
                    break
            else:
                if len(log) != len(reference):
                    print(f"FAIL {scenario.__name__}, {title}: {len(log)} entries, "
                          f"libsignal had {len(reference)}")
                    failures += 1
                else:
                    print(f"ok   {scenario.__name__}, {title}: identical")
    print(f"\n{total - failures}/{total} runs agree")
    if args.record and not failures:
        path = os.path.join(FIXTURES, "signal.vec")
        with open(path, "w") as out:
            out.write("# Conversations between two copies of libsignal-protocol-c 2.3.3,\n")
            out.write("# written by scripts/check_signal.py --record. Do not edit: every\n")
            out.write("# reply is libsignal's.\n#\n")
            out.write("# Each party is LABEL SEED REGISTRATION_ID NAME PEER; each send is\n")
            out.write("# LABEL COMMAND, and the reply after it is what that party answered.\n")
            for name, log in recorded:
                out.write(f"\n[conversation]\nname = {name}\n")
                for kind, value in log:
                    out.write(f"{kind} = {value}\n")
        print(f"{len(recorded)} conversations -> {path}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
