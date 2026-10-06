#!/usr/bin/env python3
"""Drive the TLS client against real servers. A development tool, not a test.

    python3 scripts/check_live.py              # the badssl.com matrix
    python3 scripts/check_live.py --general    # ordinary public servers too
    python3 scripts/check_live.py --host expired.badssl.com --expect reject
    python3 scripts/check_live.py --pq         # hybrid post-quantum groups

**This is deliberately not in `pytests/`.** Nothing in the gate needs the
network, and nothing should: a test that fails because a host is down, or
a CA rotated, or a corporate proxy is in the way, is a test that teaches
people to ignore failures. Run this by hand when changing certificate
verification or the handshake, and read what it says.

## What it is for

Everything in the offline suite talks to a server this repo starts, with a
certificate this repo generated. That is the right way to test, and it
leaves one gap: every certificate our verifier has ever judged was one we
made, and the ways we make them wrong are the ways we already thought of.

badssl.com is a standing set of deliberately broken servers maintained by
other people, which is the point - the failures are theirs, not ours. Each
row below says what should happen and why, and the interesting rows are
the ones that must **fail**. A client that accepts everything passes every
happy-path check ever written.

## The thing that makes this lie

A TLS-terminating middlebox - a corporate proxy, a sandbox egress gateway,
some antivirus - mints a fresh certificate for whatever name is in the
SNI, signed by a CA that is already in the trust store. Behind one of
those, `expired.badssl.com` returns a **valid, unexpired** certificate and
accepting it is correct. Every deliberately broken case is laundered into
a working one, and a run full of unexplained passes looks exactly like a
run where everything works.

So this probes for that first, and refuses to report certificate results
at all if it finds one. That check is the most important thing in the
file.
"""

from __future__ import annotations

import argparse
import re
import os
import socket
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

try:
    import allcrypt
    import allcrypt_ssl
except ImportError as reason:                    # pragma: no cover
    sys.exit(f"build the module first "
             f"(python3 scripts/build_python.py): {reason}")


def stale_module():
    """Why the compiled module is older than the Rust it was built from,
    or None.

    This script is Python and the code it measures is not: a pull
    updates the script at once and the library only when
    `build_python.py` is run. A run against a stale module reports on
    code that is no longer there - on 2026-10-01 a `--pq` run reported a
    chain-building bug already fixed and "nobody negotiated
    X25519MLKEM768" from a module built before the hybrid existed, and
    concluded the fault was ours.
    """
    built = getattr(allcrypt, "__file__", None)
    if not built or not os.path.exists(built):
        return None
    root = os.path.normpath(os.path.join(HERE, ".."))
    newest, newest_path = 0.0, None
    candidates = [os.path.join(root, "Cargo.toml")]
    for directory, _, files in os.walk(os.path.join(root, "src")):
        candidates.extend(os.path.join(directory, name) for name in files
                          if name.endswith(".rs"))
    for path in candidates:
        try:
            stamp = os.path.getmtime(path)
        except OSError:
            continue
        if stamp > newest:
            newest, newest_path = stamp, path
    if newest <= os.path.getmtime(built):
        return None
    import datetime
    when = datetime.datetime.fromtimestamp(os.path.getmtime(built))
    return (f"{built} was built {when:%Y-%m-%d %H:%M}, and "
            f"{os.path.relpath(newest_path, root)} is newer.\n"
            f"Rebuild first:  python3 scripts/build_python.py\n"
            f"(or pass --allow-stale to measure the old build on purpose)")


# --------------------------------------------------------------- the matrix ---

ACCEPT = "accept"
REJECT = "reject"

#: Each row is (host, port, expectation, why) or
#: (host, port, expectation, why, expected_reason).
#:
#: "why" is not decoration. A row whose reason nobody can state is a row
#: that will be quietly deleted the first time it goes red.
#:
#: `expected_reason` is a substring the rejection's detail must contain,
#: and it exists because this script has twice reported a row as passing
#: while it tested nothing. `sha1-intermediate` was rejected for being
#: expired rather than for its hash; `dh-composite` was rejected for its
#: group size before the primality check it exists for ever ran. Both
#: printed a green [ ok ]. A row that states what it expects to be
#: refused *for* turns that from something a human has to notice into
#: something the script reports.
BADSSL = [
    # --- must work. If these fail, something ordinary is broken. -----------
    ("badssl.com", 443, ACCEPT,
     "the control: an ordinary valid certificate"),
    ("sha256.badssl.com", 443, ACCEPT,
     "SHA-256 signature, the normal case"),
    ("rsa2048.badssl.com", 443, ACCEPT,
     "a 2048 bit RSA key, which is our default floor"),
    ("ecc256.badssl.com", 443, ACCEPT,
     "an ECDSA P-256 certificate, so ECDHE_ECDSA and our ECDSA verify"),
    ("ecc384.badssl.com", 443, ACCEPT,
     "ECDSA P-384, the other curve we implement"),
    ("extended-validation.badssl.com", 443, ACCEPT,
     "EV certificates carry policy extensions we must not choke on. This "
     "endpoint's certificate expired in August 2022, which a real run "
     "settled - so the row runs with allow_expired, because what it is "
     "for is the policy extensions and a date is not that. Refusing it "
     "on the date would have been a green row testing nothing"),
    ("1000-sans.badssl.com", 443, ACCEPT,
     "1000 subjectAltNames: parser stress, and our name matching has to "
     "find the right one rather than giving up. Expired in October 2021, "
     "so it runs with allow_expired for the same reason as above"),
    # The two long names, as badssl.com's own nginx configuration spells
    # them (`domains/ui/` in chromium/badssl.com). This row used to carry a
    # name typed from memory whose first label was 105 characters - over
    # DNS's 63 - so Python's idna codec refused it before a packet was
    # sent and the row never tested our client at all.
    ("long-extended-subdomain-name-containing-many-letters-and-dashes"
     ".badssl.com", 443, ACCEPT,
     "a 63 character label, to catch a fixed buffer or an off-by-one"),
    ("longextendedsubdomainnamewithoutdashesinordertotestwordwrapping"
     ".badssl.com", 443, ACCEPT,
     "the same length with no dashes"),

    # --- must fail, and these are the rows that matter. -------------------
    ("expired.badssl.com", 443, REJECT,
     "expired: the validity window is checked against our clock"),
    ("wrong.host.badssl.com", 443, REJECT,
     "the certificate does not cover this name (RFC 6125)"),
    ("self-signed.badssl.com", 443, REJECT,
     "self-signed and NOT in the trust store - which is the distinction "
     "that matters, since a self-signed certificate that IS in the store "
     "must be accepted, and we had that backwards once"),
    ("untrusted-root.badssl.com", 443, REJECT,
     "a complete chain to a root nobody trusts"),
    ("incomplete-chain.badssl.com", 443, REJECT,
     "the intermediate is missing, so the chain does not reach a root. A "
     "client that fetches the missing certificate would accept this; we "
     "do not do that, and this pins it"),
    ("sha1-intermediate.badssl.com", 443, REJECT,
     "SHA-1 in the chain. NOTE: a real run rejected this for being "
     "EXPIRED rather than for the hash - badssl does not renew every "
     "endpoint, so several of these certificates have simply run out. The "
     "rejection is right and the reason is not the one this row is "
     "about, which is why the expected reason now says 'Expired' rather "
     "than pretending otherwise",
     "Expired"),
    ("superfish.badssl.com", 443, REJECT,
     "signed by the Superfish root, which shipped with a known private "
     "key. Also expired now, so that is what it is rejected for"),
    ("dsdtestprovider.badssl.com", 443, REJECT,
     "same, another shipped root, also expired"),
    ("edellroot.badssl.com", 443, REJECT,
     "same, another shipped root, also expired"),
    ("null.badssl.com", 443, REJECT,
     "a NULL cipher, which Selection::modern does not offer. NOTE the "
     "reason: this is refused by the SERVER, which had nothing in common "
     "with our hello, not by us examining anything. That is the right "
     "outcome and it says nothing about whether we can speak it - see the "
     "'reaching the old things' section, which is the half that does"),
    ("dh480.badssl.com", 443, REJECT,
     "a 480 bit DH group. Now refused on the group size, which is the "
     "right reason - it used to be refused because finite-field DHE was "
     "not implemented at all, the right outcome for the wrong reason",
     "480 bit Diffie-Hellman group"),
    ("dh1024.badssl.com", 443, REJECT,
     "a 1024 bit DH group: not broken on a laptop, but the size Logjam's "
     "precomputation argument was written about. Refused by the default "
     "floor of 2048; reachable by lowering min_dh_bits, which is the "
     "whole point of the knob",
     "1024 bit Diffie-Hellman group"),
    ("dh2048.badssl.com", 443, ACCEPT,
     "a 2048 bit DH group, which is the floor rather than a wall - this "
     "row is what says the DHE path works at all rather than that it "
     "refuses everything"),
    ("dh-small-subgroup.badssl.com", 443, ACCEPT,
     "WE ACCEPT THIS AND ARGUABLY SHOULD NOT. The group order has a small "
     "factor, which TLS 1.2 gives us no way to detect: the server sends p "
     "and g and never q. See docs/pitfalls.md section 3b - listed as an "
     "expected accept so it is a known gap rather than a surprise"),
    ("dh-composite.badssl.com", 443, REJECT,
     "a composite modulus, which makes the shared secret computable by "
     "whoever chose it. Only caught with check_dh_prime on, which this "
     "script turns on for this row - the default leaves it off because it "
     "costs more than the key exchange itself. The floor is lowered for "
     "this row too, and that is not a detail: the modulus is 2047 bits, "
     "so the default floor of 2048 refused it on SIZE before the "
     "primality check ran at all. Right outcome, wrong reason, green row",
     "composite"),
    ("rc4.badssl.com", 443, REJECT,
     "RC4 only. Refused by default because we do not offer it, so the "
     "rejection comes from the server having nothing in common with our "
     "hello. 'Reachable by naming the suite' is a separate claim and it "
     "is checked separately, below"),
    ("3des.badssl.com", 443, REJECT,
     "3DES only. Same shape as the row above: refused by default because "
     "we never offer it, and reachable through the legacy set - which is "
     "checked below rather than assumed here"),

    # --- known gaps, recorded as expectations so they cannot be forgotten --
    ("revoked.badssl.com", 443, ACCEPT,
     "WE ACCEPT THIS AND SHOULD NOT. Revocation (CRL and OCSP) is not "
     "implemented - see docs/pitfalls.md. Written as an expected accept "
     "so the day it starts being rejected is visible, rather than as a "
     "failure everyone learns to ignore"),
]

#: Version-specific endpoints, each speaking exactly one protocol version.
#: Reaching the old ones through the legacy context is the point of this
#: script.
VERSIONS = [
    ("tls-v1-0.badssl.com", 1010, "TLSv1"),
    ("tls-v1-1.badssl.com", 1011, "TLSv1.1"),
    ("tls-v1-2.badssl.com", 1012, "TLSv1.2"),
]

GENERAL = ["github.com", "www.google.com", "cloudflare.com", "example.com"]

#: Public servers known to negotiate X25519MLKEM768 (RFC 10024) with a
#: client that offers it. **The only independent check of this library's
#: hybrid key exchange there is**: OpenSSL here predates it, so every other
#: test of it is this library talking to itself. A row that comes back
#: with `group=X25519MLKEM768` means a server that is not ours read our
#: 1216 byte share, encapsulated to our ML-KEM key, and derived the same
#: secret we did - the Finished messages would not have matched otherwise.
PQ_SERVERS = ["pq.cloudflareresearch.com", "cloudflare.com", "www.google.com"]


# ------------------------------------------------------------------ driving ---

def connect(host, port=443, context=None, timeout=15, **options):
    context = context or allcrypt_ssl.create_default_context()
    for name, value in options.items():
        setattr(context, name, value)
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def detect_interception():
    """Is something minting a certificate per SNI?

    Ask for a name that cannot exist. If a certificate comes back covering
    it, whatever answered is generating certificates on demand from a CA
    the trust store already has - and every deliberately broken case below
    will arrive laundered into a working one.
    """
    bogus = "this-name-does-not-exist.badssl.com"
    context = allcrypt_ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = allcrypt_ssl.CERT_NONE
    try:
        with connect(bogus, context=context, timeout=10) as sock:
            leaf = allcrypt.Certificate(sock.getpeercertchain()[0])
            details = leaf.to_dict()
            names = [value for kind, value
                     in (details.get("subjectAltName") or []) if kind == "DNS"]
            covered = any(name == bogus or
                          (name.startswith("*.") and bogus.endswith(name[1:]))
                          for name in names)
            if covered:
                return (f"a certificate covering {bogus!r} was issued by "
                        f"{leaf.issuer}")
    except Exception:
        # Not reachable at all is not interception; it is just closed.
        return None
    return None


# A few rows need something switched on that the default leaves off. Kept
# as data next to the rows rather than as branches in the loop, so that a
# row which needs a non-default context says so where it is read.
ROW_CONTEXT = {
    # The primality check is the only thing that catches a composite
    # modulus, and it is off by default because it costs more than the key
    # exchange. This row is what it exists for.
    #
    # `min_dh_bits` is lowered as well, and that is the whole point of the
    # row rather than a convenience: badssl's composite modulus is 2047
    # bits, so the default floor of 2048 refused it on size and the
    # primality check never ran. The row was green and tested nothing.
    "dh-composite.badssl.com": {"check_dh_prime": True, "min_dh_bits": 1024},

    # Both of these expired years ago. They exist to prove we parse an EV
    # certificate's policy extensions and a certificate with a thousand
    # subjectAltNames - neither of which is a question about dates, so
    # the dates are forgiven and the shapes are tested.
    "extended-validation.badssl.com": {"allow_expired": True},
    "1000-sans.badssl.com": {"allow_expired": True},
}


def permissive_context():
    """A context that will accept anything this library can do.

    "I have to talk to this box and I do not care what it offers" is a
    real position and the reason this project exists, so it is worth
    having in one place rather than assembled by hand each time.

    Every floor is at its lowest and every suite is on the table,
    including the NULL ciphers that even `legacy` leaves out. What is
    *not* relaxed is certificate verification: this is about reaching a
    server, not about believing it. `--insecure` turns that off too, and
    keeping the two separate is the point - a connection over RC4 to a
    certificate you checked is a different thing from a connection to
    nobody in particular.
    """
    context = allcrypt_ssl.create_legacy_context()
    context.set_ciphers("all")          # every implemented suite, NULL included
    context.min_dh_bits = 0             # no floor at all
    context.min_rsa_bits = 512
    context.allow_sha1 = True
    context.allow_md5 = True
    context.allow_expired = True
    return context


def context_for(host):
    tweaks = ROW_CONTEXT.get(host)
    if not tweaks:
        return None
    context = allcrypt_ssl.create_default_context()
    for name, value in tweaks.items():
        setattr(context, name, value)
    return context


def outcome(host, port, **options):
    """`(ACCEPT|REJECT, detail)` for one endpoint."""
    try:
        with connect(host, port, **options) as sock:
            name, _version, bits = sock.cipher()
            # `named_group()` rather than reaching into
            # `sock._connection._client`, which is what this did until the
            # accessor existed. A private path in a script is a private
            # path that breaks on an unrelated refactor, silently, in the
            # one tool nobody runs in CI.
            return ACCEPT, (f"{sock.version()} {name} {bits}-bit"
                            f" group={sock.named_group()}")
    except allcrypt_ssl.SSLCertVerificationError as reason:
        return REJECT, f"certificate: {reason}"
    except allcrypt_ssl.SSLError as reason:
        return REJECT, f"tls: {reason}"
    except OSError as reason:
        return None, f"unreachable: {reason}"
    except Exception as reason:                  # noqa: BLE001
        return None, f"{type(reason).__name__}: {reason}"


#: Alerts that mean "I will not do that", sent before the peer has read
#: anything we would call our own work. A row that ends this way says we
#: did not offer something the server wanted, or it does not speak what we
#: asked for - **nothing at all about whether our code is right.**
#:
#: These are spelled as the client spells them: `AlertDescription::name`.
DECLINED_BY_PEER = (
    "handshake_failure",        # nothing in common
    "insufficient_security",    # in common, but below its floor
    "protocol_version",         # not this version
    "unrecognized_name",        # not a name it serves
    "no_application_protocol",
)

#: Alerts that mean the peer **read our bytes and did not like them**.
#:
#: This is the distinction that matters, and it is the one that took a
#: session to see. `decode_error` was what CryptoPro's servers sent when
#: our ClientKeyExchange named the canonical parameter set instead of
#: echoing theirs: the suite was agreed, the server was willing, and it
#: could not parse what we produced. Lumped in with `handshake_failure`
#: that reads as "this server does not offer it" and the bug hides behind
#: an endpoint that looks merely unavailable.
OUR_FAULT_ALERTS = (
    "decode_error",
    "decrypt_error",
    "illegal_parameter",
    "bad_record_mac",
    "unexpected_message",
    "bad_certificate",
    "unsupported_certificate",
    "record_overflow",
)


def peer_alert(detail):
    """The alert name the peer sent, or `None` if it did not send one.

    **The level is part of the name.** `tls::Alert::name` formats
    `"{level} {description}"`, so the text is `fatal handshake_failure`
    and never `handshake_failure` alone. A pattern that did not allow for
    the level matched nothing at all, which is the first thing this
    function got wrong.
    """
    match = re.search(r"The peer sent a (?:fatal|warning) (\w+)\.",
                      detail or "")
    return match.group(1) if match else None


def peer_declined(detail):
    """Did the far end simply refuse, before our code was on trial?"""
    return peer_alert(detail) in DECLINED_BY_PEER


#: Things this library refuses that are the **peer** breaking a rule, not
#: a gap here.
#:
#: These are raised locally, with an alert sent *by us*, so they arrive
#: looking exactly like our own failures - and they are the opposite. The
#: messages say so in words, which is what this matches on: each names the
#: clause it is enforcing, and that phrase is asserted by a test in the
#: module that raises it, so this is pinned rather than guessed.
#:
#: `7.4.1.3` is the one that came up. `tlsgost-256.cryptopro.ru` answers a
#: hello offering only suites it cannot serve with a ServerHello naming
#: `0x0031` - a suite nobody offered, nobody here implements, and which is
#: `TLS_DH_RSA_WITH_AES_128_CBC_SHA` to IANA - instead of sending
#: `handshake_failure`. Refusing that is correct. Filing it as a bug of
#: ours is not, and it is what this script did.
PEER_BROKE_THE_RULE = (
    "RFC 5246 7.4.1.3",          # chose a suite that was not offered
    "which this client did not offer",
    "outside the",               # chose a version outside what we offered
)


def peer_broke_the_rule(detail):
    """Is this a refusal of ours *about* the peer's behaviour?"""
    return any(phrase in (detail or "") for phrase in PEER_BROKE_THE_RULE)


def peer_hung_up(detail):
    """Did the far end close the connection instead of saying anything?

    **This was being counted as a bug of ours and is not one.** A hello
    offering exactly one suite the server does not have is refused one of
    two ways: `handshake_failure`, which is the polite form, or a TCP close
    with no alert at all, which is what `www.cryptopro.ru` does. Both mean
    "not that suite here"; only the first was recognised, so five rows
    against a working server were reported under "rows that are about us".

    What it cannot distinguish - said out loud rather than papered over -
    is a close provoked by something malformed of ours. In this matrix
    that reading is available but unlikely: each connection offers one
    suite, so a server that closes has not agreed to anything yet, and the
    four suites it *does* have completed against the same server in the
    same run. A close in the middle of a handshake that had got further
    would deserve a different answer, which is why this is its own mark
    rather than being folded into `declined`.
    """
    return "closed the connection" in (detail or "")


def blames_us(detail):
    """Did the peer read what we sent and reject it - or did we fail here?

    Three things end up here and all three are ours: an alert from the
    list above, an error raised on this side during the handshake, and a
    verification failure. What is *not* ours is a declined suite, a socket
    that never opened, and a refusal of ours that is about the peer
    breaking a rule - and those three are what this has to exclude for the
    answer to mean anything.
    """
    if detail is None:
        return False
    # **Before the alert check**, because we send the alert here: a
    # ServerHello naming a suite nobody offered is refused with
    # `illegal_parameter` *by us*, and that arrives with no "The peer sent
    # a" in it at all.
    if peer_broke_the_rule(detail):
        return False
    if peer_alert(detail) in OUR_FAULT_ALERTS:
        return True
    if peer_alert(detail) is not None:
        return False
    # No alert at all: either we could not reach it, or something on this
    # side gave up.
    return not detail.startswith("unreachable:")


def report(label, expected, got, detail, width=64, expected_reason=None):
    """One row of output, and the two checks that make a row mean something.

    A row passes when the outcome matches *and*, if it said so, the
    rejection is for the reason it is about. Both halves have been learned
    the hard way:

      * the detail used to be discarded on a FAIL, so four rows came back
        from a real run saying "expected accept, got reject" and nothing
        else - exactly when the reason was the only thing worth printing;
      * and a row can be refused for the right outcome and the wrong
        reason, which prints green. `sha1-intermediate` was rejected for
        being expired rather than for its hash; `dh-composite` for its
        group size before the primality check it exists for ever ran.

    A skip prints its reason too. "could not reach it" with the reason
    thrown away is the first bug again, one layer down, and it hid why
    the long-subdomain row was unreachable for two runs.
    """
    if got is None:
        mark, note = "skip", "could not reach it"
    elif got == expected:
        mark, note = " ok ", ""
    else:
        mark, note = "FAIL", f"expected {expected}, got {got}"

    # A rejection has two possible authors and they mean opposite things.
    #
    # "we refused it" is this library applying a policy - which is what a
    # refusal row is usually claiming to test. "the peer refused us" is
    # the server finding nothing in common with our hello and hanging up,
    # which happens *before* our policy has an opinion about anything.
    # Both print as a rejection and only one of them is us.
    #
    # The rc4 and 3des rows are the case: they read "refused by default"
    # and what they observed was a server with no suite in common. Marking
    # it is the difference between a row that tests our policy and a row
    # that tests badssl's configuration.
    #
    # **This used to match on the word "fatal" alone, which is every
    # fatal alert there is.** `handshake_failure` means the server found
    # nothing in common and this row's note is right; `decode_error`
    # means the server read what we sent and could not parse it, and for
    # that the note is exactly backwards - it prints "the SERVER refused
    # us, so our own policy never applied here" about a bug of ours.
    # `decode_error` is the alert three CryptoPro endpoints sent when our
    # ClientKeyExchange named the canonical parameter set, so this is not
    # a hypothetical shape of wrongness.
    #
    # Narrowed to the alerts that actually mean "I decline", listed in
    # `DECLINED_BY_PEER`.
    #
    # The text this matches against is `Alert::name`, which formats the
    # level and the description together - `fatal handshake_failure`, never
    # the description alone. `tls::mod`'s `test_alerts` asserts that
    # format, and `pytests/test_tls_handshake.py` feeds this function an
    # alert taken from a handshake that really failed, rather than a string
    # written to match: the pattern here is only as good as the input it
    # was checked against.
    if mark == " ok " and got == REJECT and peer_declined(detail):
        mark = "peer"

    # The outcome is right but for something other than what this row is
    # about, which is a row that tests nothing while looking green.
    if (mark == " ok " and expected_reason and got == REJECT
            and expected_reason.lower() not in (detail or "").lower()):
        mark = "WRONG"
        note = f"rejected, but not for {expected_reason!r}"

    print(f"  [{mark:^5.5}] {label:<{width}.{width}} {note or detail}")
    if mark in ("FAIL", "WRONG", "skip") and detail:
        print(f"         reason: {detail}")
    if mark == "peer":
        print(f"         the SERVER refused us, so our own policy never "
              f"applied here.")
        print(f"         What this row shows is that we did not offer it. "
              f"Whether we")
        print(f"         can speak it is the 'reaching the old things' "
              f"section below.")
    # A peer refusal still satisfies a REJECT expectation - it is not a
    # failure, only a different author - so it counts as a pass.
    return " ok " if mark == "peer" else mark


# --------------------------------------------------------------------- main ---

def describe_trust_store():
    """What we are verifying against, before anything is verified.

    This exists because a run came back with two rows failing on "No
    trusted root issued CN=DigiCert Global Root CA" and nothing in the
    output said whether that root was in the store, missing from it, or
    dropped on the way in. The information was all available through the
    binding and none of it was printed.

    Which store that is depends on where this is run, and the answer is
    not always the one somebody expects - running under WSL reads the
    Linux distribution's CA bundle, not the Windows store, so a root
    Windows has is not necessarily a root this sees.
    """
    store = allcrypt.TrustStore.system()
    subjects = store.subjects()
    print(f"  trust store: {store.source}")
    print(f"  {len(subjects)} roots loaded, {store.skipped} skipped as unparseable")
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR"):
        print(f"  SSL_CERT_FILE/SSL_CERT_DIR is set, so that is what was read "
              f"rather than")
        print(f"  the distribution's default bundle.")
    if store.skipped:
        print("  NOTE: a skipped root is one our X.509 parser refused. That "
              "is worth")
        print("        chasing - see docs/pitfalls.md on over-strict parsing.")
        # The count alone was the whole diagnostic for a while, and it
        # cannot distinguish "that entry is malformed" from "we are too
        # strict" - which have opposite remedies. The reasons say which.
        for reason in store.skipped_reasons:
            print(f"        - {reason}")
        if store.skipped > len(store.skipped_reasons):
            print(f"        ... and {store.skipped - len(store.skipped_reasons)} "
                  f"more, reasons not kept")
        print("        To look at one: split the bundle and match the digest,")
        print("          awk '/BEGIN CERT/{n++} {print > (\"cert\" n \".pem\")}' \\")
        print(f"            {store.source}")
        print("          for f in cert*.pem; do openssl x509 -in $f -outform der "
              "| sha256sum | cut -c1-16; done")
    return subjects


def explain_missing_root(detail, subjects):
    """When a row fails for a missing issuer, say whether we have it.

    "No trusted root issued CN=X" has two very different causes and the
    message does not distinguish them: the chain is incomplete, or the
    root is genuinely not in this machine's store. One line of output
    settles it.
    """
    match = re.search(r"No trusted root issued ([^']+?)\.'", detail or "")
    if not match:
        return
    wanted = match.group(1)
    common_name = wanted.split(",")[0]
    present = [s for s in subjects if common_name in s]
    if present:
        print(f"         the store DOES contain {common_name} - so the chain "
              f"did not reach it")
        return
    print(f"         the store does NOT contain {common_name}, so this is a "
          f"missing")
    print(f"         root rather than anything about the certificate.")
    # The remedy differs by where the store came from, and guessing wrong
    # sends somebody to the wrong place entirely - which is how "it fails
    # on Windows" became a Windows theory when the run was under WSL.
    if sys.platform == "win32":
        print(f"         Windows fetches roots from Windows Update on demand, "
              f"so a CA")
        print(f"         nothing here has needed yet is simply not cached.")
    else:
        print(f"         On Linux (including WSL) that is the ca-certificates "
              f"package:")
        print(f"         `sudo apt install --reinstall ca-certificates` or "
              f"`update-ca-certificates`.")


def run_badssl(args):
    print("badssl.com\n" + "-" * 78)
    subjects = describe_trust_store()
    print()

    intercepted = detect_interception()
    if intercepted:
        print("\n  REFUSING TO REPORT CERTIFICATE RESULTS.\n")
        print(f"  Something is intercepting TLS here: {intercepted}.\n")
        print("  It mints a certificate per SNI from a CA already in the")
        print("  trust store, so every deliberately broken case below would")
        print("  arrive as a valid one and every rejection test would pass")
        print("  for the wrong reason - or worse, fail while the code is")
        print("  correct. Run this from a machine with a direct connection.\n")
        return 2

    failures = 0
    for row in BADSSL:
        host, port, expected, why = row[:4]
        expected_reason = row[4] if len(row) > 4 else None
        got, detail = outcome(host, port, context=context_for(host))
        mark = report(f"{host}:{port}", expected, got, detail,
                      expected_reason=expected_reason)
        if mark in ("FAIL", "WRONG"):
            failures += 1
            explain_missing_root(detail, subjects)
            print(f"         why this row exists: {why}")

    print("\nversions (the point of the whole exercise)\n" + "-" * 78)
    for host, port, version in VERSIONS:
        context = allcrypt_ssl.create_legacy_context()
        got, detail = outcome(host, port, context=context)
        mark = report(f"{host}:{port} -> {version}", ACCEPT, got, detail)
        if mark in ("FAIL", "WRONG"):
            failures += 1

    print("\nthe same failures, with the policy relaxed\n" + "-" * 78)
    print("  A rejection has to be a decision we can reverse, not a wall.")
    # sha1-intermediate is deliberately absent: that endpoint's certificate
    # is expired as well, so allow_sha1 alone cannot reach it and the row
    # would fail for a reason that has nothing to do with SHA-1. Turning
    # verification off entirely is the honest demonstration.
    for host, reason in [("expired.badssl.com", "verify off"),
                         ("self-signed.badssl.com", "verify off"),
                         ("untrusted-root.badssl.com", "verify off")]:
        context = allcrypt_ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = allcrypt_ssl.CERT_NONE
        got, detail = outcome(host, 443, context=context)
        if report(f"{host} with {reason}", ACCEPT, got, detail) != " ok ":
            failures += 1

    # ------------------------------------------------------------------
    print("\nreaching the old things, which is the entire point\n" + "-" * 78)
    print("  Refusing by default is half the claim. These rows are the")
    print("  other half, and without them the README's thesis is untested.")
    #
    # The rows above this section prove we *refuse* RC4, 3DES, the NULL
    # ciphers and the small groups. They do not prove the refusal is
    # reversible - and worse, they are satisfied by a handshake_failure
    # the *server* sent, because we offered modern suites and it had
    # nothing in common. That is the right outcome and it says nothing
    # about whether we can speak RC4 at all.
    #
    # Every row here must ACCEPT. A failure means this library does not do
    # the one thing it exists for.
    for host, port, reason, configure in [
        # The legacy set and the by-name path are different mechanisms and
        # both are claimed in the documentation, so both are checked.
        ("rc4.badssl.com", 443, "the legacy suite set",
         lambda c: c.set_ciphers("legacy")),
        ("rc4.badssl.com", 443, "RC4 by name",
         lambda c: c.set_ciphers("TLS_RSA_WITH_RC4_128_SHA,"
                                 "TLS_RSA_WITH_RC4_128_MD5,"
                                 "TLS_ECDHE_RSA_WITH_RC4_128_SHA")),
        ("3des.badssl.com", 443, "the legacy suite set",
         lambda c: c.set_ciphers("legacy")),
        ("3des.badssl.com", 443, "3DES by name",
         lambda c: c.set_ciphers("TLS_RSA_WITH_3DES_EDE_CBC_SHA,"
                                 "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")),
        # The NULL ciphers are `Insecure`, so even the legacy set excludes
        # them - naming one is the only way in, which is the whole design.
        ("null.badssl.com", 443, "a NULL cipher by name",
         lambda c: c.set_ciphers("TLS_RSA_WITH_NULL_SHA256,"
                                 "TLS_RSA_WITH_NULL_SHA,"
                                 "TLS_RSA_WITH_NULL_MD5")),
        # 480, not 512: the endpoint's group is exactly 480 bits, and a
        # floor of 512 would refuse it for being one notch too small -
        # which is how a relaxation row ends up testing the refusal it was
        # written to reverse.
        ("dh480.badssl.com", 443, "min_dh_bits=480",
         lambda c: setattr(c, "min_dh_bits", 480)),
        ("dh1024.badssl.com", 443, "min_dh_bits=1024",
         lambda c: setattr(c, "min_dh_bits", 1024)),
    ]:
        # Verification stays ON for these. What is being relaxed is the
        # cipher policy, and turning the certificate checks off as well
        # would hide a row that only works because nothing is checked.
        context = allcrypt_ssl.create_legacy_context()
        configure(context)
        got, detail = outcome(host, port, context=context)
        if report(f"{host} with {reason}", ACCEPT, got, detail) != " ok ":
            failures += 1

    # The verdict, which this script did not have.
    #
    # It printed forty rows, two of them red in the middle, and then
    # stopped - so a run that failed looked like a run that passed unless
    # somebody scrolled back and noticed. The exit code was set correctly
    # and nothing said so on screen, which is the same discarded-signal
    # mistake as the FAIL rows that threw away their reason.
    print("\n" + "=" * 78)
    if failures:
        print(f"  {failures} row{'s' if failures != 1 else ''} did not do what "
              f"it should. Search above for [FAIL] and [WRONG].")
    else:
        print("  Every row did what it should.")
    print("=" * 78)
    return 1 if failures else 0


def run_permissive(args):
    """Every endpoint, with everything allowed. `--permissive`.

    The ordinary matrix is mostly about what we refuse, which is the
    right default and is not what this library is *for*. This mode asks
    the other question: with every floor at its lowest and every suite on
    the table, what can we actually reach?

    Certificate verification stays on unless `--insecure` is given, so a
    row that connects here connects to a server whose certificate checked
    out - over RC4, or a 480 bit group, or no encryption at all.
    """
    print("everything allowed: what can this library actually reach?")
    print("-" * 78)
    describe_trust_store()
    print()
    print("  Every suite (including NULL), no group floor, SHA-1 and MD5")
    print("  accepted, expiry forgiven. Certificate verification is still")
    print("  ON unless --insecure was given.")
    print()

    # Every endpoint the script knows, de-duplicated with its port kept.
    endpoints = {}
    for host, port, *_ in BADSSL:
        endpoints.setdefault(host, port)
    for host, port, _version in VERSIONS:
        endpoints.setdefault(host, port)

    reached, refused = 0, 0
    for host, port in endpoints.items():
        context = permissive_context()
        if args.insecure:
            context.check_hostname = False
            context.verify_mode = allcrypt_ssl.CERT_NONE
        got, detail = outcome(host, port, context=context)
        if got == ACCEPT:
            reached += 1
            print(f"  [reach] {host}:{port:<5} {detail}")
        else:
            refused += 1
            print(f"  [ no  ] {host}:{port:<5} {detail}")

    print("\n" + "=" * 78)
    print(f"  reached {reached} of {reached + refused}. The ones that did not "
          f"are worth reading:")
    print(f"  a refusal here is either something we have not implemented or a "
          f"server")
    print(f"  that is genuinely gone, and the reason on each line says which.")
    print("=" * 78)
    unreachable_here()
    return 0


def unreachable_here():
    """Suites this library offers that nothing in the matrix can exercise.

    Computed rather than listed, so it cannot go stale. The point is the
    same one the "reaching the old things" section makes: a suite that is
    never reached by any row has been tested against our own reading of a
    specification and against nothing else, and that is worth saying out
    loud rather than leaving as a gap nobody counts.

    Right now this is the GOST suites. badssl has no GOST endpoint and
    this machine's OpenSSL cannot speak one, so the only way to exercise
    them against somebody else is a real server:

        python3 scripts/check_live.py --host <a GOST server> --permissive
    """
    import allcrypt

    offered = set(allcrypt.tls_suite_names("all"))
    # Nothing in the matrix is a GOST server, so every GOST suite we
    # offer is in this set by construction - but it is derived from the
    # registry rather than typed, so a suite that becomes reachable
    # leaves the list without anyone editing it.
    gost = sorted(name for name in offered if "GOSTR" in name)
    if not gost:
        return
    print()
    print("  not exercised by anything above:")
    for name in gost:
        print(f"    {name}")
    print("  badssl has no GOST endpoint and this OpenSSL cannot speak one,")
    print("  so these are checked against the documents' own worked examples")
    print("  (RFC 9189 appendix A, RFC 9367 appendix A) and against")
    print("  tests/test_gost_handshake.rs - never against a live peer.")
    print()
    print("  Public GOST TLS endpoints to point --host at:")
    for host, note in GOST_ENDPOINTS:
        print(f"    {host:<34} {note}")
    print("  None of them is contacted unless you ask - see --gost.")


# Public GOST TLS endpoints, for `--gost`.
#
# **Nothing here confirms that these are up, or that they are what they
# claim to be.** They are published test endpoints rather than anything
# this project controls, they are outside the country most of this
# library's users are in, and a name that resolves is not a guarantee.
# The reason to list them at all is the one in `unreachable_here`: a
# suite exercised only against our own reading of a specification has
# been checked against nobody, and a name to try is the difference
# between "point --host at a real GOST server" and actually doing it.
#
# They are in this script and **not in any test**. Every test here is
# offline by construction and `pytests/conftest.py` raises on any
# connection to anything but loopback; this file is a hand-run
# development tool for exactly the checks that cannot be.
GOST_ENDPOINTS = [
    ("tlsgost-256.cryptopro.ru", "CryptoPro, 256 bit GOST TLS"),
    ("tlsgost-512.cryptopro.ru", "CryptoPro, 512 bit GOST TLS"),
    ("www.cryptopro.ru", "CryptoPro's own site, usually GOST-capable"),
    # `tlsgost-2012-256.cryptopro.ru` was here and stopped resolving.
    # Removed rather than left to print `no DNS` on every run: a row that
    # always says the same thing stops being read, and this one was
    # indistinguishable from a network problem. `tlsgost-256` serves the
    # 2012 suites anyway - its certificate's CN is
    # `id-GostR3410-2001-CryptoPro-XchA-ParamSet_256noauth` and its key
    # is a 2012 key.
]

#: Every GOST suite this library implements, each with what a row of the
#: matrix below can and cannot learn from it.
#:
#: **Why one suite per connection.** Offering all nine and letting the
#: server choose exercises whatever the server likes best and nothing
#: else. Three endpoints all chose `KUZNYECHIK_CTR_OMAC`, so for as long
#: as this section existed, Magma, the 28147 CNT-IMIT suites and the 2001
#: suite had never been spoken to anything but our own server - and our
#: own server is our own reading of the same document, which is to say
#: no check at all. Restricting the hello to one suite at a time is what
#: makes each row a statement about that suite.
#:
#: `version` is what the suite needs, because a row that cannot possibly
#: succeed should say so before it is tried rather than look like a
#: failure: the four MGM suites are **TLS 1.3 only** (RFC 9367 section
#: 4.2 - they are AEAD suites with a Streebog-256 PRF and no separate MAC
#: negotiation), so a TLS 1.2 GOST server will decline all four no matter
#: how right our implementation is.
#:
#: `needs` names what the *server* must have for the row to be reachable,
#: which is the other reason a row can be declined without saying
#: anything about us - the 2001 suite needs a 2001 certificate, and
#: CryptoPro's endpoints serve 2012 keys.
GOST_SUITES = [
    ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", "1.2",
     "RFC 9189: Kuznyechik-CTR, OMAC, KExp15 key transport", None),
    ("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", "1.2",
     "RFC 9189: Magma-CTR, OMAC - the 64 bit block cipher", None),
    ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", "1.2",
     "RFC 9189: GOST 28147-89 CNT with IMIT, 2012 keys", None),
    ("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT_LEGACY", "1.2",
     "the pre-RFC 9189 spelling of the same thing", None),
    ("TLS_GOSTR341001_WITH_28147_CNT_IMIT", "1.2",
     "the 2001 suite, TC 26's own", "a GOST R 34.10-2001 certificate"),
    ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", "1.3",
     "RFC 9367: Kuznyechik-MGM, long re-keying", None),
    ("TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", "1.3",
     "RFC 9367: Magma-MGM, long re-keying", None),
    ("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", "1.3",
     "RFC 9367: Kuznyechik-MGM, short re-keying", None),
    ("TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", "1.3",
     "RFC 9367: Magma-MGM, short re-keying", None),
]


def gost_suite_row(host, port, suite):
    """One connection offering exactly `suite`, and what it proved.

    Returns `(mark, detail, negotiated, certificate)` where `mark` is one
    of:

      ``ours``
        it worked, and the suite the server chose is the one we asked
        for. This is the only value that says our implementation of that
        suite interoperates with somebody else's.
      ``declined``
        the server refused before reading anything of ours. Says nothing
        about us - see `DECLINED_BY_PEER`.
      ``BUG``
        the server was willing and could not use what we sent, or we
        failed on this side. **This is the finding.**
      ``WRONG``
        it succeeded on a suite other than the one we restricted to,
        which means the restriction did not take and the row is measuring
        a different code path while printing green.
      ``skip``
        never got a connection.
    """
    context = allcrypt_ssl.create_legacy_context()
    # Verification off for the same reason as before: the question is
    # which suites the far end speaks, and a CA this trust store happens
    # not to carry would hide every answer behind one verification
    # failure. The chain is checked separately, by `gost_chain_row`.
    context.check_hostname = False
    context.verify_mode = allcrypt_ssl.CERT_NONE
    context.set_ciphers(suite)

    try:
        with connect(host, port, context=context, timeout=15) as sock:
            negotiated = sock.cipher()[0]
            certificate = sock.getpeercert()
            detail = f"{sock.version()} {negotiated}"
            if negotiated != suite:
                # **A green row that measured something else.** If the
                # restriction silently failed, every row below would
                # succeed on the server's favourite suite and the matrix
                # would report nine working implementations having
                # tested one.
                return "WRONG", f"asked for {suite}, got {negotiated}", \
                    negotiated, certificate
            return "ours", detail, negotiated, certificate
    except OSError as reason:
        if isinstance(reason, allcrypt_ssl.SSLError):
            detail = f"tls: {reason}"
        else:
            return "skip", f"unreachable: {reason}", None, None
    except Exception as reason:                  # noqa: BLE001
        detail = f"{type(reason).__name__}: {reason}"

    if peer_declined(detail):
        return "declined", detail, None, None
    if peer_hung_up(detail):
        return "hung up", detail, None, None
    # **A fourth outcome, because a refusal has two possible authors.**
    # The server answering a suite nobody offered is a protocol violation
    # by it, refused correctly here - so the row is neither a clean
    # decline nor a bug of ours, and calling it either loses the finding.
    # It is worth its own mark because it is a real thing about a real
    # server that somebody should know.
    if peer_broke_the_rule(detail):
        return "theirs", detail, None, None
    if blames_us(detail):
        return "BUG", detail, None, None
    return "skip", detail, None, None


def gost_chain_row(host, port):
    """The same server, with verification **on**.

    Every other row in this section turns verification off on purpose,
    which leaves the certificate path unexercised against any chain we
    did not issue ourselves. This row is the one that exercises it - and
    a failure here is expected rather than alarming, because the trust
    store on this machine is very unlikely to carry a Russian test CA.
    What it is for is the *reason*: "no trusted root" is a trust store
    that does not have it, and anything else is a verifier that cannot
    read a real GOST chain.
    """
    try:
        with connect(host, port, timeout=15) as sock:
            return "verified", f"{sock.version()} {sock.cipher()[0]}"
    except allcrypt_ssl.SSLCertVerificationError as reason:
        text = str(reason)
        if "trusted root" in text or "unknown_ca" in text:
            return "no root", text
        # A name mismatch is the verifier working. It is the usual answer
        # for a local `s_server` reached as `127.0.0.1` with a
        # `CN=localhost` certificate, and reporting it as a verifier
        # fault made every local run of this end in a spurious BUG row.
        if "does not cover" in text or "hostname" in text.lower():
            return "no name", text
        if "expired" in text or "not yet valid" in text:
            return "expired", text
        return "verifier", text
    except Exception as reason:                  # noqa: BLE001
        return "skip", f"{type(reason).__name__}: {reason}"


#: What each mark means in a few words, for the row and for the summary.
#:
#: The rows used to print the whole error, which for a refusal is four
#: lines of RFC citation repeated once per suite per host - thirty lines of
#: identical prose in one run, with the four rows that *worked* lost in the
#: middle of it. The detail still exists and is still printed, but only
#: where it is the finding: under the failures at the bottom.
SUITE_MARKS = {
    "ours": "spoke it",
    "declined": "no suite in common",
    "hung up": "closed the connection without an alert",
    "theirs": "answered with a suite nobody offered",
    "BUG": "failed, and it looks like ours",
    "WRONG": "negotiated a different suite than we restricted to",
    "skip": "no answer",
}


def short_reason(mark, detail):
    """One line for a row, rather than the whole error.

    A refusal's full text is the same paragraph every time and says
    nothing that the mark does not; a failure's full text is the only thing
    worth reading. So this summarises the first kind and passes the second
    through.
    """
    if mark == "theirs":
        match = re.search(r"chose unknown suite (0x[0-9a-f]{4})", detail or "")
        if match:
            return f"answered {match.group(1)}, which nobody offered"
        return SUITE_MARKS.get(mark, "")
    if mark in ("declined", "hung up"):
        return SUITE_MARKS[mark]
    # A real failure keeps its text: it is the diagnosis.
    text = (detail or "").strip()
    return text if len(text) <= 140 else text[:137] + "..."


def run_gost(args):
    """Try every GOST endpoint above, one suite at a time, and say what
    each row proved.

    A failure here is **not** a failure of this library until it has
    been read: an endpoint may be gone, may be blocked from where this
    runs, or may have been renamed. The three outcomes are printed
    apart for that reason - no DNS, no TCP, and a real TLS refusal are
    three different findings and only the last one is about us.

    ## Why this is a matrix and not one row per host

    It used to be one connection per host offering everything we have.
    All three endpoints chose `KUZNYECHIK_CTR_OMAC`, so three green rows
    exercised **one** of our nine GOST suites; the other eight had never
    been spoken to anything but our own server. That is not a small gap:
    Magma is a different block cipher, IMIT is a different MAC, the
    LEGACY spelling is a different key derivation, and the 2001 suite is
    a different signature algorithm and a different key encoding.

    So each suite gets its own connection with the hello restricted to
    it, and the row checks that the suite we got back is the one we
    asked for - because a restriction that silently failed would print
    nine green rows having measured one.
    """
    import socket
    print("\nGOST endpoints\n" + "-" * 78)
    print("  These are third-party servers. Nothing here can confirm they are")
    print("  up, and a failure below may be the network rather than the code.")
    print("  Each suite gets its own connection, so that a row is about that")
    print("  suite and not about whichever one the server prefers.")
    # Ask first, because a green row below means nothing if the answer
    # is yes - and `detect_interception` already exists for exactly this.
    intercepted = detect_interception()
    if intercepted:
        print(f"  Something is intercepting TLS here: {intercepted}.")
        print("  Every row below is that, not the server.")

    reached = 0
    #: suite name -> the hosts that spoke it, across every endpoint.
    proved = {suite: [] for suite, _, _, _ in GOST_SUITES}
    bugs = []
    #: suite name -> [(host, mark)] for every host that did not speak it.
    #: This is what makes "not verified" say *why* instead of guessing at
    #: it from the suite's own table entry, which is a statement about the
    #: suite rather than about what happened.
    refused = {}
    #: Rows where the *server* broke a rule. Kept apart from `bugs`
    #: because mixing them is how a real finding about somebody else's
    #: box gets read as a defect here, and then chased in the wrong file.
    violations = []

    # `--gost-host` replaces the public list rather than adding to it, so
    # that pointing this at a local gost-engine `s_server` is a run whose
    # every row is about that server. Mixing the two would produce a
    # summary where "spoken with" mixes an implementation we can inspect
    # with three we cannot.
    endpoints = GOST_ENDPOINTS
    if getattr(args, "gost_host", None):
        endpoints = [(name, "given on the command line")
                     for name in args.gost_host]

    for host, note in endpoints:
        port = 443
        if ":" in host:
            host, text = host.rsplit(":", 1)
            port = int(text)
        print(f"\n  {host}:{port}  ({note})")
        try:
            socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except OSError as problem:
            print(f"    no DNS ({problem.strerror or problem}) - "
                  f"nothing below was tried")
            continue

        described = False
        for suite, version, why, needs in GOST_SUITES:
            mark, detail, _negotiated, certificate = gost_suite_row(
                host, port, suite)
            # Trim the common prefix: nine rows all starting
            # `TLS_GOSTR341112_256_WITH_` is nine rows of noise.
            short = suite.replace("TLS_GOSTR341112_256_WITH_", "") \
                         .replace("TLS_GOSTR341001_WITH_", "2001/")
            if mark == "ours":
                print(f"    [{mark:^8.8}] {short:<28} {detail}")
            else:
                print(f"    [{mark:^8.8}] {short:<28} "
                      f"{short_reason(mark, detail)}")
                refused.setdefault(suite, []).append((host, mark))
            if mark == "ours":
                proved[suite].append(host)
                reached += 1
                # Print the peer's key parameters once per host, from the
                # first suite that got far enough to see a certificate.
                #
                # **This is the field that decides it.** `gost256-a`
                # is what the curve name says for both CryptoPro-A
                # (1.2.643.2.2.35.1) and CryptoPro-XchA
                # (1.2.643.2.2.36.0), which are the same parameters under
                # two OIDs - and a ClientKeyExchange that names the wrong
                # one is refused with `decode_error`. Printing the curve
                # and not the OID is what made that invisible.
                if not described and certificate:
                    print(f"      its key: {certificate['publicKeyType']}"
                          f"  parameter set "
                          f"{certificate.get('publicKeyParameterSet')}")
                    print(f"      its CN:  {certificate.get('commonName')!r}")
                    described = True
            elif mark == "declined":
                reason = f"TLS {version} suite" if version == "1.3" else ""
                if needs:
                    reason = f"needs {needs}"
                if reason:
                    print(f"               ({reason} - expected here)")
            elif mark == "theirs":
                violations.append((host, suite, detail))
                print(f"               (the SERVER broke a protocol rule "
                      f"here; refusing it is correct)")
            elif mark in ("BUG", "WRONG"):
                bugs.append((host, suite, mark, detail))
            del why

        mark, detail = gost_chain_row(host, port)
        # **Not a blind `detail[:90]`.** That cut the issuer's name in the
        # middle of a Cyrillic word, which is where the information is:
        # "No trusted root issued CN=Тестовый УЦ ООО \"КРИПТО" tells you
        # less than the mark does. The reason is what matters, and for
        # `no root` the reason is the whole of it.
        summary = {
            "verified": detail,
            "no root": "this trust store has no root for the issuer, "
                       "which is expected for a Russian test CA",
            "no name": "the certificate does not cover the name we asked for",
            "expired": "outside its validity window",
        }.get(mark, short_reason(mark, detail))
        print(f"    [{mark:^8.8}] {'certificate chain':<28} {summary}")
        if mark == "verifier":
            bugs.append((host, "certificate chain", "BUG", detail))

    # **What was not reached is the finding, not what was.** A matrix
    # that prints one working suite and eight declined ones has tested
    # one suite, and the previous version of this section reported that
    # as three green rows.
    # **One verdict, three groups, in the order somebody wants them.**
    #
    # This block replaced three that each answered a different question and
    # none of them the question asked. A suite could appear as `spoken` in
    # one list, as `UNTESTED` in another and under "rows that are about us"
    # in a third, and the reader was left to reconcile them - "I do not
    # understand which cipher suites are verified working, which are not
    # verified, and if there are any that still are not working" is what
    # came back, and it is a fair description of what it printed.
    #
    # The three groups are exactly those three questions. Every suite
    # appears in precisely one of them.
    working, unverified, failing = [], [], []
    for suite, version, why, needs in GOST_SUITES:
        short = suite.replace("TLS_GOSTR341112_256_WITH_", "") \
                     .replace("TLS_GOSTR341001_WITH_", "2001/")
        ours_failed = [(host, mark) for host, suite_name, mark, _detail in bugs
                       if suite_name == suite]
        if proved[suite]:
            working.append((short, proved[suite]))
        elif ours_failed:
            failing.append((short, ours_failed))
        else:
            # **Why this host refused, not why the suite might be
            # refusable.** The table's own `needs`/`version` is a property
            # of the suite; what happened is a property of the run, and
            # only the second distinguishes "nobody here serves a 2001
            # certificate" from "we cannot speak it".
            marks = refused.get(suite, [])
            kinds = sorted({mark for _host, mark in marks})
            constraint = needs or (
                "TLS 1.3 only, and no endpoint here speaks TLS 1.3 GOST"
                if version == "1.3" else None)
            unverified.append((short, constraint, kinds, why))

    print("\n  verdict\n  " + "-" * 74)

    print(f"\n    WORKING against a third party - {len(working)} of "
          f"{len(GOST_SUITES)}")
    if working:
        print("    Each of these completed a handshake our client drove, on a")
        print("    server that is not ours. That is the strongest statement")
        print("    this script can make.")
        for short, hosts in working:
            print(f"      {short:<28} {len(hosts)} server(s): "
                  f"{', '.join(hosts)}")
    else:
        print("      (none)")

    print(f"\n    NOT VERIFIED - {len(unverified)} of {len(GOST_SUITES)}")
    if unverified:
        print("    No endpoint here would speak these, so this run says")
        print("    **nothing either way** about them. Not a failure; an")
        print("    absence of evidence, and the reason is given per suite.")
        for short, constraint, kinds, why in unverified:
            print(f"      {short:<28} {why}")
            if constraint:
                print(f"      {'':<28} {constraint}")
            if kinds:
                print(f"      {'':<28} every server here: "
                      f"{', '.join(SUITE_MARKS.get(k, k) for k in kinds)}")
    else:
        print("      (none)")

    print(f"\n    FAILING, AND OURS TO FIX - {len(failing)} of "
          f"{len(GOST_SUITES)} suite(s)")
    # **Driven by `bugs`, not by `failing`.** A certificate-chain failure
    # is recorded against the pseudo-suite "certificate chain", which
    # matches none of the nine - so keying this section on the per-suite
    # list would print "(none)" while a verifier fault sat in `bugs`
    # unmentioned. The count above is per suite; the detail below is
    # everything.
    if bugs:
        for short, hosts in failing:
            print(f"      {short:<28} {', '.join(h for h, _m in hosts)}")
        print("    These are the rows to act on. Each one is a server that")
        print("    agreed to the suite and could not use what we sent, a")
        print("    chain we could not verify for a reason other than a")
        print("    missing root, or a failure on this side.")
        for host, suite, mark, detail in bugs:
            print(f"      {mark} {host} {suite}")
            print(f"        {detail}")
    else:
        print("      (none - nothing here failed on our side)")

    if violations:
        print(f"\n    The server broke a protocol rule on "
              f"{len(violations)} row(s), and refusing it was correct.")
        print("    Counted under NOT VERIFIED above, because a server that")
        print("    answers a hello it cannot satisfy with a ServerHello naming")
        print("    a suite nobody offered has told us nothing about the suite.")
        seen = set()
        for host, suite, detail in violations:
            key = (host, short_reason("theirs", detail))
            if key in seen:
                continue
            seen.add(key)
            print(f"      {host}: {short_reason('theirs', detail)}")

    # **A handshake that succeeded is not the finding.** If none of them
    # negotiated a GOST suite, either no endpoint offers one any more or
    # - far more likely, and the reason no test here uses the network -
    # something between here and them is terminating TLS and answering
    # with its own certificate. A run inside a corporate proxy, a CI
    # sandbox or an agent container measures the proxy and says nothing
    # at all about this library.
    #
    # It is worth an explicit line because the rows above look green
    # either way, which is the exact shape of a check that passes while
    # observing something else.
    if not reached:
        print()
        print("  *** No endpoint negotiated a GOST suite. ***")
        print("  A green row above therefore says nothing about this library:")
        print("  a TLS-terminating proxy between here and the server answers")
        print("  every one of them, with its own certificate and its own")
        print("  suites. Check the certificate issuer before reading anything")
        print("  into these rows, and run this from a network that reaches the")
        print("  servers directly.")


def run_pq(args):
    """Ask servers that do post-quantum key exchange what they negotiated.

    Not an accept/reject matrix: every row should connect, and what is
    being read is the group. `x25519` from all of them, with no
    interception reported above, means our hybrid share was ignored -
    which is a failure of ours, since these servers prefer the hybrid.
    """
    print("\nhybrid post-quantum key exchange (RFC 10024)\n" + "-" * 78)
    interception = detect_interception()
    if interception:
        print(f"  INTERCEPTED: {interception}.\n"
              f"  Whatever is in the way terminates TLS itself, so the group "
              f"below is\n  the one it negotiated with us, not the one the "
              f"named server would.")
    hybrid = 0
    for host in PQ_SERVERS:
        got, detail = outcome(host, 443)
        report(host, ACCEPT, got, detail)
        if "group=" not in (detail or ""):
            # The key exchange happens before the certificate is judged,
            # so a certificate refusal says nothing about the group. Ask
            # again without judging it - for the group only, and said so.
            # The first run of this mode reported "none negotiated" for
            # three servers whose certificates we had refused, which was
            # a statement about the chain builder, not the share.
            context = allcrypt_ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = allcrypt_ssl.CERT_NONE
            got, detail = outcome(host, 443, context=context)
            print(f"         without checking the certificate: {detail}")
        hybrid += "group=X25519MLKEM768" in (detail or "")
    print(f"\n  {hybrid} of {len(PQ_SERVERS)} negotiated X25519MLKEM768.")
    if hybrid == 0 and not interception:
        print("  None did, and nothing appears to be intercepting: that "
              "points at our share\n  or our group list, not at the "
              "servers.")
        return 1
    return 0


def run_general(args):
    print("\nordinary public servers\n" + "-" * 78)
    for host in GENERAL:
        got, detail = outcome(host, 443)
        report(host, ACCEPT, got, detail)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--general", action="store_true",
                        help="also try ordinary public servers")
    parser.add_argument("--host", help="one host, instead of the matrix")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--expect", choices=[ACCEPT, REJECT], default=ACCEPT)
    parser.add_argument("--legacy", action="store_true",
                        help="use create_legacy_context()")
    parser.add_argument("--permissive", action="store_true",
                        help="allow every bad cipher and every low floor, "
                             "and report what can actually be reached")
    parser.add_argument("--insecure", action="store_true",
                        help="with --permissive, also turn certificate "
                             "verification off")
    parser.add_argument("--pq", action="store_true",
                        help="ask public post-quantum servers which group "
                             "they negotiate - the only independent check of "
                             "the hybrid key exchange")
    parser.add_argument("--gost", action="store_true",
                        help="try the public GOST TLS endpoints, which are "
                             "third-party servers this project does not "
                             "control and cannot vouch for")
    parser.add_argument("--gost-host", action="append", metavar="HOST[:PORT]",
                        help="run the GOST suite matrix against this server "
                             "instead of the public endpoints. Takes a local "
                             "one: point it at gost-engine's own s_server "
                             "and the matrix becomes an offline differential "
                             "test against another implementation. Repeatable.")
    parser.add_argument("--allow-stale", action="store_true",
                        help="run even though the compiled module is older "
                             "than the Rust source")
    args = parser.parse_args()

    stale = stale_module()
    if stale and not args.allow_stale:
        print(f"STALE BUILD: {stale}", file=sys.stderr)
        return 2

    if args.host:
        context = (allcrypt_ssl.create_legacy_context() if args.legacy
                   else allcrypt_ssl.create_default_context())
        got, detail = outcome(args.host, args.port, context=context)
        mark = report(f"{args.host}:{args.port}", args.expect, got, detail,
                      width=len(args.host) + 8)
        return 1 if mark in ("FAIL", "WRONG") else 0

    if args.gost or args.gost_host:
        run_gost(args)
        return 0

    if args.permissive:
        return run_permissive(args)

    if args.pq:
        return run_pq(args)

    status = run_badssl(args)
    if args.general:
        run_general(args)
    return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception:                            # noqa: BLE001
        traceback.print_exc()
        sys.exit(3)
