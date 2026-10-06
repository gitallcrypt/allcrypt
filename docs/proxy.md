# `allcrypt-proxy`

A local HTTPS proxy for reaching equipment nobody is going to upgrade.

    cargo build --release
    ./target/release/allcrypt-proxy --legacy --port 8080

Then set the browser's **HTTPS proxy** to `127.0.0.1:8080` and import
the `ca.pem` it writes into `~/.allcrypt-proxy`.

---

## Why a proxy, and not something smaller

A current browser will not speak RC4, will not speak TLS 1.0, and will
not talk to a certificate that ran out in 2014. That is right for the
open web and wrong for the switch in the rack with one management
interface and no firmware left.

The browser cannot be fixed from underneath:

- **Chromium links BoringSSL statically.** `nm -D` on the binary shows
  zero TLS imports and `SSL_connect` as a local text symbol, so there is
  nothing for `LD_PRELOAD` to interpose on. That was checked, not
  assumed.
- **Firefox's NSS is a shared library**, so it is mechanically possible
  and impractical: roughly five hundred entry points, plus NSPR's
  layered file descriptors, PKCS#11 and the certificate database.

Command-line tools are a different story — curl, wget and Python all
call `libssl.so.3` through the PLT, and [shim.md](shim.md) is the
`LD_PRELOAD` shim that does exactly that. For a browser, a proxy is the
way through. So it is on Windows for everything, where there is no
`LD_PRELOAD` to use: see [windows.md](windows.md).

## What it shows the browser

This is the part worth understanding before running it.

A terminating proxy has to present *some* certificate, and the usual
thing is to sign one with its own CA. That works, and it quietly
destroys something: every server behind the proxy then looks equally
trustworthy, because the proxy vouches for all of them. The padlock
starts meaning "the proxy was satisfied" and the person at the keyboard
has no way to know it.

So this one **mirrors** instead. The certificate it presents is as
trustworthy as the one the server actually sent, and no more:

| The real server's certificate | What the browser is shown | What the browser does |
|---|---|---|
| chained to a root we trust | signed by the CA you installed | accepts |
| self-signed | self-signed, same name | the self-signed warning |
| from a CA we do not know | from a throwaway CA nobody knows | the unknown-issuer warning |
| expired | expired, to the second | the expiry warning |
| for the wrong host | for that same wrong host | the wrong-name warning |

The subject, the subject alternative names, the validity window and the
serial are **copied**. Extensions this library does not itself
understand are copied verbatim too, because a proxy that silently
dropped one would be deciding on the browser's behalf about something it
could not read.

The result is that the browser warns exactly when it would have warned
talking directly, and the decision stays where it belongs.

### What cannot be mirrored

**The key.** The proxy must hold the private key for what it presents,
and it does not have the server's. Two consequences, both worth knowing
in advance rather than discovering:

- **A fingerprint pin does not survive.** A client that remembers "this
  host has *this* certificate" sees a different one and says so. That is
  correct behaviour on its part.
- **"Accept permanently", on a self-signed server, pins the mirror.**
  Reaching the same box directly afterwards will prompt again, and
  reaching it through the proxy after the mirror's cache entry expires
  will prompt again too.

**The signature algorithm, when the key types differ.** A mirror of an
RSA certificate is signed with the proxy's EC key. What is copied is
what a client displays and judges; what is regenerated is what a client
verifies.

**subjectKeyIdentifier and authorityKeyIdentifier.** They name keys, and
these are different keys. Copying them would produce a certificate
naming a key it does not hold, so they are recomputed.

## What you are agreeing to

**Installing this proxy's CA certificate means anything holding its key
can impersonate any site to that browser** — not only the ones you meant
to reach through here.

That is not a caveat, it is the mechanism. So:

- Generate the CA on the machine that will use it, and keep `ca.key`
  there. It is written mode `0600`, at creation rather than by a `chmod`
  afterwards — a `chmod` leaves a window in which the key is world
  readable, and that window is the whole of the exposure.
- Point **one** browser at the proxy, not the system proxy settings.
- Remove the certificate from the store when you are finished.

The proxy listens on loopback and nothing else. A proxy reachable from
the network is one anybody on it can ask to impersonate a site to you,
with a CA your browser has been told to trust.

## Reaching the old things

The two halves are configured separately, and deliberately: the
browser's side is always modern, and only the upstream side goes back in
time. Sharing one set of options would mean loosening what the browser
sees in order to reach an old box, which is the mistake the whole design
exists to avoid.

    --legacy

is everything at once: legacy suites, a TLS 1.0 floor, SHA-1 and MD5
signatures accepted in the server's chain, 1024-bit RSA, 512-bit
Diffie-Hellman. **SSLv3 is not included** — its CBC padding is
unspecified, which is POODLE, and reaching it has to be asked for by
name:

    --min-version SSLv3 --ciphers all

The narrower options exist so that "I cannot reach it" rarely has to
become "I check nothing". In order of preference:

    --root box.pem        the box's own certificate. Not a relaxation at
                          all: authentication against a certificate you
                          chose, and a man in the middle still fails.
    --allow-sha1          one signature algorithm
    --min-rsa-bits 1024   one size
    --ciphers legacy      the old suites, current certificate rules

Note that there is **no "verify nothing"** switch. There does not need
to be: an unverifiable server is mirrored as an unverifiable server, the
browser asks, and you answer. That is the same decision, made by the
person it belongs to, with the reason on screen.

## Options

| | |
|---|---|
| `-p, --port N` | listen on `127.0.0.1:N` (default 8080) |
| `--ca-dir PATH` | where `ca.pem`, `ca.der` and `ca.key` live; created on first run (default `~/.allcrypt-proxy`) |
| `--legacy` | loosen the upstream side all at once |
| `--ciphers SET` | `modern`, `legacy`, `all`, or a comma separated list |
| `--min-version V` | `SSLv3`, `TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3` |
| `--max-version V` | |
| `--allow-sha1`, `--allow-md5` | accept these in the server's chain |
| `--min-rsa-bits N`, `--min-dh-bits N` | |
| `--root FILE` | extra roots to judge the server against |
| `--no-plain-http` | refuse a plain `http://` request instead of forwarding it |
| `--keylog FILE` | the upstream connection's secrets, for Wireshark |
| `-v, `-vv`, `--verbose` | more of the log; see below |
| `-q, --quiet` | failures only |

**Every option about the protocol is about the upstream side** — the
connection to the old thing. The browser's side is always modern:
current suites, TLS 1.2 to 1.3, and the mirrored certificate. There is
deliberately no knob for it, because loosening the half of the
connection that runs over `127.0.0.1` buys nothing and the browser is
not the thing that needs reaching.

The CA is made once and kept. Regenerating it on every start would mean
asking the browser to trust a new certificate each time, which trains
whoever is using it to say yes without reading.

### `--root` with the box's own certificate

`--root` is the narrowest way to reach a box that has its own
certificate, and it is not a relaxation: it says *this* certificate,
not "anything self-signed".

It also accepts the **server's own leaf**, not only a CA. Saving what a
box presents and handing it back is the most precise thing anybody can
do here, and it used to fail in a way that looked like the option being
ignored: chain building looks for an *issuer* for the leaf, and a
self-signed server certificate is not a CA — no `basicConstraints`, no
`keyCertSign` — so nothing could be built from it and the box still
mirrored as untrusted, with its own bytes sitting in the trust store.
An exact match of the leaf's bytes is now treated as a pin.

A pin replaces the question "who issued this" and nothing else. The
certificate must still be for the host being asked for and still be
inside its validity window, so pinning a certificate for another name
does not make it verify.

```
openssl s_client -connect box.example:443 -showcerts </dev/null \
  | openssl x509 -out box.pem
allcrypt-proxy --root box.pem
```

## What it prints

A failure is never silent. Without any flag there is one line per
connection and one per failure, saying which phase it failed in and
why:

```
18:41:02.114Z #1   CONNECT box.example:443
18:41:02.335Z #1   box.example:443 TLSv1.2 TLS_RSA_WITH_AES_128_CBC_SHA [self-signed]
18:41:06.902Z #1   box.example:443 closed after 4.6s
```

The number is the connection; a browser opens six at once and their
lines interleave. The clock is UTC to the millisecond, so a line can be
lined up with a packet capture.

`-v` adds the negotiation — what was offered at startup, what the
server chose, what its certificate said, why the chain did or did not
verify, and whether the mirror was built or reused. `-vv` adds the
bytes in both directions.

**A refusal is also told to the far end.** Every failure inside the TLS
client queues the fatal alert that says which thing was wrong; the
proxy used to return on the error and drop the socket, so the alert
went out of scope unsent and the server saw a ServerHello followed by
FIN and nothing else. The alert is now flushed before the socket
closes, in both directions and mid-connection as well as during the
handshake.

`--keylog FILE` (or `$SSLKEYLOGFILE`) writes the **upstream**
connection's secrets in NSS key log format, which is what Wireshark
wants to decrypt a capture of the far side. Anyone who can read that
file can read those connections.

## How it is tested

`pytests/test_proxy.py` runs the **real binary** as a subprocess,
between a real OpenSSL client and a real OpenSSL origin server on
loopback. A `Proxy` object built in-process would be testing a wiring
nobody uses.

The origin's certificate comes from `cryptography`, not from this
library's builder: something we did not write has to be at the far end,
or the test is our own record layer talking to itself with a proxy in
the middle.

What the tests cover, beyond a page coming back:

- the mirrored certificate's subject, serial, SANs and dates equal the
  origin's, and its key does not;
- each of the three verdicts produces a *different* issuer, asserted as
  a comparison so that two behaving alike cannot pass;
- an expired origin mirrors as expired, and a wrong-name one as
  wrong-name, and in both cases a client trusting the CA still refuses;
- origins on TLS 1.0 and 1.1, on RSA key transport, on CBC suites, and
  with a 1024-bit key are all *reached* — a row that is merely refused
  proves nothing about reachability;
- the verdict in the `--verbose` log is about the host that was asked
  for.

That last one exists because removing the hostname from the judgement
left all twenty-four other tests passing: the mirror copies the origin's
names, so the *client* catches a wrong-name certificate regardless of
what the proxy concluded. An invisible check is one that can stop
working without anyone noticing, so the verdict is now observed
directly.

The mirroring itself is in `src/proxy.rs`, which is pure — certificate
in, certificate out, no sockets — and has its own tests in Rust. The
socket plumbing is in `src/main.rs` and nowhere else.

## GOST

All five GOST cipher suites are offered upstream by default, which is
most of why this program exists:

| | |
|---|---|
| `0xC100` | `TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC` |
| `0xC101` | `TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC` |
| `0xC102` | `TLS_GOSTR341112_256_WITH_28147_CNT_IMIT` |
| `0xFF85` | the same suite at the code point it had before IANA assigned one |
| `0x0081` | `TLS_GOSTR341001_WITH_28147_CNT_IMIT`, the 2001 generation |

The last two are what a box installed before 2022 and before 2012
respectively will speak, and OpenSSL's GOST engine calls them
`LEGACY-GOST2012-GOST8912-GOST8912` and `GOST2001-GOST89-GOST89`.

`-v` names which generation the server's certificate is on, because
that is the question a failed GOST handshake usually comes down to: a
2001 key and a 2012 key are the same point on the same curve under
different OIDs, and which one a box has decides which suites it can
use.

```
18:41:02.335Z #1     [0] subject CN=box / issuer CN=box / ... / GOST R 34.10-2001 gost256-a / signed with GOST R 34.10-2001 with GOST R 34.11-94
18:41:02.335Z #1   box.example:443 TLSv1.2 TLS_GOSTR341001_WITH_28147_CNT_IMIT [self-signed]
```

If a box names a parameter set this library does not carry - an
organisation's own S-box, a digest OID from a standard nobody
vendored - that is what `allcrypt.register_oid` is for; see
`docs/python.md`. The proxy has no flag for it yet.

## Limitations

- **Plain HTTP is forwarded, not proxied properly.** A browser is
  configured with one proxy for every protocol, so refusing
  `GET http://…` breaks that half of the browser for as long as the
  proxy is set — and the box this exists for usually has a plain port
  whose redirect to `https://` is how you get to it. So the request
  line is rewritten to origin form and the bytes are carried across,
  with no caching, no rewriting and no pooling. `--no-plain-http`
  refuses it instead.
- **No client certificates**, in either direction.
- **No session resumption on the browser's side**, so every connection
  through the proxy is a full handshake. The 1.3 server has no tickets
  yet. (TLS 1.3 itself *is* there on both sides now; a browser that
  offers it gets it.)
- **Nothing is fetched to check revocation.** Nothing in this library
  opens a socket for a CRL or an OCSP responder; a stapled response
  would be the way in, and is not wired up.
- **A failure after the tunnel opens has nowhere good to be reported.**
  Once the proxy has answered `200`, there is no HTTP layer left to put
  an error in. The browser is sent a fatal TLS alert so that it says
  the connection failed rather than hanging until it times out, but the
  alert cannot carry the reason — the log is where that is. A failure
  *before* the tunnel opens — an unreachable host — is a proper `502`
  with the reason in it.
