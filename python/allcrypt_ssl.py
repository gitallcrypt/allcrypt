"""An ``ssl``-shaped interface, so existing Python code can reach servers the
standard library will not talk to.

The backend is allcrypt's own TLS stack — our record layer, key schedule,
certificate verification and state machine, on our own AES, SHA-1, HMAC,
RSA and bignum, client and server, SSLv3 to TLS 1.3. The standard
library is still here as a fallback for what this stack does not do - a
server whose key this library cannot read, or a server asked to go below
TLS 1.2 - and which one is in use is reported rather than guessed at.

The first version's job was to pin down the *seam*: the exact set of
attributes and methods that ``http.client``, ``urllib3``/``requests`` and
``asyncio`` actually touch. Those tests were written against the standard
library backend and are meant to keep passing now that it has swapped. If
they need editing, the seam moved and we should know why.

Usage is deliberately identical to the standard library::

    import allcrypt_ssl, http.client

    ctx = allcrypt_ssl.SSLContext(allcrypt_ssl.PROTOCOL_TLS_CLIENT)
    conn = http.client.HTTPSConnection("example.com", context=ctx)

And the reason it exists::

    ctx = allcrypt_ssl.SSLContext()
    ctx.set_ciphers("legacy")          # RC4, 3DES, the rest
    ctx.minimum_version = allcrypt_ssl.TLSVersion.TLSv1_2
    ctx.min_rsa_bits = 1024            # a key nobody would issue today

See docs/pitfalls.md, "The ``ssl`` drop-in", for where it deliberately
differs from the standard library.
"""

from __future__ import annotations

import os as _os
import socket as _socket
import ssl as _ssl
import threading as _threading
import time as _time

try:
    import allcrypt as _allcrypt
except ImportError:                            # pragma: no cover
    _allcrypt = None

# --------------------------------------------------------------- key log ---

#: One lock for every key log file this process writes. Appends from several
#: connections at once would otherwise interleave mid-line, and a torn line
#: makes Wireshark skip the session silently rather than complain.
_keylog_lock = _threading.Lock()


def _write_keylog(path, line):
    """Append one NSS key log line, for Wireshark.

    Never raises. A debugging aid that takes down the connection it was
    meant to help debug is worse than one that quietly does not work - if
    the path is unwritable the TLS session is still perfectly good, and the
    missing file is obvious the moment anyone looks for it.
    """
    if not path or not line:
        return
    try:
        with _keylog_lock:
            # Created 0600: every line is a session secret. ``open(path,
            # "a")`` created it 0644 under the usual umask, readable by
            # every local account. An existing file keeps its mode.
            descriptor = _os.open(
                path, _os.O_WRONLY | _os.O_APPEND | _os.O_CREAT, 0o600)
            with _os.fdopen(descriptor, "a", encoding="ascii") as handle:
                handle.write(line + "\n")
    except OSError:
        pass


def _default_keylog_path():
    """``SSLKEYLOGFILE``, the variable OpenSSL, NSS, curl and every browser
    already honour.

    Reading it means a capture works without changing any code, which is
    the entire point of the convention. It also means **setting that
    variable writes this process's session keys to disk**, which is why
    the standard library gates it the same way and why it is worth saying
    out loud rather than treating as a hidden feature.
    """
    return _os.environ.get("SSLKEYLOGFILE") or None


# Re-exported so callers can use this module as a drop-in namespace rather
# than importing both. Anything not listed here is available via `_ssl`.
PROTOCOL_TLS_CLIENT = _ssl.PROTOCOL_TLS_CLIENT
PROTOCOL_TLS_SERVER = _ssl.PROTOCOL_TLS_SERVER
CERT_NONE = _ssl.CERT_NONE
CERT_OPTIONAL = _ssl.CERT_OPTIONAL
CERT_REQUIRED = _ssl.CERT_REQUIRED
SSLError = _ssl.SSLError
SSLWantReadError = _ssl.SSLWantReadError
SSLWantWriteError = _ssl.SSLWantWriteError
SSLZeroReturnError = _ssl.SSLZeroReturnError
SSLEOFError = _ssl.SSLEOFError
SSLCertVerificationError = _ssl.SSLCertVerificationError
MemoryBIO = _ssl.MemoryBIO
TLSVersion = _ssl.TLSVersion
Purpose = _ssl.Purpose

# ------------------------------------------------ the rest of the namespace ---
#
# `import allcrypt_ssl as ssl` should work, which means every name the
# standard library exports has to be here - `urllib3` alone reads a
# dozen of them at import time, and a missing one is an `AttributeError`
# in somebody else's module.
#
# These are re-exported rather than redefined wherever the value is the
# same number in both worlds: an alert description and an error code are
# facts about TLS, not about an implementation. Where our answer
# genuinely differs, it is written out below with the reason, because
# **a constant that reports somebody else's capability is a lie a caller
# will act on**.
#
# The flags are the delicate part. `OP_*` and `VERIFY_*` are not data:
# a caller sets them expecting behaviour, so exposing one that is
# absorbed and ignored is worse than not exposing it at all - it turns
# "I asked for no session tickets" into "I got session tickets". What is
# honoured, and what is refused outright, is at `SSLContext.options` and
# `SSLContext.verify_flags`.

# The enum types themselves, which callers use for annotations and
# `isinstance`.
AlertDescription = _ssl.AlertDescription
Options = _ssl.Options
SSLErrorNumber = _ssl.SSLErrorNumber
VerifyFlags = _ssl.VerifyFlags
VerifyMode = _ssl.VerifyMode

#: `ssl.CertificateError` has been an alias of `SSLCertVerificationError`
#: since 3.7, and `asyncio.sslproto` catches it by name.
CertificateError = _ssl.SSLCertVerificationError
SSLSyscallError = _ssl.SSLSyscallError
DefaultVerifyPaths = _ssl.DefaultVerifyPaths

PEM_HEADER = _ssl.PEM_HEADER
PEM_FOOTER = _ssl.PEM_FOOTER

# Alert descriptions, error numbers, verify flags and options: every
# `ALERT_DESCRIPTION_*`, `SSL_ERROR_*`, `VERIFY_*` and `OP_*` name the
# standard library has. Taken from the enums rather than listed one at a
# time, so a name added by a future Python appears here too instead of
# becoming an `AttributeError` nobody expected.
for _enum in (AlertDescription, SSLErrorNumber, VerifyFlags, Options, VerifyMode):
    for _member in _enum:
        globals().setdefault(_member.name, _member)
del _enum, _member

# The protocol constants. `PROTOCOL_TLS` and `PROTOCOL_SSLv23` are the
# same deprecated value and both are still read by `ftplib`.
PROTOCOL_TLS = _ssl.PROTOCOL_TLS
PROTOCOL_SSLv23 = _ssl.PROTOCOL_SSLv23
PROTOCOL_TLSv1 = _ssl.PROTOCOL_TLSv1
PROTOCOL_TLSv1_1 = _ssl.PROTOCOL_TLSv1_1
PROTOCOL_TLSv1_2 = _ssl.PROTOCOL_TLSv1_2

# Iterating an `IntFlag` yields only its canonical members, so the
# composite and zero-valued names have to be named. `OP_ALL` is a bag of
# other people's bug workarounds and `VERIFY_DEFAULT` is zero; both are
# set by code that never looks at them again.
OP_ALL = _ssl.OP_ALL
OP_NO_SSLv2 = _ssl.OP_NO_SSLv2
OP_SINGLE_DH_USE = _ssl.OP_SINGLE_DH_USE
OP_SINGLE_ECDH_USE = _ssl.OP_SINGLE_ECDH_USE
VERIFY_DEFAULT = _ssl.VERIFY_DEFAULT
VERIFY_CRL_CHECK_CHAIN = _ssl.VERIFY_CRL_CHECK_CHAIN

# Incidental: the standard library's `ssl` leaks its own imports into its
# namespace, and code in the wild does reach for `ssl.socket` and
# `ssl.SOCK_STREAM`. Re-exported so that substituting this module is
# total rather than nearly total; they are not part of the API and are
# not in `__all__`.
socket = _ssl.socket
socket_error = _ssl.socket_error
create_connection = _ssl.create_connection
SOCK_STREAM = _ssl.SOCK_STREAM
SOL_SOCKET = _ssl.SOL_SOCKET
SO_TYPE = _ssl.SO_TYPE
base64 = _ssl.base64
errno = _ssl.errno
os = _ssl.os
sys = _ssl.sys
warnings = _ssl.warnings
namedtuple = _ssl.namedtuple

# ---- where our answer differs from the standard library's --------------
#
# These are the ones that would be lies if they were re-exported.

#: **True here and False in the standard library.** This Python's OpenSSL
#: is built without SSLv3, so `ssl` cannot speak it at all; our record
#: layer can, and reaching a server that speaks nothing else is a reason
#: this project exists. It still takes `minimum_version = TLSVersion.SSLv3`
#: to get there - see `_OUR_LOWEST`.
HAS_SSLv3 = True

#: SSLv2 is not implemented and will not be. It is not "old", it is
#: broken in a way that has no safe use: the handshake is unauthenticated,
#: so an attacker downgrades the cipher list and the client cannot tell.
HAS_SSLv2 = False

#: These are all genuinely ours, which is more than the standard
#: library's `True` means for the first two: a modern OpenSSL reports
#: `HAS_TLSv1` and then refuses the connection at its security level.
HAS_TLSv1 = True
HAS_TLSv1_1 = True
HAS_TLSv1_2 = True
HAS_TLSv1_3 = True

HAS_ALPN = True
HAS_ECDH = True
HAS_SNI = True

#: NPN was replaced by ALPN and removed from OpenSSL. Nothing here
#: implements it and nothing should.
HAS_NPN = False

#: **False, and the standard library's answer for its own build is not
#: ours to copy.** Python 3.13 added `HAS_PSK` with the external-PSK
#: callbacks (`SSLContext.set_psk_client_callback` and the server form).
#: This stack resumes sessions with PSKs it issued itself, but it has no
#: PSK-only suites and no way to supply an external key, so a caller
#: that tests this flag before installing a callback must be told no.
HAS_PSK = False

#: `hostname_checks_common_name = False` is implemented - see that
#: property - so this is True. urllib3 reads it together with
#: `OPENSSL_VERSION` below and decides for itself whether to trust it.
HAS_NEVER_CHECK_COMMON_NAME = True

#: **Not an OpenSSL version, and deliberately not shaped like one.**
#:
#: urllib3 checks `OPENSSL_VERSION.startswith("OpenSSL ")` before relying
#: on OpenSSL-specific behaviour, so telling the truth here is also what
#: makes it stop assuming things about us. Reporting a plausible OpenSSL
#: version would earn a set of assumptions this stack does not satisfy.
OPENSSL_VERSION = "allcrypt {}".format(
    getattr(_allcrypt, "__version__", "unknown") if _allcrypt is not None
    else "not built")
OPENSSL_VERSION_INFO = (0, 0, 0, 0, 0)
#: `requests` formats this with `:x`, so it has to be an integer. Zero,
#: because any other number would be read as an OpenSSL release.
OPENSSL_VERSION_NUMBER = 0

#: What `get_channel_binding` can produce. `tls-unique` is RFC 5929 and
#: is TLS 1.2 and below only; `tls-exporter` is RFC 9266 and is what
#: TLS 1.3 uses instead. The standard library on this Python offers only
#: the first.
CHANNEL_BINDING_TYPES = ["tls-unique", "tls-exporter"]

__all__ = [
    "SSLContext", "MemoryBIO", "create_default_context",
    "create_legacy_context",
    "PROTOCOL_TLS_CLIENT", "PROTOCOL_TLS_SERVER", "PROTOCOL_TLS",
    "PROTOCOL_SSLv23", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_TLSv1_2",
    "CERT_NONE", "CERT_OPTIONAL", "CERT_REQUIRED",
    "SSLError", "SSLWantReadError", "SSLWantWriteError",
    "SSLZeroReturnError", "SSLEOFError", "SSLSyscallError",
    "SSLCertVerificationError", "CertificateError",
    "TLSVersion", "Purpose", "DefaultVerifyPaths",
    "AlertDescription", "Options", "SSLErrorNumber", "VerifyFlags", "VerifyMode",
    "SSLSession", "SSLSocket", "SSLObject", "SSLServerSocket",
    "HAS_ALPN", "HAS_ECDH", "HAS_NEVER_CHECK_COMMON_NAME", "HAS_NPN", "HAS_PSK",
    "HAS_SNI", "HAS_SSLv2", "HAS_SSLv3", "HAS_TLSv1", "HAS_TLSv1_1",
    "HAS_TLSv1_2", "HAS_TLSv1_3",
    "OPENSSL_VERSION", "OPENSSL_VERSION_INFO", "OPENSSL_VERSION_NUMBER",
    "PEM_HEADER", "PEM_FOOTER", "CHANNEL_BINDING_TYPES",
    "DER_cert_to_PEM_cert", "PEM_cert_to_DER_cert", "cert_time_to_seconds",
    "get_default_verify_paths", "get_server_certificate", "match_hostname",
    "RAND_add", "RAND_bytes", "RAND_status",
    "BACKEND",
] + [_member.name for _enum in (AlertDescription, SSLErrorNumber, VerifyFlags,
                                Options, VerifyMode)
     for _member in _enum]

#: Which implementation is behind this module. Tests assert on it so the
#: swap from the standard library is visible rather than silent.
BACKEND = "allcrypt" if _allcrypt is not None else "stdlib"

#: The versions our own stack speaks. Anything outside this falls back to
#: the standard library rather than failing, because a shim that refuses to
#: connect is worse than one that is honest about what it is using.
#:
#: TLS 1.0 and 1.1 are in here and that is the point of the project: a
#: modern OpenSSL will not speak them at all, or only at a security level
#: the distribution has usually turned off, so the *fallback* is precisely
#: what cannot reach the servers this library exists to reach. Our record
#: layer has had the chained IV (1.0) and the explicit IV (1.1) and the
#: MD5+SHA-1 PRF since it was written.
#:
#: SSLv3 is in here too, and it is the one version this stack speaks that
#: the standard library cannot - this Python's OpenSSL is built without it
#: (``ssl.HAS_SSLv3`` is False), so there is no fallback for it at all.
#: Reaching it takes ``minimum_version = TLSVersion.SSLv3`` explicitly:
#: ``_OUR_LOWEST`` below is TLS 1.0, so a context that says nothing never
#: gets there. POODLE is a property of the version rather than of a suite,
#: and the only fix is not to speak it - so speaking it is a decision
#: somebody makes, not a floor that slides.
_OUR_VERSIONS = (TLSVersion.SSLv3, TLSVersion.TLSv1, TLSVersion.TLSv1_1,
                 TLSVersion.TLSv1_2, TLSVersion.TLSv1_3)

#: The bounds a context falls back to when it has not said. **Not** the
#: ends of `_OUR_VERSIONS`: the floor is TLS 1.0 deliberately, so that
#: "minimum_version unset" never means SSLv3.
_OUR_LOWEST = TLSVersion.TLSv1
_OUR_HIGHEST = TLSVersion.TLSv1_3


def _version_name(version):
    return {
        TLSVersion.SSLv3: "SSLv3",
        TLSVersion.TLSv1: "TLSv1",
        TLSVersion.TLSv1_1: "TLSv1.1",
        TLSVersion.TLSv1_2: "TLSv1.2",
        TLSVersion.TLSv1_3: "TLSv1.3",
    }.get(version, "TLSv1.2")


def _password_bytes(password):
    """A `load_cert_chain` password in the three shapes the standard
    library accepts.

    A callable is the interesting one: it is how a passphrase gets
    prompted for at load time rather than sitting in a variable, and a
    shim that took only `bytes` would quietly force the caller to hold
    it.
    """
    if password is None:
        return None
    if callable(password):
        password = password()
    if isinstance(password, str):
        # The standard library encodes with the filesystem encoding
        # here; UTF-8 is that on every platform this runs on, and being
        # explicit beats inheriting a locale.
        return password.encode("utf-8")
    if isinstance(password, (bytes, bytearray)):
        return bytes(password)
    raise TypeError("password should be a string, bytes, or a callable "
                    "returning one")


# -------------------------------------------------------------- the session ---

class SSLSession:
    """What a connection learned that a later one can reuse.

    **Not an** ``ssl.SSLSession``. That type cannot be constructed from
    Python at all - it is handed out by OpenSSL and has no public
    constructor - so a shim that wanted to return one could not. This is
    the same shape from the caller's side: take it off a finished
    connection, hand it back as ``session=`` on the next
    :meth:`SSLContext.wrap_socket`, and ask ``session_reused``
    afterwards.

    **It holds key material.** Each ticket inside is enough to resume the
    connection it came from, and anyone who can rewrite one chooses the
    key for a connection that will then look resumed. Keep it where only
    the owner can read, and do not write it to disk without thinking
    about that.

    Tickets are **offered once**. Resumption takes one out of the object
    rather than copying it, because a PSK offered twice lets a passive
    observer link the two connections, which is exactly what a ticket's
    obfuscated age exists to prevent. So one session can be handed to
    several connections and they will not tread on each other; when it
    runs out they simply do a full handshake.
    """

    __slots__ = ("_tickets", "_hostname")

    def __init__(self, tickets=(), hostname=None):
        self._tickets = list(tickets)
        self._hostname = hostname

    @property
    def has_ticket(self):
        """Whether anything is left to offer.

        Named after ``ssl.SSLSession.has_ticket``, and false is not a
        failure: a TLS 1.2 connection stores nothing here, and a 1.3 one
        whose tickets have all been spent looks the same.
        """
        return bool(self._tickets)

    @property
    def ticket_lifetime_hint(self):
        return 0

    def _add(self, tickets, hostname):
        self._tickets.extend(tickets)
        if hostname is not None:
            self._hostname = hostname

    def _take(self):
        """One ticket, removed. See the note above about offering once."""
        if not self._tickets:
            return []
        return [self._tickets.pop(0)]

    def __len__(self):
        return len(self._tickets)

    def __repr__(self):
        return "<allcrypt_ssl.SSLSession %d ticket(s) for %r>" % (
            len(self._tickets), self._hostname)


# --------------------------------------------------------------- the object ---

class _Connection:
    """The shared half of :class:`SSLObject` and :class:`SSLSocket`.

    Holds an ``allcrypt.TlsClient`` and translates between its sans-I/O
    shape and the exceptions Python's ``ssl`` raises.
    """

    #: Which stack this connection is. A standard library ``SSLSocket`` or
    #: ``SSLObject`` has no such attribute, so ``getattr(sock,
    #: "backend_in_use", "stdlib")`` tells you what you are holding even
    #: when the context that made it is out of reach - which it is inside
    #: ``http.client`` and ``urllib3``.
    backend_in_use = "allcrypt"

    def __init__(self, context, server_hostname, session=None):
        # **The standard library requires a hostname only when something
        # is going to check it**, and this used to require one always.
        # `check_hostname = False` with `CERT_NONE` is how you talk to a
        # box by address, or to something whose certificate you are not
        # judging, and `ssl` allows `server_hostname=None` there - it
        # simply sends no SNI. Refusing it made the shim stricter than
        # the thing it is standing in for, for no benefit: there is
        # nothing to check the name against, so demanding one only makes
        # the caller invent it.
        #
        # The error below is CPython's own wording, because a caller
        # who hits it will search for that string.
        if not server_hostname:
            if context.check_hostname:
                raise ValueError("check_hostname requires server_hostname")
            server_hostname = None
        self._context = context
        self._hostname = server_hostname
        # The session is offered by taking a ticket out of it, so the
        # same object can be handed to several connections without any
        # of them offering the same PSK twice.
        self._session = session if session is not None else SSLSession(
            hostname=server_hostname)
        offered = self._session._take() if session is not None else []
        # The Rust side takes an empty string to mean "send no SNI". It
        # is `""` rather than an `Option` because every other string
        # argument on that constructor is a plain `&str`, and one
        # nullable one among them is a thing to get wrong at a call
        # site; `ClientConnection::new` refuses it unless
        # `verify_hostname` is off, so it cannot be a silent skip.
        self._client = context._new_client(server_hostname or "", offered)
        self._closed = False
        self._keylog_written = False

    # -- key log -------------------------------------------------------

    def key_log_line(self):
        """This session's NSS key log line, or ``None`` before the master
        secret exists.

        Not part of the ``ssl`` API - the standard library only offers the
        file. It is here because reading the line is often what you
        actually want in a test or a debugger, and because a file is a
        clumsy way to get one string.
        """
        return self._client.key_log_line

    def _maybe_log_keys(self):
        """Write the key log line once, as soon as there is one.

        As soon as, rather than on a completed handshake, and that is
        deliberate: a handshake that *fails* after the key exchange is
        exactly when somebody reaches for Wireshark, and waiting for
        success would withhold the keys precisely then.
        """
        if self._keylog_written:
            return
        line = self._client.key_log_line
        if not line:
            return
        self._keylog_written = True
        _write_keylog(self._context.keylog_filename, line)

    # -- what the caller sees ------------------------------------------

    def version(self):
        return self._client.version()

    def cipher(self):
        """``(name, protocol, bits)``, as ``ssl`` returns it.

        The standard library's middle element is the protocol version. Ours
        knows the suite's strength label as well, which is available
        through :meth:`cipher_strength` rather than by changing this shape -
        code that unpacks three values must keep working.
        """
        chosen = self._client.cipher()
        if chosen is None:
            return None
        name, _strength, bits = chosen
        return (name, self._client.version(), bits)

    def cipher_strength(self):
        """``"modern"``, ``"weak"``, ``"broken"`` or ``"insecure"``.

        Not part of the ``ssl`` API. It is here because this library keeps
        suites others have deleted, and a caller that enabled one should be
        able to ask what it got.
        """
        chosen = self._client.cipher()
        return chosen[1] if chosen else None

    def named_group(self):
        """The key exchange group that was negotiated, or ``None``.

        Not part of the ``ssl`` API, which has never exposed this. It is
        here because ``scripts/check_live.py`` needed it and was reaching
        into ``_connection._client`` to get it - a private path that would
        break silently, for a value a caller has an ordinary reason to
        want: which group a peer actually chose is the only way to tell an
        X448 connection from an X25519 one after the fact.

        ``None`` for a key exchange that has no group at all - RSA key
        transport, and the GOST suites, which is why
        ``check_live.py --gost`` prints ``group=None`` and is right to.
        """
        return self._client.named_group

    def getpeercert(self, binary_form=False):
        chain = self._client.peer_certificates
        if not chain:
            return None
        if binary_form:
            return chain[0]
        return _allcrypt.Certificate(chain[0]).to_dict()

    def getpeercertchain(self, binary_form=True):
        """The whole chain, which ``ssl`` does not expose. Useful when a
        connection failed and somebody has to work out why."""
        chain = self._client.peer_certificates
        if binary_form:
            return list(chain)
        return [_allcrypt.Certificate(der).to_dict() for der in chain]

    def selected_alpn_protocol(self):
        return self._client.selected_alpn_protocol()

    def selected_npn_protocol(self):
        # NPN is the abandoned predecessor of ALPN and was removed from
        # CPython's ssl module. `None` is the right answer, not a gap.
        return None

    def shared_ciphers(self):
        return None

    def compression(self):
        return None                   # Compression is CRIME; never on

    @property
    def server_hostname(self):
        return self._hostname

    @property
    def context(self):
        return self._context

    @property
    def session(self):
        """This connection's session, for handing to a later one.

        Collected as the tickets arrive, which at TLS 1.3 is *after* the
        handshake: they come under the application keys, so a session
        read before the first ``recv`` is usually empty. That is not a
        failure and not worth waiting for - read it when the connection
        is done with.
        """
        self._collect_tickets()
        return self._session

    @property
    def session_reused(self):
        """Whether this handshake resumed rather than doing the full one.

        A resumed TLS 1.3 connection sends **no certificate** - the
        pre-shared key authenticates the server, because only the peer
        that ran the original handshake could derive it - so an empty
        :meth:`getpeercert` on one is normal rather than a failure, and
        this is what to ask first.
        """
        return self._client.resumed

    def get_channel_binding(self, cb_type="tls-unique"):
        """Channel binding material for this connection.

        What SCRAM and the other SASL mechanisms mix into their
        exchange so that an authentication cannot be relayed onto a
        different TLS connection - the reason LDAP, PostgreSQL and IMAP
        clients ask for it.

        `"tls-unique"` (RFC 5929) is the first Finished message's
        verify_data and exists at **TLS 1.2 and below**; `"tls-exporter"`
        (RFC 9266) replaces it at **1.3**, because 1.3's key schedule
        made the old value no longer unique to the connection.

        Returns `None` when the negotiated version does not define the
        binding asked for, which is what the standard library does and
        is the only safe answer: a binding that is merely *a* value
        would authenticate the wrong connection, and nothing downstream
        would report it.

        Raises `ValueError` for a type this library does not implement,
        as the standard library does.
        """
        if cb_type not in CHANNEL_BINDING_TYPES:
            raise ValueError("{!r} channel binding type not implemented"
                             .format(cb_type))
        return self._client.channel_binding(cb_type)

    def _collect_tickets(self):
        """Move any new tickets into the session.

        Taken from the client rather than copied, because a ticket is
        offered once; see :class:`SSLSession`.

        **`OP_NO_TICKET` is honoured here too**, and taking them before
        dropping them is deliberate: a TLS 1.3 server sends tickets
        whether or not anyone wants them, and leaving them inside the
        connection would mean a later `.session` picked them up. Taken
        and discarded, the session stays empty and nothing this context
        holds can be replayed as a PSK.
        """
        tickets = self._client.take_tickets()
        if tickets and not self._context._no_tickets:
            self._session._add(tickets, self._hostname)

    def _translate(self, action):
        """Run something on the client, turning its errors into ``ssl``'s."""
        try:
            return action()
        except Exception as reason:                     # CryptoError
            text = str(reason)
            self._closed = True
            # A verification failure has its own exception type in `ssl`,
            # and code catches it specifically - urllib3 and requests both
            # do. Mapping it to a plain SSLError would make those paths
            # silently take the wrong branch.
            lowered = text.lower()
            if ("unknown_ca" in lowered or "bad_certificate" in lowered
                    or "certificate_expired" in lowered
                    or "does not cover" in lowered
                    or "expired" in lowered
                    or "trusted root" in lowered):
                raise SSLCertVerificationError(
                    f"certificate verify failed: {text}") from None
            raise SSLError(text) from None


class SSLObject(_Connection):
    """The memory BIO interface, which is what ``asyncio`` drives.

    ``do_handshake``, ``read`` and ``write`` raise
    :class:`ssl.SSLWantReadError` when they need more bytes, exactly as the
    standard library's does. That is the whole contract.
    """

    def __init__(self, context, incoming, outgoing, server_hostname,
                 session=None):
        super().__init__(context, server_hostname, session)
        self._incoming = incoming
        self._outgoing = outgoing

    def _pump(self):
        """Move bytes between the BIOs and the connection."""
        pending = self._incoming.read()
        if pending:
            self._client.push_incoming(pending)
        self._translate(self._client.process)
        self._maybe_log_keys()
        # **Every pump, not just the handshake.** A TLS 1.3
        # NewSessionTicket arrives under the application keys, so it can
        # turn up on any read - and a shim that only looked once, at the
        # end of the handshake, would collect nothing and resumption
        # would silently never happen.
        self._collect_tickets()
        out = self._client.take_outgoing()
        if out:
            self._outgoing.write(out)

    def do_handshake(self):
        self._pump()
        if not self._client.established:
            if self._client.state in ("Closed", "Failed"):
                raise SSLError("the handshake failed")
            raise SSLWantReadError("need more data for the handshake")

    def read(self, length=1024, buffer=None):
        self._pump()
        data = self._client.take_incoming()
        if not data:
            if self._client.state == "Closed":
                # A clean close is end of stream, not an error - the same
                # thing ssl signals with SSLZeroReturnError.
                raise SSLZeroReturnError("TLS/SSL connection has been closed")
            raise SSLWantReadError("no application data yet")
        data = data[:length]
        if buffer is not None:
            buffer[:len(data)] = data
            return len(data)
        return data

    def write(self, data):
        self._translate(lambda: self._client.write(bytes(data)))
        out = self._client.take_outgoing()
        if out:
            self._outgoing.write(out)
        return len(data)

    def pending(self):
        return 0

    def unwrap(self):
        self._translate(self._client.close)
        out = self._client.take_outgoing()
        if out:
            self._outgoing.write(out)


# --------------------------------------------------------------- the socket ---

class SSLSocket:
    """A wrapped socket, which is what ``http.client`` and ``urllib3`` use.

    Not a subclass of :class:`socket.socket`, because it does not need to
    be: what the ecosystem touches is ``recv``, ``recv_into``, ``sendall``,
    ``makefile``, ``close``, ``settimeout`` and a handful of accessors.
    Everything else falls through to the socket underneath.
    """

    #: See :attr:`_Connection.backend_in_use`. Declared again here rather
    #: than inherited, because this class composes a connection instead of
    #: subclassing one, and the whole value of the attribute is that asking
    #: any wrapped socket answers truthfully.
    backend_in_use = "allcrypt"

    def __init__(self, context, sock, server_hostname,
                 do_handshake_on_connect=True, suppress_ragged_eofs=True,
                 session=None):
        self._sock = sock
        self._connection = SSLObject.__new__(SSLObject)
        _Connection.__init__(self._connection, context, server_hostname, session)
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._plaintext = bytearray()
        self._eof = False
        self._handshake_done = False
        self._do_handshake_on_connect = do_handshake_on_connect
        # **Only handshake here if the socket is already connected.**
        # ``ssl`` wraps an unconnected socket perfectly happily and waits
        # for :meth:`connect`; this used to handshake immediately and
        # died with ``BrokenPipeError`` on a socket that had nowhere to
        # send. The standard library decides the same way, by asking the
        # socket for a peer.
        if do_handshake_on_connect and self._is_connected():
            self.do_handshake()

    def _is_connected(self):
        try:
            self._sock.getpeername()
        except OSError:
            return False
        return True

    # -- connecting ------------------------------------------------------

    # `__getattr__` forwards everything it does not define to the raw
    # socket, which for `connect` would have connected the TCP socket and
    # never started a handshake - so the caller would have read the
    # server's ClientHello-less plaintext and seen nonsense. These two
    # are defined for that reason, not for completeness.

    def connect(self, address):
        """Connect the underlying socket, then handshake."""
        self._connect(address, False)

    def connect_ex(self, address):
        """As :meth:`connect`, returning an error number instead of
        raising. A failed connect does **not** handshake."""
        return self._connect(address, True)

    def _connect(self, address, use_ex):
        if self._handshake_done:
            raise ValueError("attempt to connect already-connected SSLSocket!")
        if use_ex:
            code = self._sock.connect_ex(address)
            if code != 0:
                return code
        else:
            self._sock.connect(address)
        if self._do_handshake_on_connect:
            self.do_handshake()
        return 0 if use_ex else None

    # -- the handshake ---------------------------------------------------

    def do_handshake(self):
        client = self._connection._client
        while not client.established:
            data = client.take_outgoing()
            if data:
                self._sock.sendall(data)
            if client.established:
                break
            received = self._sock.recv(65536)
            if not received:
                raise SSLEOFError(
                    "the peer closed the connection during the handshake")
            client.push_incoming(received)
            self._connection._translate(client.process)
            self._connection._maybe_log_keys()
        # Anything queued after the last process, such as our Finished.
        data = client.take_outgoing()
        if data:
            self._sock.sendall(data)
        self._connection._maybe_log_keys()
        self._connection._collect_tickets()
        self._handshake_done = True

    # -- reading and writing ---------------------------------------------

    def _fill(self):
        """Read until there is application data or the peer stops."""
        client = self._connection._client
        while not self._plaintext and not self._eof:
            received = self._sock.recv(65536)
            if not received:
                self._eof = True
                break
            client.push_incoming(received)
            self._connection._translate(client.process)
            # A TLS 1.3 NewSessionTicket rides in with the first
            # application data, so tickets are collected on every read
            # rather than once at the end of the handshake.
            self._connection._collect_tickets()
            self._plaintext.extend(client.take_incoming())
            out = client.take_outgoing()
            if out:
                self._sock.sendall(out)
            if client.state == "Closed":
                self._eof = True

    def recv(self, length=1024, flags=0):
        if flags:
            raise ValueError("flags are not supported on a wrapped socket")
        if not self._plaintext:
            self._fill()
        data = bytes(self._plaintext[:length])
        del self._plaintext[:length]
        return data

    def recv_into(self, buffer, nbytes=None, flags=0):
        wanted = nbytes or len(buffer)
        data = self.recv(wanted, flags)
        buffer[:len(data)] = data
        return len(data)

    def send(self, data, flags=0):
        self.sendall(data, flags)
        return len(data)

    def sendall(self, data, flags=0):
        if flags:
            raise ValueError("flags are not supported on a wrapped socket")
        client = self._connection._client
        self._connection._translate(lambda: client.write(bytes(data)))
        self._sock.sendall(client.take_outgoing())
        return None

    write = sendall
    read = recv

    def makefile(self, mode="r", buffering=None, *, encoding=None,
                 errors=None, newline=None):
        """A file object over the connection.

        ``http.client`` reads responses this way, so this is load bearing
        rather than a convenience.
        """
        raw = _socket.SocketIO(self, mode.replace("b", "") + "b"
                               if "b" in mode else mode)
        # SocketIO expects to own the socket's reference count; ours does
        # not, so the underlying socket is closed explicitly instead.
        if buffering is None:
            buffering = -1
        buffered = __import__("io").BufferedReader(
            raw, buffering if buffering > 0 else __import__("io").DEFAULT_BUFFER_SIZE)
        if "b" in mode:
            return buffered
        return __import__("io").TextIOWrapper(buffered, encoding, errors, newline)

    # -- lifecycle --------------------------------------------------------

    def unwrap(self):
        client = self._connection._client
        self._connection._translate(client.close)
        data = client.take_outgoing()
        if data:
            try:
                self._sock.sendall(data)
            except OSError:
                pass
        return self._sock

    def close(self):
        try:
            self.unwrap()
        except (OSError, SSLError):
            pass
        self._sock.close()

    def shutdown(self, how):
        return self._sock.shutdown(how)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- accessors --------------------------------------------------------

    def version(self):
        return self._connection.version()

    def cipher(self):
        return self._connection.cipher()

    def cipher_strength(self):
        return self._connection.cipher_strength()

    def named_group(self):
        return self._connection.named_group()

    def getpeercert(self, binary_form=False):
        return self._connection.getpeercert(binary_form)

    def getpeercertchain(self, binary_form=True):
        return self._connection.getpeercertchain(binary_form)

    def selected_alpn_protocol(self):
        return None

    def compression(self):
        return None

    def pending(self):
        return len(self._plaintext)

    def get_channel_binding(self, cb_type="tls-unique"):
        """See :meth:`SSLObject.get_channel_binding`. Forwarded rather
        than inherited, because this class composes a connection instead
        of subclassing one."""
        return self._connection.get_channel_binding(cb_type)

    @property
    def server_hostname(self):
        return self._connection.server_hostname

    @property
    def context(self):
        return self._connection.context

    @property
    def session(self):
        """See :attr:`SSLObject.session`."""
        return self._connection.session

    @property
    def session_reused(self):
        return self._connection.session_reused

    def selected_alpn_protocol(self):
        return self._connection.selected_alpn_protocol()

    def _checkClosed(self, msg=None):
        """Required by ``socket.SocketIO``."""
        if getattr(self._sock, "_closed", False):
            raise ValueError(msg or "I/O operation on closed socket")

    def __getattr__(self, name):
        # Timeouts, fileno, getpeername, setsockopt and the rest.
        return getattr(self.__dict__["_sock"], name)

    def __repr__(self):
        return "<allcrypt_ssl.SSLSocket version=%s cipher=%s>" % (
            self.version(), self.cipher())


# --------------------------------------------------------- the server side ---

class _ServerConnection:
    """The server half, shaped like `_Connection`.

    Not a subclass of it, and not `_Connection` with a flag: a client
    connection and a server one share almost nothing. A client checks a
    certificate, a name and a chain; a server presents one and checks
    nothing unless it asks for a client certificate. Sharing the class
    would mean a server object carrying `server_hostname`,
    `certificate_verified` and half a dozen other attributes that mean
    nothing on it - and the first caller who read one expecting it to
    mean something would have a security bug.
    """

    backend_in_use = "allcrypt"

    def __init__(self, context):
        chain, key = context._identity
        self._context = context
        self._server = _allcrypt.TlsServer(
            chain, key,
            now=int(_time.time()),
            ciphers=context._ciphers,
            min_version=_version_name(context._bounded(context.minimum_version,
                                                       TLSVersion.TLSv1_2)),
            max_version=_version_name(context._bounded(context.maximum_version,
                                                       _OUR_HIGHEST)),
            alpn=list(context._alpn),
        )
        self._closed = False

    def version(self):
        return self._server.version()

    def cipher(self):
        chosen = self._server.cipher()
        if chosen is None:
            return None
        name, _strength, bits = chosen
        return (name, self._server.version(), bits)

    def getpeercert(self, binary_form=False):
        """The *client's* certificate, which is usually nothing.

        A server that did not ask gets none, and this shim does not ask.
        `None` is the same answer the standard library gives.
        """
        chain = self._server.peer_certificates
        if not chain:
            return None
        if binary_form:
            return chain[0]
        return _allcrypt.Certificate(chain[0]).to_dict()

    def selected_alpn_protocol(self):
        return self._server.selected_alpn_protocol()

    def selected_npn_protocol(self):
        return None

    def compression(self):
        return None

    def shared_ciphers(self):
        return None

    @property
    def server_hostname(self):
        """The name the *client* asked for in SNI.

        Deliberately the same attribute name the standard library's
        client-side socket uses, because it is the same question - which
        host does the other end think this is - and a caller reading it
        off either wants the same answer.
        """
        return self._server.server_name

    @property
    def context(self):
        return self._context

    @property
    def session_reused(self):
        return False              # The server side issues no tickets here.

    def _translate(self, action):
        try:
            return action()
        except Exception as reason:                     # CryptoError
            self._closed = True
            raise SSLError(str(reason)) from None


class SSLServerSocket:
    """A wrapped socket on the accepting side.

    Composed rather than inherited from `SSLSocket` for the reason in
    `_ServerConnection`: the two directions share their plumbing and
    none of their meaning.
    """

    backend_in_use = "allcrypt"

    def __init__(self, context, sock, do_handshake_on_connect=True,
                 suppress_ragged_eofs=True):
        self._sock = sock
        self._connection = _ServerConnection(context)
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._plaintext = bytearray()
        self._eof = False
        if do_handshake_on_connect:
            self.do_handshake()

    def do_handshake(self):
        server = self._connection._server
        while not server.established:
            out = server.take_outgoing()
            if out:
                self._sock.sendall(out)
            if server.established:
                break
            received = self._sock.recv(65536)
            if not received:
                raise SSLEOFError(
                    "the peer closed the connection during the handshake")
            server.push_incoming(received)
            self._connection._translate(server.process)
        out = server.take_outgoing()
        if out:
            self._sock.sendall(out)

    def _fill(self):
        server = self._connection._server
        while not self._plaintext and not self._eof:
            received = self._sock.recv(65536)
            if not received:
                self._eof = True
                break
            server.push_incoming(received)
            self._connection._translate(server.process)
            self._plaintext.extend(server.take_incoming())
            out = server.take_outgoing()
            if out:
                self._sock.sendall(out)
            if server.state == "the connection is closed":
                self._eof = True

    def recv(self, length=1024, flags=0):
        if flags:
            raise ValueError("flags are not supported on a wrapped socket")
        if not self._plaintext:
            self._fill()
        data = bytes(self._plaintext[:length])
        del self._plaintext[:length]
        return data

    def recv_into(self, buffer, nbytes=None, flags=0):
        wanted = nbytes or len(buffer)
        data = self.recv(wanted, flags)
        buffer[:len(data)] = data
        return len(data)

    def send(self, data, flags=0):
        self.sendall(data, flags)
        return len(data)

    def sendall(self, data, flags=0):
        if flags:
            raise ValueError("flags are not supported on a wrapped socket")
        server = self._connection._server
        self._connection._translate(lambda: server.write(bytes(data)))
        self._sock.sendall(server.take_outgoing())

    def unwrap(self):
        server = self._connection._server
        self._connection._translate(server.close)
        out = server.take_outgoing()
        if out:
            self._sock.sendall(out)
        return self._sock

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass

    def makefile(self, mode="r", buffering=None, *, encoding=None,
                 errors=None, newline=None):
        """A file object over the connection.

        `http.server` reads requests this way, which is what makes this
        load bearing rather than a convenience - the same reason the
        client side has one.
        """
        raw = _socket.SocketIO(self, mode.replace("b", "") + "b"
                               if "b" in mode else mode)
        if buffering is None:
            buffering = -1
        io = __import__("io")
        buffered = io.BufferedReader(
            raw, buffering if buffering > 0 else io.DEFAULT_BUFFER_SIZE)
        if "b" in mode:
            return buffered
        return io.TextIOWrapper(buffered, encoding, errors, newline)

    def pending(self):
        return len(self._plaintext)

    def version(self):
        return self._connection.version()

    def cipher(self):
        return self._connection.cipher()

    def getpeercert(self, binary_form=False):
        return self._connection.getpeercert(binary_form)

    def selected_alpn_protocol(self):
        return self._connection.selected_alpn_protocol()

    @property
    def server_hostname(self):
        return self._connection.server_hostname

    @property
    def context(self):
        return self._connection.context

    @property
    def session_reused(self):
        return False

    def _checkClosed(self, msg=None):
        if getattr(self._sock, "_closed", False):
            raise ValueError(msg or "I/O operation on closed socket")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __getattr__(self, name):
        return getattr(self.__dict__["_sock"], name)

    def __repr__(self):
        return "<allcrypt_ssl.SSLServerSocket version=%s cipher=%s>" % (
            self.version(), self.cipher())


# -------------------------------------------------------------- the context ---

class SSLContext:
    """The seam.

    Mirrors :class:`ssl.SSLContext` closely enough for ``http.client``,
    ``urllib3`` and ``asyncio``. Attribute access falls through to a
    standard library context, so anything not overridden here still works.

    Client connections from SSLv3 to TLS 1.3 go through allcrypt, and so
    do server connections at TLS 1.2 and 1.3 once :meth:`load_cert_chain`
    has given a key this library can read. A server with any other key,
    or asked to go below TLS 1.2, falls back to the standard library, and
    :attr:`backend_in_use` says which happened. A shim that refuses to
    connect is worse than one that is honest about what it used.
    """

    def __init__(self, protocol=PROTOCOL_TLS_CLIENT, *args, **kwargs):
        self._ctx = _ssl.SSLContext(protocol, *args, **kwargs)
        self.protocol = protocol
        self._roots = _allcrypt.TrustStore() if _allcrypt else None
        self._loaded_default_certs = False
        self._ciphers = "modern"
        #: Smallest RSA modulus to accept in a certificate. Lower it to
        #: reach something old; it is a named attribute so that doing so is
        #: a decision.
        self.min_rsa_bits = 2048
        #: Accept SHA-1 and MD5 signatures on certificates.
        self.allow_sha1 = False
        self.allow_md5 = False
        #: Accept a certificate outside its validity window.
        #:
        #: The chain, the signatures and the name are all still checked -
        #: this relaxes the dates and nothing else. It is the narrowest
        #: thing that reaches a box whose certificate expired in 2014, and
        #: much narrower than turning verification off.
        self.allow_expired = False
        #: Smallest finite-field Diffie-Hellman group to accept, in bits.
        #:
        #: A DHE server chooses the group by itself and the client's only
        #: say is to accept it or hang up, so this is that say. Logjam
        #: broke 512 bit export groups in real time and brought the common
        #: 1024 bit ones within reach of precomputation - lower it when you
        #: have to reach a box that was configured once, in 2003, and never
        #: again.
        self.min_dh_bits = 2048
        #: Check that the server's Diffie-Hellman modulus is prime.
        #:
        #: Off by default because it costs several full-width modular
        #: exponentiations per handshake, more than the key exchange
        #: itself. On, it is the only thing that catches a server sending a
        #: composite modulus, which makes the shared secret computable by
        #: whoever chose it while every other check passes.
        self.check_dh_prime = False
        #: Which backend the last connection actually used.
        self.backend_in_use = None
        #: Set by the property below; `None` means "whatever SSLKEYLOGFILE
        #: says", which is what makes a capture work without a code change.
        self._keylog_filename = None
        #: The certificate chain and key a *server* presents, as
        #: `(chain, key)`, once `load_cert_chain` has read them. `None`
        #: means either that none was loaded or that this library could
        #: not read it, and `_identity_error` says which.
        self._identity = None
        self._identity_error = None
        #: ALPN protocols to offer, kept here as well as on the fallback
        #: context - `set_alpn_protocols` sets both, because a caller
        #: that configures the context before we know which backend will
        #: be used must get the same offer either way.
        self._alpn = []
        #: Tracked here as well as on the fallback context; see the setters.
        self._minimum_version = self._ctx.minimum_version
        self._maximum_version = self._ctx.maximum_version

    # -- wrapping ---------------------------------------------------------

    def _can_use_allcrypt(self, server_side):
        """Whether our own stack can handle this connection.

        A connection uses allcrypt unless the caller has asked for
        something we cannot do. The first version of this was the other way
        round - allcrypt only when TLS 1.2 was pinned explicitly - and the
        result was that every one of the seam tests silently fell back
        to the standard library and passed without touching a line of our
        code. A shim that quietly is not the thing it claims to be is worse
        than no shim, so the default is now ours and the fallbacks are
        named.
        """
        if _allcrypt is None:
            return False
        if server_side or self.protocol == PROTOCOL_TLS_SERVER:
            # A server needs a certificate and a key this library can
            # read. An encrypted key, or one on a curve we do not
            # implement, falls back - the standard library has the pair
            # either way, so the context still works.
            if self._identity is None:
                return False
            # A server below TLS 1.2 is not offered here. The whole
            # reason for the low floor is reaching old *servers*, and
            # serving SSLv3 to somebody is the opposite of that: it is
            # putting POODLE in front of whoever connects. It can still
            # be done through `allcrypt.TlsServer` directly, where it is
            # a decision somebody made rather than a default.
            floor = self._bounded(self.minimum_version, _OUR_LOWEST)
            if floor < TLSVersion.TLSv1_2:
                return False

        minimum = self.minimum_version
        maximum = self.maximum_version

        # Anything from TLS 1.0 to 1.2 is ours - including the two the
        # standard library will usually refuse outright, which is the whole
        # reason to be here. SSLv3 is ours too, and has to be asked for by
        # name.
        #
        # TLS 1.3 is ours too now, with `SSLSession` and `session_reused`
        # below.
        #
        # **The server side is ours as well**, and the comment that used
        # to sit here saying otherwise - "this library has no
        # private-key parser" - was true when it was written and had
        # been false for some time. `load_cert_chain` reads the key
        # through `allcrypt.private_key`, encrypted or not, and the only
        # thing that still falls back is a key this library genuinely
        # cannot read: a curve it does not implement, or a format
        # nothing here parses. `_identity_error` says which.
        #
        # A stale comment about a fallback is expensive in a way a stale
        # comment about anything else is not: it reads as a decision, so
        # nobody re-tests it.
        if minimum not in (TLSVersion.MINIMUM_SUPPORTED,) + _OUR_VERSIONS:
            return False
        if maximum not in (TLSVersion.MAXIMUM_SUPPORTED,) + _OUR_VERSIONS:
            return False
        return True

    def _new_client(self, server_hostname, tickets=()):
        if self.verify_mode != CERT_NONE and len(self._roots) == 0:
            if not self._loaded_default_certs:
                # Match the standard library: a context that was told to
                # verify and given nothing gets the platform's roots.
                self.load_default_certs()
        window = self._version_window()
        return _allcrypt.TlsClient(
            server_hostname,
            self._roots,
            now=int(_time.time()),
            ciphers=self._ciphers,
            verify=self.verify_mode != CERT_NONE,
            # **One source of truth for the version window.** It is
            # `minimum_version`/`maximum_version` narrowed by whatever
            # `OP_NO_*` flags are set, and `_version_window` is what both
            # computes it and refuses a combination this stack cannot
            # offer - so the flags cannot be honoured here and forgotten
            # somewhere else. The floor is only lowered past TLS 1.0 by
            # an explicit minimum_version of SSLv3.
            min_version=_version_name(window[0]),
            max_version=_version_name(window[1]),
            allow_sha1=self.allow_sha1,
            allow_expired=self.allow_expired,
            # Previously not passed at all, so `check_hostname = False` set
            # the flag on the fallback context and our own stack went on
            # checking the name. A caller connecting by IP address had no
            # way to say so.
            verify_hostname=self.check_hostname,
            allow_md5=self.allow_md5,
            min_rsa_bits=self.min_rsa_bits,
            min_dh_bits=self.min_dh_bits,
            check_dh_prime=self.check_dh_prime,
            # **OP_NO_TICKET, honoured.** A caller that asked for no
            # session tickets offers none, so nothing it stored can be
            # replayed as a PSK; `_collect_tickets` drops the ones the
            # server sends anyway, so the session stays empty and
            # `session_reused` stays false. The server side needs no
            # flag - nothing here issues a ticket unless asked to.
            tickets=[] if self._no_tickets else list(tickets),
            alpn=list(self._alpn),
        )

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,
                    suppress_ragged_eofs=True, server_hostname=None, session=None):
        """Wrap a connected socket. Used by ``http.client`` and ``urllib3``."""
        if not self._can_use_allcrypt(server_side):
            self.backend_in_use = "stdlib"
            return self._ctx.wrap_socket(
                sock, server_side=server_side,
                do_handshake_on_connect=do_handshake_on_connect,
                suppress_ragged_eofs=suppress_ragged_eofs,
                server_hostname=server_hostname, session=session)

        self.backend_in_use = "allcrypt"
        if server_side:
            return SSLServerSocket(
                self, sock,
                do_handshake_on_connect=do_handshake_on_connect,
                suppress_ragged_eofs=suppress_ragged_eofs)
        if session is not None and not isinstance(session, SSLSession):
            raise TypeError(
                "session must be an allcrypt_ssl.SSLSession. An "
                "ssl.SSLSession belongs to OpenSSL's own connection state "
                "and there is nothing here that can read one.")
        return SSLSocket(self, sock, server_hostname, session=session,
                         do_handshake_on_connect=do_handshake_on_connect,
                         suppress_ragged_eofs=suppress_ragged_eofs)

    def wrap_bio(self, incoming, outgoing, server_side=False,
                 server_hostname=None, session=None):
        """Wrap a pair of memory BIOs. This is the path ``asyncio`` drives,
        and the one the sans-I/O core plugs straight into."""
        if not self._can_use_allcrypt(server_side):
            self.backend_in_use = "stdlib"
            return self._ctx.wrap_bio(
                incoming, outgoing, server_side=server_side,
                server_hostname=server_hostname, session=session)

        if server_side:
            # The memory-BIO server is not wired up. `wrap_socket` is
            # what a server uses; `wrap_bio` on that side is asyncio's
            # path and would need its own object, and offering a
            # half-built one is worse than falling back visibly.
            self.backend_in_use = "stdlib"
            return self._ctx.wrap_bio(
                incoming, outgoing, server_side=server_side,
                server_hostname=server_hostname, session=session)
        self.backend_in_use = "allcrypt"
        if session is not None and not isinstance(session, SSLSession):
            raise TypeError(
                "session must be an allcrypt_ssl.SSLSession. An "
                "ssl.SSLSession belongs to OpenSSL's own connection state "
                "and there is nothing here that can read one.")
        return SSLObject(self, incoming, outgoing, server_hostname,
                         session=session)

    # -- key log ----------------------------------------------------------

    @property
    def keylog_filename(self):
        """Where to append this context's session keys, for Wireshark.

        The same attribute the standard library has, holding the same NSS
        key log format, so a capture is decrypted the same way::

            ctx = allcrypt_ssl.create_default_context()
            ctx.keylog_filename = "/tmp/keys.log"

        then in Wireshark: *Preferences -> Protocols -> TLS -> (Pre)-Master
        Secret log filename*, or ``tshark -o tls.keylog_file:/tmp/keys.log``.

        Unset, it falls back to the ``SSLKEYLOGFILE`` environment variable,
        which OpenSSL, curl and every browser already honour - so a capture
        works against code that has never heard of this attribute. Set it to
        ``""`` to mean "off, whatever the environment says".

        **This writes the session keys to a file in plain text.** Anyone
        who reads that file can decrypt every connection it covers, from a
        capture taken at any time. It belongs in a debugging session and
        not in anything that runs unattended.
        """
        if self._keylog_filename is not None:
            return self._keylog_filename or None
        return _default_keylog_path()

    @keylog_filename.setter
    def keylog_filename(self, value):
        # Mirrored onto the standard library context too, so the fallback
        # path logs to the same file. Older versions did not have the
        # attribute, and a debugging aid should not be what breaks on them.
        self._keylog_filename = "" if value is None else str(value)
        try:
            self._ctx.keylog_filename = value
        except (AttributeError, ValueError, OSError):
            pass

    # -- configuration ----------------------------------------------------

    @property
    def check_hostname(self):
        return self._ctx.check_hostname

    @check_hostname.setter
    def check_hostname(self, value):
        self._ctx.check_hostname = value

    @property
    def verify_mode(self):
        return self._ctx.verify_mode

    @verify_mode.setter
    def verify_mode(self, value):
        self._ctx.verify_mode = value

    @staticmethod
    def _bounded(version, default):
        """A concrete version name for the core, which has no notion of
        "minimum supported" - those sentinels mean "whatever you can do",
        and what we can do is `_OUR_VERSIONS`."""
        if version in _OUR_VERSIONS:
            return version
        return default

    @property
    def minimum_version(self):
        return self._minimum_version

    @minimum_version.setter
    def minimum_version(self, value):
        # Kept here rather than only on the standard library context,
        # because a modern OpenSSL build often refuses to *hold* a minimum
        # of TLS 1.0 at all - and if setting it raised, the one
        # configuration this library exists to serve would be unreachable
        # through its own shim. The fallback context is told as well, and
        # is allowed to decline.
        self._minimum_version = value
        try:
            self._ctx.minimum_version = value
        except (ValueError, OSError):
            pass

    @property
    def maximum_version(self):
        return self._maximum_version

    @maximum_version.setter
    def maximum_version(self, value):
        self._maximum_version = value
        try:
            self._ctx.maximum_version = value
        except (ValueError, OSError):
            pass

    @property
    def options(self):
        """The `OP_*` flags, and **they are honoured rather than stored**.

        A flag a caller sets is a behaviour they asked for. Absorbing one
        and carrying on is how `urllib3`, which sets
        `OP_NO_SSLv2 | OP_NO_SSLv3 | OP_NO_COMPRESSION | OP_NO_TICKET`
        on every context it builds, would silently get session tickets
        after asking for none - so each flag here either changes what
        this stack does, is already true of it, or raises.

        `SSLContext.option_report()` says which of the three every set
        flag is.
        """
        return self._ctx.options

    @options.setter
    def options(self, value):
        value = Options(value)
        # Raise before storing, so a context is never left in a state it
        # cannot honour. `_version_window` is what does the checking and
        # is also what the handshake reads, so the two cannot drift.
        self._version_window(options=value)
        if not (value & Options.OP_ENABLE_MIDDLEBOX_COMPAT):
            raise ValueError(
                "OP_ENABLE_MIDDLEBOX_COMPAT cannot be cleared here: this "
                "stack always sends the TLS 1.3 compatibility "
                "ChangeCipherSpec, and a context that recorded the "
                "request without acting on it would be lying about what "
                "goes on the wire.")
        self._ctx.options = value

    # Flags that are already true of this stack, so setting them asks for
    # nothing new. Each is a property of the implementation rather than a
    # switch:
    #
    #   OP_NO_SSLv2          SSLv2 is not implemented and will not be.
    #   OP_NO_COMPRESSION    Nothing here compresses. TLS compression is
    #                        CRIME; the record layer has no code for it.
    #   OP_NO_RENEGOTIATION  Nothing here renegotiates, in either
    #                        direction, at any version.
    #   OP_SINGLE_DH_USE     Every ephemeral key is generated per
    #   OP_SINGLE_ECDH_USE   connection; there is nowhere to cache one.
    #   OP_ENABLE_MIDDLEBOX_COMPAT
    #                        The 1.3 compatibility ChangeCipherSpec is
    #                        always sent - which is why clearing it
    #                        raises above.
    _OPTIONS_ALREADY_TRUE = (
        Options.OP_NO_SSLv2 | Options.OP_NO_COMPRESSION
        | Options.OP_NO_RENEGOTIATION | Options.OP_SINGLE_DH_USE
        | Options.OP_SINGLE_ECDH_USE | Options.OP_ENABLE_MIDDLEBOX_COMPAT)

    #: Flags that change what this stack does. The version exclusions are
    #: applied by `_version_window`; the rest are read where they act.
    _OPTIONS_ACTED_ON = (
        Options.OP_NO_SSLv3 | Options.OP_NO_TLSv1 | Options.OP_NO_TLSv1_1
        | Options.OP_NO_TLSv1_2 | Options.OP_NO_TLSv1_3
        | Options.OP_NO_TICKET | Options.OP_CIPHER_SERVER_PREFERENCE
        | Options.OP_IGNORE_UNEXPECTED_EOF)

    #: `OP_ALL` is a bag of workarounds for bugs in *other* TLS stacks -
    #: the empty-fragment insertion, the Netscape challenge length, and
    #: so on. None of them describe anything this code does, so there is
    #: nothing here to switch on or off. It is set by default in the
    #: standard library and by every caller that copies that, which is
    #: why it is named rather than left to fall into the "unknown"
    #: bucket below.
    _OPTIONS_NOT_APPLICABLE = Options.OP_ALL

    def option_report(self):
        """What this context does with each flag it has been given.

        Returns a dict from flag name to one of `"acted on"`, `"already
        true"` or `"not applicable"`. There is deliberately no fourth
        answer: a flag that would need one raises when it is set.

        Here because "is this option doing anything?" is otherwise a
        question only the source can answer, and the source is not where
        somebody debugging a connection is looking.
        """
        current = Options(self._ctx.options)
        report = {}
        # `__members__` rather than iterating the enum, because iterating
        # an IntFlag yields only its canonical single-bit members and
        # OP_ALL is a composite - the one every caller sets.
        for flag in Options.__members__.values():
            # A zero-valued member asks for nothing - OP_NO_SSLv2 is
            # zero on any OpenSSL that dropped SSLv2, and `x & 0 == 0`
            # is true of every context, so reporting it would say this
            # one had been given a flag it had not.
            if not flag or current & flag != flag:
                continue
            if flag & self._OPTIONS_ACTED_ON == flag:
                report[flag.name] = "acted on"
            elif flag & self._OPTIONS_ALREADY_TRUE == flag:
                report[flag.name] = "already true"
            elif flag & self._OPTIONS_NOT_APPLICABLE == flag:
                report[flag.name] = "not applicable"
            else:                                  # pragma: no cover
                report[flag.name] = "unknown"
        return report

    #: Which `OP_NO_*` flag forbids which version.
    _VERSION_OPTION = (
        (TLSVersion.SSLv3, Options.OP_NO_SSLv3),
        (TLSVersion.TLSv1, Options.OP_NO_TLSv1),
        (TLSVersion.TLSv1_1, Options.OP_NO_TLSv1_1),
        (TLSVersion.TLSv1_2, Options.OP_NO_TLSv1_2),
        (TLSVersion.TLSv1_3, Options.OP_NO_TLSv1_3),
    )

    def _version_window(self, options=None):
        """The versions this context will actually offer, as
        `(minimum, maximum)`.

        `minimum_version`/`maximum_version` give a range and the `OP_NO_*`
        flags give a *set*, and the two do not have the same shape. This
        stack offers a contiguous range, so:

          * the range is narrowed by exclusions at either end, which is
            the case every real caller produces - `urllib3`'s
            `OP_NO_SSLv3` and a 1.2 floor, say;
          * an exclusion that would punch a **hole** in the middle is
            refused, by name, rather than approximated. Offering 1.2
            after being told not to is the kind of quiet disagreement
            this whole module exists not to do;
          * an empty window is refused too, and the message names both
            the range and the flag that emptied it - the common case
            being `minimum_version = SSLv3` against the `OP_NO_SSLv3`
            that the standard library sets by default.
        """
        if options is None:
            options = Options(self._ctx.options)
        low = self._bounded(self._minimum_version, _OUR_LOWEST)
        high = self._bounded(self._maximum_version, _OUR_HIGHEST)

        allowed = [version for version, flag in self._VERSION_OPTION
                   if low <= version <= high and not (options & flag)]
        if not allowed:
            refused = [flag.name for version, flag in self._VERSION_OPTION
                       if low <= version <= high and (options & flag)]
            hint = ""
            if "OP_NO_SSLv3" in refused:
                # By far the most likely way to land here, because the
                # standard library sets OP_NO_SSLv3 on every context it
                # builds - so asking for SSLv3 means clearing it too.
                hint = (" The standard library sets OP_NO_SSLv3 by default,"
                        " so reaching SSLv3 takes"
                        " `context.options &= ~allcrypt_ssl.OP_NO_SSLv3`"
                        " as well as the minimum_version;"
                        " create_legacy_context() has already done it.")
            raise ValueError(
                "this context can offer no TLS version at all: the range is "
                "{}..{} and {} excludes the rest.{}".format(
                    _version_name(low), _version_name(high),
                    " and ".join(refused) or "nothing", hint))

        span = [version for version, _flag in self._VERSION_OPTION
                if allowed[0] <= version <= allowed[-1]]
        if len(span) != len(allowed):
            holes = [_version_name(v) for v in span if v not in allowed]
            raise ValueError(
                "this stack offers a contiguous range of versions, and these "
                "options ask for a gap in the middle ({}). Narrow "
                "minimum_version/maximum_version instead, or drop the "
                "OP_NO_* flag - it will not be quietly ignored.".format(
                    ", ".join(holes)))
        return allowed[0], allowed[-1]

    # ------------------------------------------------ verify_flags ----
    #
    # Same rule as `options`: a flag either changes what this stack does,
    # is already true of it, or raises. The difference is that two of
    # these cannot be honoured *at all* here, and quietly accepting
    # either would be the worst kind of wrong - a caller who asks for
    # revocation checking and is told nothing is a caller who believes
    # revoked certificates are being refused.

    #: Already true of this verifier.
    #:
    #:   VERIFY_X509_PARTIAL_CHAIN   An anchor is trusted because it is
    #:                               in the store, not because it is
    #:                               self-signed - which is what makes a
    #:                               cross-signed root usable. See
    #:                               `x509::verify`.
    #:   VERIFY_X509_TRUSTED_FIRST   The store is consulted before the
    #:                               chain the peer sent.
    #:   VERIFY_X509_STRICT          The strict readings *are* the
    #:                               defaults here. Every leniency this
    #:                               library has is a named opt-in -
    #:                               `allow_sha1`, `allow_md5`,
    #:                               `allow_expired`, `min_rsa_bits` -
    #:                               rather than a workaround that a flag
    #:                               turns off.
    _VERIFY_FLAGS_ALREADY_TRUE = (
        VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
        | VerifyFlags.VERIFY_X509_TRUSTED_FIRST
        | VerifyFlags.VERIFY_X509_STRICT)

    #: Flags this stack cannot honour, with the reason each one raises.
    #:
    #: **Most specific first.** `VERIFY_CRL_CHECK_CHAIN` is
    #: `VERIFY_CRL_CHECK_LEAF` with another bit set, so a loop that
    #: tested LEAF first would report the wrong flag's name for a caller
    #: who asked for CHAIN - the right refusal with the wrong reason,
    #: which sends whoever reads it looking for a setting they did not
    #: make.
    _VERIFY_FLAGS_REFUSED = {
        VerifyFlags.VERIFY_CRL_CHECK_CHAIN:
            "as VERIFY_CRL_CHECK_LEAF, for every certificate in the "
            "chain rather than the leaf alone.",
        VerifyFlags.VERIFY_CRL_CHECK_LEAF:
            "nothing in this library fetches a CRL - no socket is opened "
            "anywhere in it - so this flag could only mean 'fail every "
            "chain' or 'check nothing', and both are worse than saying "
            "so. Pass the CRLs you have fetched to allcrypt.verify_chain "
            "directly, where Unknown is a third answer rather than a "
            "silent pass.",
        VerifyFlags.VERIFY_ALLOW_PROXY_CERTS:
            "proxy certificates (RFC 3820) are not parsed here, so this "
            "would be permission to accept something this library cannot "
            "read.",
    }

    @property
    def verify_flags(self):
        """The `VERIFY_*` flags, honoured or refused - never absorbed.

        `SSLContext.verify_flags_report()` says which of the two each set
        flag is, and setting one this stack cannot honour raises with the
        reason rather than recording it.
        """
        return self._ctx.verify_flags

    @verify_flags.setter
    def verify_flags(self, value):
        value = VerifyFlags(value)
        for flag, reason in self._VERIFY_FLAGS_REFUSED.items():
            # **`value & flag == flag`, not `value & flag`.**
            # VERIFY_CRL_CHECK_CHAIN is VERIFY_CRL_CHECK_LEAF with a
            # second bit, so a truthiness test matches the composite for
            # a caller who set only the leaf flag, and reports the wrong
            # name - the right refusal with the wrong reason, which sends
            # whoever reads it looking for a setting they did not make.
            if value & flag == flag:
                raise ValueError("{} cannot be honoured here: {}".format(
                    flag.name, reason))
        self._ctx.verify_flags = value

    def verify_flags_report(self):
        """What this context does with each verify flag it has been
        given. Every set flag is `"already true"`, because the others
        raise when they are set."""
        current = VerifyFlags(self._ctx.verify_flags)
        report = {}
        for flag in VerifyFlags.__members__.values():
            # As above: VERIFY_DEFAULT is zero and means "no flags".
            if not flag or current & flag != flag:
                continue
            report[flag.name] = (
                "already true"
                if flag & self._VERIFY_FLAGS_ALREADY_TRUE == flag
                else "unknown")
        return report

    @property
    def _no_tickets(self):
        """Whether `OP_NO_TICKET` forbids session resumption here.

        On the server it is true by construction as well - nothing here
        issues a ticket unless asked - but the client offers and stores
        them, so this is read on both sides rather than assumed on one.
        """
        return bool(Options(self._ctx.options) & Options.OP_NO_TICKET)

    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        self._ctx.load_verify_locations(cafile, capath, cadata)
        if self._roots is None:
            return
        if cafile:
            self._roots.add_pem(open(cafile, "r").read())
        if capath:
            import os
            for name in os.listdir(capath):
                if name.endswith((".pem", ".crt")):
                    try:
                        self._roots.add_pem(open(os.path.join(capath, name)).read())
                    except (OSError, _allcrypt.CryptoError):
                        pass
        if cadata:
            if isinstance(cadata, str):
                self._roots.add_pem(cadata)
            else:
                self._roots.add_der(bytes(cadata))

    def load_cert_chain(self, certfile, keyfile=None, password=None):
        """The certificate chain and key this context presents.

        Loaded into both backends. The standard library's copy is what
        the fallback path uses and what validates the pair; ours is what
        an allcrypt server presents.

        `password` is honoured here as well as by the standard library.
        It used to be passed only to the fallback, with a comment saying
        this library could not decrypt a private key - true when it was
        written and untrue since PBES1, PBES2 and the PKCS#12 schemes
        landed. The cost of the stale comment was a whole class of
        context silently serving through OpenSSL.

        As the standard library does, it may be `bytes`, `str`, or a
        callable returning one - a callable is how a passphrase gets
        prompted for rather than held in a variable.
        """
        result = self._ctx.load_cert_chain(certfile, keyfile, password)
        self._identity = None
        if _allcrypt is None:
            return result
        try:
            with open(certfile, "rb") as handle:
                certificate_pem = handle.read()
            with open(keyfile or certfile, "rb") as handle:
                key_pem = handle.read()
            chain = _allcrypt.pem_certificates(certificate_pem.decode())
            key = _allcrypt.private_key(key_pem, _password_bytes(password))
        except (OSError, UnicodeDecodeError, ValueError) as reason:
            # An encrypted key, a curve we do not implement, a format
            # nothing here reads. The standard library already has the
            # pair, so the context still works - through the fallback,
            # which `backend_in_use` will report.
            self._identity_error = str(reason)
            return result
        self._identity_error = None
        self._identity = (chain, key)
        return result

    def load_default_certs(self, *args, **kwargs):
        self._ctx.load_default_certs(*args, **kwargs)
        self._loaded_default_certs = True
        if self._roots is None:
            return
        try:
            system = _allcrypt.TrustStore.system()
        except _allcrypt.CryptoError:
            return
        for der in system.roots:
            try:
                self._roots.add_der(der)
            except _allcrypt.CryptoError:
                pass

    def set_ciphers(self, ciphers):
        """Select cipher suites.

        This is where the legacy suites are enabled by name. ``"modern"``
        is the default and offers nothing broken; ``"legacy"`` adds RC4,
        3DES and the rest; a comma separated list of suite names selects
        exactly those. They stay off unless asked for - see the downgrade
        note in docs/pitfalls.md.
        """
        self._ciphers = ciphers
        try:
            self._ctx.set_ciphers(ciphers)
        except (_ssl.SSLError, TypeError):
            # Our own names are not OpenSSL cipher strings, and that is
            # fine - the stdlib context is only the fallback.
            pass

    def get_ciphers(self):
        """The suites this context will offer, in hello order.

        `ssl.SSLContext.get_ciphers` returns OpenSSL's dicts; this
        returns the same shape with the fields we can actually fill,
        because the alternative is inventing values for the rest. The
        `name` is this library's registry name rather than OpenSSL's -
        several of these suites have no OpenSSL name at all, which is
        the point of the library.
        """
        return [{"name": name, "protocol": "TLSv1.2"}
                for name in _allcrypt.tls_suite_names(self._ciphers)]

    def set_alpn_protocols(self, protocols):
        """The application protocols to offer, in preference order.

        Set on both backends, because which one a connection will use is
        not settled until `wrap_socket` and a caller configuring the
        context has no way to know.
        """
        self._alpn = [str(name) for name in protocols]
        return self._ctx.set_alpn_protocols(protocols)

    def get_ca_certs(self, binary_form=False):
        return self._ctx.get_ca_certs(binary_form)

    def cert_store_stats(self):
        return {"x509": len(self._roots) if self._roots else 0,
                "x509_ca": len(self._roots) if self._roots else 0,
                "crl": 0}

    # Anything we have not had to name explicitly.
    def __getattr__(self, name):
        return getattr(self.__dict__["_ctx"], name)

    def __repr__(self):
        return "<allcrypt_ssl.SSLContext backend=%s verify_mode=%s>" % (
            BACKEND, self.verify_mode)


# ----------------------------------------------- the module level functions ---
#
# Small, and every one of them is something a caller reaches for without
# thinking - which is exactly why a missing one is an `AttributeError`
# deep inside somebody else's library rather than a sensible error.


def DER_cert_to_PEM_cert(der_cert_bytes):
    """DER to PEM, with the same header, footer and line wrapping as the
    standard library's."""
    if _allcrypt is None:                          # pragma: no cover
        return _ssl.DER_cert_to_PEM_cert(der_cert_bytes)
    return _allcrypt.pem_wrap(bytes(der_cert_bytes))


def PEM_cert_to_DER_cert(pem_cert_string):
    """PEM to DER.

    Raises `ValueError` for text that holds no certificate, as the
    standard library does - returning empty bytes would turn a
    configuration mistake into a verification failure somewhere else.
    """
    if _allcrypt is None:                          # pragma: no cover
        return _ssl.PEM_cert_to_DER_cert(pem_cert_string)
    found = _allcrypt.pem_certificates(pem_cert_string)
    if not found:
        raise ValueError("no start line: PEM_cert_to_DER_cert needs a "
                         "certificate in PEM format")
    return found[0]


def cert_time_to_seconds(cert_time):
    """A certificate's notBefore/notAfter string as a Unix timestamp.

    The format is the one `getpeercert()` produces - `"Jun  1 00:00:00
    2024 GMT"` - and it is parsed **locale independently**, with the
    month names spelled out here rather than taken from `strptime`. A
    process running under a non-English locale would otherwise fail to
    parse its own certificates, which is the bug the standard library
    fixed in 3.5 and is worth not reintroducing.
    """
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    import calendar as _calendar
    import re as _re
    match = _re.match(
        r"^\s*(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\s+GMT\s*$",
        cert_time)
    if not match or match.group(1) not in months:
        raise ValueError("time data %r does not match format "
                         "'%%b %%d %%H:%%M:%%S %%Y GMT'" % cert_time)
    month = months.index(match.group(1)) + 1
    day, hour, minute, second, year = (int(match.group(i)) for i in (2, 3, 4, 5, 6))
    return _calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))


def get_default_verify_paths():
    """Where the platform keeps its trust store.

    Answered by **this** library's loader rather than OpenSSL's, because
    they can disagree: under WSL the target is Linux and the roots come
    from the distribution's bundle, not the Windows store, and a caller
    told OpenSSL's answer would go looking in the wrong place.
    """
    if _allcrypt is None:                          # pragma: no cover
        return _ssl.get_default_verify_paths()
    try:
        source = _allcrypt.TrustStore.system().source
    except Exception:                              # noqa: BLE001
        source = None
    # The standard library's shape: the two environment variables and the
    # two built-in paths. `source` is the one this library would use.
    is_directory = bool(source) and not _os.path.isfile(source)
    return DefaultVerifyPaths(
        cafile=None if is_directory else source,
        capath=source if is_directory else None,
        openssl_cafile_env="SSL_CERT_FILE",
        openssl_cafile=None if is_directory else source,
        openssl_capath_env="SSL_CERT_DIR",
        openssl_capath=source if is_directory else None)


def get_protocol_name(protocol_code):
    return _ssl.get_protocol_name(protocol_code)


def match_hostname(cert, hostname):
    """RFC 6125 name matching over a parsed certificate dictionary.

    Deprecated in the standard library since 3.7 and removed in 3.12,
    and delegated here rather than reimplemented: it is string matching
    over a dict that this module did not produce, with no cryptography
    in it at all. `SSLSocket` does its own matching over the real
    certificate, which is the path that matters.
    """
    delegate = getattr(_ssl, "match_hostname", None)
    if delegate is None:                           # pragma: no cover
        raise AttributeError(
            "match_hostname was removed in Python 3.12. The hostname is "
            "checked during the handshake; see SSLContext.check_hostname.")
    return delegate(cert, hostname)


def RAND_bytes(num):
    """`num` cryptographically strong random bytes, from this library's
    own source rather than OpenSSL's pool."""
    if _allcrypt is None:                          # pragma: no cover
        return _ssl.RAND_bytes(num)
    return _allcrypt.random_bytes(num)


def RAND_pseudo_bytes(num):
    """Deprecated everywhere. The same bytes as :func:`RAND_bytes` and a
    `True` to say they are strong, because there is no weaker source
    here and offering one would be a trap."""
    return RAND_bytes(num), True


def RAND_status():
    """Whether the random source is seeded. Always true: the source is
    the operating system's, which is seeded before this process starts
    or cannot be read at all."""
    return True


def RAND_add(string, entropy):
    """Accepted and discarded.

    There is no user-space entropy pool here to add to - randomness
    comes from the operating system on every call - so mixing in
    caller-supplied bytes would either do nothing or make the output
    depend on them, and the second is worse. Named rather than omitted
    because code that seeds defensively should not crash.
    """
    _ = (string, entropy)


def get_server_certificate(addr, ssl_version=None, ca_certs=None, timeout=None):
    """Connect, take the peer's certificate, and return it as PEM.

    Uses **this** stack, so it can fetch a certificate from a server the
    standard library refuses to talk to at all - which is most of the
    reason anyone would call it from here.

    Verification is off, deliberately and as in the standard library:
    the point is to look at the certificate, and a server whose chain
    does not verify is exactly the one somebody is trying to look at.
    Passing `ca_certs` turns verification on.
    """
    host, port = addr
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    if ca_certs is not None:
        context.load_verify_locations(ca_certs)
    else:
        context.check_hostname = False
        context.verify_mode = CERT_NONE
    if ssl_version is not None:
        context.minimum_version = ssl_version
        context.maximum_version = ssl_version

    raw = _socket.create_connection(addr, timeout=timeout)
    try:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    finally:
        pass
    if not der:
        raise ValueError("the peer sent no certificate")
    return DER_cert_to_PEM_cert(der)


def wrap_socket(sock, keyfile=None, certfile=None, server_side=False,
                cert_reqs=CERT_NONE, ssl_version=None, ca_certs=None,
                do_handshake_on_connect=True, suppress_ragged_eofs=True,
                ciphers=None):
    """The pre-3.2 module level entry point, removed in Python 3.12.

    Here because code written against it still exists and this library's
    reason to be is reaching things nobody has updated. It builds a
    context and calls :meth:`SSLContext.wrap_socket`, which is what the
    standard library did for the decade before it was removed.
    """
    context = SSLContext(PROTOCOL_TLS_SERVER if server_side else PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = cert_reqs
    if ssl_version is not None:
        context.minimum_version = ssl_version
        context.maximum_version = ssl_version
    if ca_certs is not None:
        context.load_verify_locations(ca_certs)
    if certfile is not None:
        context.load_cert_chain(certfile, keyfile)
    if ciphers is not None:
        context.set_ciphers(ciphers)
    return context.wrap_socket(
        sock, server_side=server_side,
        do_handshake_on_connect=do_handshake_on_connect,
        suppress_ragged_eofs=suppress_ragged_eofs)


def _create_stdlib_context(protocol=None, *, cert_reqs=CERT_NONE,
                           check_hostname=False, purpose=Purpose.SERVER_AUTH,
                           certfile=None, keyfile=None, cafile=None,
                           capath=None, cadata=None):
    """The private constructor `smtplib`, `imaplib`, `poplib` and
    `ftplib` all call.

    Unlike :func:`create_default_context` it does **not** verify by
    default, which is the standard library's choice and not one to
    quietly improve on: those modules turn verification on themselves
    when they mean to, and a shim that verified anyway would refuse
    connections the caller's own code had decided to allow.
    """
    context = SSLContext(protocol or PROTOCOL_TLS_CLIENT)
    context.check_hostname = check_hostname
    if cert_reqs is not None:
        context.verify_mode = cert_reqs
    if cafile or capath or cadata:
        context.load_verify_locations(cafile, capath, cadata)
    if certfile:
        context.load_cert_chain(certfile, keyfile)
    return context


def create_default_context(purpose=Purpose.SERVER_AUTH, *,
                           cafile=None, capath=None, cadata=None):
    """Mirrors :func:`ssl.create_default_context`: verification on, hostname
    checking on."""
    protocol = (PROTOCOL_TLS_CLIENT if purpose == Purpose.SERVER_AUTH
                else PROTOCOL_TLS_SERVER)
    ctx = SSLContext(protocol)
    if purpose == Purpose.SERVER_AUTH:
        ctx.check_hostname = True
        ctx.verify_mode = CERT_REQUIRED
    if cafile or capath or cadata:
        ctx.load_verify_locations(cafile, capath, cadata)
    elif purpose == Purpose.SERVER_AUTH:
        ctx.load_default_certs(Purpose.SERVER_AUTH)
    return ctx


def create_legacy_context(*, cafile=None, capath=None, cadata=None,
                          min_rsa_bits=1024):
    """A context for talking to something old.

    Offers the legacy cipher suites, accepts SHA-1 and MD5 signatures on
    certificates, and lowers the RSA floor. Verification stays on: the
    point is to reach the server, not to stop checking who it is.

    A named constructor rather than a pile of flags, so that using it is a
    decision somebody made and can be found by grepping for it.
    """
    ctx = create_default_context(cafile=cafile, capath=capath, cadata=cadata)
    ctx.set_ciphers("legacy")
    ctx.allow_sha1 = True
    ctx.allow_md5 = True
    # A box old enough to need SHA-1 and a 1024 bit key usually also has a
    # certificate that ran out years ago, and nobody left to reissue it.
    ctx.allow_expired = True
    ctx.min_rsa_bits = min_rsa_bits
    # The same equipment offers a 1024 bit Diffie-Hellman group, and often
    # a 512 bit export one. 512 is the floor even here: below that is not
    # something anybody configured on purpose.
    ctx.min_dh_bits = 512

    # **SSLv3 is unblocked here, and only here.** The standard library
    # sets `OP_NO_SSLv3` on every context, which is the right default and
    # the wrong one for this constructor: reaching a box that speaks
    # nothing else is what a legacy context is for, and leaving the flag
    # set would make `minimum_version = TLSVersion.SSLv3` raise with a
    # contradiction the caller did not create.
    #
    # It does not *enable* SSLv3 - the floor below is TLS 1.0 and stays
    # there. It removes the second lock, so that lowering the floor is
    # one decision rather than two.
    ctx.options &= ~Options.OP_NO_SSLv3

    # Down to TLS 1.0, which is the point. This used to pin 1.2 at both
    # ends, which made "legacy context" mean nothing but a different cipher
    # list - and a server that only speaks 1.0 is the single most common
    # thing this library is pointed at. A modern OpenSSL will not reach it
    # at all, so falling back is not an answer either.
    #
    # TLS 1.0 and 1.1 are exposed to BEAST and to a padding oracle in a way
    # 1.2 with encrypt-then-MAC is not; see docs/pitfalls.md. Reaching the
    # server and being honest about what that costs are not in tension,
    # which is the whole premise here.
    ctx.minimum_version = TLSVersion.TLSv1
    ctx.maximum_version = TLSVersion.TLSv1_2
    return ctx


#: What `http.client` uses when no context is given. The standard
#: library lets an application replace this to change every HTTPS
#: connection it makes, and code in the wild does exactly that - so it
#: is a module attribute here too, defined last because it names a
#: function defined above.
_create_default_https_context = create_default_context
