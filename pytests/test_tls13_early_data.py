"""TLS 1.3 early data (0-RTT), against the real `openssl` binary.

**Python's `ssl` module has no early-data API at all** - no
`SSL_write_early_data`, no `SSL_read_early_data`, nothing - so the memory
BIO harness every other file here uses cannot reach this feature. The only
independent implementation on the machine that can is the `openssl`
command line tool, which has `s_client -early_data` and
`s_server -early_data`. So these tests run it as a subprocess over a
loopback socket, the way `test_proxy.py` runs the real proxy binary.

It matters that they do. 0-RTT is derived entirely from the *previous*
connection - the suite, the hash, the PSK and a transcript that is one
ClientHello long - so every value in it can be wrong in the same way at
both of our ends and they will agree perfectly. `src/tls/server.rs` has a
round trip between our own client and our own server, and what it settles
is the wiring: that the writer changes keys three times in the right
order, that the server holds its handshake keys back. It cannot settle a
single byte.

**No network.** Everything is 127.0.0.1; `conftest.py` raises on anything
else.
"""

import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time

import pytest

from cryptography.hazmat.primitives import serialization

import allcrypt

from test_tls_server import ec_identity

NOW = int(time.time())
PEM = serialization.Encoding.PEM
DER = serialization.Encoding.DER
# Eight bytes of key name, thirty-two of key. Shared between the two
# connections in a test, because resumption is between two of them and a
# per-connection key seals tickets nothing else can open.
TICKET_KEY = bytes(range(40))
EARLY = b"GET /early HTTP/1.0\r\n\r\n"


def openssl():
    path = shutil.which("openssl")
    if path is None:
        pytest.skip("openssl is not installed")
    return path


def has_early_data_support():
    """`-early_data` is OpenSSL 1.1.1 and later.

    Checked rather than assumed, because an older tool would fail these
    tests with an unrecognised-option error that reads exactly like a
    protocol bug.
    """
    for tool in ("s_client", "s_server"):
        help_text = subprocess.run([openssl(), tool, "-help"],
                                   capture_output=True, text=True).stderr
        if "-early_data" not in help_text:
            return False
    return True


# ----------------------------------------------- our server, on a socket ---

class OurServer:
    """`allcrypt.TlsServer` behind a real listening socket.

    A socket rather than memory BIOs because the peer is a separate
    process. One connection is served per `accept`, on its own thread,
    and what it saw is recorded for the test to assert on.
    """

    def __init__(self, replay_guard=None, **options):
        # One register for every connection this server serves. A fresh
        # one per connection has seen nothing, which is the whole reason
        # it is an object passed in rather than a number.
        self.replay_guard = replay_guard
        self.key, certificate = ec_identity()
        self.chain = [certificate.public_bytes(DER)]
        self.pem = certificate.public_bytes(PEM).decode()

        handle = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        handle.write(self.pem)
        handle.close()
        self.ca_path = handle.name

        self.options = dict(now=NOW, min_version="TLSv1.3",
                            max_version="TLSv1.3", session_tickets=2,
                            ticket_key=TICKET_KEY)
        self.options.update(options)
        if replay_guard is not None:
            self.options["replay_guard"] = replay_guard

        self.early_data = []          # one entry per connection served
        self.accepted = []
        self.errors = []

        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                raw, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,),
                             daemon=True).start()

    def _handle(self, raw):
        connection = allcrypt.TlsServer(self.chain, self.key, **self.options)
        raw.settimeout(5)
        early = b""
        try:
            while not connection.established:
                chunk = raw.recv(16384)
                if not chunk:
                    break
                connection.push_incoming(chunk)
                connection.process()
                early += connection.take_early_data()
                out = connection.take_outgoing()
                if out:
                    raw.sendall(out)
            early += connection.take_early_data()
            self.accepted.append(connection.accepted_early_data)
            self.early_data.append(early)
            if connection.established:
                # A reply, so the client has something to wait for and
                # the ticket has somewhere to ride out on.
                connection.write(b"HTTP/1.0 200 OK\r\n\r\nhello")
                raw.sendall(connection.take_outgoing())
                time.sleep(0.2)
        except Exception as reason:                       # noqa: BLE001
            self.errors.append(reason)
            self.accepted.append(False)
            self.early_data.append(early)
        finally:
            try:
                raw.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        try:
            self._listener.close()
        except OSError:
            pass
        try:
            os.unlink(self.ca_path)
        except OSError:
            pass


def s_client(server, session_path, *, early_file=None, timeout=15):
    """One `openssl s_client` connection to `server`.

    Without `early_file` it stores the session it was given; with one it
    offers that session back and sends the file as early data.
    """
    command = [openssl(), "s_client", "-connect", f"127.0.0.1:{server.port}",
               "-servername", "localhost", "-CAfile", server.ca_path,
               "-tls1_3", "-ign_eof"]
    if early_file:
        command += ["-sess_in", session_path, "-early_data", early_file]
    else:
        command += ["-sess_out", session_path]
    return subprocess.run(command, input=b"" if early_file else b"\n",
                          capture_output=True, timeout=timeout)


def warm_up(server, session_path):
    """A full handshake, so `s_client` has a ticket to offer.

    `s_client` writes the session file when the connection closes, and a
    TLS 1.3 ticket arrives *after* the handshake - so a connection that
    hangs up immediately stores a session with no ticket in it, and the
    0-RTT attempt then silently becomes an ordinary handshake and the
    test passes for the wrong reason.
    """
    result = s_client(server, session_path)
    assert os.path.exists(session_path), result.stderr.decode()[-2000:]
    return result


@pytest.fixture
def workspace(tmp_path):
    if not has_early_data_support():
        pytest.skip("this openssl has no -early_data")
    session = str(tmp_path / "session.pem")
    early = str(tmp_path / "early.txt")
    with open(early, "wb") as handle:
        handle.write(EARLY)
    return session, early


# ----------------------------------------------------- our server accepts ---

def test_an_openssl_client_sends_early_data(workspace):
    """The one that matters for our server.

    OpenSSL derived the early traffic secret itself, from the PSK inside
    a ticket we sealed, over a transcript one ClientHello long - and we
    decrypted what it wrote. Nothing on our side of the wire can say
    that: our own client makes every one of those choices the same way
    we do.
    """
    session, early = workspace
    server = OurServer(max_early_data=16384,
                       replay_guard=allcrypt.ReplayGuard())
    try:
        warm_up(server, session)
        result = s_client(server, session, early_file=early)
        assert not server.errors, server.errors
        assert server.accepted[-1], (
            "the server did not accept the early data: "
            + result.stderr.decode()[-2000:])
        assert server.early_data[-1] == EARLY
        assert b"Early data was accepted" in result.stdout + result.stderr
    finally:
        server.close()


def test_a_server_with_early_data_off_still_connects(workspace):
    """**The case the skip is for.**

    The client has already written those records under keys this server
    never derived. RFC 8446 4.2.10 says to discard them and carry on;
    failing on the first one would mean 0-RTT could be forbidden but
    never *declined*. Less obviously, a discarded record must not advance
    the reader's sequence number, or the client's real Finished decrypts
    under the wrong nonce - which looks like a completely different bug.
    """
    session, early = workspace
    # **Two servers, and the ticket comes from the first.** A client only
    # sends early data when the ticket it holds allows it, so a server
    # that never offered any is never *offered* any either - the reject
    # path would be unreachable, and a test written against one server
    # would pass while proving nothing. The two share `TICKET_KEY`, which
    # is what a restart with a changed configuration looks like.
    issuer = OurServer(max_early_data=16384,
                       replay_guard=allcrypt.ReplayGuard())
    refuser = OurServer()                     # max_early_data defaults to 0
    try:
        warm_up(issuer, session)
        result = s_client(refuser, session, early_file=early)
        assert not refuser.errors, refuser.errors
        assert not refuser.accepted[-1]
        assert refuser.early_data[-1] == b""
        # The handshake still finished, which is the whole point: the
        # records we could not read were discarded rather than fatal.
        assert b"Early data was rejected" in result.stdout + result.stderr
    finally:
        issuer.close()
        refuser.close()


def test_a_replayed_flight_is_accepted_once(workspace):
    """Byte for byte, twice.

    Not two honest connections offering the same ticket - those have
    different binders and are both legitimate. This captures one 0-RTT
    flight and sends the identical bytes again, which is what a replay
    is, and the second copy must not be accepted as early data. The
    handshake is still answered: a full 1-RTT handshake is always a
    correct answer to a 0-RTT attempt, and an alert would tell an
    attacker their replay reached a machine that remembers.
    """
    session, early = workspace
    # **The capture happens against a different server.** Recording a
    # flight means serving it, and serving it is what puts the binder in
    # the register - so capturing against the server under test would
    # spend the first copy and both replays would be refused, which
    # looks like the guard working and is the test proving nothing.
    # `TICKET_KEY` is shared, so the ticket opens at either.
    recorder = OurServer(max_early_data=16384,
                         replay_guard=allcrypt.ReplayGuard(1))
    guard = allcrypt.ReplayGuard(64)
    server = OurServer(max_early_data=16384, replay_guard=guard)
    try:
        warm_up(recorder, session)
        flight = capture_flight(recorder, session, early)
        assert flight, "nothing was captured"
        assert recorder.accepted and recorder.accepted[-1], (
            "the flight that was captured was not itself accepted, so it is "
            "not a 0-RTT flight")

        replay(server, flight)
        replay(server, flight)
        assert server.accepted[-2] != server.accepted[-1], (
            "both copies of one flight got the same answer")
        assert server.accepted[-2] and not server.accepted[-1]
        assert server.early_data[-2] == EARLY
        assert server.early_data[-1] == b""
    finally:
        recorder.close()
        server.close()


def test_more_early_data_than_the_ticket_allows_is_refused(tmp_path, workspace):
    """The limit is the server's promise about how much it will process.

    Truncating silently would be a request that half happened, so the
    connection is refused instead (RFC 8446 4.2.10). The limit here is
    tiny so one record exceeds it.
    """
    session, _ = workspace
    big = str(tmp_path / "big.txt")
    with open(big, "wb") as handle:
        handle.write(b"x" * 4096)
    # **An honest client never exceeds the limit**, because the ticket
    # told it what the limit was - so the only way to reach this check is
    # for the limit to have *changed* since the ticket was issued, which
    # is a configuration change between two connections and a thing that
    # really happens. The ticket says 16384; this server now says 64.
    issuer = OurServer(max_early_data=16384,
                       replay_guard=allcrypt.ReplayGuard())
    server = OurServer(max_early_data=64,
                       replay_guard=allcrypt.ReplayGuard())
    try:
        warm_up(issuer, session)
        s_client(server, session, early_file=big)
        assert server.errors, "the server accepted more than it promised"
        assert "early data" in str(server.errors[-1]), server.errors[-1]
    finally:
        issuer.close()
        server.close()


def capture_flight(server, session_path, early_file):
    """Record exactly what `s_client` sends before it hears anything.

    A relay rather than a patched client: the bytes have to be the ones
    that crossed the wire, and a reconstruction would be our own code
    again.
    """
    captured = bytearray()
    relay = socket.socket()
    relay.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay.bind(("127.0.0.1", 0))
    relay.listen(1)
    port = relay.getsockname()[1]

    def pump():
        client, _ = relay.accept()
        client.settimeout(5)
        upstream = socket.create_connection(("127.0.0.1", server.port))
        upstream.settimeout(5)
        first = True
        def forward(source, sink, record):
            nonlocal first
            try:
                while True:
                    chunk = source.recv(16384)
                    if not chunk:
                        break
                    if record and first:
                        captured.extend(chunk)
                    sink.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    sink.close()
                except OSError:
                    pass
        # The client's first write is the whole 0-RTT flight: the
        # ClientHello, the compatibility ChangeCipherSpec and the early
        # records, all before it has heard a word.
        try:
            chunk = client.recv(16384)
            captured.extend(chunk)
            upstream.sendall(chunk)
        except OSError:
            pass
        threading.Thread(target=forward, args=(client, upstream, False),
                         daemon=True).start()
        forward(upstream, client, False)

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()

    class Proxy:
        pass
    proxy = Proxy()
    proxy.port = port
    proxy.ca_path = server.ca_path
    s_client(proxy, session_path, early_file=early_file)
    thread.join(timeout=10)
    relay.close()
    return bytes(captured)


def replay(server, flight):
    """Send a captured flight verbatim and read whatever comes back."""
    raw = socket.create_connection(("127.0.0.1", server.port))
    # Shorter than the server's own read timeout, so this end hangs up
    # first: a socket left open until the server times out makes the
    # server record a timeout rather than a decision.
    raw.settimeout(1)
    try:
        raw.sendall(flight)
        deadline = time.time() + 1.5
        while time.time() < deadline:
            try:
                if not raw.recv(16384):
                    break
            except socket.timeout:
                break
    except OSError:
        pass
    finally:
        raw.close()
    time.sleep(0.4)


# ------------------------------------------------------ our client sends ---

class OpensslServer:
    """`openssl s_server` with early data switched on.

    It serves `count` connections and then exits, which is how the two
    halves of a resumption test get the same process - and the same
    ticket key - without the test having to manage one.
    """

    def __init__(self, tmp_path, count=2, max_early_data=16384,
                 extra=()):
        key, certificate = ec_identity()
        identity = tmp_path / "s_server.pem"
        # `ec_identity` hands back our own key object, so the PEM has to
        # come from `cryptography`'s side of the pair.
        from test_tls_server import make_cert
        from cryptography.hazmat.primitives.asymmetric import ec as pyec
        private = pyec.generate_private_key(pyec.SECP256R1())
        certificate = make_cert(private)
        identity.write_bytes(
            certificate.public_bytes(PEM)
            + private.private_bytes(PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
        self.ca_pem = certificate.public_bytes(PEM).decode()

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        self.port = listener.getsockname()[1]
        listener.close()

        command = [openssl(), "s_server", "-accept", str(self.port),
                   "-cert", str(identity), "-tls1_3", "-naccept", str(count),
                   "-early_data", "-max_early_data", str(max_early_data),
                   "-no_anti_replay"]
        command += list(extra)
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)

        # **Wait for it to say ACCEPT, not for the port to answer.**
        # `-naccept` counts connections, and a probe that opens one and
        # closes it spends one of them - so the test's own first
        # connection is then refused, which reads exactly like the
        # server having crashed.
        self._output = []
        self._listening = threading.Event()
        def drain(stream):
            for line in iter(stream.readline, b""):
                self._output.append(line)
                if line.startswith(b"ACCEPT"):
                    self._listening.set()
            stream.close()
        for stream in (self.process.stdout, self.process.stderr):
            threading.Thread(target=drain, args=(stream,), daemon=True).start()
        if not self._listening.wait(timeout=10):
            raise AssertionError("s_server never started listening: "
                                 + b"".join(self._output).decode())

    def finish(self, timeout=15):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        time.sleep(0.2)                 # let the drain threads catch up
        return b"".join(self._output)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def run_client(port, ca_pem, *, tickets=(), early_data=None):
    """One `allcrypt.TlsClient` connection over a real socket.

    `early_data=None` **omits the argument** rather than passing empty
    bytes, so the binding's own default is what decides. That is the
    only way the default is ever exercised - a helper that always passed
    something would make a wrong default unreachable, which is what
    `test_a_client_that_did_not_ask_for_0rtt_does_not_get_it` is for.
    """
    roots = allcrypt.TrustStore()
    roots.add_pem(ca_pem)
    extra = {} if early_data is None else {"early_data": early_data}
    client = allcrypt.TlsClient("localhost", roots, now=NOW,
                                min_version="TLSv1.3", max_version="TLSv1.3",
                                tickets=list(tickets),
                                **extra)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    raw.settimeout(5)
    try:
        raw.sendall(client.take_outgoing())
        deadline = time.time() + 5
        while not client.established and time.time() < deadline:
            chunk = raw.recv(16384)
            if not chunk:
                break
            client.push_incoming(chunk)
            client.process()
            out = client.take_outgoing()
            if out:
                raw.sendall(out)
        if client.established:
            client.write(b"after the handshake\n")
            raw.sendall(client.take_outgoing())
            # Give the tickets a chance to arrive; they come under the
            # application keys, so they are behind the first read.
            raw.settimeout(1.5)
            for _ in range(3):
                try:
                    chunk = raw.recv(16384)
                except socket.timeout:
                    break
                if not chunk:
                    break
                client.push_incoming(chunk)
                client.process()
    finally:
        raw.close()
    return client


def test_we_send_early_data_to_an_openssl_server(tmp_path):
    """The one that matters for our client.

    `s_server` read our 0-RTT records with keys it derived itself, from
    a PSK inside a ticket it issued, over a transcript it built from our
    ClientHello - and then accepted our EndOfEarlyData and our Finished
    over a transcript that includes it. Our own server would have agreed
    with us whatever we did.
    """
    if not has_early_data_support():
        pytest.skip("this openssl has no -early_data")
    server = OpensslServer(tmp_path, count=2)
    try:
        first = run_client(server.port, server.ca_pem)
        assert first.established
        tickets = first.take_tickets()
        assert tickets, "s_server issued no ticket"

        second = run_client(server.port, server.ca_pem, tickets=tickets[:1],
                            early_data=EARLY)
        assert second.established, second.state
        assert second.resumed
        assert second.early_data_accepted, "s_server did not take the early data"
    finally:
        output = server.finish()
        server.close()
    assert EARLY.split(b"\r\n")[0] in output, output[-2000:]
    # **And the data sent *after* the handshake.** That is the assertion
    # with teeth: early data is printed by `s_server` before it has
    # checked anything, and `established` is our own opinion - we set it
    # when we write our Finished, not when the server accepts it. Only a
    # record the server decrypted under the application keys says our
    # Finished was right, and the Finished covers the transcript
    # including EndOfEarlyData.
    assert b"after the handshake" in output, output[-2000:]


def test_a_client_that_did_not_ask_for_0rtt_does_not_get_it(tmp_path):
    """The default, on the one path where it is observable.

    A resumption to a server that *does* allow early data, with the
    argument omitted. Every other test here passes `early_data`
    explicitly, and a first connection has no ticket, so a default of
    anything other than empty bytes is inert everywhere else - it would
    send a caller's connection bytes they never wrote and nothing would
    say so. Setting the default to a single byte passes 2092 tests and
    fails this one.
    """
    if not has_early_data_support():
        pytest.skip("this openssl has no -early_data")
    server = OpensslServer(tmp_path, count=2)
    try:
        first = run_client(server.port, server.ca_pem)
        tickets = first.take_tickets()
        assert tickets, "s_server issued no ticket"

        second = run_client(server.port, server.ca_pem, tickets=tickets[:1])
        assert second.established, second.state
        assert second.resumed
        assert not second.early_data_accepted, (
            "the server took early data this client never offered")
    finally:
        output = server.finish()
        server.close()
    assert b"after the handshake" in output, output[-2000:]
    assert b"Early data" not in output, output[-2000:]


def test_a_server_that_declines_leaves_us_connected(tmp_path):
    """Declining is not failing.

    `-max_early_data 0` makes `s_server` advertise none, so our client
    offers none either - the ticket says it is not allowed - and the
    handshake is an ordinary resumption. What this asserts is that
    `early_data_accepted` says so, because a caller has to resend those
    bytes itself and a client that quietly reported success would lose
    them.
    """
    if not has_early_data_support():
        pytest.skip("this openssl has no -early_data")
    server = OpensslServer(tmp_path, count=2, max_early_data=0)
    try:
        first = run_client(server.port, server.ca_pem)
        tickets = first.take_tickets()
        assert tickets
        assert all(t is not None for t in tickets)

        second = run_client(server.port, server.ca_pem, tickets=tickets[:1],
                            early_data=EARLY)
        assert second.established
        assert second.resumed
        assert not second.early_data_accepted
    finally:
        output = server.finish()
        server.close()
    assert b"after the handshake" in output, output[-2000:]
