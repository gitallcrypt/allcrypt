"""Run a command over SSH with allcrypt's client, or serve one with its
server, over a socket.

``allcrypt.SshClient`` is sans-I/O; this is the loop that connects it to
a socket::

    import allcrypt, allcrypt_ssh

    key = allcrypt.SshKey.from_openssh(open("id_ed25519").read())
    result = allcrypt_ssh.run("switch.example", "show version", user="admin",
                              keys=[key], host_key="SHA256:...")
    print(result.exit_status, result.stdout.decode())

``host_key`` is what the server must present - an ``SshPublicKey`` or a
fingerprint string. Leaving it out accepts any key, and the one seen is
in ``result.host_key`` to pin for next time; that is a first connection,
not a habit.

An old device that offers nothing current is reached by naming what it
does offer::

    allcrypt_ssh.run("ups.local", "status", user="admin", password="...",
                     kex=["diffie-hellman-group1-sha1"], ciphers=["3des-cbc"],
                     macs=["hmac-sha1"], host_key_algorithms=["ssh-rsa"])

``serve`` is the other end: one connection to an ``allcrypt.SshServer``,
with a function deciding what each command does::

    def handler(command, stdin):
        return b"you sent %d bytes\n" % len(stdin), b"", 0

    host = allcrypt.SshKey.from_openssh(open("ssh_host_ed25519_key").read())
    listener = socket.create_server(("127.0.0.1", 2222))
    sock, _ = listener.accept()
    server = allcrypt.SshServer([host], authorized=[("alice", alice_public_key)])
    allcrypt_ssh.serve(sock, server, handler)
"""

import socket
from collections import namedtuple

import allcrypt

Result = namedtuple("Result", "exit_status stdout stderr host_key algorithms")


def run(host, command, *, port=22, user, keys=(), password=None, host_key=None,
        timeout=30, stdin=None, kex=None, ciphers=None, macs=None,
        host_key_algorithms=None):
    """Connect, authenticate, run ``command``, and return its result.

    ``stdin`` is bytes to send to the command, after which its input is
    closed. Raises ``allcrypt.CryptoError`` for anything SSH refuses -
    the host key not matching, no algorithm in common, authentication
    failing - and ``OSError`` for the network.
    """
    client = allcrypt.SshClient(user, host_key=host_key, keys=list(keys),
                                password=password, kex=kex, ciphers=ciphers,
                                macs=macs, host_key_algorithms=host_key_algorithms)
    client.exec(command)
    stdout, stderr = bytearray(), bytearray()
    sent_stdin = stdin is None
    with socket.create_connection((host, port), timeout=timeout) as sock:
        while True:
            out = client.take_outgoing()
            if out:
                sock.sendall(out)
            if client.closed:
                break
            data = sock.recv(65536)
            if not data:
                break
            client.push_incoming(data)
            client.process()
            if not sent_stdin and client.authenticated:
                client.write(stdin)
                client.send_eof()
                sent_stdin = True
            stdout += client.take_stdout()
            stderr += client.take_stderr()
    return Result(client.exit_status, bytes(stdout), bytes(stderr), client.host_key,
                  client.algorithms())


def serve(sock, server, handler, *, timeout=60):
    """Serve one connection on the connected socket ``sock``.

    Once the client has asked for a command and closed its input,
    ``handler(command, stdin)`` is called - ``command`` is ``None`` for a
    shell - and returns ``(stdout, stderr, exit_status)``, which go back
    to the client. Returns ``server`` for its ``user``, ``auth_method``
    and the rest. Raises ``allcrypt.CryptoError`` for anything SSH
    refuses, after the DISCONNECT saying why has been sent.
    """
    stdin = bytearray()
    answered = False
    sock.settimeout(timeout)
    with sock:
        while True:
            out = server.take_outgoing()
            if out:
                sock.sendall(out)
            data = sock.recv(65536)
            if not data:
                break
            server.push_incoming(data)
            try:
                server.process()
            except allcrypt.CryptoError:
                sock.sendall(server.take_outgoing())
                raise
            if server.request is not None:
                stdin += server.take_stdin()
                if server.stdin_closed and not answered:
                    answered = True
                    _, command = server.request
                    stdout, stderr, status = handler(command, bytes(stdin))
                    server.write(stdout)
                    server.write_stderr(stderr)
                    server.finish(status)
    return server
