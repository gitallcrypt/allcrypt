"""The SSH server's Python surface, and OpenSSH's `ssh` against it when
one is installed.

The server against OpenSSH is checked elsewhere as well: by
`tests/test_ssh_server_sessions.rs`, which replays fifteen sessions with
OpenSSH 10.0's and 7.4's `ssh` byte for byte, and by
`scripts/check_ssh_server.py`, which runs every algorithm live. Here the
binding is driven by our own client in memory and over a loopback
socket - and, if an OpenSSH `ssh` is on this machine, by that, on
127.0.0.1.
"""

import os
import shutil
import socket
import subprocess
import threading

import pytest

import allcrypt
import allcrypt_ssh

HOST = allcrypt.SshKey.generate("ed25519")
ALICE = allcrypt.SshKey.generate("ed25519")


def pump(client, server, app=lambda server: None, rounds=500):
    for _ in range(rounds):
        up = client.take_outgoing()
        if up:
            server.push_incoming(up)
            server.process()
        app(server)
        down = server.take_outgoing()
        if down:
            client.push_incoming(down)
            client.process()
        if not up and not down:
            return


def upper(server):
    """Standard input, upper-cased, once it is complete."""
    if server.request is None:
        return
    upper.data = getattr(upper, "data", b"") + server.take_stdin()
    if server.stdin_closed and not getattr(upper, "done", False):
        upper.done = True
        server.write(upper.data.upper())
        server.write_stderr(b"to stderr\n")
        server.finish(3)


def test_our_client_and_server_in_memory():
    upper.data, upper.done = b"", False
    server = allcrypt.SshServer([HOST], authorized=[("alice", ALICE.public_key())])
    client = allcrypt.SshClient("alice", host_key=HOST.public_key(), keys=[ALICE])
    client.exec("upper")
    pump(client, server, upper)
    client.write(b"quiet words")
    client.send_eof()
    pump(client, server, upper)
    assert client.take_stdout() == b"QUIET WORDS"
    assert client.take_stderr() == b"to stderr\n"
    assert client.exit_status == 3
    assert client.closed and server.closed
    assert server.user == "alice"
    assert server.auth_method == "publickey ssh-ed25519"
    assert server.request == ("exec", "upper")
    assert server.strict_kex and server.key_exchanges == 1
    assert server.client_version.startswith("SSH-2.0-allcrypt_")
    assert server.algorithms() == client.algorithms()
    assert server.algorithms()["kex"] == "mlkem768x25519-sha256"


def test_a_password_and_a_refusal():
    server = allcrypt.SshServer([HOST], authorized=[("bob", "hunter2")])
    client = allcrypt.SshClient("bob", host_key=HOST.public_key(), password="hunter2")
    client.exec("x")
    pump(client, server, lambda s: s.request and not s.closed and s.finish(0))
    assert server.auth_method == "password" and client.exit_status == 0

    server = allcrypt.SshServer([HOST], authorized=[("bob", "hunter2")])
    client = allcrypt.SshClient("bob", host_key=HOST.public_key(), password="hunter3")
    with pytest.raises(allcrypt.CryptoError, match="would take password"):
        pump(client, server)


def test_legacy_algorithms_are_reached_by_naming_them():
    server = allcrypt.SshServer([HOST], authorized=[("bob", "pw")],
                                kex=["diffie-hellman-group1-sha1"], ciphers=["3des-cbc"],
                                macs=["hmac-md5"])
    client = allcrypt.SshClient("bob", host_key=HOST.public_key(), password="pw",
                                kex=["diffie-hellman-group1-sha1"], ciphers=["3des-cbc"],
                                macs=["hmac-md5"])
    client.exec("x")
    pump(client, server, lambda s: s.request and not s.closed and s.finish(0))
    assert server.algorithms()["cipher_client_to_server"] == "3des-cbc"
    assert server.algorithms()["mac_server_to_client"] == "hmac-md5"


def test_authorized_entries_are_keys_or_passwords():
    with pytest.raises(TypeError):
        allcrypt.SshServer([HOST], authorized=[("alice", 42)])
    with pytest.raises(allcrypt.CryptoError, match="host key"):
        allcrypt.SshServer([])


def test_serve_and_run_over_a_socket():
    """`allcrypt_ssh.serve` on one side of a loopback socket and
    `allcrypt_ssh.run` on the other."""
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    served = {}

    def handler(command, stdin):
        return f"{command}: {len(stdin)} bytes\n".encode(), b"", 5

    def accept():
        sock, _ = listener.accept()
        server = allcrypt.SshServer([HOST], authorized=[("alice", ALICE.public_key())])
        served["server"] = allcrypt_ssh.serve(sock, server, handler)

    thread = threading.Thread(target=accept)
    thread.start()
    try:
        result = allcrypt_ssh.run("127.0.0.1", "count", port=port, user="alice", keys=[ALICE],
                                  host_key=HOST.public_key(), stdin=b"x" * 100_000)
    finally:
        thread.join(timeout=30)
        listener.close()
    assert result.exit_status == 5
    assert result.stdout == b"count: 100000 bytes\n"
    assert served["server"].user == "alice"


def openssh_client():
    for candidate in (shutil.which("ssh"), "/opt/openssh/bin/ssh"):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


@pytest.mark.skipif(os.name != "posix" or openssh_client() is None,
                    reason="no OpenSSH ssh client here")
@pytest.mark.parametrize("options", [
    [],
    ["KexAlgorithms=curve25519-sha256", "Ciphers=aes128-ctr",
     "MACs=hmac-sha2-256-etm@openssh.com", "HostKeyAlgorithms=ssh-ed25519"],
    ["KexAlgorithms=ecdh-sha2-nistp256", "Ciphers=aes256-gcm@openssh.com",
     "RekeyLimit=16K"],
], ids=["defaults", "x25519-ctr-etm", "nistp256-gcm-rekeying"])
def test_openssh_ssh_against_our_server(tmp_path, options):
    """The installed OpenSSH client, on 127.0.0.1, checking our host key
    against a known_hosts entry and authenticating with a key file."""
    ssh = openssh_client()
    key_path = tmp_path / "id_ed25519"
    key_path.write_text(ALICE.to_openssh())
    key_path.chmod(0o600)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    known = tmp_path / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {HOST.public_key().to_line()}\n")
    served = {}

    def accept():
        sock, _ = listener.accept()
        server = allcrypt.SshServer([HOST], authorized=[("alice", ALICE.public_key())])
        try:
            served["server"] = allcrypt_ssh.serve(
                sock, server, lambda command, stdin: (stdin[::-1], b"err\n", 9))
        except Exception as error:  # noqa: BLE001 - the test reports it
            served["error"] = error

    thread = threading.Thread(target=accept)
    thread.start()
    data = bytes(range(256)) * 200
    try:
        argv = [ssh, "-F", "/dev/null", "-p", str(port), "-i", str(key_path),
                "-o", f"UserKnownHostsFile={known}", "-o", "StrictHostKeyChecking=yes",
                "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"]
        for option in options:
            argv += ["-o", option]
        run = subprocess.run(argv + ["alice@127.0.0.1", "reverse"], input=data,
                             capture_output=True, timeout=60)
    finally:
        thread.join(timeout=30)
        listener.close()
    assert "error" not in served, served.get("error")
    assert run.returncode == 9, run.stderr
    assert run.stdout == data[::-1]
    assert run.stderr == b"err\n"
    server = served["server"]
    assert server.auth_method == "publickey ssh-ed25519"
    assert server.client_version.startswith("SSH-2.0-OpenSSH_")
    if "RekeyLimit=16K" in options:
        assert server.key_exchanges > 1
