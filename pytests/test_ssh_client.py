"""The SSH client's Python surface.

The client's behaviour against a real server is checked elsewhere: by
`tests/test_ssh_sessions.rs`, which replays fourteen recorded sessions
with OpenSSH's sshd byte for byte, and by `scripts/check_ssh_client.py`,
which runs every algorithm against sshd live. Neither can run here
(there is no sshd in the gate), so these check the binding: what it
sends first, what it refuses before any key exchange, and its argument
handling.
"""

import pytest

import allcrypt


def kexinit_names(packet):
    """The ten name-lists of the first KEXINIT in `packet`."""
    payload = packet[5:]
    assert payload[0] == 20                      # SSH_MSG_KEXINIT
    at, names = 17, []
    for _ in range(10):
        length = int.from_bytes(payload[at:at + 4], "big")
        names.append(payload[at + 4:at + 4 + length].decode().split(","))
        at += 4 + length
    return names


def first_flight(**kwargs):
    client = allcrypt.SshClient("user", **kwargs)
    out = client.take_outgoing()
    line, _, packet = out.partition(b"\r\n")
    return client, line, packet


def test_the_first_flight_is_a_version_line_and_a_kexinit():
    client, line, packet = first_flight()
    assert line.startswith(b"SSH-2.0-allcrypt_")
    kex, host_keys, ciphers, _, macs, _, compression, _, _, _ = kexinit_names(packet)
    # Post-quantum first, then the classical methods; and the two
    # markers RFC 8308 and strict key exchange add to the first KEXINIT.
    assert kex[0] == "mlkem768x25519-sha256"
    assert "ext-info-c" in kex and "kex-strict-c-v00@openssh.com" in kex
    # Nothing legacy unless asked for.
    assert "diffie-hellman-group1-sha1" not in kex
    assert "ssh-rsa" not in host_keys and "3des-cbc" not in ciphers
    assert ciphers[0] == "chacha20-poly1305@openssh.com"
    assert compression == ["none"]
    assert not client.authenticated and not client.closed


def test_legacy_algorithms_are_reached_by_naming_them():
    _, _, packet = first_flight(kex=["diffie-hellman-group1-sha1"], ciphers=["3des-cbc"],
                                macs=["hmac-md5"], host_key_algorithms=["ssh-rsa"])
    kex, host_keys, ciphers, _, macs, _, _, _, _, _ = kexinit_names(packet)
    assert kex[0] == "diffie-hellman-group1-sha1"
    assert (host_keys, ciphers, macs) == (["ssh-rsa"], ["3des-cbc"], ["hmac-md5"])


def test_an_ssh1_server_is_refused():
    client, _, _ = first_flight()
    client.push_incoming(b"SSH-1.5-OldServer\r\n")
    with pytest.raises(allcrypt.CryptoError, match="not SSH 2"):
        client.process()


def test_lines_before_the_version_are_skipped():
    # RFC 4253 4.2 allows a server to send text before its version line.
    client, _, _ = first_flight()
    client.push_incoming(b"Welcome to the box\r\nAuthorised use only\r\n")
    client.process()
    client.push_incoming(b"SSH-2.0-Test\r\n")
    client.process()
    assert client.server_version == "SSH-2.0-Test"


def test_host_key_argument_types():
    key = allcrypt.SshKey.generate("ed25519")
    allcrypt.SshClient("u", host_key=key.public_key())
    allcrypt.SshClient("u", host_key=key.public_key().fingerprint())
    with pytest.raises(TypeError):
        allcrypt.SshClient("u", host_key=42)
