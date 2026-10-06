"""The guard in conftest.py, tested.

A guard that silently stopped working would look exactly like a suite that
never used the network, which is the whole problem it exists to prevent -
so it needs a test of its own, in a file pytest actually collects.
(`conftest.py` is imported for its fixtures; tests written in it are not
collected, which is a quiet way to have a test that never runs.)
"""

import socket

import pytest


def test_the_network_guard_blocks_the_internet():
    with pytest.raises(BaseException) as caught:
        socket.create_connection(("example.com", 80), timeout=1)
    assert "may use the network" in str(caught.value)


def test_the_network_guard_blocks_by_address_not_by_name():
    """A literal address must be blocked too, or the guard is a DNS filter
    rather than a network one."""
    with pytest.raises(BaseException) as caught:
        socket.create_connection(("93.184.216.34", 80), timeout=1)
    assert "may use the network" in str(caught.value)


def test_loopback_still_works():
    """Or every other test in this suite would fail for the wrong reason."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        with socket.create_connection(listener.getsockname(), timeout=5):
            pass
    finally:
        listener.close()


def test_connect_ex_is_guarded_too():
    """`connect_ex` returns an error code rather than raising, so a guard
    that only wrapped `connect` would leave an unblocked way out."""
    sock = socket.socket()
    try:
        with pytest.raises(BaseException) as caught:
            sock.connect_ex(("example.com", 80))
        assert "may use the network" in str(caught.value)
    finally:
        sock.close()
