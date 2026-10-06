"""Shared setup, and one rule the whole suite is held to.

**No test in this directory may use the network.** Not "should not" - may
not. Every connection to anything but loopback raises, for every test,
always.

This is enforced rather than documented because the failure mode is
invisible. A test that quietly reaches the internet passes on the machine
that wrote it and fails in CI, on a plane, behind a corporate proxy, or on
the day the host it depended on goes away - and by then nobody remembers
which test it was. Worse, a proxy that intercepts TLS can make such a test
*pass* while proving nothing at all, which this project has already been
bitten by.

If a test needs a server, it starts one on 127.0.0.1. That is what every
test here already does.

Checking against real servers is a development activity, not a test. It
lives in `scripts/check_live.py`, which is run by hand.
"""

import os
import socket
import sys

import pytest

# Where scripts/build_python.py puts the module, so `python3 -m pytest`
# works from a clean checkout with nothing on PYTHONPATH. Appended rather
# than inserted: an installed copy, or one the caller pointed at, wins.
_BUILT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "python")
if os.path.isdir(_BUILT) and _BUILT not in sys.path:
    sys.path.append(_BUILT)

#: Where a test is allowed to connect. Loopback in both families, and the
#: name for it - some libraries resolve "localhost" themselves rather than
#: handing over an address.
_ALLOWED = {"127.0.0.1", "::1", "localhost", "ip6-localhost"}

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _address_is_local(address):
    """Loopback, or something that is not an IP connection at all.

    A unix socket address is a path, and an `AF_UNIX` connection does not
    leave the machine, so there is nothing to block.
    """
    if not isinstance(address, tuple) or not address:
        return True
    host = address[0]
    if not isinstance(host, str):
        return True
    return host in _ALLOWED


def _blocked(address):
    return pytest.fail(
        f"This test tried to connect to {address!r}.\n\n"
        f"No test in pytests/ may use the network - see the note at the top "
        f"of conftest.py. A test that reaches the internet passes on one "
        f"machine and fails on another, and behind a TLS-intercepting proxy "
        f"it can pass while proving nothing.\n\n"
        f"Start a server on 127.0.0.1, as every other test here does. To "
        f"check against real servers, use scripts/check_live.py, which is a "
        f"development tool rather than a test.",
        pytrace=False)


@pytest.fixture(autouse=True, scope="session")
def _no_network():
    """Block every non-loopback connection, for the whole session."""

    def connect(self, address):
        if not _address_is_local(address):
            _blocked(address)
        return _real_connect(self, address)

    def connect_ex(self, address):
        if not _address_is_local(address):
            _blocked(address)
        return _real_connect_ex(self, address)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    try:
        yield
    finally:
        socket.socket.connect = _real_connect
        socket.socket.connect_ex = _real_connect_ex
