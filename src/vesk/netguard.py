"""Process-wide network guard: refuse sockets to anything but an allowed set of hosts.

Used by `vesk scan --offline` and by the no-telemetry test. DNS lookups for names that are
not allowed fail before any packet is sent; connects to addresses that were not resolved from
an allowed name (or are not an allowed literal) are refused.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from urllib.parse import urlsplit


class NetworkBlocked(OSError):
    """Raised when something tries to reach a host the guard does not allow."""


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def is_local_host(host: str) -> bool:
    """True for localhost and loopback / private IP literals (no DNS involved)."""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


@contextmanager
def guard(allowed: Iterable[str], *, local_ok: bool = False) -> Iterator[None]:
    """Allow only `allowed` hostnames/IPs. `local_ok` also allows loopback and private IPs."""
    names = {h.lower() for h in allowed if h}
    ips: set[str] = set()
    orig_gai, orig_connect, orig_connect_ex = (
        socket.getaddrinfo,
        socket.socket.connect,
        socket.socket.connect_ex,
    )

    def permitted(host: str) -> bool:
        return host in names or host in ips or (local_ok and is_local_host(host))

    def gai(host, *a, **k):
        h = host.decode() if isinstance(host, bytes) else host
        if h is None or not permitted(str(h).lower()):
            raise NetworkBlocked(f"vesk network guard: lookup of {h!r} blocked")
        res = orig_gai(host, *a, **k)
        ips.update(r[4][0] for r in res)
        return res

    def check(addr):
        if isinstance(addr, tuple) and not permitted(str(addr[0]).lower()):
            raise NetworkBlocked(f"vesk network guard: connection to {addr[0]!r} blocked")

    def connect(self, addr):
        check(addr)
        return orig_connect(self, addr)

    def connect_ex(self, addr):
        check(addr)
        return orig_connect_ex(self, addr)

    socket.getaddrinfo = gai
    socket.socket.connect = connect  # type: ignore[method-assign]
    socket.socket.connect_ex = connect_ex  # type: ignore[method-assign]
    try:
        yield
    finally:
        socket.getaddrinfo = orig_gai
        socket.socket.connect = orig_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = orig_connect_ex  # type: ignore[method-assign]
