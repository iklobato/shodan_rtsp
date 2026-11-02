"""Route an otherwise un-proxyable TCP client (e.g. OpenCV/FFmpeg for RTSP)
through the residential proxy.

FFmpeg has no proxy option for RTSP, so instead of a proxy setting we give it a
local endpoint: ``ProxyTunnel`` listens on 127.0.0.1, and every connection it
accepts is relayed to the real destination *through the proxy* (HTTP CONNECT or
a SOCKS5 handshake). The client believes it talks to a local server; the bytes
actually leave via the proxy exit. Force ``rtsp_transport=tcp`` on the client so
control and media share the one TCP stream the tunnel can carry.

The socket boundaries here keep the few try blocks they need (a relay of raw
sockets is exactly the "external boundary" error handling belongs at); the
scheme choice is a dispatch table, not an if/elif ladder.
"""

import logging
import select
import socket
import threading
import urllib.parse
from contextlib import closing

_RELAY_CHUNK = 65536


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("proxy closed during handshake")
        buf += chunk
    return buf


def http_connect(sock: socket.socket, host: str, port: int) -> None:
    """Ask an HTTP proxy to CONNECT-tunnel to host:port (proxy cannot inject)."""
    sock.sendall(
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    )
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("proxy closed before CONNECT reply")
        resp += chunk
    status_line = resp.split(b"\r\n", 1)[0]
    if b" 200 " not in status_line + b" ":
        raise ConnectionError(f"proxy refused CONNECT: {status_line!r}")


def socks5_connect(sock: socket.socket, host: str, port: int) -> None:
    """SOCKS5 CONNECT with a domain target, so DNS is resolved at the exit."""
    sock.sendall(b"\x05\x01\x00")  # version 5, one method: no auth
    if _recv_exact(sock, 2) != b"\x05\x00":
        raise ConnectionError("socks5 proxy rejected no-auth")
    domain = host.encode()
    if len(domain) > 255:
        raise ValueError(f"host too long for socks5: {host}")
    sock.sendall(
        b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + port.to_bytes(2, "big")
    )
    reply = _recv_exact(sock, 4)
    if reply[1] != 0x00:
        raise ConnectionError(f"socks5 CONNECT failed, reply code {reply[1]}")
    _consume_bound_address(sock, reply[3])


def _consume_bound_address(sock: socket.socket, address_type: int) -> None:
    if address_type == 0x01:
        _recv_exact(sock, 4 + 2)  # IPv4 + port
    elif address_type == 0x03:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)  # domain len + name + port
    elif address_type == 0x04:
        _recv_exact(sock, 16 + 2)  # IPv6 + port
    else:
        raise ConnectionError(f"socks5 unknown bound address type {address_type}")


# scheme -> handshake, so the transport is chosen by lookup, not an if/elif chain
_HANDSHAKES = {
    "http": http_connect,
    "https": http_connect,
    "socks5": socks5_connect,
    "socks5h": socks5_connect,
}


class ProxyTunnel:
    """Local 127.0.0.1 listener relaying every connection to (host, port)
    through ``proxy_url``. Use as a context manager: it yields the local
    (host, port) to point the client at."""

    def __init__(
        self, proxy_url: str, dest_host: str, dest_port: int, timeout: int = 15
    ):
        self._proxy = urllib.parse.urlsplit(proxy_url)
        self._handshake = _HANDSHAKES.get(self._proxy.scheme)
        if self._handshake is None:
            raise ValueError(f"unsupported proxy scheme {self._proxy.scheme!r}")
        self._dest = (dest_host, dest_port)
        self._timeout = timeout
        self._listener = None
        self._closed = False

    def __enter__(self) -> tuple[str, int]:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(4)
        self._listener.settimeout(0.5)
        threading.Thread(target=self._serve, daemon=True).start()
        return self._listener.getsockname()

    def __exit__(self, *exc) -> None:
        self._closed = True
        if self._listener is not None:
            self._listener.close()

    def _serve(self) -> None:
        while not self._closed:
            client = self._accept()
            if client is None:
                continue
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _accept(self):
        # accept() with a timeout is the standard cooperative-shutdown pattern
        try:
            client, _ = self._listener.accept()
            return client
        except (TimeoutError, socket.timeout):
            return None
        except OSError:
            self._closed = True
            return None

    def _handle(self, client: socket.socket) -> None:
        with closing(client):
            upstream = self._dial_quietly()
            if upstream is None:
                return
            with closing(upstream):
                self._relay_quietly(client, upstream)

    def _dial_quietly(self):
        # one boundary catch: a failed dial must not crash the accept loop
        try:
            return self._dial()
        except (OSError, ValueError) as error:
            logging.debug("tunnel dial failed: %s", error)
            return None

    def _dial(self) -> socket.socket:
        sock = socket.create_connection(
            (self._proxy.hostname, self._proxy.port), timeout=self._timeout
        )
        self._handshake(sock, *self._dest)
        return sock

    def _relay_quietly(self, a: socket.socket, b: socket.socket) -> None:
        # a peer reset mid-relay is normal for a proxied stream, not an error
        try:
            self._relay(a, b)
        except OSError as error:
            logging.debug("tunnel relay ended: %s", error)

    def _relay(self, a: socket.socket, b: socket.socket) -> None:
        while True:
            readable, _, _ = select.select([a, b], [], [], self._timeout * 2)
            if not readable:
                return
            for src in readable:
                data = src.recv(_RELAY_CHUNK)
                if not data:
                    return
                (b if src is a else a).sendall(data)
