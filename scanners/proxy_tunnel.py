"""Route an otherwise un-proxyable TCP client (e.g. OpenCV/FFmpeg for RTSP)
through the residential proxy.

FFmpeg has no proxy option for RTSP, so instead of a proxy setting we give it a
local endpoint: ``ProxyTunnel`` listens on 127.0.0.1, and every connection it
accepts is relayed to the real destination *through the proxy* (HTTP CONNECT or
a SOCKS5 handshake). The client believes it talks to a local server; the bytes
actually leave via the proxy exit. Force ``rtsp_transport=tcp`` on the client so
control and media share the one TCP stream the tunnel can carry.
"""

import logging
import select
import socket
import threading
import urllib.parse


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
    atyp = reply[3]
    if atyp == 0x01:
        _recv_exact(sock, 4 + 2)  # IPv4 + port
    elif atyp == 0x03:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)  # domain len + name + port
    elif atyp == 0x04:
        _recv_exact(sock, 16 + 2)  # IPv6 + port
    else:
        raise ConnectionError(f"socks5 unknown bound address type {atyp}")


class ProxyTunnel:
    """Local 127.0.0.1 listener relaying every connection to (host, port)
    through ``proxy_url``. Use as a context manager: it yields the local
    (host, port) to point the client at."""

    def __init__(
        self, proxy_url: str, dest_host: str, dest_port: int, timeout: int = 15
    ):
        self._proxy = urllib.parse.urlsplit(proxy_url)
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
            try:
                client, _ = self._listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            upstream = self._dial()
        except Exception as e:
            logging.debug("tunnel dial failed: %s", e)
            client.close()
            return
        self._pump(client, upstream)

    def _dial(self) -> socket.socket:
        sock = socket.create_connection(
            (self._proxy.hostname, self._proxy.port), timeout=self._timeout
        )
        host, port = self._dest
        if self._proxy.scheme in ("socks5", "socks5h"):
            socks5_connect(sock, host, port)
        elif self._proxy.scheme in ("http", "https"):
            http_connect(sock, host, port)
        else:
            sock.close()
            raise ValueError(f"unsupported proxy scheme {self._proxy.scheme!r}")
        return sock

    def _pump(self, a: socket.socket, b: socket.socket) -> None:
        try:
            while True:
                readable, _, _ = select.select([a, b], [], [], self._timeout * 2)
                if not readable:
                    return
                for src in readable:
                    data = src.recv(65536)
                    if not data:
                        return
                    (b if src is a else a).sendall(data)
        except OSError:
            return
        finally:
            a.close()
            b.close()
