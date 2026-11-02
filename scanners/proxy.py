"""2captcha residential proxy provider and an anonymised HTTP client.

Whitelist mode (recommended for a scanner on a fixed box): the machine's public
IPv4 must be added to the account whitelist in the 2captcha web dashboard first
(there is no API for that step). Then the API hands back a ready http://ip:port
that connects with no credentials from that IP.

Login mode: username:password@host:port, where the username is read from the API
and the host/port/password come from the dashboard (config-provided).

Config comes from config.yaml (see scanners/config.py). Run
`python -m scanners.proxy` to generate a proxy and print the exit IP.
"""

import importlib.util
import json
import logging
import urllib.parse
import urllib.request
from contextlib import closing
from http.client import HTTPConnection, HTTPSConnection
from ssl import SSLContext, create_default_context
from typing import Protocol

from scanners.config import ProxyConfig, get_config

_API = "https://api.2captcha.com"
_IP_ECHO = "https://api.ipify.org"

# Browser header set for the stdlib fallback (the curl backend brings its own
# coherent headers). A Windows Chrome UA matches the residential exit nodes,
# whose TCP fingerprint reads as Windows, so the story stays coherent.
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Connection": "keep-alive",
}


def _load_curl_requests():
    """curl_cffi is optional: return its requests module, or None if absent.

    find_spec (look before you leap) avoids a try/except around the import.
    """
    if importlib.util.find_spec("curl_cffi") is None:
        return None
    from curl_cffi import requests as curl_requests

    return curl_requests


_CURL_REQUESTS = _load_curl_requests()


def requests_proxies(proxy_url: str) -> dict:
    """A requests-style proxies dict. socks5 is upgraded to socks5h so DNS is
    resolved at the exit, never by the local resolver."""
    if proxy_url.startswith("socks5://"):
        proxy_url = "socks5h://" + proxy_url[len("socks5://") :]
    return {"http": proxy_url, "https": proxy_url}


class TwoCaptchaProxy:
    """Resolves a proxy URL from the 2captcha API, configured from ProxyConfig."""

    def __init__(
        self,
        config: ProxyConfig = None,
        http_get_json=None,
        http_get_text=None,
    ):
        self._s = config or get_config().proxy
        self._get_json = http_get_json or self._default_get_json
        self._get_text = http_get_text or self._default_get_text
        self._cached_url = None

    def url(self) -> str:
        if self._cached_url is None:
            self._cached_url = self._resolve_url()
        return self._cached_url

    def client(self, fetcher: "Fetcher" = None) -> "AnonymousProxyClient":
        """An HTTP client that reaches a destination through this proxy without
        revealing the proxy at the destination."""
        return AnonymousProxyClient(self, fetcher)

    def _resolve_url(self) -> str:
        if self._s.auth_mode == "login":
            return self._build_login_url(self._account_username())
        ip = self._s.public_ip or self._get_text(_IP_ECHO).strip()
        data = self._api(
            "/proxy/generate_white_list_connections",
            ip=ip,
            protocol=self._s.protocol,
            country=self._s.country,
            connection_count=1,
        )
        return self._normalize(self._first_connection(data))

    def _build_login_url(self, username: str) -> str:
        s = self._s
        if not (s.gateway_host and s.gateway_port and s.gateway_password):
            raise ValueError(
                "login mode needs gateway_host, gateway_port and gateway_password"
            )
        return f"{s.protocol}://{username}:{s.gateway_password}@{s.gateway_host}:{s.gateway_port}"

    def _normalize(self, connection: str) -> str:
        if "://" in connection:
            return connection
        return f"{self._s.protocol}://{connection}"

    def _account_username(self) -> str:
        data = self._api("/proxy")
        return data["data"]["username"]

    @staticmethod
    def _first_connection(data: dict) -> str:
        """Pull the first proxy out of a generate_white_list_connections reply.

        Confirmed success shape: {"status":"OK","data":["http://ip:port", ...]}.
        The endpoint can also pack an error (e.g. a missing country) inside a
        200 'data' list, so anything that is not a real connection falls through
        and the raw body is raised instead of a silent wrong proxy.
        """
        if data.get("status") != "OK":
            raise RuntimeError(f"2captcha proxy error: {data.get('message', data)}")
        items = data.get("data", [])
        if isinstance(items, dict):
            items = items.get("connections") or items.get("list") or []
        for item in items:
            if isinstance(item, str):
                if item.startswith(("http://", "https://", "socks5://")):
                    return item
                if ":" in item and " " not in item:  # bare ip:port
                    return item
            elif isinstance(item, dict):
                ip, port = item.get("ip"), item.get("port")
                if ip and port:
                    return f"{ip}:{port}"
        raise RuntimeError(f"no usable proxy in 2captcha reply: {data}")

    def _api(self, path: str, **params) -> dict:
        params["key"] = self._s.token
        return self._get_json(f"{_API}{path}?{urllib.parse.urlencode(params)}")

    @staticmethod
    def _default_get_json(url: str) -> dict:
        with urllib.request.urlopen(url, timeout=25) as response:
            return json.loads(response.read().decode())

    @staticmethod
    def _default_get_text(url: str) -> str:
        with urllib.request.urlopen(url, timeout=15) as response:
            return response.read().decode()


class Fetcher(Protocol):
    """Performs one GET through the proxy, returning (status, body)."""

    def get(self, url: str) -> tuple[int, bytes]: ...


class CurlFetcher:
    """Fetch through the proxy with a browser TLS (JA3/JA4) and HTTP/2
    fingerprint, via curl_cffi's impersonation."""

    def __init__(
        self,
        proxy: TwoCaptchaProxy,
        curl_requests=_CURL_REQUESTS,
        impersonate: str = "chrome",
        timeout: int = 40,
        verify: bool = True,
    ):
        self._proxy = proxy
        self._curl = curl_requests
        self._impersonate = impersonate
        self._timeout = timeout
        self._verify = verify

    def get(self, url: str) -> tuple[int, bytes]:
        response = self._curl.get(
            url,
            proxies=requests_proxies(self._proxy.url()),
            impersonate=self._impersonate,
            timeout=self._timeout,
            verify=self._verify,
        )
        return response.status_code, response.content


class ConnectFetcher:
    """Dependency-free fallback: always CONNECT-tunnels so the proxy relays
    opaque bytes and cannot inject Proxy-Host / Via / X-Forwarded-For, and sends
    a browser header set. TLS stays OpenSSL's; http proxies only (socks5 needs
    the curl backend)."""

    def __init__(
        self,
        proxy: TwoCaptchaProxy,
        headers: dict = None,
        timeout: int = 40,
        ssl_context: SSLContext = None,
        connection_factory=None,
    ):
        self._proxy = proxy
        self._headers = headers or dict(_BROWSER_HEADERS)
        self._timeout = timeout
        self._ssl_context = ssl_context or create_default_context()
        self._new_connection = connection_factory or self._connection

    def get(self, url: str) -> tuple[int, bytes]:
        proxy = urllib.parse.urlsplit(self._proxy.url())
        if proxy.scheme not in ("http", "https"):
            raise ValueError(
                f"stdlib backend needs an http proxy, got {proxy.scheme!r}; "
                "install curl_cffi for socks5"
            )
        destination = urllib.parse.urlsplit(url)
        port = destination.port or (443 if destination.scheme == "https" else 80)
        path = destination.path or "/"
        if destination.query:
            path = f"{path}?{destination.query}"
        connection = self._new_connection(
            destination.scheme, proxy.hostname, proxy.port
        )
        with closing(connection):
            connection.set_tunnel(destination.hostname, port)
            connection.request(
                "GET", path, headers={"Host": destination.hostname, **self._headers}
            )
            response = connection.getresponse()
            return response.status, response.read()

    def _connection(self, scheme: str, proxy_host: str, proxy_port: int):
        if scheme == "https":
            return HTTPSConnection(
                proxy_host, proxy_port, timeout=self._timeout, context=self._ssl_context
            )
        return HTTPConnection(proxy_host, proxy_port, timeout=self._timeout)


class AnonymousProxyClient:
    """Reaches a destination through the proxy without revealing the proxy.

    It composes a Fetcher strategy and closes what is ours to control:

    * L7 injection: both fetchers CONNECT/tunnel, so the proxy relays opaque
      bytes and cannot add Proxy-Host / Via / X-Forwarded-For.
    * L7 shape and TLS: CurlFetcher impersonates a browser (JA3/JA4 + HTTP/2);
      ConnectFetcher is the dependency-free fallback (browser headers, but the
      TLS fingerprint stays OpenSSL's).

    The exit node's IP TTL and TCP handshake are not ours to set once the proxy
    re-originates the connection, so we leave them: they already read as the
    residential exit, which is the point.
    """

    def __init__(self, proxy: TwoCaptchaProxy, fetcher: Fetcher = None):
        self._proxy = proxy
        self._fetcher = fetcher or self._default_fetcher()

    def get(self, url: str) -> tuple[int, bytes]:
        if not urllib.parse.urlsplit(url).hostname:
            raise ValueError(f"url has no host: {url}")
        return self._fetcher.get(url)

    def _default_fetcher(self) -> Fetcher:
        if _CURL_REQUESTS is not None:
            return CurlFetcher(self._proxy)
        return ConnectFetcher(self._proxy)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    proxy = TwoCaptchaProxy()
    logging.info("Generated proxy: %s", proxy.url())
    backend = "curl_cffi (browser JA3/H2)" if _CURL_REQUESTS else "stdlib CONNECT"
    status, body = proxy.client().get("https://api.ipify.org")
    logging.info("Exit IP: %s (%s, via %s)", body.decode().strip(), status, backend)
