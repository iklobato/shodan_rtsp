"""2captcha residential proxy provider.

Whitelist mode (recommended for a scanner on a fixed box): the machine's
public IPv4 must be added to the account whitelist in the 2captcha web
dashboard first (there is no API for that step). Then the API hands back a
ready http://ip:port that connects with no credentials from that IP.

Login mode: username:password@host:port, where the username is read from the
API and the host/port/password come from the dashboard (env-configured).

Run `python -m scanners.proxy` to generate and print a proxy URL.
"""

import http.client
import json
import logging
import ssl
import urllib.parse
import urllib.request

from pydantic_settings import BaseSettings, SettingsConfigDict

try:  # optional: matches the TLS (JA3/JA4) and HTTP/2 fingerprint to a browser
    from curl_cffi import requests as _curl_requests
except ImportError:  # falls back to the stdlib CONNECT client below
    _curl_requests = None

_API = "https://api.2captcha.com"
_IP_ECHO = "https://api.ipify.org"

# Browser header set for the stdlib fallback path (the curl backend supplies its
# own coherent headers). A Windows Chrome UA is used because the residential exit
# nodes 2captcha hands out read as Windows in their TCP fingerprint, so the story
# is coherent instead of "python-urllib behind a home IP".
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


class TwoCaptchaSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    proxy_2captcha_aip_token: str
    auth_mode: str = "whitelist"  # 'whitelist' | 'login'
    protocol: str = "http"  # http | https | socks5
    country: str = "us"  # exit country code; BR is not offered by 2captcha
    public_ip: str = ""  # whitelist mode; auto-detected when empty
    gateway_host: str = ""  # login mode (from dashboard)
    gateway_port: int = 0  # login mode (from dashboard)
    gateway_password: str = ""  # login mode (from dashboard)


class TwoCaptchaProxy:
    """Builds a proxy URL for outbound tools, self-configured from the API."""

    def __init__(
        self,
        settings: TwoCaptchaSettings = None,
        http_get_json=None,
        http_get_text=None,
    ):
        self._s = settings or TwoCaptchaSettings()
        self._get_json = http_get_json or self._default_get_json
        self._get_text = http_get_text or self._default_get_text
        self._cached_url = None

    def url(self) -> str:
        if self._cached_url is None:
            self._cached_url = self._resolve_url()
        return self._cached_url

    def requests_proxies(self) -> dict:
        proxy_url = self.url()
        return {"http": proxy_url, "https": proxy_url}

    def client(self, **kwargs) -> "AnonymousProxyClient":
        """An HTTP client that reaches a destination through this proxy
        without revealing the proxy at the destination."""
        return AnonymousProxyClient(self, **kwargs)

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
        200 'data' list, so anything that is not a real connection falls
        through and the raw body is raised instead of a silent wrong proxy.
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
        params["key"] = self._s.proxy_2captcha_aip_token
        return self._get_json(f"{_API}{path}?{urllib.parse.urlencode(params)}")

    @staticmethod
    def _default_get_json(url: str) -> dict:
        with urllib.request.urlopen(url, timeout=25) as response:
            return json.loads(response.read().decode())

    @staticmethod
    def _default_get_text(url: str) -> str:
        with urllib.request.urlopen(url, timeout=15) as response:
            return response.read().decode()


class AnonymousProxyClient:
    """Reaches a destination through the proxy without revealing the proxy.

    A naive proxy request leaks at three layers; this client closes all three
    (each verified against a live capture, see tests/test_refactor.py):

    * L7 header injection. A plaintext HTTP request is *forwarded* by the proxy,
      which lets it add ``Proxy-Host`` / ``Via`` / ``X-Forwarded-For`` to what
      the destination reads. Both backends here only ever CONNECT-tunnel, so the
      proxy sees ``CONNECT host:port`` and relays opaque bytes: it cannot inject.
    * L7 header shape. The stdlib fallback sends a browser header set
      (``_BROWSER_HEADERS``); the curl backend lets curl_cffi own the headers so
      they stay internally coherent with the impersonated browser (UA, client
      hints and JA3/JA4 all match one real Chrome build).
    * TLS (below HTTP, end-to-end through the tunnel). OpenSSL's ClientHello has
      a JA3/JA4 that reads as "not a browser", and it is the only sub-HTTP
      fingerprint the client controls: IP TTL and the TCP handshake are the exit
      node's, not ours, once the proxy re-originates the connection. When
      ``curl_cffi`` is installed this client uses it with ``impersonate`` so the
      JA3/JA4 and HTTP/2 fingerprint match a real browser; otherwise it falls
      back to the stdlib CONNECT client (L7 clean, TLS still OpenSSL's).

    Residual we cannot fix from here: the exit node's OS (seen in its TCP/IP
    fingerprint) is not ours to choose, so it may differ from the impersonated
    browser's OS. Matching them would need control of the exit, which a shared
    residential pool does not give. Do NOT paper over it by editing the UA OS
    token alone: that desyncs the UA from ``sec-ch-ua-platform`` and is a louder
    tell than the OS mismatch itself.

    SOCKS5 (``protocol=socks5`` in settings) works on the curl backend for free:
    the url is upgraded to ``socks5h`` so DNS is resolved at the exit, not here.
    The stdlib fallback is HTTP-CONNECT only and rejects a socks proxy.
    """

    def __init__(
        self,
        proxy: TwoCaptchaProxy,
        headers: dict = None,
        timeout: int = 40,
        ssl_context: ssl.SSLContext = None,
        connection_factory=None,
        impersonate: str = "chrome",
        verify: bool = True,
        curl_backend=_curl_requests,
    ):
        self._proxy = proxy
        self._headers = headers or dict(_BROWSER_HEADERS)
        self._timeout = timeout
        self._ssl_context = ssl_context or ssl.create_default_context()
        self._new_conn = connection_factory or self._default_connection
        self._impersonate = impersonate
        self._verify = verify
        self._curl = curl_backend

    def get(self, url: str) -> tuple[int, bytes]:
        if not urllib.parse.urlsplit(url).hostname:
            raise ValueError(f"url has no host: {url}")
        if self._curl is not None:
            return self._get_curl(url)
        return self._get_stdlib(url)

    def _get_curl(self, url: str) -> tuple[int, bytes]:
        response = self._curl.get(
            url,
            proxies=self._proxies(),
            impersonate=self._impersonate,
            timeout=self._timeout,
            verify=self._verify,
        )
        return response.status_code, response.content

    def _get_stdlib(self, url: str) -> tuple[int, bytes]:
        proxy = urllib.parse.urlsplit(self._proxy.url())
        if proxy.scheme not in ("http", "https"):
            raise ValueError(
                f"stdlib backend needs an http proxy, got {proxy.scheme!r}; "
                "install curl_cffi for socks5"
            )
        dest = urllib.parse.urlsplit(url)
        port = dest.port or (443 if dest.scheme == "https" else 80)
        path = dest.path or "/"
        if dest.query:
            path = f"{path}?{dest.query}"

        conn = self._new_conn(dest.scheme, proxy.hostname, proxy.port)
        conn.set_tunnel(dest.hostname, port)  # CONNECT: proxy can't read/inject L7
        headers = {"Host": dest.hostname, **self._headers}
        try:
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def _proxies(self) -> dict:
        url = self._proxy.url()
        if url.startswith("socks5://"):  # socks5h -> the exit resolves DNS, not us
            url = "socks5h://" + url[len("socks5://") :]
        return {"http": url, "https": url}

    def _default_connection(self, scheme: str, proxy_host: str, proxy_port: int):
        if scheme == "https":
            return http.client.HTTPSConnection(
                proxy_host, proxy_port, timeout=self._timeout, context=self._ssl_context
            )
        return http.client.HTTPConnection(proxy_host, proxy_port, timeout=self._timeout)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    proxy = TwoCaptchaProxy()
    logging.info("Generated proxy: %s", proxy.url())
    backend = "curl_cffi (browser JA3/H2)" if _curl_requests else "stdlib CONNECT"
    status, body = proxy.client().get("https://api.ipify.org")
    logging.info(
        "Exit IP seen by destination: %s (%s, via %s)",
        body.decode().strip(),
        status,
        backend,
    )
