"""Unit tests for the scanner's core logic.

Run: python3 -m pytest tests/ -q

Anything needing python-nmap / shodan is skipped when those are absent, so the
suite runs without the scanning stack installed.
"""

import pytest

from models.managers import CameraRepository
from scanners.config import CheckersConfig
from scanners.proxy import (
    AnonymousProxyClient,
    ConnectFetcher,
    CurlFetcher,
    TwoCaptchaProxy,
    TwoCaptchaSettings,
    requests_proxies,
)
from scanners.proxy_tunnel import ProxyTunnel, http_connect, socks5_connect
from scanners.rtsp_probe import (
    DirectTransport,
    ProxiedTransport,
    RtspProbe,
    RtspTarget,
    _rewrite_netloc,
)


def _proxy(cached_url="http://78.141.222.54:15000", **overrides):
    overrides.setdefault("protocol", "http")  # do not depend on the ambient .env
    proxy = TwoCaptchaProxy(
        settings=TwoCaptchaSettings(proxy_2captcha_aip_token="tok", **overrides)
    )
    if cached_url is not None:
        proxy._cached_url = cached_url  # skip the network call in url()
    return proxy


# --- domain values --------------------------------------------------------


def test_rtsp_target_url_is_formatted_once():
    target = RtspTarget(
        host="10.0.0.1",
        port=554,
        user="admin",
        password="pass",
        url_template="rtsp://{}:{}@{}:{}/live",
    )
    assert target.url == "rtsp://admin:pass@10.0.0.1:554/live"


def test_sanitize_city_strips_injection_chars():
    assert CameraRepository._sanitize_city('Sa\'o; "Paulo"') == "Sao Paulo"
    assert CameraRepository._sanitize_city(None) == ""


@pytest.mark.parametrize("value,expected", [("false", False), ("true", True)])
def test_checkers_randomize_is_coerced_to_bool(value, expected):
    config = CheckersConfig(
        wordlist_users="config.ini",
        wordlist_passwords="config.ini",
        wordlist_rtsp_urls="config.ini",
        randomize=value,
    )
    assert config.randomize is expected


# --- TwoCaptchaProxy reply parsing ---------------------------------------


def test_first_connection_reads_confirmed_success_shape():
    proxy = _proxy()
    reply = {
        "status": "OK",
        "data": ["http://78.141.222.54:15000", "http://78.141.222.54:15001"],
    }
    assert proxy._first_connection(reply) == "http://78.141.222.54:15000"


def test_first_connection_prepends_scheme_for_bare_ip_port():
    proxy = _proxy(protocol="socks5")
    conn = proxy._first_connection({"status": "OK", "data": ["1.2.3.4:8080"]})
    assert proxy._normalize(conn) == "socks5://1.2.3.4:8080"


def test_first_connection_rejects_error_packed_in_200():
    reply = {
        "status": "OK",
        "data": ["Foreign key constraint failed on country_code", "Bad Request", 400],
    }
    with pytest.raises(RuntimeError, match="no usable proxy"):
        _proxy()._first_connection(reply)


def test_first_connection_raises_on_error_status():
    reply = {"status": "ERROR_MISSING_IP", "message": "IP address is missing"}
    with pytest.raises(RuntimeError, match="IP address is missing"):
        _proxy()._first_connection(reply)


def test_login_url_needs_gateway_fields():
    proxy = _proxy(
        auth_mode="login",
        gateway_host="gw.example",
        gateway_port=8000,
        gateway_password="pw",
    )
    assert proxy._build_login_url("uc123") == "http://uc123:pw@gw.example:8000"


def test_login_url_missing_gateway_fields_raises():
    with pytest.raises(ValueError):
        _proxy(auth_mode="login")._build_login_url("uc123")


# --- proxies dict / socks5h ----------------------------------------------


def test_requests_proxies_upgrades_socks5_to_socks5h():
    assert requests_proxies("socks5://1.2.3.4:1080") == {
        "http": "socks5h://1.2.3.4:1080",
        "https": "socks5h://1.2.3.4:1080",
    }


def test_requests_proxies_leaves_http_untouched():
    assert requests_proxies("http://1.2.3.4:8080")["https"] == "http://1.2.3.4:8080"


# --- fetchers -------------------------------------------------------------


class _FakeCurlResponse:
    status_code = 200
    content = b"curl-ok"


class _FakeCurl:
    def __init__(self):
        self.call = None

    def get(self, url, **kwargs):
        self.call = {"url": url, **kwargs}
        return _FakeCurlResponse()


def test_curl_fetcher_impersonates_and_uses_proxy():
    curl = _FakeCurl()
    status, body = CurlFetcher(_proxy(), curl_requests=curl).get(
        "https://example.com/x"
    )
    assert (status, body) == (200, b"curl-ok")
    assert curl.call["impersonate"] == "chrome"
    assert curl.call["proxies"]["https"] == "http://78.141.222.54:15000"


def test_curl_fetcher_upgrades_socks5():
    curl = _FakeCurl()
    CurlFetcher(_proxy("socks5://1.2.3.4:1080"), curl_requests=curl).get("https://x/")
    assert curl.call["proxies"]["https"] == "socks5h://1.2.3.4:1080"


class _FakeResponse:
    status = 200

    def read(self):
        return b"ok"


class _FakeConn:
    def __init__(self):
        self.tunnel = None
        self.sent = None

    def set_tunnel(self, host, port, headers=None):
        self.tunnel = (host, port)

    def request(self, method, path, headers=None):
        self.sent = (method, path, headers)

    def getresponse(self):
        return _FakeResponse()

    def close(self):
        pass


def _connect_fetcher(cached_url="http://78.141.222.54:15000"):
    conn = _FakeConn()
    seen = {}

    def factory(scheme, host, port):
        seen["proxy"] = (scheme, host, port)
        return conn

    return ConnectFetcher(_proxy(cached_url), connection_factory=factory), conn, seen


def test_connect_fetcher_tunnels_https_with_browser_headers():
    fetcher, conn, seen = _connect_fetcher()
    status, body = fetcher.get("https://example.com/path?q=1")
    assert (status, body) == (200, b"ok")
    assert conn.tunnel == ("example.com", 443)  # CONNECT, not forward
    method, path, headers = conn.sent
    assert (method, path) == ("GET", "/path?q=1")
    assert headers["Host"] == "example.com"
    assert "Chrome/" in headers["User-Agent"]
    assert not any(h.lower().startswith("proxy-") for h in headers)
    assert seen["proxy"] == ("https", "78.141.222.54", 15000)


def test_connect_fetcher_tunnels_plain_http_too():
    fetcher, conn, seen = _connect_fetcher()
    fetcher.get("http://example.com/")
    assert conn.tunnel == ("example.com", 80)
    assert seen["proxy"][0] == "http"


def test_connect_fetcher_rejects_socks_proxy():
    fetcher, _, _ = _connect_fetcher("socks5://1.2.3.4:1080")
    with pytest.raises(ValueError, match="socks5"):
        fetcher.get("https://example.com/")


class _FakeFetcher:
    def __init__(self):
        self.url = None

    def get(self, url):
        self.url = url
        return 200, b"delegated"


def test_anonymous_client_delegates_to_fetcher():
    fetcher = _FakeFetcher()
    client = AnonymousProxyClient(_proxy(), fetcher=fetcher)
    assert client.get("https://example.com/a") == (200, b"delegated")
    assert fetcher.url == "https://example.com/a"


def test_anonymous_client_rejects_url_without_host():
    client = AnonymousProxyClient(_proxy(), fetcher=_FakeFetcher())
    with pytest.raises(ValueError, match="no host"):
        client.get("not-a-url")


# --- proxy tunnel handshakes ---------------------------------------------


class _FakeProxySock:
    def __init__(self, reads):
        self.sent = b""
        self._reads = list(reads)

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        return self._reads.pop(0) if self._reads else b""


def test_socks5_connect_sends_domain_request_for_remote_dns():
    sock = _FakeProxySock(
        [b"\x05\x00", b"\x05\x00\x00\x01", b"\x00\x00\x00\x00\x00\x00"]
    )
    socks5_connect(sock, "cam.example", 554)
    assert sock.sent.startswith(b"\x05\x01\x00")  # no-auth greeting
    assert b"\x05\x01\x00\x03\x0bcam.example\x02\x2a" in sock.sent  # domain + 554


def test_http_connect_accepts_200():
    sock = _FakeProxySock([b"HTTP/1.1 200 Connection established\r\n\r\n"])
    http_connect(sock, "cam.example", 554)
    assert sock.sent.startswith(b"CONNECT cam.example:554 HTTP/1.1")


def test_http_connect_rejects_non_200():
    sock = _FakeProxySock([b"HTTP/1.1 403 Forbidden\r\n\r\n"])
    with pytest.raises(ConnectionError):
        http_connect(sock, "cam.example", 554)


def test_proxy_tunnel_rejects_unsupported_scheme():
    with pytest.raises(ValueError, match="unsupported proxy scheme"):
        ProxyTunnel("ftp://1.2.3.4:21", "cam", 554)


# --- rtsp transport -------------------------------------------------------


def test_rewrite_netloc_keeps_creds_and_path():
    out = _rewrite_netloc("rtsp://admin:pass@10.0.0.5:554/live", "127.0.0.1", 8554)
    assert out == "rtsp://admin:pass@127.0.0.1:8554/live"


def test_direct_transport_yields_target_url():
    target = RtspTarget(
        host="10.0.0.5",
        port=554,
        user="a",
        password="b",
        url_template="rtsp://{}:{}@{}:{}/live",
    )
    with DirectTransport().open(target) as url:
        assert url == target.url


def test_default_transport_selects_by_proxy():
    assert isinstance(RtspProbe()._transport, DirectTransport)
    assert isinstance(RtspProbe(proxy=_proxy())._transport, ProxiedTransport)


# --- tasks (need the scanning stack) -------------------------------------


def test_nmap_task_rejects_socks5_proxy():
    pytest.importorskip("nmap")
    from scanners.config import NmapConfig
    from scanners.task import NmapTask

    class _SocksProxy:
        def url(self):
            return "socks5://1.2.3.4:1080"

    task = NmapTask(NmapConfig(ip_range="10.0.0.0/30"), _SocksProxy())
    with pytest.raises(ValueError, match="socks5"):
        task._scan("10.0.0.1")  # guard fires before any real scan runs


def test_shodan_banner_ignores_extra_and_coerces():
    pytest.importorskip("shodan")
    from scanners.task import ShodanBanner

    banner = ShodanBanner(
        ip_str="1.2.3.4",
        port="554",
        location={"city": "SP", "unrelated": 1},
        junk="ignored",
    )
    assert banner.port == 554
    assert banner.location.city == "SP"
