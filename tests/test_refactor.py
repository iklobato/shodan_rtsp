"""Runnable self-checks for the refactored logic. No test framework needed:

python3 -m tests.test_refactor
"""

from models.managers import CameraRepository
from scanners.config import CheckersConfig
from scanners.proxy import AnonymousProxyClient, TwoCaptchaProxy, TwoCaptchaSettings
from scanners.proxy_tunnel import http_connect, socks5_connect
from scanners.rtsp_probe import RtspTarget, _rewrite_netloc


def test_rtsp_target_url_is_formatted_once():
    target = RtspTarget(
        host="10.0.0.1",
        port=554,
        user="admin",
        password="pass",
        url_template="rtsp://{}:{}@{}:{}/live",
    )
    assert target.url == "rtsp://admin:pass@10.0.0.1:554/live", target.url


def test_sanitize_city_strips_injection_chars():
    assert CameraRepository._sanitize_city('Sa\'o; "Paulo"') == "Sao Paulo"
    assert CameraRepository._sanitize_city(None) == ""


def test_checkers_randomize_is_coerced_to_bool():
    existing = "config.ini"  # FilePath only checks existence
    assert (
        CheckersConfig(
            wordlist_users=existing,
            wordlist_passwords=existing,
            wordlist_rtsp_urls=existing,
            randomize="false",
        ).randomize
        is False
    )
    assert (
        CheckersConfig(
            wordlist_users=existing,
            wordlist_passwords=existing,
            wordlist_rtsp_urls=existing,
            randomize="true",
        ).randomize
        is True
    )


def _proxy(auth_mode, **overrides):
    # pin protocol so tests do not depend on the ambient .env transport
    overrides.setdefault("protocol", "http")
    settings = TwoCaptchaSettings(
        proxy_2captcha_aip_token="tok", auth_mode=auth_mode, **overrides
    )
    return TwoCaptchaProxy(settings=settings)


def test_first_connection_reads_confirmed_success_shape():
    # Confirmed live: data is a list of full proxy URLs.
    proxy = _proxy("whitelist", protocol="http")
    reply = {
        "status": "OK",
        "data": ["http://78.141.222.54:15000", "http://78.141.222.54:15001"],
    }
    conn = proxy._first_connection(reply)
    assert conn == "http://78.141.222.54:15000"
    assert proxy._normalize(conn) == "http://78.141.222.54:15000"


def test_first_connection_prepends_scheme_for_bare_ip_port():
    proxy = _proxy("whitelist", protocol="socks5")
    conn = proxy._first_connection({"status": "OK", "data": ["1.2.3.4:8080"]})
    assert proxy._normalize(conn) == "socks5://1.2.3.4:8080"


def test_first_connection_rejects_error_packed_in_200():
    # The real failure seen when country was missing (FK error inside data).
    proxy = _proxy("whitelist")
    reply = {
        "status": "OK",
        "data": ["Foreign key constraint failed on country_code", "Bad Request", 400],
    }
    try:
        proxy._first_connection(reply)
    except RuntimeError as e:
        assert "no usable proxy" in str(e)
    else:
        raise AssertionError("expected RuntimeError when data holds an error")


def test_first_connection_raises_on_error_status():
    proxy = _proxy("whitelist")
    try:
        proxy._first_connection(
            {"status": "ERROR_MISSING_IP", "message": "IP address is missing"}
        )
    except RuntimeError as e:
        assert "IP address is missing" in str(e)
    else:
        raise AssertionError("expected RuntimeError on error status")


def test_login_url_needs_gateway_fields():
    proxy = _proxy(
        "login", gateway_host="gw.example", gateway_port=8000, gateway_password="pw"
    )
    assert proxy._build_login_url("uc123") == "http://uc123:pw@gw.example:8000"

    incomplete = _proxy("login")
    try:
        incomplete._build_login_url("uc123")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError when gateway fields are missing")


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


def _anon_client(cached_url="http://78.141.222.54:15000"):
    proxy = _proxy("whitelist")
    proxy._cached_url = cached_url  # skip the network call in url()
    conn = _FakeConn()
    seen = {}

    def factory(scheme, host, port):
        seen["proxy"] = (scheme, host, port)
        return conn

    # curl_backend=None forces the stdlib CONNECT path these tests inspect
    client = AnonymousProxyClient(proxy, connection_factory=factory, curl_backend=None)
    return client, conn, seen


class _FakeCurlResponse:
    status_code = 200
    content = b"curl-ok"


class _FakeCurl:
    def __init__(self):
        self.call = None

    def get(self, url, **kwargs):
        self.call = {"url": url, **kwargs}
        return _FakeCurlResponse()


def test_anon_client_tunnels_https_and_sends_browser_headers():
    client, conn, seen = _anon_client()
    status, body = client.get("https://example.com/path?q=1")
    assert (status, body) == (200, b"ok")
    # CONNECT to the destination (proxy tunnels, cannot inject L7), not forward
    assert conn.tunnel == ("example.com", 443)
    method, path, headers = conn.sent
    assert (method, path) == ("GET", "/path?q=1")
    assert headers["Host"] == "example.com"
    assert "Chrome/" in headers["User-Agent"]
    # nothing we send announces a proxy
    assert not any(h.lower().startswith("proxy-") for h in headers)
    assert seen["proxy"] == ("https", "78.141.222.54", 15000)


def test_anon_client_tunnels_plain_http_too():
    # Plaintext HTTP is the case the proxy would otherwise forward and inject
    # Proxy-Host into; CONNECT-tunnelling it closes that hole.
    client, conn, seen = _anon_client()
    client.get("http://example.com/")
    assert conn.tunnel == ("example.com", 80)
    assert seen["proxy"][0] == "http"


def test_anon_client_uses_curl_backend_with_impersonation():
    proxy = _proxy("whitelist")
    proxy._cached_url = "http://78.141.222.54:15000"
    curl = _FakeCurl()
    client = AnonymousProxyClient(proxy, curl_backend=curl, impersonate="chrome")
    status, body = client.get("https://example.com/x")
    assert (status, body) == (200, b"curl-ok")
    # the browser TLS/H2 fingerprint is requested and traffic goes via the proxy
    assert curl.call["impersonate"] == "chrome"
    assert curl.call["proxies"]["https"] == "http://78.141.222.54:15000"


def test_anon_client_upgrades_socks5_to_socks5h_for_remote_dns():
    proxy = _proxy("whitelist")
    proxy._cached_url = "socks5://1.2.3.4:1080"
    curl = _FakeCurl()
    AnonymousProxyClient(proxy, curl_backend=curl).get("https://example.com/")
    assert curl.call["proxies"]["https"] == "socks5h://1.2.3.4:1080"


def test_anon_client_stdlib_rejects_socks_proxy():
    proxy = _proxy("whitelist")
    proxy._cached_url = "socks5://1.2.3.4:1080"
    client = AnonymousProxyClient(proxy, curl_backend=None)
    try:
        client.get("https://example.com/")
    except ValueError as e:
        assert "socks5" in str(e)
    else:
        raise AssertionError("stdlib backend must reject a socks proxy")


class _FakeProxySock:
    def __init__(self, reads):
        self.sent = b""
        self._reads = list(reads)

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        return self._reads.pop(0) if self._reads else b""


def test_rewrite_netloc_keeps_creds_and_path():
    out = _rewrite_netloc("rtsp://admin:pass@10.0.0.5:554/live", "127.0.0.1", 8554)
    assert out == "rtsp://admin:pass@127.0.0.1:8554/live"


def test_socks5_connect_sends_domain_request_for_remote_dns():
    sock = _FakeProxySock(
        [b"\x05\x00", b"\x05\x00\x00\x01", b"\x00\x00\x00\x00\x00\x00"]
    )
    socks5_connect(sock, "cam.example", 554)
    assert sock.sent.startswith(b"\x05\x01\x00")  # no-auth greeting
    # CONNECT, domain type (0x03), remote DNS, port 554 = 0x022a
    assert b"\x05\x01\x00\x03\x0bcam.example\x02\x2a" in sock.sent


def test_http_connect_accepts_200_and_rejects_others():
    ok = _FakeProxySock([b"HTTP/1.1 200 Connection established\r\n\r\n"])
    http_connect(ok, "cam.example", 554)
    assert ok.sent.startswith(b"CONNECT cam.example:554 HTTP/1.1")

    bad = _FakeProxySock([b"HTTP/1.1 403 Forbidden\r\n\r\n"])
    try:
        http_connect(bad, "cam.example", 554)
    except ConnectionError:
        pass
    else:
        raise AssertionError("http_connect must reject a non-200 CONNECT reply")


def _run():
    test_rtsp_target_url_is_formatted_once()
    test_sanitize_city_strips_injection_chars()
    test_checkers_randomize_is_coerced_to_bool()
    test_first_connection_reads_confirmed_success_shape()
    test_first_connection_prepends_scheme_for_bare_ip_port()
    test_first_connection_rejects_error_packed_in_200()
    test_first_connection_raises_on_error_status()
    test_login_url_needs_gateway_fields()
    test_anon_client_tunnels_https_and_sends_browser_headers()
    test_anon_client_tunnels_plain_http_too()
    test_anon_client_uses_curl_backend_with_impersonation()
    test_anon_client_upgrades_socks5_to_socks5h_for_remote_dns()
    test_anon_client_stdlib_rejects_socks_proxy()
    test_rewrite_netloc_keeps_creds_and_path()
    test_socks5_connect_sends_domain_request_for_remote_dns()
    test_http_connect_accepts_200_and_rejects_others()

    try:
        from scanners.task import ShodanBanner
    except ImportError:
        print("OK (ShodanBanner check skipped: nmap/shodan not installed)")
    else:
        banner = ShodanBanner(
            ip_str="1.2.3.4",
            port="554",
            location={"city": "SP", "unrelated": 1},
            junk="ignored",
        )
        assert banner.port == 554
        assert banner.location.city == "SP"

        from scanners.config import NmapConfig
        from scanners.task import NmapTask

        class _SocksProxy:
            def url(self):
                return "socks5://1.2.3.4:1080"

        task = NmapTask(NmapConfig(ip_range="10.0.0.0/30"), _SocksProxy())
        try:
            task._scan("10.0.0.1")  # guard fires before any real scan runs
        except ValueError as e:
            assert "socks5" in str(e)
        else:
            raise AssertionError("NmapTask must reject a socks5 proxy")

    print("all self-checks passed")


if __name__ == "__main__":
    _run()
