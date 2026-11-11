"""Unit tests for the scanner's core logic.

Run: python3 -m pytest tests/ -q

Anything needing python-nmap / shodan is skipped when those are absent, so the
suite runs without the scanning stack installed.
"""

from collections.abc import Sequence
from pathlib import Path

import pytest

from models.camera import Camera, CameraStatus
from models.managers import CameraRepository
from scanners.config import CheckersConfig, NmapConfig, ProxyConfig, load_config
from scanners.proxy import (
    AnonymousProxyClient,
    ConnectFetcher,
    CurlFetcher,
    TwoCaptchaProxy,
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
from tests.conftest import MemoryDatabase


def _proxy(cached_url="http://78.141.222.54:15000", **overrides):
    overrides.setdefault("protocol", "http")
    proxy = TwoCaptchaProxy(config=ProxyConfig(token="tok", **overrides))
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
        wordlist_users="requirements.txt",  # FilePath only checks existence
        wordlist_passwords="requirements.txt",
        wordlist_rtsp_urls="requirements.txt",
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

_RTSP_PORT = 554
_SERVICE_PORTS = "554,80,443,8000,8080,8554,34567"
_NMAP_XML_NAME = "nmap.xml"
_LAB_RANGE = "10.0.0.0/30"
_ONE_CAMERA = 1


class _StubNmapScanner:
    """Fake nmap: records the arguments and replays a canned scan result."""

    def __init__(self, hosts: dict, xml: bytes = b"") -> None:
        self.arguments: str | None = None
        self._hosts = hosts
        self._xml = xml

    def scan(self, hosts: str, arguments: str) -> dict:
        self.arguments = arguments
        return {"scan": self._hosts}

    def get_nmap_last_output(self) -> bytes:
        return self._xml


def test_nmap_task_rejects_socks5_proxy():
    pytest.importorskip("nmap")
    from scanners.task import NmapTask, UnsupportedProxySchemeError

    class _SocksProxy:
        def url(self):
            return "socks5://1.2.3.4:1080"

    task = NmapTask(NmapConfig(ip_range=_LAB_RANGE), _SocksProxy())
    with pytest.raises(UnsupportedProxySchemeError, match="socks5"):
        task._scan("10.0.0.1")  # guard fires before any real scan runs


def test_nmap_task_scans_direct_without_proxy(
    tmp_path: Path, database: MemoryDatabase
) -> None:
    """proxy.enabled false gives NmapTask no proxy: nmap must run un-proxied."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    scanner = _StubNmapScanner({})
    task = NmapTask(
        NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME)),
        None,
        database,
    )
    task.scanner = scanner
    task.run()
    assert scanner.arguments == f"-p {_SERVICE_PORTS} -sV"


def test_nmap_task_stores_open_ports_only(
    tmp_path: Path, database: MemoryDatabase
) -> None:
    """A live host with 554 closed must not land in the DB as a camera."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    config = NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME))
    task = NmapTask(config, None, database)
    task.scanner = _StubNmapScanner(
        {
            "10.0.0.1": {"tcp": {_RTSP_PORT: {"state": "closed"}}},
            "10.0.0.2": {"tcp": {_RTSP_PORT: {"state": "open"}}},
        }
    )
    task.run()
    with database.session_scope() as session:
        stored = [(row.ip, row.port) for row in session.query(Camera).all()]
    assert stored == [("10.0.0.2", _RTSP_PORT)]


def test_nmap_task_records_the_run_it_reached(
    tmp_path: Path, database: MemoryDatabase
) -> None:
    """FR-002: the run keeps the range it was allowed to reach, and its result."""
    pytest.importorskip("nmap")
    from models.scan_run import ScanKind, ScanRun
    from scanners.task import NmapTask

    config = NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME))
    task = NmapTask(config, None, database)
    task.scanner = _StubNmapScanner(
        {"10.0.0.2": {"tcp": {_RTSP_PORT: {"state": "open"}}}}
    )
    task.run()
    with database.session_scope() as session:
        run = session.query(ScanRun).one()
        assert run.kind is ScanKind.nmap
        assert run.target_set == _LAB_RANGE
        assert run.camera_count == _ONE_CAMERA
        assert run.finished_at is not None


def test_nmap_task_keeps_the_run_xml(tmp_path: Path, database: MemoryDatabase) -> None:
    """The vuln mode reads this file, so the run must leave it on disk."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    xml = b'<nmaprun><host><address addr="10.0.0.2"/></host></nmaprun>'
    task = NmapTask(
        NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME)),
        None,
        database,
    )
    task.scanner = _StubNmapScanner({}, xml=xml)
    task.run()
    assert (tmp_path / _NMAP_XML_NAME).read_bytes() == xml


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


# --- the target gate (D18, FR-001) ----------------------------------------

_DECLARED = "10.0.0.0/8"
_INSIDE = "net:10.1.2.0/24 webcam"
_OUTSIDE = "net:200.1.2.0/24 webcam"
_NO_RANGE = "screenshot.label:webcam country:BR"
_HOST_BITS = "net:10.0.0.5/24"
_NOT_A_RANGE = "net:not-a-range"
_NO_DECLARATION: tuple[str, ...] = ()


@pytest.mark.parametrize(
    "query,allowed",
    [
        (_OUTSIDE, [_DECLARED]),
        (_NO_RANGE, [_DECLARED]),
        (_INSIDE, _NO_DECLARATION),
        (_HOST_BITS, [_DECLARED]),
        (_NOT_A_RANGE, [_DECLARED]),
    ],
)
def test_shodan_query_outside_the_declared_ranges_is_refused(
    query: str, allowed: Sequence[str]
) -> None:
    """Every way of reaching past the declared list fails closed, before the API."""
    pytest.importorskip("shodan")
    from scanners.task import ShodanScope, TargetOutsideScopeError

    with pytest.raises(TargetOutsideScopeError):
        ShodanScope(allowed).require_inside(query)


def test_shodan_query_inside_the_declared_range_passes() -> None:
    pytest.importorskip("shodan")
    from scanners.task import ShodanScope

    ShodanScope([_DECLARED]).require_inside(_INSIDE)


# --- repository (in-memory sqlite, no external DB) ------------------------


def test_mark_stream_obtained_persists_credentials_into_columns(
    database: MemoryDatabase,
) -> None:
    repo = CameraRepository(database=database)
    repo.get_or_create(Camera(ip="1.2.3.4", port=_RTSP_PORT))
    found = Camera(
        ip="1.2.3.4",
        port=_RTSP_PORT,
        user="admin",
        password="1234",
        url="rtsp://admin:1234@1.2.3.4:554/live",
        status=CameraStatus.stream_obtained,
    )
    assert repo.mark_stream_obtained(found) is True
    stored = repo.get_with_frame()[0]
    assert (stored.user, stored.password) == ("admin", "1234")
    assert stored.url == "rtsp://admin:1234@1.2.3.4:554/live"


def test_get_or_create_does_not_duplicate_the_camera(
    database: MemoryDatabase,
) -> None:
    """A second scan of one endpoint finds the row instead of adding one."""
    repo = CameraRepository(database=database)
    first = repo.get_or_create(Camera(ip="1.2.3.4", port=_RTSP_PORT))
    second = repo.get_or_create(Camera(ip="1.2.3.4", port=_RTSP_PORT))
    assert second.id == first.id


def test_mark_stream_obtained_returns_false_for_unknown_camera(
    database: MemoryDatabase,
) -> None:
    repo = CameraRepository(database=database)
    assert repo.mark_stream_obtained(Camera(ip="9.9.9.9", port=1)) is False


# --- centralised config (single config.yaml) ------------------------------


def test_load_config_reads_all_sections(tmp_path):
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("admin\n")
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"""
shodan:
  api_key: SKEY
checkers:
  wordlist_users: {wordlist}
  wordlist_passwords: {wordlist}
  wordlist_rtsp_urls: {wordlist}
  randomize: true
nmap:
  ip_range: 10.0.0.0/24
proxy:
  token: PTOKEN
  protocol: socks5
database:
  user: u
  password: p
  host: h
  db: d
""")
    config = load_config(str(cfg))
    assert config.shodan.api_key == "SKEY"
    assert config.shodan.query.startswith("screenshot.label")  # default applied
    assert config.checkers.randomize is True
    assert config.nmap.ip_range == "10.0.0.0/24"
    assert config.proxy.protocol == "socks5"
    assert config.database.dsn == "postgresql://u:p@h/d"


def test_load_config_missing_required_field_fails_fast(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("shodan:\n  api_key: x\n")  # missing checkers/nmap/proxy/database
    with pytest.raises(Exception):
        load_config(str(cfg))
