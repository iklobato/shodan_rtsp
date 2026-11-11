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
from scanners.config import CheckersConfig, NmapConfig, load_config
from scanners.rtsp_probe import DirectTransport, RtspTarget
from tests.conftest import MemoryDatabase


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


@pytest.mark.parametrize("value,expected", [("false", False), ("true", True)])
def test_checkers_randomize_is_coerced_to_bool(value, expected):
    config = CheckersConfig(
        wordlist_users="requirements.txt",  # FilePath only checks existence
        wordlist_passwords="requirements.txt",
        wordlist_rtsp_urls="requirements.txt",
        randomize=value,
    )
    assert config.randomize is expected


# --- rtsp transport -------------------------------------------------------


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


def test_nmap_task_scans_the_service_ports(
    tmp_path: Path, database: MemoryDatabase
) -> None:
    """One nmap invocation over the port list of D15, with no proxy argument."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    scanner = _StubNmapScanner({})
    task = NmapTask(
        NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME)),
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
    task = NmapTask(config, database)
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
    task = NmapTask(config, database)
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
    assert config.database.dsn == "postgresql://u:p@h/d"


def test_load_config_missing_required_field_fails_fast(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("shodan:\n  api_key: x\n")  # missing checkers/nmap/database
    with pytest.raises(Exception):
        load_config(str(cfg))
