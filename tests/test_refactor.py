"""Unit tests for the scanner's core logic.

Run: python3 -m pytest tests/ -q

Anything needing python-nmap / shodan is skipped when those are absent, so the
suite runs without the scanning stack installed.
"""

from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from models.camera import Camera, CameraStatus
from models.managers import CameraRepository
from scanners.brand_probe import BrandBook, Identifier
from scanners.config import CheckersConfig, NmapConfig, load_config
from scanners.rtsp_probe import DirectTransport, RtspTarget
from tests.conftest import MemoryDatabase

if TYPE_CHECKING:
    from scanners.task import CheckDeps

# The brands file the repo ships, so these tests also read the real one.
_BRANDS_FILE = Path(__file__).resolve().parents[1] / "brands.yaml"


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


@pytest.fixture
def identifier() -> Identifier:
    """The identifier over the brands file this repo ships."""
    return Identifier(BrandBook.load(str(_BRANDS_FILE)))


def test_nmap_task_scans_the_service_ports(
    tmp_path: Path, database: MemoryDatabase, identifier: Identifier
) -> None:
    """One nmap invocation over the port list of D15, with no proxy argument."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    scanner = _StubNmapScanner({})
    task = NmapTask(
        NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME)),
        identifier,
        database,
    )
    task.scanner = scanner
    task.run()
    assert scanner.arguments == f"-p {_SERVICE_PORTS} -sV"


def test_nmap_task_stores_open_ports_only(
    tmp_path: Path, database: MemoryDatabase, identifier: Identifier
) -> None:
    """A live host with 554 closed must not land in the DB as a camera."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    config = NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME))
    task = NmapTask(config, identifier, database)
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
    tmp_path: Path, database: MemoryDatabase, identifier: Identifier
) -> None:
    """FR-002: the run keeps the range it was allowed to reach, and its result."""
    pytest.importorskip("nmap")
    from models.scan_run import ScanKind, ScanRun
    from scanners.task import NmapTask

    config = NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME))
    task = NmapTask(config, identifier, database)
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


def test_nmap_task_keeps_the_run_xml(
    tmp_path: Path, database: MemoryDatabase, identifier: Identifier
) -> None:
    """The vuln mode reads this file, so the run must leave it on disk."""
    pytest.importorskip("nmap")
    from scanners.task import NmapTask

    xml = b'<nmaprun><host><address addr="10.0.0.2"/></host></nmaprun>'
    task = NmapTask(
        NmapConfig(ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME)),
        identifier,
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
    from scanners.task import TargetGate, TargetOutsideScopeError

    with pytest.raises(TargetOutsideScopeError):
        TargetGate(allowed).require_inside(query)


def test_shodan_query_inside_the_declared_range_passes() -> None:
    pytest.importorskip("shodan")
    from scanners.task import TargetGate

    TargetGate([_DECLARED]).require_inside(_INSIDE)


# --- the gate over stored cameras (FR-001, D18) ---------------------------

_STORED_INSIDE: tuple[str, ...] = ("10.1.2.3", "10.9.9.9")
_STORED_OUTSIDE: tuple[str, ...] = ("10.1.2.3", "192.0.2.10", "198.51.100.7")
_STORED_UNPARSABLE: tuple[str, ...] = ("not-an-address",)
_MANY_OUTSIDE: tuple[str, ...] = tuple(f"192.0.2.{last}" for last in range(1, 13))
_NAMED_LIMIT = 10


def test_a_run_over_declared_addresses_passes() -> None:
    """Every stored camera inside the declared list, so nothing to refuse."""
    from scanners.task import TargetGate

    TargetGate([_DECLARED]).require_reachable(_STORED_INSIDE)


def test_a_run_over_outside_addresses_is_refused() -> None:
    """A stored camera outside the declared list stops the whole run."""
    from scanners.task import TargetGate, TargetOutsideScopeError

    with pytest.raises(TargetOutsideScopeError) as refused:
        TargetGate([_DECLARED]).require_reachable(_STORED_OUTSIDE)

    assert "192.0.2.10" in str(refused.value), (
        f"the refusal does not name the first outside address: {refused.value}"
    )
    assert "198.51.100.7" in str(refused.value), (
        f"the refusal stops at the first address instead of naming every one: "
        f"{refused.value}"
    )


def test_an_empty_declaration_refuses_every_address() -> None:
    """No declared list authorizes nothing, so a stored camera is out too."""
    from scanners.task import TargetGate, TargetOutsideScopeError

    with pytest.raises(TargetOutsideScopeError):
        TargetGate(_NO_DECLARATION).require_reachable(_STORED_INSIDE)


def test_an_address_that_does_not_parse_is_outside() -> None:
    """An address the gate cannot read is never treated as declared."""
    from scanners.task import TargetGate, TargetOutsideScopeError

    with pytest.raises(TargetOutsideScopeError):
        TargetGate([_DECLARED]).require_reachable(_STORED_UNPARSABLE)


def test_a_long_refusal_stops_naming_after_the_limit() -> None:
    """The whole camera table is not an error line: it is cut, and the rest counted."""
    from scanners.task import TargetGate, TargetOutsideScopeError

    with pytest.raises(TargetOutsideScopeError) as refused:
        TargetGate([_DECLARED]).require_reachable(_MANY_OUTSIDE)

    message = str(refused.value)
    assert f"192.0.2.{_NAMED_LIMIT}" in message, (
        f"the address at the limit is missing: {message}"
    )
    assert f"192.0.2.{_NAMED_LIMIT + 1}" not in message, (
        f"the list was not cut short: {message}"
    )
    assert f"and {len(_MANY_OUTSIDE) - _NAMED_LIMIT} more" in message, (
        f"the count of what was left out is missing: {message}"
    )


class _StubProbe:
    """Fake RTSP probe: records every target it was handed and answers none."""

    def __init__(self) -> None:
        self.targets: list[RtspTarget] = []

    def probe(self, target: RtspTarget) -> None:
        self.targets.append(target)


class TestCheckGate:
    """What a check run reaches, over the cameras already in the database."""

    @pytest.fixture
    def deps(self, tmp_path: Path, identifier: Identifier) -> "CheckDeps":
        """Check settings over one-line wordlists, so a run tries one combo."""
        from scanners.config import TargetsConfig
        from scanners.task import CheckDeps

        wordlist = tmp_path / "one.txt"
        wordlist.write_text("admin\n")
        return CheckDeps(
            config=CheckersConfig(
                wordlist_users=str(wordlist),
                wordlist_passwords=str(wordlist),
                wordlist_rtsp_urls=str(wordlist),
            ),
            targets=TargetsConfig(allowed_cidrs=[_DECLARED]),
            identifier=identifier,
        )

    def test_a_stored_camera_outside_the_list_is_refused(
        self, deps: "CheckDeps", database: MemoryDatabase
    ) -> None:
        """A camera already in the database is still checked against the list."""
        from scanners.task import CheckTask, TargetOutsideScopeError

        repository = CameraRepository(database=database)
        repository.get_or_create(Camera(ip="192.0.2.10", port=_RTSP_PORT))
        probe = _StubProbe()

        with pytest.raises(TargetOutsideScopeError):
            CheckTask(replace(deps, probe=probe), database).run()

        assert probe.targets == [], f"the run reached the camera anyway: {probe.targets}"

    def test_narrowing_to_one_camera_reaches_it(
        self, deps: "CheckDeps", database: MemoryDatabase
    ) -> None:
        """D18: `--camera-id` reaches the address the operator named."""
        from scanners.task import CheckTask

        repository = CameraRepository(database=database)
        outside = repository.get_or_create(Camera(ip="192.0.2.10", port=_RTSP_PORT))
        probe = _StubProbe()

        CheckTask(replace(deps, camera_id=outside.id, probe=probe), database).run()

        assert [target.host for target in probe.targets] == ["192.0.2.10"], (
            f"the narrowed run did not reach the named camera: {probe.targets}"
        )


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


def test_load_config_reads_all_sections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The environment overrides the database host, so a job that exports
    # DATABASE_HOST (ci.yml does, for the migration tests) would otherwise
    # decide this assertion instead of the file.
    monkeypatch.delenv("DATABASE_HOST", raising=False)
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
