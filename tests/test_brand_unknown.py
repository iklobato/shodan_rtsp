"""A device matching no signature is stored as unknown, banner kept (T037).

FR-014. The evidence is what a later front re-reads when a signature is added,
so it has to survive the device not being named today.
"""

from pathlib import Path

import pytest

from models.camera import Camera, CameraStatus
from scanners.brand_probe import BrandBook, Identifier
from scanners.config import NmapConfig
from scanners.task import NmapTask
from tests.conftest import MemoryDatabase

_RTSP_PORT = 554
_LAB_RANGE = "127.0.0.1/32"
_NMAP_XML_NAME = "nmap.xml"
_OPEN = "open"
_STRANGER = "Frobnicator 3000"
_KNOWN_BANNER = "Hikvision-IP camera"
_FILE = """
brands:
  hikvision:
    match: ["Hikvision-IP"]
    vendor: hikvision
    product: ip_camera
"""


class StubNmapScanner:
    """Fake nmap: replays one host with one open port and its service fields."""

    def __init__(self, port_data: dict) -> None:
        self.port_data = port_data

    def scan(self, hosts: str, arguments: str) -> dict:
        return {"scan": {"127.0.0.1": {"tcp": {_RTSP_PORT: self.port_data}}}}

    def get_nmap_last_output(self) -> bytes:
        return b""


@pytest.fixture
def identifier(tmp_path: Path) -> Identifier:
    path = tmp_path / "brands.yaml"
    path.write_text(_FILE)

    return Identifier(BrandBook.load(str(path)))


@pytest.fixture
def scan_an_unknown_device(
    tmp_path: Path, database: MemoryDatabase, identifier: Identifier
) -> tuple[MemoryDatabase, Path]:
    """Run one nmap pass over a host whose service matches no signature."""
    xml_path = tmp_path / _NMAP_XML_NAME
    config = NmapConfig(ip_range=_LAB_RANGE, xml_path=str(xml_path))
    task = NmapTask(config, identifier, database)
    task.scanner = StubNmapScanner(
        {"state": _OPEN, "product": _STRANGER, "version": "1.2"}
    )
    task.run()

    return database, xml_path


class TestStoredUnknown:
    """What the camera row holds after the device was not named."""

    @pytest.fixture
    def stored(self, scan_an_unknown_device: tuple) -> Camera:
        database, _ = scan_an_unknown_device
        with database.session_scope() as session:
            return session.query(Camera).one()

    def test_an_unmatched_device_is_not_named(self, stored: Camera) -> None:
        assert (stored.vendor, stored.product) == ("", ""), (
            f"no signature matched, so nothing is named, got {stored.vendor!r}"
        )

    def test_the_status_stays_unknown(self, stored: Camera) -> None:
        assert stored.status is CameraStatus.unknown, (
            f"identifying nothing does not change the status, got {stored.status}"
        )

    def test_the_raw_banner_survives(self, stored: Camera) -> None:
        assert stored.raw_banner is not None, (
            "the evidence the identification failed on was thrown away"
        )
        assert stored.raw_banner["product"] == _STRANGER, (
            f"the banner kept is {stored.raw_banner}"
        )


def test_a_named_device_keeps_its_evidence_too(
    tmp_path: Path, database: MemoryDatabase, identifier: Identifier
) -> None:
    """The banner is kept for a device that was named, not only for a stranger."""
    config = NmapConfig(
        ip_range=_LAB_RANGE, xml_path=str(tmp_path / _NMAP_XML_NAME)
    )
    task = NmapTask(config, identifier, database)
    task.scanner = StubNmapScanner(
        {"state": _OPEN, "product": _KNOWN_BANNER, "version": "5.4.0"}
    )
    task.run()

    with database.session_scope() as session:
        stored = session.query(Camera).one()

    assert stored.raw_banner["banner"] == _KNOWN_BANNER, (
        f"the banner the identification used is the evidence, got {stored.raw_banner}"
    )
