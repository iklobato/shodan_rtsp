"""Brand detection comes from brands.yaml, so a new brand is a data line (T036).

FR-012: the signature data drives the detection. The second test adds a brand
that exists only in the file, which is the whole point of the front: no code
change and no release to support a device the scanner has never seen.
"""

from pathlib import Path

import pytest

from scanners.brand_probe import BrandBook, Identifier, ServiceEvidence

_FILE = """
brands:
  hikvision:
    match: ["Hikvision-IP", "Hikvision", "IpCamera$"]
    vendor: hikvision
    product: ip_camera
    users: [admin]
    passwords: [admin, 12345]
    url_templates: ["rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101"]
  acme:
    match: ["ACME-CAM"]
    vendor: acme
    product: acme_cam
"""


@pytest.fixture
def book(tmp_path: Path) -> BrandBook:
    """A brands file holding one known brand and one only the file knows."""
    path = tmp_path / "brands.yaml"
    path.write_text(_FILE)

    return BrandBook.load(str(path))


@pytest.fixture
def identifier(book: BrandBook) -> Identifier:
    return Identifier(book)


def test_a_known_banner_names_the_vendor_and_the_product(
    identifier: Identifier,
) -> None:
    evidence = ServiceEvidence(source="shodan", banner="Hikvision-IP camera")

    found = identifier.identify(evidence)

    assert (found.vendor, found.product) == ("hikvision", "ip_camera"), (
        f"the banner names a Hikvision camera, got {found}"
    )


def test_a_brand_only_in_the_file_is_detected(identifier: Identifier) -> None:
    evidence = ServiceEvidence(source="nmap", banner="ACME-CAM/2.1 httpd")

    found = identifier.identify(evidence)

    assert (found.vendor, found.product) == ("acme", "acme_cam"), (
        f"a brand the file adds must be detected with no code change, got {found}"
    )


def test_the_version_comes_from_what_the_scan_reported(
    identifier: Identifier,
) -> None:
    evidence = ServiceEvidence(
        source="nmap", banner="Hikvision", product="Hikvision", version="5.4.0"
    )

    found = identifier.identify(evidence)

    assert found.version == "5.4.0", f"the scan reported 5.4.0, got {found.version!r}"


def test_a_cpe_from_the_scan_wins_over_a_signature(identifier: Identifier) -> None:
    """The CPE is what the device said about itself, so it outranks a pattern."""
    evidence = ServiceEvidence(
        source="nmap",
        banner="nginx",
        product="nginx",
        cpe="cpe:2.3:a:hikvision:ip_camera:5.4.0:*:*:*:*:*:*:*",
    )

    found = identifier.identify(evidence)

    assert (found.vendor, found.product, found.version) == (
        "hikvision",
        "ip_camera",
        "5.4.0",
    ), f"the CPE names the device, got {found}"


def test_the_brand_it_matched_is_kept(identifier: Identifier) -> None:
    evidence = ServiceEvidence(source="shodan", banner="Hikvision-IP camera")

    found = identifier.identify(evidence)

    assert found.brand == "hikvision", f"the matched brand was dropped: {found}"


_SHIPPED_FILE = Path(__file__).resolve().parents[1] / "brands.yaml"
_EMBEDDED_SERVERS: tuple[str, ...] = ("Boa/0.94.14rc21", "GoAhead-Webs")
_EMBEDDED_PAIRS: tuple[tuple[str, str], ...] = (
    ("boa", "boa"),
    ("embedthis", "goahead"),
)


def test_the_shipped_file_names_the_web_servers_cameras_embed() -> None:
    """A camera that reports only its web server is still named, from the file."""
    identifier = Identifier(BrandBook.load(str(_SHIPPED_FILE)))

    found = [
        identifier.identify(ServiceEvidence.from_nmap({"product": banner}))
        for banner in _EMBEDDED_SERVERS
    ]

    assert [(identity.vendor, identity.product) for identity in found] == list(
        _EMBEDDED_PAIRS
    ), f"the shipped file does not name the embedded servers: {found}"
