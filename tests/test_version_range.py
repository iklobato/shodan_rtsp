"""The CVE map attaches the vulnerable range that covered the version (T038).

FR-013. The range is what a later front writes to `cve_finding.matched_range`, so
it has to come out of the match itself and not be recomputed from the version.

The second half is the shape a real NVD camera record has, and the one the first
half got wrong: the hardware CPE of a camera is flagged `vulnerable: false` and
the range sits on the firmware CPE of the same model. Measured against
CVE-2017-7921 on 2026-11-11: 58 vulnerable ranges, every one of them a
`hikvision:<model>_firmware` product.
"""

from pathlib import Path

import pytest

from scanners.vuln_probe import CpeMap, CveFeed, DeviceFingerprint, VulnProbe

_HOST = "127.0.0.1"
_PORT = 554
_BOUNDED_RANGE = ">=5.0.0, <5.5.0"
_PRODUCT = "Hikvision IP camera"
_EMPTY_MAP = "products: {}\n"
_MODEL = "ds-2cd2032-i"
_MODEL_CVE = "CVE-2017-7921"
_CPE_MAP = f"""
products:
  {_PRODUCT}: "hikvision:ip_camera"
"""
_FEED_JSON = """{
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-36260",
                "descriptions": [{"lang": "en", "value": "command injection"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:hikvision:ip_camera:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "5.0.0",
                                        "versionEndExcluding": "5.5.0"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        },
        {
            "cve": {
                "id": "CVE-2017-7921",
                "descriptions": [{"lang": "en", "value": "auth bypass"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:hikvision:ip_camera:4.0.0:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    ]
}"""


_FIRMWARE_FEED_JSON = """{
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2017-7921",
                "descriptions": [{"lang": "en", "value": "auth bypass"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": false,
                                        "criteria": "cpe:2.3:h:hikvision:ds-2cd2032-i:-:*:*:*:*:*:*:*"
                                    },
                                    {
                                        "vulnerable": true,
                                        "criteria": "cpe:2.3:o:hikvision:ds-2cd2032-i_firmware:-:*:*:*:*:*:*:*"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    ]
}"""


@pytest.fixture
def probe(tmp_path: Path) -> VulnProbe:
    """A probe over a two-record feed and the map that reaches it."""
    feed_path = tmp_path / "nvdcve.json"
    feed_path.write_text(_FEED_JSON)
    map_path = tmp_path / "cpe_map.yaml"
    map_path.write_text(_CPE_MAP)

    return VulnProbe(CveFeed(str(feed_path)), CpeMap(str(map_path)))


@pytest.fixture
def firmware_probe(tmp_path: Path) -> VulnProbe:
    """A probe over the record shape a real camera CVE has."""
    feed_path = tmp_path / "firmware.json"
    feed_path.write_text(_FIRMWARE_FEED_JSON)
    map_path = tmp_path / "cpe_map.yaml"
    map_path.write_text(_EMPTY_MAP)

    return VulnProbe(CveFeed(str(feed_path)), CpeMap(str(map_path)))


def test_the_range_that_covered_the_version_is_attached(probe: VulnProbe) -> None:
    device = DeviceFingerprint(host=_HOST, port=_PORT, product=_PRODUCT, version="5.4.0")

    found = probe.match(device)

    assert [cve_match.matched_range for cve_match in found] == [_BOUNDED_RANGE], (
        f"5.4.0 sits inside the range, got {[cve_match.matched_range for cve_match in found]}"
    )


def test_a_version_outside_the_range_matches_nothing(probe: VulnProbe) -> None:
    device = DeviceFingerprint(host=_HOST, port=_PORT, product=_PRODUCT, version="5.6.0")

    found = probe.match(device)

    assert found == [], f"5.6.0 is above the range, got {found}"


def test_an_exact_version_match_reports_that_version(probe: VulnProbe) -> None:
    device = DeviceFingerprint(host=_HOST, port=_PORT, product=_PRODUCT, version="4.0.0")

    found = probe.match(device)

    assert [cve_match.matched_range for cve_match in found] == ["4.0.0"], (
        f"the pattern names one version, got {[cve_match.matched_range for cve_match in found]}"
    )


def test_a_pair_the_feed_does_not_carry_is_retried_as_the_firmware_cpe(
    firmware_probe: VulnProbe,
) -> None:
    """The model alone is not a product NVD knows: the range is on its firmware."""
    device = DeviceFingerprint(
        host=_HOST, port=_PORT, vendor="hikvision", product=_MODEL
    )

    found = firmware_probe.match(device)

    assert [cve_match.cve_id for cve_match in found] == [_MODEL_CVE], (
        f"the model's firmware CPE is the one the range names, got {found}"
    )


def test_a_pair_the_feed_carries_in_neither_form_matches_nothing(
    firmware_probe: VulnProbe,
) -> None:
    """The retry adds one product name, it does not invent a match."""
    device = DeviceFingerprint(
        host=_HOST, port=_PORT, vendor="hikvision", product="ip_camera"
    )

    found = firmware_probe.match(device)

    assert found == [], f"no product of that name is in the feed, got {found}"


def test_the_identified_vendor_and_product_reach_the_feed(probe: VulnProbe) -> None:
    """A camera named from brands.yaml needs no product string in the CVE map."""
    device = DeviceFingerprint(
        host=_HOST, port=_PORT, vendor="hikvision", product="ip_camera", version="5.4.0"
    )

    found = probe.match(device)

    assert [cve_match.cve_id for cve_match in found] == ["CVE-2021-36260"], (
        f"the camera fields name the CPE, got {[cve_match.cve_id for cve_match in found]}"
    )
