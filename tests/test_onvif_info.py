"""The ONVIF class describes the device, and a description is not a picture.

FR-019 is the reason this class is in the batch at all: the model and the
firmware it reads unauthenticated are what a firmware-level CVE is matched on
later, even though the read yields no frame (D31).
"""

from pathlib import Path

import pytest

from models.camera import CameraStatus
from models.finding import CveOutcome
from scanners.cve.base import CveTarget, ReadMethod, ReadRequest, ReadResponse
from scanners.cve.unauth_onvif import OnvifReadAction, XiongmaiOnvifInfo
from tests.conftest import (
    CveLab,
    MemoryDatabase,
    RecordingProbe,
    StubRoute,
    StubServer,
)

_LOOPBACK = "127.0.0.1"
_PORT = 8000
_OK_STATUS = 200
_SOAP_CONTENT_TYPE = "application/soap+xml"
_SERVICE_PATH = "/onvif/device_service"
_GET_DEVICE_INFORMATION = "GetDeviceInformation"
_MODEL = "IPC-HFW1230S"
_FIRMWARE = "V5.00.R02.00.00"
_ONVIF_CVE = "CVE-2025-65856"
_FIRST = 0
_ONE_ACTION = 1
_BATCH_CLASSES = 4

# A real GetDeviceInformationResponse, namespaced the way a device sends it.
_DEVICE_INFO = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    b'<tds:GetDeviceInformationResponse'
    b' xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
    b"<tds:Manufacturer>Xiongmai</tds:Manufacturer>"
    b"<tds:Model>IPC-HFW1230S</tds:Model>"
    b"<tds:FirmwareVersion>V5.00.R02.00.00</tds:FirmwareVersion>"
    b"<tds:SerialNumber>ABC123456</tds:SerialNumber>"
    b"</tds:GetDeviceInformationResponse></s:Body></s:Envelope>"
)
_NOT_XML = b"\x00\x01 not xml at all <<<"
_ALL_CVES: tuple[str, ...] = (
    "CVE-2017-7921",
    "CVE-2025-34022",
    "CVE-2016-15055",
    _ONVIF_CVE,
)


class FixedTransport:
    """A transport that answers every read with the one body the test named."""

    def __init__(self, response: ReadResponse) -> None:
        self._response = response
        self.asked: list[ReadRequest] = []

    def fetch(self, request: ReadRequest) -> ReadResponse:
        self.asked.append(request)
        return self._response


@pytest.fixture
def target() -> CveTarget:
    """Where the read is sent: one address and one port."""
    return CveTarget(host=_LOOPBACK, ports=(_PORT,))


@pytest.fixture
def lab(database: MemoryDatabase, stub_server: StubServer, tmp_path: Path) -> CveLab:
    """A camera at the stub server's port, with its frames under tmp_path."""
    return CveLab.at(database, tmp_path, stub_server.port)


def test_the_class_can_only_ask_for_the_device_description() -> None:
    """One read action, so a state-changing SOAP call cannot be expressed."""
    assert [action.value for action in OnvifReadAction] == [_GET_DEVICE_INFORMATION]


def test_the_description_comes_back_as_the_model_and_the_firmware(
    target: CveTarget,
) -> None:
    transport = FixedTransport(
        ReadResponse(
            status=_OK_STATUS, body=_DEVICE_INFO, content_type=_SOAP_CONTENT_TYPE
        )
    )
    outcome = XiongmaiOnvifInfo(transport).attempt(target)
    assert outcome.frame is None
    assert (outcome.model, outcome.firmware) == (_MODEL, _FIRMWARE)
    assert "not a picture" in outcome.reason
    request = transport.asked[_FIRST]
    assert request.method is ReadMethod.form_post
    assert request.url.endswith(_SERVICE_PATH)
    assert request.body.count(_GET_DEVICE_INFORMATION) == _ONE_ACTION


def test_a_body_that_is_not_a_description_records_a_plain_failure(
    target: CveTarget,
) -> None:
    """A body nobody can parse is a failure with no fields, not a description."""
    transport = FixedTransport(
        ReadResponse(
            status=_OK_STATUS, body=_NOT_XML, content_type=_SOAP_CONTENT_TYPE
        )
    )
    outcome = XiongmaiOnvifInfo(transport).attempt(target)
    assert (outcome.frame, outcome.model, outcome.firmware) == (None, "", "")
    assert "no device description" in outcome.reason


def test_the_model_and_the_firmware_land_on_the_camera_row(
    lab: CveLab, stub_server: StubServer
) -> None:
    """FR-019: ONVIF runs last, and what it read is kept even with no picture."""
    stub_server.routes[_SERVICE_PATH] = StubRoute(
        status=_OK_STATUS, body=_DEVICE_INFO, content_type=_SOAP_CONTENT_TYPE
    )
    lab.read_batch(lab.deps(probe=RecordingProbe(_ALL_CVES)))
    assert lab.outcomes() == [CveOutcome.no_frame] * _BATCH_CLASSES
    stored = lab.stored_camera()
    assert (stored.product, stored.version) == (_MODEL, _FIRMWARE)
    assert stored.status is CameraStatus.responded
    assert lab.frame_rows() == []
    finding = lab.findings()[-1]
    assert finding.cve_id == _ONVIF_CVE
    assert "not a picture" in finding.failure_reason
