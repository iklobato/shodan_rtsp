"""Report the CVEs of the services in an nmap run, without exploiting them.

Reads an `nmap -sV -oX` file, names each open service through the configured
product -> CPE map, matches it against the configured NVD feed and writes the
findings to the report path. Nothing here contacts a device.
"""

import json
import logging
import xml.etree.ElementTree as ElementTree
from dataclasses import asdict, dataclass, replace
from xml.etree.ElementTree import Element

from scanners.config import AppConfig, VulnConfig
from scanners.task import Task
from scanners.vuln_probe import CpeMap, CveFeed, CveMatch, DeviceFingerprint, VulnProbe


class NmapXmlReader:
    """Reads an `nmap -sV -oX` file into one fingerprint per open service."""

    _HOST_TAG = "host"
    _ADDRESS_TAG = "address"
    _PORT_TAG = "port"
    _SERVICE_TAG = "service"
    _STATE_TAG = "state"
    _OPEN_STATE = "open"

    def read(self, path: str) -> list[DeviceFingerprint]:
        root = ElementTree.parse(path).getroot()
        return [
            fingerprint
            for host in root.iter(self._HOST_TAG)
            for fingerprint in self._host_fingerprints(host)
        ]

    def _host_fingerprints(self, host: Element) -> list[DeviceFingerprint]:
        # The first address is the IPv4 one; nmap lists the MAC after it.
        address = host.find(self._ADDRESS_TAG)
        if address is None:
            return []
        host_ip = address.get("addr", "")
        return [
            self._fingerprint(host_ip, port)
            for port in host.iter(self._PORT_TAG)
            if self._is_open(port)
        ]

    def _is_open(self, port: Element) -> bool:
        state = port.find(self._STATE_TAG)
        return state is not None and state.get("state") == self._OPEN_STATE

    def _fingerprint(self, host_ip: str, port: Element) -> DeviceFingerprint:
        port_id = int(port.get("portid", 0))
        service = port.find(self._SERVICE_TAG)
        if service is None:
            return DeviceFingerprint(host=host_ip, port=port_id)
        return DeviceFingerprint(
            host=host_ip,
            port=port_id,
            product=service.get("product", ""),
            version=service.get("version", ""),
            cpe=service.get("cpe", ""),
        )


@dataclass(frozen=True)
class VulnScanDeps:
    """What VulnScanTask needs, so its constructor stays under three args."""

    config: VulnConfig
    probe: VulnProbe | None = None
    reader: NmapXmlReader | None = None


class VulnScanTask(Task):
    """Report the CVEs of the services in an nmap run. No device is contacted."""

    _REPORT_INDENT = 2

    def __init__(self, deps: VulnScanDeps) -> None:
        self._deps = deps

    @classmethod
    def from_config(cls, config: AppConfig) -> "VulnScanTask":
        return cls(deps=VulnScanDeps(config=config.vuln))

    def report_findings(self) -> None:
        config = self._deps.config
        devices = self._reader().read(config.nmap_xml)
        logging.info("Read %d services from %s", len(devices), config.nmap_xml)
        matches = self._match_all(devices)
        self._write_report(matches)
        for match in matches:
            logging.info(
                "%s:%d %s (CVSS %.1f)", match.host, match.port, match.cve_id, match.cvss
            )
        logging.info("%d CVE matches in %d services", len(matches), len(devices))

    # Task declares run() abstract and the CLI calls it; the mode's own name is
    # report_findings, which says what this task does where "run" does not.
    run = report_findings

    def _match_all(self, devices: list[DeviceFingerprint]) -> list[CveMatch]:
        probe = self._probe()
        return [match for device in devices for match in probe.match(device)]

    def _probe(self) -> VulnProbe:
        if self._deps.probe is None:
            config = self._deps.config
            self._deps = replace(
                self._deps,
                probe=VulnProbe(
                    feed=CveFeed(config.feed_path),
                    cpe_map=CpeMap(config.cpe_map_path),
                    min_cvss=config.min_cvss,
                ),
            )
        return self._deps.probe

    def _reader(self) -> NmapXmlReader:
        if self._deps.reader is None:
            self._deps = replace(self._deps, reader=NmapXmlReader())
        return self._deps.reader

    def _write_report(self, matches: list[CveMatch]) -> None:
        with open(self._deps.config.report_path, "w") as handle:
            json.dump(
                [asdict(match) for match in matches], handle, indent=self._REPORT_INDENT
            )
