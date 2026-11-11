import itertools
import logging
import random
from abc import ABC, abstractmethod
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Network
from typing import Dict

import nmap
import shodan
from pydantic import BaseModel, ConfigDict, Field
from shodan import APIError

from models.camera import Camera
from models.database import Database, default_database
from models.managers import (
    CameraObservationRepository,
    CameraRepository,
    ScanRunRepository,
)
from models.scan_run import ScanKind, ScanRun
from scanners.config import CheckersConfig, NmapConfig, ShodanConfig
from scanners.rtsp_probe import RtspProbe, RtspTarget

__version__ = "0.1.0"

# nmap's port state for a service that accepted the connection.
_OPEN_STATE = "open"

# Shodan's range filter. It is the only part of a query that names an address
# range, so it is the only part the declared list can be checked against (D18).
_NET_FILTER = "net:"


class TargetOutsideScopeError(Exception):
    """The scan asks for addresses that are not in the declared target list."""


class _Location(BaseModel):
    model_config = ConfigDict(extra="ignore")

    city: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    region_code: str | None = None


class ShodanBanner(BaseModel):
    """The subset of a Shodan search banner this scanner cares about."""

    model_config = ConfigDict(extra="ignore")

    ip_str: str
    port: int
    location: _Location = Field(default_factory=_Location)
    org: str = ""  # ISP/org name from Shodan
    hostnames: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class Task(ABC):
    """Base task: a validated config model and the database it writes through."""

    def __init__(self, config: BaseModel, database: Database = None):
        if config is None:
            raise ValueError("Config is required")
        self.config = config
        self.database = database

    @property
    def repository(self) -> CameraRepository:
        """The camera table, on the database this task was given."""
        return CameraRepository(self._database())

    @property
    def runs(self) -> ScanRunRepository:
        return ScanRunRepository(self._database())

    @property
    def observations(self) -> CameraObservationRepository:
        return CameraObservationRepository(self._database())

    def _database(self) -> Database:
        return self.database or default_database()

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError("You must implement the run method")


class NmapTask(Task):
    """Scan a network range with nmap and store the hosts that answer on RTSP."""

    def __init__(self, config: NmapConfig, database: Database = None):
        super().__init__(config, database)
        self.scanner = nmap.PortScanner()

    def run(self) -> None:
        logging.info(f"Starting nmap scanning on {self.config.ip_range}")
        run = self.runs.start(ScanKind.nmap, self.config.ip_range)

        hosts = self._scan(self.config.ip_range)
        logging.info(f"Found {len(hosts)} hosts using nmap scan")

        self._write_xml()
        cameras = 0
        for host, host_data in hosts.items():
            cameras += self._store_open_ports(host, host_data, run)
        self.runs.finish(run, cameras)
        logging.info("Executors: finished nmap scan")

    def _write_xml(self) -> None:
        """Keep the run's raw nmap XML, where the vuln mode reads it.

        python-nmap owns the XML: it rejects an `-oX` argument of ours, so the
        only way to keep the run's output is to ask it for the last one it made.
        That is the raw stdout of `nmap -oX -`, so it is bytes, despite the
        method's docstring saying string.
        """
        with open(self.config.xml_path, "wb") as handle:
            handle.write(self.scanner.get_nmap_last_output())
        logging.info(f"nmap XML written to {self.config.xml_path}")

    def _store_open_ports(self, host: str, host_data: Dict, run: ScanRun) -> int:
        """Store the host's open ports only, and say how many cameras that was.

        nmap reports every scanned port, closed and filtered included; only an
        open one is a camera, otherwise each live host lands in the DB as a
        camera the check task then burns a full credential run on. Every sighting
        is also snapshotted against the run, so the series keeps what the camera
        looked like at this moment (FR-006).
        """
        stored = 0
        for port, port_data in host_data.get("tcp", {}).items():
            if port_data["state"] != _OPEN_STATE:
                continue
            camera = self.repository.get_or_create(Camera(ip=host, port=port))
            self.observations.record(camera, run)
            stored += 1
            logging.debug(f"Added on db {host}:{port}")
        return stored

    def _scan(self, target: str) -> Dict:
        arguments = f"-p {self._ports_argument()} -sV"
        if self.config.parallelism > 0:
            arguments += f" -T4 --min-parallelism {self.config.parallelism}"
        response = self.scanner.scan(hosts=target, arguments=arguments)
        return response.get("scan")

    def _ports_argument(self) -> str:
        """The service scan port list of D15, as nmap wants it."""
        return ",".join(str(port) for port in self.config.ports)


class ShodanScope:
    """The target gate of D18: what a Shodan query is allowed to reach.

    Shodan's `net:` filter is the only part of a query that names an address
    range, so it is the only part that can be checked before the API call.
    Everything else in a query is a keyword, and Shodan gives no way to ask
    whether a result set stays inside a range. A query with no `net:` filter
    therefore reaches the whole index and fails closed: an empty declared list
    authorizes nothing.
    """

    def __init__(self, allowed_cidrs: Sequence[str]) -> None:
        self._allowed_cidrs = allowed_cidrs

    def require_inside(self, query: str) -> None:
        """Refuse the query unless every range it names is declared."""
        networks = self._parse(self._net_tokens(query))
        if not networks:
            raise TargetOutsideScopeError(
                "the query names no `net:` range, so it reaches the whole index; "
                "declare the range the scan may reach in the query itself"
            )
        allowed = self._parse(self._allowed_cidrs)
        for network in networks:
            if not any(network.subnet_of(declared) for declared in allowed):
                raise TargetOutsideScopeError(
                    f"{network} is outside the declared ranges "
                    f"{self._allowed_cidrs}; declare it in shodan.allowed_cidrs"
                )

    def _net_tokens(self, query: str) -> list[str]:
        """The value of each `net:` filter of the query, as written."""
        return [
            token.removeprefix(_NET_FILTER)
            for token in query.split()
            if token.startswith(_NET_FILTER)
        ]

    def _parse(self, tokens: Sequence[str]) -> list[IPv4Network]:
        """Each token as an IPv4 network, refusing anything that is not one.

        IPv4Network turns down an IPv6 token too, which is what this pipeline
        wants: every address in it (Shodan banner, nmap range, RTSP host) is
        IPv4. strict=True so a token like 10.0.0.5/24 is refused instead of
        being quietly widened to 10.0.0.0/24: a declared range must never cover
        more than what was written.
        """
        ranges = []
        for token in tokens:
            try:
                ranges.append(IPv4Network(token, strict=True))
            except ValueError as unparsable:
                raise TargetOutsideScopeError(
                    f"address range does not parse: {token}"
                ) from unparsable
        return ranges


class ShodanTask(Task):
    """Search Shodan for cameras and store the new ones in the database."""

    config: ShodanConfig

    _BLOCKED_ORGS: frozenset[str] = frozenset(
        {
            "university",
            "college",
            "school",
            "education",
            "hospital",
            "medical",
            "clinic",
            "government",
            "military",
            "municipality",
            "library",
            "museum",
            "church",
            "mosque",
            "at&t",
            "comcast",
            "verizon",
            "spectrum",
            "xfinity",
            "charter",
            "cox",
            "frontier",
        }
    )

    _BLOCKED_TAGS: frozenset[str] = frozenset(
        {
            "university",
            "college",
            "school",
            "education",
            "hospital",
            "medical",
            "clinic",
            "government",
            "military",
            "municipality",
            "library",
            "museum",
            "church",
            "mosque",
        }
    )

    _PRIORITY_TAGS: frozenset[str] = frozenset(
        {
            "residential",
            "home",
            "office",
            "business",
            "company",
            "enterprise",
            "corporate",
            "apartment",
            "hotel",
            "motel",
        }
    )

    _PRIORITY_ORGS: frozenset[str] = frozenset(
        {
            "comcast",
            "verizon",
            "at&t",
            "spectrum",
            "xfinity",
            "charter",
            "cox",
            "frontier",
        }
    )

    def run(self) -> None:
        scope = ShodanScope(self.config.allowed_cidrs)
        scope.require_inside(self.config.query)
        run = self.runs.start(ScanKind.shodan, self.config.query)
        api = shodan.Shodan(self.config.api_key)
        query = self.config.query
        logging.info("Updating database")

        cams_added = 0
        try:
            for raw in api.search_cursor(query):
                banner = ShodanBanner(**raw)
                if self.repository.find(banner.ip_str, banner.port):
                    continue
                category = self._classify_banner(banner)
                if category is None:
                    logging.debug(
                        "Skipped %s:%d (blocked org/tag)", banner.ip_str, banner.port
                    )
                    continue
                camera = self.repository.get_or_create(
                    Camera(
                        ip=banner.ip_str,
                        port=banner.port,
                        city=banner.location.city,
                        country_code=banner.location.country_code,
                        country_name=banner.location.country_name,
                        region_code=banner.location.region_code,
                    )
                )
                self.observations.record(camera, run)
                logging.debug(
                    "%s:%d added (priority=%s)", banner.ip_str, banner.port, category
                )
                cams_added += 1
            logging.info(f"{cams_added} cameras added")
        except APIError as e:
            logging.error(f"Shodan api error: {e}")
        finally:
            # A run left open reads as a scan still in flight, so the row is
            # closed even when the API call died halfway.
            self.runs.finish(run, cams_added)

    @classmethod
    def _classify_banner(cls, banner: ShodanBanner) -> str | None:
        """Classify a Shodan banner into priority tier."""
        org_lower = banner.org.lower() if banner.org else ""
        tags_lower = {tag.lower() for tag in banner.tags}
        hostnames_lower = {hostname.lower() for hostname in banner.hostnames}
        if cls._is_blocked_org(org_lower):
            return None
        if cls._has_blocked_tag(tags_lower):
            return None
        if cls._has_blocked_hostname(hostnames_lower):
            return None
        if cls._is_priority_org(org_lower):
            return "high"
        if cls._has_priority_tag(tags_lower):
            return "high"
        return "medium"

    @classmethod
    def _is_blocked_org(cls, org_lower: str) -> bool:
        return org_lower in cls._BLOCKED_ORGS

    @classmethod
    def _has_blocked_tag(cls, tags_lower: set[str]) -> bool:
        return bool(tags_lower & cls._BLOCKED_TAGS)

    @classmethod
    def _has_blocked_hostname(cls, hostnames_lower: set[str]) -> bool:
        for hostname in hostnames_lower:
            domain = hostname.split(".")[-1]
            if domain in cls._BLOCKED_TAGS:
                return True
        return False

    @classmethod
    def _is_priority_org(cls, org_lower: str) -> bool:
        return org_lower in cls._PRIORITY_ORGS

    @classmethod
    def _has_priority_tag(cls, tags_lower: set[str]) -> bool:
        return bool(tags_lower & cls._PRIORITY_TAGS)


class CheckTask(Task):
    """Try RTSP credential combinations against inactive cameras in the database."""

    def __init__(
        self,
        config: CheckersConfig,
        database: Database = None,
        probe: RtspProbe = None,
    ):
        super().__init__(config, database)
        self.probe = probe or RtspProbe()

    def run(self) -> None:
        logging.info("Starting check task")
        users = self._read_lines(self.config.wordlist_users)
        passwords = self._read_lines(self.config.wordlist_passwords)
        rtsp_urls = self._read_lines(self.config.wordlist_rtsp_urls)

        if self.config.randomize:
            random.shuffle(users)
            random.shuffle(passwords)
            random.shuffle(rtsp_urls)

        cameras = self.repository.get_random_without_frame()
        logging.debug(f"Testing {len(cameras)} cameras")

        combinations = itertools.product(rtsp_urls, users, passwords, cameras)
        targets = (
            RtspTarget(
                host=camera.ip,
                port=camera.port,
                user=user,
                password=password,
                url_template=url_template,
            )
            for url_template, user, password, camera in combinations
        )
        # concurrency workers probe in parallel (I/O-bound); results are consumed
        # here on one thread so set_active stays serial. map preserves order and
        # pulls the target generator lazily, so all combos are never materialised.
        with ThreadPoolExecutor(max_workers=self.config.concurrency) as pool:
            for found in pool.map(self.probe.probe, targets):
                if found:
                    self.repository.mark_stream_obtained(found.camera)
        logging.info("Executors: finished testing cameras")

    @staticmethod
    def _read_lines(path):
        with open(path, "r") as f:
            return f.read().splitlines()
