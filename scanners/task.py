import itertools
import logging
import random
from abc import ABC, abstractmethod
from collections.abc import Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from ipaddress import IPv4Network, ip_address
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
from scanners.brand_probe import Identifier, ServiceEvidence
from scanners.config import CheckersConfig, NmapConfig, ShodanConfig, TargetsConfig
from scanners.rtsp_probe import ProbeResult, RtspProbe, RtspTarget

__version__ = "0.1.0"

# nmap's port state for a service that accepted the connection.
_OPEN_STATE = "open"

# Shodan's range filter. It is the only part of a query that names an address
# range, so it is the only part the declared list can be checked against (D18).
_NET_FILTER = "net:"


class TargetOutsideScopeError(Exception):
    """The scan asks for addresses that are not in the declared target list."""


class UnknownCameraError(Exception):
    """The run was narrowed to a camera id that is not in the database."""


@dataclass(frozen=True)
class Sighting:
    """One open port as nmap reported it: where it is, and what the service said."""

    host: str
    port: int
    service: Dict


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
    # Shodan names this field `data`; the name here says what it holds. It is
    # the service banner, which is what the brand patterns run against.
    banner_text: str = Field(default="", alias="data")


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

    def __init__(
        self,
        config: NmapConfig,
        identifier: Identifier,
        database: Database = None,
    ) -> None:
        super().__init__(config, database)
        self.identifier = identifier
        # Built on the first scan. python-nmap looks for the nmap binary inside
        # `PortScanner()`, so an eager one makes the binary a requirement of
        # every caller, a test that injects its own scanner included.
        self.scanner: nmap.PortScanner | None = None

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
            handle.write(self._scanner().get_nmap_last_output())
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
            self._store_sighting(Sighting(host, port, port_data), run)
            stored += 1
        return stored

    def _store_sighting(self, sighting: Sighting, run: ScanRun) -> None:
        """Write one open port: what the scan said, and what it was read as."""
        evidence = ServiceEvidence.from_nmap(sighting.service)
        identity = self.identifier.identify(evidence)
        camera = self.repository.record_identity(
            Camera(
                ip=sighting.host,
                port=sighting.port,
                vendor=identity.vendor,
                product=identity.product,
                version=identity.version,
                raw_banner=asdict(evidence),
            )
        )
        self.observations.record(camera, run)
        logging.debug("Added on db %s:%d", sighting.host, sighting.port)

    def _scan(self, target: str) -> Dict:
        arguments = f"-p {self._ports_argument()} -sV"
        if self.config.parallelism > 0:
            arguments += f" -T4 --min-parallelism {self.config.parallelism}"
        response = self._scanner().scan(hosts=target, arguments=arguments)
        return response.get("scan")

    def _scanner(self) -> nmap.PortScanner:
        """The scanner of this task, built once, or the one a caller injected."""
        if self.scanner is None:
            self.scanner = nmap.PortScanner()
        return self.scanner

    def _ports_argument(self) -> str:
        """The service scan port list of D15, as nmap wants it."""
        return ",".join(str(port) for port in self.config.ports)


class TargetGate:
    """The target gate of D18: what a run is allowed to reach.

    One declared list guards two different ways of reaching an address. A Shodan
    query is checked on its `net:` filter, the only part of it that names a
    range; a run over stored cameras is checked on the addresses already in the
    database, which the operator did not type this time. Both fail closed: an
    empty declared list authorizes nothing.
    """

    _NAMED_LIMIT = 10

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
                    f"{self._allowed_cidrs}; declare it in targets.allowed_cidrs"
                )

    def require_reachable(self, addresses: Sequence[str]) -> None:
        """Refuse the run unless every address it would reach is declared.

        The refusal names every address that is outside instead of stopping at
        the first one, so one run is enough to fix the whole list. A long list
        is cut short: the whole table of cameras is not a readable error line.
        """
        allowed = self._parse(self._allowed_cidrs)
        outside = [
            address for address in addresses if not self._is_inside(address, allowed)
        ]
        if outside:
            raise TargetOutsideScopeError(
                f"{len(outside)} of {len(addresses)} addresses are outside the "
                f"declared ranges {self._allowed_cidrs}: {self._named(outside)}; "
                "declare them in targets.allowed_cidrs, or narrow the run with "
                "--camera-id"
            )

    def _named(self, outside: list[str]) -> str:
        """The first addresses, then how many are left, so the line stays short."""
        if len(outside) <= self._NAMED_LIMIT:
            return ", ".join(outside)
        rest = len(outside) - self._NAMED_LIMIT
        return f"{', '.join(outside[: self._NAMED_LIMIT])} and {rest} more"

    def _is_inside(self, address: str, allowed: list[IPv4Network]) -> bool:
        """Whether the address is in one declared range. Unparsable is outside."""
        try:
            parsed = ip_address(address)
        except ValueError:
            return False
        return any(parsed in network for network in allowed)

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


@dataclass(frozen=True)
class ShodanDeps:
    """What ShodanTask needs: the query, the declared ranges, the identifier."""

    config: ShodanConfig
    targets: TargetsConfig
    identifier: Identifier


class ShodanTask(Task):
    """Search Shodan for cameras and store the new ones in the database."""

    def __init__(self, deps: ShodanDeps, database: Database = None) -> None:
        self._deps = deps
        self.database = database

    @property
    def config(self) -> ShodanConfig:
        """The Shodan section, so the base class contract still holds."""
        return self._deps.config

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
        TargetGate(self._deps.targets.allowed_cidrs).require_inside(
            self._deps.config.query
        )
        run = self.runs.start(ScanKind.shodan, self._deps.config.query)
        api = shodan.Shodan(self._deps.config.api_key)
        logging.info("Updating database")

        cams_added = 0
        try:
            for raw in api.search_cursor(self._deps.config.query):
                cams_added += self._store_banner(ShodanBanner(**raw), run)
            logging.info(f"{cams_added} cameras added")
        except APIError as error:
            logging.error(f"Shodan api error: {error}")
        finally:
            # A run left open reads as a scan still in flight, so the row is
            # closed even when the API call died halfway.
            self.runs.finish(run, cams_added)

    def _store_banner(self, banner: ShodanBanner, run: ScanRun) -> int:
        """Store one banner as a camera, and say whether it was a new one."""
        if self.repository.find(banner.ip_str, banner.port):
            return 0
        category = self._classify_banner(banner)
        if category is None:
            logging.debug("Skipped %s:%d (blocked org/tag)", banner.ip_str, banner.port)
            return 0
        evidence = ServiceEvidence.from_shodan(banner.banner_text)
        camera = self.repository.record_identity(self._camera_from(banner, evidence))
        self.observations.record(camera, run)
        logging.debug("%s:%d added (priority=%s)", banner.ip_str, banner.port, category)
        return 1

    def _camera_from(self, banner: ShodanBanner, evidence: ServiceEvidence) -> Camera:
        """The camera row a banner describes, with what it was read as."""
        identity = self._deps.identifier.identify(evidence)
        return Camera(
            ip=banner.ip_str,
            port=banner.port,
            vendor=identity.vendor,
            product=identity.product,
            version=identity.version,
            raw_banner=asdict(evidence),
            city=banner.location.city,
            country_code=banner.location.country_code,
            country_name=banner.location.country_name,
            region_code=banner.location.region_code,
        )

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


@dataclass(frozen=True)
class CheckDeps:
    """What CheckTask needs: the wordlists, the gate's list, the identifier.

    `camera_id` is 0 for a run over every camera waiting for a frame, and the id
    of one camera when the operator named it on the command line.
    """

    config: CheckersConfig
    targets: TargetsConfig
    identifier: Identifier
    camera_id: int = 0
    probe: RtspProbe | None = None


class CheckTask(Task):
    """Try RTSP credential combinations against cameras that have no frame yet."""

    def __init__(self, deps: CheckDeps, database: Database = None) -> None:
        self._deps = deps
        self.database = database

    @property
    def config(self) -> CheckersConfig:
        """The checkers section, so the base class contract still holds."""
        return self._deps.config

    def run(self) -> None:
        logging.info("Starting check task")
        cameras = self._queue()
        # D18: a run narrowed with --camera-id reaches the address the operator
        # named, which is the authorization itself; only the wide run, over
        # addresses nobody typed this time, is gated.
        if not self._deps.camera_id:
            TargetGate(self._deps.targets.allowed_cidrs).require_reachable(
                [camera.ip for camera in cameras]
            )
        logging.debug(f"Testing {len(cameras)} cameras")
        self._probe_all(cameras)
        logging.info("Executors: finished testing cameras")

    def _queue(self) -> list[Camera]:
        """The cameras this run reaches: the named one, or every one waiting."""
        if not self._deps.camera_id:
            return self.repository.get_random_without_frame()
        named = self.repository.find_by_id(self._deps.camera_id)
        if named is None:
            raise UnknownCameraError(f"no camera with id {self._deps.camera_id}")
        return [named]

    def _probe_all(self, cameras: list[Camera]) -> None:
        """Probe the cameras with their own combos, on the configured threads."""
        # concurrency workers probe in parallel (I/O-bound); results are consumed
        # here on one thread so the writes stay serial. map pulls the target
        # generator lazily, so all combos are never materialised.
        with ThreadPoolExecutor(max_workers=self._deps.config.concurrency) as pool:
            self._keep(pool.map(self._probe().probe, self._targets(cameras)))

    def _keep(self, probed: Iterator[ProbeResult | None]) -> None:
        """Record the credentials that worked, as the results come in."""
        for answered in probed:
            if answered:
                self.repository.mark_stream_obtained(answered.camera)

    def _probe(self) -> RtspProbe:
        if self._deps.probe is None:
            self._deps = replace(self._deps, probe=RtspProbe())
        return self._deps.probe

    def _targets(self, cameras: list[Camera]) -> Iterator[RtspTarget]:
        """Every target of the run, camera by camera."""
        return (
            RtspTarget(
                host=camera.ip,
                port=camera.port,
                user=user,
                password=password,
                url_template=url_template,
            )
            for camera in cameras
            for url_template, user, password in self._combos(camera)
        )

    def _combos(self, camera: Camera) -> list[tuple[str, str, str]]:
        """The brand credential set of D22 first, then the generic wordlists."""
        combos = self._brand_combos(camera)
        seen = set(combos)
        for combo in self._generic_combos():
            if combo not in seen:
                seen.add(combo)
                combos.append(combo)
        return combos

    def _brand_combos(self, camera: Camera) -> list[tuple[str, str, str]]:
        """What the brand the camera was read as says to try first."""
        evidence = ServiceEvidence.from_stored(camera.raw_banner)
        brand = self._deps.identifier.signature(evidence)
        return brand.combos() if brand else []

    def _generic_combos(self) -> list[tuple[str, str, str]]:
        """The three wordlists, as (url_template, user, password) triples."""
        users = self._read_lines(self._deps.config.wordlist_users)
        passwords = self._read_lines(self._deps.config.wordlist_passwords)
        urls = self._read_lines(self._deps.config.wordlist_rtsp_urls)
        if self._deps.config.randomize:
            random.shuffle(users)
            random.shuffle(passwords)
            random.shuffle(urls)
        return list(itertools.product(urls, users, passwords))

    @staticmethod
    def _read_lines(path: str) -> list[str]:
        with open(path, "r") as handle:
            return handle.read().splitlines()
