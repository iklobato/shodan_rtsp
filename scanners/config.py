"""Every setting for the scanner, in one place, loaded from config.yaml.

This is the single config hub: config.ini and .env are retired. Secrets live in
config.yaml (git-ignored); config.yaml.example is the committed template.
"""

from functools import lru_cache

import yaml
from pydantic import BaseModel, Field

_DEFAULT_QUERY = "screenshot.label:webcam,cam country:BR"
_DEFAULT_MIN_CVSS = 0.0
# RTSP plus the web and ONVIF ports most cameras expose instead of it, so a
# camera that answers on no RTSP port is still found (D15).
_DEFAULT_PORTS: tuple[int, ...] = (554, 80, 443, 8000, 8080, 8554, 34567)


class ShodanConfig(BaseModel):
    api_key: str
    query: str = _DEFAULT_QUERY
    # The ranges this scanner is allowed to reach (FR-001, D18). Every `net:`
    # filter in the query must sit inside one of them, and a query that names no
    # range at all is refused, so an empty list authorizes nothing.
    allowed_cidrs: list[str] = Field(default_factory=list)


class CheckersConfig(BaseModel):
    # plain paths: existence is checked at the edge (CheckTask reads them), so
    # loading the whole config never fails for a mode that does not use them
    wordlist_users: str
    wordlist_passwords: str
    wordlist_rtsp_urls: str
    randomize: bool = False
    # RTSP probes are I/O-bound (network + ffmpeg wait), so threads give near
    # linear speedup. The real ceiling is the proxy exit, not the CPU: too many
    # concurrent streams through one residential exit get throttled. 1 keeps the
    # old sequential behaviour; raise it and watch the error rate.
    concurrency: int = 1


class NmapConfig(BaseModel):
    ip_range: str
    # Ports every host in the range is scanned on. The list is one scan, not one
    # scan per port: nmap takes them all in a single invocation.
    ports: list[int] = Field(default_factory=lambda: list(_DEFAULT_PORTS))
    # nmap parallelises hosts itself; this tunes that. When > 0 the scan runs
    # with `-T4 --min-parallelism <N>`. 0 leaves nmap's own defaults untouched.
    parallelism: int = 0
    # Where the run's raw XML lands. This is the file the vuln mode reads, so
    # keep it in step with VulnConfig.nmap_xml.
    xml_path: str = "logs/nmap.xml"


class ProxyConfig(BaseModel):
    # False routes every probe straight from the local IP: the only sane mode
    # for a private range (192.168.x.x is unreachable through a residential
    # exit) and for a box whose 2captcha account is down. Public scans must
    # leave this True.
    enabled: bool = True
    token: str
    auth_mode: str = "whitelist"  # 'whitelist' | 'login'
    protocol: str = "http"  # http | https | socks5
    country: str = "us"  # exit country code; BR is not offered by 2captcha
    public_ip: str = ""  # whitelist mode; auto-detected when empty
    gateway_host: str = ""  # login mode (from dashboard)
    gateway_port: int = 0  # login mode (from dashboard)
    gateway_password: str = ""  # login mode (from dashboard)


class FaceConfig(BaseModel):
    """Face recognition settings for FaceScanTask."""

    enabled: bool = True
    # How many frames to grab per camera per scan (0 = disable multi-frame, keep single)
    frames_per_scan: int = 5
    # Seconds between frames within a single scan
    frame_interval: float = 2.0
    # Cosine distance threshold: below = same person
    match_threshold: float = 0.5
    # Minimum faces per frame to count it (0 = any face counts)
    min_faces_per_frame: int = 1
    # Save full frame to face_frames table when face detected
    save_frames: bool = True
    # Max faces to store per camera (oldest removed first)
    max_faces_per_camera: int = 1000


class VulnConfig(BaseModel):
    """CVE identification settings: an NVD feed plus a product -> CPE map.

    Identification only. The scanner reads what an nmap or Shodan scan already
    collected and names the CVEs that cover it; it never sends a payload or
    attempts an exploit.
    """

    # The nmap XML to read. `--start_nmap` writes it (NmapConfig.xml_path); a
    # standalone run can also drop one here: `nmap -sV -oX logs/nmap.xml <range>`.
    nmap_xml: str = "logs/nmap.xml"
    # NVD 2.0 JSON feed. A per-product subset from the NVD API is the intended
    # input; the full year files are hundreds of MB and load whole.
    feed_path: str = "nvdcve-2.0.json"
    cpe_map_path: str = "cpe_map.yaml"
    # Drop findings below this CVSS base score (0.0 keeps every scored CVE).
    min_cvss: float = _DEFAULT_MIN_CVSS
    report_path: str = "logs/vuln_report.json"


class FramesConfig(BaseModel):
    """Where captured frames land on disk.

    The database holds the path, never the payload (D17), and the layout under
    this root is the one in research R8.
    """

    root_path: str = "logs/frames"


class BrandsConfig(BaseModel):
    """The brand signature data file, so a new brand is a data line (D27)."""

    signature_path: str = "brands.yaml"


class DatabaseConfig(BaseModel):
    user: str
    password: str
    host: str
    db: str

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}/{self.db}"


class AppConfig(BaseModel):
    """The whole configuration tree, one section per concern."""

    shodan: ShodanConfig
    checkers: CheckersConfig
    nmap: NmapConfig
    proxy: ProxyConfig
    face: FaceConfig = Field(default_factory=FaceConfig)
    vuln: VulnConfig = Field(default_factory=VulnConfig)
    frames: FramesConfig = Field(default_factory=FramesConfig)
    brands: BrandsConfig = Field(default_factory=BrandsConfig)
    database: DatabaseConfig


def load_config(path: str = "config.yaml") -> AppConfig:
    """Read and validate the config from a specific yaml file (fail fast)."""
    with open(path) as config_file:
        data = yaml.safe_load(config_file) or {}
    return AppConfig.model_validate(data)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """The process-wide config from the default config.yaml, read once.

    Used by the default factories (Database, TwoCaptchaProxy) when nothing is
    injected; the composition root in main.py loads and injects explicitly.
    """
    return load_config()
