"""Every setting for the scanner, in one place, loaded from config.yaml.

This is the single config hub: config.ini and .env are retired. Secrets live in
config.yaml (git-ignored); config.yaml.example is the committed template.
"""

import os
from functools import lru_cache

import yaml
from pydantic import BaseModel, Field

_DEFAULT_QUERY = "screenshot.label:webcam,cam country:BR"
_DEFAULT_MIN_CVSS = 0.0
# RTSP plus the web and ONVIF ports most cameras expose instead of it, so a
# camera that answers on no RTSP port is still found (D15).
_DEFAULT_PORTS: tuple[int, ...] = (554, 80, 443, 8000, 8080, 8554, 34567)
# The HTTP ports of that list: what a CVE read is tried on, after the port the
# camera was actually seen on.
_WEB_PORTS: tuple[int, ...] = (80, 443, 8000, 8080)
# One network step. The RTSP probe already spends 8 s on a camera that accepts
# the connection and never answers (rtsp_probe._TCP_CAPTURE_OPTIONS), so a CVE
# read is held to the same bound and the run records the timeout (FR-020).
_DEFAULT_TIMEOUT_SECONDS = 8.0
# The verification threshold of a named target search, separate from the
# grouping threshold of the clustering (D51). PLACEHOLDER: a guess until
# `measure threshold` runs on this data, so every report says so (D60).
_DEFAULT_PERSON_MATCH_THRESHOLD = 0.5


class ShodanConfig(BaseModel):
    api_key: str
    query: str = _DEFAULT_QUERY


class TargetsConfig(BaseModel):
    """The addresses this scanner may reach (FR-001, D18).

    One list, read by the Shodan gate and by every command that reaches a stored
    camera, so the authorization is declared once. An empty list authorizes
    nothing: every check fails closed.
    """

    allowed_cidrs: list[str] = Field(default_factory=list)


class CheckersConfig(BaseModel):
    # plain paths: existence is checked at the edge (CheckTask reads them), so
    # loading the whole config never fails for a mode that does not use them
    wordlist_users: str
    wordlist_passwords: str
    wordlist_rtsp_urls: str
    randomize: bool = False
    # RTSP probes are I/O-bound (network + ffmpeg wait), so threads give near
    # linear speedup. The ceiling is the lab and the cameras, not the CPU. 1
    # keeps the old sequential behaviour; raise it and watch the error rate.
    concurrency: int = 1


class NmapConfig(BaseModel):
    ip_range: str
    # Ports every host in the range is scanned on. The list is one scan, not one
    # scan per port: nmap takes them all in a single invocation.
    ports: list[int] = Field(default_factory=lambda: list(_DEFAULT_PORTS))
    # nmap parallelises hosts itself; this tunes that. When > 0 the scan runs
    # with `-T4 --min-parallelism <N>`. 0 leaves nmap's own defaults untouched.
    parallelism: int = 0
    # Where the run's raw XML lands, as the record of what nmap saw. The CVE
    # task does not read it: it matches what the scan stored (D30).
    xml_path: str = "logs/nmap.xml"


class FaceConfig(BaseModel):
    """Face recognition settings for FaceScanTask."""

    enabled: bool = True
    # How many frames to grab per camera per scan, for a camera holding none.
    # 0 grabs no frame at all, so the camera is never read.
    frames_per_scan: int = 5
    # Seconds between frames within a single scan
    frame_interval: float = 2.0
    # Minimum cosine similarity for two faces to be the same person: cosine over
    # the L2-normalized 512-d embedding, so 1.0 is the same direction and higher
    # means more alike (D44, D45).
    # PLACEHOLDER: not measured on this data. `measure threshold` derives it from
    # a labelled pair set, and until that run happens this value is a guess (D16,
    # FR-025, SC-010).
    match_threshold: float = 0.5
    # The labelled pair set `measure threshold` reads when --pairs is not given:
    # one directory per identity, two or more images each (D16).
    pairs_path: str = "lab/faces"


class VulnConfig(BaseModel):
    """CVE matching, and the read-only attempt that follows a match (D9, D30).

    The feed and the map name the CVEs a camera is exposed to. A match is then
    read once, bounded by `timeout_seconds`, and never written to the device.
    """

    # NVD 2.0 JSON feed. A per-product subset from the NVD API is the intended
    # input; the full year files are hundreds of MB and load whole.
    feed_path: str = "nvdcve-2.0.json"
    cpe_map_path: str = "cpe_map.yaml"
    # Drop findings below this CVSS base score (0.0 keeps every scored CVE).
    min_cvss: float = _DEFAULT_MIN_CVSS
    # The ports a read is tried on after the camera's own: the HTTP ones of D15.
    web_ports: list[int] = Field(default_factory=lambda: list(_WEB_PORTS))
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS


class FramesConfig(BaseModel):
    """Where captured frames land on disk.

    The database holds the path, never the payload (D17), and the layout under
    this root is the one in research R8.
    """

    root_path: str = "logs/frames"


class PersonSearchConfig(BaseModel):
    """How close a stored face has to be to count as the registered target.

    A value of its own, separate from `face.match_threshold`: the grouping
    threshold answers when two faces are one person, this one answers when a
    face is the person the operator named (D51).
    """

    # PLACEHOLDER: not measured on this data (D60). A measured value is written
    # here by hand after `measure threshold`, and prints without the word.
    match_threshold: float = _DEFAULT_PERSON_MATCH_THRESHOLD


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
    targets: TargetsConfig = Field(default_factory=TargetsConfig)
    face: FaceConfig = Field(default_factory=FaceConfig)
    person_search: PersonSearchConfig = Field(default_factory=PersonSearchConfig)
    vuln: VulnConfig = Field(default_factory=VulnConfig)
    frames: FramesConfig = Field(default_factory=FramesConfig)
    brands: BrandsConfig = Field(default_factory=BrandsConfig)
    database: DatabaseConfig


def load_config(path: str = "config.yaml") -> AppConfig:
    """Read and validate the config from a specific yaml file (fail fast).

    `DATABASE_HOST` overrides the `database.host` of the file when it is set. The
    database address is the one value that differs between a run on the host
    (localhost:5440) and a run in a container (postgres:5432), so it comes from
    the environment instead of one config file per environment. Every other
    value, the authorized ranges and the secrets included, stays in the file.
    """
    with open(path) as config_file:
        document = yaml.safe_load(config_file) or {}
    host = os.environ.get("DATABASE_HOST")
    if host and isinstance(document, dict):
        database = {**(document.get("database") or {}), "host": host}
        document = {**document, "database": database}
    return AppConfig.model_validate(document)


@lru_cache(maxsize=1)
def get_config() -> AppConfig:
    """The process-wide config from the default config.yaml, read once.

    Used by the default factories (Database) when nothing is injected; the
    composition root in main.py loads and injects explicitly.
    """
    return load_config()
