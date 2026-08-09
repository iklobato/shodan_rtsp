"""Every setting for the scanner, in one place, loaded from config.yaml.

This is the single config hub: config.ini and .env are retired. Secrets live in
config.yaml (git-ignored); config.yaml.example is the committed template.
"""

from functools import lru_cache

import yaml
from pydantic import BaseModel

_DEFAULT_QUERY = "screenshot.label:webcam,cam country:BR"


class ShodanConfig(BaseModel):
    api_key: str
    query: str = _DEFAULT_QUERY


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
    # nmap parallelises hosts itself; this tunes that. When > 0 the scan runs
    # with `-T4 --min-parallelism <N>`. 0 leaves nmap's own defaults untouched.
    parallelism: int = 0


class ProxyConfig(BaseModel):
    token: str
    auth_mode: str = "whitelist"  # 'whitelist' | 'login'
    protocol: str = "http"  # http | https | socks5
    country: str = "us"  # exit country code; BR is not offered by 2captcha
    public_ip: str = ""  # whitelist mode; auto-detected when empty
    gateway_host: str = ""  # login mode (from dashboard)
    gateway_port: int = 0  # login mode (from dashboard)
    gateway_password: str = ""  # login mode (from dashboard)


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
