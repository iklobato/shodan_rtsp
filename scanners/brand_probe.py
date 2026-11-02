"""Brand detection from Shodan banners and per-brand credential sets.

Shodan banners contain service headers (HTTP Server, device hostname, raw
banner text) that reveal the camera manufacturer. This module maps those
signals to credential sets (users, passwords, RTSP URL templates) so the
checker tries brand-specific combos first instead of blind brute force.
"""

import re
from dataclasses import dataclass
from pathlib import Path

from scanners.config import CheckersConfig

# Brand identifier patterns: each tuple is (raw_regex, brand_label).
BRAND_PATTERN_SPECS: tuple[tuple[str, str], ...] = (
    (r"Hikvision-IP", "hikvision"),
    (r"Hikvision", "hikvision"),
    (r"IpCamera$", "hikvision"),
    (r"Dahua", "dahua"),
    (r"DMSS", "dahua"),
    (r"TP-Link", "tplink"),
    (r"Reolink", "reolink"),
    (r"HiLook", "hilook"),
    (r"Longse", "longse"),
    (r"XMEYE", "xmeye"),
    (r"XMeye", "xmeye"),
    (r"Ezviz", "ezviz"),
    (r"AMCre", "amcrest"),
    (r"SAMSUNG", "samsung"),
    (r"Panasonic", "panasonic"),
    (r"PANASONIC", "panasonic"),
    (r"Axis", "axis"),
    (r"Sony", "sony"),
    (r"Bosch", "bosch"),
    (r"Fujitsu", "fujitsu"),
    (r"Honeywell", "honeywell"),
    (r"Hanwha", "hanwha"),
    (r"LG-IPC", "lg"),
    (r"Pelco", "pelco"),
    (r"Canon", "canon"),
    (r"JVC", "jvc"),
    (r"Mitsubishi", "mitsubishi"),
    (r"NEC", "nec"),
    (r"Sanyo", "sanyo"),
    (r"Samsung", "samsung"),
    (r"nginx", "generic_nginx"),
    (r"lighttpd", "generic_lighttpd"),
    (r"Apache", "generic_apache"),
    (r"ONVIF", "generic_onvif"),
)


@dataclass(frozen=True)
class CredentialSet:
    """A brand-specific credential set for RTSP probing."""

    users: tuple[str, ...]
    passwords: tuple[str, ...]
    url_templates: tuple[str, ...]


@dataclass(frozen=True)
class BrandProbeConfig:
    """Configuration for brand-aware credential probing."""

    config: CheckersConfig
    camera_ip: str
    camera_port: int


class BrandCredentialRegistry:
    """Registry of brand-specific credential sets and lookup logic."""

    _CREDENTIALS: dict[str, CredentialSet] = {}

    @classmethod
    def _hikvision(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin",),
            passwords=(
                "admin",
                "12345",
                "123456",
                "12345678",
                "Password123",
                "Hik12345",
                "abc123",
                "1q2w3e4r",
            ),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/h264/ch1/main/av_stream",
                "rtsp://{0}:{1}@{2}:{3}/h264/ch2/sub/av_stream",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/102",
            ),
        )

    @classmethod
    def _dahua(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin",),
            passwords=(
                "admin",
                "12345",
                "888888",
                "123456",
                "111111",
                "admin12345",
                "Password123",
            ),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/live/supStream",
                "rtsp://{0}:{1}@{2}:{3}/live/subStream",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/102",
                "rtsp://{0}:{1}@{2}:{3}/cam/realmonitor?channel=1&subtype=1",
                "rtsp://{0}:{1}@{2}:{3}/cam/realmonitor?channel=1&subtype=0",
            ),
        )

    @classmethod
    def _generic_nginx(cls) -> CredentialSet:
        return CredentialSet(
            ("admin", "root", "user"),
            (
                "admin",
                "password",
                "12345",
                "123456",
                "root",
                "888888",
                "000000",
                "111111",
            ),
            (
                "rtsp://{0}:{1}@{2}:{3}/",
                "rtsp://{0}:{1}@{2}:{3}/live.sdp",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
                "rtsp://{0}:{1}@{2}:{3}/h264/ch1/main/av_stream",
            ),
        )

    @classmethod
    def _amcrest(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin",),
            passwords=("admin", "amcrest", "12345", "123456", "666666", "888888"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/cam/realmonitor?channel=1&subtype=0",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
                "rtsp://{0}:{1}@{2}:{3}/video1",
            ),
        )

    @classmethod
    def _reolink(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin",),
            passwords=("admin", "123456", "12345", "password", ""),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/h264/ch1/main/av_stream",
                "rtsp://{0}:{1}@{2}:{3}/h264/ch1/sub/av_stream",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
            ),
        )

    @classmethod
    def _axis(cls) -> CredentialSet:
        return CredentialSet(
            users=("root", "admin"),
            passwords=("pass", "admin", "admin", "12345", "password"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/axis-media/media.amp",
                "rtsp://{0}:{1}@{2}:{3}/axis-cgi/mjpegb/stream",
                "rtsp://{0}:{1}@{2}:{3}/mjpg/mjpg.cgi",
            ),
        )

    @classmethod
    def _samsung(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin",),
            passwords=("admin", "4321", "1234", "111111", "888888", "666666"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/mpeg4/media.amp",
                "rtsp://{0}:{1}@{2}:{3}/multiMediaOutput/ch1",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
            ),
        )

    @classmethod
    def _panasonic(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin",),
            passwords=("admin", "12345", "1234", "password", "root"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/video1",
                "rtsp://{0}:{1}@{2}:{3}/video2",
            ),
        )

    @classmethod
    def _bosch(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin", "root"),
            passwords=("admin", "bosch", "secret", "password", "123456"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/video1",
                "rtsp://{0}:{1}@{2}:{3}/axis-media/media.amp",
            ),
        )


class BrandCredentialLoader:
    """Loads brand credential sets into the registry."""

    @classmethod
    def _generic_nginx(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin", "root", "user"),
            passwords=(
                "admin",
                "password",
                "12345",
                "123456",
                "root",
                "888888",
                "000000",
                "111111",
            ),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/",
                "rtsp://{0}:{1}@{2}:{3}/live.sdp",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
                "rtsp://{0}:{1}@{2}:{3}/h264/ch1/main/av_stream",
            ),
        )

    @classmethod
    def _generic_lighttpd(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin", "user"),
            passwords=("admin", "password", "12345", "123456", "0000", "888888"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/",
                "rtsp://{0}:{1}@{2}:{3}/live1.sdp",
                "rtsp://{0}:{1}@{2}:{3}/live2.sdp",
            ),
        )

    @classmethod
    def _generic_apache(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin", "root"),
            passwords=("admin", "password", "12345", "123456", "1234"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/",
                "rtsp://{0}:{1}@{2}:{3}/movie.cgi",
                "rtsp://{0}:{1}@{2}:{3}/cgi-bin/video.cgi",
            ),
        )

    @classmethod
    def _generic_onvif(cls) -> CredentialSet:
        return CredentialSet(
            users=("admin", "root", "user"),
            passwords=("admin", "password", "12345", "123456", "000000", "111111"),
            url_templates=(
                "rtsp://{0}:{1}@{2}:{3}/",
                "rtsp://{0}:{1}@{2}:{3}/video1",
                "rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/101",
            ),
        )

    _CREDENTIALS: dict[str, CredentialSet] = {}

    @classmethod
    def init(cls) -> dict[str, CredentialSet]:
        if cls._CREDENTIALS:
            return cls._CREDENTIALS
        cls._CREDENTIALS = {
            "hikvision": BrandCredentialRegistry._hikvision.__func__(cls),
            "dahua": BrandCredentialRegistry._dahua.__func__(cls),
            "amcrest": BrandCredentialRegistry._amcrest.__func__(cls),
            "reolink": BrandCredentialRegistry._reolink.__func__(cls),
            "axis": BrandCredentialRegistry._axis.__func__(cls),
            "samsung": BrandCredentialRegistry._samsung.__func__(cls),
            "panasonic": BrandCredentialRegistry._panasonic.__func__(cls),
            "bosch": BrandCredentialRegistry._bosch.__func__(cls),
            "generic_nginx": cls._generic_nginx(),
            "generic_lighttpd": cls._generic_lighttpd(),
            "generic_apache": cls._generic_apache(),
            "generic_onvif": cls._generic_onvif(),
        }
        return cls._CREDENTIALS

    @classmethod
    def lookup(cls, brand: str) -> CredentialSet | None:
        if not cls._CREDENTIALS:
            cls.init()
        return cls._CREDENTIALS.get(brand)


class ComboBuilder:
    """Builds (user, password, url_template) combos for a camera."""

    @classmethod
    def build(
        cls, cfg: BrandProbeConfig, banner: str | None = None
    ) -> list[tuple[str, str, str]]:
        brand = BrandDetector().detect(banner or "")
        seen: set[tuple[str, str, str]] = set()
        combos: list[tuple[str, str, str]] = []
        BrandCredentialLoader.init()
        cls._lookup_brand(brand, seen, combos)
        cls._add_generic(cfg.config, seen, combos)
        return combos

    @classmethod
    def _lookup_brand(
        cls,
        brand: str | None,
        seen: set[tuple[str, str, str]],
        combos: list[tuple[str, str, str]],
    ) -> None:
        brand_creds = BrandCredentialLoader.lookup(brand) if brand else None
        if brand_creds:
            cls._add_brand(brand_creds, seen, combos)

    @classmethod
    def _add_brand(
        cls,
        creds: CredentialSet,
        seen: set[tuple[str, str, str]],
        combos: list[tuple[str, str, str]],
    ) -> None:
        _UserComboAdder(creds, seen, combos).execute()

    @classmethod
    def _add_generic(
        cls,
        config: CheckersConfig,
        seen: set[tuple[str, str, str]],
        combos: list[tuple[str, str, str]],
    ) -> None:
        builder = cls.__new__(cls)
        users = builder._read_lines(config.wordlist_users)
        passwords = builder._read_lines(config.wordlist_passwords)
        url_templates = builder._read_lines(config.wordlist_rtsp_urls)
        _GenericComboAdder(users, passwords, url_templates, seen, combos).execute()

    def _read_lines(self, path_str: str) -> list[str]:
        return Path(path_str).read_text(encoding="utf-8").splitlines()


@dataclass(frozen=True)
class _UserComboAdder:
    """Adds brand-specific credential combos."""

    creds: CredentialSet
    seen: set[tuple[str, str, str]]
    combos: list[tuple[str, str, str]]

    def execute(self) -> None:
        _PasswordUrlLoop(
            self.creds.passwords,
            self.creds.url_templates,
            self.creds.users,
            self.seen,
            self.combos,
        ).execute()


@dataclass(frozen=True)
class _PasswordUrlLoop:
    """Inner loop: passwords × url_templates."""

    passwords: tuple[str, ...]
    url_templates: tuple[str, ...]
    users: tuple[str, ...]
    seen: set[tuple[str, str, str]]
    combos: list[tuple[str, str, str]]

    def execute(self) -> None:
        for password in self.passwords:
            _UrlLoop(
                self.url_templates,
                password,
                self.users,
                self.seen,
                self.combos,
            ).execute()


@dataclass(frozen=True)
class _UrlLoop:
    """Innermost loop: url_templates."""

    url_templates: tuple[str, ...]
    password: str
    users: tuple[str, ...]
    seen: set[tuple[str, str, str]]
    combos: list[tuple[str, str, str]]

    def execute(self) -> None:
        for url_tmpl in self.url_templates:
            for user in self.users:
                self._add_unique(user, self.password, url_tmpl)

    def _add_unique(self, user: str, password: str, url_template: str) -> None:
        key = (user, password, url_template)
        if key not in self.seen:
            self.combos.append(key)
            self.seen.add(key)


@dataclass(frozen=True)
class _GenericComboAdder:
    """Adds generic wordlist credential combos."""

    users: list[str]
    passwords: list[str]
    url_templates: list[str]
    seen: set[tuple[str, str, str]]
    combos: list[tuple[str, str, str]]

    def execute(self) -> None:
        _GenericPasswordUrlLoop(
            self.passwords,
            self.url_templates,
            self.users,
            self.seen,
            self.combos,
        ).execute()

    def _add_unique(
        self,
        user: str,
        password: str,
        url_template: str,
    ) -> None:
        key = (user, password, url_template)
        if key not in self.seen:
            self.combos.append(key)
            self.seen.add(key)


@dataclass(frozen=True)
class _GenericPasswordUrlLoop:
    """Inner loop for generic wordlist combos."""

    passwords: list[str]
    url_templates: list[str]
    users: list[str]
    seen: set[tuple[str, str, str]]
    combos: list[tuple[str, str, str]]

    def execute(self) -> None:
        for password in self.passwords:
            _GenericUrlLoop(
                self.url_templates,
                password,
                self.users,
                self.seen,
                self.combos,
            ).execute()


@dataclass(frozen=True)
class _GenericUrlLoop:
    """Innermost loop for generic wordlist combos."""

    url_templates: list[str]
    password: str
    users: list[str]
    seen: set[tuple[str, str, str]]
    combos: list[tuple[str, str, str]]

    def execute(self) -> None:
        for url_tmpl in self.url_templates:
            for user in self.users:
                self._add_unique(user, self.password, url_tmpl)

    def _add_unique(self, user: str, password: str, url_template: str) -> None:
        key = (user, password, url_template)
        if key not in self.seen:
            self.combos.append(key)
            self.seen.add(key)


class BrandDetector:
    """Detects camera brand from a Shodan banner string."""

    def detect(self, banner_text: str) -> str | None:
        if not banner_text:
            return None
        for raw_pattern, brand_label in BRAND_PATTERN_SPECS:
            try:
                compiled = re.compile(raw_pattern, re.IGNORECASE)
            except re.error:
                continue
            if compiled.search(banner_text):
                return brand_label
        return None


class BrandProbe:
    """Entry point for brand-aware credential probing."""

    def __init__(self, config: CheckersConfig) -> None:
        self._config = config

    def detect_brand(self, banner_text: str) -> str | None:
        detector = BrandDetector()
        return detector.detect(banner_text)

    def build_combos(
        self,
        camera_ip: str,
        camera_port: int,
        banner: str | None = None,
    ) -> list[tuple[str, str, str]]:
        cfg = BrandProbeConfig(
            config=self._config,
            camera_ip=camera_ip,
            camera_port=camera_port,
        )
        return ComboBuilder.build(cfg, banner)


if __name__ == "__main__":
    BrandCredentialLoader.init()
