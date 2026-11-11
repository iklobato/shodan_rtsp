"""Identify a camera from the evidence a scan collected, using brands.yaml.

The signature data lives in the YAML file, not here, so supporting a brand the
scanner has never seen is a line in that file and no release (D27). This module
reads the file, matches the evidence against its patterns and hands back what it
read, together with the credential set the check mode tries first (D22).

Identification only: nothing here opens a connection. The evidence it consumes
is what an nmap or Shodan scan already collected.
"""

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

# cpe:2.3:<part>:<vendor>:<product>:<version>:... - offsets are the same for the
# a (application), o (os) and h (hardware) parts, so only the prefix is checked.
_CPE_PREFIX = "cpe:2.3:"
_CPE_VENDOR_INDEX = 3
_CPE_PRODUCT_INDEX = 4
_CPE_VERSION_INDEX = 5
# NVD writes "any version" as * and "not applicable" as - in the version field.
_UNBOUNDED_VERSION = ("", "*", "-")

_BRANDS_KEY = "brands"
_MATCH_KEY = "match"
_VENDOR_KEY = "vendor"
_PRODUCT_KEY = "product"
_USERS_KEY = "users"
_PASSWORDS_KEY = "passwords"
_URLS_KEY = "url_templates"

_NMAP_SOURCE = "nmap"
_SHODAN_SOURCE = "shodan"


class BrandsFileError(Exception):
    """The brands file is missing, unreadable or holds a malformed entry."""


@dataclass(frozen=True)
class ServiceEvidence:
    """What a scan reported about one service: the raw material to identify on.

    `banner` is the text the patterns run against. For Shodan that is the raw
    banner; for nmap it is the service product string, which is the only free
    text nmap gives. The whole object is what a camera row keeps as its
    `raw_banner`, so a device that matched nothing today can be re-read from the
    database once the file gains its brand (FR-014).
    """

    source: str
    banner: str = ""
    product: str = ""
    version: str = ""
    cpe: str = ""

    @classmethod
    def from_nmap(cls, service: dict) -> "ServiceEvidence":
        """The evidence in one nmap service element."""
        product = str(service.get("product", ""))
        return cls(
            source=_NMAP_SOURCE,
            banner=product,
            product=product,
            version=str(service.get("version", "")),
            cpe=str(service.get("cpe", "")),
        )

    @classmethod
    def from_shodan(cls, banner_text: str) -> "ServiceEvidence":
        """The evidence in one Shodan banner."""
        return cls(source=_SHODAN_SOURCE, banner=banner_text)

    @classmethod
    def from_stored(cls, raw: dict | None) -> "ServiceEvidence":
        """The evidence a camera row kept, read back on a later run."""
        stored = raw or {}
        return cls(
            source=str(stored.get("source", "")),
            banner=str(stored.get("banner", "")),
            product=str(stored.get("product", "")),
            version=str(stored.get("version", "")),
            cpe=str(stored.get("cpe", "")),
        )

    @property
    def text(self) -> str:
        """The text to match patterns against, whichever field carries it."""
        return self.banner or self.product


@dataclass(frozen=True)
class BrandSignature:
    """One entry of brands.yaml: what it matches on and what it identifies."""

    name: str
    patterns: tuple[re.Pattern, ...]
    vendor: str
    product: str
    users: tuple[str, ...] = ()
    passwords: tuple[str, ...] = ()
    url_templates: tuple[str, ...] = ()

    def matches(self, text: str) -> bool:
        return any(pattern.search(text) for pattern in self.patterns)

    def combos(self) -> list[tuple[str, str, str]]:
        """This brand's (url_template, user, password) combos, in try order."""
        return [
            (template, user, password)
            for template in self.url_templates
            for user in self.users
            for password in self.passwords
        ]


@dataclass(frozen=True)
class _Entry:
    """One brands.yaml entry, with where it sits so an error can name the line."""

    name: str
    body: object
    path: str
    line: int = 0

    @property
    def where(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass(frozen=True)
class Identified:
    """What the identification read off a device. Empty fields mean unnamed."""

    vendor: str = ""
    product: str = ""
    version: str = ""
    brand: str = ""


class BrandBook:
    """The brands file, read once, matched in the order the file lists them."""

    def __init__(self, signatures: tuple[BrandSignature, ...]) -> None:
        self._signatures = signatures

    @classmethod
    def load(cls, path: str) -> "BrandBook":
        """Read the file, refusing a malformed entry at its own line."""
        text = cls._read(path)
        entries = cls._entries(text, path)
        lines = cls._brand_lines(text)
        return cls(
            tuple(
                cls._signature(
                    _Entry(
                        name=name,
                        body=entry,
                        path=path,
                        line=lines.get(name, 0),
                    )
                )
                for name, entry in entries.items()
            )
        )

    def match(self, text: str) -> BrandSignature | None:
        """The first brand whose patterns hit the text, or None."""
        if not text:
            return None
        return next((brand for brand in self._signatures if brand.matches(text)), None)

    @classmethod
    def _read(cls, path: str) -> str:
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError as error:
            raise BrandsFileError(f"cannot read brands file {path}: {error}") from error

    @classmethod
    def _entries(cls, text: str, path: str) -> dict:
        """The `brands` mapping, or a refusal naming the file."""
        try:
            document = yaml.safe_load(text) or {}
        except yaml.YAMLError as error:
            raise BrandsFileError(f"cannot read brands file {path}: {error}") from error
        entries = document.get(_BRANDS_KEY) if isinstance(document, dict) else None
        if not isinstance(entries, dict):
            raise BrandsFileError(f"{path}: no `{_BRANDS_KEY}` mapping")
        return entries

    @classmethod
    def _brand_lines(cls, text: str) -> dict[str, int]:
        """Where each brand key sits, so a bad entry can name its line."""
        document = yaml.compose(text)
        if not isinstance(document, yaml.MappingNode):
            return {}
        for key_node, value_node in document.value:
            if key_node.value == _BRANDS_KEY and isinstance(
                value_node, yaml.MappingNode
            ):
                return {
                    brand.value: brand.start_mark.line + 1
                    for brand, _ in value_node.value
                }
        return {}

    @classmethod
    def _signature(cls, entry: _Entry) -> BrandSignature:
        if not isinstance(entry.body, dict):
            raise BrandsFileError(
                f"{entry.where}: brand {entry.name!r} is not a mapping"
            )
        return BrandSignature(
            name=entry.name,
            patterns=cls._patterns(entry),
            vendor=cls._required(entry, _VENDOR_KEY),
            product=cls._required(entry, _PRODUCT_KEY),
            users=cls._listed(entry, _USERS_KEY),
            passwords=cls._listed(entry, _PASSWORDS_KEY),
            url_templates=cls._listed(entry, _URLS_KEY),
        )

    @classmethod
    def _patterns(cls, entry: _Entry) -> tuple[re.Pattern, ...]:
        """The compiled patterns, refusing a brand with nothing to match on."""
        raw = entry.body.get(_MATCH_KEY)
        if not isinstance(raw, list) or not raw:
            raise BrandsFileError(
                f"{entry.where}: brand {entry.name!r} needs a non-empty "
                f"`{_MATCH_KEY}` list"
            )
        return tuple(cls._compiled(entry, pattern) for pattern in raw)

    @classmethod
    def _compiled(cls, entry: _Entry, pattern: object) -> re.Pattern:
        try:
            return re.compile(str(pattern), re.IGNORECASE)
        except re.error as error:
            raise BrandsFileError(
                f"{entry.where}: brand {entry.name!r} has an unusable pattern "
                f"{pattern!r}: {error}"
            ) from error

    @classmethod
    def _required(cls, entry: _Entry, key: str) -> str:
        value = str(entry.body.get(key, "")).strip()
        if not value:
            raise BrandsFileError(
                f"{entry.where}: brand {entry.name!r} needs a `{key}`"
            )
        return value

    @classmethod
    def _listed(cls, entry: _Entry, key: str) -> tuple[str, ...]:
        raw = entry.body.get(key)
        if raw is None:
            return ()
        if not isinstance(raw, list):
            raise BrandsFileError(f"{entry.where}: `{key}` must be a list, got {raw!r}")
        return tuple(str(item) for item in raw)


class Identifier:
    """Reads a device's identity out of the evidence a scan collected."""

    def __init__(self, book: BrandBook) -> None:
        self._book = book

    def identify(self, evidence: ServiceEvidence) -> Identified:
        """What the evidence names, or an empty identity when it names nothing."""
        from_cpe = self._from_cpe(evidence)
        if from_cpe is not None:
            return from_cpe
        brand = self.signature(evidence)
        if brand is None:
            return Identified(version=evidence.version)
        return Identified(
            vendor=brand.vendor,
            product=brand.product,
            version=evidence.version,
            brand=brand.name,
        )

    def signature(self, evidence: ServiceEvidence) -> BrandSignature | None:
        """The brand entry the evidence matches, if any."""
        return self._book.match(evidence.text)

    def _from_cpe(self, evidence: ServiceEvidence) -> Identified | None:
        """The CPE the scan reported, which outranks a pattern: the device said it."""
        if not evidence.cpe.startswith(_CPE_PREFIX):
            return None
        parts = evidence.cpe.split(":")
        if len(parts) <= _CPE_VERSION_INDEX:
            return None
        version = parts[_CPE_VERSION_INDEX]
        return Identified(
            vendor=parts[_CPE_VENDOR_INDEX].lower(),
            product=parts[_CPE_PRODUCT_INDEX].lower(),
            version="" if version in _UNBOUNDED_VERSION else version,
        )
