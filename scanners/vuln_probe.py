"""Identify the CVEs that cover a scanned service, without touching the device.

Everything here is data-driven: an NVD 2.0 JSON feed supplies the records and a
YAML map translates the product string a scan reports into a CPE. Both paths
come from config, so supporting a new product is a YAML line, never a code
change.

Identification only. Nothing in this module opens a connection, sends a payload
or attempts an exploit; the fingerprint it consumes is what an nmap or Shodan
scan already collected.
"""

import json
import re
from dataclasses import dataclass
from typing import Iterator

import yaml

# cpe:2.3:<part>:<vendor>:<product>:<version>:... - offsets are the same for the
# a (application), o (os) and h (hardware) parts, so only the prefix is checked.
_CPE_PREFIX = "cpe:2.3:"
_CPE_VENDOR_INDEX = 3
_CPE_PRODUCT_INDEX = 4
_CPE_VERSION_INDEX = 5
# NVD writes "any version" as * and "not applicable" as - in the version field.
_UNBOUNDED_VERSION = ("", "*", "-")
_SEGMENT_SEPARATOR = re.compile(r"[._\-]")
# Sort ranks that keep a mixed numeric/text version key totally ordered.
_NUMERIC_SEGMENT = 0
_TEXT_SEGMENT = 1
_NO_SCORE = 0.0


class MalformedCpeError(Exception):
    """The string is not a CPE 2.3 name, so no product can be read from it."""


class CveFeedError(Exception):
    """The feed file is missing, unreadable or not an NVD 2.0 document."""


class CpeMapError(Exception):
    """The map file is missing, unreadable or holds a malformed entry."""


@dataclass(frozen=True)
class CpeVersion:
    """A CPE version string, compared segment by segment.

    CPE versions are not semver: "1.2.3", "2.4", "2019.4" and "1.0.1a" all
    occur. A segment compares as a number when both sides are digits and as text
    otherwise, and a digit always sorts before text, so the order stays total.
    """

    raw: str

    def is_below(self, other: "CpeVersion") -> bool:
        return self._key() < other._key()

    def _key(self) -> tuple:
        return tuple(
            (0, int(segment), "") if segment.isdigit() else (1, 0, segment.lower())
            for segment in _SEGMENT_SEPARATOR.split(self.raw)
        )


@dataclass(frozen=True)
class CpeName:
    """A CPE 2.3 name reduced to the three fields matching needs."""

    vendor: str
    product: str
    version: str = ""

    @classmethod
    def parse(cls, criteria: str) -> "CpeName":
        if not criteria.startswith(_CPE_PREFIX):
            raise MalformedCpeError(f"not a CPE 2.3 name: {criteria!r}")
        parts = criteria.split(":")
        if len(parts) <= _CPE_VERSION_INDEX:
            raise MalformedCpeError(f"CPE has no version field: {criteria!r}")
        version = parts[_CPE_VERSION_INDEX]
        return cls(
            vendor=parts[_CPE_VENDOR_INDEX].lower(),
            product=parts[_CPE_PRODUCT_INDEX].lower(),
            version="" if version in _UNBOUNDED_VERSION else version,
        )


@dataclass(frozen=True)
class CpeMatchRange:
    """One NVD cpeMatch node: a CPE pattern plus the version bounds it covers."""

    vendor: str
    product: str
    version: str = ""
    start_including: str = ""
    start_excluding: str = ""
    end_including: str = ""
    end_excluding: str = ""

    @classmethod
    def parse(cls, node: dict) -> "CpeMatchRange":
        cpe = CpeName.parse(node["criteria"])
        return cls(
            vendor=cpe.vendor,
            product=cpe.product,
            version=cpe.version,
            start_including=node.get("versionStartIncluding", ""),
            start_excluding=node.get("versionStartExcluding", ""),
            end_including=node.get("versionEndIncluding", ""),
            end_excluding=node.get("versionEndExcluding", ""),
        )

    def covers(self, device: CpeName) -> bool:
        if (self.vendor, self.product) != (device.vendor, device.product):
            return False
        if self.version:
            return self.version == device.version
        if not device.version:
            # An unknown version cannot be shown to sit inside a bounded range;
            # it only matches a pattern that names no range at all.
            return not self._has_bounds()
        return self._within_bounds(device.version)

    def _has_bounds(self) -> bool:
        return any(
            (
                self.start_including,
                self.start_excluding,
                self.end_including,
                self.end_excluding,
            )
        )

    def _within_bounds(self, version: str) -> bool:
        candidate = CpeVersion(version)
        if self.start_including and candidate.is_below(
            CpeVersion(self.start_including)
        ):
            return False
        if self.start_excluding and not CpeVersion(self.start_excluding).is_below(
            candidate
        ):
            return False
        if self.end_including and CpeVersion(self.end_including).is_below(candidate):
            return False
        if self.end_excluding and not candidate.is_below(
            CpeVersion(self.end_excluding)
        ):
            return False
        return True


@dataclass(frozen=True)
class CveEntry:
    """One NVD vulnerability record, reduced to what matching needs."""

    cve_id: str
    cvss: float
    summary: str
    ranges: tuple[CpeMatchRange, ...]

    def covers(self, device: CpeName) -> bool:
        return any(match.covers(device) for match in self.ranges)


@dataclass(frozen=True)
class CveMatch:
    """A CVE that applies to a scanned service."""

    cve_id: str
    cvss: float
    summary: str
    host: str
    port: int


@dataclass(frozen=True)
class DeviceFingerprint:
    """What a scan learned about one service: enough to name it, and no more."""

    host: str
    port: int
    product: str = ""
    version: str = ""
    cpe: str = ""


class NvdRecordParser:
    """Turns one NVD 2.0 vulnerability object into a CveEntry."""

    # Newest metric first: a record carries whichever CVSS version NVD scored it
    # with, and v3 is the one to report when both exist.
    _CVSS_KEYS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

    def parse(self, record: dict) -> CveEntry | None:
        cve = record.get("cve", {})
        ranges = self._ranges(cve)
        if not ranges:
            return None
        return CveEntry(
            cve_id=cve.get("id", ""),
            cvss=self._score(cve),
            summary=self._summary(cve),
            ranges=ranges,
        )

    def _ranges(self, cve: dict) -> tuple[CpeMatchRange, ...]:
        nodes = [
            node
            for configuration in cve.get("configurations", [])
            for node in configuration.get("nodes", [])
        ]
        matches = [
            match
            for node in nodes
            for match in node.get("cpeMatch", [])
            if match.get("vulnerable")
            and str(match.get("criteria", "")).startswith(_CPE_PREFIX)
        ]
        return tuple(CpeMatchRange.parse(match) for match in matches)

    def _score(self, cve: dict) -> float:
        metrics = cve.get("metrics", {})
        for key in self._CVSS_KEYS:
            scored = metrics.get(key, [])
            if scored:
                return float(scored[0]["cvssData"]["baseScore"])
        return _NO_SCORE

    def _summary(self, cve: dict) -> str:
        for description in cve.get("descriptions", []):
            if description.get("lang") == "en":
                return description.get("value", "")
        return ""


class CveFeed:
    """An NVD 2.0 JSON feed, indexed by (vendor, product) and read lazily."""

    def __init__(self, path: str, parser: NvdRecordParser = None) -> None:
        self._path = path
        self._parser = parser
        self._by_product: dict[tuple[str, str], dict[str, CveEntry]] = {}
        self._loaded = False

    def entries_for(self, cpe: CpeName) -> list[CveEntry]:
        if not self._loaded:
            self._load()
        return list(self._by_product.get((cpe.vendor, cpe.product), {}).values())

    def _load(self) -> None:
        parser = self._parser or NvdRecordParser()
        self._by_product = {}
        for record in self._records():
            self._index(parser.parse(record))
        self._loaded = True

    def _index(self, entry: CveEntry | None) -> None:
        """Bucket an entry under every product its ranges mention.

        Keyed by cve_id so an entry with several ranges on one product is still
        returned once.
        """
        if entry is None:
            return
        for match in entry.ranges:
            product = (match.vendor, match.product)
            self._by_product.setdefault(product, {})[entry.cve_id] = entry

    def _records(self) -> Iterator[dict]:
        """The vulnerability objects of the feed.

        ponytail: json.load holds the whole file in memory (an NVD year file is
        ~200MB, all years over 1GB). Point feed_path at a per-product subset
        built from the NVD API; switch to a streaming parser if the full feed
        has to be read in one go.
        """
        try:
            with open(self._path) as handle:
                feed = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            raise CveFeedError(f"cannot read NVD feed {self._path}: {error}") from error
        return iter(feed.get("vulnerabilities", []))


class CpeMap:
    """Maps the product string a scan reports to a CPE vendor:product pair."""

    _PRODUCTS_KEY = "products"

    def __init__(self, path: str) -> None:
        self._path = path
        self._entries: dict[str, str] = {}
        self._loaded = False

    def resolve(self, product: str) -> CpeName | None:
        """The vendor and product of a reported product string, or None."""
        if not self._loaded:
            self._load()
        mapped = self._entries.get(product.strip().lower())
        if mapped is None:
            return None
        vendor, _, name = mapped.partition(":")
        return CpeName(vendor=vendor.strip().lower(), product=name.strip().lower())

    def _load(self) -> None:
        try:
            with open(self._path) as handle:
                mapping = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as error:
            raise CpeMapError(f"cannot read CPE map {self._path}: {error}") from error
        self._entries = self._read_entries(mapping.get(self._PRODUCTS_KEY, {}))
        self._loaded = True

    def _read_entries(self, raw: dict) -> dict[str, str]:
        """Normalise the map, failing loud on an entry that names no product."""
        entries = {}
        for key, value in raw.items():
            if ":" not in str(value):
                raise CpeMapError(
                    f"{self._path}: {key!r} needs a vendor:product value, got {value!r}"
                )
            entries[str(key).strip().lower()] = str(value).strip()
        return entries


class VulnProbe:
    """Identifies the CVEs that cover a device, from a configured feed.

    Identification only: it reads a feed and a map and never contacts the
    device. The fingerprint it takes is what a scan already collected.
    """

    def __init__(
        self, feed: CveFeed, cpe_map: CpeMap, min_cvss: float = _NO_SCORE
    ) -> None:
        self._feed = feed
        self._cpe_map = cpe_map
        self._min_cvss = min_cvss

    def match(self, device: DeviceFingerprint) -> list[CveMatch]:
        identified = self._identify(device)
        if identified is None:
            return []
        return [
            self._to_match(entry, device)
            for entry in self._feed.entries_for(identified)
            if entry.cvss >= self._min_cvss and entry.covers(identified)
        ]

    def _identify(self, device: DeviceFingerprint) -> CpeName | None:
        """The device's CPE: its own when the scan reported one, else the map's.

        A scan may report a CPE 2.2 URI (Shodan does), which carries no version
        in the 2.3 layout, so only a 2.3 name is used directly.
        """
        if device.cpe.startswith(_CPE_PREFIX):
            return CpeName.parse(device.cpe)
        mapped = self._cpe_map.resolve(device.product)
        if mapped is None:
            return None
        return CpeName(
            vendor=mapped.vendor, product=mapped.product, version=device.version
        )

    def _to_match(self, entry: CveEntry, device: DeviceFingerprint) -> CveMatch:
        return CveMatch(
            cve_id=entry.cve_id,
            cvss=entry.cvss,
            summary=entry.summary,
            host=device.host,
            port=device.port,
        )
