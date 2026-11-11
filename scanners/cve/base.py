"""One class of the CVE batch: what it reads, and what the read produced.

Every class of the batch is a read. The only request that can be built here is a
`ReadRequest`, whose method enum holds no write verb, and the transport speaks
HTTP through `http.client`, which has no redirect logic at all, so "pull at most
one frame and write nothing to the device" (D5, FR-003) is a property of the
types instead of a rule each module has to remember.

A step that never answers raises `ReadFailed` instead of hanging: the timeout is
on the transport, and the task turns the failure into the recorded reason
(FR-020).
"""

import enum
import http.client
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

import cv2
import numpy as np

from models.finding import CveClass

# The most of one answer worth holding: a 4K JPEG is about 2 MB and a file read
# returns a few KB, so 4 MiB covers both. The cap is what keeps a hostile or
# broken endpoint from filling memory; the test for a picture is the decode.
_MAX_BODY_BYTES = 4 * 1024 * 1024
_OK_FIRST = 200
_OK_LAST = 300
_HTTP_PORT = 80
_HTTPS_PORT = 443


class ReadFailed(Exception):
    """The request never reached the device, or the answer never came back."""


class InvalidAttempt(Exception):
    """An attempt result that says neither what it got nor why it got nothing."""


class ReadMethod(enum.Enum):
    """How a read is sent. There is no write verb here, by design."""

    get = "GET"
    form_post = "POST"


@dataclass(frozen=True)
class ReadRequest:
    """One request that only reads."""

    method: ReadMethod
    url: str
    body: str = ""
    content_type: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            raise ReadFailed("a read needs a url")
        if self.method is ReadMethod.form_post and not self.body:
            raise ReadFailed(f"a form read carries its fields: {self.url}")


@dataclass(frozen=True)
class ReadResponse:
    """What came back: the status, the bytes, and the type the server claimed."""

    status: int
    body: bytes = b""
    content_type: str = ""

    @property
    def is_ok(self) -> bool:
        return _OK_FIRST <= self.status < _OK_LAST

    def describe(self) -> str:
        """A short line for a failure reason. Never the body: it may be a secret."""
        return f"HTTP {self.status} {self.content_type} {len(self.body)}B".strip()


class ReadTransport(Protocol):
    """Sends a read and returns what came back, or raises `ReadFailed`."""

    def fetch(self, request: ReadRequest) -> ReadResponse: ...


class HttpReadTransport:
    """One bounded HTTP read, straight at the address it was given.

    `http.client` never follows a redirect, so a 3xx comes back as a status the
    class records instead of a read that lands on a host nobody authorized
    (FR-001).
    """

    def __init__(self, timeout: float) -> None:
        self._timeout = timeout

    def fetch(self, request: ReadRequest) -> ReadResponse:
        """Log the address before the call, then read at most the cap."""
        logging.info("CVE read %s %s", request.method.value, request.url)
        parts = urlsplit(request.url)
        try:
            return self._read(parts, request)
        except (OSError, http.client.HTTPException) as unreachable:
            raise ReadFailed(f"{request.url}: {unreachable}") from unreachable

    def _read(self, parts: SplitResult, request: ReadRequest) -> ReadResponse:
        """One request, and the socket is closed whether it answered or not.

        `HTTPConnection` is not a context manager, so the close is explicit: a
        read that times out must not leave the connection open.
        """
        connection = self._connection(parts)
        try:
            return self._answered(connection, parts, request)
        finally:
            connection.close()

    def _answered(
        self,
        connection: http.client.HTTPConnection,
        parts: SplitResult,
        request: ReadRequest,
    ) -> ReadResponse:
        connection.request(
            request.method.value,
            self._path(parts),
            body=request.body.encode() if request.body else None,
            headers=self._headers(request),
        )
        answer = connection.getresponse()
        return ReadResponse(
            status=answer.status,
            body=answer.read(_MAX_BODY_BYTES),
            content_type=answer.headers.get("Content-Type", ""),
        )

    def _connection(self, parts: SplitResult) -> http.client.HTTPConnection:
        host = parts.hostname or ""
        port = parts.port or self._default_port(parts.scheme)
        if parts.scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=self._timeout)
        return http.client.HTTPConnection(host, port, timeout=self._timeout)

    def _headers(self, request: ReadRequest) -> dict[str, str]:
        if not request.content_type:
            return {}
        return {"Content-Type": request.content_type}

    def _path(self, parts: SplitResult) -> str:
        return f"{parts.path}?{parts.query}" if parts.query else parts.path

    def _default_port(self, scheme: str) -> int:
        return _HTTPS_PORT if scheme == "https" else _HTTP_PORT


@dataclass(frozen=True)
class CveTarget:
    """Where an attempt may read: one address, and the ports worth trying."""

    host: str
    ports: tuple[int, ...]

    def url(self, port: int, path: str) -> str:
        scheme = "https" if port == _HTTPS_PORT else "http"
        return f"{scheme}://{self.host}:{port}{path}"


@dataclass(frozen=True)
class AttemptResult:
    """What one class produced: at most one frame, or the reason it produced none."""

    frame: np.ndarray | None = None
    reason: str = ""
    model: str = ""
    firmware: str = ""

    def __post_init__(self) -> None:
        has_frame = self.frame is not None
        if has_frame and self.reason:
            raise InvalidAttempt("a frame and a failure reason are exclusive")
        if not has_frame and not self.reason:
            raise InvalidAttempt("an attempt with no frame states why")

    @classmethod
    def obtained(cls, frame: np.ndarray) -> "AttemptResult":
        return cls(frame=frame)

    @classmethod
    def recorded(cls, reason: str) -> "AttemptResult":
        return cls(reason=reason)


class CveAttempt(ABC):
    """One class of the batch: the CVEs it covers, and what it reads."""

    def __init__(self, transport: ReadTransport) -> None:
        self._transport = transport

    @property
    @abstractmethod
    def cve_ids(self) -> tuple[str, ...]:
        """The CVEs this class proves. The task only calls it for a match."""

    @property
    @abstractmethod
    def cve_class(self) -> CveClass:
        """Which class of D9 this is, for the finding row."""

    @abstractmethod
    def attempt(self, target: CveTarget) -> AttemptResult:
        """Read the target and say what came back, or why nothing did."""

    def covers(self, cve_id: str) -> bool:
        return cve_id in self.cve_ids


class ImageAttempt(CveAttempt):
    """A class whose proof is a picture: one read per candidate port.

    The two file-read classes are this shape too. They return a file and not an
    image, so the decode below fails and the attempt records the reason, which is
    exactly the outcome D31 asks for.
    """

    def attempt(self, target: CveTarget) -> AttemptResult:
        outcomes = []
        for port in target.ports:
            frame = self._first_image(target, port, outcomes)
            if frame is not None:
                return AttemptResult.obtained(frame)
        return AttemptResult.recorded(self._no_frame_reason(outcomes))

    @abstractmethod
    def _requests_for(self, target: CveTarget, port: int) -> tuple[ReadRequest, ...]:
        """The reads this class sends to one port, in the order to try them."""

    def _first_image(
        self, target: CveTarget, port: int, outcomes: list[str]
    ) -> np.ndarray | None:
        for request in self._requests_for(target, port):
            frame = self._read_image(request, port, outcomes)
            if frame is not None:
                return frame
        return None

    def _read_image(
        self, request: ReadRequest, port: int, outcomes: list[str]
    ) -> np.ndarray | None:
        """One read. A step that never answers is recorded, never raised.

        A port that refuses the connection says nothing about the next one, so
        the class goes on and the reason lists every port it tried (FR-018).
        """
        try:
            response = self._transport.fetch(request)
        except ReadFailed as unreachable:
            outcomes.append(f"{port} unreachable: {unreachable}")
            return None
        frame = self._image(response)
        if frame is None:
            outcomes.append(f"{port} {response.describe()}")
        return frame

    def _no_frame_reason(self, outcomes: list[str]) -> str:
        return f"{self.cve_ids[0]}: no image; " + "; ".join(outcomes)

    def _image(self, response: ReadResponse) -> np.ndarray | None:
        """The body as a picture, or None when it is not one."""
        if not response.is_ok or not response.body:
            return None
        try:
            return cv2.imdecode(
                np.frombuffer(response.body, dtype=np.uint8), cv2.IMREAD_COLOR
            )
        except cv2.error:
            return None
