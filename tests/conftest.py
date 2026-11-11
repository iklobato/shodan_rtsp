"""Shared test support.

The database fake lives here because every model test needs one, and the lab
server must not be a requirement for the unit suite: sqlite in memory holds the
same seven tables (`models/base.py` makes the PostgreSQL-only pieces of the
schema dialect-conditional).

The capture fake lives here for the same reason: the RTSP probe is tested for
what it logs and which URL it opens, and neither needs a camera or ffmpeg.

The stub server is the third: the CVE reads are tested for the requests they
send and for what a real socket does when it refuses, never answers, or
redirects, and none of that needs a camera.

`CveLab` is the last: the three CVE read modules assert the same handful of
things about a run, so the reads of the database live here once and each module
only points the lab at the port it wants read.

The face fakes come with them: `Vectors` builds embeddings whose angles are
exact, and `FakeDetector` hands the real recognizer the faces a test chose, so
the metric, the threshold and the clustering are the code under test.
"""

import threading

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from math import cos, radians, sin
from pathlib import Path

import numpy as np
import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from models.base import BASE
from models.camera import Camera, CameraStatus
from models.face import Face
from models.finding import CveFinding, CveOutcome
from models.frame import FaceFrame, FrameSource
from models.managers import (
    CameraRepository,
    FaceFrameRepository,
    FaceRepository,
)
from models.person import Person
from models.scan_run import ScanRun
from scanners import rtsp_probe
from scanners.config import FaceConfig, FramesConfig, TargetsConfig, VulnConfig
from scanners.cve import CVE_BATCH
from scanners.cve.base import CveAttempt
from scanners.face_recognizer import FaceRecognizer
from scanners.face_task import FaceScanDeps, FaceScanTask
from scanners.frames import FrameStore
from scanners.reports import StdoutLines
from scanners.rtsp_probe import RtspProbe
from scanners.vuln_probe import CveMatch, DeviceFingerprint
from scanners.vuln_task import CveDeps, CveTask

_FRAME_SHAPE: tuple[int, ...] = (2, 2, 3)
_PROBE_CVSS = 9.8

_LOOPBACK = "127.0.0.1"
_PORT_INDEX = 1
_QUERY_SEPARATOR = "?"
_NOT_FOUND_STATUS = 404
_ALLOWED_CIDR = "127.0.0.1/32"
_READ_TIMEOUT_SECONDS = 5.0

# The recognition model emits 512 values, so a test vector is that long too.
_EMBEDDING_LENGTH = 512
_FACE_BOX: tuple[int, int, int, int] = (10, 20, 60, 70)
_DET_SCORE = 0.99

# The lab of the face modules: one camera on a declared range, a URL template a
# probe can open, and a frame big enough to encode to a real file.
_LAB_IP = "10.0.0.1"
_LAB_PORT = 554
_LAB_USER = "admin"
_LAB_PASSWORD = "lab"
_LAB_URL = "rtsp://{}:{}@{}:{}/Streaming/Channels/1"
_LAB_CIDR = "10.0.0.0/24"
_LAB_THRESHOLD = 0.5
# One frame per scan, so a captured run writes one file: two frames of one
# camera inside the same second would collide on the frame file name.
_LAB_FRAMES_PER_SCAN = 1
_LAB_FRAME_INTERVAL = 0.0
_FRAME_WIDTH = 640
_FRAME_HEIGHT = 480
_FRAME_CHANNELS = 3



@dataclass(frozen=True)
class StubRoute:
    """One scripted answer: what the stub server sends for a path."""

    status: int
    body: bytes = b""
    content_type: str = "text/plain"
    headers: tuple[tuple[str, str], ...] = ()


class StubHandler(BaseHTTPRequestHandler):
    """Answers one read from the table its server carries, and records it."""

    def do_GET(self) -> None:
        self._answer()

    def do_POST(self) -> None:
        self._drain_body()
        self._answer()

    def _answer(self) -> None:
        self.server.asked.append((self.command, self.path))
        route = self.server.routes.get(self._asked_path(), StubRoute(_NOT_FOUND_STATUS))
        self.send_response(route.status)
        self.send_header("Content-Type", route.content_type)
        self.send_header("Content-Length", str(len(route.body)))
        for name, value in route.headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(route.body)

    def _drain_body(self) -> None:
        """Read the form body, so the connection stays in step for the answer."""
        self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def _asked_path(self) -> str:
        """The path without its query, which is how the routes are keyed."""
        path, _separator, _query = self.path.partition(_QUERY_SEPARATOR)
        return path


class StubServerNotStarted(Exception):
    """The stub server was used before it was started."""


class StubServer:
    """A loopback server that answers from `routes` and records what was asked.

    Every request lands in `asked` as (method, path), so a test asserts what the
    code under test actually sent, not only what came back. `routes` is read on
    every request, so a test may fill it before or after `start`.
    """

    def __init__(self) -> None:
        self.routes: dict[str, StubRoute] = {}
        self.asked: list[tuple[str, str]] = []
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> None:
        """Bind an ephemeral loopback port and serve it on a daemon thread."""
        self._server = ThreadingHTTPServer((_LOOPBACK, 0), StubHandler)
        self._server.routes = self.routes
        self._server.asked = self.asked
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    @property
    def port(self) -> int:
        """The port it bound, so a test can point a camera at it."""
        return self._bound()[_PORT_INDEX]

    def _bound(self) -> tuple:
        if self._server is None:
            raise StubServerNotStarted("the stub server was not started")
        return self._server.server_address


@pytest.fixture
def stub_server() -> Iterator[StubServer]:
    """A loopback server answering from whatever the test puts in `routes`."""
    server = StubServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


class RecordingProbe:
    """A matcher that answers with the CVEs the test named, and keeps what it saw."""

    def __init__(self, cve_ids: tuple[str, ...], cvss: float = _PROBE_CVSS) -> None:
        self.cve_ids = cve_ids
        self.cvss = cvss
        self.asked: list[DeviceFingerprint] = []

    def match(self, device: DeviceFingerprint) -> list[CveMatch]:
        self.asked.append(device)
        return [
            CveMatch(
                cve_id=cve_id,
                cvss=self.cvss,
                summary="",
                host=device.host,
                port=device.port,
            )
            for cve_id in self.cve_ids
        ]


class MemoryDatabase:
    """A Database stand-in backed by one shared in-memory sqlite connection."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def create_schema(self) -> None:
        """Build every table of the schema on the empty in-memory database."""
        BASE.metadata.create_all(self.engine)

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Yield a session, commit on success, always close.

        `expire_on_commit=False` matches `models/database.py`: the repositories
        hand back detached rows that callers read after the scope closed.
        """
        session = Session(bind=self.engine, expire_on_commit=False)
        try:
            yield session
            session.commit()
        finally:
            session.close()


@pytest.fixture
def database() -> MemoryDatabase:
    """An empty in-memory database with the whole schema already built on it."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    memory = MemoryDatabase(engine)
    memory.create_schema()
    return memory


class FakeCapture:
    """Stands in for the cv2 capture: one frame per read, and the URL it opened.

    `readable` is set to False by a test that wants the camera which answers
    nothing, so the branch that logs and returns None is reachable without one.
    """

    def __init__(self) -> None:
        self.urls: list[str] = []
        self.readable = True

    @contextmanager
    def __call__(self, url: str) -> Iterator["FakeCapture"]:
        """Install as `_opened_capture`: record the URL, then yield this capture."""
        self.urls.append(url)
        yield self

    def read(self) -> tuple[bool, np.ndarray | None]:
        """One frame, or nothing at all when the test asked for a silent camera."""
        if not self.readable:
            return False, None
        return True, np.zeros(_FRAME_SHAPE, dtype=np.uint8)


@pytest.fixture
def opened_frames(monkeypatch: pytest.MonkeyPatch) -> FakeCapture:
    """Replace the cv2 capture, so probing needs no camera and no ffmpeg."""
    capture = FakeCapture()
    monkeypatch.setattr(rtsp_probe, "_opened_capture", capture)
    return capture


class Vectors:
    """Embeddings a test can reason about: the angle between two of them is exact.

    The recognition model emits 512 values, so a test vector is that long too,
    with only the first two carrying the direction. The cosine between two of
    them is the cosine of the difference of the angles they were built from.
    """

    @classmethod
    def unit(cls, degrees: float) -> np.ndarray:
        """A unit vector in the first plane, `degrees` from the first axis."""
        angle = radians(degrees)
        vector = np.zeros(_EMBEDDING_LENGTH, dtype=np.float32)
        vector[0] = cos(angle)
        vector[1] = sin(angle)
        return vector

    @classmethod
    def scaled(cls, degrees: float, factor: float) -> np.ndarray:
        """The same direction at a different length: what cosine ignores (D44)."""
        return cls.unit(degrees) * factor


class FakeFace:
    """One face as the insightface app hands it back: a box, a vector, a score."""

    def __init__(
        self, bbox: np.ndarray, embedding: np.ndarray, det_score: float
    ) -> None:
        self.bbox = bbox
        self.embedding = embedding
        self.det_score = det_score

    @classmethod
    def of(cls, embedding: np.ndarray) -> "FakeFace":
        """One detected face at the box this suite uses, with a high score."""
        return cls(
            np.array(_FACE_BOX, dtype=np.float32), embedding, _DET_SCORE
        )


class FakeDetector:
    """Stands in for the insightface app: the faces of each frame, in order.

    The real recognizer runs over these, so the matching, the threshold and the
    clustering are the code under test; only the pixels are missing. A frame the
    test did not describe raises IndexError, so a run that reads more frames than
    the test set up fails loudly instead of passing on nothing.
    """

    def __init__(self, per_frame: list[list[FakeFace]]) -> None:
        self.per_frame = per_frame
        self.seen: list[np.ndarray] = []

    def get(self, image: np.ndarray) -> list[FakeFace]:
        """The faces of this frame, in the order the frames were read."""
        self.seen.append(image)
        return self.per_frame[len(self.seen) - 1]


@dataclass(frozen=True)
class CveLab:
    """A stored camera and the CVE run that reads it.

    The three CVE read modules assert the same handful of things: which findings
    were opened, with which outcome, how many frames were stored, what the
    camera row says now, and whether the run was closed. Those reads live here
    once, and each module only builds the lab over the port it wants read.
    """

    database: MemoryDatabase
    root: Path
    camera: Camera

    @classmethod
    def at(cls, database: MemoryDatabase, root: Path, port: int) -> "CveLab":
        """Store a camera at one port, and hand back the lab over it."""
        camera = CameraRepository(database=database).get_or_create(
            Camera(ip=_LOOPBACK, port=port, status=CameraStatus.responded)
        )
        return cls(database, root, camera)

    def deps(
        self,
        probe: RecordingProbe,
        batch: tuple[type[CveAttempt], ...] = CVE_BATCH,
        timeout: float = _READ_TIMEOUT_SECONDS,
    ) -> CveDeps:
        """What the task needs, over the real transport: the socket is exercised.

        `web_ports` is empty, so the only port a read is sent to is the camera's
        own, which is the one the test pointed at a server.
        """
        return CveDeps(
            config=VulnConfig(web_ports=[], timeout_seconds=timeout),
            frames=FramesConfig(root_path=str(self.root)),
            targets=TargetsConfig(allowed_cidrs=[_ALLOWED_CIDR]),
            probe=probe,
            batch=batch,
        )

    def read_batch(self, deps: CveDeps) -> None:
        """Run the task once over this camera."""
        CveTask(deps, database=self.database).run()

    def findings(self) -> list[CveFinding]:
        """The findings in the order the run opened them."""
        with self.database.session_scope() as session:
            return session.query(CveFinding).order_by(CveFinding.id).all()

    def outcomes(self) -> list[CveOutcome]:
        """Each finding's outcome, in the same order."""
        return [finding.outcome for finding in self.findings()]

    def frame_rows(self) -> list[FaceFrame]:
        with self.database.session_scope() as session:
            return session.query(FaceFrame).all()

    def stored_camera(self) -> Camera:
        """The camera as the database holds it now."""
        return CameraRepository(database=self.database).find_by_id(self.camera.id)

    def last_run(self) -> ScanRun:
        with self.database.session_scope() as session:
            return session.query(ScanRun).order_by(ScanRun.id.desc()).first()


class CapturedLines(StdoutLines):
    """A writer that keeps the lines, so a report is asserted without stdout."""

    def __init__(self) -> None:
        self._lines: list[str] = []

    def write(self, line: str) -> None:
        """Keep the line instead of printing it."""
        self._lines.append(line)

    def all(self) -> list[str]:
        """Every line written so far, in order."""
        return list(self._lines)


@dataclass(frozen=True)
class FaceLab:
    """A stored camera, the frames it holds, and the rows a face run writes.

    The face scan, the clustering and the reports read the same four tables, so
    the rows a test seeds and the rows it then asserts on are built here once.
    """

    database: MemoryDatabase
    root: Path
    camera: Camera

    @classmethod
    def at(cls, database: MemoryDatabase, root: Path) -> "FaceLab":
        """One camera a frame exists for, with the URL a probe would open."""
        camera = CameraRepository(database=database).get_or_create(
            Camera(
                ip=_LAB_IP,
                port=_LAB_PORT,
                user=_LAB_USER,
                password=_LAB_PASSWORD,
                url=_LAB_URL,
                status=CameraStatus.stream_obtained,
            )
        )
        return cls(database, root, camera)

    def frame(self, moment: datetime, source: FrameSource = FrameSource.rtsp) -> int:
        """Write one frame file, record the row that points at it, return its id."""
        pixels = np.zeros(
            (_FRAME_HEIGHT, _FRAME_WIDTH, _FRAME_CHANNELS), dtype=np.uint8
        )
        stored = FrameStore(str(self.root)).write(self.camera.id, source, pixels)
        return self._frame_rows().record(
            FaceFrame(
                camera_id=self.camera.id,
                path=stored.path,
                source=source,
                width=_FRAME_WIDTH,
                height=_FRAME_HEIGHT,
                captured_at=moment,
            )
        ).id

    def face(
        self, frame_id: int, embedding: np.ndarray, person_id: int | None = None
    ) -> int:
        """One stored face of a frame, in the person the test named or in none."""
        top, left, bottom, right = _FACE_BOX
        return self._face_rows().store(
            Face(
                frame_id=frame_id,
                person_id=person_id,
                embedding=embedding.tolist(),
                bbox_top=top,
                bbox_left=left,
                bbox_bottom=bottom,
                bbox_right=right,
                confidence=_DET_SCORE,
            )
        )

    def person(self, label: str | None = None) -> Person:
        """A person row, as the clustering or a hand would have left it."""
        person = Person(label=label)
        with self.database.session_scope() as session:
            session.add(person)
        return person

    def people(self) -> list[Person]:
        with self.database.session_scope() as session:
            return session.query(Person).order_by(Person.id).all()

    def faces(self) -> list[Face]:
        with self.database.session_scope() as session:
            return session.query(Face).order_by(Face.id).all()

    def frames(self) -> list[FaceFrame]:
        with self.database.session_scope() as session:
            return session.query(FaceFrame).order_by(FaceFrame.id).all()

    def last_run(self) -> ScanRun:
        with self.database.session_scope() as session:
            return session.query(ScanRun).order_by(ScanRun.id.desc()).first()

    def deps(
        self, detector: FakeDetector, probe: RtspProbe | None = None
    ) -> FaceScanDeps:
        """What the face scan needs, with the detector the test chose."""
        config = FaceConfig(
            match_threshold=_LAB_THRESHOLD,
            frames_per_scan=_LAB_FRAMES_PER_SCAN,
            frame_interval=_LAB_FRAME_INTERVAL,
        )
        return FaceScanDeps(
            config=config,
            frames=FramesConfig(root_path=str(self.root)),
            targets=TargetsConfig(allowed_cidrs=[_LAB_CIDR]),
            probe=probe,
            recognizer=FaceRecognizer(config, detector),
            store=FrameStore(str(self.root)),
        )

    def scan(self, deps: FaceScanDeps) -> None:
        """Run the face scan once over this camera."""
        FaceScanTask(deps, database=self.database).run()

    def _frame_rows(self) -> FaceFrameRepository:
        return FaceFrameRepository(self.database)

    def _face_rows(self) -> FaceRepository:
        return FaceRepository(self.database)


@pytest.fixture
def face_lab(database: MemoryDatabase, tmp_path: Path) -> FaceLab:
    """The camera of the face modules, with no frame and no face stored yet."""
    return FaceLab.at(database, tmp_path)
