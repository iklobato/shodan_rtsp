"""Face scan: read a camera's frames, detect the faces, cluster them into people.

The frames read here are the ones the pipeline already obtained, at their own
rows, so a camera whose only frame came through a CVE class is readable without a
stream to open (D33). A camera that holds no frame is captured over RTSP.

Every face points at the frame row it was found in, which is what lets `search`
answer where a person was seen (FR-027). Nothing here labels a person: a person
is a cluster of faces and stays anonymous until an operator names it (D28).
"""

import logging
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import cv2
import numpy as np

from models.camera import Camera
from models.database import Database
from models.face import Face
from models.frame import FaceFrame, FrameSource
from models.managers import FaceFrameRepository, FaceRepository, PersonRepository
from models.scan_run import ScanKind, ScanRun
from scanners.config import FaceConfig, FramesConfig, TargetsConfig
from scanners.face_recognizer import DetectedFace, FaceRecognizer, KnownEmbedding
from scanners.frames import FrameStore
from scanners.rtsp_probe import RtspProbe, RtspTarget
from scanners.task import Task, TargetGate, UnknownCameraError

# frame.shape is (rows, columns, channels), so the axes are named rather than
# written as bare 0 and 1 at the one place that reads them.
_HEIGHT_AXIS: int = 0
_WIDTH_AXIS: int = 1


@dataclass(frozen=True)
class FaceScanDeps:
    """What the face scan needs beyond the database.

    `camera_id` is 0 for a run over every camera that holds a frame, and the id
    of one camera when the operator named it. `probe`, `recognizer` and `store`
    are the seams the tests inject; a real run leaves them None.
    """

    config: FaceConfig
    frames: FramesConfig
    targets: TargetsConfig
    camera_id: int = 0
    probe: RtspProbe | None = None
    recognizer: FaceRecognizer | None = None
    store: FrameStore | None = None


@dataclass(frozen=True)
class FrameToRead:
    """One frame to detect faces in, and the row it already has.

    `frame_id` is None for a frame captured now, which is written before its
    faces are: a face with no frame row would be a face with no place.
    """

    image: np.ndarray
    frame_id: int | None = None


@dataclass(frozen=True)
class FaceContext:
    """The camera being read, the run it belongs to, and what it is compared to."""

    camera: Camera
    run: ScanRun
    known: "KnownFaces"


class KnownFaces:
    """What a new face is compared against: the stored faces, plus this run's.

    A face this run stored is known to the next frame of the same run, so one
    person seen twice in one run is one person (FR-022) without re-reading the
    table for every face.
    """

    def __init__(self, known: list[KnownEmbedding]) -> None:
        self._known = known

    @classmethod
    def from_stored(cls, stored: list[Face]) -> "KnownFaces":
        """The comparison set of a run that starts with the table as it is."""
        return cls(
            [
                KnownEmbedding(face_id=face.id, embedding=face.embedding)
                for face in stored
            ]
        )

    def all(self) -> list[KnownEmbedding]:
        """Every face to compare against, oldest first."""
        return list(self._known)

    def remember(self, face_id: int, embedding: np.ndarray) -> None:
        """Add a face this run just stored, so the next frame can match it."""
        self._known.append(
            KnownEmbedding(face_id=face_id, embedding=embedding.tolist())
        )


class FaceScanTask(Task):
    """Detect the faces in the frames of a camera and cluster them into people."""

    def __init__(self, deps: FaceScanDeps, database: Database = None) -> None:
        self._deps = deps
        self.database = database

    @property
    def config(self) -> FaceConfig:
        """The face section, so the base class contract still holds."""
        return self._deps.config

    @property
    def _face_rows(self) -> FaceRepository:
        return FaceRepository(self._database())

    @property
    def _frame_rows(self) -> FaceFrameRepository:
        return FaceFrameRepository(self._database())

    @property
    def _people(self) -> PersonRepository:
        return PersonRepository(self._database())

    def scan_frames(self) -> None:
        logging.info("Starting the face scan")
        if not self._deps.config.enabled:
            logging.info("The face scan is disabled in the config")
            return
        cameras = self._queue()
        # D18: a run narrowed with --camera-id reaches the address the operator
        # named, which is the authorization itself; only the wide run, over
        # addresses nobody typed this time, is gated.
        if not self._deps.camera_id:
            TargetGate(self._deps.targets.allowed_cidrs).require_reachable(
                [camera.ip for camera in cameras]
            )
        run = self.runs.start(ScanKind.faces, self._target_set(cameras))
        known = KnownFaces.from_stored(self._face_rows.known())
        faces = sum(
            self._read_camera(FaceContext(camera, run, known)) for camera in cameras
        )
        self.runs.finish(run, len(cameras))
        logging.info("Executors: finished the face scan with %d face(s)", faces)

    # Task declares run() abstract and the CLI calls it; the mode's own name says
    # what this task does where "run" does not.
    run = scan_frames

    def _queue(self) -> list[Camera]:
        """The cameras this run reaches: the named one, or every one with a frame."""
        if not self._deps.camera_id:
            return self.repository.get_with_frame()
        named = self.repository.find_by_id(self._deps.camera_id)
        if named is None:
            raise UnknownCameraError(f"no camera with id {self._deps.camera_id}")
        return [named]

    def _target_set(self, cameras: list[Camera]) -> str:
        """What the run reached, recorded before any packet leaves (FR-002)."""
        addresses = sorted({camera.ip for camera in cameras})
        return ", ".join(addresses) if addresses else "no camera holding a frame"

    def _read_camera(self, context: FaceContext) -> int:
        """Every face of one camera, on the frame each was found in."""
        found = 0
        for frame in self._frames_of(context):
            found += self._read_frame(context, frame)
        if found:
            logging.info(
                "%s:%d holds %d face(s)", context.camera.ip, context.camera.port, found
            )
        return found

    def _read_frame(self, context: FaceContext, frame: FrameToRead) -> int:
        faces = self._recognizer().detect(frame.image)
        if not faces:
            return 0
        frame_id = frame.frame_id
        if frame_id is None:
            frame_id = self._store_frame(context, frame.image)
        for face in faces:
            self._cluster(context, frame_id, face)
        return len(faces)

    def _cluster(self, context: FaceContext, frame_id: int, face: DetectedFace) -> None:
        """Store the face, then put it with the person it belongs to (FR-021)."""
        face_id = self._face_rows.store(self._face_row(frame_id, face))
        matches = self._recognizer().match_against(face.embedding, context.known.all())
        # ponytail: every stored face is compared with the new one, so a run is
        # O(faces) per face. At lab scale (tens of cameras, a bounded number of
        # faces) a linear scan in Python is correct and needs no extension; a
        # pgvector index on face.embedding is the upgrade path (R9).
        matched = [one.existing_face_id for one in matches]
        person = self._people.person_for([face_id, *matched])
        context.known.remember(face_id, face.embedding)
        logging.debug("face %d joined person %d", face_id, person.id)

    def _face_row(self, frame_id: int, face: DetectedFace) -> Face:
        """The row of one detected face: where it is, and the vector that names it."""
        top, left, bottom, right = face.bbox
        return Face(
            frame_id=frame_id,
            embedding=face.embedding.tolist(),
            bbox_top=top,
            bbox_left=left,
            bbox_bottom=bottom,
            bbox_right=right,
            confidence=face.confidence,
        )

    def _frames_of(self, context: FaceContext) -> Iterable[FrameToRead]:
        """The frames the camera already holds, or fresh ones when it holds none.

        The frame the pipeline obtained is already on disk, so reading it again
        is what "the path that worked" means: a camera read through a CVE class
        has no stream to open (D33).
        """
        rows = self._stored_rows(context.camera)
        stored = [read for read in map(self._read_stored, rows) if read]
        if stored:
            return stored
        return self._captured_frames(context)

    def _stored_rows(self, camera: Camera) -> list[FaceFrame]:
        return self._frame_rows.for_camera(camera.id)

    def _read_stored(self, row: FaceFrame) -> FrameToRead | None:
        """The frame file behind a row, or a skip when it is no longer readable."""
        image = cv2.imread(str(Path(self._deps.frames.root_path) / row.path))
        if image is None:
            logging.warning("the frame %s is not readable, skipping it", row.path)
            return None
        return FrameToRead(image=image, frame_id=row.id)

    def _captured_frames(self, context: FaceContext) -> Iterator[FrameToRead]:
        """Fresh frames over RTSP, one interval apart, handed over as captured.

        Each frame is yielded as soon as it is read, so the caller writes its row
        before the next capture: the row and its file name carry the instant of
        the capture, not the instant the run got around to storing it.
        """
        for index in range(self._deps.config.frames_per_scan):
            if index:
                time.sleep(self._deps.config.frame_interval)
            image = self._capture(context.camera)
            if image is None:
                return
            yield FrameToRead(image=image)

    def _capture(self, camera: Camera) -> np.ndarray | None:
        """One frame over RTSP, or nothing when the stream does not answer."""
        target = RtspTarget(
            host=camera.ip,
            port=camera.port,
            user=camera.user,
            password=camera.password,
            url_template=camera.url,
        )
        probed = self._probe().probe(target)
        if probed is None:
            logging.warning("%s:%d answered no frame over RTSP", camera.ip, camera.port)
            return None
        return probed.frame

    def _store_frame(self, context: FaceContext, image: np.ndarray) -> int:
        """Write the frame file first, then the row that points at it (R8, D17)."""
        stored = self._frame_store().write(
            context.camera.id, FrameSource.rtsp, image
        )
        return self._frame_rows.record(
            FaceFrame(
                camera_id=context.camera.id,
                scan_run_id=context.run.id,
                path=stored.path,
                source=FrameSource.rtsp,
                width=image.shape[_WIDTH_AXIS],
                height=image.shape[_HEIGHT_AXIS],
                captured_at=stored.captured_at,
            )
        ).id

    def _probe(self) -> RtspProbe:
        if self._deps.probe is None:
            self._deps = replace(self._deps, probe=RtspProbe())
        return self._deps.probe

    def _recognizer(self) -> FaceRecognizer:
        if self._deps.recognizer is None:
            self._deps = replace(
                self._deps, recognizer=FaceRecognizer(self._deps.config)
            )
        return self._deps.recognizer

    def _frame_store(self) -> FrameStore:
        if self._deps.store is None:
            self._deps = replace(
                self._deps, store=FrameStore(self._deps.frames.root_path)
            )
        return self._deps.store
