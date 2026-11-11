"""Face scan task: capture frames from active cameras, detect faces, store embeddings."""

import logging
import time
from dataclasses import dataclass, field, replace

import numpy as np

from models.camera import Camera as CameraModel
from models.database import Database
from models.frame import Face, FaceFrame, FrameSource
from models.managers import CameraRepository
from scanners.config import AppConfig, FaceConfig
from scanners.face_recognizer import (
    DetectedFace,
    FaceMatch,
    FaceRecognizer,
    KnownEmbedding,
)
from scanners.frames import FrameStore
from scanners.proxy import TwoCaptchaProxy
from scanners.rtsp_probe import RtspProbe, RtspTarget
from scanners.task import Task

_BBOX_Y: int = 0
_BBOX_X: int = 1
_BBOX_H: int = 2
_BBOX_W: int = 3
_HEIGHT_AXIS: int = 0
_WIDTH_AXIS: int = 1


@dataclass(frozen=True)
class FaceScanDeps:
    """Dependency injection container for FaceScanTask."""

    config: AppConfig = field(repr=False)
    # Not optional: this task's whole job is walking the active cameras, so a
    # deps without a repository cannot do anything.
    repository: CameraRepository
    probe: RtspProbe | None = None
    database: Database | None = None
    recognizer: FaceRecognizer | None = None


@dataclass(frozen=True)
class FrameInput:
    """Parameters for frame-level processing."""

    frame: np.ndarray
    camera: CameraModel
    known_faces: list[KnownEmbedding]
    all_matches: list[FaceMatch]
    frame_idx: int
    num_frames: int
    interval: float


@dataclass(frozen=True)
class StoreBatch:
    """Parameters for face storage batch."""

    camera: CameraModel
    known_faces: list[KnownEmbedding]
    all_matches: list[FaceMatch]
    frame: np.ndarray


class FaceScanTask(Task):
    """Capture frames from active cameras, detect faces, match against known faces."""

    def __init__(self, deps: FaceScanDeps) -> None:
        self._deps = deps

    @classmethod
    def from_config(cls, config: AppConfig) -> "FaceScanTask":
        deps = FaceScanDeps(config=config, repository=CameraRepository())
        return cls(deps=deps)

    @property
    def _s(self) -> FaceConfig:
        return self._deps.config.face

    @property
    def _probe(self) -> RtspProbe:
        if self._deps.probe is None:
            proxy_config = self._deps.config.proxy
            proxy = TwoCaptchaProxy(proxy_config) if proxy_config.enabled else None
            self._deps = replace(self._deps, probe=RtspProbe(proxy=proxy))
        return self._deps.probe

    @property
    def _database(self) -> Database:
        if self._deps.database is None:
            self._deps = replace(
                self._deps, database=Database(self._deps.config.database)
            )
        return self._deps.database

    @property
    def _frames(self) -> FrameStore:
        return FrameStore(self._deps.config.frames.root_path)

    @property
    def _recognizer(self) -> FaceRecognizer:
        if self._deps.recognizer is None:
            self._deps = replace(
                self._deps, recognizer=FaceRecognizer(self._deps.config.face)
            )
        return self._deps.recognizer

    def scan_active_cameras(self) -> None:
        if not self._s.enabled:
            logging.info("Face scan disabled")
            return
        self._run_scan()

    # Task declares run() abstract and the CLI calls it; the mode's own name is
    # scan_active_cameras, which says what this task does where "run" does not.
    run = scan_active_cameras

    def _run_scan(self) -> None:
        cameras = self._deps.repository.get_active()
        if not cameras:
            logging.info("No active cameras to scan")
            return
        known_faces = self._get_all_known_embeddings()
        logging.info(
            "Scanning %d cameras, %d known faces",
            len(cameras),
            len(known_faces),
        )
        for camera in cameras:
            matches = self._scan_camera(camera, known_faces)
            if matches:
                logging.info(
                    "Camera %s:%d matched %d faces",
                    camera.ip,
                    camera.port,
                    len(matches),
                )

    def _scan_camera(
        self,
        camera: CameraModel,
        known_faces: list[KnownEmbedding],
    ) -> list[FaceMatch]:
        all_matches: list[FaceMatch] = []
        self._capture_loop(camera, known_faces, all_matches)
        return all_matches

    def _capture_loop(
        self,
        camera: CameraModel,
        known_faces: list[KnownEmbedding],
        all_matches: list[FaceMatch],
    ) -> None:
        for idx in range(self._s.frames_per_scan):
            frame = self._capture_frame(camera)
            if frame is not None:
                self._process_frame(
                    FrameInput(
                        frame=frame,
                        camera=camera,
                        known_faces=known_faces,
                        all_matches=all_matches,
                        frame_idx=idx,
                        num_frames=self._s.frames_per_scan,
                        interval=self._s.frame_interval,
                    )
                )

    def _process_frame(self, input: FrameInput) -> None:
        faces = self._recognizer.detect(input.frame)
        if not faces:
            if self._s.save_frames:
                self._save_frame(input.camera, input.frame)
            if input.frame_idx > 0:
                time.sleep(input.interval)
            return
        self._store_batch(
            StoreBatch(
                camera=input.camera,
                known_faces=input.known_faces,
                all_matches=input.all_matches,
                frame=input.frame,
            ),
            faces,
        )
        if input.frame_idx < input.num_frames - 1:
            time.sleep(input.interval)

    def _store_batch(
        self,
        batch: StoreBatch,
        faces: list[DetectedFace],
    ) -> None:
        # Every face points at the frame it was found in, so the frame is written
        # whether or not save_frames asked for the frameless ones.
        frame_id = self._save_frame(batch.camera, batch.frame)
        if frame_id is None:
            return
        for face in faces:
            matches = self._recognizer.match_against(face.embedding, batch.known_faces)
            batch.all_matches.extend(matches)
            self._store_face(frame_id, face)

    def _capture_frame(self, camera: CameraModel) -> np.ndarray | None:
        target = RtspTarget(
            host=camera.ip,
            port=camera.port,
            user=camera.user,
            password=camera.password,
            url_template=camera.url,
        )
        probe_result = self._probe.probe(target)
        if probe_result is None:
            return None
        return probe_result.frame

    def _save_frame(self, camera: CameraModel, frame: np.ndarray | None) -> int | None:
        """Write the frame under the layout of R8 and return its row id."""
        if frame is None:
            return None
        stored = self._frames.write(camera.id, FrameSource.rtsp, frame)
        with self._database.session_scope() as session:
            face_frame = FaceFrame(
                camera_id=camera.id,
                path=stored.path,
                source=FrameSource.rtsp,
                width=frame.shape[_WIDTH_AXIS],
                height=frame.shape[_HEIGHT_AXIS],
                captured_at=stored.captured_at,
            )
            session.add(face_frame)
            session.flush()
            return face_frame.id

    def _store_face(self, frame_id: int, face: DetectedFace) -> None:
        with self._database.session_scope() as session:
            session.add(
                Face(
                    frame_id=frame_id,
                    embedding=face.embedding.tolist(),
                    bbox_top=face.bbox[_BBOX_Y],
                    bbox_left=face.bbox[_BBOX_X],
                    bbox_bottom=face.bbox[_BBOX_H],
                    bbox_right=face.bbox[_BBOX_W],
                    confidence=float(face.confidence),
                )
            )

    def _get_all_known_embeddings(self) -> list[KnownEmbedding]:
        """Every stored face, with the camera of the frame it was found in."""
        with self._database.session_scope() as session:
            rows = (
                session.query(Face.id, FaceFrame.camera_id, Face.embedding)
                .join(FaceFrame, Face.frame_id == FaceFrame.id)
                .all()
            )
            return [
                KnownEmbedding(face_id=face_id, camera_id=camera_id, embedding=embedding)
                for face_id, camera_id, embedding in rows
            ]
