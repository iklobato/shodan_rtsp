"""The repositories, one per entity.

Each front adds the repository next to the code that uses it, so no table has a
repository nothing calls yet.
"""

import logging

from contextlib import AbstractContextManager

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.camera import Camera, CameraStatus
from models.database import Database, default_database
from models.observation import CameraObservation
from models.scan_run import ScanKind, ScanRun

# The two statuses that mean a frame exists for the camera: one grabbed over
# RTSP, one obtained through a CVE (D33). Both are the face scan's queue.
_FRAME_STATUSES = (CameraStatus.stream_obtained, CameraStatus.frame_by_cve)


class CameraRepository:
    """Encapsulates every query against the camera table."""

    def __init__(self, database: Database = None):
        self._db = database or default_database()

    def get_or_create(self, camera: Camera) -> Camera:
        """The stored camera at (ip, port), inserted when it is new.

        UNIQUE (ip, port) makes the endpoint the identity of a camera, so a
        second scan of the same endpoint has to find the row instead of adding a
        duplicate (FR-006).
        """
        with self._db.session_scope() as session:
            stored = self._find_in(session, camera.ip, camera.port)
            if stored is not None:
                logging.debug("Camera %s:%s already stored", camera.ip, camera.port)
                return stored
            session.add(camera)
            return camera

    def find(self, ip: str, port: int) -> Camera | None:
        with self._db.session_scope() as session:
            return self._find_in(session, ip, port)

    def get_random_without_frame(self) -> list[Camera]:
        """The cameras with no frame yet, shuffled: the check task's queue."""
        with self._db.session_scope() as session:
            return (
                session.query(Camera)
                .filter(Camera.status.notin_(_FRAME_STATUSES))
                .order_by(func.random())
                .all()
            )

    def get_with_frame(self) -> list[Camera]:
        """The cameras a frame exists for: the face scan's queue."""
        with self._db.session_scope() as session:
            return session.query(Camera).filter(Camera.status.in_(_FRAME_STATUSES)).all()

    def mark_stream_obtained(self, camera: Camera) -> bool:
        """Record that the credentials worked and a stream was grabbed."""
        with self._db.session_scope() as session:
            stored = self._find_in(session, camera.ip, camera.port)
            if stored is None:
                logging.warning(
                    "Camera %s:%s not found in the database.", camera.ip, camera.port
                )
                return False
            stored.status = CameraStatus.stream_obtained
            stored.user = camera.user
            stored.password = camera.password
            stored.url = camera.url
            logging.debug("Updated %s:%s", camera.ip, camera.port)
            return True

    def _find_in(self, session: Session, ip: str, port: int) -> Camera | None:
        return (
            session.query(Camera)
            .filter(Camera.ip == ip, Camera.port == port)
            .one_or_none()
        )


class ScanRunRepository:
    """Encapsulates every query against the scan_run table."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def start(self, kind: ScanKind, target_set: str) -> ScanRun:
        """Open a run and record what it is allowed to reach (FR-002, D6).

        The target set is the only place that answers, after the fact, what the
        run reached, so it is written before any packet leaves.
        """
        run = ScanRun(kind=kind, target_set=target_set)
        with self._scope() as session:
            session.add(run)
        return run

    def finish(self, run: ScanRun, camera_count: int) -> None:
        """Close the run and keep how many cameras it reached."""
        with self._scope() as session:
            stored = session.query(ScanRun).filter(ScanRun.id == run.id).one()
            stored.finished_at = func.now()
            stored.camera_count = camera_count

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


class CameraObservationRepository:
    """Encapsulates every query against the camera_observation table."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def record(self, camera: Camera, run: ScanRun) -> CameraObservation:
        """Snapshot what this camera looks like in this run, once per port.

        UNIQUE (camera_id, scan_run_id, port) makes a second sighting inside the
        same run an update of the same row, so a run that sees one camera twice
        does not double the series (FR-006).
        """
        with self._scope() as session:
            stored = self._find_in(session, camera, run)
            if stored is None:
                stored = CameraObservation(
                    camera_id=camera.id, scan_run_id=run.id, port=camera.port
                )
                session.add(stored)
            self._copy_from(stored, camera)
            session.flush()
            return stored

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()

    def _find_in(
        self, session: Session, camera: Camera, run: ScanRun
    ) -> CameraObservation | None:
        return (
            session.query(CameraObservation)
            .filter(
                CameraObservation.camera_id == camera.id,
                CameraObservation.scan_run_id == run.id,
                CameraObservation.port == camera.port,
            )
            .one_or_none()
        )

    def _copy_from(self, observation: CameraObservation, camera: Camera) -> None:
        """What the camera looks like now is what this run observed."""
        observation.status = camera.status
        observation.vendor = camera.vendor
        observation.product = camera.product
        observation.version = camera.version
        observation.raw_banner = camera.raw_banner
