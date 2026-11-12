"""The repositories, one per entity.

Each front adds the repository next to the code that uses it, so no table has a
repository nothing calls yet.
"""

import logging

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Query, Session

from models.camera import Camera, CameraStatus
from models.database import Database, default_database
from models.face import Face
from models.finding import CveFinding, CveOutcome
from models.frame import FaceFrame, FrameSource
from models.observation import CameraObservation
from models.person import Person
from models.scan_run import ScanKind, ScanRun
from models.target import Target, TargetHit, TargetPhoto

# The two statuses that mean a frame exists for the camera: one grabbed over
# RTSP, one obtained through a CVE (D33). Both are the face scan's queue.
_FRAME_STATUSES = (CameraStatus.stream_obtained, CameraStatus.frame_by_cve)

# cve_finding.failure_reason is a 512 character column, so a reason is cut to fit
# at the boundary instead of failing the write after the attempt already ran.
_MAX_REASON_CHARS = 480


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

    def find_by_id(self, camera_id: int) -> Camera | None:
        """The camera of one id, for a run narrowed to a single camera."""
        with self._db.session_scope() as session:
            return session.get(Camera, camera_id)

    def record_identity(self, camera: Camera) -> Camera:
        """Write what a scan read off the device onto its row, creating it.

        The row holds what the device looks like now, so a device first seen
        before its brand was in brands.yaml picks up the name on the next run.
        The per-run sighting is the observation's job, not this one.
        """
        with self._db.session_scope() as session:
            stored = self._find_in(session, camera.ip, camera.port)
            if stored is None:
                session.add(camera)
                return camera
            stored.vendor = camera.vendor
            stored.product = camera.product
            stored.version = camera.version
            stored.raw_banner = camera.raw_banner
            return stored

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

    def mark_frame_by_cve(self, camera: Camera) -> bool:
        """Record that the frame came through a CVE class, not over RTSP (D33)."""
        with self._db.session_scope() as session:
            stored = self._find_in(session, camera.ip, camera.port)
            if stored is None:
                logging.warning(
                    "Camera %s:%s not found in the database.", camera.ip, camera.port
                )
                return False
            stored.status = CameraStatus.frame_by_cve
            return True

    def record_device_description(
        self, camera: Camera, model: str, firmware: str
    ) -> bool:
        """Write the model and the firmware an unauthenticated read reported.

        FR-019 asks for them because they are what a firmware-level CVE needs to
        be matched later. A field the read did not carry keeps what the row
        already had, so a description never blanks out the identification.
        """
        with self._db.session_scope() as session:
            stored = self._find_in(session, camera.ip, camera.port)
            if stored is None:
                logging.warning(
                    "Camera %s:%s not found in the database.", camera.ip, camera.port
                )
                return False
            stored.product = model or stored.product
            stored.version = firmware or stored.version
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


@dataclass(frozen=True)
class PersonCameraFrames:
    """What one camera holds of one person: how many faces, from which paths."""

    ip: str
    port: int
    faces: int
    sources: tuple[FrameSource, ...]


@dataclass(frozen=True)
class PersonSummary:
    """One person as `report faces` prints them (FR-028)."""

    person_id: int
    label: str | None
    faces: int
    first_seen: datetime
    last_seen: datetime
    cameras: tuple[PersonCameraFrames, ...]


@dataclass(frozen=True)
class PersonAppearance:
    """One line of the monitoring answer: who, where and when (FR-027, D25)."""

    captured_at: datetime
    person_id: int
    label: str | None
    ip: str
    port: int
    source: FrameSource


@dataclass(frozen=True)
class AppearanceFilters:
    """What narrows the monitoring answer. Every field is optional (D25)."""

    person_id: int | None = None
    camera_id: int | None = None
    since: datetime | None = None
    until: datetime | None = None


class FaceRepository:
    """Encapsulates every query against the face table."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def store(self, face: Face) -> int:
        """Store one detected face and hand back its id.

        The clustering points at the row, so the id is what it needs, and the
        length CHECK of the model is what refuses a vector of the wrong size.
        """
        with self._scope() as session:
            session.add(face)
            session.flush()
            return face.id

    def known(self) -> list[Face]:
        """Every stored face: what a new one is compared against (FR-021).

        That is the whole table, and the ceiling it carries is named where the
        scan calls this (R9).
        """
        with self._scope() as session:
            return session.query(Face).order_by(Face.id).all()

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


class PersonRepository:
    """The person table as the clustering writes it (FR-022, FR-023)."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def person_for(self, face_ids: list[int]) -> Person:
        """The one person those matched faces are, created or merged as needed.

        FR-022: a face that matches joins the person it matched, and a face that
        matches nothing is a new person. FR-023: when the matches name more than
        one person they are merged, and the older row wins (D35). A matched face
        that has no person yet is adopted by the winner, so a face stored before
        the clustering existed joins on the next run.

        All of it is one transaction: a merge that half happened would leave two
        people for one individual.
        """
        with self._scope() as session:
            return self._resolve_in(session, face_ids)

    def name_if_empty(self, person_id: int, name: str) -> bool:
        """Write the target name as the label, only where the label is null.

        A label an operator typed by hand always wins (D63), which is the one
        place this repository breaks the rule of D28 that nothing labels itself.
        True when the write happened, so the caller can log it.
        """
        with self._scope() as session:
            person = session.get(Person, person_id)
            if person is None or person.label is not None:
                return False
            person.label = name
            return True

    def release_label(self, name: str) -> int:
        """Clear every label that equals the name of a removed target (D64).

        Only the exact name is cleared, so a label of a person set by hand under
        another name survives. Returns how many rows were released.
        """
        with self._scope() as session:
            return (
                session.query(Person)
                .filter(Person.label == name)
                .update({Person.label: None})
            )

    def _resolve_in(self, session: Session, face_ids: list[int]) -> Person:
        faces = self._faces_in(session, face_ids)
        found = self._persons_of(session, faces)
        winner = found[0] if found else self._added(session)
        for loser in found[1:]:
            self._merge_in(session, winner, loser)
        self._point_at(faces, winner)
        session.flush()
        return winner

    def _faces_in(self, session: Session, face_ids: list[int]) -> list[Face]:
        return session.query(Face).filter(Face.id.in_(face_ids)).all()

    def _persons_of(self, session: Session, faces: list[Face]) -> list[Person]:
        """The people those faces belong to, oldest first: the merge order (D35)."""
        named = {face.person_id for face in faces if face.person_id is not None}
        if not named:
            return []
        return session.query(Person).filter(Person.id.in_(named)).order_by(Person.id).all()

    def _added(self, session: Session) -> Person:
        person = Person()
        session.add(person)
        session.flush()
        return person

    def _merge_in(self, session: Session, winner: Person, loser: Person) -> None:
        """Move every face of the loser to the winner, then drop the loser row.

        No face and no frame is deleted, so the merge does not touch the
        unlimited retention of D10 (D35).
        """
        session.query(Face).filter(Face.person_id == loser.id).update(
            {Face.person_id: winner.id}
        )
        session.delete(loser)

    def _point_at(self, faces: list[Face], person: Person) -> None:
        for face in faces:
            if face.person_id != person.id:
                face.person_id = person.id

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


class PersonReader:
    """The person table as the reports read it (FR-027, FR-028).

    Read-only, and separate from the clustering: the two share the table and
    nothing else, and a report must not be able to change a person.
    """

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def summaries(self, person_id: int | None = None) -> list[PersonSummary]:
        """Every person with their faces, their window and their cameras."""
        with self._scope() as session:
            totals = self._totals_in(session, person_id)
            cameras = self._cameras_of(session, person_id)
            return [
                PersonSummary(
                    person_id=person.id,
                    label=person.label,
                    faces=faces,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    cameras=cameras.get(person.id, ()),
                )
                for person, faces, first_seen, last_seen in totals
            ]

    def appearances(self, filters: AppearanceFilters) -> list[PersonAppearance]:
        """Who appeared, where and when, oldest first (FR-027, D25).

        One line per appearance, so a person seen twice in one frame is one
        line: the rows are distinct on the person and the frame. The label comes
        with the line, so a report can print the name the row carries (D28).
        """
        with self._scope() as session:
            rows = self._narrow(self._appearance_query(session), filters).all()
            return [
                PersonAppearance(
                    captured_at=captured_at,
                    person_id=found_person,
                    label=label,
                    ip=ip,
                    port=port,
                    source=source,
                )
                for captured_at, found_person, label, ip, port, source in rows
            ]

    def _appearance_query(self, session: Session) -> Query:
        return (
            session.query(
                FaceFrame.captured_at,
                Face.person_id,
                Person.label,
                Camera.ip,
                Camera.port,
                FaceFrame.source,
            )
            .join(Face, Face.frame_id == FaceFrame.id)
            .join(Person, Face.person_id == Person.id)
            .join(Camera, FaceFrame.camera_id == Camera.id)
            .filter(Face.person_id.isnot(None))
            .distinct()
            .order_by(FaceFrame.captured_at, Face.person_id)
        )

    def _narrow(self, query: Query, filters: AppearanceFilters) -> Query:
        """Every filter is a bound parameter, and none of them is built as text."""
        if filters.person_id is not None:
            query = query.filter(Face.person_id == filters.person_id)
        if filters.camera_id is not None:
            query = query.filter(FaceFrame.camera_id == filters.camera_id)
        if filters.since is not None:
            query = query.filter(FaceFrame.captured_at >= filters.since)
        if filters.until is not None:
            query = query.filter(FaceFrame.captured_at <= filters.until)
        return query

    def _totals_in(
        self, session: Session, person_id: int | None
    ) -> list[tuple[Person, int, datetime, datetime]]:
        """One row per person: how many faces, and the window they span."""
        query = (
            session.query(
                Person,
                func.count(Face.id),
                func.min(FaceFrame.captured_at),
                func.max(FaceFrame.captured_at),
            )
            .join(Face, Face.person_id == Person.id)
            .join(FaceFrame, Face.frame_id == FaceFrame.id)
            .group_by(Person.id)
            .order_by(Person.id)
        )
        if person_id is not None:
            query = query.filter(Person.id == person_id)
        return query.all()

    def _cameras_of(
        self, session: Session, person_id: int | None
    ) -> dict[int, tuple[PersonCameraFrames, ...]]:
        """What each camera holds of each person: one query, folded here.

        The fold is in Python rather than in SQL because concatenating the
        sources per camera is a dialect function, and the number of rows is the
        number of cameras a person was seen on.
        """
        counted: dict[tuple[int, str, int], dict[FrameSource, int]] = {}
        for person_id_seen, ip, port, source, faces in self._camera_rows(
            session, person_id
        ):
            counted.setdefault((person_id_seen, ip, port), {})[source] = faces
        grouped: dict[int, list[PersonCameraFrames]] = {}
        for (person_id_seen, ip, port), sources in counted.items():
            grouped.setdefault(person_id_seen, []).append(
                self._frames_of(ip, port, sources)
            )
        return {seen: tuple(cameras) for seen, cameras in grouped.items()}

    def _camera_rows(self, session: Session, person_id: int | None) -> list[tuple]:
        """One row per person, camera and frame source, with the face count."""
        query = (
            session.query(
                Face.person_id,
                Camera.ip,
                Camera.port,
                FaceFrame.source,
                func.count(Face.id),
            )
            .join(FaceFrame, Face.frame_id == FaceFrame.id)
            .join(Camera, FaceFrame.camera_id == Camera.id)
            .group_by(Face.person_id, Camera.ip, Camera.port, FaceFrame.source)
            .order_by(Face.person_id, Camera.ip, Camera.port)
        )
        if person_id is not None:
            query = query.filter(Face.person_id == person_id)
        return query.all()

    def _frames_of(
        self, ip: str, port: int, sources: dict[FrameSource, int]
    ) -> PersonCameraFrames:
        return PersonCameraFrames(
            ip=ip,
            port=port,
            faces=sum(sources.values()),
            sources=tuple(sorted(sources, key=self._source_order)),
        )

    def _source_order(self, source: FrameSource) -> int:
        """The order the paths are declared in, so the line reads the same twice."""
        return list(FrameSource).index(source)

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


class CveFindingRepository:
    """Encapsulates every query against the cve_finding table."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def upsert(self, finding: CveFinding) -> CveFinding:
        """The row of this camera and CVE, inserted when the pair is new.

        UNIQUE (camera_id, cve_id) makes the pair the identity of a finding, so a
        repeated run updates the row and `first_seen_at` keeps when the CVE was
        first matched (D31).
        """
        with self._scope() as session:
            stored = self._find_in(session, finding.camera_id, finding.cve_id)
            if stored is None:
                session.add(finding)
                return finding
            stored.cve_class = finding.cve_class
            # The column default applies at INSERT only, so a caller that never
            # stated a range hands over None here; the column is not nullable.
            stored.matched_range = finding.matched_range or ""
            stored.cvss = finding.cvss
            stored.scan_run_id = finding.scan_run_id
            return stored

    def record_frame(self, finding: CveFinding, frame_id: int) -> None:
        """The class produced the picture: the frame is the whole outcome."""
        with self._scope() as session:
            stored = self._stored_in(session, finding)
            stored.outcome = CveOutcome.frame_obtained
            stored.failure_reason = ""
            stored.frame_id = frame_id
            stored.last_attempt_at = func.now()

    def record_failure(self, finding: CveFinding, reason: str) -> None:
        """The class produced no picture: the reason is recorded, not dropped.

        A reason is cut to the width of the column, because losing the tail of a
        long list of ports is better than losing the write (FR-018).
        """
        with self._scope() as session:
            stored = self._stored_in(session, finding)
            stored.outcome = CveOutcome.no_frame
            stored.failure_reason = reason[:_MAX_REASON_CHARS]
            stored.last_attempt_at = func.now()

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()

    def _find_in(
        self, session: Session, camera_id: int, cve_id: str
    ) -> CveFinding | None:
        return (
            session.query(CveFinding)
            .filter(CveFinding.camera_id == camera_id, CveFinding.cve_id == cve_id)
            .one_or_none()
        )

    def _stored_in(self, session: Session, finding: CveFinding) -> CveFinding:
        """The row as the session holds it, so the write lands on the stored one."""
        return session.query(CveFinding).filter(CveFinding.id == finding.id).one()


class FaceFrameRepository:
    """Encapsulates every query against the face_frame table."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def record(self, frame: FaceFrame) -> FaceFrame:
        """Store the row of a frame that is already on disk.

        The file comes first: a row without its file is a broken reference, and
        UNIQUE (path) makes a second write of the same file one row (R8).
        """
        with self._scope() as session:
            session.add(frame)
            session.flush()
            return frame

    def for_camera(self, camera_id: int) -> list[FaceFrame]:
        """Every frame stored for one camera, oldest first: what a scan reads.

        The face scan detects in these frames before it captures anything, so the
        order is the order the pipeline obtained them.
        """
        with self._scope() as session:
            return (
                session.query(FaceFrame)
                .filter(FaceFrame.camera_id == camera_id)
                .order_by(FaceFrame.captured_at, FaceFrame.id)
                .all()
            )

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


@dataclass(frozen=True)
class StoredFace:
    """One stored face with the frame it lives in: the comparison input (D47)."""

    face_id: int
    person_id: int
    label: str | None
    embedding: list[float]
    camera_id: int
    captured_at: datetime
    ip: str
    port: int
    source: FrameSource
    path: str


@dataclass(frozen=True)
class RankedAppearance:
    """One line of the target ranking: where the target was, and how close."""

    score: float
    target_id: int
    target_name: str
    person_id: int
    label: str | None
    captured_at: datetime
    ip: str
    port: int
    path: str


@dataclass(frozen=True)
class PersonTargetMatch:
    """A target one person matches, as the face report prints it (D58)."""

    target_id: int
    name: str
    score: float


@dataclass(frozen=True)
class RemovedTarget:
    """What a removal deleted, so the command can say it out loud (D64)."""

    target_id: int
    name: str
    photos: tuple[str, ...]
    hits: int


class TargetRepository:
    """The target table and the photo rows that belong to it (D55, D57)."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def find_by_name(self, name: str) -> Target | None:
        with self._scope() as session:
            return session.query(Target).filter(Target.name == name).one_or_none()

    def find_by_id(self, target_id: int) -> Target | None:
        with self._scope() as session:
            return session.get(Target, target_id)

    def resolve(self, name: str) -> Target:
        """The target of that name, created when the name is new (D55).

        The name is the identity key, so a repeated registration adds photos to
        the target that is already there instead of a second one.
        """
        with self._scope() as session:
            found = session.query(Target).filter(Target.name == name).one_or_none()
            if found is not None:
                return found
            target = Target(name=name)
            session.add(target)
            session.flush()
            return target

    def add_photo(self, target_id: int, path: str, embedding: list[float]) -> None:
        with self._scope() as session:
            session.add(TargetPhoto(target_id=target_id, path=path, embedding=embedding))

    def photos_of(self, target_id: int) -> list[TargetPhoto]:
        with self._scope() as session:
            return (
                session.query(TargetPhoto)
                .filter(TargetPhoto.target_id == target_id)
                .order_by(TargetPhoto.id)
                .all()
            )

    def all(self) -> list[Target]:
        with self._scope() as session:
            return session.query(Target).order_by(Target.id).all()

    def remove(self, target_id: int) -> RemovedTarget | None:
        """Drop the target with its hits and photos in one transaction (D54).

        The photo paths come back so the caller deletes the files after the
        commit: a file orphaned by a failed commit is harmless, a row pointing
        at a deleted file is not. No face and no frame is touched.
        """
        with self._scope() as session:
            target = session.get(Target, target_id)
            if target is None:
                return None
            removed = RemovedTarget(
                target_id=target_id,
                name=target.name,
                photos=self._paths_in(session, target_id),
                hits=self._delete_rows(session, target_id),
            )
            session.delete(target)
            return removed

    def _paths_in(self, session: Session, target_id: int) -> tuple[str, ...]:
        rows = (
            session.query(TargetPhoto)
            .filter(TargetPhoto.target_id == target_id)
            .order_by(TargetPhoto.id)
            .all()
        )
        return tuple(row.path for row in rows)

    def _delete_rows(self, session: Session, target_id: int) -> int:
        hits = session.query(TargetHit).filter(TargetHit.target_id == target_id).delete()
        session.query(TargetPhoto).filter(TargetPhoto.target_id == target_id).delete()
        return hits

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


class TargetHitRepository:
    """The hit table: one row per target and face, never two (FR-012, R6)."""

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def record(self, target_id: int, face_id: int, score: float) -> bool:
        """Store the hit, raising the score only when the new one is higher.

        A later, worse photo cannot lower the evidence that the person is there,
        and a repeated search cannot grow the table. True when the row changed.
        """
        with self._scope() as session:
            stored = self._stored_in(session, target_id, face_id)
            if stored is None:
                session.add(TargetHit(target_id=target_id, face_id=face_id, score=score))
                return True
            if score <= stored.score:
                return False
            stored.score = score
            return True

    def count(self) -> int:
        with self._scope() as session:
            return session.query(TargetHit).count()

    def count_of(self, target_id: int) -> int:
        with self._scope() as session:
            return self._of_target(session, target_id).count()

    def _of_target(self, session: Session, target_id: int) -> Query:
        return session.query(TargetHit).filter(TargetHit.target_id == target_id)

    def _stored_in(
        self, session: Session, target_id: int, face_id: int
    ) -> TargetHit | None:
        return (
            session.query(TargetHit)
            .filter(TargetHit.target_id == target_id, TargetHit.face_id == face_id)
            .one_or_none()
        )

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()


class TargetReader:
    """What the target search and the face report read (D47, D58)."""

    _FACE_COLUMNS = (
        "face_id",
        "person_id",
        "label",
        "embedding",
        "camera_id",
        "captured_at",
        "ip",
        "port",
        "source",
        "path",
    )

    def __init__(self, database: Database | None = None) -> None:
        self._database = database

    def faces(self, filters: AppearanceFilters) -> list[StoredFace]:
        """Every stored face with its person, camera, time and frame path.

        Only faces the clustering already assigned: a face with no person has
        nobody to rank, and the ranking line names a person (D50).
        """
        with self._scope() as session:
            rows = self._narrow(self._face_query(session), filters).all()
        return [self._stored(row) for row in rows]

    def matches_of(
        self, person_id: int | None = None
    ) -> dict[int, list[PersonTargetMatch]]:
        """The targets each person matches, best score first (D58)."""
        with self._scope() as session:
            rows = self._match_query(session, person_id).all()
            return self._grouped(rows)

    def _face_query(self, session: Session) -> Query:
        return (
            session.query(
                Face.id,
                Face.person_id,
                Person.label,
                Face.embedding,
                FaceFrame.camera_id,
                FaceFrame.captured_at,
                Camera.ip,
                Camera.port,
                FaceFrame.source,
                FaceFrame.path,
            )
            .join(FaceFrame, Face.frame_id == FaceFrame.id)
            .join(Person, Face.person_id == Person.id)
            .join(Camera, FaceFrame.camera_id == Camera.id)
            .order_by(Face.id)
        )

    def _narrow(self, query: Query, filters: AppearanceFilters) -> Query:
        if filters.person_id is not None:
            query = query.filter(Face.person_id == filters.person_id)
        if filters.camera_id is not None:
            query = query.filter(FaceFrame.camera_id == filters.camera_id)
        if filters.since is not None:
            query = query.filter(FaceFrame.captured_at >= filters.since)
        if filters.until is not None:
            query = query.filter(FaceFrame.captured_at <= filters.until)
        return query

    def _stored(self, row: tuple) -> StoredFace:
        row_values = dict(zip(self._FACE_COLUMNS, row))
        return StoredFace(
            face_id=row_values["face_id"],
            person_id=row_values["person_id"],
            label=row_values["label"],
            embedding=list(row_values["embedding"]),
            camera_id=row_values["camera_id"],
            captured_at=row_values["captured_at"],
            ip=row_values["ip"],
            port=row_values["port"],
            source=row_values["source"],
            path=row_values["path"],
        )

    def _match_query(self, session: Session, person_id: int | None) -> Query:
        query = (
            session.query(Face.person_id, Target.id, Target.name, TargetHit.score)
            .join(TargetHit, TargetHit.face_id == Face.id)
            .join(Target, TargetHit.target_id == Target.id)
        )
        if person_id is None:
            return query
        return query.filter(Face.person_id == person_id)

    def _grouped(self, rows: list[tuple]) -> dict[int, list[PersonTargetMatch]]:
        best: dict[int, dict[int, PersonTargetMatch]] = {}
        for person_id, target_id, name, score in rows:
            of_person = best.setdefault(person_id, {})
            if target_id not in of_person or score > of_person[target_id].score:
                of_person[target_id] = PersonTargetMatch(
                    target_id=target_id, name=name, score=score
                )
        return {person: self._ranked(found) for person, found in best.items()}

    def _ranked(
        self, found: dict[int, PersonTargetMatch]
    ) -> list[PersonTargetMatch]:
        return sorted(found.values(), key=lambda match: match.score, reverse=True)

    def _scope(self) -> AbstractContextManager[Session]:
        """The injected database, or the process-wide one."""
        return (self._database or default_database()).session_scope()
