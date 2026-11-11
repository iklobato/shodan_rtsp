"""Match the stored observations against the CVE map, then read the device.

The match comes from the database, never from the nmap XML: the XML is what one
scan collected, and a run has to be answerable afterwards from what was stored
(D30, FR-029).

Every attempt is a read. A class that yields no frame records why and the next
class of the batch is tried; the run stops at the first frame (FR-017). A run
that ends with no frame at all finished, it did not fail.
"""

import logging
from dataclasses import dataclass, replace

import numpy as np

from models.camera import Camera
from models.database import Database
from models.finding import CveClass, CveFinding
from models.frame import FaceFrame, FrameSource
from models.managers import CveFindingRepository, FaceFrameRepository
from models.scan_run import ScanKind, ScanRun
from scanners.brand_probe import ServiceEvidence
from scanners.config import FramesConfig, TargetsConfig, VulnConfig
from scanners.cve import CVE_BATCH
from scanners.cve.base import (
    AttemptResult,
    CveAttempt,
    CveTarget,
    HttpReadTransport,
    ReadFailed,
    ReadTransport,
)
from scanners.frames import FrameStore, StoredFrame
from scanners.task import Task, TargetGate, UnknownCameraError
from scanners.vuln_probe import CpeMap, CveFeed, CveMatch, DeviceFingerprint, VulnProbe

# frame.shape is (rows, columns, channels), so the axes are named rather than
# written as bare 0 and 1 at the one place that reads them.
_HEIGHT_AXIS = 0
_WIDTH_AXIS = 1


@dataclass(frozen=True)
class AttemptContext:
    """The camera being read, the run it belongs to, and what the class proves.

    One object because the four calls an attempt makes (open the finding, send
    the read, write the camera, store the frame) all need the same three things.
    """

    camera: Camera
    run: ScanRun
    cve_class: CveClass


@dataclass(frozen=True)
class CveDeps:
    """What the CVE task needs beyond the database.

    `probe`, `attempts`, `transport` and `store` are the seams the tests inject;
    a real run leaves them None and the task builds each one from the config.
    """

    config: VulnConfig
    frames: FramesConfig
    targets: TargetsConfig
    camera_id: int = 0
    probe: VulnProbe | None = None
    attempts: tuple[CveAttempt, ...] | None = None
    batch: tuple[type[CveAttempt], ...] = CVE_BATCH
    transport: ReadTransport | None = None
    store: FrameStore | None = None


class CveTask(Task):
    """Try the read-only CVE classes of the batch against the stored cameras."""

    def __init__(self, deps: CveDeps, database: Database = None) -> None:
        self._deps = deps
        self.database = database

    @property
    def config(self) -> VulnConfig:
        """The vuln section, so the base class contract still holds."""
        return self._deps.config

    @property
    def _finding_rows(self) -> CveFindingRepository:
        return CveFindingRepository(self._database())

    @property
    def _frame_rows(self) -> FaceFrameRepository:
        return FaceFrameRepository(self._database())

    def attempt_matches(self) -> None:
        logging.info("Starting the CVE task")
        cameras = self._queue()
        # D18: a run narrowed with --camera-id reaches the address the operator
        # named, which is the authorization itself; only the wide run, over
        # addresses nobody typed this time, is gated.
        if not self._deps.camera_id:
            TargetGate(self._deps.targets.allowed_cidrs).require_reachable(
                [camera.ip for camera in cameras]
            )
        run = self.runs.start(ScanKind.cve, self._target_set(cameras))
        for camera in cameras:
            self._try_camera(camera, run)
        self.runs.finish(run, len(cameras))
        logging.info("Executors: finished the CVE task")

    # Task declares run() abstract and the CLI calls it; the mode's own name says
    # what this task does where "run" does not.
    run = attempt_matches

    def _queue(self) -> list[Camera]:
        """The cameras this run reaches: the named one, or every one waiting."""
        if not self._deps.camera_id:
            return self.repository.get_random_without_frame()
        named = self.repository.find_by_id(self._deps.camera_id)
        if named is None:
            raise UnknownCameraError(f"no camera with id {self._deps.camera_id}")
        return [named]

    def _target_set(self, cameras: list[Camera]) -> str:
        """What the run reached, recorded before any packet leaves (FR-002)."""
        addresses = sorted({camera.ip for camera in cameras})
        return ", ".join(addresses) if addresses else "no camera waiting for a frame"

    def _try_camera(self, camera: Camera, run: ScanRun) -> None:
        matches = self._probe().match(self._fingerprint(camera))
        if not matches:
            return
        logging.info("%s:%d matches %d CVE(s)", camera.ip, camera.port, len(matches))
        self._try_classes(camera, matches, run)

    def _try_classes(self, camera: Camera, matches: list[CveMatch], run: ScanRun) -> None:
        """The batch in order, until one class yields the frame (FR-017)."""
        by_cve = {match.cve_id: match for match in matches}
        for attempt in self._attempts():
            context = AttemptContext(camera, run, attempt.cve_class)
            covered = [
                by_cve[cve_id] for cve_id in attempt.cve_ids if cve_id in by_cve
            ]
            if not covered:
                continue
            findings = [self._open_finding(match, context) for match in covered]
            outcome = self._read(attempt, context)
            self._write_to_camera(context, outcome)
            frame_id = self._store_frame(context, outcome)
            for finding in findings:
                self._record(finding, outcome, frame_id)
            if frame_id is not None:
                break

    def _fingerprint(self, camera: Camera) -> DeviceFingerprint:
        """What the scan already stored about this camera (D30, FR-029).

        The row carries what its newest observation saw, because the scan writes
        both from the same sighting. Nothing here re-reads the nmap XML.
        """
        evidence = ServiceEvidence.from_stored(camera.raw_banner)
        return DeviceFingerprint(
            host=camera.ip,
            port=camera.port,
            vendor=camera.vendor,
            product=camera.product,
            version=camera.version,
            cpe=evidence.cpe,
        )

    def _open_finding(self, match: CveMatch, context: AttemptContext) -> CveFinding:
        """The finding row, open before its attempt runs, so a crash keeps it."""
        return self._finding_rows.upsert(
            CveFinding(
                camera_id=context.camera.id,
                scan_run_id=context.run.id,
                cve_id=match.cve_id,
                cve_class=context.cve_class,
                matched_range=match.matched_range,
                cvss=match.cvss,
            )
        )

    def _read(self, attempt: CveAttempt, context: AttemptContext) -> AttemptResult:
        """One class, bounded: a device that never answers is a recorded reason."""
        try:
            return attempt.attempt(self._target(context.camera))
        except ReadFailed as unreachable:
            return AttemptResult.recorded(f"{attempt.cve_ids[0]}: {unreachable}")

    def _record(
        self, finding: CveFinding, outcome: AttemptResult, frame_id: int | None
    ) -> None:
        """What the attempt produced, on the finding row (FR-018)."""
        if frame_id is None:
            self._finding_rows.record_failure(finding, outcome.reason)
            return
        self._finding_rows.record_frame(finding, frame_id)

    def _write_to_camera(self, context: AttemptContext, outcome: AttemptResult) -> None:
        """What the read proved, on the camera row: the frame, or the model."""
        if outcome.frame is not None:
            self.repository.mark_frame_by_cve(context.camera)
        if outcome.model or outcome.firmware:
            self.repository.record_device_description(
                context.camera, outcome.model, outcome.firmware
            )

    def _store_frame(self, context: AttemptContext, outcome: AttemptResult) -> int | None:
        """Write the one frame of the run: the file first, then its row (R8)."""
        if outcome.frame is None:
            return None
        stored = self._frame_store().write(
            context.camera.id, FrameSource.cve, outcome.frame
        )
        return self._frame_rows.record(
            self._face_frame(context, stored, outcome.frame)
        ).id

    def _face_frame(
        self, context: AttemptContext, stored: StoredFrame, frame: np.ndarray
    ) -> FaceFrame:
        return FaceFrame(
            camera_id=context.camera.id,
            scan_run_id=context.run.id,
            path=stored.path,
            source=FrameSource.cve,
            width=frame.shape[_WIDTH_AXIS],
            height=frame.shape[_HEIGHT_AXIS],
        )

    def _target(self, camera: Camera) -> CveTarget:
        """The camera's own port first, then the web ports the config names."""
        extra = [port for port in self._deps.config.web_ports if port != camera.port]
        return CveTarget(host=camera.ip, ports=(camera.port, *extra))

    def _probe(self) -> VulnProbe:
        if self._deps.probe is None:
            config = self._deps.config
            self._deps = replace(
                self._deps,
                probe=VulnProbe(
                    feed=CveFeed(config.feed_path),
                    cpe_map=CpeMap(config.cpe_map_path),
                    min_cvss=config.min_cvss,
                ),
            )
        return self._deps.probe

    def _attempts(self) -> tuple[CveAttempt, ...]:
        """One instance per class of the batch, over the configured transport."""
        if self._deps.attempts is None:
            transport = self._deps.transport or HttpReadTransport(
                self._deps.config.timeout_seconds
            )
            self._deps = replace(
                self._deps,
                attempts=tuple(built(transport) for built in self._deps.batch),
            )
        return self._deps.attempts

    def _frame_store(self) -> FrameStore:
        if self._deps.store is None:
            self._deps = replace(self._deps, store=FrameStore(self._deps.frames.root_path))
        return self._deps.store
