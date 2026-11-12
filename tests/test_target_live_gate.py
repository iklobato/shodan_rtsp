"""`search person` reaches a camera only with `--live`, and only inside the list.

Without the flag the command is a query over the stored rows and no socket is
opened. With it, the live pass is the face scan path itself, so the same
`targets.allowed_cidrs` gate refuses a wide run before any packet leaves and
the run is recorded as a scan of kind `faces` (D61, D62).
"""

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from models.scan_run import ScanKind
from scanners.config import FaceConfig, TargetsConfig
from scanners.face_task import FaceScanTask
from scanners.reports import SearchPersonCommand, SearchPersonDeps
from scanners.task import TargetOutsideScopeError
from tests.conftest import FaceLab, FakeDetector, FakeFace, Vectors

_NAME = "maria"
_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_OUTSIDE_CIDR = "127.0.0.1/32"
_SAME_DEGREES = 0.0


class Order:
    """The steps one run took, in the order it took them."""

    def __init__(self) -> None:
        self.steps: list[str] = []


class Recording:
    """A step that only says it ran, in the order the command calls it."""

    def __init__(self, order: Order, label: str) -> None:
        self._order = order
        self._label = label

    def note_step(self) -> None:
        self._order.steps.append(self._label)

    # The command calls run() on the object it was handed, as the CLI does.
    run = note_step


class CountedSearch:
    """The search of the command: it records the call and answers nothing."""

    def __init__(self, order: Order) -> None:
        self._order = order

    def matches(self) -> list:
        self._order.steps.append("search")
        return []


class RecordingReport:
    """The ranking the command prints, recorded so the order is visible."""

    def __init__(self, order: Order) -> None:
        self._order = order

    def render(self, ranked: list) -> None:
        self._order.steps.append(f"report {len(ranked)}")


class NoRegistration:
    """A photo-less run registers nothing, and this one would fail if it did."""

    def register(self, name: str, images: list[str]) -> None:
        raise AssertionError("a run without --image registers nothing")


class CommandBuilder:
    """The command under test, with stubs that record the order of its steps."""

    @classmethod
    def over(cls, order: Order, live: Recording | None) -> SearchPersonCommand:
        return SearchPersonCommand(
            SearchPersonDeps(
                registration=NoRegistration(),
                search=CountedSearch(order),
                report=RecordingReport(order),
                name=_NAME,
                live=live,
            )
        )


def test_without_live_no_scan_runs() -> None:
    """No flag, no camera: the run is the stored rows and nothing else."""
    order = Order()

    CommandBuilder.over(order, None).run()

    assert order.steps == ["search", "report 0"]


def test_the_live_scan_runs_before_the_search() -> None:
    """The faces a live pass stores are searched by the same run (D52)."""
    order = Order()

    CommandBuilder.over(order, Recording(order, "live")).run()

    assert order.steps == ["live", "search", "report 0"]


def test_the_live_pass_is_gated_before_any_packet(face_lab: FaceLab) -> None:
    """The wide run of `--live` carries the gate of the face scan (D18, D61)."""
    deps = replace(
        face_lab.deps(FakeDetector([[FakeFace.of(Vectors.unit(_SAME_DEGREES))]])),
        config=FaceConfig(),
        targets=TargetsConfig(allowed_cidrs=[_OUTSIDE_CIDR]),
    )

    with pytest.raises(TargetOutsideScopeError):
        FaceScanTask(deps, database=face_lab.database).run()

    assert face_lab.last_run() is None


def test_the_live_pass_writes_a_run_of_kind_faces(face_lab: FaceLab) -> None:
    face_lab.frame(_MOMENT)

    face_lab.scan(
        face_lab.deps(FakeDetector([[FakeFace.of(Vectors.unit(_SAME_DEGREES))]]))
    )

    assert face_lab.last_run().kind is ScanKind.faces
