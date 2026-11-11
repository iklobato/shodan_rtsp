"""The read-only commands: `report faces`, `search` and `measure threshold`.

None of them writes anything. They read the database or a labelled pair set and
put lines on stdout, and every line names a person by id: nothing labels a person
automatically, so a name would be a claim the data does not carry (D28). A label
set on the row by hand is printed beside the id, because that one the data does
carry.

The lines go through a writer instead of a bare `print`, because a class of this
repository never prints: the command line owns stdout, this module owns the
format, and the format is the one `contracts/cli.md` prints.
"""

import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from models.managers import (
    AppearanceFilters,
    PersonAppearance,
    PersonCameraFrames,
    PersonReader,
    PersonSummary,
)
from scanners.face_recognizer import ThresholdMeasurement

_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_UTC = timezone.utc
_NO_PERSON = "no person stored"
_NO_APPEARANCE = "no appearance stored"
_FIRST_WIDTH = 1


class Runnable(Protocol):
    """What a command of this CLI hands back: calling run() does its job."""

    run: Callable[[], None]


class TimestampNotParsed(Exception):
    """A --since or --until that is not an instant this build can read."""


class Stamp:
    """One instant as the contract prints it: UTC, to the second, with the Z."""

    @classmethod
    def of(cls, moment: datetime) -> str:
        """The instant, read as UTC when the row carried no zone.

        A row read from sqlite is naive, and a naive instant is UTC here because
        that is what the database stores: a local reading would print a time the
        row never held.
        """
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=_UTC)
        return moment.astimezone(_UTC).strftime(_TIMESTAMP_FORMAT)


class Boundary:
    """The instant a --since or --until names (D25)."""

    @classmethod
    def parsed(cls, value: str | None) -> datetime | None:
        """The instant, or None when the option was not given."""
        if value is None:
            return None
        try:
            moment = datetime.fromisoformat(value)
        except ValueError as unreadable:
            raise TimestampNotParsed(
                f"{value} is not a timestamp: {unreadable}"
            ) from unreadable
        if moment.tzinfo is None:
            return moment.replace(tzinfo=_UTC)
        return moment


class StdoutLines:
    """Where a read-only command puts its result: one line per call.

    `sys.stdout.write` and not a bare `print`, so a class of this repository
    never prints and a caller can send the lines somewhere else.
    """

    def write(self, line: str) -> None:
        sys.stdout.write(f"{line}\n")


@dataclass(frozen=True)
class PersonCell:
    """How a person is named in a line: the id, and the label when one was set."""

    @classmethod
    def of(cls, person_id: int, label: str | None) -> str:
        """`person 3`, or `person 3 (henry)` when the row carries a label (D28)."""
        if label:
            return f"person {person_id} ({label})"
        return f"person {person_id}"


@dataclass(frozen=True)
class ColumnWidths:
    """The widest cell of each column, so the lines of one report line up."""

    person: int = _FIRST_WIDTH
    faces: int = _FIRST_WIDTH
    address: int = 0

    @classmethod
    def of_people(cls, summaries: list[PersonSummary]) -> "ColumnWidths":
        """The widths `report faces` needs, over the people it is about to print."""
        addresses = [
            address
            for summary in summaries
            for address in cls._addresses(summary.cameras)
        ]
        return cls(
            person=cls._widest(
                PersonCell.of(summary.person_id, summary.label) for summary in summaries
            ),
            faces=cls._widest(str(summary.faces) for summary in summaries),
            address=cls._widest(addresses),
        )

    @classmethod
    def of_appearances(cls, appearances: list[PersonAppearance]) -> "ColumnWidths":
        """The widths `search` needs, over the appearances it is about to print."""
        return cls(
            person=cls._widest(
                PersonCell.of(one.person_id, one.label) for one in appearances
            ),
            address=cls._widest(f"{one.ip}:{one.port}" for one in appearances),
        )

    @classmethod
    def _addresses(cls, cameras: tuple[PersonCameraFrames, ...]) -> list[str]:
        return [f"{camera.ip}:{camera.port}" for camera in cameras]

    @classmethod
    def _widest(cls, cells: Iterable[str]) -> int:
        """The longest cell, or one column of nothing when there is no row."""
        return max((len(cell) for cell in cells), default=_FIRST_WIDTH)


@dataclass(frozen=True)
class ReportDeps:
    """What a read-only report needs: the data, the lines, and the narrowing."""

    people: PersonReader
    lines: StdoutLines
    filters: AppearanceFilters = AppearanceFilters()


class PersonReport:
    """`report faces`: what the face scan found, person by person (FR-028)."""

    def __init__(self, deps: ReportDeps) -> None:
        self._deps = deps

    def render(self) -> None:
        """One block per person: their faces, their window and their cameras."""
        summaries = self._deps.people.summaries(self._deps.filters.person_id)
        if not summaries:
            self._deps.lines.write(_NO_PERSON)
            return
        widths = ColumnWidths.of_people(summaries)
        for summary in summaries:
            self._deps.lines.write(self._headline(summary, widths))
            for camera in summary.cameras:
                self._deps.lines.write(self._camera_line(camera, widths))

    # The command line calls run() on whatever a group hands back; the mode's own
    # name says what this report does where "run" does not.
    run = render

    def _headline(self, summary: PersonSummary, widths: ColumnWidths) -> str:
        """The person, how many faces are theirs, and the window they span."""
        cell = PersonCell.of(summary.person_id, summary.label)
        return (
            f"{cell:<{widths.person}}  "
            f"faces {summary.faces:<{widths.faces}}  "
            f"first seen {Stamp.of(summary.first_seen)}  "
            f"last seen {Stamp.of(summary.last_seen)}"
        )

    def _camera_line(self, camera: PersonCameraFrames, widths: ColumnWidths) -> str:
        """One camera of one person, and the paths that produced its frames."""
        address = f"{camera.ip}:{camera.port}"
        paths = ", ".join(source.value for source in camera.sources)
        return (
            f"  camera {address:<{widths.address}}  "
            f"frames {camera.faces}  frame {paths}"
        )


class SearchReport:
    """`search`: who appeared, where and when, oldest first (FR-027, D25)."""

    def __init__(self, deps: ReportDeps) -> None:
        self._deps = deps

    def render(self) -> None:
        """One line per appearance, and nothing at all when there was none."""
        appearances = self._deps.people.appearances(self._deps.filters)
        if not appearances:
            self._deps.lines.write(_NO_APPEARANCE)
            return
        widths = ColumnWidths.of_appearances(appearances)
        for appearance in appearances:
            self._deps.lines.write(self._line(appearance, widths))

    run = render

    def _line(self, appearance: PersonAppearance, widths: ColumnWidths) -> str:
        address = f"{appearance.ip}:{appearance.port}"
        cell = PersonCell.of(appearance.person_id, appearance.label)
        return (
            f"{Stamp.of(appearance.captured_at)}  "
            f"{cell:<{widths.person}}  "
            f"camera {address:<{widths.address}}  frame {appearance.source.value}"
        )


class ThresholdReport:
    """`measure threshold`: the pair set measured, and nothing written (D16)."""

    def __init__(self, measurement: ThresholdMeasurement, lines: StdoutLines) -> None:
        self._measurement = measurement
        self._lines = lines

    def render(self) -> None:
        """The two groups and the separation, as the contract prints them."""
        for line in self._measurement.report():
            self._lines.write(line)

    run = render
