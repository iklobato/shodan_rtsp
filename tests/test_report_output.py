"""The two read-only reports print the lines `contracts/cli.md` prints.

The stub tests pin the format, the padding included, over rows a test built by
hand; the last one runs the same two reports over rows the repositories stored,
so the joins and the aggregation are the code under test.
"""

from datetime import datetime, timezone

from models.frame import FrameSource
from models.managers import (
    AppearanceFilters,
    PersonAppearance,
    PersonCameraFrames,
    PersonReader,
    PersonSummary,
)
from scanners.reports import PersonReport, ReportDeps, SearchReport
from tests.conftest import CapturedLines, FaceLab, Vectors

_FIRST_PERSON = 3
_SECOND_PERSON = 12
_FIRST_FACES = 12
_SECOND_FACES = 2
_FIRST_CAMERA_IP = "192.0.2.10"
_FIRST_CAMERA_PORT = 554
_SECOND_CAMERA_IP = "192.0.2.11"
_SECOND_CAMERA_PORT = 80
_FIRST_CAMERA_FRAMES = 4
_SECOND_CAMERA_FRAMES = 2
_CAMERA_ID = 7
_LAB_ADDRESS = "10.0.0.1:554"
_FIRST_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_MIDDLE_MOMENT = datetime(2026, 11, 11, 10, 20, 0, tzinfo=timezone.utc)
_LAST_MOMENT = datetime(2026, 11, 11, 11, 2, 41, tzinfo=timezone.utc)
_FIRST_STAMP = "2026-11-11T09:14:02Z"
_MIDDLE_STAMP = "2026-11-11T10:20:00Z"
_LAST_STAMP = "2026-11-11T11:02:41Z"
_NEAR_DEGREES = 12.0
_SAME_FACE_DEGREES = 5.0
_THREE_FACES = 3

class Stored:
    """The rows a report prints, built the way the reader hands them over."""

    @classmethod
    def first_person(cls) -> PersonSummary:
        """One person over a camera that produced frames both ways."""
        return PersonSummary(
            person_id=_FIRST_PERSON,
            label=None,
            faces=_FIRST_FACES,
            first_seen=_FIRST_MOMENT,
            last_seen=_LAST_MOMENT,
            cameras=(
                PersonCameraFrames(
                    ip=_FIRST_CAMERA_IP,
                    port=_FIRST_CAMERA_PORT,
                    faces=_FIRST_CAMERA_FRAMES,
                    sources=(FrameSource.rtsp, FrameSource.cve),
                ),
            ),
        )

    @classmethod
    def second_person(cls) -> PersonSummary:
        """A second person, seen once, on a shorter address."""
        return PersonSummary(
            person_id=_SECOND_PERSON,
            label=None,
            faces=_SECOND_FACES,
            first_seen=_MIDDLE_MOMENT,
            last_seen=_MIDDLE_MOMENT,
            cameras=(
                PersonCameraFrames(
                    ip=_SECOND_CAMERA_IP,
                    port=_SECOND_CAMERA_PORT,
                    faces=_SECOND_CAMERA_FRAMES,
                    sources=(FrameSource.cve,),
                ),
            ),
        )

    @classmethod
    def first_appearance(cls) -> PersonAppearance:
        return PersonAppearance(
            captured_at=_FIRST_MOMENT,
            person_id=_FIRST_PERSON,
            label=None,
            ip=_FIRST_CAMERA_IP,
            port=_FIRST_CAMERA_PORT,
            source=FrameSource.rtsp,
        )

    @classmethod
    def second_appearance(cls) -> PersonAppearance:
        return PersonAppearance(
            captured_at=_MIDDLE_MOMENT,
            person_id=_SECOND_PERSON,
            label=None,
            ip=_SECOND_CAMERA_IP,
            port=_SECOND_CAMERA_PORT,
            source=FrameSource.cve,
        )

# The counts differ on purpose: the faces column is two wide, so the shorter
# count is padded, and the two addresses differ by one character. The person
# column is padded the same way, because one id is a digit longer than the other.
_EXPECTED_REPORT: tuple[str, ...] = (
    f"person {_FIRST_PERSON}   faces {_FIRST_FACES}  "
    f"first seen {_FIRST_STAMP}  last seen {_LAST_STAMP}",
    f"  camera {_FIRST_CAMERA_IP}:{_FIRST_CAMERA_PORT}  "
    f"frames {_FIRST_CAMERA_FRAMES}  frame rtsp, cve",
    f"person {_SECOND_PERSON}  faces {_SECOND_FACES}   "
    f"first seen {_MIDDLE_STAMP}  last seen {_MIDDLE_STAMP}",
    f"  camera {_SECOND_CAMERA_IP}:{_SECOND_CAMERA_PORT}   "
    f"frames {_SECOND_CAMERA_FRAMES}  frame cve",
)
_EXPECTED_SEARCH: tuple[str, ...] = (
    f"{_FIRST_STAMP}  person {_FIRST_PERSON}   "
    f"camera {_FIRST_CAMERA_IP}:{_FIRST_CAMERA_PORT}  frame rtsp",
    f"{_MIDDLE_STAMP}  person {_SECOND_PERSON}  "
    f"camera {_SECOND_CAMERA_IP}:{_SECOND_CAMERA_PORT}   frame cve",
)


class StubReader:
    """A reader that answers what the test built, and keeps what it was asked."""

    def __init__(
        self,
        summaries: list[PersonSummary],
        appearances: list[PersonAppearance],
    ) -> None:
        self._summaries = summaries
        self._appearances = appearances
        self.asked_persons: list[int | None] = []
        self.asked_filters: list[AppearanceFilters] = []

    def summaries(self, person_id: int | None = None) -> list[PersonSummary]:
        """The people the test built, whatever narrowing was asked for."""
        self.asked_persons.append(person_id)
        return self._summaries

    def appearances(self, filters: AppearanceFilters) -> list[PersonAppearance]:
        """The appearances the test built, whatever narrowing was asked for."""
        self.asked_filters.append(filters)
        return self._appearances


class Seeded:
    """The rows a scan leaves behind, stored through the repositories."""

    @classmethod
    def one_person_in_two_frames(cls, lab: FaceLab) -> int:
        """Three faces of one person, in a frame of each path, and their id."""
        first = lab.frame(_FIRST_MOMENT)
        second = lab.frame(_LAST_MOMENT, FrameSource.cve)
        person = lab.person()
        lab.face(first, Vectors.unit(0.0), person.id)
        lab.face(first, Vectors.unit(_NEAR_DEGREES), person.id)
        lab.face(second, Vectors.unit(_SAME_FACE_DEGREES), person.id)
        return person.id


def test_report_faces_prints_a_block_per_person_with_aligned_columns() -> None:
    lines = CapturedLines()
    reader = StubReader([Stored.first_person(), Stored.second_person()], [])

    PersonReport(ReportDeps(people=reader, lines=lines)).run()

    assert tuple(lines.all()) == _EXPECTED_REPORT


def test_search_prints_one_aligned_line_per_appearance() -> None:
    lines = CapturedLines()
    reader = StubReader([], [Stored.first_appearance(), Stored.second_appearance()])

    SearchReport(ReportDeps(people=reader, lines=lines)).run()

    assert tuple(lines.all()) == _EXPECTED_SEARCH


def test_report_faces_says_so_when_no_person_is_stored() -> None:
    lines = CapturedLines()

    PersonReport(ReportDeps(people=StubReader([], []), lines=lines)).run()

    assert tuple(lines.all()) == ("no person stored",)


def test_search_says_so_when_nothing_appeared() -> None:
    lines = CapturedLines()

    SearchReport(ReportDeps(people=StubReader([], []), lines=lines)).run()

    assert tuple(lines.all()) == ("no appearance stored",)


def test_the_person_filter_reaches_the_reader() -> None:
    reader = StubReader([], [])
    filters = AppearanceFilters(person_id=_FIRST_PERSON)

    PersonReport(ReportDeps(people=reader, lines=CapturedLines(), filters=filters)).run()

    assert reader.asked_persons == [_FIRST_PERSON]


def test_the_search_filters_reach_the_reader() -> None:
    reader = StubReader([], [])
    filters = AppearanceFilters(
        person_id=_FIRST_PERSON,
        camera_id=_CAMERA_ID,
        since=_FIRST_MOMENT,
        until=_LAST_MOMENT,
    )

    SearchReport(ReportDeps(people=reader, lines=CapturedLines(), filters=filters)).run()

    assert reader.asked_filters == [filters]


def test_the_reports_read_the_rows_the_scan_stored(face_lab: FaceLab) -> None:
    """The joins and the aggregation, over the real reader (FR-027, FR-028)."""
    person_id = Seeded.one_person_in_two_frames(face_lab)
    report_lines = CapturedLines()
    search_lines = CapturedLines()

    PersonReport(ReportDeps(PersonReader(face_lab.database), report_lines)).run()
    SearchReport(ReportDeps(PersonReader(face_lab.database), search_lines)).run()

    assert tuple(report_lines.all()) == (
        f"person {person_id}  faces {_THREE_FACES}  "
        f"first seen {_FIRST_STAMP}  last seen {_LAST_STAMP}",
        f"  camera {_LAB_ADDRESS}  frames {_THREE_FACES}  frame rtsp, cve",
    )
    assert tuple(search_lines.all()) == (
        f"{_FIRST_STAMP}  person {person_id}  camera {_LAB_ADDRESS}  frame rtsp",
        f"{_LAST_STAMP}  person {person_id}  camera {_LAB_ADDRESS}  frame cve",
    )
