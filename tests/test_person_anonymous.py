"""How a person is named in a report: by id, and by the label when one was set.

Nothing in this batch labels a person automatically (D28), so a person the
clustering opened prints as `person <id>`. A label set on the row by hand is
data the reports carry, so both of them print it beside the id.
"""

from datetime import datetime, timezone

from models.managers import PersonReader
from scanners.reports import PersonReport, ReportDeps, SearchReport
from tests.conftest import CapturedLines, FaceLab, Vectors

_LABEL = "henry"
_FIRST_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_LAB_ADDRESS = "10.0.0.1:554"
_ONE_FACE = 1


class Seeded:
    """One person, labelled or not, with one face the scan stored."""

    @classmethod
    def person(cls, lab: FaceLab, label: str | None) -> int:
        """Store a person and one face of theirs, and hand back the id."""
        frame = lab.frame(_FIRST_MOMENT)
        person = lab.person(label)
        lab.face(frame, Vectors.unit(0.0), person.id)
        return person.id

    @classmethod
    def rendered(cls, lab: FaceLab) -> tuple[CapturedLines, CapturedLines]:
        """Both read-only reports over that lab, as the lines they wrote."""
        report_lines = CapturedLines()
        search_lines = CapturedLines()
        reader = PersonReader(lab.database)
        PersonReport(ReportDeps(reader, report_lines)).run()
        SearchReport(ReportDeps(reader, search_lines)).run()
        return report_lines, search_lines


def test_a_person_with_no_label_is_printed_by_id(face_lab: FaceLab) -> None:
    """The person the clustering opened has no name to print (D28)."""
    person_id = Seeded.person(face_lab, None)
    report_lines, search_lines = Seeded.rendered(face_lab)

    assert report_lines.all()[0].startswith(
        f"person {person_id}  faces {_ONE_FACE}  first seen "
    )
    assert search_lines.all()[0].endswith(
        f"person {person_id}  camera {_LAB_ADDRESS}  frame rtsp"
    )


def test_a_labelled_person_is_printed_with_the_label(face_lab: FaceLab) -> None:
    """A label set by hand on the row is read back by both reports."""
    person_id = Seeded.person(face_lab, _LABEL)
    report_lines, search_lines = Seeded.rendered(face_lab)

    assert f"person {person_id} ({_LABEL})" in report_lines.all()[0]
    assert f"person {person_id} ({_LABEL})" in search_lines.all()[0]


def test_the_label_stays_on_the_row(face_lab: FaceLab) -> None:
    """A manual label is data this batch keeps, and now data it prints."""
    person_id = Seeded.person(face_lab, _LABEL)

    assert [(one.id, one.label) for one in face_lab.people()] == [(person_id, _LABEL)]
