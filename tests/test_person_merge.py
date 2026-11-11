"""The clustering of one face: open a person, join one, or merge two (FR-022, FR-023).

Nothing here is deleted: a merge moves faces and drops the loser row, so the
faces and the frames of both people survive it (D10, D35).
"""

from datetime import datetime, timezone

from models.frame import FrameSource
from models.managers import PersonRepository
from tests.conftest import FaceLab, Vectors

_FIRST_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_SECOND_MOMENT = datetime(2026, 11, 11, 11, 2, 41, tzinfo=timezone.utc)
_SAME_FACE_DEGREES = 5.0
_NEAR_DEGREES = 12.0
_ONE_PERSON = 1
_TWO_FACES = 2
_TWO_FRAMES = 2
_THREE_FACES = 3


class Seeded:
    """Two people who turn out to be one, and the face that says so."""

    @classmethod
    def two_people_sharing_a_face(cls, lab: FaceLab) -> tuple[int, int, list[int]]:
        """Store both people in their own frame, plus a face matching both.

        The ids come back in the order they were created, and the matched faces
        in the order a merge would receive them: the younger person first.
        """
        first = lab.frame(_FIRST_MOMENT)
        second = lab.frame(_SECOND_MOMENT, FrameSource.cve)
        older = lab.person()
        younger = lab.person()
        in_older = lab.face(first, Vectors.unit(0.0), older.id)
        in_younger = lab.face(second, Vectors.unit(_SAME_FACE_DEGREES), younger.id)
        newcomer = lab.face(second, Vectors.unit(_NEAR_DEGREES))
        return older.id, younger.id, [in_younger, in_older, newcomer]


def test_a_face_that_matches_nothing_opens_a_person(face_lab: FaceLab) -> None:
    """FR-022: no match is a new person, and the face points at it."""
    frame = face_lab.frame(_FIRST_MOMENT)
    only = face_lab.face(frame, Vectors.unit(0.0))

    person = PersonRepository(database=face_lab.database).person_for([only])

    assert [one.id for one in face_lab.people()] == [person.id]
    assert face_lab.faces()[0].person_id == person.id


def test_a_face_that_matches_a_person_joins_it_without_a_new_person(
    face_lab: FaceLab,
) -> None:
    """A matched face is adopted by the person it matched, not a second row."""
    frame = face_lab.frame(_FIRST_MOMENT)
    known = face_lab.person()
    stored = face_lab.face(frame, Vectors.unit(0.0), known.id)
    newcomer = face_lab.face(frame, Vectors.unit(_SAME_FACE_DEGREES))

    person = PersonRepository(database=face_lab.database).person_for(
        [newcomer, stored]
    )

    assert person.id == known.id
    assert len(face_lab.people()) == _ONE_PERSON
    assert [face.person_id for face in face_lab.faces()] == [known.id] * _TWO_FACES


def test_a_face_that_matches_two_people_merges_them_and_the_older_wins(
    face_lab: FaceLab,
) -> None:
    """FR-023, D35: the loser is listed first and still loses, and nothing is lost."""
    older, younger, matched = Seeded.two_people_sharing_a_face(face_lab)

    person = PersonRepository(database=face_lab.database).person_for(matched)

    assert older < younger
    assert person.id == older
    assert [one.id for one in face_lab.people()] == [older]
    assert [face.person_id for face in face_lab.faces()] == [older] * _THREE_FACES
    assert len(face_lab.frames()) == _TWO_FRAMES
