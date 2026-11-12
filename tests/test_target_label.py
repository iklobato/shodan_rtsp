"""Only an empty label takes the target name; a hand-typed one always wins.

D63 breaks the rule of D28 in exactly one place, so these tests pin down where
that place stops: a label already on the row is never overwritten, a second
target matching the same person does not rename it, and both hits are kept.
"""

import pytest

from datetime import datetime, timezone

from models.managers import (
    AppearanceFilters,
    PersonRepository,
    TargetHitRepository,
    TargetReader,
    TargetRepository,
)
from scanners.target_search import TargetSearch, TargetSearchDeps
from tests.conftest import FaceLab, MemoryDatabase, Vectors

_NAME = "maria"
_OTHER_NAME = "joao"
_MANUAL_LABEL = "vizinha do 302"
_THRESHOLD = 0.5
_SAME_DEGREES = 0.0
_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_ONE_HIT = 1
_TWO_HITS = 2


class LabelLab:
    """The rows of one label run, and the search that writes the label."""

    def __init__(self, database: MemoryDatabase, face_lab: FaceLab) -> None:
        self.database = database
        self.faces_lab = face_lab

    def target(self, name: str) -> int:
        targets = TargetRepository(self.database)
        target = targets.resolve(name)
        targets.add_photo(target.id, f"{name}.jpg", Vectors.unit(_SAME_DEGREES).tolist())
        return target.id

    def person_with_face(self, label: str | None) -> int:
        person = self.faces_lab.person(label)
        frame_id = self.faces_lab.frame(_MOMENT)
        self.faces_lab.face(frame_id, Vectors.unit(_SAME_DEGREES), person.id)
        return person.id

    def search(self) -> TargetSearch:
        return TargetSearch(
            TargetSearchDeps(
                faces=TargetReader(self.database),
                targets=TargetRepository(self.database),
                hits=TargetHitRepository(self.database),
                people=PersonRepository(self.database),
                threshold=_THRESHOLD,
                filters=AppearanceFilters(),
            )
        )

    def label_of(self, person_id: int) -> str | None:
        return next(one.label for one in self.faces_lab.people() if one.id == person_id)

    def hits(self) -> int:
        return TargetHitRepository(self.database).count()


@pytest.fixture
def label_lab(database: MemoryDatabase, face_lab: FaceLab) -> LabelLab:
    return LabelLab(database, face_lab)


def test_an_empty_label_takes_the_target_name(label_lab: LabelLab) -> None:
    label_lab.target(_NAME)
    person_id = label_lab.person_with_face(None)

    label_lab.search().matches()

    assert label_lab.label_of(person_id) == _NAME


def test_the_name_written_shows_in_the_same_run(label_lab: LabelLab) -> None:
    """The label is read again after the write, so the first run already shows it."""
    label_lab.target(_NAME)
    label_lab.person_with_face(None)

    ranked = label_lab.search().matches()

    assert ranked[0].label == _NAME


def test_a_hand_typed_label_is_not_overwritten(label_lab: LabelLab) -> None:
    """D63: the label an operator typed is the one the row keeps."""
    label_lab.target(_NAME)
    person_id = label_lab.person_with_face(_MANUAL_LABEL)

    label_lab.search().matches()

    assert label_lab.label_of(person_id) == _MANUAL_LABEL
    assert label_lab.hits() == _ONE_HIT


def test_a_second_target_leaves_the_first_name_and_keeps_both_hits(
    label_lab: LabelLab,
) -> None:
    label_lab.target(_NAME)
    label_lab.target(_OTHER_NAME)
    person_id = label_lab.person_with_face(None)

    label_lab.search().matches()

    assert label_lab.label_of(person_id) == _NAME
    assert label_lab.hits() == _TWO_HITS
