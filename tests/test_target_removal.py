"""Removing a target deletes the target, its photos, its hits, and its label.

Nothing else goes: the faces, the frames and the people stay, and a label an
operator typed under another name survives too (D54, D64). A photo already gone
from the disk is not a failure, because the rows are what a removal is about.
"""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from models.managers import (
    PersonRepository,
    TargetHitRepository,
    TargetRepository,
)
from scanners.frames import FrameStore
from scanners.target_search import RemovalDeps, TargetRemoval, UnknownTargetError
from tests.conftest import FaceLab, MemoryDatabase, Vectors

_NAME = "maria"
_OTHER_NAME = "joao"
_MANUAL_LABEL = "vizinha do 302"
_PHOTO = "targets/1/reference.jpg"
_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_SAME_DEGREES = 0.0
_TARGET_ID = 1
_ONE_PHOTO = 1
_TWO_HITS = 2
_UNKNOWN_ID = 99
_NO_ROWS = 0


class RemovalLab:
    """A stored target with a photo, a hit, and a label it wrote."""

    def __init__(self, database: MemoryDatabase, face_lab: FaceLab, root: Path) -> None:
        self.database = database
        self.faces_lab = face_lab
        self.root = root

    def target(self, label_owner: str | None = None) -> int:
        """One target, one photo on the disk, and two people that matched it."""
        targets = TargetRepository(self.database)
        target = targets.resolve(_NAME)
        photo = self.photo()
        targets.add_photo(target.id, photo, Vectors.unit(_SAME_DEGREES).tolist())
        self._person_with_hit(target.id, label_owner)
        return target.id

    def photo(self) -> str:
        path = self.root / _PHOTO
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"reference")
        return _PHOTO

    def removal(self) -> TargetRemoval:
        return TargetRemoval(
            RemovalDeps(
                targets=TargetRepository(self.database),
                people=PersonRepository(self.database),
                frames=FrameStore(str(self.root)),
            )
        )

    def photo_still_there(self) -> bool:
        return (self.root / _PHOTO).is_file()

    def targets(self) -> int:
        return len(TargetRepository(self.database).all())

    def hits(self) -> int:
        return TargetHitRepository(self.database).count()

    def labels(self) -> list[str | None]:
        return [person.label for person in self.faces_lab.people()]

    def _person_with_hit(self, target_id: int, label_owner: str | None) -> None:
        person = self.faces_lab.person(label_owner)
        frame_id = self.faces_lab.frame(_MOMENT)
        face_id = self.faces_lab.face(frame_id, Vectors.unit(_SAME_DEGREES), person.id)
        TargetHitRepository(self.database).record(target_id, face_id, _SAME_DEGREES)


@pytest.fixture
def removal_lab(
    database: MemoryDatabase, face_lab: FaceLab, tmp_path: Path
) -> RemovalLab:
    return RemovalLab(database, face_lab, tmp_path / "frames")


def test_removal_drops_the_target_its_photo_and_its_hit(removal_lab: RemovalLab) -> None:
    target_id = removal_lab.target()

    removed = removal_lab.removal().remove(target_id)

    assert removed.name == _NAME
    assert len(removed.photos) == _ONE_PHOTO
    assert removal_lab.targets() == _NO_ROWS
    assert removal_lab.hits() == _NO_ROWS
    assert not removal_lab.photo_still_there()


def test_removal_clears_the_label_it_wrote(removal_lab: RemovalLab) -> None:
    target_id = removal_lab.target()

    removal_lab.removal().remove(target_id)

    assert removal_lab.labels() == [None]


def test_removal_keeps_a_label_typed_by_hand(removal_lab: RemovalLab) -> None:
    """D64: only the label equal to the target name goes, nothing else."""
    target_id = removal_lab.target(label_owner=_MANUAL_LABEL)

    removal_lab.removal().remove(target_id)

    assert removal_lab.labels() == [_MANUAL_LABEL]


def test_removal_keeps_the_faces_and_the_frames(removal_lab: RemovalLab) -> None:
    target_id = removal_lab.target()

    removal_lab.removal().remove(target_id)

    assert len(removal_lab.faces_lab.faces()) == 1
    assert len(removal_lab.faces_lab.people()) == 1


def test_removal_finishes_when_the_photo_is_already_gone(
    removal_lab: RemovalLab,
) -> None:
    target_id = removal_lab.target()
    (removal_lab.root / _PHOTO).unlink()

    removed = removal_lab.removal().remove(target_id)

    assert len(removed.photos) == _ONE_PHOTO
    assert removal_lab.targets() == _NO_ROWS


def test_removing_an_unknown_target_is_refused(removal_lab: RemovalLab) -> None:
    with pytest.raises(UnknownTargetError):
        removal_lab.removal().remove(_UNKNOWN_ID)


def test_two_hits_of_one_target_are_both_counted(removal_lab: RemovalLab) -> None:
    target_id = removal_lab.target()
    second = removal_lab.faces_lab.person()
    frame_id = removal_lab.faces_lab.frame(_MOMENT)
    face_id = removal_lab.faces_lab.face(frame_id, Vectors.unit(_SAME_DEGREES), second.id)
    TargetHitRepository(removal_lab.database).record(target_id, face_id, _SAME_DEGREES)

    removed = removal_lab.removal().remove(target_id)

    assert removed.hits == _TWO_HITS
