"""`target list` prints one line per target with its photos and its hits (D80).

The counts come from one grouped query per table, so the test seeds two targets
with different amounts and checks that neither count leaks into the other.
"""

import pytest

from datetime import datetime, timezone

from models.managers import TargetHitRepository, TargetListReader, TargetRepository
from models.target import Target
from scanners.reports import TargetListingReport
from tests.conftest import CapturedLines, FaceLab, MemoryDatabase, Vectors

_NAME = "maria"
_OTHER_NAME = "joao"
_MOMENT = datetime(2026, 11, 12, 8, 30, 0, tzinfo=timezone.utc)
_SAME_DEGREES = 0.0
_SCORE = 0.9
_NO_TARGET = "no target registered"
_TWO_PHOTOS = 2
_THREE_HITS = 3
_ONE_PHOTO = 1
_NO_HIT = 0
_ONE_TARGET = 1


class ListingLab:
    """The targets and the hits a list run reads, and the lines it writes."""

    def __init__(self, database: MemoryDatabase, face_lab: FaceLab) -> None:
        self.database = database
        self.faces_lab = face_lab

    def target(self, name: str, photos: int = 0, hits: int = 0) -> int:
        """One target holding that many reference photos and that many hits."""
        targets = TargetRepository(self.database)
        target = targets.resolve(name)
        self._photos(targets, target, photos)
        self._hits(target.id, hits)
        return target.id

    def lines(self) -> list[str]:
        """What `target list` puts on stdout, run the way the CLI runs it."""
        writer = CapturedLines()
        TargetListingReport(TargetListReader(self.database), writer).run()
        return writer.all()

    def _photos(self, targets: TargetRepository, target: Target, count: int) -> None:
        """One row per photo: the path is unique across the whole table."""
        for index in range(count):
            targets.add_photo(
                target.id,
                f"targets/{target.id}/{target.name}-{index}.jpg",
                Vectors.unit(_SAME_DEGREES).tolist(),
            )

    def _hits(self, target_id: int, count: int) -> None:
        """One stored face per hit: a hit is one face of one target, never two."""
        if not count:
            return
        frame_id = self.faces_lab.frame(_MOMENT)
        for index in range(count):
            embedding = Vectors.unit(_SAME_DEGREES + index)
            face_id = self.faces_lab.face(frame_id, embedding)
            TargetHitRepository(self.database).record(target_id, face_id, _SCORE)


@pytest.fixture
def listing_lab(database: MemoryDatabase, face_lab: FaceLab) -> ListingLab:
    return ListingLab(database, face_lab)


def test_each_target_shows_its_own_photos_and_hits(listing_lab: ListingLab) -> None:
    listing_lab.target(_NAME, photos=_TWO_PHOTOS, hits=_THREE_HITS)
    listing_lab.target(_OTHER_NAME, photos=_ONE_PHOTO, hits=_NO_HIT)

    assert listing_lab.lines() == [
        f"target {_ONE_TARGET}  {_NAME}  "
        f"{_TWO_PHOTOS} reference photos  {_THREE_HITS} hits",
        f"target {_ONE_TARGET + 1}  {_OTHER_NAME}  "
        f"{_ONE_PHOTO} reference photos  {_NO_HIT} hits",
    ]


def test_a_target_with_nothing_stored_shows_zeros(listing_lab: ListingLab) -> None:
    listing_lab.target(_NAME)

    assert listing_lab.lines() == [
        f"target {_ONE_TARGET}  {_NAME}  {_NO_HIT} reference photos  {_NO_HIT} hits"
    ]


def test_no_target_registered_says_so(listing_lab: ListingLab) -> None:
    assert listing_lab.lines() == [_NO_TARGET]
