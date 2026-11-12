"""The target search ranks the stored faces and stores one hit per face.

The rows are seeded through the same repositories the face scan uses, so the
joins, the filtering and the comparison are the code under test. The threshold
decides what is a hit, and a repeated run may not grow the table (D50, D53).
"""

from datetime import datetime, timezone

import pytest

from models.managers import (
    AppearanceFilters,
    PersonRepository,
    TargetHitRepository,
    TargetReader,
    TargetRepository,
)
from scanners.target_search import TargetSearch, TargetSearchDeps, UnknownTargetError
from tests.conftest import FaceLab, MemoryDatabase, Vectors

_NAME = "maria"
_OTHER_NAME = "joao"
_THRESHOLD = 0.5
_FIRST_MOMENT = datetime(2026, 11, 11, 9, 14, 2, tzinfo=timezone.utc)
_SECOND_MOMENT = datetime(2026, 11, 11, 10, 20, 0, tzinfo=timezone.utc)
_SAME_DEGREES = 0.0
_NEAR_DEGREES = 20.0
_FAR_DEGREES = 120.0
_ONE_HIT = 1
_TWO_HITS = 2
_UNKNOWN_ID = 99


class SearchLab:
    """The seeded rows of one search, and the search over them."""

    def __init__(self, database: MemoryDatabase, face_lab: FaceLab) -> None:
        self.database = database
        self.faces_lab = face_lab

    def target(self, name: str, photos: list[float]) -> int:
        """A target registered with the embeddings this test chose."""
        targets = TargetRepository(self.database)
        target = targets.resolve(name)
        for index, degrees in enumerate(photos):
            targets.add_photo(
                target.id, f"{name}-{index}.jpg", Vectors.unit(degrees).tolist()
            )
        return target.id

    def person_with_face(self, degrees: float, moment: datetime) -> int:
        """One person with one stored face of that angle, in one camera."""
        person = self.faces_lab.person()
        frame_id = self.faces_lab.frame(moment)
        self.faces_lab.face(frame_id, Vectors.unit(degrees), person.id)
        return person.id

    def search(
        self,
        target_id: int | None = None,
        filters: AppearanceFilters | None = None,
    ) -> TargetSearch:
        """The search over the rows seeded so far, at the test threshold."""
        return TargetSearch(
            TargetSearchDeps(
                faces=TargetReader(self.database),
                targets=TargetRepository(self.database),
                hits=TargetHitRepository(self.database),
                people=PersonRepository(self.database),
                threshold=_THRESHOLD,
                filters=filters or AppearanceFilters(),
                target_id=target_id,
            )
        )

    def hits(self) -> int:
        return TargetHitRepository(self.database).count()


@pytest.fixture
def search_lab(database: MemoryDatabase, face_lab: FaceLab) -> SearchLab:
    return SearchLab(database, face_lab)


def test_the_ranking_is_best_score_first(search_lab: SearchLab) -> None:
    """Two faces of the target: the closer one is printed first."""
    target_id = search_lab.target(_NAME, [_SAME_DEGREES])
    search_lab.person_with_face(_NEAR_DEGREES, _FIRST_MOMENT)
    search_lab.person_with_face(_SAME_DEGREES, _SECOND_MOMENT)

    ranked = search_lab.search(target_id=target_id).matches()

    assert len(ranked) == _TWO_HITS
    # The later moment is the identical face, so it scores higher and comes first.
    assert ranked[0].captured_at > ranked[1].captured_at
    assert ranked[0].score > ranked[1].score
    assert ranked[0].target_name == _NAME


def test_a_face_under_the_threshold_is_not_a_hit(search_lab: SearchLab) -> None:
    """The search answers nothing and stores nothing for a face that far off."""
    target_id = search_lab.target(_NAME, [_SAME_DEGREES])
    search_lab.person_with_face(_FAR_DEGREES, _FIRST_MOMENT)

    ranked = search_lab.search(target_id=target_id).matches()

    assert ranked == []
    assert search_lab.hits() == 0


def test_a_repeated_search_keeps_the_hit_count(search_lab: SearchLab) -> None:
    """D53: one row per target and face, however many times it is found."""
    target_id = search_lab.target(_NAME, [_SAME_DEGREES])
    search_lab.person_with_face(_NEAR_DEGREES, _FIRST_MOMENT)

    search_lab.search(target_id=target_id).matches()
    search_lab.search(target_id=target_id).matches()

    assert search_lab.hits() == _ONE_HIT


def test_the_best_of_several_photos_is_the_score_used(
    search_lab: SearchLab,
) -> None:
    """A second, worse photo cannot lower what a first one already proved."""
    target_id = search_lab.target(_NAME, [_FAR_DEGREES, _SAME_DEGREES])
    search_lab.person_with_face(_NEAR_DEGREES, _FIRST_MOMENT)

    ranked = search_lab.search(target_id=target_id).matches()

    assert len(ranked) == _ONE_HIT
    assert ranked[0].score > _THRESHOLD


def test_every_target_is_searched_when_no_target_is_named(
    search_lab: SearchLab,
) -> None:
    search_lab.target(_NAME, [_SAME_DEGREES])
    search_lab.target(_OTHER_NAME, [_NEAR_DEGREES])
    search_lab.person_with_face(_NEAR_DEGREES, _FIRST_MOMENT)

    ranked = search_lab.search().matches()

    assert {found.target_name for found in ranked} == {_NAME, _OTHER_NAME}
    assert search_lab.hits() == _TWO_HITS


def test_the_camera_filter_narrows_the_search(search_lab: SearchLab) -> None:
    """D65: the narrowing is the same one the appearance search takes."""
    target_id = search_lab.target(_NAME, [_SAME_DEGREES])
    search_lab.person_with_face(_SAME_DEGREES, _FIRST_MOMENT)

    ranked = search_lab.search(
        target_id=target_id, filters=AppearanceFilters(camera_id=_UNKNOWN_ID)
    ).matches()

    assert ranked == []
    assert search_lab.hits() == 0


def test_an_unknown_target_id_is_refused(search_lab: SearchLab) -> None:
    with pytest.raises(UnknownTargetError):
        search_lab.search(target_id=_UNKNOWN_ID).matches()
