"""The metric is cosine over the direction, never a distance (D44, T060).

The comparison this replaces treated a longer vector of the same face as a
different person. The first test is the regression: the two vectors it compares
really do differ in length, so a distance metric separates them and the cosine
does not.
"""

from math import cos, radians

import numpy as np
import pytest

from scanners.config import FaceConfig
from scanners.face_recognizer import (
    CosineSimilarity,
    FaceRecognizer,
    KnownEmbedding,
    ZeroEmbeddingError,
)
from tests.conftest import Vectors

_THRESHOLD = 0.5
_ALMOST_ONE = 0.99
# 110 degrees apart is a cosine of -0.342: a different person at this threshold.
_DIFFERENT_DEGREES = 110.0
_CLOSE_DEGREES = 10.0
_FARTHER_DEGREES = 30.0
# The two vectors of the first test: one is the other, scaled up.
_SCALE = 7.5
# A cosine computed from numpy and one from the standard library differ in the
# last bits, so the compared values carry a tolerance.
_TOLERANCE = 1e-6
_CLOSE_FACE_ID = 9
_FARTHER_FACE_ID = 7
_DIFFERENT_FACE_ID = 11
# Three stored faces: the closest, the farther, and one that is a different
# person at this threshold.
_THREE_FACES = (
    (_FARTHER_FACE_ID, _FARTHER_DEGREES),
    (_CLOSE_FACE_ID, _CLOSE_DEGREES),
    (_DIFFERENT_FACE_ID, _DIFFERENT_DEGREES),
)
_ONE_FACE = ((_FARTHER_FACE_ID, _FARTHER_DEGREES),)


class Known:
    """The stored faces a test compares against, built from their angles."""

    @classmethod
    def at(cls, angled: tuple[tuple[int, float], ...]) -> list[KnownEmbedding]:
        """One stored face per (face id, degrees) pair the test named."""
        return [
            KnownEmbedding(face_id=face_id, embedding=Vectors.unit(degrees).tolist())
            for face_id, degrees in angled
        ]


def test_the_same_face_at_another_length_is_the_same_person() -> None:
    """The regression of D44: the direction is the identity, not the length."""
    unit = Vectors.unit(0.0)
    longer = Vectors.scaled(0.0, _SCALE)

    # A distance metric separates these two: they sit 6.5 apart, well past the
    # threshold. The cosine does not, because they point the same way.
    assert float(np.linalg.norm(longer - unit)) > _THRESHOLD
    assert CosineSimilarity.of(unit, longer) == pytest.approx(1.0)


def test_a_vector_with_no_direction_is_refused() -> None:
    """A zero embedding is not a face, so it is refused and not compared."""
    with pytest.raises(ZeroEmbeddingError) as refused:
        CosineSimilarity.of(np.zeros_like(Vectors.unit(0.0)), Vectors.unit(0.0))

    assert str(refused.value) == "a zero embedding has no direction to compare"


def test_the_closest_face_comes_first_and_the_far_ones_are_dropped() -> None:
    """The order decides which person the new face joins (FR-022, FR-023)."""
    recognizer = FaceRecognizer(FaceConfig(match_threshold=_THRESHOLD))

    matches = recognizer.match_against(Vectors.unit(0.0), Known.at(_THREE_FACES))

    assert [match.existing_face_id for match in matches] == [
        _CLOSE_FACE_ID,
        _FARTHER_FACE_ID,
    ]
    assert [match.similarity for match in matches] == pytest.approx(
        [cos(radians(_CLOSE_DEGREES)), cos(radians(_FARTHER_DEGREES))],
        abs=_TOLERANCE,
    )


def test_the_threshold_is_what_drops_a_match() -> None:
    """The same pair is a match at one threshold and not at the other (D16)."""
    known = Known.at(_ONE_FACE)

    at_half = FaceRecognizer(FaceConfig(match_threshold=_THRESHOLD))
    at_almost_one = FaceRecognizer(FaceConfig(match_threshold=_ALMOST_ONE))

    assert len(at_half.match_against(Vectors.unit(0.0), known)) == 1
    assert at_almost_one.match_against(Vectors.unit(0.0), known) == []
