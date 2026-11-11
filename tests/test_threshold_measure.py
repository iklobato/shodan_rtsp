"""`measure threshold` scores a labelled pair set, and writes nothing (D16).

The numbers are the ones the metric produces: the same identity pairs of the set
below are 20 degrees apart, and the different identity pairs are 90, 110 and 130
degrees apart, so the expected lines are arithmetic, not a recording.
"""

from pathlib import Path

import cv2
import numpy as np
import pytest

from scanners.config import FaceConfig
from scanners.face_recognizer import (
    FaceRecognizer,
    PairSet,
    PairSetError,
    ThresholdMeasurement,
)
from scanners.reports import ThresholdReport
from tests.conftest import CapturedLines, FakeDetector, FakeFace, Vectors

_THRESHOLD = 0.5
_FIRST_IDENTITY = "person_a"
_SECOND_IDENTITY = "person_b"
_IDENTITIES: tuple[str, ...] = (_FIRST_IDENTITY, _SECOND_IDENTITY)
_FIRST_IMAGE = "01.jpg"
_SECOND_IMAGE = "02.jpg"
_MISSING = "no-such-directory"
_PIXELS: tuple[int, int, int] = (8, 8, 3)
_FIRST_DEGREES = 0.0
_SAME_DEGREES = 20.0
_SECOND_IDENTITY_DEGREES = 110.0
_FAR_DEGREES = 130.0
_TWO_IMAGES = 2
_ONE_IMAGE = 1
_ONE_IDENTITY = 1
_TWO_FACES = 2

_EXPECTED: tuple[str, ...] = (
    "same identity        pairs 2   min 0.940  mean 0.940  max 0.940",
    "different identity   pairs 4   min -0.643  mean -0.332  max 0.000",
    "separation           0.940 between the largest different and the smallest same",
)


class PairSetOnDisk:
    """A labelled pair set in a temporary directory: one directory per identity."""

    @classmethod
    def written(
        cls,
        root: Path,
        identities: tuple[str, ...] = _IDENTITIES,
        images: int = _TWO_IMAGES,
    ) -> Path:
        """Write that many images for each identity, and hand the root back."""
        for identity in identities:
            directory = root / identity
            directory.mkdir(parents=True, exist_ok=True)
            cls._images(directory, images)
        return root

    @classmethod
    def _images(cls, directory: Path, images: int) -> None:
        """The images of one identity, named in the order the measurement reads."""
        names = (_FIRST_IMAGE, _SECOND_IMAGE)[:images]
        for name in names:
            cv2.imwrite(str(directory / name), np.zeros(_PIXELS, dtype=np.uint8))


class Detector:
    """The faces the recognizer hands back, one per labelled image, in order."""

    @classmethod
    def recognizer(cls) -> FaceRecognizer:
        """A recognizer over the four images, as the set is read."""
        return FaceRecognizer(FaceConfig(match_threshold=_THRESHOLD), cls._faces())

    @classmethod
    def with_two_faces_in_the_first_image(cls) -> FaceRecognizer:
        """The same set, with a second face in the first image of the first identity."""
        return FaceRecognizer(
            FaceConfig(match_threshold=_THRESHOLD),
            FakeDetector(
                [
                    [FakeFace.of(Vectors.unit(_FIRST_DEGREES))] * _TWO_FACES,
                    [FakeFace.of(Vectors.unit(_SAME_DEGREES))],
                    [FakeFace.of(Vectors.unit(_SECOND_IDENTITY_DEGREES))],
                    [FakeFace.of(Vectors.unit(_FAR_DEGREES))],
                ]
            ),
        )

    @classmethod
    def _faces(cls) -> FakeDetector:
        return FakeDetector(
            [
                [FakeFace.of(Vectors.unit(_FIRST_DEGREES))],
                [FakeFace.of(Vectors.unit(_SAME_DEGREES))],
                [FakeFace.of(Vectors.unit(_SECOND_IDENTITY_DEGREES))],
                [FakeFace.of(Vectors.unit(_FAR_DEGREES))],
            ]
        )


def test_the_two_groups_and_the_separation_are_printed(tmp_path: Path) -> None:
    root = PairSetOnDisk.written(tmp_path)
    lines = CapturedLines()
    measurement = ThresholdMeasurement(Detector.recognizer(), PairSet(str(root)))

    ThresholdReport(measurement, lines).run()

    assert tuple(lines.all()) == _EXPECTED


def test_an_identity_with_one_image_is_refused(tmp_path: Path) -> None:
    """One image cannot form a pair, so the set is refused before any score."""
    root = PairSetOnDisk.written(tmp_path, images=_ONE_IMAGE)

    with pytest.raises(PairSetError) as refused:
        PairSet(str(root)).identities()

    assert str(refused.value) == (
        f"identity {_FIRST_IDENTITY} holds {_ONE_IMAGE} image(s), and one image "
        f"cannot form a pair: it needs {_TWO_IMAGES}"
    )


def test_one_identity_cannot_measure_a_separation(tmp_path: Path) -> None:
    root = PairSetOnDisk.written(tmp_path, identities=(_FIRST_IDENTITY,))

    with pytest.raises(PairSetError) as refused:
        PairSet(str(root)).identities()

    assert str(refused.value) == (
        f"the pair set {root} holds {_ONE_IDENTITY} identity(ies); "
        f"measuring a separation needs {_TWO_IMAGES}"
    )


def test_a_root_that_is_not_a_directory_is_refused(tmp_path: Path) -> None:
    missing = tmp_path / _MISSING

    with pytest.raises(PairSetError) as refused:
        PairSet(str(missing)).identities()

    assert str(refused.value) == f"the pair set {missing} is not a directory"


def test_a_labelled_image_holding_two_faces_is_refused(tmp_path: Path) -> None:
    """A second face in a labelled image makes the label ambiguous."""
    root = PairSetOnDisk.written(tmp_path)
    measurement = ThresholdMeasurement(
        Detector.with_two_faces_in_the_first_image(), PairSet(str(root))
    )

    with pytest.raises(PairSetError) as refused:
        measurement.report()

    assert str(refused.value).startswith(
        f"{root / _FIRST_IDENTITY / _FIRST_IMAGE} holds {_TWO_FACES} faces"
    )
