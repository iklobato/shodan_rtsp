"""A reference photo registers a target, and a bad photo registers nothing.

The photo is read for real (a jpg on disk) and detected through a fake detector,
so the branch under test is the one that decides whether a photo can name a
target: exactly one face, a file that exists, and a name that adds to the target
that is already there instead of creating a second one (D55, D57).
"""

from pathlib import Path

import cv2
import numpy as np
import pytest

from models.managers import TargetRepository
from models.target import Target
from scanners.config import FaceConfig
from scanners.face_recognizer import FaceRecognizer
from scanners.frames import FrameStore
from scanners.target_search import (
    ReferencePhotoError,
    ReferencePhotoReader,
    RegistrationDeps,
    TargetRegistration,
)
from tests.conftest import FakeDetector, FakeFace, MemoryDatabase, Vectors

_NAME = "maria"
_PHOTO = "reference.jpg"
_SECOND_PHOTO = "reference-2.jpg"
_ONE_TARGET = 1
_TWO_PHOTOS = 2
_PIXELS = 8
_CHANNELS = 3
# One registration may read more than one photo, so the detector holds that many.
_READS = 2
_SECOND_FACE_DEGREES = 30.0


class PhotoLab:
    """A registration over an empty database, one frame root and one photo."""

    def __init__(self, database: MemoryDatabase, root: Path) -> None:
        self.database = database
        self.root = root

    def registration(self, faces: list[FakeFace]) -> TargetRegistration:
        """The registration, with the faces this test's photos carry."""
        recognizer = FaceRecognizer(FaceConfig(), FakeDetector([faces] * _READS))
        return TargetRegistration(
            RegistrationDeps(
                reader=ReferencePhotoReader(recognizer),
                targets=TargetRepository(self.database),
                frames=FrameStore(str(self.root)),
            )
        )

    def photo(self, name: str = _PHOTO) -> str:
        """A real jpg on disk, which is what the reader opens."""
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        written = np.zeros((_PIXELS, _PIXELS, _CHANNELS), dtype=np.uint8)
        cv2.imwrite(str(path), written)
        return str(path)

    def targets(self) -> list[Target]:
        return TargetRepository(self.database).all()

    def photos(self, target_id: int) -> list[str]:
        return [photo.path for photo in TargetRepository(self.database).photos_of(target_id)]


@pytest.fixture
def photo_lab(database: MemoryDatabase, tmp_path: Path) -> PhotoLab:
    return PhotoLab(database, tmp_path / "frames")


def test_one_face_registers_the_target_and_keeps_the_photo(
    photo_lab: PhotoLab,
) -> None:
    """The photo is copied under the root, and the row points at the copy."""
    registration = photo_lab.registration([FakeFace.of(Vectors.unit(0.0))])

    target = registration.register(_NAME, [photo_lab.photo()])

    assert [found.name for found in photo_lab.targets()] == [_NAME]
    stored = photo_lab.photos(target.id)
    assert len(stored) == 1
    assert (photo_lab.root / stored[0]).is_file()


def test_a_photo_with_no_face_creates_no_target(photo_lab: PhotoLab) -> None:
    registration = photo_lab.registration([])

    with pytest.raises(ReferencePhotoError):
        registration.register(_NAME, [photo_lab.photo()])

    assert photo_lab.targets() == []


def test_a_photo_with_two_faces_is_refused(photo_lab: PhotoLab) -> None:
    """Two faces cannot say which person is the target, so neither is chosen."""
    registration = photo_lab.registration(
        [FakeFace.of(Vectors.unit(0.0)), FakeFace.of(Vectors.unit(_SECOND_FACE_DEGREES))]
    )

    with pytest.raises(ReferencePhotoError):
        registration.register(_NAME, [photo_lab.photo()])

    assert photo_lab.targets() == []


def test_a_photo_that_does_not_exist_is_refused(photo_lab: PhotoLab) -> None:
    registration = photo_lab.registration([FakeFace.of(Vectors.unit(0.0))])

    with pytest.raises(ReferencePhotoError):
        registration.register(_NAME, [str(photo_lab.root / _PHOTO)])

    assert photo_lab.targets() == []


def test_the_same_name_adds_a_photo_instead_of_a_second_target(
    photo_lab: PhotoLab,
) -> None:
    """D55: the name is the identity, so a second run accumulates photos."""
    registration = photo_lab.registration([FakeFace.of(Vectors.unit(0.0))])
    first = registration.register(_NAME, [photo_lab.photo(_PHOTO)])

    second = registration.register(_NAME, [photo_lab.photo(_SECOND_PHOTO)])

    assert len(photo_lab.targets()) == _ONE_TARGET
    assert second.id == first.id
    assert len(photo_lab.photos(first.id)) == _TWO_PHOTOS


def test_a_second_bad_photo_does_not_half_register_the_first(
    photo_lab: PhotoLab,
) -> None:
    """Every photo is read before anything is written, so nothing survives."""
    registration = photo_lab.registration(
        [FakeFace.of(Vectors.unit(0.0)), FakeFace.of(Vectors.unit(0.0))]
    )

    with pytest.raises(ReferencePhotoError):
        registration.register(_NAME, [photo_lab.photo(_PHOTO), photo_lab.photo(_SECOND_PHOTO)])

    assert photo_lab.targets() == []
