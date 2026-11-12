"""The named person search: register a target, find it, remove it (D47 to D67).

A target is a name and reference photos. The search compares every stored face
against those photos, keeps the best score of each photo set, and stores a hit
for every face above the verification threshold. Nothing here reads a camera:
the live pass belongs to the scan path, and this module only answers from what
the database already holds (D47, D61).
"""

from dataclasses import dataclass, field, replace
from typing import Protocol

import cv2
import numpy as np

from models.managers import (
    AppearanceFilters,
    PersonRepository,
    RankedAppearance,
    RemovedTarget,
    StoredFace,
    TargetHitRepository,
    TargetReader,
    TargetRepository,
)
from models.target import Target
from scanners.face_recognizer import CosineSimilarity, FaceRecognizer
from scanners.frames import FrameStore


class ReferencePhotoError(Exception):
    """A reference photo that cannot name a target, and the reason why."""


class UnknownTargetError(Exception):
    """A target id that names no stored target."""


class ReferencePhotos(Protocol):
    """Reads the embedding a reference photo carries: one face, no more."""

    def embedding(self, path: str) -> list[float]: ...


class ReferencePhotoReader:
    """One reference image in, the embedding of its only face out (R2).

    A photo with no face or with several cannot say which person is the target,
    so it is refused instead of guessed (D57).
    """

    def __init__(self, recognizer: FaceRecognizer) -> None:
        self._recognizer = recognizer

    def embedding(self, path: str) -> list[float]:
        """The vector of the one face the photo holds."""
        faces = self._recognizer.detect(self._read(path))
        if not faces:
            raise ReferencePhotoError(f"no face found in the reference photo: {path}")
        if len(faces) > 1:
            raise ReferencePhotoError(
                f"the reference photo holds {len(faces)} faces and a target needs "
                f"exactly one: {path}"
            )
        return [float(value) for value in faces[0].embedding]

    def _read(self, path: str) -> np.ndarray:
        frame = cv2.imread(path)
        if frame is None:
            raise ReferencePhotoError(f"the reference photo cannot be read: {path}")
        return frame


@dataclass(frozen=True)
class RegistrationDeps:
    """What registering a target needs: the reader, the table, the files."""

    reader: ReferencePhotos
    targets: TargetRepository
    frames: FrameStore


class TargetRegistration:
    """Resolves the target by name and adds its photos (D55, D57)."""

    def __init__(self, deps: RegistrationDeps) -> None:
        self._deps = deps

    def register(self, name: str, images: list[str]) -> Target:
        """Add those photos to the target of that name, created when it is new.

        Every photo is read before anything is written, so a bad one leaves no
        half-registered target behind.
        """
        embeddings = [self._deps.reader.embedding(image) for image in images]
        target = self._deps.targets.resolve(name)
        self._store(target, images, embeddings)
        return target

    def _store(
        self, target: Target, images: list[str], embeddings: list[list[float]]
    ) -> None:
        for image, embedding in zip(images, embeddings):
            path = self._deps.frames.write_reference(image, target.id)
            self._deps.targets.add_photo(target.id, path, embedding)


class TargetComparison:
    """How close one stored face is to the photos of one target (R1)."""

    @classmethod
    def best_of(cls, face: StoredFace, photos: list[list[float]]) -> float:
        """The best score of that face against every photo of the target.

        The best, not the newest: a second photo can only add evidence, so an
        extra photo never lowers a match a first one already proved.
        """
        return max(CosineSimilarity.of(face.embedding, photo) for photo in photos)


@dataclass(frozen=True)
class TargetSearchDeps:
    """What one search reads and writes: the tables, the threshold, the filters."""

    faces: TargetReader
    targets: TargetRepository
    hits: TargetHitRepository
    people: PersonRepository
    threshold: float
    filters: AppearanceFilters = field(default_factory=AppearanceFilters)
    target_id: int | None = None


class TargetSearch:
    """Compares the stored faces against the targets and stores the hits."""

    def __init__(self, deps: TargetSearchDeps) -> None:
        self._deps = deps

    def matches(self) -> list[RankedAppearance]:
        """Every appearance of every target searched, best score first."""
        faces = self._deps.faces.faces(self._deps.filters)
        ranked = [
            found
            for target in self._wanted()
            for found in self._appearances_of(target, faces)
        ]
        return sorted(ranked, key=lambda found: found.score, reverse=True)

    def _wanted(self) -> list[Target]:
        """The target asked for, or every registered one (D65)."""
        if self._deps.target_id is None:
            return self._deps.targets.all()
        found = self._deps.targets.find_by_id(self._deps.target_id)
        if found is None:
            raise UnknownTargetError(f"no target with id {self._deps.target_id}")
        return [found]

    def _appearances_of(
        self, target: Target, faces: list[StoredFace]
    ) -> list[RankedAppearance]:
        """The faces close enough to be that target, stored and named."""
        photos = [
            list(photo.embedding) for photo in self._deps.targets.photos_of(target.id)
        ]
        kept = [
            self._kept(target, face, TargetComparison.best_of(face, photos))
            for face in faces
        ]
        return [found for found in kept if found is not None]

    def _kept(
        self, target: Target, face: StoredFace, score: float
    ) -> RankedAppearance | None:
        """Whether that face is the target, and the hit written when it is.

        # ponytail: linear scan over the stored embeddings, one pass per target
        # photo. A pgvector index is the upgrade path when the table outgrows
        # the lab; the ceiling is recorded rather than paid for now.
        """
        if score < self._deps.threshold:
            return None
        self._deps.hits.record(target.id, face.face_id, score)
        written = self._deps.people.name_if_empty(face.person_id, target.name)
        shown = self._labelled(face, target.name) if written else face
        return self._appearance(target, shown, score)

    @classmethod
    def _labelled(cls, face: StoredFace, name: str) -> StoredFace:
        """The face with the label this run just wrote, so the line shows it now."""
        return replace(face, label=name)

    def _appearance(
        self, target: Target, face: StoredFace, score: float
    ) -> RankedAppearance:
        return RankedAppearance(
            score=score,
            target_id=target.id,
            target_name=target.name,
            person_id=face.person_id,
            label=face.label,
            captured_at=face.captured_at,
            ip=face.ip,
            port=face.port,
            path=face.path,
        )


class TargetSelection:
    """The target one argument names: by name first, by id second (D79).

    A target is named by what the operator remembers, and the name is the
    identity key of the table, so the name wins. A numeric argument is read as
    an id only when no target carries that exact name.
    """

    def __init__(self, targets: TargetRepository) -> None:
        self._targets = targets

    def id_of(self, argument: str) -> int:
        """The id of the target that argument names, refused when none does."""
        wanted = argument.strip()
        named = self._targets.find_by_name(wanted)
        if named is not None:
            return named.id
        numbered = self._numbered(wanted)
        if numbered is not None:
            return numbered
        raise UnknownTargetError(f"no target named or numbered {wanted}")

    def _numbered(self, argument: str) -> int | None:
        """The id a digit only argument carries, when a target holds it."""
        if not argument.isdigit():
            return None
        found = self._targets.find_by_id(int(argument))
        return None if found is None else found.id


@dataclass(frozen=True)
class RemovalDeps:
    """What a removal deletes from: the target table, the files, the labels."""

    targets: TargetRepository
    people: PersonRepository
    frames: FrameStore


class TargetRemoval:
    """Undoes a wrong registration, touching no face and no frame (D54, D64)."""

    def __init__(self, deps: RemovalDeps) -> None:
        self._deps = deps

    def remove(self, target_id: int) -> RemovedTarget:
        """Drop the rows first, then the files, then the label it wrote."""
        removed = self._deps.targets.remove(target_id)
        if removed is None:
            raise UnknownTargetError(f"no target with id {target_id}")
        self._delete_files(removed)
        self._deps.people.release_label(removed.name)
        return removed

    def _delete_files(self, removed: RemovedTarget) -> None:
        """A file already gone is not a failure: the rows are what is left."""
        for path in removed.photos:
            self._deps.frames.remove_reference(path)
