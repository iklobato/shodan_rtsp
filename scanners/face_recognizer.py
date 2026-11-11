"""Face detection, embedding, matching, and the threshold measurement.

insightface runs a RetinaFace detector and a ResNet recognition model (ONNX
runtime), both downloaded on first use and cached in `~/.insightface/models`.

The recognition model emits 512 values. The comparison is cosine similarity over
the L2-normalized vector, and the raw vector is what gets stored, so a later
change of metric stays recomputable from the original measurement (D44).

The same metric measures the threshold: `ThresholdMeasurement` scores the pairs
of a labelled pair set and hands back the lines to print, and the operator writes
the value it reports into the config by hand (D16).
"""

from dataclasses import dataclass
from itertools import combinations
from operator import attrgetter
from pathlib import Path
from statistics import fmean

import cv2
import numpy as np

from scanners.config import FaceConfig, get_config

# insightface hands back a box as x1, y1, x2, y2 and the stored box is top,
# left, bottom, right, so the four indices are named rather than written bare.
_X1: int = 0
_Y1: int = 1
_X2: int = 2
_Y2: int = 3

_RGB_CHANNEL_REVERSE: tuple[int, int, int] = (2, 1, 0)
_DETECTION_SIZE: int = 640
_IMAGE_SUFFIXES: tuple[str, ...] = (".jpg", ".jpeg", ".png", ".bmp")
_ONE_FACE: int = 1
_PAIR_SIZE: int = 2
_MIN_IMAGES_PER_IDENTITY: int = 2
_MIN_IDENTITIES: int = 2
_LABEL_WIDTH: int = 20
_COUNT_WIDTH: int = 3
_DECIMALS: int = 3


class PairSetError(Exception):
    """The labelled pair set cannot be measured, and the reason is the message."""


class ZeroEmbeddingError(Exception):
    """A vector of no length has no direction, so it is not a face to compare."""


@dataclass(frozen=True)
class DetectedFace:
    """One face found in a frame: where it is, and the vector that names it."""

    bbox: tuple[int, int, int, int]  # (top, left, bottom, right)
    embedding: np.ndarray  # 512-d float32, as the model emitted it
    confidence: float


@dataclass(frozen=True)
class FaceMatch:
    """A stored face the new one is the same person as.

    Only the face id: the person is resolved by the clustering, from the rows as
    they are inside its own transaction, so a merge cannot leave a stale person
    id in the list this match came from.
    """

    existing_face_id: int
    similarity: float  # cosine, higher = more alike


@dataclass(frozen=True)
class KnownEmbedding:
    """A stored embedding, ready to be compared."""

    face_id: int
    embedding: list[float]


@dataclass(frozen=True)
class IdentityImages:
    """One identity of a pair set: its name, and the images that carry it."""

    name: str
    paths: tuple[str, ...]


class CosineSimilarity:
    """The one metric of this project: direction, never magnitude (D44)."""

    @classmethod
    def normalized(cls, embedding: np.ndarray) -> np.ndarray:
        """The unit vector of the same direction.

        A zero vector has no direction to compare, so it is refused here rather
        than compared as if it were a face.
        """
        vector = np.asarray(embedding, dtype=np.float32).reshape(-1)
        length = float(np.linalg.norm(vector))
        if length == 0.0:
            raise ZeroEmbeddingError("a zero embedding has no direction to compare")
        return vector / length

    @classmethod
    def of(cls, one: np.ndarray, other: np.ndarray) -> float:
        """How alike two embeddings are, from -1 to 1."""
        return float(np.dot(cls.normalized(one), cls.normalized(other)))


class FaceRecognizer:
    """Detects faces, reads their embeddings, matches against known ones."""

    def __init__(
        self,
        config: FaceConfig | None = None,
        detection_provider: object | None = None,
    ) -> None:
        self._s = config
        self._detection = detection_provider

    @property
    def settings(self) -> FaceConfig:
        if self._s is None:
            self._s = get_config().face
        return self._s

    def detect(self, frame: np.ndarray) -> list[DetectedFace]:
        """Detect faces in a BGR numpy array (OpenCV frame)."""
        detector = self._ensure_detection()
        return self._build_faces(detector.get(self._to_rgb(frame)))

    def match_against(
        self,
        new_embedding: np.ndarray,
        known_embeddings: list[KnownEmbedding],
    ) -> list[FaceMatch]:
        """The stored faces the new one is the same person as, best match first.

        The order matters to the caller: the best match decides which person the
        new face joins when the matches name more than one (FR-022, FR-023).
        """
        new_vector = CosineSimilarity.normalized(new_embedding)
        found = (self._match_one(new_vector, known) for known in known_embeddings)
        matches = [match for match in found if match is not None]
        return sorted(matches, key=attrgetter("similarity"), reverse=True)

    def _match_one(
        self,
        new_vector: np.ndarray,
        known: KnownEmbedding,
    ) -> FaceMatch | None:
        known_vector = CosineSimilarity.normalized(known.embedding)
        similarity = float(np.dot(new_vector, known_vector))
        if similarity < self.settings.match_threshold:
            return None
        return FaceMatch(existing_face_id=known.face_id, similarity=similarity)

    def _ensure_detection(self) -> object:
        if self._detection is None:
            self._detection = self._init_detector()
        return self._detection

    def _to_rgb(self, frame: np.ndarray) -> np.ndarray:
        return frame[:, :, _RGB_CHANNEL_REVERSE]

    def _build_faces(self, detected: list[object]) -> list[DetectedFace]:
        return [self._one_face(face) for face in detected]

    def _one_face(self, face: object) -> DetectedFace:
        """One insightface Face: its box, its raw vector and its detect score."""
        box = np.asarray(face.bbox).astype(int)
        return DetectedFace(
            bbox=(int(box[_Y1]), int(box[_X1]), int(box[_Y2]), int(box[_X2])),
            embedding=np.asarray(face.embedding, dtype=np.float32),
            confidence=float(face.det_score),
        )

    def _init_detector(self) -> object:
        from insightface.app import FaceAnalysis

        app = FaceAnalysis(name="buffalo_l", root=str(self._model_root()))
        app.prepare(ctx_id=0, det_size=(_DETECTION_SIZE, _DETECTION_SIZE))
        return app

    def _model_root(self) -> str:
        return str(Path.home() / ".insightface")


class PairSet:
    """A labelled pair set on disk: one directory per identity (D16).

    Every pair inside one directory is a same identity pair, and every pair
    across two directories is a different identity pair, which is what makes the
    threshold measurable without a second source of labels.
    """

    def __init__(self, root: str) -> None:
        self._root = root

    def identities(self) -> list[IdentityImages]:
        """Every identity, or the reason the set cannot be measured."""
        found = [self._identity(path) for path in self._directories()]
        if len(found) < _MIN_IDENTITIES:
            raise PairSetError(
                f"the pair set {self._root} holds {len(found)} identity(ies); "
                f"measuring a separation needs {_MIN_IDENTITIES}"
            )
        return found

    def _directories(self) -> list[Path]:
        root = Path(self._root)
        if not root.is_dir():
            raise PairSetError(f"the pair set {self._root} is not a directory")
        return sorted(path for path in root.iterdir() if path.is_dir())

    def _identity(self, directory: Path) -> IdentityImages:
        images = sorted(
            str(path)
            for path in directory.iterdir()
            if path.suffix.lower() in _IMAGE_SUFFIXES
        )
        if len(images) < _MIN_IMAGES_PER_IDENTITY:
            raise PairSetError(
                f"identity {directory.name} holds {len(images)} image(s), and one "
                f"image cannot form a pair: it needs {_MIN_IMAGES_PER_IDENTITY}"
            )
        return IdentityImages(name=directory.name, paths=tuple(images))


class ThresholdMeasurement:
    """Scores the pairs of a labelled set and reports the separation (D16).

    It reads and returns lines, and never writes the config: a value that
    changes itself is not a measured value, so the operator writes the number by
    hand.
    """

    def __init__(self, recognizer: FaceRecognizer, pair_set: PairSet) -> None:
        self._recognizer = recognizer
        self._pair_set = pair_set

    def report(self) -> list[str]:
        """The two groups and the separation between them, as lines to print."""
        vectors = [self._vectors(identity) for identity in self._pair_set.identities()]
        same = self._pairs_within(vectors)
        different = self._pairs_across(vectors)
        return [
            self._group_line("same identity", same),
            self._group_line("different identity", different),
            self._separation_line(same, different),
        ]

    def _vectors(self, identity: IdentityImages) -> list[np.ndarray]:
        return [self._vector(path) for path in identity.paths]

    def _vector(self, path: str) -> np.ndarray:
        """The one face of a labelled image, or the reason it cannot be used."""
        image = cv2.imread(path)
        if image is None:
            raise PairSetError(f"{path} is not an image this build can read")
        faces = self._recognizer.detect(image)
        if len(faces) != _ONE_FACE:
            raise PairSetError(
                f"{path} holds {len(faces)} faces, and a labelled image holds "
                f"exactly {_ONE_FACE}: a second face makes the label ambiguous"
            )
        return faces[0].embedding

    def _pairs_within(self, vectors: list[list[np.ndarray]]) -> list[float]:
        """Every pair of images of the same identity."""
        return [
            CosineSimilarity.of(one, other)
            for group in vectors
            for one, other in combinations(group, _PAIR_SIZE)
        ]

    def _pairs_across(self, vectors: list[list[np.ndarray]]) -> list[float]:
        """Every pair of images of two different identities."""
        identities = combinations(range(len(vectors)), _PAIR_SIZE)
        return [
            CosineSimilarity.of(one, other)
            for left, right in identities
            for one in vectors[left]
            for other in vectors[right]
        ]

    def _group_line(self, label: str, values: list[float]) -> str:
        return (
            f"{label:<{_LABEL_WIDTH}} pairs {len(values):<{_COUNT_WIDTH}} "
            f"min {min(values):.{_DECIMALS}f}  "
            f"mean {fmean(values):.{_DECIMALS}f}  "
            f"max {max(values):.{_DECIMALS}f}"
        )

    def _separation_line(self, same: list[float], different: list[float]) -> str:
        return (
            f"{'separation':<{_LABEL_WIDTH}} "
            f"{min(same) - max(different):.{_DECIMALS}f} between the largest "
            "different and the smallest same"
        )
