"""Face detection, embedding, and matching via insightface.

insightface uses a ResNet model (ONNX runtime) for 128-d embeddings and a
RetinaFace model for detection. Models are downloaded on first use and cached
in ~/.insightface/models.
"""

from dataclasses import dataclass

import numpy as np

from scanners.config import FaceConfig, get_config

_DETECTION_SLICE_START: int = 4
_RGB_CHANNEL_REVERSE: tuple[int, int, int] = (2, 1, 0)
_CONFIDENCE_SLICE_INDEX: int = 4
_EMBEDDING_SLICE_START: int = 5
_CONFIDENCE_DISPLAY_CHARS: int = 20
_DETECTION_SIZE: int = 640
_BBOX_Y_INDEX: int = 1
_BBOX_X_INDEX: int = 0
_BBOX_H_INDEX: int = 3
_BBOX_W_INDEX: int = 2


@dataclass(frozen=True)
class DetectedFace:
    """One face found in a frame."""

    bbox: tuple[int, int, int, int]  # (top, left, bottom, right)
    embedding: np.ndarray  # 128-d float32
    confidence: float


@dataclass(frozen=True)
class FaceMatch:
    """A match between a new face and an existing stored embedding."""

    existing_face_id: int
    camera_id: int
    distance: float  # Euclidean distance, lower = more similar
    confidence: str  # from existing face record


@dataclass(frozen=True)
class KnownEmbedding:
    """A stored embedding reference for matching."""

    face_id: int
    camera_id: int
    embedding: list[float]


class FaceRecognizer:
    """Detects faces, computes embeddings, matches against known embeddings."""

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
        rgb_frame = self._to_rgb(frame)
        blocks = detector.get(rgb_frame)
        return self._build_faces(blocks)

    def match_against(
        self,
        new_embedding: np.ndarray,
        known_embeddings: list[KnownEmbedding],
    ) -> list[FaceMatch]:
        """Compare one embedding against stored KnownEmbedding objects."""
        new_vec = new_embedding.reshape(1, -1)
        matches: list[FaceMatch] = []
        for known in known_embeddings:
            match_result = self._match_one(new_vec, known)
            if match_result is not None:
                matches.append(match_result)
        return matches

    def _match_one(
        self,
        new_vec: np.ndarray,
        known: KnownEmbedding,
    ) -> FaceMatch | None:
        known_vec = np.array(known.embedding, dtype=np.float32).reshape(1, -1)
        dist = float(np.linalg.norm(new_vec - known_vec))
        if dist < self.settings.match_threshold:
            return FaceMatch(
                existing_face_id=known.face_id,
                camera_id=known.camera_id,
                distance=dist,
                confidence=self._short_embed(self._embedding_to_str(known_vec)),
            )
        return None

    def _ensure_detection(self) -> object:
        if self._detection is None:
            self._detection = self._init_detector()
        return self._detection

    def _to_rgb(self, frame: np.ndarray) -> np.ndarray:
        return frame[:, :, _RGB_CHANNEL_REVERSE]

    def _build_faces(self, blocks: list[np.ndarray]) -> list[DetectedFace]:
        results: list[DetectedFace] = []
        for block in blocks:
            bbox_raw = block[:_DETECTION_SLICE_START].astype(int)
            confidence = float(block[_CONFIDENCE_SLICE_INDEX])
            embedding = block[_EMBEDDING_SLICE_START:].astype(np.float32)
            results.append(
                DetectedFace(
                    bbox=(
                        int(bbox_raw[_BBOX_Y_INDEX]),
                        int(bbox_raw[_BBOX_X_INDEX]),
                        int(bbox_raw[_BBOX_H_INDEX]),
                        int(bbox_raw[_BBOX_W_INDEX]),
                    ),
                    embedding=embedding,
                    confidence=confidence,
                )
            )
        return results

    def _short_embed(self, embed_str: str) -> str:
        return embed_str[:_CONFIDENCE_DISPLAY_CHARS] + "..."

    def embedding_to_str(self, embedding: np.ndarray) -> str:
        return self._embedding_to_str(embedding)

    def _embedding_to_str(self, embedding: np.ndarray) -> str:
        formatted_values = ",".join(
            f"{component:.6f}" for component in embedding.flatten()
        )
        return formatted_values

    def _init_detector(self) -> object:
        from insightface.app import FaceAnalysis

        app = FaceAnalysis(name="buffalo_l", root=str(self._model_root()))
        app.prepare(ctx_id=0, det_size=(_DETECTION_SIZE, _DETECTION_SIZE))
        return app

    def _model_root(self) -> str:
        import pathlib

        return str(pathlib.Path.home() / ".insightface")
