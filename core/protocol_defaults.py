"""Default timing parameters for CamShield."""

from __future__ import annotations

DEFAULT_SEGMENT_DURATION_S = 5.0
DEFAULT_EPOCH_DURATION_S = 3600
DEFAULT_CAPTURE_FPS = 10


def default_aus_per_segment(fps: int = DEFAULT_CAPTURE_FPS) -> int:
    """Access units per segment at the given capture rate."""
    if fps <= 0:
        raise ValueError("fps must be positive")
    return max(1, int(round(DEFAULT_SEGMENT_DURATION_S * fps)))


def segment_duration_s(*, aus_per_segment: int, fps: int) -> float:
    """Segment duration from AU grouping parameters."""
    if fps <= 0:
        raise ValueError("fps must be positive")
    return float(aus_per_segment) / float(fps)
