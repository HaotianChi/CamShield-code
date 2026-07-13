"""
Wire serialization for distributed CamShield deployment.

This file serializes and deserializes objects for HTTP transport.
It does not perform cryptographic computation.
"""

from __future__ import annotations

import base64
from typing import Any

from core.models import CameraSignedSegment


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def camera_segment_to_json(segment: CameraSignedSegment) -> dict[str, Any]:
    return {
        "cid": segment.cid,
        "sid": segment.sid,
        "seq": segment.seq,
        "timestamp": segment.timestamp,
        "raw_payload_b64": b64e(segment.raw_payload),
        "hi_b64": b64e(segment.hi),
        "gamma_prev_b64": b64e(segment.gamma_prev),
        "gamma_b64": b64e(segment.gamma),
        "sigma_c_b64": b64e(segment.sigma_c),
    }


def camera_segment_from_json(obj: dict[str, Any]) -> CameraSignedSegment:
    return CameraSignedSegment(
        cid=obj["cid"],
        sid=obj["sid"],
        seq=int(obj["seq"]),
        timestamp=int(obj["timestamp"]),
        raw_payload=b64d(obj["raw_payload_b64"]),
        hi=b64d(obj["hi_b64"]),
        gamma_prev=b64d(obj["gamma_prev_b64"]),
        gamma=b64d(obj["gamma_b64"]),
        sigma_c=b64d(obj["sigma_c_b64"]),
    )
