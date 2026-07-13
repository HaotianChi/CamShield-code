"""
SHA-256 hash helpers.

segment_hash uses a chained structure bound to key metadata; prev_segment_hash
prevents reordering or deletion of segments.
"""
from __future__ import annotations

import hashlib
from typing import Iterable


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def concat_sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def sha256_joined(parts: Iterable[bytes], sep: bytes = b"") -> bytes:
    return sha256(sep.join(parts))


def canonical_tag_list(tags: list[str]) -> bytes:
    return ",".join(sorted(tags)).encode("utf-8")


def segment_metadata_bytes(
    segment_id: str,
    camera_id: str,
    location: str,
    seq_no: int,
    timestamp_start: int,
    timestamp_end: int,
    event_tags: list[str],
    object_tags: list[str],
) -> bytes:
    """Canonical metadata encoding reused by segment_hash and verification."""
    return b"|".join(
        [
            segment_id.encode(),
            camera_id.encode(),
            location.encode(),
            str(seq_no).encode(),
            str(timestamp_start).encode(),
            str(timestamp_end).encode(),
            canonical_tag_list(event_tags),
            canonical_tag_list(object_tags),
        ]
    )


def segment_hash(
    segment_id: str,
    camera_id: str,
    location: str,
    seq_no: int,
    timestamp_start: int,
    timestamp_end: int,
    event_tags: list[str],
    object_tags: list[str],
    payload_hash: bytes,
    prev_segment_hash: bytes,
) -> bytes:
    """SHA256(metadata || payload_hash || prev_segment_hash)."""
    return concat_sha256(
        segment_metadata_bytes(
            segment_id,
            camera_id,
            location,
            seq_no,
            timestamp_start,
            timestamp_end,
            event_tags,
            object_tags,
        ),
        payload_hash,
        prev_segment_hash,
    )


def payload_hash_of(raw_payload: bytes) -> bytes:
    return sha256(raw_payload)
