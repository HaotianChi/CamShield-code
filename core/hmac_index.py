"""
Epoch-specific HMAC encrypted index utilities for CamShield.

Index token logic:
    Kidx^e = KDF(Kidx, e)
    τe_cid,w = HMAC_{Kidx^e}("CamShield.index.token.v2" || cid || w)
    qi     = H(Sort(Ti^e))
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Iterable


def normalize_keyword(keyword: str) -> str:
    return keyword.strip().lower()


def normalize_camera_id(camera_id: str) -> str:
    if camera_id is None:
        raise ValueError("camera_id must not be None")
    cid = str(camera_id).strip().lower()
    if not cid:
        raise ValueError("camera_id must not be empty")
    return cid


def make_index_token(kidx_e: bytes, keyword: str, camera_id: str | None = None) -> bytes:
    if not kidx_e:
        raise ValueError("kidx_e must not be empty")
    if camera_id is None:
        raise ValueError("camera_id is required for camera-scoped retrieval tokens")

    cid = normalize_camera_id(camera_id).encode("utf-8")
    w = normalize_keyword(keyword).encode("utf-8")

    return hmac.new(
        kidx_e,
        b"CamShield.index.token.v2|" + cid + b"|" + w,
        hashlib.sha256,
    ).digest()


def make_index_tokens(
    kidx_e: bytes,
    keywords: Iterable[str],
    camera_id: str | None = None,
) -> list[bytes]:
    if camera_id is None:
        raise ValueError("camera_id is required for make_index_tokens()")
    tokens = {make_index_token(kidx_e, kw, camera_id=camera_id) for kw in keywords}
    return sorted(tokens)


def index_digest(tokens: Iterable[bytes]) -> bytes:
    sorted_tokens = sorted(tokens)

    h = hashlib.sha256()
    domain = b"CamShield.index.digest.v1"
    h.update(len(domain).to_bytes(8, "big"))
    h.update(domain)

    for token in sorted_tokens:
        h.update(len(token).to_bytes(8, "big"))
        h.update(token)

    return h.digest()


def keyword_set_for_record(
    cid: str,
    sid: str,
    seq: int,
    extra_keywords: Iterable[str] | None = None,
) -> list[str]:
    keywords = [
        f"camera:{cid}",
        f"segment:{sid}",
        f"seq:{seq}",
    ]
    if extra_keywords:
        keywords.extend(extra_keywords)
    return [normalize_keyword(k) for k in keywords]


def tokens_for_record(
    kidx_e: bytes,
    cid: str,
    sid: str,
    seq: int,
    extra_keywords: Iterable[str] | None = None,
) -> list[bytes]:
    keywords = keyword_set_for_record(
        cid=cid,
        sid=sid,
        seq=seq,
        extra_keywords=extra_keywords,
    )
    return make_index_tokens(kidx_e, keywords, camera_id=cid)


def token_hex(token: bytes) -> str:
    return token.hex()


def tokens_hex(tokens: Iterable[bytes]) -> list[str]:
    return [t.hex() for t in tokens]
