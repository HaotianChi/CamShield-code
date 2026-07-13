"""
AES-GCM utilities for CamShield.

Encryption logic:
    ci = AE.Enc_ki(mi, aadi)

where:
    ki   = KDF(EKe, ridi || e)
    aadi = (ridi, cid, sidi, seqi, ti, e, γi)

Important:
- This file no longer generates a per-record random CEK.
- ABE/ABKEM encapsulates the epoch key EKe, not a per-record CEK.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class GCMResult:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def _lp(data: bytes) -> bytes:
    """
    Length-prefix encoding to avoid ambiguous concatenation.
    """
    return len(data).to_bytes(8, "big") + data


def generate_nonce() -> bytes:
    """
    AES-GCM standard nonce length: 96 bits = 12 bytes.
    """
    return os.urandom(12)


def build_associated_data(
    rid: bytes,
    cid: str,
    sid: str,
    seq: int,
    timestamp: int,
    epoch: int,
    gamma: bytes,
) -> bytes:
    """
    aadi = (ridi, cid, sidi, seqi, ti, e, γi)

    This binds the ciphertext to:
    - record id ridi
    - camera id cid
    - segment id sidi
    - sequence number seqi
    - timestamp ti
    - epoch e
    - camera hash-chain state γi
    """
    return b"".join(
        [
            _lp(b"CamShield.aad.v1"),
            _lp(rid),
            _lp(cid.encode("utf-8")),
            _lp(sid.encode("utf-8")),
            _lp(seq.to_bytes(8, "big")),
            _lp(timestamp.to_bytes(8, "big")),
            _lp(epoch.to_bytes(8, "big")),
            _lp(gamma),
        ]
    )


def encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes,
    nonce: bytes | None = None,
) -> GCMResult:
    """
    Encrypt plaintext using AES-GCM.

    key is ki, derived from EKe and ridi:
        ki = KDF(EKe, ridi || e)
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 16, 24, or 32 bytes")

    if nonce is None:
        nonce = generate_nonce()

    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")

    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    return GCMResult(
        nonce=nonce,
        ciphertext=ct_with_tag[:-16],
        tag=ct_with_tag[-16:],
    )


def decrypt(
    key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    tag: bytes,
    associated_data: bytes,
) -> bytes:
    """
    Decrypt AES-GCM ciphertext.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 16, 24, or 32 bytes")

    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)