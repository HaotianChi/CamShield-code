"""
Epoch keys and scheduled epoch transitions.

EKe, Kidx^e, and Krid^e are derived per epoch; record keys use
ki = HKDF(EKe, ridi || e) with ridi = H(Krid^e || cid || sidi || e).
Epochs advance on a fixed schedule (default: local hourly boundaries).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime

from core.protocol_defaults import DEFAULT_EPOCH_DURATION_S

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.models import _u64, hash_parts


def epoch_window_start(ts: int, duration_s: int = DEFAULT_EPOCH_DURATION_S) -> int:
    """Start of the local wall-clock window containing ``ts`` (hourly when Δe = 1 h)."""
    duration = max(1, int(duration_s))
    ts = int(ts)
    if duration == 3600:
        dt = datetime.fromtimestamp(ts)
        return int(dt.replace(minute=0, second=0, microsecond=0).timestamp())

    dt = datetime.fromtimestamp(ts)
    midnight = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    midnight_ts = int(midnight.timestamp())
    offset = ts - midnight_ts
    return midnight_ts + (offset // duration) * duration


def epoch_window_end(ts: int, duration_s: int = DEFAULT_EPOCH_DURATION_S) -> int:
    """End of the local wall-clock window containing ``ts``."""
    return epoch_window_start(ts, duration_s) + max(1, int(duration_s))


def kdf(key: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 key derivation (default 32-byte output)."""
    if not key:
        raise ValueError("KDF key must not be empty")
    if length <= 0 or length > 64:
        raise ValueError("length must be in range 1..64")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"CamShield.kdf.v1",
        info=info,
    ).derive(key)


def derive_record_key(EKe: bytes, rid: bytes, epoch: int) -> bytes:
    """ki = KDF(EKe, ridi || e)."""
    return kdf(
        EKe,
        b"record-key|" + rid + b"|" + str(epoch).encode("utf-8"),
        length=32,
    )


def derive_index_key(Kidx_master: bytes, epoch: int) -> bytes:
    """Kidx^e = KDF(Kidx, e)."""
    return kdf(
        Kidx_master,
        b"index-key|" + str(epoch).encode("utf-8"),
        length=32,
    )


def derive_rid_key(Krid_master: bytes, epoch: int) -> bytes:
    """Krid^e = KDF(Krid, e)."""
    return kdf(
        Krid_master,
        b"rid-key|" + str(epoch).encode("utf-8"),
        length=32,
    )


def derive_record_id(Krid_e: bytes, cid: str, sid: str, epoch: int) -> bytes:
    """ridi = H(Krid^e || cid || sidi || e)."""
    return hash_parts(
        b"CamShield.record-id.v1",
        Krid_e,
        cid.encode("utf-8"),
        sid.encode("utf-8"),
        _u64(epoch),
    )


def build_abe_policy(
    role: str,
    purpose: str,
    mode: str,
    scope: str,
) -> str:
    """CP-ABE access-class policy (epoch and version are not embedded)."""
    return (
        f"(ROLE_{role} and PURPOSE_{purpose} and MODE_{mode} "
        f"and SCOPE_{scope})"
    )


def build_policy(
    role: str,
    purpose: str,
    mode: str,
    scope: str,
    epoch: int | None = None,
    version: int | None = None,
) -> str:
    """Alias for build_abe_policy."""
    _ = epoch
    _ = version
    return build_abe_policy(role, purpose, mode, scope)


@dataclass
class EpochState:
    epoch: int
    version: int
    EKe: bytes


@dataclass
class EpochManager:
    """Epoch counter, version, and per-epoch key material."""

    epoch: int = 1
    version: int = 1
    epoch_duration_s: int = DEFAULT_EPOCH_DURATION_S
    epoch_started_at: int = field(default_factory=lambda: epoch_window_start(int(time.time())))
    Kidx_master: bytes = field(default_factory=lambda: os.urandom(32))
    Krid_master: bytes = field(default_factory=lambda: os.urandom(32))
    _epoch_keys: dict[int, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.epoch not in self._epoch_keys:
            self._epoch_keys[self.epoch] = os.urandom(32)
        self.epoch_started_at = epoch_window_start(
            int(self.epoch_started_at),
            self.epoch_duration_s,
        )

    def _duration_s(self) -> int:
        return max(1, int(self.epoch_duration_s))

    def _normalize_window_anchor(self) -> None:
        self.epoch_started_at = epoch_window_start(
            int(self.epoch_started_at),
            self.epoch_duration_s,
        )

    def current_epoch(self) -> int:
        return self.epoch

    def current_version(self) -> int:
        return self.version

    def epoch_key(self, epoch: int | None = None) -> bytes:
        e = self.epoch if epoch is None else epoch
        if e not in self._epoch_keys:
            raise KeyError(f"No epoch key for epoch {e}")
        return self._epoch_keys[e]

    def index_key(self, epoch: int | None = None) -> bytes:
        e = self.epoch if epoch is None else epoch
        return derive_index_key(self.Kidx_master, e)

    def rid_key(self, epoch: int | None = None) -> bytes:
        e = self.epoch if epoch is None else epoch
        return derive_rid_key(self.Krid_master, e)

    def record_id(self, cid: str, sid: str, epoch: int | None = None) -> bytes:
        e = self.epoch if epoch is None else epoch
        return derive_record_id(self.rid_key(e), cid, sid, e)

    def record_key(self, rid: bytes, epoch: int | None = None) -> bytes:
        e = self.epoch if epoch is None else epoch
        return derive_record_key(self.epoch_key(e), rid, e)

    def current_state(self) -> EpochState:
        return EpochState(
            epoch=self.epoch,
            version=self.version,
            EKe=self.epoch_key(self.epoch),
        )

    def epoch_ends_at(self) -> int:
        return int(self.epoch_started_at) + self._duration_s()

    def seconds_until_rotation(self, now: int | None = None) -> int:
        now = int(time.time()) if now is None else int(now)
        return max(0, self.epoch_ends_at() - now)

    def rotate_epoch(self, *, manual: bool = False, now: int | None = None) -> EpochState:
        """Advance epoch and version; derive fresh EKe for the new epoch."""
        now_ts = int(time.time()) if now is None else int(now)
        duration = self._duration_s()
        self.epoch += 1
        self.version += 1
        self._epoch_keys[self.epoch] = os.urandom(32)
        if manual:
            self.epoch_started_at = epoch_window_start(now_ts, duration)
        else:
            self.epoch_started_at = int(self.epoch_started_at) + duration
            if duration == 3600:
                self.epoch_started_at = epoch_window_start(
                    self.epoch_started_at,
                    duration,
                )
        return self.current_state()

    def maybe_rotate_epoch(self, now: int | None = None) -> list[EpochState]:
        """Apply every scheduled transition that is due at ``now``."""
        now_ts = int(time.time()) if now is None else int(now)
        self._normalize_window_anchor()
        duration = self._duration_s()
        states: list[EpochState] = []
        while now_ts >= int(self.epoch_started_at) + duration:
            states.append(self.rotate_epoch(manual=False, now=now_ts))
        return states
