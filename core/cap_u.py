"""
Client capability bundle Cap_u.

Cred_u = (SK_u, Cap_u);  Cap_u = (Lease_u, RetrScope_u, IdxCap_u).
"""

from __future__ import annotations

import re
import time
from typing import Any

from core.protocol_defaults import DEFAULT_EPOCH_DURATION_S

# Default lease spans ~30 days of hourly epochs without re-contacting Gateway.
DEFAULT_LEASE_TTL_SECONDS = 30 * 24 * 3600

ABE_ATTR_RE = re.compile(r"\b(?:ROLE|PURPOSE|MODE|SCOPE)_[A-Za-z0-9_:-]+\b")


def abe_access_attrs(
    *,
    role: str,
    purpose: str,
    mode: str,
    scope: str,
) -> list[str]:
    return [
        f"ROLE_{role}".upper(),
        f"PURPOSE_{purpose}".upper(),
        f"MODE_{mode}".upper(),
        f"SCOPE_{scope}".upper(),
    ]


def abe_client_attrs(
    *,
    role: str,
    purpose: str,
    mode: str,
    scope: str,
    epoch: int | None = None,
    version: int | None = None,
) -> list[str]:
    """Stable SK_u attributes (access class only). epoch/version args ignored."""
    _ = epoch
    _ = version
    return abe_access_attrs(role=role, purpose=purpose, mode=mode, scope=scope)


def parse_abe_attrs_from_policy(policy: str) -> list[str]:
    """Extract access-class CP-ABE attributes from a policy string."""
    return sorted({t.strip().upper() for t in ABE_ATTR_RE.findall(policy or "")})


def default_lease_epoch_max(
    current_epoch: int,
    ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
) -> int:
    span = max(1, int(ttl_seconds) // max(1, DEFAULT_EPOCH_DURATION_S))
    return int(current_epoch) + span


def default_lease_version_max(current_version: int, *, span: int = 10_000) -> int:
    """Wide ceiling so routine epoch rotation does not force SK_u re-issuance."""
    return int(current_version) + int(span)


def _match_tag_pattern(pattern: str, keyword: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return keyword.startswith(pattern[:-1])
    return keyword == pattern


def cap_lease(cap: dict[str, Any] | None) -> dict[str, Any]:
    if not cap:
        return {}
    lease = cap.get("Lease_u")
    if isinstance(lease, dict):
        return lease
    return {
        "epoch_min": cap.get("epoch_min", 1),
        "epoch_max": cap.get("epoch_max", cap.get("epoch_min", 1)),
        "version_min": cap.get("version_min", 1),
        "version_max": cap.get("version_max", cap.get("version_min", 1)),
        "expires_at": cap.get("expires_at", 0),
        "granted_at": cap.get("granted_at", 0),
        "granted_epoch": cap.get("granted_epoch"),
        "granted_version": cap.get("granted_version"),
    }


def cap_retr_scope(cap: dict[str, Any] | None) -> dict[str, Any]:
    if not cap:
        return {}
    scope = cap.get("RetrScope_u")
    if isinstance(scope, dict):
        return scope
    camera_id = str(cap.get("camera_id", "")).strip()
    return {
        "cameras": [camera_id] if camera_id else [],
        "tag_patterns": cap.get("tag_patterns", []),
        "modes": cap.get("modes", ["READ"]),
    }


def grant_cap_u(
    *,
    client_id: str,
    camera_id: str,
    abe_attrs: list[str],
    current_epoch: int,
    current_version: int,
    epoch_min: int = 1,
    epoch_max: int | None = None,
    version_min: int = 1,
    version_max: int | None = None,
    expires_at: int = 0,
    ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    tag_patterns: list[str] | None = None,
    modes: list[str] | None = None,
    idx_cap_u: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    if epoch_max is None:
        epoch_max = default_lease_epoch_max(current_epoch, ttl_seconds)
    if version_max is None:
        version_max = default_lease_version_max(current_version)
    if expires_at <= 0 and ttl_seconds > 0:
        expires_at = now + ttl_seconds

    if tag_patterns is None:
        tag_patterns = [
            f"camera:{camera_id}",
            "event:*",
            "location:*",
            "object:*",
        ]

    lease_u = {
        "epoch_min": int(epoch_min),
        "epoch_max": int(epoch_max),
        "version_min": int(version_min),
        "version_max": int(version_max),
        "expires_at": int(expires_at),
        "granted_at": now,
        "granted_epoch": int(current_epoch),
        "granted_version": int(current_version),
    }

    retr_scope_u = {
        "cameras": [str(camera_id)],
        "tag_patterns": list(tag_patterns),
        "modes": list(modes or ["READ"]),
    }

    return {
        "type": "Cap_u",
        "status": "active",
        "client_id": client_id,
        "Lease_u": lease_u,
        "RetrScope_u": retr_scope_u,
        "IdxCap_u": idx_cap_u,
        "abe_attrs": sorted({a.strip().upper() for a in abe_attrs}),
    }


def cap_u_is_active(cap: dict[str, Any] | None) -> bool:
    if not cap:
        return False
    return str(cap.get("status", "")).lower() == "active"


def validate_retr_scope_u(
    cap: dict[str, Any] | None,
    *,
    camera_id: str,
    keywords: list[str],
) -> tuple[bool, str]:
    scope = cap_retr_scope(cap)
    cameras = [str(c) for c in scope.get("cameras", [])]
    if cameras and camera_id not in cameras:
        return False, f"camera {camera_id} outside RetrScope_u cameras {cameras}"

    patterns = scope.get("tag_patterns") or []
    if patterns:
        denied = [
            kw for kw in keywords
            if not any(_match_tag_pattern(p, kw) for p in patterns)
        ]
        if denied:
            return False, f"keywords outside RetrScope_u: {denied}"

    return True, "ok"


def validate_cap_u_for_search(
    cap: dict[str, Any] | None,
    *,
    client_id: str,
    camera_id: str,
    epoch: int,
    gateway_version: int,
    keywords: list[str] | None = None,
    now: int | None = None,
) -> tuple[bool, str]:
    if not cap_u_is_active(cap):
        return False, "missing or inactive Cap_u lease"

    if cap.get("client_id") != client_id:
        return False, "Cap_u client_id mismatch"

    lease = cap_lease(cap)
    e_min = int(lease.get("epoch_min", 1))
    e_max = int(lease.get("epoch_max", e_min))
    if epoch < e_min or epoch > e_max:
        return False, f"epoch {epoch} outside Lease_u window [{e_min}, {e_max}]"

    v_min = int(lease.get("version_min", 1))
    v_max = int(lease.get("version_max", gateway_version))
    if gateway_version < v_min:
        return False, f"gateway version {gateway_version} below Lease_u version_min {v_min}"
    if gateway_version > v_max:
        return False, (
            f"gateway version {gateway_version} exceeds Lease_u version_max {v_max}; "
            "occasional lease renewal required"
        )

    expires_at = int(lease.get("expires_at", 0))
    if expires_at > 0:
        ts = int(time.time()) if now is None else now
        if ts > expires_at:
            return False, "Lease_u expired"

    if keywords is not None:
        ok_scope, msg_scope = validate_retr_scope_u(
            cap, camera_id=camera_id, keywords=keywords
        )
        if not ok_scope:
            return False, msg_scope

    return True, "ok"


def validate_cap_u_for_bootstrap(cap: dict[str, Any] | None) -> tuple[bool, str]:
    if not cap_u_is_active(cap):
        return False, "missing or inactive Cap_u lease"

    lease = cap_lease(cap)
    expires_at = int(lease.get("expires_at", 0))
    if expires_at > 0 and int(time.time()) > expires_at:
        return False, "Lease_u expired"

    if not cap.get("abe_attrs"):
        return False, "Cap_u missing abe_attrs"

    return True, "ok"


def extend_cap_u(
    cap: dict[str, Any],
    *,
    epoch_max: int | None = None,
    version_max: int | None = None,
    expires_at: int | None = None,
    abe_attrs: list[str] | None = None,
) -> dict[str, Any]:
    updated = dict(cap)
    lease = dict(cap_lease(cap))
    if epoch_max is not None:
        lease["epoch_max"] = int(epoch_max)
    if version_max is not None:
        lease["version_max"] = int(version_max)
    if expires_at is not None:
        lease["expires_at"] = int(expires_at)
    lease["refreshed_at"] = int(time.time())
    updated["Lease_u"] = lease
    updated["status"] = "active"
    if abe_attrs is not None:
        updated["abe_attrs"] = sorted({a.strip().upper() for a in abe_attrs})
    return updated


def cred_u_bundle(*, cap_u: dict[str, Any], sk_u: Any = None) -> dict[str, Any]:
    out: dict[str, Any] = {"Cap_u": cap_u}
    if sk_u is not None:
        out["SK_u"] = sk_u
    return out
