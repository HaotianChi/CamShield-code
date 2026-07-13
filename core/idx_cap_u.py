"""
IdxCap_u: offline index capability bundled in Cap_u.

Clients derive epoch-specific search tokens locally from IdxCap_u.
"""

from __future__ import annotations

from typing import Any

from core import hmac_index
from core.cap_u import cap_lease, validate_cap_u_for_search, validate_retr_scope_u
from core.epoch import derive_index_key


def build_idx_cap_u(
    *,
    kidx_master: bytes,
    epoch_min: int,
    epoch_max: int,
    cameras: list[str],
) -> dict[str, Any]:
    e_min = int(epoch_min)
    e_max = int(epoch_max)
    if e_max < e_min:
        raise ValueError("epoch_max must be >= epoch_min")

    kidx_by_epoch = {
        str(e): derive_index_key(kidx_master, e).hex()
        for e in range(e_min, e_max + 1)
    }

    return {
        "type": "IdxCap_u",
        "mode": "leased-offline",
        "cameras": [str(c) for c in cameras],
        "epoch_min": e_min,
        "epoch_max": e_max,
        "kidx_by_epoch": kidx_by_epoch,
    }


def attach_idx_cap_u(
    cap_u: dict[str, Any],
    *,
    kidx_master: bytes,
    cameras: list[str] | None = None,
) -> dict[str, Any]:
    """Return Cap_u with IdxCap_u populated from Lease_u epoch window."""
    lease = cap_lease(cap_u)
    camera_id = str(cameras[0]) if cameras else str(
        (cap_u.get("RetrScope_u") or {}).get("cameras", ["cam01"])[0]
    )
    cam_list = cameras or [camera_id]
    updated = dict(cap_u)
    updated["IdxCap_u"] = build_idx_cap_u(
        kidx_master=kidx_master,
        epoch_min=int(lease.get("epoch_min", 1)),
        epoch_max=int(lease.get("epoch_max", lease.get("epoch_min", 1))),
        cameras=cam_list,
    )
    return updated


def search_tokens_from_cap_u(
    cap_u: dict[str, Any],
    *,
    client_id: str,
    camera_id: str,
    epoch: int,
    keywords: list[str],
    gateway_version: int | None = None,
) -> list[bytes]:
    """
    Derive retrieval tokens offline using IdxCap_u.

    Validates Lease_u and RetrScope_u locally before derivation.
    """
    if gateway_version is None:
        lease = cap_lease(cap_u)
        gateway_version = int(lease.get("granted_version", lease.get("version_max", 1)))

    ok, msg = validate_cap_u_for_search(
        cap_u,
        client_id=client_id,
        camera_id=camera_id,
        epoch=epoch,
        gateway_version=gateway_version,
        keywords=keywords,
    )
    if not ok:
        raise PermissionError(msg)

    idx = cap_u.get("IdxCap_u")
    if not isinstance(idx, dict):
        raise ValueError("Cap_u missing IdxCap_u for offline retrieval")

    ok_scope, msg_scope = validate_retr_scope_u(
        cap_u, camera_id=camera_id, keywords=keywords
    )
    if not ok_scope:
        raise PermissionError(msg_scope)

    kidx_map = idx.get("kidx_by_epoch") or {}
    kidx_hex = kidx_map.get(str(int(epoch)))
    if not kidx_hex:
        raise ValueError(
            f"epoch {epoch} not covered by IdxCap_u "
            f"(range {idx.get('epoch_min')}..{idx.get('epoch_max')})"
        )

    cameras = idx.get("cameras") or []
    if cameras and camera_id not in [str(c) for c in cameras]:
        raise PermissionError(f"camera {camera_id} outside IdxCap_u cameras {cameras}")

    kidx_e = bytes.fromhex(str(kidx_hex))
    return hmac_index.make_index_tokens(kidx_e, keywords, camera_id=camera_id)


def search_token_hex_from_cap_u(
    cap_u: dict[str, Any],
    *,
    client_id: str,
    camera_id: str,
    epoch: int,
    keywords: list[str],
    gateway_version: int | None = None,
) -> list[str]:
    tokens = search_tokens_from_cap_u(
        cap_u,
        client_id=client_id,
        camera_id=camera_id,
        epoch=epoch,
        keywords=keywords,
        gateway_version=gateway_version,
    )
    return [t.hex() for t in tokens]
