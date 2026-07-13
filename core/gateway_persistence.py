from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.ed25519_sig import load_public_key, public_key_bytes


DEFAULT_STATE_PATH = Path(os.environ.get(
    "CAMSHIELD_GATEWAY_STATE",
    ".camshield_gateway_state.json",
))


def _b64e(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")


def _b64d(x: str) -> bytes:
    return base64.b64decode(x.encode("ascii"))


def _sk_to_raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_simple(v: Any):
    if isinstance(v, bytes):
        return {"__type__": "bytes", "b64": _b64e(v)}

    if isinstance(v, (str, int, float, bool)) or v is None:
        return v

    if isinstance(v, list):
        out = []
        for x in v:
            sx = _serialize_simple(x)
            if sx is not None:
                out.append(sx)
        return {"__type__": "list", "items": out}

    if isinstance(v, tuple):
        out = []
        for x in v:
            sx = _serialize_simple(x)
            if sx is not None:
                out.append(sx)
        return {"__type__": "tuple", "items": out}

    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if not isinstance(k, (str, int, float, bool)):
                continue
            sx = _serialize_simple(x)
            if sx is not None:
                out[str(k)] = sx
        return {"__type__": "dict", "items": out}

    return None


def _deserialize_simple(v: Any):
    if isinstance(v, dict) and "__type__" in v:
        t = v["__type__"]

        if t == "bytes":
            return _b64d(v["b64"])

        if t == "list":
            return [_deserialize_simple(x) for x in v.get("items", [])]

        if t == "tuple":
            return tuple(_deserialize_simple(x) for x in v.get("items", []))

        if t == "dict":
            out = {}
            for k, x in v.get("items", {}).items():
                                                            
                                                                                  
                if isinstance(k, str) and k.isdigit():
                    kk = int(k)
                else:
                    kk = k
                out[kk] = _deserialize_simple(x)
            return out

    return v


def _serialize_epoch_manager(epoch_manager: Any) -> dict[str, Any]:
    """
    Persist epoch and index-key state.

    This catches bytes/int fields such as Kidx, Krid, EKe, current_epoch,
    current_version, etc., without trying to serialize Charm ABE objects.
    """
    if epoch_manager is None or not hasattr(epoch_manager, "__dict__"):
        return {}

    out = {}
    for k, v in vars(epoch_manager).items():
        if k.startswith("_") and not isinstance(v, (bytes, int, str, bool, dict, list, tuple)):
            continue
        sv = _serialize_simple(v)
        if sv is not None:
            out[k] = sv

    return out


def _restore_epoch_manager(epoch_manager: Any, data: dict[str, Any]) -> None:
    if epoch_manager is None:
        return

    for k, v in data.items():
        try:
            setattr(epoch_manager, k, _deserialize_simple(v))
        except Exception:
            pass


def _serialize_camera_registry(gateway: Any) -> dict[str, Any]:
    registry = getattr(gateway, "camera_registry", None)
    cameras = getattr(registry, "cameras", {}) if registry is not None else {}

    out = {}
    for cid, entry in cameras.items():
        pk = getattr(entry, "public_key", None)
        last_gamma = getattr(entry, "last_gamma", b"\x00" * 32)
        expected_seq = getattr(entry, "expected_seq", 1)

        if pk is None:
            continue

        out[str(cid)] = {
            "public_key_b64": _b64e(public_key_bytes(pk)),
            "last_gamma_b64": _b64e(last_gamma),
            "expected_seq": int(expected_seq),
        }

    return out


def _restore_camera_registry(gateway: Any, camera_registry_data: dict[str, Any], state: dict[str, Any] | None) -> None:
    if state is not None:
        state.setdefault("camera_public_keys", {})
        state.setdefault("enrolled", set())

    for cid, item in camera_registry_data.items():
        try:
            pk_raw = _b64d(item["public_key_b64"])
            pk = load_public_key(pk_raw)
            last_gamma = _b64d(item.get("last_gamma_b64", _b64e(b"\x00" * 32)))
            expected_seq = int(item.get("expected_seq", 1))

            gateway.enroll_camera(
                cid=str(cid),
                camera_public_key=pk,
                initial_gamma=last_gamma,
                expected_seq=expected_seq,
            )

            if state is not None:
                state["camera_public_keys"][str(cid)] = item["public_key_b64"]
                state["enrolled"].add(str(cid))

        except Exception as exc:
            print(f"[PERSIST] failed to restore camera {cid}: {exc}")


def save_gateway_state(gateway: Any, state: dict[str, Any] | None = None, path: Path = DEFAULT_STATE_PATH) -> None:
    path = Path(path)

    data = {
        "type": "camshield-gateway-state-v1",
        "gateway_signing_key_raw_b64": _b64e(_sk_to_raw(gateway.skG)),
        "gateway_public_key_b64": _b64e(public_key_bytes(gateway.pkG)),
        "epoch_manager": _serialize_epoch_manager(getattr(gateway, "epoch_manager", None)),
        "camera_registry": _serialize_camera_registry(gateway),
    }

    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[PERSIST] saved Gateway state to {path}")


def load_or_init_gateway_state(gateway: Any, state: dict[str, Any] | None = None, path: Path = DEFAULT_STATE_PATH) -> None:
    path = Path(path)

    if not path.exists():
        print(f"[PERSIST] no existing state at {path}; creating a new one")
        save_gateway_state(gateway, state, path)
        return

    data = json.loads(path.read_text(encoding="utf-8"))

    raw_sk = _b64d(data["gateway_signing_key_raw_b64"])
    gateway.skG = Ed25519PrivateKey.from_private_bytes(raw_sk)
    gateway.pkG = gateway.skG.public_key()

    _restore_epoch_manager(
        getattr(gateway, "epoch_manager", None),
        data.get("epoch_manager", {}),
    )

    _restore_camera_registry(
        gateway,
        data.get("camera_registry", {}),
        state,
    )

    print(f"[PERSIST] loaded Gateway state from {path}")
