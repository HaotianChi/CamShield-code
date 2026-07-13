from __future__ import annotations

import os
import pickle
import time
from pathlib import Path
from typing import Any


DEFAULT_CLOUD_STATE_PATH = Path(os.environ.get(
    "CAMSHIELD_CLOUD_STATE",
    ".camshield_cloud_state.pkl",
))


def _can_pickle(x: Any) -> bool:
    try:
        pickle.dumps(x, protocol=pickle.HIGHEST_PROTOCOL)
        return True
    except Exception:
        return False


def _extract_persistable_fields(state: Any) -> dict[str, Any]:
    """
    Persist only fields that can be pickled.

    CloudState may contain runtime-only objects such as threading.Lock,
    which must not be persisted. We skip those fields and keep the freshly
    initialized runtime objects after restart.
    """
    if isinstance(state, dict):
        items = state.items()
    elif hasattr(state, "__dict__"):
        items = vars(state).items()
    else:
        raise RuntimeError(f"unsupported Cloud state type: {type(state).__name__}")

    out = {}

    for k, v in items:
        if str(k).startswith("__"):
            continue

        if _can_pickle(v):
            out[str(k)] = v
        else:
            print(f"[CLOUD-PERSIST] skip non-pickleable field: {k} ({type(v).__name__})")

    return out


def _apply_fields(target_state: Any, fields: dict[str, Any]) -> None:
    """
    Restore saved fields while preserving runtime-only fields, such as locks,
    that were created by CloudState.__init__ during server startup.
    """
    if isinstance(target_state, dict):
        target_state.update(fields)
        return

    if hasattr(target_state, "__dict__"):
        for k, v in fields.items():
            setattr(target_state, k, v)
        return

    raise RuntimeError(f"unsupported Cloud state restore target: {type(target_state).__name__}")


def save_cloud_state(state: Any, path: Path = DEFAULT_CLOUD_STATE_PATH) -> None:
    """
    Persist Cloud-side encrypted storage.

    This stores encrypted records, encrypted index maps, checkpoint material,
    and public metadata. It skips runtime-only objects such as locks.
    """
    path = Path(path)

    fields = _extract_persistable_fields(state)

    payload = {
        "type": "camshield-cloud-state-fields-pickle-v1",
        "saved_at": int(time.time()),
        "state_class": type(state).__name__,
        "fields": fields,
    }

    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("wb") as f:
        pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)

    tmp.replace(path)
    print(f"[CLOUD-PERSIST] saved Cloud state to {path} fields={list(fields.keys())}")


def load_cloud_state(state: Any, path: Path = DEFAULT_CLOUD_STATE_PATH) -> None:
    path = Path(path)

    if not path.exists():
        print(f"[CLOUD-PERSIST] no existing Cloud state at {path}; starting empty")
        return

    with path.open("rb") as f:
        payload = pickle.load(f)

    fields = payload.get("fields", {})
    if not isinstance(fields, dict):
        print(f"[CLOUD-PERSIST] invalid Cloud state file {path}; starting empty")
        return

    _apply_fields(state, fields)

    print(f"[CLOUD-PERSIST] loaded Cloud state from {path} fields={list(fields.keys())}")
