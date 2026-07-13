"""msgpack serialization with base64 wrapping for bytes fields in protocol messages."""
from __future__ import annotations

import base64
from typing import Any, Type, TypeVar

import msgpack
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def _encode_obj(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return {"__b64__": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, dict):
        return {k: _encode_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_encode_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return [_encode_obj(v) for v in obj]
    return obj


def _decode_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        if set(obj.keys()) == {"__b64__"}:
            return base64.b64decode(obj["__b64__"])
        return {k: _decode_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_decode_obj(v) for v in obj]
    return obj


def to_bytes(model: BaseModel) -> bytes:
    return msgpack.packb(_encode_obj(model.model_dump(mode="python")), use_bin_type=True)


def from_bytes(cls: Type[T], data: bytes) -> T:
    return cls.model_validate(_decode_obj(msgpack.unpackb(data, raw=False)))
