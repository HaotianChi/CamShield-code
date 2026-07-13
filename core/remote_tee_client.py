                           
"""
Remote TEE client for CameraMain.

This implements the same TeeInterface expected by CameraMain,
but forwards attest requests to tee_server.py over localhost HTTP.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.camera import CameraAuditLog, TeeAttestRequest, TeeAttestResponse
from core.ed25519_sig import load_public_key
from core.wire import b64e, b64d


@dataclass
class RemoteTeeClient:
    base_url: str
    camera_id: str = "cam01"
    timeout: int = 60

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        self._public_key_bytes: bytes | None = None
        self._public_key: Ed25519PublicKey | None = None
        self._audit_log = CameraAuditLog(camera_id=self.camera_id)

    def _post_json(self, path: str, obj: dict) -> dict:
        url = f"{self.base_url}{path}"
        resp = requests.post(url, json=obj, timeout=self.timeout)
        data = resp.json()
        if resp.status_code >= 400 or not data.get("ok", False):
            raise RuntimeError(
                f"TEE request failed: {url}, status={resp.status_code}, data={data}"
            )
        return data

    def _get_json(self, path: str) -> dict:
        url = f"{self.base_url}{path}"
        resp = requests.get(url, timeout=self.timeout)
        data = resp.json()
        if resp.status_code >= 400 or not data.get("ok", False):
            raise RuntimeError(
                f"TEE request failed: {url}, status={resp.status_code}, data={data}"
            )
        return data

    @property
    def public_key_bytes(self) -> bytes:
        if self._public_key_bytes is None:
            data = self._get_json("/public-key")
            self._public_key_bytes = b64d(data["public_key_b64"])
        return self._public_key_bytes

    @property
    def public_key(self) -> Ed25519PublicKey:
        if self._public_key is None:
            self._public_key = load_public_key(self.public_key_bytes)
        return self._public_key

    @property
    def audit_log(self) -> CameraAuditLog:
        return self._audit_log

    def attest_segment(self, request: TeeAttestRequest) -> TeeAttestResponse:
        obj = {
            "cid": request.cid,
            "sid": request.sid,
            "seq": request.seq,
            "timestamp": request.timestamp,
            "raw_payload_b64": b64e(request.raw_payload),
        }

        data = self._post_json("/attest", obj)

        return TeeAttestResponse(
            hi=b64d(data["hi_b64"]),
            gamma_prev=b64d(data["gamma_prev_b64"]),
            gamma=b64d(data["gamma_b64"]),
            sigma_c=b64d(data["sigma_c_b64"]),
        )
