"""
Camera-side module for CamShield.

Role:
    Camera/TEE -> Gateway : (mi, SSi)

where:
    μi  = (cid, sidi, seqi, ti)
    hi  = H(mi)
    γi  = H(μi || hi || γi-1)
    σi  = Sign_skC(γi)
    SSi = (μi, hi, γi-1, γi, σi)

Important:
- The camera-side TEE signs only the camera-origin descriptor.
- It does NOT sign event_tags, object_tags, location, or granularity.
- Search tags are Gateway-side inputs used later for encrypted retrieval.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.ed25519_sig import generate_keypair, public_key_bytes, sign
from core.models import (
    CameraSignedSegment,
    camera_chain_hash,
    payload_hash,
)


                                                                             
                                  
                                                                             

@dataclass(frozen=True)
class SensorCaptureRequest:
    """
    Main -> Sensor.

    The sensor only captures or produces the raw segment mi.
    It does not perform cryptographic operations.
    """

    camera_id: str
    seq: int
    timestamp: int
    sid: str | None = None
    raw_payload: bytes | None = None


@dataclass(frozen=True)
class SensorSegmentData:
    """
    Sensor -> Main.

    Raw segment data before camera-side attestation.
    """

    cid: str
    sid: str
    seq: int
    timestamp: int
    raw_payload: bytes


@dataclass(frozen=True)
class TeeAttestRequest:
    """
    Main -> TEE.

    The TEE receives the raw payload mi and minimal metadata μi.
    """

    cid: str
    sid: str
    seq: int
    timestamp: int
    raw_payload: bytes


@dataclass(frozen=True)
class TeeAttestResponse:
    """
    TEE -> Main.

    This is the cryptographic descriptor material.
    """

    hi: bytes
    gamma_prev: bytes
    gamma: bytes
    sigma_c: bytes


@dataclass
class CameraAuditEntry:
    """
    Local audit entry for operator inspection.

    Local audit helper; not part of the wire protocol.
    """

    sid: str
    seq: int
    timestamp: int
    hi: bytes
    gamma_prev: bytes
    gamma: bytes
    sigma_c: bytes


@dataclass
class CameraAuditLog:
    """
    Local camera-side audit log.

    Local camera-side audit log for operator inspection.
    """

    camera_id: str
    entries: list[CameraAuditEntry] = field(default_factory=list)


                                                                             
            
                                                                             

@runtime_checkable
class SensorInterface(Protocol):
    def capture_segment(self, request: SensorCaptureRequest) -> SensorSegmentData:
        ...


@runtime_checkable
class TeeInterface(Protocol):
    @property
    def public_key(self) -> Ed25519PublicKey:
        ...

    @property
    def public_key_bytes(self) -> bytes:
        ...

    @property
    def audit_log(self) -> CameraAuditLog:
        ...

    def attest_segment(self, request: TeeAttestRequest) -> TeeAttestResponse:
        ...


@runtime_checkable
class MainInterface(Protocol):
    def produce_signed_segment(
        self,
        seq_no: int,
        timestamp: int | None = None,
        raw_payload: bytes | None = None,
        sid: str | None = None,
        **legacy_kwargs,
    ) -> CameraSignedSegment:
        ...


                                                                             
                 
                                                                             

class SimulatedSensor:
    """
    Simulated camera sensor.

    Later replacement:
    - USB camera
    - RTSP camera
    - V4L2 / ffmpeg segmenter
    """

    def capture_segment(self, request: SensorCaptureRequest) -> SensorSegmentData:
        sid = request.sid or f"{request.camera_id}_seg_{request.seq:06d}"

        if request.raw_payload is None:
            raw_payload = json.dumps(
                {
                    "cid": request.camera_id,
                    "sid": sid,
                    "seq": request.seq,
                    "timestamp": request.timestamp,
                    "sim": secrets.token_hex(8),
                    "noise": os.urandom(16).hex(),
                },
                sort_keys=True,
            ).encode("utf-8")
        else:
            raw_payload = request.raw_payload

        return SensorSegmentData(
            cid=request.camera_id,
            sid=sid,
            seq=request.seq,
            timestamp=request.timestamp,
            raw_payload=raw_payload,
        )


class LocalTeeModule:
    """
    Local software TEE simulator.

    Deployment mapping:
    - In Plan 2A, this logic can run on MP157 as an isolated signing service.
    - In Plan 2B, this logic should be moved into an OP-TEE Trusted Application.
    - skC and γ state must not be exposed to Raspberry Pi / Gateway / Cloud.
    """

    def __init__(self, camera_id: str):
        self._camera_id = camera_id
        self._sk, self._pk = generate_keypair()
        self._gamma_prev = b"\x00" * 32
        self._audit_log = CameraAuditLog(camera_id=camera_id)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._pk

    @property
    def public_key_bytes(self) -> bytes:
        return public_key_bytes(self._pk)

    @property
    def audit_log(self) -> CameraAuditLog:
        return self._audit_log

    def attest_segment(self, request: TeeAttestRequest) -> TeeAttestResponse:
        if request.cid != self._camera_id:
            raise ValueError("TEE camera_id mismatch")

                    
        hi = payload_hash(request.raw_payload)

                                  
        gamma = camera_chain_hash(
            cid=request.cid,
            sid=request.sid,
            seq=request.seq,
            timestamp=request.timestamp,
            hi=hi,
            gamma_prev=self._gamma_prev,
        )

                           
        sigma_c = sign(self._sk, gamma)

        gamma_prev = self._gamma_prev
        self._gamma_prev = gamma

        self._audit_log.entries.append(
            CameraAuditEntry(
                sid=request.sid,
                seq=request.seq,
                timestamp=request.timestamp,
                hi=hi,
                gamma_prev=gamma_prev,
                gamma=gamma,
                sigma_c=sigma_c,
            )
        )

        return TeeAttestResponse(
            hi=hi,
            gamma_prev=gamma_prev,
            gamma=gamma,
            sigma_c=sigma_c,
        )


@dataclass
class CameraMain:
    """
    Camera main controller.

    Main does not hold skC.
    Main only:
    1. asks Sensor to produce mi
    2. forwards μi and mi to TEE
    3. assembles CameraSignedSegment = (mi, SSi)
    """

    camera_id: str
    sensor: SensorInterface = field(default_factory=SimulatedSensor)
    tee: TeeInterface | None = None

    def __post_init__(self) -> None:
        if self.tee is None:
            self.tee = LocalTeeModule(self.camera_id)

    @property
    def public_key(self) -> Ed25519PublicKey:
        if self.tee is None:
            raise RuntimeError("TEE not initialized")
        return self.tee.public_key

    @property
    def public_key_bytes(self) -> bytes:
        if self.tee is None:
            raise RuntimeError("TEE not initialized")
        return self.tee.public_key_bytes

    @property
    def audit_log(self) -> CameraAuditLog:
        if self.tee is None:
            raise RuntimeError("TEE not initialized")
        return self.tee.audit_log

    def produce_signed_segment(
        self,
        seq_no: int,
        timestamp: int | None = None,
        raw_payload: bytes | None = None,
        sid: str | None = None,
        **legacy_kwargs,
    ) -> CameraSignedSegment:
        """
        Produce:
            C -> G : (mi, SSi)

        Parameters:
        - seq_no: segment sequence number
        - timestamp: segment timestamp
        - raw_payload: caller-supplied segment payload
        - sid: optional segment id

        Additional keyword arguments are accepted for API compatibility and
        ignored by camera-side signing.
        """

                                                   
                                                                                 
        if timestamp is None:
            timestamp = legacy_kwargs.get("timestamp_start")
        if timestamp is None:
            timestamp = int(time.time())

                        
        sensor_req = SensorCaptureRequest(
            camera_id=self.camera_id,
            seq=seq_no,
            timestamp=timestamp,
            sid=sid,
            raw_payload=raw_payload,
        )
        segment_data = self.sensor.capture_segment(sensor_req)

                     
        attest_req = TeeAttestRequest(
            cid=segment_data.cid,
            sid=segment_data.sid,
            seq=segment_data.seq,
            timestamp=segment_data.timestamp,
            raw_payload=segment_data.raw_payload,
        )
        attest = self.tee.attest_segment(attest_req)                            

                                                  
        return CameraSignedSegment(
            cid=segment_data.cid,
            sid=segment_data.sid,
            seq=segment_data.seq,
            timestamp=segment_data.timestamp,
            raw_payload=segment_data.raw_payload,
            hi=attest.hi,
            gamma_prev=attest.gamma_prev,
            gamma=attest.gamma,
            sigma_c=attest.sigma_c,
        )