"""
Verification utilities for CamShield segments and records.

Verification checks:

Camera-side descriptor:
    hi = H(mi)
    γi = H(μi || hi || γi-1)
    σi = Sign_skC(γi)
    SSi = (μi, hi, γi-1, γi, σi)

Gateway encrypted evidence record:
    ba,i = H(
        ridi || γi || H(ci) || qi || pa,e || ua,e
        || a || e || cid || sidi || seqi
    )
    ηa,i = Sign_skG(ba,i)
"""

from __future__ import annotations

from typing import Any

from core.ed25519_sig import verify
from core.models import (
    CameraSignedSegment,
    EncryptedEvidenceRecord,
    SegmentDescriptor,
    camera_chain_hash,
    payload_hash,
)


                                                                             
                                
                                                                             

def verify_segment_descriptor(
    descriptor: SegmentDescriptor,
    camera_pk: Any,
    expected_gamma_prev: bytes | None = None,
) -> tuple[bool, str]:
    """
    Verify SSi = (μi, hi, γi-1, γi, σi).

    This function does not verify H(mi) = hi because it does not have mi.
    It verifies:
        1. optional γi-1 continuity
        2. γi = H(μi || hi || γi-1)
        3. Verify_pkC(γi, σi)
    """

    if expected_gamma_prev is not None and descriptor.gamma_prev != expected_gamma_prev:
        return False, "Camera hash-chain continuity failed"

    expected_gamma = camera_chain_hash(
        cid=descriptor.cid,
        sid=descriptor.sid,
        seq=descriptor.seq,
        timestamp=descriptor.timestamp,
        hi=descriptor.hi,
        gamma_prev=descriptor.gamma_prev,
    )

    if expected_gamma != descriptor.gamma:
        return False, "Invalid camera hash-chain value"

    if not verify(camera_pk, descriptor.gamma, descriptor.sigma_c):
        return False, "Invalid camera signature"

    return True, "ok"


def verify_camera_signed_segment(
    segment: CameraSignedSegment,
    camera_pk: Any,
    expected_gamma_prev: bytes | None = None,
) -> tuple[bool, str]:
    """
    Verify Camera -> Gateway message:
        (mi, SSi)

    Checks:
        1. hi = H(mi)
        2. γi = H(μi || hi || γi-1)
        3. σi verifies over γi
        4. optional γi-1 continuity
    """

    expected_hi = payload_hash(segment.raw_payload)

    if expected_hi != segment.hi:
        return False, "Invalid payload hash"

    descriptor = segment.descriptor()

    return verify_segment_descriptor(
        descriptor=descriptor,
        camera_pk=camera_pk,
        expected_gamma_prev=expected_gamma_prev,
    )


                            
                                            
def verify_camera_segment(
    segment: CameraSignedSegment,
    camera_pk: Any,
    expected_gamma_prev: bytes | None = None,
) -> tuple[bool, str]:
    return verify_camera_signed_segment(
        segment=segment,
        camera_pk=camera_pk,
        expected_gamma_prev=expected_gamma_prev,
    )


                                                                             
                                        
                                                                             

def verify_record_camera_binding(
    record: EncryptedEvidenceRecord,
    camera_pk: Any,
    expected_gamma_prev: bytes | None = None,
) -> tuple[bool, str]:
    """
    Verify the camera descriptor SSi embedded inside ERa,i.

    Since ERa,i stores encrypted video, this function cannot verify
    H(mi) = hi. That check can only be done after decryption.

    This checks:
        1. optional γi-1 continuity
        2. γi = H(μi || hi || γi-1)
        3. Verify_pkC(γi, σi)
    """

    return verify_segment_descriptor(
        descriptor=record.SSi,
        camera_pk=camera_pk,
        expected_gamma_prev=expected_gamma_prev,
    )


def verify_record_digests(
    record: EncryptedEvidenceRecord,
) -> tuple[bool, str]:
    """
    Verify the internal digests inside ERa,i.

    Checks:
        pa,e = H(policy)
        ua,e = H(kappa)
        qi   = H(Sort(Ti^e))
    """

    if record.expected_policy_digest() != record.policy_digest:
        return False, "Invalid policy digest"

    if record.expected_capsule_digest() != record.capsule_digest:
        return False, "Invalid capsule digest"

    if not record.is_live_record():
        if record.expected_index_digest() != record.index_digest:
            return False, "Invalid index digest"

    return True, "ok"


def verify_record_binding_hash(
    record: EncryptedEvidenceRecord,
) -> tuple[bool, str]:
    """
    Verify:
        ba,i = H(
            ridi || γi || H(ci) || qi || pa,e || ua,e
            || a || e || cid || sidi || seqi
        )
    """

    expected_binding = record.expected_binding_hash()

    if expected_binding != record.binding_hash:
        return False, "Invalid record binding hash"

    return True, "ok"


def verify_gateway_record_signature(
    record: EncryptedEvidenceRecord,
    gateway_pk: Any,
) -> tuple[bool, str]:
    """
    Verify:
        ηa,i = Sign_skG(ba,i)
    """

    if not verify(gateway_pk, record.binding_hash, record.gateway_signature):
        return False, "Invalid gateway record signature"

    return True, "ok"


def verify_encrypted_evidence_record(
    record: EncryptedEvidenceRecord,
    camera_pk: Any,
    gateway_pk: Any,
    expected_gamma_prev: bytes | None = None,
) -> tuple[bool, str]:
    """
    Full verification of ERa,i before decryption.

    Checks:
        1. camera descriptor SSi
        2. policy/capsule/index digests
        3. record binding hash ba,i
        4. gateway signature ηa,i

    This does not check H(mi) = hi because mi is encrypted.
    Use verify_decrypted_plaintext() after decryption.
    """

    ok, msg = verify_record_camera_binding(
        record=record,
        camera_pk=camera_pk,
        expected_gamma_prev=expected_gamma_prev,
    )
    if not ok:
        return ok, msg

    ok, msg = verify_record_digests(record)
    if not ok:
        return ok, msg

    ok, msg = verify_record_binding_hash(record)
    if not ok:
        return ok, msg

    ok, msg = verify_gateway_record_signature(record, gateway_pk)
    if not ok:
        return ok, msg

    return True, "ok"


def verify_decrypted_plaintext(
    record: EncryptedEvidenceRecord,
    plaintext: bytes,
) -> tuple[bool, str]:
    """
    Verify after AES-GCM decryption:
        H(mi) = hi

    This links the decrypted video payload back to the camera-signed descriptor.
    """

    if payload_hash(plaintext) != record.SSi.hi:
        return False, "Decrypted payload hash does not match camera descriptor"

    return True, "ok"


                                                                             
                                            
                                                                             

def verify_camera_chain_sequence(
    descriptors: list[SegmentDescriptor],
    camera_pk: Any,
    initial_gamma: bytes | None = None,
) -> tuple[bool, str]:
    """
    Verify a sequence of camera descriptors.

    Checks:
        γi-1 continuity across descriptors
        γi computation
        camera signature

    This is useful for verifier-side batch checking.
    """

    expected_prev = initial_gamma

    for idx, descriptor in enumerate(descriptors):
        ok, msg = verify_segment_descriptor(
            descriptor=descriptor,
            camera_pk=camera_pk,
            expected_gamma_prev=expected_prev,
        )
        if not ok:
            return False, f"Descriptor {idx} failed: {msg}"

        expected_prev = descriptor.gamma

    return True, "ok"


def verify_signed_segment_sequence(
    segments: list[CameraSignedSegment],
    camera_pk: Any,
    initial_gamma: bytes | None = None,
) -> tuple[bool, str]:
    """
    Verify a sequence of CameraSignedSegment objects.

    This checks both:
        H(mi) = hi
    and:
        hash-chain/signature validity.
    """

    expected_prev = initial_gamma

    for idx, segment in enumerate(segments):
        ok, msg = verify_camera_signed_segment(
            segment=segment,
            camera_pk=camera_pk,
            expected_gamma_prev=expected_prev,
        )
        if not ok:
            return False, f"Segment {idx} failed: {msg}"

        expected_prev = segment.gamma

    return True, "ok"