"""
CamShield Gateway: ingest, encrypt, index, and issue client credentials.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core import aes_gcm, hmac_index
from core.abe import CPABEBase
from core.ed25519_sig import (
    generate_keypair,
    public_key_bytes,
    sign,
)
from core.epoch import EpochManager, build_abe_policy
from core.cap_u import (
    abe_access_attrs,
    abe_client_attrs,
    cap_lease,
    extend_cap_u,
    grant_cap_u,
    validate_cap_u_for_bootstrap,
    validate_cap_u_for_search,
)
from core.idx_cap_u import attach_idx_cap_u
from core.models import (
    CameraSignedSegment,
    ClientTrustMaterial,
    EncryptedEvidenceRecord,
    SegmentDescriptor,
    sha256,
)
from core.segment_verify import verify_camera_signed_segment


@dataclass
class CameraRegistryEntry:
    cid: str
    public_key: Ed25519PublicKey
    last_gamma: bytes = b"\x00" * 32
    expected_seq: int = 1


@dataclass
class GatewayCameraRegistry:
    """Per-camera public keys and hash-chain state."""

    cameras: dict[str, CameraRegistryEntry] = field(default_factory=dict)

    def enroll_camera(
        self,
        cid: str,
        public_key: Ed25519PublicKey,
        initial_gamma: bytes | None = None,
        expected_seq: int = 1,
    ) -> None:
        self.cameras[cid] = CameraRegistryEntry(
            cid=cid,
            public_key=public_key,
            last_gamma=initial_gamma if initial_gamma is not None else b"\x00" * 32,
            expected_seq=expected_seq,
        )

    def has_camera(self, cid: str) -> bool:
        return cid in self.cameras

    def get(self, cid: str) -> CameraRegistryEntry:
        if cid not in self.cameras:
            raise KeyError(f"Camera not enrolled: {cid}")
        return self.cameras[cid]

    def get_public_key(self, cid: str) -> Ed25519PublicKey:
        return self.get(cid).public_key

    def get_last_gamma(self, cid: str) -> bytes:
        return self.get(cid).last_gamma

    def get_expected_seq(self, cid: str) -> int:
        return self.get(cid).expected_seq

    def update_after_verified_segment(self, cid: str, seq: int, gamma: bytes) -> None:
        entry = self.get(cid)
        entry.last_gamma = gamma
        entry.expected_seq = seq + 1

    def first_camera_id(self) -> str | None:
        if not self.cameras:
            return None
        return next(iter(self.cameras.keys()))


class Gateway:
    role_name = "Gateway"

    def __init__(
        self,
        gateway_id: str = "gateway-001",
        abe: CPABEBase | None = None,
        mpk: Any | None = None,
        msk: Any | None = None,
        epoch_manager: EpochManager | None = None,
        camera_registry: GatewayCameraRegistry | None = None,
    ):
        self.gateway_id = gateway_id

        self.skG, self.pkG = generate_keypair()

        self.abe = abe
        self.mpk = mpk
        self.msk = msk

        self.epoch_manager = epoch_manager or EpochManager()
        self.camera_registry = camera_registry or GatewayCameraRegistry()
        self.client_caps: dict[str, dict] = {}

                                                                           
                               
        if self.abe is not None and (self.mpk is None or self.msk is None):
            self._try_abe_setup()

                                                                        
                 
                                                                        

    @property
    def public_key(self):
        return self.pkG

    @property
    def public_key_bytes(self) -> bytes:
        return public_key_bytes(self.pkG)

                                                                        
                                
                                                                        

    def _try_abe_setup(self) -> None:
        """
        Try to initialize ABE mpk/msk.

        Different ABE implementations may expose slightly different APIs.
        This wrapper supports both MockCPABE and Charm-based ABE backends.
        """
        if self.abe is None:
            return

        if hasattr(self.abe, "setup"):
            result = self.abe.setup()
            if isinstance(result, tuple) and len(result) == 2:
                self.mpk, self.msk = result
                return

                                                             
        if hasattr(self.abe, "mpk") and self.mpk is None:
            self.mpk = getattr(self.abe, "mpk")
        if hasattr(self.abe, "msk") and self.msk is None:
            self.msk = getattr(self.abe, "msk")

    def _abe_keygen(self, attributes: list[str]) -> Any:
        """
        Generate user secret key SKu.

        Protocol:
            SKu <- ABE.KeyGen(MSKABE, Au)

        For MockCPABE, this returns the attribute list directly.
        """
        if self.abe is None:
                                                        
            return {"attributes": attributes}

        if hasattr(self.abe, "keygen"):
                           
                                  
                                       
                             
            try:
                return self.abe.keygen(self.msk, attributes)
            except TypeError:
                pass

            try:
                return self.abe.keygen(self.mpk, self.msk, attributes)
            except TypeError:
                pass

            try:
                return self.abe.keygen(attributes)
            except TypeError:
                pass

                            
        return {"attributes": attributes}

    def _abe_encrypt_epoch_key(self, policy: str, EKe: bytes) -> bytes:
        """
        Encapsulate epoch data key EKe.

        Protocol:
            κa,e = ABE.Enc(PKABE, EKe, πa,e)

        Important:
            We encapsulate EKe, not per-record CEK.
        """
        if self.abe is None:
                                                                                
            return b"MOCK_ABE_CAPSULE|" + policy.encode("utf-8") + b"|" + EKe

        if hasattr(self.abe, "encrypt"):
                           
                                             
                                        
                                        
            try:
                return self.abe.encrypt(self.mpk, policy, EKe)
            except TypeError:
                pass

            try:
                return self.abe.encrypt(policy, EKe)
            except TypeError:
                pass

            try:
                return self.abe.encrypt(EKe, policy)
            except TypeError:
                pass

        raise RuntimeError("ABE backend does not support encrypt()")

                                                                        
                       
                                                                        

    def enroll_camera(
        self,
        cid: str,
        camera_public_key: Ed25519PublicKey,
        initial_gamma: bytes | None = None,
        expected_seq: int = 1,
    ) -> None:
        """
        Register camera public key pkC at Gateway.

        This replaces old Authority camera registry.
        """
        self.camera_registry.enroll_camera(
            cid=cid,
            public_key=camera_public_key,
            initial_gamma=initial_gamma,
            expected_seq=expected_seq,
        )

                                                                        
                                                
                                                                        

    def issue_client_bootstrap(
        self,
        role_name: str,
        attributes: list[str],
        cid: str | None = None,
        client_id: str = "owner",
        purpose: str = "SURVEILLANCE",
        mode: str = "READ",
    ) -> tuple[ClientTrustMaterial, Any]:
        """
        Gateway issues client trust anchors and ABE secret key (SK_u).

        Requires an active Cap_u lease; returns Cred_u components (trust + SK_u).
        """
        if cid is None:
            cid = self.camera_registry.first_camera_id()

        if cid is None:
            raise RuntimeError("No camera enrolled; cannot issue client trust material")

        cap = self.client_caps.get(client_id)
        ok, msg = validate_cap_u_for_bootstrap(cap)
        if not ok:
            raise PermissionError(f"Cap_u required before bootstrap: {msg}")

        attrs = list(cap.get("abe_attrs", attributes))
        if not attrs:
            raise PermissionError("Cap_u missing abe_attrs for SK_u issuance")

        camera_pk = self.camera_registry.get_public_key(cid)
        abe_sk = self._abe_keygen(attrs)

        lease = cap_lease(cap)
        trust = ClientTrustMaterial(
            role_name=role_name,
            camera_public_key_bytes=public_key_bytes(camera_pk),
            gateway_public_key_bytes=self.public_key_bytes,
            min_epoch=int(lease.get("epoch_min", 1)),
            min_checkpoint_version=0,
        )

        return trust, abe_sk

    def grant_client_cap(
        self,
        client_id: str,
        camera_id: str,
        *,
        abe_attrs: list[str] | None = None,
        epoch_min: int = 1,
        epoch_max: int | None = None,
        version_max: int | None = None,
        expires_at: int = 0,
        tag_patterns: list[str] | None = None,
        modes: list[str] | None = None,
    ) -> dict:
        e = self.epoch_manager.current_epoch()
        v = self.epoch_manager.current_version()
        if abe_attrs is None:
            abe_attrs = abe_client_attrs(
                role="OWNER",
                purpose="SURVEILLANCE",
                mode="READ",
                scope=camera_id,
            )
        cap = grant_cap_u(
            client_id=client_id,
            camera_id=camera_id,
            abe_attrs=abe_attrs,
            current_epoch=e,
            current_version=v,
            epoch_min=epoch_min,
            epoch_max=epoch_max,
            version_max=version_max,
            expires_at=expires_at,
            tag_patterns=tag_patterns,
            modes=modes,
        )
        cap = attach_idx_cap_u(
            cap,
            kidx_master=self.epoch_manager.Kidx_master,
            cameras=[camera_id],
        )
        self.client_caps[client_id] = cap
        return cap

    def refresh_client_cap(
        self,
        client_id: str,
        *,
        epoch_max: int | None = None,
        version_max: int | None = None,
    ) -> dict:
        cap = self.client_caps.get(client_id)
        if cap is None:
            raise KeyError(f"No Cap_u lease for client: {client_id}")
        updated = extend_cap_u(
            cap,
            epoch_max=epoch_max,
            version_max=version_max,
        )
        updated = attach_idx_cap_u(
            updated,
            kidx_master=self.epoch_manager.Kidx_master,
        )
        self.client_caps[client_id] = updated
        return updated

    def issue_search_tokens(
        self,
        user_attrs: list[str],
        keywords: list[str],
        epoch: int | None = None,
        camera_id: str | None = None,
        client_id: str | None = None,
    ) -> list[bytes]:
        """
        Issue epoch-specific encrypted query tokens.

        Protocol:
            Kidx^e = KDF(Kidx, e)
            τw^e = HMAC_{Kidx^e}(w)

        Requires an active Cap_u lease covering the requested epoch.
        """
        if camera_id is None or str(camera_id).strip() == "":
            raise ValueError("camera_id is required for camera-scoped search tokens")

        e = self.epoch_manager.current_epoch() if epoch is None else epoch

        if client_id is not None:
            cap = self.client_caps.get(client_id)
            ok, msg = validate_cap_u_for_search(
                cap,
                client_id=client_id,
                camera_id=str(camera_id).strip(),
                epoch=e,
                gateway_version=self.epoch_manager.current_version(),
                keywords=keywords,
            )
            if not ok:
                raise PermissionError(f"Cap_u denied search tokens: {msg}")

        kidx_e = self.epoch_manager.index_key(e)
        return hmac_index.make_index_tokens(kidx_e, keywords, camera_id=camera_id)

                                                                        
                        
                                                                        

    def process_segment(
        self,
        segment: CameraSignedSegment,
        extra_keywords: Iterable[str] | None = None,
        role: str = "OWNER",
        purpose: str = "SURVEILLANCE",
        mode: str = "READ",
        scope: str | None = None,
        access_class: str = "RAW",
        live: bool = False,
    ) -> EncryptedEvidenceRecord:
        """
        Main Gateway entry point.

        Input:
            CameraSignedSegment = (mi, SSi)

        Output:
            EncryptedEvidenceRecord = ERa,i (archival)
            or LERa,i when live=True (no index digest; blive binding)

        One video segment produces one encrypted evidence record.
        """
        self.maybe_rotate_epoch()

        if scope is None:
            scope = segment.cid

        self._verify_camera_input(segment)

        record = self._build_encrypted_record(
            segment=segment,
            extra_keywords=extra_keywords,
            role=role,
            purpose=purpose,
            mode=mode,
            scope=scope,
            access_class=access_class,
            live=live,
        )

                                                                              
        self.camera_registry.update_after_verified_segment(
            cid=segment.cid,
            seq=segment.seq,
            gamma=segment.gamma,
        )

        return record

    def _verify_camera_input(self, segment: CameraSignedSegment) -> None:
        """
        Verify camera-origin provenance before processing.

        Checks:
            H(mi) = hi
            γi = H(μi || hi || γi-1)
            Verify_pkC(γi, σi)
            γi-1 continuity
            optional seq continuity
        """
        if not self.camera_registry.has_camera(segment.cid):
            raise PermissionError(f"Unenrolled camera: {segment.cid}")

        entry = self.camera_registry.get(segment.cid)

                                         
        if segment.seq != entry.expected_seq:
            raise ValueError(
                f"Unexpected sequence number for {segment.cid}: "
                f"got {segment.seq}, expected {entry.expected_seq}"
            )

        ok, msg = verify_camera_signed_segment(
            segment=segment,
            camera_pk=entry.public_key,
            expected_gamma_prev=entry.last_gamma,
        )
        if not ok:
            raise ValueError(f"Invalid camera segment: {msg}")

    def _build_encrypted_record(
        self,
        segment: CameraSignedSegment,
        extra_keywords: Iterable[str] | None,
        role: str,
        purpose: str,
        mode: str,
        scope: str,
        access_class: str,
        live: bool = False,
    ) -> EncryptedEvidenceRecord:
        """
        Build encrypted evidence record.

        Archival path produces ERa,i with index digest qi and binding ba,i.
        Live fast path produces LERa,i with empty qi and binding blive.
        """
        e = self.epoch_manager.current_epoch()

                                       
        rid = self.epoch_manager.record_id(segment.cid, segment.sid, e)

                     
        EKe = self.epoch_manager.epoch_key(e)
        ki = self.epoch_manager.record_key(rid, e)

                                                   
        aad = aes_gcm.build_associated_data(
            rid=rid,
            cid=segment.cid,
            sid=segment.sid,
            seq=segment.seq,
            timestamp=segment.timestamp,
            epoch=e,
            gamma=segment.gamma,
        )

                                  
        gcm = aes_gcm.encrypt(
            key=ki,
            plaintext=segment.raw_payload,
            associated_data=aad,
        )

                                                           
        policy = build_abe_policy(
            role=role,
            purpose=purpose,
            mode=mode,
            scope=scope,
        )

                                          
        kappa = self._abe_encrypt_epoch_key(policy=policy, EKe=EKe)

        if live:
            index_tokens: list[bytes] = []
            qi = b""
        else:
            kidx_e = self.epoch_manager.index_key(e)
            keywords = hmac_index.keyword_set_for_record(
                cid=segment.cid,
                sid=segment.sid,
                seq=segment.seq,
                extra_keywords=extra_keywords,
            )
            index_tokens = hmac_index.make_index_tokens(
                kidx_e, keywords, camera_id=segment.cid
            )
            qi = hmac_index.index_digest(index_tokens)

                       
        policy_digest = sha256(policy.encode("utf-8"))
        capsule_digest = sha256(kappa)

        descriptor = SegmentDescriptor(
            cid=segment.cid,
            sid=segment.sid,
            seq=segment.seq,
            timestamp=segment.timestamp,
            hi=segment.hi,
            gamma_prev=segment.gamma_prev,
            gamma=segment.gamma,
            sigma_c=segment.sigma_c,
        )

        record = EncryptedEvidenceRecord(
            rid=rid,
            SSi=descriptor,
            a=access_class,
            epoch=e,
            nonce=gcm.nonce,
            ciphertext=gcm.ciphertext,
            tag=gcm.tag,
            kappa=kappa,
            policy=policy,
            policy_digest=policy_digest,
            capsule_digest=capsule_digest,
            index_tokens=index_tokens,
            index_digest=qi,
            binding_hash=b"",
            gateway_signature=b"",
        )

        if live:
            record.binding_hash = record.compute_live_binding_hash()
        else:
            record.binding_hash = record.compute_binding_hash()

        record.gateway_signature = sign(self.skG, record.binding_hash)

        return record

    def maybe_rotate_epoch(self) -> list:
        """Apply scheduled epoch transitions that are due at the current time."""
        return self.epoch_manager.maybe_rotate_epoch()

    def rotate_epoch(self, *, manual: bool = False):
        """Advance to the next epoch (scheduled or manual)."""
        return self.epoch_manager.rotate_epoch(manual=manual)