"""
CamShield protocol data models.

This file defines the protocol objects shared by Camera/TEE, Gateway, Cloud,
Client, and Verifier.

Core objects:
- SSi: camera-signed segment descriptor
- ERa,i: encrypted evidence record
- Checkpoint: signed Merkle checkpoint over posting-list digests
- SearchResponse: posting lists + Merkle proofs + checkpoint
- EvidencePackage: offline verification package
"""
from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, Field


                                                                             
                                  
                                                                             

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _u64(x: int) -> bytes:
    if x < 0:
        raise ValueError("integer must be non-negative")
    return x.to_bytes(8, "big")


def _lp(data: bytes) -> bytes:
    """Length-prefix encoding to avoid ambiguous concatenation."""
    return len(data).to_bytes(8, "big") + data


def hash_parts(domain: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_lp(domain))
    for p in parts:
        h.update(_lp(p))
    return h.digest()


def encode_mu(cid: str, sid: str, seq: int, timestamp: int) -> bytes:
    """
    μi = (cid, sidi, seqi, ti)
    """
    return b"".join(
        [
            _lp(cid.encode("utf-8")),
            _lp(sid.encode("utf-8")),
            _lp(_u64(seq)),
            _lp(_u64(timestamp)),
        ]
    )


def payload_hash(raw_payload: bytes) -> bytes:
    """
    hi = H(mi)
    """
    return sha256(raw_payload)


def camera_chain_hash(
    cid: str,
    sid: str,
    seq: int,
    timestamp: int,
    hi: bytes,
    gamma_prev: bytes,
) -> bytes:
    """
    γi = H(μi || hi || γi-1)
    """
    return hash_parts(
        b"CamShield.camera.chain.v1",
        encode_mu(cid, sid, seq, timestamp),
        hi,
        gamma_prev,
    )


CHECKPOINT_CHAIN_GENESIS = b"\x00" * 32


def compute_checkpoint_chain_value(
    epoch: int,
    version: int,
    timestamp: int,
    root: bytes,
    prev_chain: bytes,
) -> bytes:
    """
    χ_{e,v} = H(e || v || tv || Ω_{e,v} || χ_{e,v-1})
    """
    return hash_parts(
        b"CamShield.index.checkpoint.chain.v1",
        _u64(epoch),
        _u64(version),
        _u64(timestamp),
        root,
        prev_chain,
    )


def compute_posting_digest(record_ids: list[bytes]) -> bytes:
    """
    λτ^v = H(Sort(PLτ^v))

    record_ids are protocol-level ridi values, encoded as bytes.
    """
    return hash_parts(
        b"CamShield.posting.digest.v1",
        *sorted(record_ids),
    )


def checkpoint_leaf_data(token: bytes, posting_digest: bytes, version: int) -> bytes:
    """
    Leaf data for Merkle checkpoint:
        leafτ = (τ, λτ^v, v)

    Note:
    core/merkle.py hashes each leaf internally, so this function returns the
    raw leaf payload, not H(leaf).
    """
    return b"".join(
        [
            _lp(b"CamShield.index.leaf.v1"),
            _lp(token),
            _lp(posting_digest),
            _lp(_u64(version)),
        ]
    )


                                                                             
                     
                                                                             

class SegmentDescriptor(BaseModel):
    """
    SSi = (μi, hi, γi-1, γi, σi)

    This object does not contain the raw video payload mi.
    It is the camera-side provenance descriptor.
    """

    cid: str
    sid: str
    seq: int
    timestamp: int

    hi: bytes
    gamma_prev: bytes
    gamma: bytes
    sigma_c: bytes

    model_config = {"arbitrary_types_allowed": True}

    def mu_bytes(self) -> bytes:
        return encode_mu(self.cid, self.sid, self.seq, self.timestamp)

    def expected_gamma(self) -> bytes:
        return camera_chain_hash(
            cid=self.cid,
            sid=self.sid,
            seq=self.seq,
            timestamp=self.timestamp,
            hi=self.hi,
            gamma_prev=self.gamma_prev,
        )


class CameraSignedSegment(BaseModel):
    """
    Camera output:
        C -> G : (mi, SSi)

    raw_payload is mi.
    Other fields are the camera-signed descriptor SSi.
    """

    cid: str
    sid: str
    seq: int
    timestamp: int

    raw_payload: bytes

    hi: bytes
    gamma_prev: bytes
    gamma: bytes
    sigma_c: bytes

    model_config = {"arbitrary_types_allowed": True}

    def descriptor(self) -> SegmentDescriptor:
        return SegmentDescriptor(
            cid=self.cid,
            sid=self.sid,
            seq=self.seq,
            timestamp=self.timestamp,
            hi=self.hi,
            gamma_prev=self.gamma_prev,
            gamma=self.gamma,
            sigma_c=self.sigma_c,
        )


                                                                             
                                   
                                                                             

class EncryptedEvidenceRecord(BaseModel):
    """
    ERa,i = (
        ridi,
        SSi,
        a,
        e,
        ci,
        κa,e,
        pa,e,
        qi,
        ba,i,
        ηa,i
    )

    In implementation:
    - ci is represented by (nonce, ciphertext, tag)
    - κa,e is kappa
    - pa,e is policy_digest
    - ua,e is capsule_digest
    - qi is index_digest
    - ba,i is binding_hash
    - ηa,i is gateway_signature
    """

    rid: bytes
    SSi: SegmentDescriptor

                                                               
    a: str

              
    epoch: int

                            
    nonce: bytes
    ciphertext: bytes
    tag: bytes

                                                     
    kappa: bytes
    policy: str

                    
    policy_digest: bytes

                    
    capsule_digest: bytes

                   
    index_tokens: list[bytes] = Field(default_factory=list)

                        
    index_digest: bytes

          
    binding_hash: bytes

                           
    gateway_signature: bytes

    model_config = {"arbitrary_types_allowed": True}

    def ciphertext_blob(self) -> bytes:
        """
        Implementation representation of ci.

        Binding uses H(ci). Since AES-GCM output is stored as
        nonce + ciphertext + tag, we bind all three.
        """
        return self.nonce + self.ciphertext + self.tag

    def ciphertext_digest(self) -> bytes:
        return sha256(self.ciphertext_blob())

    def expected_index_digest(self) -> bytes:
        return hash_parts(
            b"CamShield.index.digest.v1",
            *sorted(self.index_tokens),
        )

    def expected_policy_digest(self) -> bytes:
        return sha256(self.policy.encode("utf-8"))

    def expected_capsule_digest(self) -> bytes:
        return sha256(self.kappa)

    def descriptor_hash(self) -> bytes:
        """H(VPi) over the camera-signed descriptor fields."""
        return hash_parts(
            b"CamShield.vpi.v1",
            self.SSi.mu_bytes(),
            self.SSi.hi,
            self.SSi.gamma_prev,
            self.SSi.gamma,
            self.SSi.sigma_c,
        )

    def is_live_record(self) -> bool:
        return not self.index_tokens and self.index_digest == b""

    def compute_binding_hash(self) -> bytes:
        """
        ba,i = H(
            ridi || γi || H(ci) || qi || pa,e || ua,e
            || a || e || cid || sidi || seqi
        )
        """
        return hash_parts(
            b"CamShield.record.binding.v1",
            self.rid,
            self.SSi.gamma,
            self.ciphertext_digest(),
            self.index_digest,
            self.policy_digest,
            self.capsule_digest,
            self.a.encode("utf-8"),
            _u64(self.epoch),
            self.SSi.cid.encode("utf-8"),
            self.SSi.sid.encode("utf-8"),
            _u64(self.SSi.seq),
        )

    def compute_live_binding_hash(self) -> bytes:
        """
        blive_a,i = H(
            ridi || H(VPi) || H(ci) || pa,e || ua,e
            || a || e || cid || sidi || seqi || live
        )
        """
        return hash_parts(
            b"CamShield.record.live-binding.v1",
            self.rid,
            self.descriptor_hash(),
            self.ciphertext_digest(),
            self.policy_digest,
            self.capsule_digest,
            self.a.encode("utf-8"),
            _u64(self.epoch),
            self.SSi.cid.encode("utf-8"),
            self.SSi.sid.encode("utf-8"),
            _u64(self.SSi.seq),
            b"live",
        )

    def expected_binding_hash(self) -> bytes:
        if self.is_live_record():
            return self.compute_live_binding_hash()
        return self.compute_binding_hash()

    def core_fields_bytes(self) -> bytes:
        """
        Alias for compute_binding_hash().
        """
        return self.compute_binding_hash()


                                                                             
                           
                                                                             

class MerkleProofData(BaseModel):
    leaf_index: int
    leaf_hash: bytes
    siblings: list[tuple[str, bytes]]
    root: bytes

    model_config = {"arbitrary_types_allowed": True}


class PostingListData(BaseModel):
    """
    A returned encrypted posting list for a token τ.
    """

    token: bytes
    record_ids: list[bytes] = Field(default_factory=list)
    posting_digest: bytes

    model_config = {"arbitrary_types_allowed": True}

    def expected_digest(self) -> bytes:
        return compute_posting_digest(self.record_ids)

    def checkpoint_leaf_data(self, version: int) -> bytes:
        return checkpoint_leaf_data(self.token, self.posting_digest, version)


class PostingListProof(BaseModel):
    """
    Merkle proof that (τ, λτ^v, v) belongs to checkpoint root Ωe,v.
    """

    token: bytes
    posting_digest: bytes
    proof: MerkleProofData

    model_config = {"arbitrary_types_allowed": True}


class IndexCheckpoint(BaseModel):
    """
    Checkpoint = (e, v, tv, Ωe,v, χe,v, Ψe,v)

    Ψe,v = Sign_skG(e || v || tv || Ωe,v || χe,v)
    """

    epoch: int
    version: int
    timestamp: int
    root: bytes
    chain_value: bytes = Field(default_factory=lambda: CHECKPOINT_CHAIN_GENESIS)
    gateway_signature: bytes

    model_config = {"arbitrary_types_allowed": True}

    def signed_bytes(self) -> bytes:
        return b"".join(
            [
                _lp(b"CamShield.index.checkpoint.v1"),
                _lp(_u64(self.epoch)),
                _lp(_u64(self.version)),
                _lp(_u64(self.timestamp)),
                _lp(self.root),
                _lp(self.chain_value),
            ]
        )


                                                                             
                         
                                                                             

class SearchRequest(BaseModel):
    query_tokens: list[bytes]
    operator: str = "AND"
    epoch: int

    model_config = {"arbitrary_types_allowed": True}


class SearchResponse(BaseModel):
    """
    Cloud response to encrypted search.

    Cloud returns:
    - result_record_ids
    - posting lists for the query tokens
    - ordered Merkle membership / non-membership proofs
    - signed ordered checkpoint
    """

    result_record_ids: list[bytes]
    operator: str
    query_token_count: int
    epoch: int

    postings: list[PostingListData] = Field(default_factory=list)
    proofs: list[PostingListProof] = Field(default_factory=list)
    checkpoint: IndexCheckpoint

    signed_checkpoint: dict[str, Any] | None = None
    membership_proofs: dict[str, Any] = Field(default_factory=dict)
    non_membership_proofs: dict[str, Any] = Field(default_factory=dict)
    postings_hex: dict[str, list[str]] = Field(default_factory=dict)
    query_token_ids_hex: list[str] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    def proof_for_token(self, token: bytes) -> PostingListProof | None:
        for proof in self.proofs:
            if proof.token == token:
                return proof
        return None

    def posting_for_token(self, token: bytes) -> PostingListData | None:
        for posting in self.postings:
            if posting.token == token:
                return posting
        return None


                                                                             
                                      
                                                                             

class ClientTrustMaterial(BaseModel):
    """
    Client trust anchors.

    No Authority exists in this protocol.
    The client only needs camera and gateway public keys plus freshness floors.
    """

    role_name: str
    camera_public_key_bytes: bytes
    gateway_public_key_bytes: bytes

    min_epoch: int = 1
    min_checkpoint_version: int = 0

    model_config = {"arbitrary_types_allowed": True}


class ClientSessionState(BaseModel):
    """
    Client local freshness cursor.

    Tracks the highest checkpoint version and chain value seen per epoch.
    """

    last_checkpoint_versions: dict[int, int] = Field(default_factory=dict)
    last_chain_values: dict[int, bytes] = Field(default_factory=dict)

    model_config = {"arbitrary_types_allowed": True}

    def last_version(self, epoch: int, floor: int = 0) -> int:
        return max(floor, self.last_checkpoint_versions.get(epoch, floor))

    def last_chain_value(self, epoch: int) -> bytes:
        return self.last_chain_values.get(epoch, CHECKPOINT_CHAIN_GENESIS)

    def advance(self, epoch: int, version: int, chain_value: bytes) -> None:
        self.last_checkpoint_versions[epoch] = max(
            self.last_checkpoint_versions.get(epoch, 0),
            version,
        )
        self.last_chain_values[epoch] = chain_value


class SearchVerifyResult(BaseModel):
    ok: bool
    message: str
    epoch: int = 0
    checkpoint_version: int = 0
    result_count: int = 0

    model_config = {"arbitrary_types_allowed": True}


                                                                             
                  
                                                                             

class EvidencePackage(BaseModel):
    """
    Offline verification package.

    A verifier can check:
    - camera descriptor signature
    - gateway record binding signature
    - checkpoint signature
    - posting-list Merkle proof
    - optional plaintext hash after decryption
    """

    record: EncryptedEvidenceRecord
    checkpoint: IndexCheckpoint
    posting_proof: PostingListProof | None = None
    query_token: bytes | None = None
    plaintext_hash: bytes | None = None

    model_config = {"arbitrary_types_allowed": True}


                                                                             
                                       
                                                                             
                                               
             
                    
                  
                     
                          
 
                                                                             
                       
