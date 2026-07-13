"""CamShield client: search, verify, decrypt."""
from __future__ import annotations

from typing import Any

from core import aes_gcm, merkle
from core.cloud_ordered import (
    verify_ordered_checkpoint_chain,
    verify_ordered_checkpoint_signature,
    verify_ordered_membership_proof,
    verify_ordered_non_membership_proof,
)
from core.abe import CPABEBase
from core.ed25519_sig import load_public_key, verify
from core.epoch import derive_record_key
from core.models import (
    CameraSignedSegment,
    CHECKPOINT_CHAIN_GENESIS,
    ClientSessionState,
    ClientTrustMaterial,
    EncryptedEvidenceRecord,
    EvidencePackage,
    IndexCheckpoint,
    MerkleProofData,
    PostingListData,
    PostingListProof,
    SearchRequest,
    SearchResponse,
    SearchVerifyResult,
    camera_chain_hash,
    checkpoint_leaf_data,
    compute_checkpoint_chain_value,
    compute_posting_digest,
    payload_hash,
)


def _derive_record_key(EKe: bytes, rid: bytes, epoch: int) -> bytes:
    return derive_record_key(EKe, rid, epoch)


class Client:
    role_name: str = "Client"
    attributes: list[str] = []
    client_id: str = "owner"

    def __init__(
        self,
        abe_sk: Any,
        abe: CPABEBase,
        trust: ClientTrustMaterial,
    ):
        self.abe_sk = abe_sk
        self.abe = abe
        self.trust = trust

        self.camera_pk = load_public_key(trust.camera_public_key_bytes)
        self.gateway_pk = load_public_key(trust.gateway_public_key_bytes)

        self.session = ClientSessionState()
        self.last_verify_result: SearchVerifyResult | None = None
        self.cap_u: dict | None = None

    def attach_cap_u(self, cap_u: dict) -> None:
        """Attach Cap_u (with IdxCap_u) for offline tag-based retrieval."""
        self.cap_u = cap_u

    @classmethod
    def create(cls, gateway: Any, abe: CPABEBase) -> "Client":
        """
        Create a client through Gateway bootstrap.

        Your Gateway should implement:
            issue_client_bootstrap(role_name, attributes) -> (ClientTrustMaterial, abe_sk)

        This replaces the old Authority-based bootstrap.
        """
        trust, abe_sk = gateway.issue_client_bootstrap(cls.role_name, cls.attributes)
        return cls(abe_sk=abe_sk, abe=abe, trust=trust)

                                                                        
                           
                                                                        

    def request_search_tokens(
        self,
        gateway: Any,
        keywords: list[str],
        epoch: int,
        camera_id: str,
    ) -> list[bytes]:
        """
        Obtain epoch-specific query tokens.

        Default: derive offline from IdxCap_u in Cap_u (leased mode).
        Fallback: request tokens from Gateway (/search-tokens on-demand mode).
        """
        if self.cap_u and self.cap_u.get("IdxCap_u"):
            from core.idx_cap_u import search_tokens_from_cap_u

            gw_ver = getattr(gateway, "epoch_manager", None)
            version = (
                gw_ver.current_version()
                if gw_ver is not None
                else None
            )
            return search_tokens_from_cap_u(
                self.cap_u,
                client_id=self.client_id,
                camera_id=camera_id,
                epoch=epoch,
                keywords=keywords,
                gateway_version=version,
            )

        return gateway.issue_search_tokens(
            user_attrs=self.attributes,
            keywords=keywords,
            epoch=epoch,
            camera_id=camera_id,
            client_id=self.client_id,
        )

    def search(
        self,
        gateway: Any,
        cloud: Any,
        keywords: list[str],
        epoch: int,
        operator: str = "AND",
        camera_id: str = "cam01",
    ) -> SearchResponse:
        tokens = self.request_search_tokens(gateway, keywords, epoch, camera_id)
        request = SearchRequest(
            query_tokens=tokens,
            operator=operator,
            epoch=epoch,
        )
        return cloud.search(request)

                                                                        
                                  
                                                                        

    def verify_search_response(self, response: SearchResponse) -> tuple[bool, str]:
        result = self.verify_search_response_detailed(response)
        self.last_verify_result = result
        return result.ok, result.message

    def verify_search_response_detailed(self, response: SearchResponse) -> SearchVerifyResult:
        if response.signed_checkpoint is not None:
            ok, msg = self._verify_ordered_search_response(response)
            if not ok:
                return SearchVerifyResult(ok=False, message=msg)

            cp = response.signed_checkpoint
            self.session.advance(
                int(cp["epoch"]),
                int(cp["version"]),
                bytes.fromhex(str(cp["chain_hex"])),
            )
            return SearchVerifyResult(
                ok=True,
                message="ok",
                epoch=int(cp["epoch"]),
                checkpoint_version=int(cp["version"]),
                result_count=len(response.result_record_ids),
            )

        ok, msg = self._verify_checkpoint(response.checkpoint)
        if not ok:
            return SearchVerifyResult(ok=False, message=msg)

        ok, msg = self._verify_posting_list_proofs(response)
        if not ok:
            return SearchVerifyResult(ok=False, message=msg)

        ok, msg = self._verify_result_integrity(response)
        if not ok:
            return SearchVerifyResult(ok=False, message=msg)

        self.session.advance(
            response.checkpoint.epoch,
            response.checkpoint.version,
            response.checkpoint.chain_value,
        )

        return SearchVerifyResult(
            ok=True,
            message="ok",
            epoch=response.checkpoint.epoch,
            checkpoint_version=response.checkpoint.version,
            result_count=len(response.result_record_ids),
        )

    def _verify_ordered_search_response(self, response: SearchResponse) -> tuple[bool, str]:
        signed = response.signed_checkpoint
        if signed is None:
            return False, "missing signed ordered checkpoint"

        if int(signed.get("epoch", -1)) != int(response.epoch):
            return False, "Search response epoch does not match checkpoint epoch"

        if int(signed.get("epoch", -1)) < self.trust.min_epoch:
            return False, "Checkpoint epoch is below trusted minimum"

        floor = self.session.last_version(
            int(signed["epoch"]),
            floor=self.trust.min_checkpoint_version,
        )
        if int(signed.get("version", 0)) < floor:
            return False, "Cloud misbehavior detected: checkpoint rollback"

        prev_chain = CHECKPOINT_CHAIN_GENESIS
        if int(signed.get("version", 0)) > 1:
            prev_chain = self.session.last_chain_value(int(signed["epoch"]))

        ok, msg = verify_ordered_checkpoint_chain(
            signed,
            prev_chain=prev_chain,
        )
        if not ok:
            return False, msg

        ok, msg = verify_ordered_checkpoint_signature(signed)
        if not ok:
            return False, msg

        root_hex = str(signed["root_hex"])
        query_tokens = list(response.query_token_ids_hex)
        if not query_tokens:
            return False, "missing query token ids for ordered proof verification"

        if len(query_tokens) != response.query_token_count:
            return False, "Cloud misbehavior detected: incomplete query token set"

        for token_hex in query_tokens:
            posting = response.postings_hex.get(token_hex, [])
            if posting:
                proof = response.membership_proofs.get(token_hex)
                if not proof:
                    return False, f"Missing membership proof for token {token_hex[:16]}"
                ok, msg = verify_ordered_membership_proof(
                    root_hex=root_hex,
                    token_hex=token_hex,
                    posting_record_ids=posting,
                    proof=proof,
                )
                if not ok:
                    return False, msg
            else:
                proof = response.non_membership_proofs.get(token_hex)
                if not proof:
                    return False, f"Missing non-membership proof for token {token_hex[:16]}"
                ok, msg = verify_ordered_non_membership_proof(
                    root_hex=root_hex,
                    token_hex=token_hex,
                    proof=proof,
                )
                if not ok:
                    return False, msg

        posting_sets = [
            set(response.postings_hex.get(token_hex, []))
            for token_hex in query_tokens
        ]
        op = response.operator.upper()
        if op == "OR":
            expected = sorted(set().union(*posting_sets) if posting_sets else set())
        elif op == "AND":
            expected = sorted(set.intersection(*posting_sets) if posting_sets else set())
        else:
            return False, f"Unsupported search operator: {response.operator}"

        actual = sorted(rid.hex() for rid in response.result_record_ids)
        if actual != expected:
            return False, "Cloud misbehavior detected: incorrect search result"

        return True, "ok"

    def _verify_checkpoint(self, checkpoint: IndexCheckpoint) -> tuple[bool, str]:
        """
        Verify:
            Ψe,v = Sign_skG(e || v || tv || Ωe,v || χe,v)

        Also check rollback against local session cursor and chain continuity.
        """
        if checkpoint.epoch < self.trust.min_epoch:
            return False, "Checkpoint epoch is below trusted minimum"

        floor = self.session.last_version(
            checkpoint.epoch,
            floor=self.trust.min_checkpoint_version,
        )
        if checkpoint.version < floor:
            return False, "Cloud misbehavior detected: checkpoint rollback"

        prev_chain = CHECKPOINT_CHAIN_GENESIS
        if checkpoint.version > 1:
            prev_chain = self.session.last_chain_value(checkpoint.epoch)

        expected_chain = compute_checkpoint_chain_value(
            epoch=checkpoint.epoch,
            version=checkpoint.version,
            timestamp=checkpoint.timestamp,
            root=checkpoint.root,
            prev_chain=prev_chain,
        )
        if expected_chain != checkpoint.chain_value:
            return False, "Invalid checkpoint chain value"

        if not verify(self.gateway_pk, checkpoint.signed_bytes(), checkpoint.gateway_signature):
            return False, "Invalid gateway checkpoint signature"

        return True, "ok"

    def _verify_posting_list_proofs(self, response: SearchResponse) -> tuple[bool, str]:
        """
        Verify each returned posting list against the signed checkpoint root.

        For each token τ:
            λτ^v = H(Sort(PLτ^v))
            leaf = (τ, λτ^v, v)
            Verify MerkleProof(leaf, Ωe,v)
        """
        cp = response.checkpoint

        if response.epoch != cp.epoch:
            return False, "Search response epoch does not match checkpoint epoch"

                                                                                   
                                                                            
        if len(response.postings) != response.query_token_count:
            return False, "Cloud misbehavior detected: incomplete posting lists"

        seen_tokens: set[bytes] = set()

        for posting in response.postings:
            if posting.token in seen_tokens:
                return False, "Duplicate posting list returned"
            seen_tokens.add(posting.token)

            expected_digest = compute_posting_digest(posting.record_ids)
            if posting.posting_digest != expected_digest:
                return False, "Invalid posting-list digest"

            proof_obj = response.proof_for_token(posting.token)
            if proof_obj is None:
                return False, "Missing Merkle proof for posting list"

            if proof_obj.posting_digest != posting.posting_digest:
                return False, "Posting proof digest does not match posting list"

            leaf_data = checkpoint_leaf_data(
                token=posting.token,
                posting_digest=posting.posting_digest,
                version=cp.version,
            )

            proof = merkle.MerkleProof(
                leaf_index=proof_obj.proof.leaf_index,
                leaf_hash=proof_obj.proof.leaf_hash,
                siblings=proof_obj.proof.siblings,
                root=proof_obj.proof.root,
            )

            if proof.root != cp.root:
                return False, "Merkle proof root does not match checkpoint root"

            if not merkle.verify_merkle_proof(leaf_data, proof):
                return False, "Invalid Merkle proof for posting list"

        return True, "ok"

    def _verify_result_integrity(self, response: SearchResponse) -> tuple[bool, str]:
        """
        Recompute AND/OR result locally from returned posting lists.

        This detects omission/substitution among the returned posting lists.
        """
        posting_sets: list[set[bytes]] = [set(p.record_ids) for p in response.postings]

        op = response.operator.upper()
        if op == "OR":
            expected = sorted(set().union(*posting_sets) if posting_sets else set())
        elif op == "AND":
            expected = sorted(set.intersection(*posting_sets) if posting_sets else set())
        else:
            return False, f"Unsupported search operator: {response.operator}"

        if sorted(response.result_record_ids) != expected:
            return False, "Cloud misbehavior detected: incorrect search result"

        return True, "ok"

                                                                        
                         
                                                                        

    def verify_segment_descriptor(self, segment: CameraSignedSegment) -> tuple[bool, str]:
        """
        Verify camera output (mi, SSi).

        Used when the client/verifier has access to plaintext mi.
        """
        hi = payload_hash(segment.raw_payload)
        if hi != segment.hi:
            return False, "Invalid payload hash"

        gamma = camera_chain_hash(
            cid=segment.cid,
            sid=segment.sid,
            seq=segment.seq,
            timestamp=segment.timestamp,
            hi=segment.hi,
            gamma_prev=segment.gamma_prev,
        )
        if gamma != segment.gamma:
            return False, "Invalid camera hash-chain value"

        if not verify(self.camera_pk, segment.gamma, segment.sigma_c):
            return False, "Invalid camera signature"

        return True, "ok"

    def verify_record_descriptor(self, record: EncryptedEvidenceRecord) -> tuple[bool, str]:
        """
        Verify SSi inside encrypted evidence record.

        This checks descriptor consistency and camera signature.
        It cannot check H(mi) == hi until decryption reveals mi.
        """
        SSi = record.SSi

        expected_gamma = camera_chain_hash(
            cid=SSi.cid,
            sid=SSi.sid,
            seq=SSi.seq,
            timestamp=SSi.timestamp,
            hi=SSi.hi,
            gamma_prev=SSi.gamma_prev,
        )
        if expected_gamma != SSi.gamma:
            return False, "Invalid camera descriptor hash-chain value"

        if not verify(self.camera_pk, SSi.gamma, SSi.sigma_c):
            return False, "Invalid camera descriptor signature"

        return True, "ok"

    def verify_record(self, record: EncryptedEvidenceRecord) -> tuple[bool, str]:
        """
        Verify ERa,i.

        Checks:
        - camera descriptor SSi
        - pa,e = H(policy)
        - ua,e = H(kappa)
        - qi = H(Sort(Ti^e))
        - ba,i record binding
        - ηa,i Gateway signature
        """
        ok, msg = self.verify_record_descriptor(record)
        if not ok:
            return ok, msg

        if record.expected_policy_digest() != record.policy_digest:
            return False, "Invalid policy digest"

        if record.expected_capsule_digest() != record.capsule_digest:
            return False, "Invalid capsule digest"

        if not record.is_live_record():
            if record.expected_index_digest() != record.index_digest:
                return False, "Invalid index digest"

        expected_binding = record.expected_binding_hash()
        if expected_binding != record.binding_hash:
            return False, "Invalid record binding hash"

        if not verify(self.gateway_pk, record.binding_hash, record.gateway_signature):
            return False, "Invalid gateway record signature"

        return True, "ok"

    def fetch_and_verify_record(
        self,
        cloud: Any,
        record_id: bytes,
    ) -> tuple[EncryptedEvidenceRecord | None, str]:
        rec = cloud.get_record(record_id)
        if rec is None:
            return None, "Cloud misbehavior detected: record unavailable"

        ok, msg = self.verify_record(rec)
        if not ok:
            return None, msg

        return rec, "ok"

                                                                        
                
                                                                        

    def decrypt_record(self, record: EncryptedEvidenceRecord) -> tuple[bytes | None, str]:
        """
        Decrypt ERa,i.

        Decryption:
            EKe = ABE.Dec(SKu, κa,e)
            ki = KDF(EKe, ridi || e)
            mi = AE.Dec_ki(ci, aadi)
        """
        ok, msg = self.verify_record(record)
        if not ok:
            return None, msg

        EKe = self.abe.decrypt(self.abe_sk, record.kappa)
        if EKe is None:
            return None, "CP-ABE decrypt failed: policy not satisfied"

        ki = _derive_record_key(EKe, record.rid, record.epoch)

        associated_data = aes_gcm.build_associated_data(
            rid=record.rid,
            cid=record.SSi.cid,
            sid=record.SSi.sid,
            seq=record.SSi.seq,
            timestamp=record.SSi.timestamp,
            epoch=record.epoch,
            gamma=record.SSi.gamma,
        )

        try:
            plaintext = aes_gcm.decrypt(
                ki,
                record.ciphertext,
                record.nonce,
                record.tag,
                associated_data,
            )
        except Exception:
            return None, "AES-GCM decrypt failed"

        if payload_hash(plaintext) != record.SSi.hi:
            return None, "Decrypted payload hash does not match camera descriptor"

        return plaintext, "ok"

                                                                        
                      
                                                                        

    def build_evidence_package(
        self,
        record: EncryptedEvidenceRecord,
        checkpoint: IndexCheckpoint,
        posting_proof: PostingListProof | None = None,
        query_token: bytes | None = None,
        plaintext: bytes | None = None,
    ) -> EvidencePackage:
        return EvidencePackage(
            record=record,
            checkpoint=checkpoint,
            posting_proof=posting_proof,
            query_token=query_token,
            plaintext_hash=payload_hash(plaintext) if plaintext is not None else None,
        )