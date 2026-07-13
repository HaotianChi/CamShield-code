"""CamShield Cloud: encrypted storage and searchable index."""

from __future__ import annotations

import base64
import time
from typing import Any

from core.cloud_ordered import (
    build_signed_ordered_checkpoint,
    execute_ordered_search,
    merge_record_tokens,
)
from core.models import (
    CHECKPOINT_CHAIN_GENESIS,
    EncryptedEvidenceRecord,
    IndexCheckpoint,
    SearchRequest,
    SearchResponse,
)
from core.ordered_merkle import OrderedMerkleSnapshot


class Cloud:
    role_name = "Cloud"

    def __init__(self) -> None:
        self.records: dict[bytes, EncryptedEvidenceRecord] = {}
        self.token_to_record_ids: dict[str, list[str]] = {}
        self.snapshot: OrderedMerkleSnapshot | None = None
        self.latest_signed_checkpoint: dict[str, Any] | None = None
        self.ordered_checkpoint_version: int = 0
        self.last_chain_by_epoch: dict[int, bytes] = {}
        self.final_epoch_checkpoints: dict[int, dict[str, Any]] = {}
        self.latest_versions: dict[int, int] = {}

    def store_record(self, record: EncryptedEvidenceRecord) -> None:
        """Store one encrypted evidence record and update the encrypted index."""
        self.records[record.rid] = record
        self.token_to_record_ids = merge_record_tokens(
            self.token_to_record_ids,
            index_tokens=record.index_tokens,
            rid_hex=record.rid.hex(),
        )

    def store_live_record(self, record: EncryptedEvidenceRecord) -> None:
        """Store a live encrypted record (LER) without updating the inverted index."""
        self.records[record.rid] = record

    def store_records(self, records: list[EncryptedEvidenceRecord]) -> None:
        for record in records:
            self.store_record(record)

    def get_record(self, rid: bytes) -> EncryptedEvidenceRecord | None:
        return self.records.get(rid)

    def get_records(self, rids: list[bytes]) -> list[EncryptedEvidenceRecord]:
        return [self.records[rid] for rid in rids if rid in self.records]

    def build_checkpoint(
        self,
        gateway: Any,
        epoch: int,
        version: int | None = None,
        timestamp: int | None = None,
    ) -> IndexCheckpoint:
        """
        Build a Gateway-signed ordered Merkle checkpoint over the current index.

        The returned IndexCheckpoint mirrors the ordered checkpoint root and chain
        for in-process client session tracking.
        """
        self.ordered_checkpoint_version += 1
        cp_version = (
            int(version)
            if version is not None
            else self.ordered_checkpoint_version
        )
        prev_chain = self.last_chain_by_epoch.get(epoch, CHECKPOINT_CHAIN_GENESIS)

        signed_checkpoint, snapshot = build_signed_ordered_checkpoint(
            gateway,
            epoch=epoch,
            token_to_record_ids=self.token_to_record_ids,
            version=cp_version,
            prev_chain=prev_chain,
            timestamp=timestamp,
        )

        self.snapshot = snapshot
        self.latest_signed_checkpoint = signed_checkpoint
        self.last_chain_by_epoch[epoch] = bytes.fromhex(
            str(signed_checkpoint["chain_hex"])
        )
        self.latest_versions[epoch] = max(
            self.latest_versions.get(epoch, 0),
            cp_version,
        )

        return IndexCheckpoint(
            epoch=int(signed_checkpoint["epoch"]),
            version=int(signed_checkpoint["version"]),
            timestamp=int(signed_checkpoint["timestamp"]),
            root=bytes.fromhex(str(signed_checkpoint["root_hex"])),
            chain_value=bytes.fromhex(str(signed_checkpoint["chain_hex"])),
            gateway_signature=base64.b64decode(
                str(signed_checkpoint["signature_b64"])
            ),
        )

    def close_epoch(self, epoch: int) -> dict[str, Any] | None:
        """Finalize the latest signed checkpoint for a closed epoch."""
        if self.latest_signed_checkpoint is None:
            return None
        if int(self.latest_signed_checkpoint.get("epoch", -1)) != int(epoch):
            checkpoint = self.latest_checkpoint_dict(epoch)
            if checkpoint is None:
                return None
            self.final_epoch_checkpoints[epoch] = checkpoint
            return checkpoint

        self.final_epoch_checkpoints[epoch] = dict(self.latest_signed_checkpoint)
        return self.final_epoch_checkpoints[epoch]

    def latest_checkpoint(self, epoch: int) -> IndexCheckpoint:
        signed = self.latest_checkpoint_dict(epoch)
        if signed is None:
            raise RuntimeError(f"No checkpoint exists for epoch {epoch}")
        return IndexCheckpoint(
            epoch=int(signed["epoch"]),
            version=int(signed["version"]),
            timestamp=int(signed["timestamp"]),
            root=bytes.fromhex(str(signed["root_hex"])),
            chain_value=bytes.fromhex(str(signed["chain_hex"])),
            gateway_signature=b"",
        )

    def latest_checkpoint_dict(self, epoch: int) -> dict[str, Any] | None:
        signed = self.latest_signed_checkpoint
        if signed is None:
            return None
        if int(signed.get("epoch", -1)) == int(epoch):
            return signed
        return self.final_epoch_checkpoints.get(epoch)

    def search(self, request: SearchRequest) -> SearchResponse:
        """
        Search the encrypted inverted index using ordered Merkle proofs.

        Returns membership proofs for indexed tokens and non-membership proofs
        for absent tokens, matching the deployment Cloud HTTP service.
        """
        if self.snapshot is None or self.latest_signed_checkpoint is None:
            raise RuntimeError("no checkpoint")

        signed = self.latest_signed_checkpoint
        if int(signed.get("epoch", -1)) != int(request.epoch):
            raise RuntimeError(
                f"latest checkpoint is for epoch {signed.get('epoch')}, "
                f"requested epoch {request.epoch}"
            )

        query_token_ids_hex = [token.hex() for token in request.query_tokens]
        search_data = execute_ordered_search(
            snapshot=self.snapshot,
            token_to_record_ids=self.token_to_record_ids,
            query_token_ids=query_token_ids_hex,
            operator=request.operator,
        )

        if str(search_data["checkpoint_root_hex"]) != str(signed["root_hex"]):
            raise RuntimeError("ordered checkpoint root mismatch during search")

        return SearchResponse(
            result_record_ids=[
                bytes.fromhex(rid) for rid in search_data["result_record_ids"]
            ],
            operator=str(search_data["operator"]),
            query_token_count=len(query_token_ids_hex),
            epoch=int(request.epoch),
            signed_checkpoint=signed,
            membership_proofs=search_data["membership_proofs"],
            non_membership_proofs=search_data["non_membership_proofs"],
            postings_hex=search_data["postings"],
            query_token_ids_hex=query_token_ids_hex,
            checkpoint=self.latest_checkpoint(request.epoch),
        )

    def delete_record_without_index_update(self, rid: bytes) -> None:
        """Attack helper: remove record object but keep posting list entries."""
        self.records.pop(rid, None)

    def tamper_record(self, rid: bytes, tampered_record: EncryptedEvidenceRecord) -> None:
        """Attack helper: replace a stored record."""
        self.records[rid] = tampered_record

    def remove_rid_from_current_index(self, epoch: int, token: bytes, rid: bytes) -> None:
        """Attack helper: remove a record id from the current mutable index."""
        _ = epoch
        token_hex = token.hex()
        rid_hex = rid.hex()
        if token_hex in self.token_to_record_ids:
            self.token_to_record_ids[token_hex] = [
                x for x in self.token_to_record_ids[token_hex] if x != rid_hex
            ]

    def rollback_latest_checkpoint(self, epoch: int, version: int) -> None:
        """Attack helper: force latest version pointer to an older checkpoint."""
        signed = self.final_epoch_checkpoints.get(epoch)
        if signed is None or int(signed.get("version", -1)) != int(version):
            raise KeyError(f"Checkpoint ({epoch}, {version}) does not exist")
        self.latest_signed_checkpoint = dict(signed)
        self.latest_versions[epoch] = int(version)
        from core.ordered_merkle import build_ordered_merkle_snapshot

        self.snapshot = build_ordered_merkle_snapshot(self.token_to_record_ids)
