"""
Ordered-index Cloud helpers shared by in-process Cloud and Gateway upload paths.
"""

from __future__ import annotations

import base64
import time
from typing import Any

from core.ed25519_sig import public_key_bytes, sign
from core.models import CHECKPOINT_CHAIN_GENESIS, compute_checkpoint_chain_value
from core.ordered_merkle import (
    MembershipProof,
    NonMembershipProof,
    OrderedMerkleSnapshot,
    build_ordered_merkle_snapshot,
    make_real_token_id,
)


def canonical_json_bytes(obj: Any) -> bytes:
    import json

    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ordered_checkpoint_signed_bytes(
    *,
    epoch: int,
    version: int,
    timestamp: int,
    root_hex: str,
    chain_hex: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "type": "camshield-ordered-checkpoint-v1",
            "epoch": epoch,
            "version": version,
            "timestamp": timestamp,
            "root_hex": root_hex,
            "chain_hex": chain_hex,
        }
    )


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def merge_record_tokens(
    token_to_record_ids: dict[str, list[str]],
    *,
    index_tokens: list[bytes],
    rid_hex: str,
) -> dict[str, list[str]]:
    updated = {k: list(v) for k, v in token_to_record_ids.items()}
    for token in index_tokens:
        token_hex = token.hex()
        posting = updated.setdefault(token_hex, [])
        if rid_hex not in posting:
            posting.append(rid_hex)
            posting.sort()
    return updated


def build_signed_ordered_checkpoint(
    gateway: Any,
    *,
    epoch: int,
    token_to_record_ids: dict[str, list[str]],
    version: int,
    prev_chain: bytes,
    timestamp: int | None = None,
) -> tuple[dict[str, Any], OrderedMerkleSnapshot]:
    snapshot = build_ordered_merkle_snapshot(token_to_record_ids)
    ts = int(time.time()) if timestamp is None else int(timestamp)
    root_hex = snapshot.root_hex
    chain_value = compute_checkpoint_chain_value(
        epoch=epoch,
        version=version,
        timestamp=ts,
        root=bytes.fromhex(root_hex),
        prev_chain=prev_chain,
    )
    chain_hex = chain_value.hex()
    signed_bytes = ordered_checkpoint_signed_bytes(
        epoch=epoch,
        version=version,
        timestamp=ts,
        root_hex=root_hex,
        chain_hex=chain_hex,
    )
    signature = sign(gateway.skG, signed_bytes)
    signed_checkpoint = {
        "type": "camshield-ordered-checkpoint-v1",
        "epoch": int(epoch),
        "version": int(version),
        "timestamp": ts,
        "root_hex": root_hex,
        "chain_hex": chain_hex,
        "signature_b64": b64e(signature),
        "gateway_public_key_b64": b64e(public_key_bytes(gateway.pkG)),
        "token_count": len(token_to_record_ids),
    }
    return signed_checkpoint, snapshot


def execute_ordered_search(
    *,
    snapshot: OrderedMerkleSnapshot,
    token_to_record_ids: dict[str, list[str]],
    query_token_ids: list[str],
    operator: str,
) -> dict[str, Any]:
    op = str(operator).upper()
    if op not in ("AND", "OR"):
        raise ValueError(f"Unsupported search operator: {operator}")

    membership_proofs: dict[str, Any] = {}
    non_membership_proofs: dict[str, Any] = {}
    postings: dict[str, list[str]] = {}
    posting_sets: list[set[str]] = []

    for raw_query_token in query_token_ids:
        raw_query_token = str(raw_query_token)
        token_id = make_real_token_id(raw_query_token)
        raw_token_hex = (
            raw_query_token[2:]
            if raw_query_token.startswith("1:")
            else raw_query_token
        )

        if token_id in snapshot.leaves and raw_token_hex in token_to_record_ids:
            rid_list = sorted(token_to_record_ids.get(raw_token_hex, []))
            postings[raw_query_token] = rid_list
            membership_proofs[raw_query_token] = snapshot.membership_proof(
                token_id
            ).to_dict()
            posting_sets.append(set(rid_list))
        else:
            postings[raw_query_token] = []
            non_membership_proofs[raw_query_token] = snapshot.non_membership_proof(
                token_id
            ).to_dict()
            posting_sets.append(set())

    if not posting_sets:
        result: set[str] = set()
    elif op == "AND":
        result = set.intersection(*posting_sets)
    else:
        result = set.union(*posting_sets)

    return {
        "operator": op,
        "query_token_ids": list(query_token_ids),
        "result_record_ids": sorted(result),
        "postings": postings,
        "membership_proofs": membership_proofs,
        "non_membership_proofs": non_membership_proofs,
        "checkpoint_root_hex": snapshot.root_hex,
    }


def verify_ordered_checkpoint_signature(cp: dict[str, Any]) -> tuple[bool, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        pk = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(cp["gateway_public_key_b64"])
        )
        sig = base64.b64decode(cp["signature_b64"])
        pk.verify(sig, ordered_checkpoint_signed_bytes(
            epoch=int(cp["epoch"]),
            version=int(cp["version"]),
            timestamp=int(cp["timestamp"]),
            root_hex=str(cp["root_hex"]),
            chain_hex=str(cp["chain_hex"]),
        ))
        return True, "ok"
    except Exception as exc:
        return False, f"checkpoint signature invalid: {exc}"


def verify_ordered_checkpoint_chain(
    cp: dict[str, Any],
    *,
    prev_chain: bytes | None = None,
) -> tuple[bool, str]:
    chain_hex = cp.get("chain_hex")
    if not chain_hex:
        return False, "checkpoint missing chain_hex"

    prev = CHECKPOINT_CHAIN_GENESIS if prev_chain is None else prev_chain
    expected = compute_checkpoint_chain_value(
        epoch=int(cp["epoch"]),
        version=int(cp["version"]),
        timestamp=int(cp["timestamp"]),
        root=bytes.fromhex(str(cp["root_hex"])),
        prev_chain=prev,
    ).hex()
    if expected != chain_hex:
        return False, "checkpoint chain value mismatch"
    return True, "ok"


def verify_ordered_membership_proof(
    *,
    root_hex: str,
    token_hex: str,
    posting_record_ids: list[str],
    proof: dict[str, Any],
) -> tuple[bool, str]:
    from core.ordered_merkle import verify_membership_proof

    return verify_membership_proof(
        root_hex=root_hex,
        token_id=token_hex,
        posting_record_ids=posting_record_ids,
        proof=MembershipProof.from_dict(proof),
    )


def verify_ordered_non_membership_proof(
    *,
    root_hex: str,
    token_hex: str,
    proof: dict[str, Any],
) -> tuple[bool, str]:
    from core.ordered_merkle import verify_non_membership_proof

    return verify_non_membership_proof(
        root_hex=root_hex,
        query_token_id=token_hex,
        proof=NonMembershipProof.from_dict(proof),
    )
