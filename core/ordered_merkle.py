                        
"""
Ordered Merkle tree for CamShield searchable-index checkpoints.

Purpose:
    Support both membership proof and non-membership proof.

Core idea:
    All encrypted search tokens are sorted.
    Each leaf stores:
        token_id
        posting_digest_hex
        next_token_id

    If a token exists:
        Cloud returns the token leaf + Merkle proof.

    If a token does not exist:
        Cloud returns predecessor leaf + successor leaf + their Merkle proofs.
        Client verifies:
            pred.token_id < query_token_id < succ.token_id
            pred.next_token_id == succ.token_id
            pred and succ are both included in the signed Merkle root.

Token ID format:
    MIN sentinel: "0:"
    Real token:   "1:<token_hex>"
    MAX sentinel: "2:"

This makes normal string sorting safe:
    "0:" < "1:..." < "2:"
"""

from __future__ import annotations

import bisect
import hashlib
import json
from dataclasses import dataclass
from typing import Any


MIN_TOKEN_ID = "0:"
MAX_TOKEN_ID = "2:"
EMPTY_POSTING_DIGEST_HEX = hashlib.sha256(b"").hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_real_token_id(token_hex: str) -> str:
    """
    Convert a raw token hex string into ordered-token ID.
    """
    if token_hex.startswith("1:") or token_hex in (MIN_TOKEN_ID, MAX_TOKEN_ID):
        return token_hex
    return "1:" + token_hex


def strip_real_token_id(token_id: str) -> str:
    if token_id.startswith("1:"):
        return token_id[2:]
    return token_id


def posting_digest_hex(record_ids: list[str]) -> str:
    """
    Digest of a posting list.

    record_ids should be hex strings. Sorting makes digest deterministic.
    """
    normalized = sorted(str(x) for x in record_ids)
    return sha256_hex(canonical_json_bytes(normalized))


@dataclass(frozen=True)
class OrderedTokenLeaf:
    token_id: str
    posting_digest_hex: str
    next_token_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "token_id": self.token_id,
            "posting_digest_hex": self.posting_digest_hex,
            "next_token_id": self.next_token_id,
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "OrderedTokenLeaf":
        return OrderedTokenLeaf(
            token_id=str(obj["token_id"]),
            posting_digest_hex=str(obj["posting_digest_hex"]),
            next_token_id=str(obj["next_token_id"]),
        )


@dataclass(frozen=True)
class MerkleSibling:
    side: str
    hash_hex: str

    def to_dict(self) -> dict[str, str]:
        return {
            "side": self.side,
            "hash_hex": self.hash_hex,
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "MerkleSibling":
        return MerkleSibling(
            side=str(obj["side"]),
            hash_hex=str(obj["hash_hex"]),
        )


@dataclass(frozen=True)
class MembershipProof:
    token_id: str
    leaf: OrderedTokenLeaf
    merkle_path: list[MerkleSibling]

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "leaf": self.leaf.to_dict(),
            "merkle_path": [x.to_dict() for x in self.merkle_path],
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "MembershipProof":
        return MembershipProof(
            token_id=str(obj["token_id"]),
            leaf=OrderedTokenLeaf.from_dict(obj["leaf"]),
            merkle_path=[MerkleSibling.from_dict(x) for x in obj["merkle_path"]],
        )


@dataclass(frozen=True)
class NonMembershipProof:
    query_token_id: str
    predecessor_leaf: OrderedTokenLeaf
    predecessor_path: list[MerkleSibling]
    successor_leaf: OrderedTokenLeaf
    successor_path: list[MerkleSibling]

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_token_id": self.query_token_id,
            "predecessor_leaf": self.predecessor_leaf.to_dict(),
            "predecessor_path": [x.to_dict() for x in self.predecessor_path],
            "successor_leaf": self.successor_leaf.to_dict(),
            "successor_path": [x.to_dict() for x in self.successor_path],
        }

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "NonMembershipProof":
        return NonMembershipProof(
            query_token_id=str(obj["query_token_id"]),
            predecessor_leaf=OrderedTokenLeaf.from_dict(obj["predecessor_leaf"]),
            predecessor_path=[MerkleSibling.from_dict(x) for x in obj["predecessor_path"]],
            successor_leaf=OrderedTokenLeaf.from_dict(obj["successor_leaf"]),
            successor_path=[MerkleSibling.from_dict(x) for x in obj["successor_path"]],
        )


@dataclass
class OrderedMerkleSnapshot:
    root_hex: str
    leaves: dict[str, OrderedTokenLeaf]
    sorted_token_ids: list[str]
    paths: dict[str, list[MerkleSibling]]

    def membership_proof(self, token_id: str) -> MembershipProof:
        token_id = make_real_token_id(token_id)
        if token_id not in self.leaves:
            raise KeyError(f"token not found: {token_id}")

        return MembershipProof(
            token_id=token_id,
            leaf=self.leaves[token_id],
            merkle_path=self.paths[token_id],
        )

    def non_membership_proof(self, query_token_id: str) -> NonMembershipProof:
        query_token_id = make_real_token_id(query_token_id)

        if query_token_id in self.leaves:
            raise ValueError(f"token exists, use membership proof: {query_token_id}")

        idx = bisect.bisect_left(self.sorted_token_ids, query_token_id)

        if idx <= 0 or idx >= len(self.sorted_token_ids):
            raise ValueError(f"query token out of sentinel range: {query_token_id}")

        pred_id = self.sorted_token_ids[idx - 1]
        succ_id = self.sorted_token_ids[idx]

        pred_leaf = self.leaves[pred_id]
        succ_leaf = self.leaves[succ_id]

        return NonMembershipProof(
            query_token_id=query_token_id,
            predecessor_leaf=pred_leaf,
            predecessor_path=self.paths[pred_id],
            successor_leaf=succ_leaf,
            successor_path=self.paths[succ_id],
        )


def leaf_hash_hex(leaf: OrderedTokenLeaf) -> str:
    obj = {
        "type": "ordered-token-leaf-v1",
        "token_id": leaf.token_id,
        "posting_digest_hex": leaf.posting_digest_hex,
        "next_token_id": leaf.next_token_id,
    }
    return sha256_hex(canonical_json_bytes(obj))


def parent_hash_hex(left_hex: str, right_hex: str) -> str:
    obj = {
        "type": "ordered-merkle-parent-v1",
        "left": left_hex,
        "right": right_hex,
    }
    return sha256_hex(canonical_json_bytes(obj))


def _build_paths(leaf_hashes: list[str]) -> tuple[str, dict[int, list[MerkleSibling]]]:
    """
    Build Merkle root and proof paths for each leaf index.

    Each node keeps the list of original leaf indices under it.
    When two nodes are merged, every leaf under the left node receives the
    right sibling, and every leaf under the right node receives the left sibling.

    If a level has odd number of nodes, duplicate the last node.
    """
    if not leaf_hashes:
        raise ValueError("cannot build Merkle tree with no leaves")

    paths: dict[int, list[MerkleSibling]] = {i: [] for i in range(len(leaf_hashes))}

                                                            
    level: list[tuple[str, list[int]]] = [
        (h, [i]) for i, h in enumerate(leaf_hashes)
    ]

    while len(level) > 1:
        if len(level) % 2 == 1:
                                                           
            last_hash, last_indices = level[-1]
            level.append((last_hash, list(last_indices)))

        next_level: list[tuple[str, list[int]]] = []

        for i in range(0, len(level), 2):
            left_hash, left_indices = level[i]
            right_hash, right_indices = level[i + 1]
            parent = parent_hash_hex(left_hash, right_hash)

            if left_hash == right_hash and left_indices == right_indices:
                for leaf_idx in left_indices:
                    paths[leaf_idx].append(
                        MerkleSibling(side="right", hash_hex=right_hash)
                    )
                merged_indices = list(left_indices)
            else:
                for leaf_idx in left_indices:
                    paths[leaf_idx].append(
                        MerkleSibling(side="right", hash_hex=right_hash)
                    )
                for leaf_idx in right_indices:
                    paths[leaf_idx].append(
                        MerkleSibling(side="left", hash_hex=left_hash)
                    )
                merged_indices = sorted(set(left_indices + right_indices))

            next_level.append((parent, merged_indices))

        level = next_level

    return level[0][0], paths


def build_ordered_merkle_snapshot(
    token_to_record_ids: dict[str, list[str]],
) -> OrderedMerkleSnapshot:
    """
    token_to_record_ids:
        key: raw token hex string, or already ordered token_id "1:<hex>"
        value: list of record id hex strings

    Returns a snapshot with sentinels included.
    """
    real_token_ids = sorted(make_real_token_id(t) for t in token_to_record_ids.keys())

    sorted_token_ids = [MIN_TOKEN_ID] + real_token_ids + [MAX_TOKEN_ID]

    leaves: dict[str, OrderedTokenLeaf] = {}

    for i, token_id in enumerate(sorted_token_ids):
        next_token_id = sorted_token_ids[i + 1] if i + 1 < len(sorted_token_ids) else ""

        if token_id in (MIN_TOKEN_ID, MAX_TOKEN_ID):
            digest_hex = EMPTY_POSTING_DIGEST_HEX
        else:
            raw = strip_real_token_id(token_id)
                                                                             
            record_ids = token_to_record_ids.get(raw)
            if record_ids is None:
                record_ids = token_to_record_ids.get(token_id, [])
            digest_hex = posting_digest_hex(record_ids)

        leaves[token_id] = OrderedTokenLeaf(
            token_id=token_id,
            posting_digest_hex=digest_hex,
            next_token_id=next_token_id,
        )

    leaf_hashes = [leaf_hash_hex(leaves[token_id]) for token_id in sorted_token_ids]
    root_hex, index_paths = _build_paths(leaf_hashes)

    paths: dict[str, list[MerkleSibling]] = {}
    for i, token_id in enumerate(sorted_token_ids):
        paths[token_id] = index_paths[i]

    return OrderedMerkleSnapshot(
        root_hex=root_hex,
        leaves=leaves,
        sorted_token_ids=sorted_token_ids,
        paths=paths,
    )


def verify_merkle_path(
    root_hex: str,
    leaf: OrderedTokenLeaf,
    merkle_path: list[MerkleSibling],
) -> bool:
    cur = leaf_hash_hex(leaf)

    for sibling in merkle_path:
        if sibling.side == "left":
            cur = parent_hash_hex(sibling.hash_hex, cur)
        elif sibling.side == "right":
            cur = parent_hash_hex(cur, sibling.hash_hex)
        else:
            return False

    return cur == root_hex


def verify_membership_proof(
    root_hex: str,
    token_id: str,
    posting_record_ids: list[str],
    proof: MembershipProof,
) -> tuple[bool, str]:
    token_id = make_real_token_id(token_id)

    if proof.token_id != token_id:
        return False, "membership token_id mismatch"

    if proof.leaf.token_id != token_id:
        return False, "membership leaf token_id mismatch"

    expected_digest = posting_digest_hex(posting_record_ids)
    if proof.leaf.posting_digest_hex != expected_digest:
        return False, "posting digest mismatch"

    if not verify_merkle_path(root_hex, proof.leaf, proof.merkle_path):
        return False, "membership Merkle path invalid"

    return True, "ok"


def verify_non_membership_proof(
    root_hex: str,
    query_token_id: str,
    proof: NonMembershipProof,
) -> tuple[bool, str]:
    query_token_id = make_real_token_id(query_token_id)

    pred = proof.predecessor_leaf
    succ = proof.successor_leaf

    if proof.query_token_id != query_token_id:
        return False, "non-membership query token mismatch"

    if not (pred.token_id < query_token_id < succ.token_id):
        return False, "query token is not between predecessor and successor"

    if pred.next_token_id != succ.token_id:
        return False, "predecessor and successor are not adjacent"

    if not verify_merkle_path(root_hex, pred, proof.predecessor_path):
        return False, "predecessor Merkle path invalid"

    if not verify_merkle_path(root_hex, succ, proof.successor_path):
        return False, "successor Merkle path invalid"

    return True, "ok"


def self_test() -> None:
    token_to_records = {
        "aaa": ["01", "02"],
        "ccc": ["03"],
        "fff": ["04", "05"],
    }

    snapshot = build_ordered_merkle_snapshot(token_to_records)

    mp = snapshot.membership_proof("ccc")
    ok, msg = verify_membership_proof(
        root_hex=snapshot.root_hex,
        token_id="ccc",
        posting_record_ids=["03"],
        proof=mp,
    )
    assert ok, msg

    nmp = snapshot.non_membership_proof("ddd")
    ok, msg = verify_non_membership_proof(
        root_hex=snapshot.root_hex,
        query_token_id="ddd",
        proof=nmp,
    )
    assert ok, msg

                                           
    ok, msg = verify_non_membership_proof(
        root_hex=snapshot.root_hex,
        query_token_id="bbb",
        proof=nmp,
    )
    assert not ok

    print("ordered_merkle self-test OK")
    print("root =", snapshot.root_hex)


if __name__ == "__main__":
    self_test()
