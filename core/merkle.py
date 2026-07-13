"""
Binary SHA-256 Merkle tree.

Used for posting-list commitments: Cloud computes a root over record IDs,
Gateway signs the root, and the client verifies results with inclusion proofs.
Leaf nodes use prefix 0x00; internal nodes use prefix 0x01 (domain separation).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass


def _hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"EMPTY").digest()
    layer = [_hash_leaf(leaf) for leaf in leaves]
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            if i + 1 < len(layer):
                next_layer.append(_hash_node(layer[i], layer[i + 1]))
            else:
                next_layer.append(_hash_node(layer[i], layer[i]))
        layer = next_layer
    return layer[0]


@dataclass
class MerkleProof:
    leaf_index: int
    leaf_hash: bytes
    siblings: list[tuple[str, bytes]]                           
    root: bytes


def merkle_proof(leaves: list[bytes], index: int) -> MerkleProof:
    if not leaves or index < 0 or index >= len(leaves):
        raise ValueError("Invalid merkle proof index")
    leaf_hashes = [_hash_leaf(leaf) for leaf in leaves]
    proof_siblings: list[tuple[str, bytes]] = []
    idx = index
    layer = leaf_hashes[:]
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else layer[i]
            if i == idx or i + 1 == idx:
                if i == idx:
                    proof_siblings.append(("R", right))
                else:
                    proof_siblings.append(("L", left))
            next_layer.append(_hash_node(left, right))
        idx //= 2
        layer = next_layer
    return MerkleProof(
        leaf_index=index,
        leaf_hash=leaf_hashes[index],
        siblings=proof_siblings,
        root=layer[0],
    )


def verify_merkle_proof(leaf: bytes, proof: MerkleProof) -> bool:
    h = _hash_leaf(leaf)
    idx = proof.leaf_index
    for side, sibling in proof.siblings:
        if side == "L":
            h = _hash_node(sibling, h)
        else:
            h = _hash_node(h, sibling)
        idx //= 2
    return h == proof.root
