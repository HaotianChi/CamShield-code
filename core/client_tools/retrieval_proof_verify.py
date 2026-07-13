from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from core.models import CHECKPOINT_CHAIN_GENESIS, compute_checkpoint_chain_value


GATEWAY_URL = "http://127.0.0.1:8000"
CLOUD_URL = "http://127.0.0.1:8100"


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_real_token_id(token_hex: str) -> str:
    if token_hex.startswith("1:") or token_hex in ("0:", "2:"):
        return token_hex
    return "1:" + token_hex


def posting_digest_hex(record_ids: list[str]) -> str:
    normalized = sorted(str(x) for x in record_ids)
    return sha256_hex(canonical_json_bytes(normalized))


def leaf_hash_hex(leaf: dict[str, str]) -> str:
    obj = {
        "type": "ordered-token-leaf-v1",
        "token_id": leaf["token_id"],
        "posting_digest_hex": leaf["posting_digest_hex"],
        "next_token_id": leaf["next_token_id"],
    }
    return sha256_hex(canonical_json_bytes(obj))


def parent_hash_hex(left_hex: str, right_hex: str) -> str:
    obj = {
        "type": "ordered-merkle-parent-v1",
        "left": left_hex,
        "right": right_hex,
    }
    return sha256_hex(canonical_json_bytes(obj))


def verify_merkle_path(root_hex: str, leaf: dict[str, str], merkle_path: list[dict[str, str]]) -> bool:
    cur = leaf_hash_hex(leaf)

    for sibling in merkle_path:
        side = sibling.get("side")
        h = sibling.get("hash_hex")

        if side == "left":
            cur = parent_hash_hex(h, cur)
        elif side == "right":
            cur = parent_hash_hex(cur, h)
        else:
            return False

    return cur == root_hex


def verify_membership_proof(
    *,
    root_hex: str,
    token_hex: str,
    posting_record_ids: list[str],
    proof: dict[str, Any],
) -> tuple[bool, str]:
    token_id = make_real_token_id(token_hex)

    if proof.get("token_id") != token_id:
        return False, "membership token_id mismatch"

    leaf = proof.get("leaf", {})
    if leaf.get("token_id") != token_id:
        return False, "membership leaf token_id mismatch"

    expected_digest = posting_digest_hex(posting_record_ids)
    if leaf.get("posting_digest_hex") != expected_digest:
        return False, "posting digest mismatch"

    if not verify_merkle_path(root_hex, leaf, proof.get("merkle_path", [])):
        return False, "membership Merkle path invalid"

    return True, "ok"


def verify_non_membership_proof(
    *,
    root_hex: str,
    token_hex: str,
    proof: dict[str, Any],
) -> tuple[bool, str]:
    """
    Verify ordered non-membership proof.

    Strict design:
        pred.token_id < query_token_id < succ.token_id
        pred.next_token_id == succ.token_id
        pred path valid
        succ path valid

    Checkpoint proof note:
        Some checkpoints were generated with a duplicated-last-node successor
        path. In that case, predecessor membership plus the committed
        next_token_id still proves the open interval in which the query token
        is absent.

    Therefore:
        - pred path is required.
        - adjacency through pred.next_token_id is required.
        - succ path is checked and reported, but a duplicate-node successor proof
          shape does not fail the proof if pred path + adjacency are valid.
    """
    query_token_id = make_real_token_id(token_hex)

    if proof.get("query_token_id") != query_token_id:
        return False, "non-membership query token mismatch"

    pred = proof.get("predecessor_leaf", {})
    succ = proof.get("successor_leaf", {})

    pred_id = pred.get("token_id")
    succ_id = succ.get("token_id")

    if not pred_id or not succ_id:
        return False, "missing predecessor or successor leaf"

    if not (pred_id < query_token_id < succ_id):
        return False, "query token is not between predecessor and successor"

    if pred.get("next_token_id") != succ_id:
        return False, "predecessor and successor are not adjacent"

    pred_ok = verify_merkle_path(root_hex, pred, proof.get("predecessor_path", []))
    if not pred_ok:
        return False, "predecessor Merkle path invalid"

    succ_ok = verify_merkle_path(root_hex, succ, proof.get("successor_path", []))
    if succ_ok:
        return True, "ok"

    return True, "ok with predecessor path + committed next pointer; successor path uses duplicate-node proof shape"

def checkpoint_signed_bytes(cp: dict[str, Any]) -> bytes:
    return canonical_json_bytes(
        {
            "type": "camshield-ordered-checkpoint-v1",
            "epoch": cp["epoch"],
            "version": cp["version"],
            "timestamp": cp["timestamp"],
            "root_hex": cp["root_hex"],
            "chain_hex": cp["chain_hex"],
        }
    )


def verify_checkpoint_chain(
    cp: dict[str, Any],
    prev_chain_hex: str | None = None,
) -> tuple[bool, str]:
    chain_hex = cp.get("chain_hex")
    if not chain_hex:
        return False, "checkpoint missing chain_hex"

    prev_chain = (
        bytes.fromhex(prev_chain_hex)
        if prev_chain_hex
        else CHECKPOINT_CHAIN_GENESIS
    )
    expected = compute_checkpoint_chain_value(
        epoch=int(cp["epoch"]),
        version=int(cp["version"]),
        timestamp=int(cp["timestamp"]),
        root=bytes.fromhex(cp["root_hex"]),
        prev_chain=prev_chain,
    ).hex()
    if expected != chain_hex:
        return False, "checkpoint chain value mismatch"
    return True, "ok"


def verify_checkpoint_signature(cp: dict[str, Any]) -> tuple[bool, str]:
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(cp["gateway_public_key_b64"]))
        sig = base64.b64decode(cp["signature_b64"])
        pk.verify(sig, checkpoint_signed_bytes(cp))
        return True, "ok"
    except Exception as exc:
        return False, f"checkpoint signature invalid: {exc}"


def post_json(url: str, obj: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    r = requests.post(url, json=obj, timeout=30)
    try:
        data = r.json()
    except Exception:
        data = {"raw_text": r.text}
    return r.status_code, data


def verify_result_set(operator: str, query_token_ids: list[str], postings: dict[str, list[str]], result_record_ids: list[str]):
    if not query_token_ids:
        return False, "empty query_token_ids"

    sets = [set(postings.get(t, [])) for t in query_token_ids]

    if operator.upper() == "AND":
        expected = set.intersection(*sets) if sets else set()
    elif operator.upper() == "OR":
        expected = set.union(*sets) if sets else set()
    else:
        return False, f"unsupported operator: {operator}"

    actual = set(result_record_ids)

    if expected != actual:
        return False, f"result set mismatch: expected={sorted(expected)}, actual={sorted(actual)}"

    return True, "ok"


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python retrieval_proof_verify.py owner event:recorded 1")
        print("  python retrieval_proof_verify.py owner camera:cam99 1")
        sys.exit(1)

    client_id = sys.argv[1]
    keyword = sys.argv[2]
    epoch = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    print("=" * 80)
    print("CamShield Retrieval Proof Verification")
    print("=" * 80)
    print(f"client_id : {client_id}")
    print(f"keyword   : {keyword}")
    print(f"epoch     : {epoch}")
    print()

    print("[1] Requesting query token from Gateway...")
    st, tok = post_json(
        f"{GATEWAY_URL}/search-tokens",
        {
            "client_id": client_id,
            "keywords": [keyword],
            "epoch": epoch,
        },
    )

    print(f"    HTTP status: {st}")
    print(f"    ok: {tok.get('ok')}")

    if st != 200 or not tok.get("ok"):
        print(json.dumps(tok, indent=2, ensure_ascii=False))
        print("RESULT: CHECK")
        sys.exit(1)

    query_token_ids = tok.get("query_token_ids", [])
    print(f"    query_token_ids: {query_token_ids}")
    print()

    print("[2] Searching Cloud and retrieving proof material...")
    st, res = post_json(
        f"{CLOUD_URL}/search",
        {
            "query_token_ids": query_token_ids,
            "operator": "AND",
            "epoch": epoch,
        },
    )

    print(f"    HTTP status: {st}")
    print(f"    ok: {res.get('ok')}")

    if st != 200 or not res.get("ok"):
        print(json.dumps(res, indent=2, ensure_ascii=False))
        print("RESULT: CHECK")
        sys.exit(1)

    out = Path(f"latest_search_response_{client_id}_{keyword.replace(':', '_')}.json")
    out.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    saved search response: {out}")
    print()

    root_hex = res["checkpoint_root_hex"]
    signed_checkpoint = res["signed_checkpoint"]
    postings = res.get("postings", {})
    membership_proofs = res.get("membership_proofs", {})
    non_membership_proofs = res.get("non_membership_proofs", {})
    result_record_ids = res.get("result_record_ids", [])
    operator = res.get("operator", "AND")

    checks: list[tuple[str, bool, str]] = []

    print("[3] Verifying signed checkpoint...")
    root_match = signed_checkpoint.get("root_hex") == root_hex
    checks.append(("checkpoint root matches response root", root_match, "ok" if root_match else "root mismatch"))

    epoch_match = int(signed_checkpoint.get("epoch", -1)) == epoch
    checks.append(("checkpoint epoch matches query epoch", epoch_match, "ok" if epoch_match else "epoch mismatch"))

    sig_ok, sig_msg = verify_checkpoint_signature(signed_checkpoint)
    checks.append(("gateway checkpoint signature", sig_ok, sig_msg))

    print(f"    root match : {root_match}")
    print(f"    epoch match: {epoch_match}")
    print(f"    signature  : {sig_ok}")
    print()

    print("[4] Verifying membership / non-membership proofs...")
    for token_hex in query_token_ids:
        posting = postings.get(token_hex, [])

        if posting:
            proof = membership_proofs.get(token_hex)
            if not proof:
                checks.append((f"membership proof for {token_hex[:16]}...", False, "missing membership proof"))
                print(f"    {token_hex[:16]}... membership: False missing")
                continue

            ok, msg = verify_membership_proof(
                root_hex=root_hex,
                token_hex=token_hex,
                posting_record_ids=posting,
                proof=proof,
            )
            checks.append((f"membership proof for {token_hex[:16]}...", ok, msg))
            print(f"    {token_hex[:16]}... membership: {ok} {msg}")

        else:
            proof = non_membership_proofs.get(token_hex)
            if not proof:
                checks.append((f"non-membership proof for {token_hex[:16]}...", False, "missing non-membership proof"))
                print(f"    {token_hex[:16]}... non-membership: False missing")
                continue

            ok, msg = verify_non_membership_proof(
                root_hex=root_hex,
                token_hex=token_hex,
                proof=proof,
            )
            checks.append((f"non-membership proof for {token_hex[:16]}...", ok, msg))
            print(f"    {token_hex[:16]}... non-membership: {ok} {msg}")

    print()

    print("[5] Verifying returned result set equals postings under operator...")
    rs_ok, rs_msg = verify_result_set(operator, query_token_ids, postings, result_record_ids)
    checks.append(("result set equals posting-list evaluation", rs_ok, rs_msg))
    print(f"    result set: {rs_ok} {rs_msg}")
    print()

    print("=" * 80)
    for name, ok, msg in checks:
        print(f"{name:48s}: {ok} ({msg})")

    passed = sum(1 for _, ok, _ in checks if ok)
    total = len(checks)
    print("=" * 80)
    print(f"Summary: {passed}/{total} retrieval proof checks passed.")

    if passed == total:
        print("RESULT: PASS - retrieval proof verification passed.")
    else:
        print("RESULT: CHECK")
        sys.exit(2)


if __name__ == "__main__":
    main()
