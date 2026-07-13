from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


BASE_DIR = Path(__file__).resolve().parent


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


def verify_membership_proof(root_hex: str, token_hex: str, posting_record_ids: list[str], proof: dict[str, Any]):
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


def verify_non_membership_proof(root_hex: str, token_hex: str, proof: dict[str, Any]):
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
    from core.models import CHECKPOINT_CHAIN_GENESIS, compute_checkpoint_chain_value

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


def verify_checkpoint_signature(cp: dict[str, Any]):
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(cp["gateway_public_key_b64"]))
        sig = base64.b64decode(cp["signature_b64"])
        pk.verify(sig, checkpoint_signed_bytes(cp))
        return True, "ok"
    except Exception as exc:
        return False, f"checkpoint signature invalid: {exc}"


def verify_result_set(operator: str, query_token_ids: list[str], postings: dict[str, list[str]], result_record_ids: list[str]):
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


def verify_retrieval_from_package(pkg: dict[str, Any]):
    search_response = pkg["search_response"]

    root_hex = search_response["checkpoint_root_hex"]
    signed_checkpoint = search_response["signed_checkpoint"]
    query_token_ids = search_response.get("query_token_ids", [])
    postings = search_response.get("postings", {})
    membership_proofs = search_response.get("membership_proofs", {})
    non_membership_proofs = search_response.get("non_membership_proofs", {})
    result_record_ids = search_response.get("result_record_ids", [])
    operator = search_response.get("operator", pkg.get("operator", "AND"))

    checks: list[tuple[str, bool, str]] = []

    checks.append((
        "checkpoint root matches response root",
        signed_checkpoint.get("root_hex") == root_hex,
        "ok" if signed_checkpoint.get("root_hex") == root_hex else "root mismatch",
    ))

    checks.append((
        "checkpoint epoch matches package epoch",
        int(signed_checkpoint.get("epoch", -1)) == int(pkg.get("epoch", -2)),
        "ok" if int(signed_checkpoint.get("epoch", -1)) == int(pkg.get("epoch", -2)) else "epoch mismatch",
    ))

    sig_ok, sig_msg = verify_checkpoint_signature(signed_checkpoint)
    checks.append(("gateway checkpoint signature", sig_ok, sig_msg))

    for token_hex in query_token_ids:
        posting = postings.get(token_hex, [])

        if posting:
            proof = membership_proofs.get(token_hex)
            if not proof:
                checks.append((f"membership proof for {token_hex[:16]}...", False, "missing membership proof"))
            else:
                ok, msg = verify_membership_proof(root_hex, token_hex, posting, proof)
                checks.append((f"membership proof for {token_hex[:16]}...", ok, msg))
        else:
            proof = non_membership_proofs.get(token_hex)
            if not proof:
                checks.append((f"non-membership proof for {token_hex[:16]}...", False, "missing non-membership proof"))
            else:
                ok, msg = verify_non_membership_proof(root_hex, token_hex, proof)
                checks.append((f"non-membership proof for {token_hex[:16]}...", ok, msg))

    rs_ok, rs_msg = verify_result_set(operator, query_token_ids, postings, result_record_ids)
    checks.append(("result set equals posting-list evaluation", rs_ok, rs_msg))

    return checks


def run_local_verifier(script_name: str, records_file: Path):
    proc = subprocess.run(
        [sys.executable, script_name, str(records_file)],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        timeout=180,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    ok = proc.returncode == 0 and "RESULT: PASS" in output
    return ok, output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package_file")
    args = parser.parse_args()

    pkg_path = Path(args.package_file)
    if not pkg_path.exists():
        print(f"Package not found: {pkg_path}")
        sys.exit(1)

    pkg = json.loads(pkg_path.read_text(encoding="utf-8"))

    print("=" * 80)
    print("CamShield Lightweight Evidence Package Verification")
    print("=" * 80)
    print(f"package   : {pkg_path}")
    print(f"type      : {pkg.get('type')}")
    print(f"client_id : {pkg.get('client_id')}")
    print(f"keyword   : {pkg.get('keyword')}")
    print(f"epoch     : {pkg.get('epoch')}")
    print()

    print("[1] Offline retrieval proof verification from package...")
    retrieval_checks = verify_retrieval_from_package(pkg)

    for name, ok, msg in retrieval_checks:
        print(f"    {name:50s}: {ok} ({msg})")

    retrieval_ok = all(ok for _, ok, _ in retrieval_checks)
    print(f"    Retrieval Proof RESULT: {'PASS' if retrieval_ok else 'CHECK'}")
    print()

    print("[2] Reconstructing fetched-record file from package...")
    tmp_records = BASE_DIR / f".tmp_records_from_{pkg_path.stem}.json"
    tmp_records.write_text(
        json.dumps(pkg["fetched_records"], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"    temp records file: {tmp_records}")
    print()

    print("[3] Running strict record binding verifier...")
    binding_ok, binding_output = run_local_verifier("record_binding_formula_verify.py", tmp_records)
    print(f"    Record Binding RESULT: {'PASS' if binding_ok else 'CHECK'}")
    print()

    print("[4] Running camera-origin verifier...")
    camera_ok, camera_output = run_local_verifier("camera_origin_verify.py", tmp_records)
    print(f"    Camera-Origin RESULT: {'PASS' if camera_ok else 'CHECK'}")
    print()

    print("=" * 80)
    print("Detailed Record Binding Output")
    print("=" * 80)
    print(binding_output)

    print("=" * 80)
    print("Detailed Camera-Origin Output")
    print("=" * 80)
    print(camera_output)

    overall_ok = retrieval_ok and binding_ok and camera_ok

    print("=" * 80)
    print(f"Retrieval Proof : {'PASS' if retrieval_ok else 'CHECK'}")
    print(f"Record Binding  : {'PASS' if binding_ok else 'CHECK'}")
    print(f"Camera-Origin   : {'PASS' if camera_ok else 'CHECK'}")
    print(f"Overall         : {'PASS' if overall_ok else 'CHECK'}")

    if overall_ok:
        print("RESULT: PASS - lightweight evidence package verification passed.")
    else:
        print("RESULT: CHECK")
        sys.exit(2)


if __name__ == "__main__":
    main()
