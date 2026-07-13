"""Attack scenario definitions for CamShield detection demos."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class AttackSpec:
    attack_id: str
    title: str
    injected_inconsistency: str
    expected_client_signal: str
    mutate_search: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    mutate_record: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]] | None = None


def _deep(data: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(data)


def _first_rid(response: dict[str, Any]) -> str | None:
    ids = response.get("result_record_ids") or []
    return str(ids[0]) if ids else None


def _other_rid(state_records: dict[str, Any], skip_rid: str | None) -> str | None:
    for rid in sorted(state_records.keys()):
        if skip_rid is None or str(rid) != str(skip_rid):
            return str(rid)
    return None


def _flip_hex_byte(hex_value: str) -> str:
    raw = bytearray(bytes.fromhex(hex_value))
    if not raw:
        raw = bytearray([0x00])
    raw[0] ^= 0x01
    return raw.hex()


def mutate_a1_hide_matching(response: dict[str, Any]) -> dict[str, Any]:
    """A1: Cloud hides matching records."""
    out = _deep(response)
    ids = list(out.get("result_record_ids") or [])
    if len(ids) > 1:
        out["result_record_ids"] = ids[:-1]
    elif ids:
        out["result_record_ids"] = []
    return out


def mutate_a2_empty_result(response: dict[str, Any]) -> dict[str, Any]:
    """A2: Cloud returns no result for a non-empty query."""
    out = _deep(response)
    if any(out.get("postings", {}).values()):
        out["result_record_ids"] = []
    return out


def mutate_a4_stale_checkpoint(response: dict[str, Any]) -> dict[str, Any]:
    """A4: Cloud returns a stale checkpoint."""
    out = _deep(response)
    sc = _deep(out.get("signed_checkpoint") or {})
    if sc:
        try:
            sc["version"] = max(0, int(sc.get("version", 1)) - 1)
        except Exception:
            sc["version"] = 0
        if sc.get("root_hex"):
            sc["root_hex"] = _flip_hex_byte(str(sc["root_hex"]))
        out["signed_checkpoint"] = sc
        out["checkpoint_root_hex"] = sc.get("root_hex", out.get("checkpoint_root_hex"))
    return out


def mutate_a5_hide_newer_checkpoint(response: dict[str, Any]) -> dict[str, Any]:
    """A5: Cloud hides newer checkpoint states."""
    return mutate_a4_stale_checkpoint(response)


def mutate_a6_partial_multi_tag(response: dict[str, Any]) -> dict[str, Any]:
    """A6: Cloud evaluates only part of a multi-tag query."""
    out = _deep(response)
    tokens = list(out.get("query_token_ids") or [])
    if len(tokens) >= 2:
        drop = tokens[-1]
        out["postings"].pop(drop, None)
        out.get("membership_proofs", {}).pop(drop, None)
        out.get("non_membership_proofs", {}).pop(drop, None)
        posting_sets = [set(out.get("postings", {}).get(t, [])) for t in tokens if t in out.get("postings", {})]
        if posting_sets:
            if str(out.get("operator", "AND")).upper() == "AND":
                out["result_record_ids"] = sorted(set.intersection(*posting_sets))
            else:
                out["result_record_ids"] = sorted(set.union(*posting_sets))
    return out


def mutate_record_a3_unrelated(
    record: dict[str, Any],
    *,
    state_records: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any]:
    """A3: Cloud returns unrelated ciphertext."""
    out = _deep(record)
    other = _other_rid(state_records, str(out.get("rid", "")))
    if other and other in state_records:
        donor = state_records[other]
        out["ciphertext"] = donor.get("ciphertext", out.get("ciphertext"))
        out["nonce"] = donor.get("nonce", out.get("nonce"))
        out["tag"] = donor.get("tag", out.get("tag"))
    return out


def mutate_record_a7_payload(
    record: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any]:
    """A7: Cloud modifies encrypted payload."""
    out = _deep(record)
    if out.get("ciphertext"):
        out["ciphertext"] = _flip_hex_byte(str(out["ciphertext"]))
    return out


def mutate_record_a8_wrong_capsule(
    record: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any]:
    """A8: Cloud attaches wrong ABE capsule."""
    out = _deep(record)
    if out.get("kappa"):
        out["kappa"] = _flip_hex_byte(str(out["kappa"]))
    return out


def mutate_record_a9_wrong_policy_digest(
    record: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any]:
    """A9: Cloud attaches wrong policy digest."""
    out = _deep(record)
    if out.get("policy_digest"):
        out["policy_digest"] = _flip_hex_byte(str(out["policy_digest"]))
    return out


def mutate_record_a10_metadata_mismatch(
    record: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any]:
    """A10: Record is inconsistent with retrieval metadata."""
    out = _deep(record)
    if out.get("index_digest"):
        out["index_digest"] = _flip_hex_byte(str(out["index_digest"]))
    return out


def mutate_record_a11_wrong_ssi(
    record: dict[str, Any],
    **_kwargs: Any,
) -> dict[str, Any]:
    """A11: Record uses wrong signed segment metadata."""
    out = _deep(record)
    ssi = out.get("SSi")
    if isinstance(ssi, dict) and ssi.get("sid"):
        ssi = _deep(ssi)
        ssi["sid"] = str(ssi["sid"]) + "-tampered"
        out["SSi"] = ssi
    return out


def _wrap_record(fn: Callable[..., dict[str, Any]]):
    def inner(record: dict[str, Any], *, state_records: dict[str, Any]) -> dict[str, Any]:
        return fn(record, state_records=state_records)

    return inner


ATTACKS: dict[str, AttackSpec] = {
    "A1": AttackSpec(
        attack_id="A1",
        title="Cloud hides matching records",
        injected_inconsistency="Remove matched record IDs from the search result set.",
        expected_client_signal="retrieval_ok=false; check 'result set equals posting-list evaluation'.",
        mutate_search=mutate_a1_hide_matching,
    ),
    "A2": AttackSpec(
        attack_id="A2",
        title="Cloud returns no result for a non-empty query",
        injected_inconsistency="Force an empty result set while postings still contain matches.",
        expected_client_signal="retrieval_ok=false; empty result_record_ids with non-empty postings.",
        mutate_search=mutate_a2_empty_result,
    ),
    "A3": AttackSpec(
        attack_id="A3",
        title="Cloud returns unrelated ciphertext",
        injected_inconsistency="Swap ciphertext fields with another stored record.",
        expected_client_signal="decrypt_ok=false or binding_ok=false after fetch.",
        mutate_record=_wrap_record(mutate_record_a3_unrelated),
    ),
    "A4": AttackSpec(
        attack_id="A4",
        title="Cloud returns a stale checkpoint",
        injected_inconsistency="Tamper checkpoint version/root in the search response.",
        expected_client_signal="retrieval_ok=false; checkpoint or Merkle proof checks fail.",
        mutate_search=mutate_a4_stale_checkpoint,
    ),
    "A5": AttackSpec(
        attack_id="A5",
        title="Cloud hides newer checkpoint states",
        injected_inconsistency="Serve an older checkpoint snapshot in the search response.",
        expected_client_signal="retrieval_ok=false; checkpoint signature or proof mismatch.",
        mutate_search=mutate_a5_hide_newer_checkpoint,
    ),
    "A6": AttackSpec(
        attack_id="A6",
        title="Cloud evaluates only part of a multi-tag query",
        injected_inconsistency="Drop one query token from postings/proofs.",
        expected_client_signal="retrieval_ok=false; missing proof or result-set mismatch.",
        mutate_search=mutate_a6_partial_multi_tag,
    ),
    "A7": AttackSpec(
        attack_id="A7",
        title="Cloud modifies encrypted payload",
        injected_inconsistency="Flip a byte in record ciphertext.",
        expected_client_signal="decrypt_ok=false; AES-GCM decrypt failed.",
        mutate_record=_wrap_record(mutate_record_a7_payload),
    ),
    "A8": AttackSpec(
        attack_id="A8",
        title="Cloud attaches wrong ABE capsule",
        injected_inconsistency="Tamper the ABE capsule (kappa).",
        expected_client_signal="decrypt_ok=false; CP-ABE decrypt failed.",
        mutate_record=_wrap_record(mutate_record_a8_wrong_capsule),
    ),
    "A9": AttackSpec(
        attack_id="A9",
        title="Cloud attaches wrong policy digest",
        injected_inconsistency="Tamper policy_digest in the stored record.",
        expected_client_signal="binding_ok=false; record binding verification fails.",
        mutate_record=_wrap_record(mutate_record_a9_wrong_policy_digest),
    ),
    "A10": AttackSpec(
        attack_id="A10",
        title="Record inconsistent with retrieval metadata",
        injected_inconsistency="Tamper index_digest in the stored record.",
        expected_client_signal="binding_ok=false; binding hash mismatch.",
        mutate_record=_wrap_record(mutate_record_a10_metadata_mismatch),
    ),
    "A11": AttackSpec(
        attack_id="A11",
        title="Record uses wrong signed segment metadata",
        injected_inconsistency="Tamper camera-signed segment descriptor (SSi).",
        expected_client_signal="camera_ok=false; camera-origin verification fails.",
        mutate_record=_wrap_record(mutate_record_a11_wrong_ssi),
    ),
}


def get_attack(attack_id: str) -> AttackSpec:
    key = attack_id.strip().upper()
    if key not in ATTACKS:
        known = ", ".join(sorted(ATTACKS))
        raise KeyError(f"Unknown attack '{attack_id}'. Choose from: {known}")
    return ATTACKS[key]


def list_attacks() -> list[AttackSpec]:
    return [ATTACKS[k] for k in sorted(ATTACKS)]
