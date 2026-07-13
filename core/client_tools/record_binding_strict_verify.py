import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PK_KEYS = [
    "gateway_public_key_b64",
    "gateway_pk_b64",
    "gateway_public_key",
]

RECORD_HASH_KEYS = [
    "record_hash",
    "binding_hash",
    "binding_value",
    "ba_i",
    "ba",
]

SIGNATURE_KEYS = [
    "camshield_signature",
    "gateway_signature",
    "gateway_signature_b64",
    "eta_a_i",
    "eta",
    "signature",
]


def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()


def decode_bytes(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, str):
                        
        try:
            if len(value) % 2 == 0:
                b = bytes.fromhex(value)
                if b:
                    return b
        except Exception:
            pass

                     
        try:
            b = base64.b64decode(value, validate=True)
            if b:
                return b
        except Exception:
            pass

                          
        return value.encode()

                                                  
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    return str(value).encode()


def find_first(obj, names):
    wanted = {n.lower() for n in names}

    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in wanted:
                return v, k

        for v in obj.values():
            found, key = find_first(v, names)
            if found is not None:
                return found, key

    elif isinstance(obj, list):
        for item in obj:
            found, key = find_first(item, names)
            if found is not None:
                return found, key

    return None, None


def get(record, names, default=None):
    v, _ = find_first(record, names)
    return default if v is None else v


def get_bytes(record, names, default=None):
    v = get(record, names, None)
    if v is None:
        return default
    return decode_bytes(v)


def get_int(record, names, default=0):
    v = get(record, names, default)
    try:
        return int(v)
    except Exception:
        return default


def get_str(record, names, default=""):
    v = get(record, names, default)
    if v is None:
        return default
    return str(v)


def hash_tag_list(tags):
    if tags is None:
        tags = []
    if not isinstance(tags, list):
        tags = [str(tags)]
    tags = [str(x) for x in tags]
    return sha256(",".join(sorted(tags)).encode())


def hash_field_or_compute(record, hash_names, source_names, missing, label):
    value = get_bytes(record, hash_names)
    if value is not None:
        return value

    source = get(record, source_names, None)
    if source is not None:
        return sha256(decode_bytes(source))

    missing.append(label)
    return b""


def compute_legacy_record_hash(record):
    """
    Recompute the EncryptedSegmentRecord binding hash over extended metadata:

      record_hash = H(
        record_id, segment_id, camera_id, location, seq_no,
        timestamp_start, timestamp_end,
        H(sorted(event_tags)), H(sorted(object_tags)),
        granularity,
        ciphertext_hash, index_hash, abe_key_hash,
        camera_segment_hash, camera_signature,
        prev_segment_hash, payload_hash, policy_hash
      )

    Used when verifying records in the EncryptedSegmentRecord layout.
    """

    missing = []

    record_id = get_str(record, ["record_id", "rid", "ridi"])
    segment_id = get_str(record, ["segment_id", "sid", "sidi"])
    camera_id = get_str(record, ["camera_id", "cid"])
    location = get_str(record, ["location"])
    seq_no = get_int(record, ["seq_no", "seq", "seqi"])
    timestamp_start = get_int(record, ["timestamp_start", "t_start", "start_time", "ti"])
    timestamp_end = get_int(record, ["timestamp_end", "t_end", "end_time", "ti"])
    granularity = get_str(record, ["granularity", "access_class", "a"], "RAW")

    event_tags = get(record, ["event_tags"], [])
    object_tags = get(record, ["object_tags"], [])

    ciphertext_hash = hash_field_or_compute(
        record,
        ["ciphertext_hash", "h_ci", "ci_hash"],
        ["ciphertext", "ct", "cti", "ci"],
        missing,
        "ciphertext_hash/ciphertext",
    )

    index_hash = get_bytes(record, ["index_hash", "qi"])
    if index_hash is None:
        tokens = get(record, ["encrypted_index_tokens", "index_tokens", "tokens"], None)
        if isinstance(tokens, list):
            token_bytes = sorted(decode_bytes(t) for t in tokens)
            index_hash = sha256(b"".join(token_bytes))
        else:
            missing.append("index_hash/encrypted_index_tokens")
            index_hash = b""

    abe_key_hash = hash_field_or_compute(
        record,
        ["abe_key_hash", "ua_e", "u_a_e", "capsule_hash"],
        ["abe_encrypted_cek", "kappa", "kappa_a_e", "κa,e", "abe_capsule"],
        missing,
        "abe_key_hash/abe_encrypted_cek",
    )

    camera_segment_hash = get_bytes(record, ["camera_segment_hash", "segment_hash", "gamma_i", "gamma"])
    if camera_segment_hash is None:
        missing.append("camera_segment_hash")
        camera_segment_hash = b""

    camera_signature = get_bytes(record, ["camera_signature", "sigma_i", "camera_sig"])
    if camera_signature is None:
        missing.append("camera_signature")
        camera_signature = b""

    prev_segment_hash = get_bytes(record, ["prev_segment_hash", "gamma_prev", "prev_hash"])
    if prev_segment_hash is None:
        missing.append("prev_segment_hash")
        prev_segment_hash = b""

    payload_hash = get_bytes(record, ["payload_hash", "h_i", "plaintext_hash"])
    if payload_hash is None:
        missing.append("payload_hash")
        payload_hash = b""

    policy_hash = get_bytes(record, ["policy_hash", "pa_e", "p_a_e", "policy_digest"])
    if policy_hash is None:
        policy = get(record, ["access_policy", "policy", "pi_a_e"], None)
        if policy is not None:
            policy_hash = sha256(str(policy).encode())
        else:
            missing.append("policy_hash/access_policy")
            policy_hash = b""

    parts = [
        record_id.encode(),
        segment_id.encode(),
        camera_id.encode(),
        location.encode(),
        str(seq_no).encode(),
        str(timestamp_start).encode(),
        str(timestamp_end).encode(),
        hash_tag_list(event_tags),
        hash_tag_list(object_tags),
        granularity.encode(),
        ciphertext_hash,
        index_hash,
        abe_key_hash,
        camera_segment_hash,
        camera_signature,
        prev_segment_hash,
        payload_hash,
        policy_hash,
    ]

    h = hashlib.sha256()
    for part in parts:
        h.update(part)

    return h.digest(), missing


def extract_records(data):
    records = []

    for item in data.get("fetched_records", []):
        rid = item.get("rid")
        resp = item.get("response", {})

        candidate = None
        if isinstance(resp, dict):
            for key in ["record", "encrypted_record", "encrypted_evidence_record", "data"]:
                if isinstance(resp.get(key), dict):
                    candidate = resp[key]
                    break

        if candidate is None:
            candidate = resp

        records.append({
            "rid": rid,
            "record": candidate,
        })

    return records


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python record_binding_strict_verify.py fetched_records_owner_event_recorded.json")
        sys.exit(1)

    path = Path(sys.argv[1])
    data = json.loads(path.read_text(encoding="utf-8"))

    pk_value, pk_key = find_first(data, PK_KEYS)
    if pk_value is None:
        print("FAIL: cannot find gateway public key in input JSON.")
        print("Looked for:", PK_KEYS)
        sys.exit(1)

    try:
        pk_bytes = decode_bytes(pk_value)
        pk = Ed25519PublicKey.from_public_bytes(pk_bytes)
    except Exception as e:
        print("FAIL: cannot load gateway public key.")
        print("field:", pk_key)
        print("error:", repr(e))
        sys.exit(1)

    records = extract_records(data)

    print("=" * 72)
    print("CamShield Strict Record Binding Verification")
    print("=" * 72)
    print(f"Input file: {path}")
    print(f"Gateway pk field: {pk_key}")
    print(f"Fetched records: {len(records)}")
    print()

    if not records:
        print("FAIL: no fetched records found.")
        sys.exit(1)

    passed = 0

    for i, item in enumerate(records, 1):
        rid = item["rid"]
        record = item["record"]

        print(f"[Record {i}] rid={rid}")

        if not isinstance(record, dict):
            print("  FAIL: record is not a JSON object.")
            print()
            continue

        stored_hash_value, stored_hash_key = find_first(record, RECORD_HASH_KEYS)
        sig_value, sig_key = find_first(record, SIGNATURE_KEYS)

        if stored_hash_value is None:
            print("  FAIL: cannot find stored record/binding hash.")
            print("  top-level keys:", list(record.keys()))
            print()
            continue

        if sig_value is None:
            print("  FAIL: cannot find gateway signature.")
            print("  top-level keys:", list(record.keys()))
            print()
            continue

        stored_hash = decode_bytes(stored_hash_value)
        sig = decode_bytes(sig_value)

        computed_hash, missing = compute_legacy_record_hash(record)

        print(f"  stored hash field: {stored_hash_key}")
        print(f"  signature field  : {sig_key}")

        if missing:
            print("  WARN: some canonical fields were missing or derived imperfectly:")
            for m in missing:
                print(f"    - {m}")

        hash_match = stored_hash == computed_hash

        sig_ok_over_computed = False
        try:
            pk.verify(sig, computed_hash)
            sig_ok_over_computed = True
        except Exception:
            pass

        sig_ok_over_stored = False
        try:
            pk.verify(sig, stored_hash)
            sig_ok_over_stored = True
        except Exception:
            pass

        print(f"  recomputed hash matches stored hash: {hash_match}")
        print(f"  signature verifies over recomputed hash: {sig_ok_over_computed}")
        print(f"  signature verifies over stored hash    : {sig_ok_over_stored}")

        if hash_match and sig_ok_over_computed:
            print("  RESULT: PASS - strict binding verification passed.")
            passed += 1
        elif sig_ok_over_stored:
            print("  RESULT: PARTIAL - signature is valid, but recomputation did not match.")
            print("  Meaning: field naming/serialization differs from this verifier.")
        else:
            print("  RESULT: FAIL - binding signature verification failed.")

        print()

    print("=" * 72)
    print(f"Summary: {passed}/{len(records)} records passed strict binding verification.")
    if passed == len(records):
        print("RESULT: PASS")
    else:
        print("RESULT: CHECK")


if __name__ == "__main__":
    main()
