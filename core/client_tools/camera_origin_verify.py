import base64
import hashlib
import json
import sys
from pathlib import Path

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


GATEWAY_URL = "http://127.0.0.1:8000"


def lp(x: bytes) -> bytes:
    return len(x).to_bytes(8, "big") + x


def hash_parts(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(lp(p))
    return h.digest()


def u64(x: int) -> bytes:
    return int(x).to_bytes(8, "big")


def hx(s: str) -> bytes:
    return bytes.fromhex(s)


def load_records(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    records = []
    for item in data.get("fetched_records", []):
        resp = item.get("response", {})
        records.append(resp.get("record", resp))
    return records


def fetch_camera_pk(cid: str):
    r = requests.get(GATEWAY_URL + "/bootstrap/trust", timeout=10)
    data = r.json()

    if not data.get("ok"):
        raise RuntimeError(f"bootstrap failed: {data}")

    pk_b64 = data["camera_public_keys"].get(cid)
    if not pk_b64:
        raise RuntimeError(f"no camera pk for cid={cid}")

    return Ed25519PublicKey.from_public_bytes(base64.b64decode(pk_b64))


def encode_mu(cid: str, sid: str, seq: int, timestamp: int) -> bytes:
    """
    Match core.models.encode_mu():

        μi = (cid, sid_i, seq_i, t_i)

    encoded as:
        lp(cid) || lp(sid) || lp(u64(seq)) || lp(u64(timestamp))
    """
    return b"".join([
        lp(cid.encode("utf-8")),
        lp(sid.encode("utf-8")),
        lp(u64(seq)),
        lp(u64(timestamp)),
    ])


def compute_gamma(ssi: dict) -> bytes:
    """
    Match core.models.camera_chain_hash():

        γi = hash_parts(
            b"CamShield.camera.chain.v1",
            encode_mu(cid, sid, seq, timestamp),
            hi,
            gamma_prev,
        )
    """
    mu = encode_mu(
        ssi["cid"],
        ssi["sid"],
        int(ssi["seq"]),
        int(ssi["timestamp"]),
    )

    return hash_parts(
        b"CamShield.camera.chain.v1",
        mu,
        hx(ssi["hi"]),
        hx(ssi["gamma_prev"]),
    )


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python camera_origin_verify.py fetched_records_owner_event_recorded.json")
        sys.exit(1)

    path = Path(sys.argv[1])
    records = load_records(path)

    print("=" * 80)
    print("CamShield Camera-Origin Proof Verification")
    print("=" * 80)
    print(f"Input file: {path}")
    print(f"Fetched records: {len(records)}")
    print()

    if not records:
        print("FAIL: no records")
        sys.exit(1)

    cid = records[0]["SSi"]["cid"]
    camera_pk = fetch_camera_pk(cid)

    ordered = sorted(records, key=lambda r: int(r["SSi"]["seq"]))

    passed = 0
    last_gamma = None
    last_seq = None

    for i, record in enumerate(ordered, 1):
        ssi = record["SSi"]
        rid = record["rid"]

        stored_gamma = hx(ssi["gamma"])
        recomputed_gamma = compute_gamma(ssi)
        sigma_c = hx(ssi["sigma_c"])

        gamma_ok = stored_gamma == recomputed_gamma

        sig_ok = False
        try:
            camera_pk.verify(sigma_c, stored_gamma)
            sig_ok = True
        except Exception:
            sig_ok = False

        if last_gamma is None:
            chain_ok = True
            chain_note = "first fetched record"
        elif int(ssi["seq"]) == int(last_seq) + 1:
            chain_ok = hx(ssi["gamma_prev"]) == last_gamma
            chain_note = "adjacent seq"
        else:
            chain_ok = True
            chain_note = "non-adjacent seq; continuity skipped"

        print(f"[Record {i}] rid={rid}")
        print(f"  cid/sid/seq     : {ssi['cid']} / {ssi['sid']} / {ssi['seq']}")
        print(f"  gamma recomputed: {gamma_ok}")
        print(f"  camera signature: {sig_ok}")
        print(f"  chain continuity: {chain_ok} ({chain_note})")

        if gamma_ok and sig_ok and chain_ok:
            print("  RESULT: PASS - camera-origin proof verifies.")
            passed += 1
        else:
            print("  RESULT: FAIL/CHECK")
            if not gamma_ok:
                print(f"    stored gamma    : {stored_gamma.hex()}")
                print(f"    recomputed gamma: {recomputed_gamma.hex()}")

        print()

        last_gamma = stored_gamma
        last_seq = ssi["seq"]

    print("=" * 80)
    print(f"Summary: {passed}/{len(records)} records passed camera-origin verification.")
    if passed == len(records):
        print("RESULT: PASS")
    else:
        print("RESULT: CHECK")


if __name__ == "__main__":
    main()
