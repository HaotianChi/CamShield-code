from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests


BASE_DIR = Path(__file__).resolve().parent
GATEWAY_URL = "http://127.0.0.1:8000"
CLOUD_URL = "http://127.0.0.1:8100"


def safe_keyword(keyword: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", keyword).strip("_")


def post_json(url: str, obj: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    r = requests.post(url, json=obj, timeout=30)
    try:
        data = r.json()
    except Exception:
        data = {"raw_text": r.text}
    return r.status_code, data


def get_json(url: str) -> tuple[int, dict[str, Any]]:
    r = requests.get(url, timeout=30)
    try:
        data = r.json()
    except Exception:
        data = {"raw_text": r.text}
    return r.status_code, data


def run_cmd(args: list[str], timeout: int = 180) -> tuple[int, str]:
    proc = subprocess.run(
        args,
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def infer_fetched_file(client_id: str, keyword: str) -> Path:
    return BASE_DIR / f"fetched_records_{client_id}_{safe_keyword(keyword)}.json"


def extract_record_from_cloud_response(data: dict[str, Any]) -> dict[str, Any]:
    if isinstance(data, dict):
        for k in ["record", "encrypted_record", "evidence_record", "ER"]:
            if k in data and isinstance(data[k], dict):
                return data[k]
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("client_id", nargs="?", default="owner")
    parser.add_argument("keyword", nargs="?", default="event:recorded")
    parser.add_argument("epoch", nargs="?", type=int, default=1)
    parser.add_argument("--operator", default="AND")
    parser.add_argument("--gateway-url", default=GATEWAY_URL)
    parser.add_argument("--cloud-url", default=CLOUD_URL)
    args = parser.parse_args()

    client_id = args.client_id
    keyword = args.keyword
    epoch = args.epoch
    operator = args.operator.upper()
    gateway_url = args.gateway_url.rstrip("/")
    cloud_url = args.cloud_url.rstrip("/")

    print("=" * 80)
    print("CamShield Lightweight Evidence Package Export")
    print("=" * 80)
    print(f"client_id : {client_id}")
    print(f"keyword   : {keyword}")
    print(f"epoch     : {epoch}")
    print(f"operator  : {operator}")
    print()

    print("[1] Running Search + Fetch to collect records...")
    fetch_code, fetch_output = run_cmd([
        sys.executable,
        "record_fetch_test.py",
        client_id,
        keyword,
        str(epoch),
    ])

    fetched_file = infer_fetched_file(client_id, keyword)
    print(f"    fetch return code: {fetch_code}")
    print(f"    fetched file     : {fetched_file}")

    if fetch_code != 0 or not fetched_file.exists():
        print(fetch_output)
        print("RESULT: CHECK - fetch failed or fetched file missing.")
        sys.exit(1)

    fetched_records_json = json.loads(fetched_file.read_text(encoding="utf-8"))
    print("    fetched file loaded.")
    print()

    print("[2] Requesting query token IDs from Gateway...")
    st, token_response = post_json(
        f"{gateway_url}/search-tokens",
        {
            "client_id": client_id,
            "keywords": [keyword],
            "epoch": epoch,
        },
    )

    print(f"    HTTP status: {st}")
    print(f"    ok: {token_response.get('ok')}")
    if st != 200 or not token_response.get("ok"):
        print(json.dumps(token_response, indent=2, ensure_ascii=False))
        sys.exit(1)

    query_token_ids = token_response.get("query_token_ids", [])
    print(f"    query_token_ids: {query_token_ids}")
    print()

    print("[3] Requesting Cloud retrieval proof...")
    st, search_response = post_json(
        f"{cloud_url}/search",
        {
            "query_token_ids": query_token_ids,
            "operator": operator,
            "epoch": epoch,
        },
    )

    print(f"    HTTP status: {st}")
    print(f"    ok: {search_response.get('ok')}")
    if st != 200 or not search_response.get("ok"):
        print(json.dumps(search_response, indent=2, ensure_ascii=False))
        sys.exit(1)

    result_record_ids = search_response.get("result_record_ids", [])
    print(f"    result_record_ids count: {len(result_record_ids)}")
    print()

    print("[4] Fetching trust anchors from Gateway...")
    st, trust = get_json(f"{gateway_url}/bootstrap/trust")
    print(f"    HTTP status: {st}")
    print(f"    ok: {trust.get('ok')}")
    if st != 200 or not trust.get("ok"):
        print(json.dumps(trust, indent=2, ensure_ascii=False))
        sys.exit(1)
    print()

    print("[5] Fetching direct records from Cloud for package redundancy...")
    direct_records = []
    for rid in result_record_ids:
        st, data = get_json(f"{cloud_url}/record/{rid}")
        ok = st == 200 and data.get("ok", True)
        print(f"    rid={rid[:16]}... status={st} ok={ok}")
        if st == 200:
            direct_records.append({
                "rid": rid,
                "cloud_response": data,
                "record": extract_record_from_cloud_response(data),
            })

    package = {
        "type": "camshield-evidence-package-lite-v1",
        "exported_at": int(time.time()),
        "gateway_url": gateway_url,
        "cloud_url": cloud_url,
        "client_id": client_id,
        "keyword": keyword,
        "epoch": epoch,
        "operator": operator,
        "query_token_ids": query_token_ids,
        "token_response": token_response,
        "search_response": search_response,
        "trust": trust,
        "fetched_records_file_name": fetched_file.name,
        "fetched_records": fetched_records_json,
        "direct_records": direct_records,
        "notes": [
            "Evidence package for retrieval verification.",
            "Includes retrieval proof, signed checkpoint, fetched encrypted records, and trust anchors.",
            "Plaintext disclosure and H(mi)=hi verification require the decryption pipeline.",
        ],
    }

    out = BASE_DIR / f"evidence_package_{client_id}_{safe_keyword(keyword)}.json"
    out.write_text(json.dumps(package, indent=2, ensure_ascii=False), encoding="utf-8")

    print()
    print("=" * 80)
    print(f"Evidence package saved: {out}")
    print(f"Records in search result: {len(result_record_ids)}")
    print("RESULT: PASS - evidence package exported.")
    print("=" * 80)


if __name__ == "__main__":
    main()
