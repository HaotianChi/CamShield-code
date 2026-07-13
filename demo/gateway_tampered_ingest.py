#!/usr/bin/env python3
"""
Gateway-side tamper demo: send a signed segment with corrupted payload bytes.

The gateway should reject the ingest before any record reaches the cloud.
Use this alongside the client web console only to confirm that tampered
camera-side data never enters the trusted pipeline.
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.camera import CameraMain
from core.wire import camera_segment_to_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="POST a tampered segment to the gateway.")
    parser.add_argument("--gateway-url", default="http://127.0.0.1:8000")
    parser.add_argument("--camera-id", default="cam01")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    gateway = args.gateway_url.rstrip("/")

    camera = CameraMain(camera_id=args.camera_id)
    segment = camera.produce_signed_segment(
        seq_no=int(time.time()) % 100000,
        timestamp=int(time.time()),
        sid="demo-tamper-001",
        raw_payload=b"CamShield gateway tamper demo payload",
    )

    payload = camera_segment_to_json(segment)
    raw = bytearray(base64.b64decode(payload["raw_payload_b64"]))
    raw[0] ^= 0xFF
    payload["raw_payload_b64"] = base64.b64encode(bytes(raw)).decode("ascii")

    body = {
        "segment": payload,
        "extra_keywords": ["event:demo", "location:lab", "object:person"],
        "role": "OWNER",
        "purpose": "SURVEILLANCE",
        "mode": "READ",
        "scope": args.camera_id,
        "access_class": "RAW",
    }

    print("[Gateway Tamper Demo] POST /ingest with corrupted payload bytes (signature unchanged)")
    resp = requests.post(f"{gateway}/ingest", json=body, timeout=30)
    print(f"[Gateway Tamper Demo] HTTP {resp.status_code}")
    try:
        print(resp.json())
    except Exception:
        print(resp.text)

    if resp.status_code >= 400:
        print("[Gateway Tamper Demo] EXPECTED: gateway rejected tampered segment.")
    else:
        print("[Gateway Tamper Demo] UNEXPECTED: gateway accepted tampered segment.")


if __name__ == "__main__":
    main()
