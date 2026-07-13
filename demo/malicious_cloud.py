"""Malicious cloud server for attack-detection demos."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

from flask import Flask, jsonify

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.attacks import get_attack  # noqa: E402
from core import cloud_server  # noqa: E402


def _attach_state(app: Flask, state: Any) -> None:
    app.config["CAMSHIELD_CLOUD_STATE"] = state


def _get_state(app: Flask) -> Any:
    return app.config["CAMSHIELD_CLOUD_STATE"]


def create_malicious_app(attack_id: str) -> Flask:
    attack = get_attack(attack_id)
    app = cloud_server.create_app()
    state = _extract_state(app)
    _attach_state(app, state)

    original_search = app.view_functions["search"]
    original_get_record = app.view_functions["get_record"]

    def malicious_search():
        response = original_search()
        if attack.mutate_search is None:
            return response
        if response.status_code != 200:
            return response
        data = response.get_json(silent=True) or {}
        if not data.get("ok"):
            return response
        mutated = attack.mutate_search(data)
        return jsonify(mutated), 200

    def malicious_get_record(rid: str):
        response = original_get_record(rid)
        if attack.mutate_record is None:
            return response
        if response.status_code != 200:
            return response
        payload = response.get_json(silent=True) or {}
        if not payload.get("ok"):
            return response
        record = payload.get("record")
        if not isinstance(record, dict):
            return response
        with state.lock:
            records = dict(state.records)
        mutated_record = attack.mutate_record(record, state_records=records)
        payload = dict(payload)
        payload["record"] = mutated_record
        return jsonify(payload), 200

    app.view_functions["search"] = malicious_search
    app.view_functions["get_record"] = malicious_get_record

    @app.get("/demo/attack")
    def demo_attack_info():
        return jsonify(
            {
                "ok": True,
                "attack_id": attack.attack_id,
                "title": attack.title,
                "injected_inconsistency": attack.injected_inconsistency,
                "expected_client_signal": attack.expected_client_signal,
            }
        )

    return app


def _extract_state(app: Flask) -> Any:
    """Reach CloudState created inside create_app via the debug route closure."""
    get_state = app.view_functions.get("debug_state")
    if get_state is None:
        raise RuntimeError("Could not locate cloud state on Flask app")

    closure = get_state.__closure__
    if not closure:
        raise RuntimeError("Could not inspect cloud state closure")

    for cell in closure:
        value = cell.cell_contents
        if isinstance(value, cloud_server.CloudState):
            return value

    raise RuntimeError("CloudState not found in Flask app closures")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a malicious cloud that injects a selected attack scenario."
    )
    parser.add_argument(
        "--attack",
        required=True,
        help="Attack ID (A1–A11). Use demo/list_attacks.py to print details.",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8100)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    attack = get_attack(args.attack)
    app = create_malicious_app(args.attack)

    print("[Demo Cloud] Malicious cloud server")
    print(f"[Demo Cloud] attack={attack.attack_id} — {attack.title}")
    print(f"[Demo Cloud] listening on http://{args.host}:{args.port}")
    print(f"[Demo Cloud] pid={os.getpid()}")
    print(f"[Demo Cloud] expected client signal: {attack.expected_client_signal}")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
