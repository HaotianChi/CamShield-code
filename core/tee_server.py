
"""
Software-isolated TEE server for CamShield camera node.

This process owns:
    - camera signing key skC
    - gamma_prev chain state
    - camera-side attest logic

Camera node calls this server over localhost HTTP.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import resource
import sys
import threading
import time
import traceback
from pathlib import Path

from flask import Flask, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.camera import LocalTeeModule, TeeAttestRequest
from core.wire import b64e, b64d


DEFAULT_TEE_STATE_PATH = Path(
    os.environ.get("CAMSHIELD_TEE_STATE", ".camshield_tee_state.json")
)


def _private_key_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _save_tee_state(tee: LocalTeeModule, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "type": "camshield-tee-state-v1",
        "camera_id": tee._camera_id,
        "private_key_b64": base64.b64encode(_private_key_raw(tee._sk)).decode("ascii"),
        "gamma_prev_hex": tee.gamma_prev.hex(),
        "next_seq": tee.next_seq,
        "updated_at": int(time.time()),
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _load_or_create_tee(camera_id: str, path: Path) -> LocalTeeModule:
    path = Path(path)
    if not path.exists():
        tee = LocalTeeModule(camera_id)
        _save_tee_state(tee, path)
        return tee

    data = json.loads(path.read_text(encoding="utf-8"))
    stored_camera = str(data.get("camera_id", camera_id))
    if stored_camera != camera_id:
        raise RuntimeError(
            f"TEE state camera mismatch: state={stored_camera}, requested={camera_id}"
        )
    raw = base64.b64decode(data["private_key_b64"])
    return LocalTeeModule(
        camera_id,
        signing_key=Ed25519PrivateKey.from_private_bytes(raw),
        gamma_prev=bytes.fromhex(data.get("gamma_prev_hex", "00" * 32)),
        next_seq=int(data.get("next_seq", 1)),
    )


def create_app(camera_id: str, state_path: Path | None = None) -> Flask:
    app = Flask(__name__)

    resolved_state_path = Path(state_path or DEFAULT_TEE_STATE_PATH)
    tee = _load_or_create_tee(camera_id, resolved_state_path)
    state_lock = threading.Lock()

    metrics = {
        "attest_count": 0,
        "total_attest_ms": 0.0,
        "last_attest_ms": 0.0,
        "last_payload_bytes": 0,
        "total_payload_bytes": 0,
    }

    @app.get("/health")
    def health():
        return jsonify(
            {
                    "ok": True,
                    "camera_id": camera_id,
                    "pid": os.getpid(),
                    "next_seq": tee.next_seq,
                    "state_path": str(resolved_state_path),
                }
            )

    @app.get("/state")
    def state():
        with state_lock:
            return jsonify(
                {
                    "ok": True,
                    "camera_id": camera_id,
                    "public_key_b64": b64e(tee.public_key_bytes),
                    "gamma_prev_hex": tee.gamma_prev.hex(),
                    "next_seq": tee.next_seq,
                }
            )

    @app.get("/public-key")
    def public_key():
        return jsonify(
            {
                "ok": True,
                "camera_id": camera_id,
                "public_key_b64": b64e(tee.public_key_bytes),
            }
        )

    @app.post("/reset")
    def reset():
        """
        Reset camera-side hash-chain state for a new session.

        Aligns gamma_prev with Gateway enrollment (expected_seq starts at 1).
        """
        obj = request.get_json(force=True, silent=True) or {}
        cid = obj.get("camera_id") or obj.get("cid") or camera_id

        if cid != camera_id:
            return jsonify(
                {
                    "ok": False,
                    "error": f"camera_id mismatch: server={camera_id}, requested={cid}",
                }
            ), 400

        with state_lock:
            tee._gamma_prev = b"\x00" * 32
            tee._next_seq = 1
            _save_tee_state(tee, resolved_state_path)


        metrics["attest_count"] = 0
        metrics["total_attest_ms"] = 0.0
        metrics["last_attest_ms"] = 0.0
        metrics["last_payload_bytes"] = 0
        metrics["total_payload_bytes"] = 0

        return jsonify(
            {
                "ok": True,
                "camera_id": camera_id,
                "reset": "gamma_prev",
                "gamma_prev_hex": tee._gamma_prev.hex(),
            }
        )

    @app.post("/tee/reset")
    def tee_reset_alias():
        return reset()

    @app.post("/camera/reset")
    def camera_reset_alias():
        return reset()


    @app.post("/attest")
    def attest():
        try:
            obj = request.get_json(force=True)

            req = TeeAttestRequest(
                cid=obj["cid"],
                sid=obj["sid"],
                seq=int(obj["seq"]),
                timestamp=int(obj["timestamp"]),
                raw_payload=b64d(obj["raw_payload_b64"]),
            )

            t0 = time.perf_counter()
            with state_lock:
                resp = tee.attest_segment(req)
                _save_tee_state(tee, resolved_state_path)
            t1 = time.perf_counter()

            elapsed_ms = (t1 - t0) * 1000.0
            payload_len = len(req.raw_payload)

            metrics["attest_count"] += 1
            metrics["total_attest_ms"] += elapsed_ms
            metrics["last_attest_ms"] = elapsed_ms
            metrics["last_payload_bytes"] = payload_len
            metrics["total_payload_bytes"] += payload_len

            return jsonify(
                {
                    "ok": True,
                    "hi_b64": b64e(resp.hi),
                    "gamma_prev_b64": b64e(resp.gamma_prev),
                    "gamma_b64": b64e(resp.gamma),
                    "sigma_c_b64": b64e(resp.sigma_c),
                    "attest_ms": elapsed_ms,
                    "payload_bytes": payload_len,
                }
            )

        except Exception as exc:
            traceback.print_exc()
            return jsonify(
                {
                    "ok": False,
                    "error": str(exc),
                }
            ), 500

    @app.get("/metrics")
    def get_metrics():
        count = metrics["attest_count"]
        avg_attest_ms = metrics["total_attest_ms"] / count if count else 0.0
        avg_payload_bytes = metrics["total_payload_bytes"] / count if count else 0.0

        usage = resource.getrusage(resource.RUSAGE_SELF)

        return jsonify(
            {
                "ok": True,
                "camera_id": camera_id,
                "pid": os.getpid(),
                "attest_count": count,
                "last_attest_ms": metrics["last_attest_ms"],
                "avg_attest_ms": avg_attest_ms,
                "last_payload_bytes": metrics["last_payload_bytes"],
                "avg_payload_bytes": avg_payload_bytes,
                "max_rss_kb": usage.ru_maxrss,
                "user_cpu_sec": usage.ru_utime,
                "system_cpu_sec": usage.ru_stime,
            }
        )

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--camera-id", default="cam01")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        "--state-path",
        default=str(DEFAULT_TEE_STATE_PATH),
        help="Persistent camera signing key and hash-chain state",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    app = create_app(args.camera_id, Path(args.state_path))

    print("[TEE] Software-isolated TEE server")
    print(f"[TEE] camera_id={args.camera_id}")
    print(f"[TEE] listening on http://{args.host}:{args.port}")
    print(f"[TEE] pid={os.getpid()}")

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
