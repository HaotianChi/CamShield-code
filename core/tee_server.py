               
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
import os
import resource
import time
import traceback

from flask import Flask, jsonify, request

from core.camera import LocalTeeModule, TeeAttestRequest
from core.wire import b64e, b64d


def create_app(camera_id: str) -> Flask:
    app = Flask(__name__)

    tee = LocalTeeModule(camera_id)

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
        Reset camera-side hash-chain state for a fresh camera session.

        Gateway enrollment resets expected_seq to 1. For the same new run,
        the remote software TEE must also reset gamma_prev to gamma_0.
        This keeps the camera-side chain state aligned with Gateway state.
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

        tee._gamma_prev = b"\x00" * 32

                                                                              
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
            resp = tee.attest_segment(req)
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    app = create_app(args.camera_id)

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
