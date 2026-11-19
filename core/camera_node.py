
"""
Camera node for CamShield AU deployment.

Pipeline:
    USB camera / ffmpeg testsrc
        -> H.264 Annex-B stdout
        -> NALU/AU parser
        -> AU group as m_i
        -> CameraMain.produce_signed_segment()
        -> HTTP POST (m_i, SS_i) to Gateway

This uses HTTP as the current transport protocol.
It does not implement RTP.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import time

import requests
from pathlib import Path
import csv

from core.camera import CameraMain
from core.camera_sensor import FFmpegH264LiveSensor, FileH264AUSensor
from core.protocol_defaults import (
    DEFAULT_CAPTURE_FPS,
    DEFAULT_EPOCH_DURATION_S,
    DEFAULT_SEGMENT_DURATION_S,
    default_aus_per_segment,
    segment_duration_s,
)
from core.wire import b64e, camera_segment_to_json
from core.remote_tee_client import RemoteTeeClient


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument("--gateway", required=True, help="Gateway base URL, e.g. http://192.168.1.102:8000")
    parser.add_argument("--camera-id", default="cam01")
    parser.add_argument("--max-segments", type=int, default=10)


    parser.add_argument("--file", default=None, help="Use offline .h264 file instead of live ffmpeg")
    parser.add_argument("--testsrc", action="store_true", help="Use ffmpeg testsrc instead of USB camera")
    parser.add_argument("--device", default="/dev/video0")
    parser.add_argument(
        "--avfoundation-index",
        default=None,
        help="Use macOS AVFoundation video device index, e.g. 1 for '-i 1:none'",
    )


    parser.add_argument("--fps", type=int, default=DEFAULT_CAPTURE_FPS)
    parser.add_argument("--size", default="640x360")
    parser.add_argument("--bitrate", default="500k")
    parser.add_argument("--ffmpeg-bin", default="ffmpeg")
    parser.add_argument(
        "--aus-per-segment",
        type=int,
        default=default_aus_per_segment(),
        help=f"Access units per segment (default ≈ {DEFAULT_SEGMENT_DURATION_S}s at --fps)",
    )
    parser.add_argument(
        "--realtime-pacing",
        action="store_true",
        help="Pace segment generation by wall-clock time so that each segment lasts approximately aus_per_segment / fps seconds.",
    )


    parser.add_argument("--keyword", action="append", default=None)
    parser.add_argument("--scope", default=None)
    parser.add_argument("--timing-csv", default=None, help="Write per-segment ingest timing CSV")
    parser.add_argument(
        "--ingest-timeout-s",
        type=float,
        default=240.0,
        help="HTTP timeout for Camera -> Gateway /ingest. Use a larger value when Gateway retries Cloud /store-batch.",
    )
    parser.add_argument(
        "--run-id",
        default="",
        help="Optional session identifier prepended to segment sid to avoid RID reuse across runs.",
    )
    parser.add_argument(
        "--spool-dir",
        default=os.environ.get("CAMSHIELD_CAMERA_SPOOL", ".camshield_camera_spool"),
        help="Durable directory for signed segments awaiting Gateway acknowledgement",
    )
    parser.add_argument("--retry-forever", action="store_true")
    parser.add_argument("--retry-delay-s", type=float, default=3.0)
    parser.add_argument("--disk-stop-percent", type=float, default=90.0)
    parser.add_argument("--disk-resume-percent", type=float, default=85.0)

    parser.add_argument(
        "--tee-url",
        default=None,
        help="Local software TEE URL, e.g. http://127.0.0.1:9000. If omitted, use in-process LocalTeeModule.",
    )
    parser.add_argument(
        "--reset-tee-on-start",
        action="store_true",
        help="Reset remote TEE camera hash-chain state before starting a new camera session.",
    )
    parser.add_argument(
        "--no-reset-tee-on-start",
        action="store_true",
        help="Do not reset remote TEE state even if --tee-url is used.",
    )

    return parser.parse_args()


def post_json(url: str, obj: dict, timeout: int = 60) -> dict:
    headers = {}
    api_token = os.environ.get("CAMSHIELD_API_TOKEN", "").strip()
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    resp = requests.post(url, json=obj, headers=headers, timeout=timeout)
    try:
        data = resp.json()
    except Exception:
        raise RuntimeError(f"Non-JSON response from {url}: status={resp.status_code}, text={resp.text[:500]}")

    if resp.status_code >= 400 or not data.get("ok", False):
        raise RuntimeError(f"Request failed: url={url}, status={resp.status_code}, data={data}")

    return data


def _write_spool(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _send_spooled(
    *,
    gateway_url: str,
    path: Path,
    timeout_s: float,
    retry_forever: bool,
    retry_delay_s: float,
) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    while True:
        try:
            response = post_json(
                f"{gateway_url}/ingest",
                obj,
                timeout=max(1, int(timeout_s)),
            )
            path.unlink(missing_ok=True)
            return response
        except Exception as exc:
            if not retry_forever:
                raise
            print(
                f"[CameraNode] Gateway unavailable; segment remains at {path}. "
                f"retry in {retry_delay_s:.1f}s: {exc}"
            )
            time.sleep(max(0.2, retry_delay_s))


def _validate_resume_alignment(
    *,
    tee_next_seq: int,
    pending_seq: int | None,
    gateway_expected_seq: int,
) -> str:
    """
    Validate the durable camera, TEE, and Gateway recovery positions.

    A Gateway that is exactly one sequence ahead of the oldest pending segment
    may have persisted the camera-chain transition before its acknowledgement.
    The Gateway ingest path can safely replay that segment after checking the
    persisted chain state.
    """
    if pending_seq is None:
        if gateway_expected_seq != tee_next_seq:
            raise RuntimeError(
                "Camera resume state is inconsistent: "
                f"TEE next_seq={tee_next_seq}, "
                f"Gateway expected_seq={gateway_expected_seq}, "
                "and no durable segment is available to reconcile the gap. "
                "Use camshieldctl reset-camera-chain only if a new evidence "
                "chain is intended."
            )
        return "aligned"

    if gateway_expected_seq == pending_seq:
        return "resend-pending"

    if gateway_expected_seq == pending_seq + 1:
        return "recover-incomplete-ack"

    raise RuntimeError(
        "Camera resume state is inconsistent: "
        f"oldest pending seq={pending_seq}, "
        f"TEE next_seq={tee_next_seq}, "
        f"Gateway expected_seq={gateway_expected_seq}. "
        "Automatic recovery only supports an unacknowledged pending segment "
        "or a Gateway that is exactly one sequence ahead."
    )


def reset_remote_tee_state(tee_url: str, camera_id: str) -> None:
    """
    Reset remote TEE hash-chain state for a new camera session.

    Gateway enrollment starts expected_seq at 1; the TEE must reset gamma_prev
    to gamma_0 so the first segment verifies against Gateway chain state.
    """
    base = tee_url.rstrip("/")
    payload = {
        "camera_id": camera_id,
        "cid": camera_id,
        "expected_seq": 1,
        "reset_chain": True,
    }

    endpoints = [
        "/reset",
        "/tee/reset",
        "/camera/reset",
        "/reset-camera",
        "/state/reset",
    ]

    errors = []
    for ep in endpoints:
        url = base + ep
        try:
            resp = requests.post(url, json=payload, timeout=10)
            text = resp.text[:500]
            try:
                data = resp.json()
            except Exception:
                data = {"raw_text": text}

            if resp.status_code < 400 and data.get("ok", False):
                print(f"[CameraNode] Remote TEE reset OK via {url}: {data}")
                return

            errors.append(f"{url}: status={resp.status_code}, data={data}")
        except Exception as e:
            errors.append(f"{url}: {repr(e)}")

    raise RuntimeError(
        "Remote TEE reset failed. Either add a reset endpoint to the TEE server "
        "or restart the TEE process before each new camera session. Tried:\n"
        + "\n".join(errors[-10:])
    )


def main() -> None:
    args = parse_args()

    gateway_url = args.gateway.rstrip("/")

    if args.file:
        sensor = FileH264AUSensor(
            h264_path=args.file,
            aus_per_segment=args.aus_per_segment,
            loop=True,
        )
        print(f"[CameraNode] Using offline file sensor: {args.file}")
    else:
        input_format = "avfoundation" if args.avfoundation_index is not None else "v4l2"
        device = (
            f"{args.avfoundation_index}:none"
            if args.avfoundation_index is not None
            else args.device
        )
        sensor = FFmpegH264LiveSensor(
            device=device,
            fps=args.fps,
            size=args.size,
            aus_per_segment=args.aus_per_segment,
            ffmpeg_bin=args.ffmpeg_bin,
            bitrate=args.bitrate,
            testsrc=args.testsrc,
            input_format=input_format,
        )
        if args.avfoundation_index is not None:
            print(f"[CameraNode] Using macOS AVFoundation camera index: {args.avfoundation_index}")
        else:
            print("[CameraNode] Using live ffmpeg H.264 sensor")

    if args.tee_url:
        if args.reset_tee_on_start and not args.no_reset_tee_on_start:
            reset_remote_tee_state(args.tee_url, args.camera_id)

        tee = RemoteTeeClient(
            base_url=args.tee_url,
            camera_id=args.camera_id,
        )
        tee_state = tee.state()
        print(f"[CameraNode] Using remote software TEE: {args.tee_url}")
    else:
        tee = None
        tee_state = {"next_seq": 1, "gamma_prev_hex": "00" * 32}
        print("[CameraNode] Using in-process LocalTeeModule")

    camera = CameraMain(
        camera_id=args.camera_id,
        sensor=sensor,
        tee=tee,
    )

    spool_dir = Path(args.spool_dir)
    spool_dir.mkdir(parents=True, exist_ok=True)
    pending_paths = sorted(spool_dir.glob("segment-*.json"))
    tee_next_seq = int(tee_state.get("next_seq", 1))
    pending_seq = None
    resume_gamma_hex = str(tee_state.get("gamma_prev_hex", "00" * 32))
    if pending_paths:
        try:
            pending_segment = json.loads(
                pending_paths[0].read_text(encoding="utf-8")
            )["segment"]
            pending_seq = int(pending_segment["seq"])
            import base64

            resume_gamma_hex = base64.b64decode(
                pending_segment["gamma_prev_b64"]
            ).hex()
        except Exception:
            pending_seq = None
    resume_seq = min(tee_next_seq, pending_seq) if pending_seq is not None else tee_next_seq

    enroll_obj = {
        "cid": args.camera_id,
        "camera_public_key_b64": b64e(camera.public_key_bytes),
        "expected_seq": resume_seq,
        "initial_gamma_hex": resume_gamma_hex,
        "resume": True,
    }

    print("[CameraNode] Enrolling camera at Gateway...")
    enroll_resp = post_json(f"{gateway_url}/enroll", enroll_obj)
    print(f"[CameraNode] Enrolled: {enroll_resp}")
    gateway_expected_seq = int(enroll_resp["expected_seq"])
    resume_mode = _validate_resume_alignment(
        tee_next_seq=tee_next_seq,
        pending_seq=pending_seq,
        gateway_expected_seq=gateway_expected_seq,
    )
    print(
        f"[CameraNode] Resume alignment: mode={resume_mode}, "
        f"tee_next_seq={tee_next_seq}, pending_seq={pending_seq}, "
        f"gateway_expected_seq={gateway_expected_seq}"
    )
    print(
        f"[CameraNode] Timing: Δs={DEFAULT_SEGMENT_DURATION_S}s (default), "
        f"Δe={DEFAULT_EPOCH_DURATION_S}s; "
        f"segment≈{segment_duration_s(aus_per_segment=args.aus_per_segment, fps=args.fps):.1f}s "
        f"(aus_per_segment={args.aus_per_segment}, fps={args.fps})"
    )

    for pending_path in pending_paths:
        print(f"[CameraNode] Resending durable segment: {pending_path}")
        pending_resp = _send_spooled(
            gateway_url=gateway_url,
            path=pending_path,
            timeout_s=args.ingest_timeout_s,
            retry_forever=args.retry_forever,
            retry_delay_s=args.retry_delay_s,
        )
        print(f"[CameraNode] Durable segment accepted: {pending_resp}")

    keywords = args.keyword or [
        "event:motion",
        "location:lab",
        "object:person",
    ]

    scope = args.scope or args.camera_id

    segment_period_s = float(args.aus_per_segment) / max(float(args.fps), 1.0)
    if args.realtime_pacing:
        print(
            f"[CameraNode] Realtime pacing enabled: "
            f"aus_per_segment={args.aus_per_segment}, fps={args.fps}, "
            f"target_segment_period={segment_period_s:.3f}s"
        )

    seq = tee_next_seq
    produced = 0
    while args.max_segments == 0 or produced < args.max_segments:
        usage = shutil.disk_usage(spool_dir)
        disk_percent = (usage.used / usage.total) * 100.0
        if disk_percent >= args.disk_stop_percent:
            while disk_percent >= args.disk_resume_percent:
                print(
                    f"[CameraNode] ALERT: spool filesystem is {disk_percent:.1f}% "
                    f"full; capture paused until below "
                    f"{args.disk_resume_percent:.1f}%"
                )
                time.sleep(30)
                usage = shutil.disk_usage(spool_dir)
                disk_percent = (usage.used / usage.total) * 100.0
        t_segment_cycle0 = time.perf_counter()
        if args.run_id:
            sid = f"{args.run_id}-seg-{seq:06d}"
        else:
            sid = f"{args.camera_id}-seg-{seq:012d}"
        timestamp = int(time.time())

        print(f"[CameraNode] Capturing AU segment seq={seq} sid={sid}...")

        t_signed0 = time.perf_counter()
        segment = camera.produce_signed_segment(
            seq_no=seq,
            timestamp=timestamp,
            sid=sid,
        )
        t_signed1 = time.perf_counter()
        signed_segment_ms = (t_signed1 - t_signed0) * 1000.0

        obj = {
            "segment": camera_segment_to_json(segment),
            "extra_keywords": keywords,
            "role": "OWNER",
            "purpose": "SURVEILLANCE",
            "mode": "READ",
            "scope": scope,
            "access_class": "RAW",
        }

        print(
            f"[CameraNode] Sending sid={segment.sid}, "
            f"bytes={len(segment.raw_payload)}, hi={segment.hi.hex()[:16]}..."
        )

        t_ingest_start_wall = time.time()
        t_ingest0 = time.perf_counter()
        spool_path = spool_dir / f"segment-{seq:012d}.json"
        _write_spool(spool_path, obj)
        resp = _send_spooled(
            gateway_url=gateway_url,
            path=spool_path,
            timeout_s=args.ingest_timeout_s,
            retry_forever=args.retry_forever,
            retry_delay_s=args.retry_delay_s,
        )
        t_ingest1 = time.perf_counter()
        t_ingest_end_wall = time.time()
        ingest_ms = (t_ingest1 - t_ingest0) * 1000.0

        if args.timing_csv:
            timing_path = Path(args.timing_csv)
            timing_path.parent.mkdir(parents=True, exist_ok=True)
            write_header = not timing_path.exists()
            with timing_path.open("a", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=[
                        "camera_id",
                        "seq",
                        "sid",
                        "fps",
                        "size",
                        "aus_per_segment",
                        "payload_bytes",
                        "signed_segment_ms",
                        "ingest_ms",
                        "rid",
                        "epoch",
                        "record_count",
                        "start_wall",
                        "end_wall",
                    ],
                )
                if write_header:
                    w.writeheader()
                w.writerow({
                    "camera_id": args.camera_id,
                    "seq": seq,
                    "sid": segment.sid,
                    "fps": args.fps,
                    "size": args.size,
                    "aus_per_segment": args.aus_per_segment,
                    "payload_bytes": len(segment.raw_payload),
                    "signed_segment_ms": signed_segment_ms,
                    "ingest_ms": ingest_ms,
                    "rid": resp.get("rid", ""),
                    "epoch": resp.get("epoch", ""),
                    "record_count": resp.get("record_count", ""),
                    "start_wall": t_ingest_start_wall,
                    "end_wall": t_ingest_end_wall,
                })

        print(f"[CameraNode] ingest_ms={ingest_ms:.2f}")

        print(
            f"[CameraNode] Gateway OK: rid={resp['rid'][:32]}..., "
            f"epoch={resp['epoch']}, record_count={resp['record_count']}"
        )

        produced += 1
        has_more = args.max_segments == 0 or produced < args.max_segments
        if args.realtime_pacing and has_more:
            elapsed_s = time.perf_counter() - t_segment_cycle0
            sleep_s = segment_period_s - elapsed_s
            if sleep_s > 0:
                print(
                    f"[CameraNode] realtime pacing sleep={sleep_s:.3f}s "
                    f"(elapsed={elapsed_s:.3f}s, target={segment_period_s:.3f}s)"
                )
                time.sleep(sleep_s)
            else:
                print(
                    f"[CameraNode] realtime pacing overrun={-sleep_s:.3f}s "
                    f"(elapsed={elapsed_s:.3f}s, target={segment_period_s:.3f}s)"
                )
        seq += 1

    if hasattr(sensor, "close"):
        sensor.close()

    print("[CameraNode] Done")


if __name__ == "__main__":
    main()
