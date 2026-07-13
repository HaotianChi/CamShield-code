#!/usr/bin/env python3
"""CamShield simulation and deployment runner."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from core.abe import get_cpabe
from core.camera import CameraMain
from core.cap_u import abe_client_attrs
from core.client import Client
from core.cloud import Cloud
from core.gateway import Gateway
from core.models import payload_hash
from core.protocol_defaults import DEFAULT_CAPTURE_FPS, default_aus_per_segment


class OwnerClient(Client):
    role_name = "OWNER"
    client_id = "owner"
    attributes: list[str] = []


def _grant_owner_cap(gateway: Gateway, camera_id: str = "cam01") -> None:
    gateway.grant_client_cap(
        client_id="owner",
        camera_id=camera_id,
        abe_attrs=abe_client_attrs(
            role="OWNER",
            purpose="SURVEILLANCE",
            mode="READ",
            scope=camera_id,
        ),
        tag_patterns=[
            "camera:*",
            "location:*",
            "event:*",
            "case:*",
            "time:*",
            "service:*",
            "scale:*",
        ],
    )


def run_simulation(*, segments: int, use_charm: bool) -> None:
    print("========== CamShield Simulation Run ==========")

    abe = get_cpabe(use_charm=use_charm)
    gateway = Gateway(gateway_id="gateway-001", abe=abe)
    cloud = Cloud()
    camera = CameraMain(camera_id="cam01")

    gateway.enroll_camera(
        cid="cam01",
        camera_public_key=camera.public_key,
        expected_seq=1,
    )

    records = []

    for seq in range(1, segments + 1):
        raw_payload = (
            f"CamShield test video segment payload: frame data seq={seq}"
        ).encode("utf-8")

        segment = camera.produce_signed_segment(
            seq_no=seq,
            timestamp=int(time.time()),
            sid=f"seg-{seq:06d}",
            raw_payload=raw_payload,
        )

        record = gateway.process_segment(
            segment=segment,
            extra_keywords=[
                "event:motion",
                "location:lab",
                "object:person",
            ],
            role="OWNER",
            purpose="SURVEILLANCE",
            mode="READ",
            scope="cam01",
            access_class="RAW",
        )

        cloud.store_record(record)
        records.append(record)

        print(f"[OK] segment={segment.sid} rid={record.rid.hex()[:32]}...")

    checkpoint = cloud.build_checkpoint(
        gateway=gateway,
        epoch=records[0].epoch,
    )

    print(f"[OK] checkpoint root={checkpoint.root.hex()[:32]}...")

    _grant_owner_cap(gateway, camera_id="cam01")

    client = OwnerClient.create(
        gateway=gateway,
        abe=abe,
    )
    client.attach_cap_u(gateway.client_caps["owner"])

    response = client.search(
        gateway=gateway,
        cloud=cloud,
        keywords=["event:motion"],
        epoch=records[0].epoch,
        operator="AND",
        camera_id="cam01",
    )

    ok, msg = client.verify_search_response(response)
    if not ok:
        raise RuntimeError(f"Search verification failed: {msg}")

    print(f"[OK] search verified result_count={len(response.result_record_ids)}")

    if not response.result_record_ids:
        raise RuntimeError("No records returned")

    for rid in response.result_record_ids:
        fetched, msg = client.fetch_and_verify_record(
            cloud=cloud,
            record_id=rid,
        )

        if fetched is None:
            raise RuntimeError(f"Fetch/verify record failed: {msg}")

        plaintext, msg = client.decrypt_record(fetched)

        if plaintext is None:
            raise RuntimeError(f"Decrypt failed: {msg}")

        if payload_hash(plaintext) != fetched.SSi.hi:
            raise RuntimeError("Payload hash check failed")

        print(f"[OK] decrypted rid={rid.hex()[:32]}... bytes={len(plaintext)}")

    gateway.rotate_epoch(manual=True)

    segment_rot = camera.produce_signed_segment(
        seq_no=segments + 1,
        timestamp=int(time.time()),
        sid=f"seg-{segments + 1:06d}",
        raw_payload=b"CamShield post-rotation segment",
    )
    record_rot = gateway.process_segment(
        segment=segment_rot,
        extra_keywords=["event:motion"],
        role="OWNER",
        purpose="SURVEILLANCE",
        mode="READ",
        scope="cam01",
    )
    cloud.store_record(record_rot)

    plaintext_rot, msg = client.decrypt_record(record_rot)
    if plaintext_rot is None:
        raise RuntimeError(f"Post-rotation decrypt failed with stable SK_u: {msg}")
    print(
        f"[OK] post-rotation decrypt epoch={record_rot.epoch} "
        f"(same SK_u, no Gateway re-bootstrap) "
        f"rid={record_rot.rid.hex()[:32]}..."
    )

    checkpoint_rot = cloud.build_checkpoint(
        gateway=gateway,
        epoch=record_rot.epoch,
    )
    response_rot = client.search(
        gateway=gateway,
        cloud=cloud,
        keywords=["event:motion"],
        epoch=record_rot.epoch,
        operator="AND",
        camera_id="cam01",
    )
    ok_rot, msg_rot = client.verify_search_response(response_rot)
    if not ok_rot:
        raise RuntimeError(f"Post-rotation search verification failed: {msg_rot}")
    print(f"[OK] post-rotation search verified epoch={checkpoint_rot.epoch}")

    print("========== SIMULATION RUN PASSED ==========")


def run_deployment_role(args: argparse.Namespace) -> None:
    py = sys.executable
    roles_dir = Path(__file__).resolve().parent / "roles"

    if args.role == "tee":
        from core.tee_server import main as tee_main

        tee_main()
        return

    if args.role == "gateway":
        cmd = [py, str(roles_dir / "gateway.py")]
        if args.cloud_url:
            cmd.extend(["--cloud-url", args.cloud_url])
        if args.mock_abe:
            cmd.append("--mock-abe")
        raise SystemExit(subprocess.call(cmd + args.extra))

    if args.role == "cloud":
        raise SystemExit(subprocess.call([py, str(roles_dir / "cloud.py"), *args.extra]))

    if args.role == "camera":
        if not args.gateway_url:
            raise SystemExit("deployment camera role requires --gateway-url")
        cmd = [
            py,
            str(roles_dir / "camera.py"),
            "--gateway",
            args.gateway_url,
            "--tee-url",
            args.tee_url,
            "--camera-id",
            args.camera_id,
            "--device",
            args.device,
            "--fps",
            str(args.fps),
            "--size",
            args.size,
            "--aus-per-segment",
            str(args.aus_per_segment),
            "--max-segments",
            str(args.max_segments),
            "--keyword",
            "event:demo",
            "--keyword",
            "location:lab",
            "--keyword",
            f"camera:{args.camera_id}",
            "--scope",
            args.camera_id,
        ]
        raise SystemExit(subprocess.call(cmd + args.extra))

    if args.role == "client":
        if not args.gateway_url or not args.cloud_url:
            raise SystemExit(
                "deployment client role requires --gateway-url and --cloud-url"
            )
        cmd = [
            py,
            str(roles_dir / "client.py"),
            "--gateway-url",
            args.gateway_url,
            "--cloud-url",
            args.cloud_url,
            "--tee-url",
            args.tee_url,
            "--host",
            args.host,
            "--port",
            str(args.port),
        ]
        raise SystemExit(subprocess.call(cmd + args.extra))

    raise SystemExit(f"unknown deployment role: {args.role}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CamShield runner")
    parser.add_argument(
        "--mode",
        choices=("simulation", "deployment"),
        default="simulation",
        help="simulation: in-process test (default); deployment: distributed nodes",
    )

    parser.add_argument("--segments", type=int, default=1)
    parser.add_argument(
        "--no-charm",
        action="store_true",
        help="Use MockCPABE instead of Charm (simulation mode only)",
    )

    parser.add_argument(
        "--role",
        choices=("tee", "gateway", "cloud", "camera", "client"),
        help="Node role (deployment mode only)",
    )
    parser.add_argument("--gateway-url")
    parser.add_argument("--cloud-url")
    parser.add_argument("--tee-url", default="http://127.0.0.1:9000")
    parser.add_argument("--camera-id", default="cam01")
    parser.add_argument("--device", default="/dev/video0")
    parser.add_argument("--fps", type=int, default=DEFAULT_CAPTURE_FPS)
    parser.add_argument("--size", default="640x480")
    parser.add_argument(
        "--aus-per-segment",
        type=int,
        default=default_aus_per_segment(),
        help=f"Access units per segment (default ≈ 5s at --fps)",
    )
    parser.add_argument("--max-segments", type=int, default=20)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--mock-abe", action="store_true")
    parser.add_argument(
        "extra",
        nargs=argparse.REMAINDER,
        help="Extra arguments forwarded to the node script",
    )

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.mode == "simulation":
        if args.role:
            raise SystemExit("--role is only valid with --mode deployment")
        run_simulation(segments=args.segments, use_charm=not args.no_charm)
        return

    if not args.role:
        raise SystemExit("deployment mode requires --role tee|gateway|cloud|camera|client")

    run_deployment_role(args)


if __name__ == "__main__":
    main()
