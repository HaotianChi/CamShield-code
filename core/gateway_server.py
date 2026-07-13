"""
Gateway HTTP service for distributed deployment.
"""

from __future__ import annotations
import os

import argparse
import base64
import json
import threading
import time
import traceback
from typing import Any

import requests
from flask import Flask, jsonify, request

from core.cloud import Cloud
from core.gateway import Gateway
from core.gateway_persistence import load_or_init_gateway_state, save_gateway_state
from core.epoch import EpochManager
from core.abe import get_cpabe
from core.ed25519_sig import load_public_key, public_key_bytes, sign
from core.models import CHECKPOINT_CHAIN_GENESIS, compute_checkpoint_chain_value
from core.ordered_merkle import build_ordered_merkle_snapshot
from core.cap_u import (
    abe_access_attrs,
    abe_client_attrs,
    extend_cap_u,
    grant_cap_u,
    parse_abe_attrs_from_policy,
    validate_cap_u_for_bootstrap,
    validate_cap_u_for_search,
)
from core.idx_cap_u import attach_idx_cap_u
from core.protocol_defaults import (
    DEFAULT_CAPTURE_FPS,
    DEFAULT_EPOCH_DURATION_S,
    DEFAULT_SEGMENT_DURATION_S,
    default_aus_per_segment,
)
from core.wire import b64d, camera_segment_from_json


                                          
def _camshield_extract_status(result):
    if isinstance(result, tuple):
        for x in result[:2]:
            if isinstance(x, int):
                return x
            if isinstance(x, str) and x.isdigit():
                return int(x)
    if hasattr(result, "status_code"):
        return int(result.status_code)
    return None


def _camshield_sleep_for_retry(attempt):
    base = float(os.environ.get("CAMSHIELD_GATEWAY_RETRY_SLEEP", "1.0"))
    return min(10.0, base * attempt)


def _camshield_should_retry_status(status):
    return status in {429, 500, 502, 503, 504}



def camshield_requests_post_with_retries(*args, **kwargs):
    attempts = int(os.environ.get("CAMSHIELD_GATEWAY_POST_RETRIES", "30"))
    last_exc = None
    url = args[0] if args else kwargs.get("url", "<unknown>")

    for attempt in range(1, attempts + 1):
        try:
            resp = requests.post(*args, **kwargs)
            status = int(getattr(resp, "status_code", 0))

            if not _camshield_should_retry_status(status):
                return resp

            if attempt >= attempts:
                print(f"[gateway retry] giving up HTTP {status} url={url} after {attempts} attempts")
                return resp

            sleep_s = _camshield_sleep_for_retry(attempt)
            print(f"[gateway retry] HTTP {status} url={url}; attempt {attempt}/{attempts}, sleep={sleep_s:.2f}s")
            time.sleep(sleep_s)

        except Exception as exc:
            last_exc = exc

            if attempt >= attempts:
                print(f"[gateway retry] giving up exception url={url}: {exc}")
                raise

            sleep_s = _camshield_sleep_for_retry(attempt)
            print(f"[gateway retry] exception url={url}: {exc}; attempt {attempt}/{attempts}, sleep={sleep_s:.2f}s")
            time.sleep(sleep_s)

    if last_exc is not None:
        raise last_exc
    return requests.post(*args, **kwargs)





                                 
                                  
                                 

CLIENT_PROFILES = {
    "owner": {
        "allowed_patterns": [
            "camera:*",
            "location:*",
            "event:*",
            "case:*",
            "time:*",
            "service:*",
            "scale:*",
        ]
    },
    "auditor": {
        "allowed_patterns": [
            "camera:*",
            "location:*",
            "event:recorded",
            "time:*",
        ]
    },
    "guest": {
        "allowed_patterns": []
    },
}



def _client_is_revoked(state: dict, client_id: str) -> bool:
    return client_id in state.get("revoked_clients", set())


def _lease_status(state: dict, client_id: str) -> dict:
    leases = state.setdefault("client_leases", {})
    return leases.get(client_id, {})


def _match_tag_pattern(pattern: str, keyword: str) -> bool:
    """
    Match a keyword against a simple scoped tag pattern.

    Examples:
      camera:*       matches camera:cam01
      event:*        matches event:recorded
      event:recorded matches event:recorded only
    """
    if pattern == "*":
        return True

    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return keyword.startswith(prefix)

    return keyword == pattern


def authorize_client_keyword(client_id: str, keyword: str) -> bool:
    profile = CLIENT_PROFILES.get(client_id)
    if profile is None:
        return False

    allowed_patterns = profile.get("allowed_patterns", [])
    return any(_match_tag_pattern(p, keyword) for p in allowed_patterns)


def authorize_client_keywords(client_id: str, keywords: list[str]) -> tuple[bool, list[str]]:
    denied = [w for w in keywords if not authorize_client_keyword(client_id, w)]
    return len(denied) == 0, denied


def _store_client_cap(state: dict, gateway: Gateway, cap: dict) -> dict:
    client_id = str(cap["client_id"])
    state.setdefault("client_leases", {})[client_id] = cap
    gateway.client_caps[client_id] = cap
    return cap


def _client_cap(state: dict, gateway: Gateway, client_id: str) -> dict | None:
    cap = state.get("client_leases", {}).get(client_id)
    if cap:
        gateway.client_caps[client_id] = cap
    return cap


def _grant_client_cap(
    state: dict,
    gateway: Gateway,
    *,
    client_id: str,
    camera_id: str,
    epoch_max: int | None = None,
    version_max: int | None = None,
    expires_at: int = 0,
    abe_attrs: list[str] | None = None,
) -> dict:
    profile = CLIENT_PROFILES.get(client_id, {})
    e = gateway.epoch_manager.current_epoch()
    v = gateway.epoch_manager.current_version()
    if abe_attrs is None:
        abe_attrs = abe_client_attrs(
            role="OWNER",
            purpose="SURVEILLANCE",
            mode="READ",
            scope=camera_id,
        )
    cap = grant_cap_u(
        client_id=client_id,
        camera_id=camera_id,
        abe_attrs=abe_attrs,
        current_epoch=e,
        current_version=v,
        epoch_max=epoch_max,
        version_max=version_max,
        expires_at=expires_at,
        tag_patterns=profile.get("allowed_patterns"),
    )
    cap = attach_idx_cap_u(
        cap,
        kidx_master=gateway.epoch_manager.Kidx_master,
        cameras=[camera_id],
    )
    return _store_client_cap(state, gateway, cap)




def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ordered_checkpoint_signed_bytes(
    *,
    epoch: int,
    version: int,
    timestamp: int,
    root_hex: str,
    chain_hex: str,
) -> bytes:
    """
    Bytes signed by Gateway for ordered checkpoint.

    Client Web will use the same canonical format later to verify signature.
    """
    return canonical_json_bytes(
        {
            "type": "camshield-ordered-checkpoint-v1",
            "epoch": epoch,
            "version": version,
            "timestamp": timestamp,
            "root_hex": root_hex,
            "chain_hex": chain_hex,
        }
    )


def to_jsonable(obj: Any) -> Any:
    """
    Convert Pydantic models / bytes / nested containers into JSON-safe objects.

    For JSON persistence, bytes fields are encoded as hex strings.

    Compatible with both Pydantic v1 (.dict) and v2 (.model_dump).
    """
    if isinstance(obj, bytes):
        return obj.hex()

    if isinstance(obj, bytearray):
        return bytes(obj).hex()

    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, bytes):
                key = k.hex()
            else:
                key = str(k)
            out[key] = to_jsonable(v)
        return out

    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(v) for v in obj]

                 
    if hasattr(obj, "model_dump"):
        return to_jsonable(obj.model_dump(mode="python"))

                 
    if hasattr(obj, "dict"):
        return to_jsonable(obj.dict())

                                
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj

                                                                         
    return str(obj)


def _resolve_epoch_duration_s(epoch_duration_s: int | None) -> int:
    if epoch_duration_s is not None:
        return max(1, int(epoch_duration_s))
    env = os.environ.get("CAMSHIELD_EPOCH_DURATION_S")
    if env:
        return max(1, int(env))
    return DEFAULT_EPOCH_DURATION_S


def _finalize_epoch_checkpoint(state: dict[str, Any], cloud: Cloud, epoch: int) -> None:
    if state.get("last_ordered_checkpoint"):
        state["final_epoch_checkpoints"][str(epoch)] = state["last_ordered_checkpoint"]
    cloud.close_epoch(epoch)


def apply_scheduled_epoch_rotations(
    gateway: Gateway,
    state: dict[str, Any],
    cloud: Cloud,
    *,
    manual: bool = False,
) -> list[dict[str, Any]]:
    """Apply manual rotation or every scheduled transition that is currently due."""
    summaries: list[dict[str, Any]] = []

    if manual:
        before_epoch = gateway.epoch_manager.current_epoch()
        before_version = gateway.epoch_manager.current_version()
        _finalize_epoch_checkpoint(state, cloud, before_epoch)
        gateway.rotate_epoch(manual=True)
        save_gateway_state(gateway, state)
        summaries.append(
            {
                "before_epoch": before_epoch,
                "before_version": before_version,
                "after_epoch": gateway.epoch_manager.current_epoch(),
                "after_version": gateway.epoch_manager.current_version(),
                "manual": True,
            }
        )
        return summaries

    while gateway.epoch_manager.seconds_until_rotation() == 0:
        before_epoch = gateway.epoch_manager.current_epoch()
        before_version = gateway.epoch_manager.current_version()
        _finalize_epoch_checkpoint(state, cloud, before_epoch)
        gateway.rotate_epoch(manual=False)
        save_gateway_state(gateway, state)
        summaries.append(
            {
                "before_epoch": before_epoch,
                "before_version": before_version,
                "after_epoch": gateway.epoch_manager.current_epoch(),
                "after_version": gateway.epoch_manager.current_version(),
                "manual": False,
            }
        )
    return summaries


def create_app(
    use_charm: bool = True,
    cloud_url: str | None = None,
    epoch_duration_s: int | None = None,
) -> Flask:
    app = Flask(__name__)

    abe = get_cpabe(use_charm=use_charm)
    resolved_epoch_duration = _resolve_epoch_duration_s(epoch_duration_s)
    gateway = Gateway(
        gateway_id="gateway-001",
        abe=abe,
        epoch_manager=EpochManager(epoch_duration_s=resolved_epoch_duration),
    )
    cloud = Cloud()

    normalized_cloud_url = cloud_url.rstrip("/") if cloud_url else None

    state: dict[str, Any] = {
        "enrolled": set(),
        "camera_public_keys": {},
        "record_count": 0,
        "last_checkpoint": None,
        "last_ordered_checkpoint": None,
        "cloud_url": normalized_cloud_url,
        "cloud_uploads": 0,
        "last_cloud_upload": None,
        "cloud_upload_ms_samples": [],
        "last_cloud_error": None,

                                        
                                              
                                                                             
                                                                           
                                                                   
        "live_fast_path_sessions": {},
        "live_fast_path_cameras": {},

                                         
        "token_to_record_ids": {},
        "ordered_checkpoint_version": 0,
        "last_checkpoint_chain_by_epoch": {},
        "final_epoch_checkpoints": {},

                               
        "revoked_clients": set(),
        "client_leases": {},
    }

                                                 
    load_or_init_gateway_state(gateway, state)

    for item in apply_scheduled_epoch_rotations(gateway, state, cloud):
        print(
            f"[Gateway] epoch catch-up "
            f"{item['before_epoch']}->{item['after_epoch']}"
        )

    def _epoch_scheduler_loop() -> None:
        interval = float(
            os.environ.get(
                "CAMSHIELD_EPOCH_SCHEDULER_INTERVAL_S",
                str(min(60.0, max(5.0, resolved_epoch_duration / 4))),
            )
        )
        while True:
            try:
                for item in apply_scheduled_epoch_rotations(gateway, state, cloud):
                    print(
                        f"[Gateway] epoch rotated "
                        f"{item['before_epoch']}->{item['after_epoch']}"
                    )
            except Exception as exc:
                print(f"[Gateway] epoch rotation error: {exc}")
            time.sleep(interval)

    threading.Thread(
        target=_epoch_scheduler_loop,
        name="camshield-epoch-scheduler",
        daemon=True,
    ).start()

    _camshield_original_process_segment = gateway.process_segment

    def _camshield_persisting_process_segment(*args, **kwargs):
        apply_scheduled_epoch_rotations(gateway, state, cloud)
        rec = _camshield_original_process_segment(*args, **kwargs)
        save_gateway_state(gateway, state)
        return rec

    gateway.process_segment = _camshield_persisting_process_segment
                                               

    @app.get("/health")
    def health():
        em = gateway.epoch_manager
        return jsonify(
            {
                "ok": True,
                "use_charm": use_charm,
                "enrolled": sorted(state["enrolled"]),
                "record_count": state["record_count"],
                "cloud_url": state["cloud_url"],
                "cloud_uploads": state["cloud_uploads"],
                "last_cloud_upload": state["last_cloud_upload"],
                "last_cloud_error": state["last_cloud_error"],
                "has_ordered_checkpoint": state["last_ordered_checkpoint"] is not None,
                "current_epoch": em.current_epoch(),
                "current_version": em.current_version(),
                "epoch_duration_s": em.epoch_duration_s,
                "epoch_started_at": em.epoch_started_at,
                "epoch_ends_at": em.epoch_ends_at(),
                "seconds_until_rotation": em.seconds_until_rotation(),
            }
        )

    @app.post("/enroll")
    def enroll():
        obj = request.get_json(force=True)

        cid = obj["cid"]
        pk_bytes = b64d(obj["camera_public_key_b64"])
        expected_seq = int(obj.get("expected_seq", 1))

        pk = load_public_key(pk_bytes)

        gateway.enroll_camera(
            cid=cid,
            camera_public_key=pk,
            expected_seq=expected_seq,
        )

        state["enrolled"].add(cid)
                                                           
        import base64 as _camshield_b64
        state.setdefault("camera_public_keys", {})[cid] = _camshield_b64.b64encode(pk_bytes).decode("ascii")
        save_gateway_state(gateway, state)
                                                         
        
        print(f"[ENROLL] cid={cid}, expected_seq={expected_seq}")

        return jsonify(
            {
                "ok": True,
                "cid": cid,
                "expected_seq": expected_seq,
            }
        )

    def update_remote_index_state(record: Any) -> dict[str, list[str]]:
        """
        Update Gateway-side posting snapshot for remote Cloud.

        record.index_tokens is expected to be list[bytes].
        record.rid is expected to be bytes.
        """
        rid_hex = record.rid.hex()

        token_to_record_ids: dict[str, set[str]] = state["token_to_record_ids"]

        for token in record.index_tokens:
            token_hex = token.hex()
            token_to_record_ids.setdefault(token_hex, set()).add(rid_hex)

                                                                             
        return {
            token_hex: sorted(rids)
            for token_hex, rids in token_to_record_ids.items()
        }

    def build_signed_ordered_checkpoint(
        *,
        epoch: int,
        token_to_record_ids: dict[str, list[str]],
    ) -> dict[str, Any]:
        snapshot = build_ordered_merkle_snapshot(token_to_record_ids)

        state["ordered_checkpoint_version"] += 1
        version = int(state["ordered_checkpoint_version"])
        timestamp = int(time.time())

        root_hex = snapshot.root_hex

        chain_by_epoch: dict[str, str] = state["last_checkpoint_chain_by_epoch"]
        prev_chain_hex = chain_by_epoch.get(str(epoch), CHECKPOINT_CHAIN_GENESIS.hex())
        prev_chain = bytes.fromhex(prev_chain_hex)
        chain_value = compute_checkpoint_chain_value(
            epoch=epoch,
            version=version,
            timestamp=timestamp,
            root=bytes.fromhex(root_hex),
            prev_chain=prev_chain,
        )
        chain_hex = chain_value.hex()

        signed_bytes = ordered_checkpoint_signed_bytes(
            epoch=epoch,
            version=version,
            timestamp=timestamp,
            root_hex=root_hex,
            chain_hex=chain_hex,
        )

        signature = sign(gateway.skG, signed_bytes)

        signed_checkpoint = {
            "type": "camshield-ordered-checkpoint-v1",
            "epoch": epoch,
            "version": version,
            "timestamp": timestamp,
            "root_hex": root_hex,
            "chain_hex": chain_hex,
            "signature_b64": b64e(signature),
            "gateway_public_key_b64": b64e(public_key_bytes(gateway.pkG)),
            "token_count": len(token_to_record_ids),
        }

        state["last_ordered_checkpoint"] = signed_checkpoint
        chain_by_epoch[str(epoch)] = chain_hex

        return signed_checkpoint

    @app.get("/debug/cloud-upload-timing")
    def debug_cloud_upload_timing():
        import math as _math

        samples = list(state.get("cloud_upload_ms_samples", []))
        if not samples:
            return jsonify({
                "ok": True,
                "count": 0,
                "avg_ms": None,
                "p95_ms": None,
                "min_ms": None,
                "max_ms": None,
                "samples_ms": [],
            })

        ss = sorted(samples)
        idx = max(0, min(len(ss) - 1, _math.ceil(0.95 * len(ss)) - 1))

        return jsonify({
            "ok": True,
            "count": len(samples),
            "avg_ms": sum(samples) / len(samples),
            "p95_ms": ss[idx],
            "min_ms": min(samples),
            "max_ms": max(samples),
            "samples_ms": samples,
        })

    @app.post("/debug/cloud-upload-timing/reset")
    def reset_cloud_upload_timing():
        state["cloud_upload_ms_samples"] = []
        state["last_cloud_upload_ms"] = None
        return jsonify({"ok": True, "reset": "cloud_upload_ms_samples"})

    def upload_to_remote_cloud(
        *,
        record: Any,
        token_to_record_ids: dict[str, list[str]],
        signed_checkpoint: dict[str, Any],
    ) -> dict[str, Any]:
        if not normalized_cloud_url:
            return {
                "ok": True,
                "skipped": True,
                "reason": "cloud_url not configured",
            }

        rid_hex = record.rid.hex()

        payload = {
            "records": [
                {
                    "rid": rid_hex,
                    "record": to_jsonable(record),
                }
            ],
            "token_to_record_ids": token_to_record_ids,
            "signed_checkpoint": signed_checkpoint,
        }

        url = normalized_cloud_url + "/store-batch"

        import time as _cloud_time
        _cloud_upload_t0 = _cloud_time.perf_counter()
        resp = camshield_requests_post_with_retries(
            url,
            json=payload,
            timeout=15,
        )

        try:
            data = resp.json()
        except Exception:
            data = {
                "ok": False,
                "error": resp.text,
            }

        if resp.status_code != 200 or not data.get("ok", False):
            raise RuntimeError(
                f"remote cloud upload failed: status={resp.status_code}, response={data}"
            )

        cloud_upload_ms = (_cloud_time.perf_counter() - _cloud_upload_t0) * 1000.0
        state.setdefault("cloud_upload_ms_samples", []).append(cloud_upload_ms)
        state["last_cloud_upload_ms"] = cloud_upload_ms

        state["cloud_uploads"] += 1
        state["last_cloud_upload"] = {
            "timestamp": int(time.time()),
            "url": url,
            "rid": rid_hex,
            "response": data,
        }
        state["last_cloud_error"] = None

        return data

    def upload_live_record_to_remote_cloud(
        *,
        record: Any,
        camera_id: str,
        session_id: str,
    ) -> dict[str, Any]:
        if not normalized_cloud_url:
            return {
                "ok": True,
                "skipped": True,
                "reason": "cloud_url not configured",
            }

        rid_hex = record.rid.hex()
        payload = {
            "records": [
                {
                    "rid": rid_hex,
                    "record": to_jsonable(record),
                }
            ],
            "camera_id": camera_id,
            "session_id": session_id,
        }

        url = normalized_cloud_url + "/store-live"

        import time as _cloud_time
        _cloud_upload_t0 = _cloud_time.perf_counter()
        resp = camshield_requests_post_with_retries(
            url,
            json=payload,
            timeout=15,
        )

        try:
            data = resp.json()
        except Exception:
            data = {
                "ok": False,
                "error": resp.text,
            }

        if resp.status_code != 200 or not data.get("ok", False):
            raise RuntimeError(
                f"remote cloud live upload failed: status={resp.status_code}, response={data}"
            )

        cloud_upload_ms = (_cloud_time.perf_counter() - _cloud_upload_t0) * 1000.0
        state.setdefault("cloud_upload_ms_samples", []).append(cloud_upload_ms)
        state["last_cloud_upload_ms"] = cloud_upload_ms
        state["cloud_uploads"] += 1
        state["last_cloud_upload"] = {
            "timestamp": int(time.time()),
            "url": url,
            "rid": rid_hex,
            "mode": "live-fast-path",
            "response": data,
        }
        state["last_cloud_error"] = None

        return data

    @app.post("/search-tokens")
    def search_tokens():
        obj = request.get_json(force=True)

        keywords = obj.get("keywords", [])
        epoch = int(obj.get("epoch", 1))
        client_id = obj.get("client_id", "owner")
        camera_id = obj.get("camera_id", obj.get("cid", None))

                                   
                                                                         
                                                                       
        if client_id in state.get("revoked_clients", set()):
            return jsonify({
                "ok": False,
                "error": "revoked client cannot receive future retrieval tokens",
                "client_id": client_id,
                "revoked": True,
                "revoked_clients": sorted(state.get("revoked_clients", set())),
            }), 403

        if not isinstance(keywords, list) or len(keywords) == 0:
            return jsonify({
                "ok": False,
                "error": "keywords must be a non-empty list"
            }), 400

        if camera_id is None or str(camera_id).strip() == "":
            return jsonify({
                "ok": False,
                "error": "camera_id is required for camera-scoped retrieval tokens"
            }), 400

        camera_id = str(camera_id).strip()

        if client_id not in CLIENT_PROFILES:
            return jsonify({
                "ok": False,
                "error": f"unknown client_id: {client_id}",
                "known_clients": sorted(CLIENT_PROFILES.keys()),
            }), 400

        camera_keyword = f"camera:{camera_id}"
        if not authorize_client_keyword(client_id, camera_keyword):
            return jsonify({
                "ok": False,
                "error": "camera not authorized for this client",
                "client_id": client_id,
                "camera_id": camera_id,
                "required_camera_keyword": camera_keyword,
                "allowed_patterns": CLIENT_PROFILES[client_id]["allowed_patterns"],
            }), 403

        allowed, denied_keywords = authorize_client_keywords(client_id, keywords)
        if not allowed:
            return jsonify({
                "ok": False,
                "error": "keyword not authorized for this client",
                "client_id": client_id,
                "camera_id": camera_id,
                "denied_keywords": denied_keywords,
                "allowed_patterns": CLIENT_PROFILES[client_id]["allowed_patterns"],
            }), 403

        cap = _client_cap(state, gateway, client_id)
        ok_cap, cap_msg = validate_cap_u_for_search(
            cap,
            client_id=client_id,
            camera_id=camera_id,
            epoch=epoch,
            gateway_version=gateway.epoch_manager.current_version(),
            keywords=keywords,
        )
        if not ok_cap:
            return jsonify({
                "ok": False,
                "error": cap_msg,
                "hint": "POST /client/cap-grant or /client/credential-setup first",
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": epoch,
                "cap_u": cap,
            }), 403

        user_attrs = obj.get(
            "user_attrs",
            ["role:OWNER", "purpose:SURVEILLANCE", "mode:READ"],
        )

        tokens = gateway.issue_search_tokens(
            user_attrs,
            keywords,
            epoch,
            camera_id=camera_id,
            client_id=client_id,
        )

        query_token_ids = []
        keyword_to_token_id = {}

        for keyword, token in zip(keywords, tokens):
            token_hex = token.hex() if isinstance(token, (bytes, bytearray)) else str(token)
            query_token_ids.append(token_hex)
            keyword_to_token_id[keyword] = token_hex

        return jsonify({
            "ok": True,
            "client_id": client_id,
            "epoch": epoch,
            "camera_id": camera_id,
            "keywords": keywords,
            "query_token_ids": query_token_ids,
            "keyword_to_token_id": keyword_to_token_id,
            "allowed_patterns": CLIENT_PROFILES[client_id]["allowed_patterns"],
            "cap_u": cap,
        })



    @app.post("/ingest")
    def ingest():
        try:
            obj = request.get_json(force=True)

            segment = camera_segment_from_json(obj["segment"])

            extra_keywords = obj.get(
                "extra_keywords",
                ["event:motion", "location:lab", "object:person"],
            )

            role = obj.get("role", "OWNER")
            purpose = obj.get("purpose", "SURVEILLANCE")
            mode = obj.get("mode", "READ")
            scope = obj.get("scope", segment.cid)
            access_class = obj.get("access_class", "RAW")

            print(
                f"[INGEST] cid={segment.cid} sid={segment.sid} "
                f"seq={segment.seq} bytes={len(segment.raw_payload)}"
            )

                                                                    
                                                                    
                                                                             
                                                                 
            seq = int(getattr(segment, "seq", 0))

            if seq <= 10:
                dynamic_tags = [
                    "event:recorded",
                    "camera:cam01",
                    "location:lab",
                    "case:caseA",
                ]
            elif seq <= 20:
                dynamic_tags = [
                    "event:recorded",
                    "camera:cam01",
                    "location:hall",
                    "case:caseA",
                ]
            else:
                dynamic_tags = [
                    "event:recorded",
                    "camera:cam02",
                    "location:lab",
                    "case:caseB",
                ]

                                                            
                                                                         
                                                                       
            scale_prefix = os.environ.get("FIG6A_SCALE_PREFIX", "")
            if scale_prefix:
                                                                            
                                                                              
                                                                             
                bounds_raw = os.environ.get("FIG6A_SCALE_BOUNDS", "5,10,20,40,60")
                bounds = [int(x.strip()) for x in bounds_raw.split(",") if x.strip()]
                for bound in bounds:
                    if seq <= bound:
                        dynamic_tags.append(f"{scale_prefix}{bound}")

                                                  
                                                                            
                                                                     
            qtype_prefix = os.environ.get("FIG6B_TAG_PREFIX", "")
            if qtype_prefix:
                                              
                if seq <= 50:
                    dynamic_tags.append(f"scale:{qtype_prefix}single")

                                    
                                                              
                                                       
                if seq <= 100:
                    dynamic_tags.append(f"scale:{qtype_prefix}and_a")
                if seq <= 50:
                    dynamic_tags.append(f"scale:{qtype_prefix}and_b")

                                    
                                                                
                                                    
                if seq <= 25:
                    dynamic_tags.append(f"scale:{qtype_prefix}or_a")
                if 26 <= seq <= 50:
                    dynamic_tags.append(f"scale:{qtype_prefix}or_b")

                                              
                                                                    
                if seq <= 100:
                    dynamic_tags.append(f"case:{qtype_prefix}case")

                                                                          
                                                                           
                                                                              
            requested_keywords = obj.get("extra_keywords", [])
            if not isinstance(requested_keywords, list):
                requested_keywords = []

            extra_keywords = list(dict.fromkeys(dynamic_tags + requested_keywords))

            live_session_id = state.get("live_fast_path_cameras", {}).get(segment.cid)
            live_mode = live_session_id is not None

            record = gateway.process_segment(
                segment=segment,
                extra_keywords=extra_keywords,
                role=role,
                purpose=purpose,
                mode=mode,
                scope=scope,
                access_class=access_class,
                live=live_mode,
            )

            cloud.store_record(record)
            state["record_count"] += 1

            if live_mode:
                cloud_upload_result = upload_live_record_to_remote_cloud(
                    record=record,
                    camera_id=segment.cid,
                    session_id=live_session_id,
                )

                print(
                    f"[OK] live record rid={record.rid.hex()[:32]}... "
                    f"epoch={record.epoch} session={live_session_id}"
                )

                if normalized_cloud_url:
                    print(
                        f"[CLOUD] live uploaded rid={record.rid.hex()[:32]}... "
                        f"to {normalized_cloud_url}"
                    )

                return jsonify(
                    {
                        "ok": True,
                        "mode": "live-fast-path",
                        "live": True,
                        "session_id": live_session_id,
                        "rid": record.rid.hex(),
                        "epoch": record.epoch,
                        "index_token_count": 0,
                        "binding_hash": record.binding_hash.hex(),
                        "record_count": state["record_count"],
                        "cloud_upload": cloud_upload_result,
                    }
                )

            checkpoint = cloud.build_checkpoint(
                gateway=gateway,
                epoch=record.epoch,
            )
            state["last_checkpoint"] = checkpoint

            token_to_record_ids = update_remote_index_state(record)
            signed_ordered_checkpoint = build_signed_ordered_checkpoint(
                epoch=record.epoch,
                token_to_record_ids=token_to_record_ids,
            )

            cloud_upload_result = upload_to_remote_cloud(
                record=record,
                token_to_record_ids=token_to_record_ids,
                signed_checkpoint=signed_ordered_checkpoint,
            )

            print(
                f"[OK] record rid={record.rid.hex()[:32]}... "
                f"epoch={record.epoch} local_checkpoint={checkpoint.root.hex()[:32]}... "
                f"ordered_checkpoint={signed_ordered_checkpoint['root_hex'][:32]}..."
            )

            if normalized_cloud_url:
                print(
                    f"[CLOUD] uploaded rid={record.rid.hex()[:32]}... "
                    f"to {normalized_cloud_url}"
                )

            return jsonify(
                {
                    "ok": True,
                    "rid": record.rid.hex(),
                    "epoch": record.epoch,
                    "index_token_count": len(record.index_tokens),
                    "binding_hash": record.binding_hash.hex(),
                    "checkpoint_root": checkpoint.root.hex(),
                    "ordered_checkpoint_root": signed_ordered_checkpoint["root_hex"],
                    "ordered_checkpoint_version": signed_ordered_checkpoint["version"],
                    "record_count": state["record_count"],
                    "cloud_upload": cloud_upload_result,
                }
            )

        except Exception as exc:
            traceback.print_exc()
            state["last_cloud_error"] = str(exc)
            return jsonify(
                {
                    "ok": False,
                    "error": str(exc),
                }
            ), 500

    
    
                                                   
    @app.get("/bootstrap/trust")
    def camshield_bootstrap_trust():
        """
        Client trust bootstrap endpoint.

        Returns camera public keys and Gateway public key for client-side verification.
        """
        import base64 as _camshield_b64

        camera_public_keys = dict(state.get("camera_public_keys", {}))

                                                               
        registry = getattr(gateway, "camera_registry", None)
        cameras = getattr(registry, "cameras", {}) if registry is not None else {}
        for cid, entry in cameras.items():
            if str(cid) not in camera_public_keys:
                pk = getattr(entry, "public_key", None)
                if pk is not None:
                    camera_public_keys[str(cid)] = _camshield_b64.b64encode(public_key_bytes(pk)).decode("ascii")

        gateway_public_key_b64 = _camshield_b64.b64encode(public_key_bytes(gateway.pkG)).decode("ascii")

        if not camera_public_keys:
            return jsonify({
                "ok": False,
                "error": "no camera public key enrolled yet",
                "gateway_public_key_b64": gateway_public_key_b64,
                "hint": "Run camera_node_au.py once so it POSTs /enroll to Gateway.",
                "enrolled": sorted(state.get("enrolled", [])),
            }), 500

        return jsonify({
            "ok": True,
            "camera_public_keys": camera_public_keys,
            "gateway_public_key_b64": gateway_public_key_b64,
            "enrolled": sorted(state.get("enrolled", [])),
        })
                                                 


                                                                        
                                    
                          
     
                                                                            
                                                                            
     
                                
                                                                
                                                                             
                                          
                                                                        

    @app.post("/live/fast-path/start")
    def live_fast_path_start():
        data = request.get_json(force=True, silent=True) or {}

        session_id = str(data.get("session_id", "")).strip()
        client_id = str(data.get("client_id", "owner")).strip()
        camera_id = str(data.get("camera_id", data.get("cid", ""))).strip()
        epoch = data.get("epoch", None)
        cloud_origin = str(data.get("cloud_url", normalized_cloud_url or "")).strip()

        if not session_id:
            return jsonify({
                "ok": False,
                "error": "session_id is required",
            }), 400

        if not camera_id:
            return jsonify({
                "ok": False,
                "error": "camera_id is required",
            }), 400

        if client_id not in CLIENT_PROFILES:
            return jsonify({
                "ok": False,
                "error": f"unknown client_id: {client_id}",
                "known_clients": sorted(CLIENT_PROFILES.keys()),
            }), 400

        if _client_is_revoked(state, client_id):
            return jsonify({
                "ok": False,
                "error": "revoked client cannot start live fast path",
                "client_id": client_id,
                "revoked": True,
            }), 403

        camera_keyword = f"camera:{camera_id}"
        if not authorize_client_keyword(client_id, camera_keyword):
            return jsonify({
                "ok": False,
                "error": "camera not authorized for this client",
                "client_id": client_id,
                "camera_id": camera_id,
                "required_camera_keyword": camera_keyword,
                "allowed_patterns": CLIENT_PROFILES[client_id]["allowed_patterns"],
            }), 403

        live_epoch = int(epoch) if epoch is not None else gateway.epoch_manager.current_epoch()
        cap = _client_cap(state, gateway, client_id)
        ok_cap, cap_msg = validate_cap_u_for_search(
            cap,
            client_id=client_id,
            camera_id=camera_id,
            epoch=live_epoch,
            gateway_version=gateway.epoch_manager.current_version(),
        )
        if not ok_cap:
            return jsonify({
                "ok": False,
                "error": cap_msg,
                "hint": "POST /client/cap-grant or /client/credential-setup first",
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": live_epoch,
                "cap_u": cap,
            }), 403

        sess = {
            "session_id": session_id,
            "client_id": client_id,
            "camera_id": camera_id,
            "epoch": epoch,
            "cloud_url": cloud_origin,
            "created_at": int(time.time()),
            "mode": "live-fast-path",
            "fast_path_ready": True,
            "vp_verification_default": False,
            "basic_verification_only": True,
            "status": "active",
        }

        state.setdefault("live_fast_path_sessions", {})[session_id] = sess
        state.setdefault("live_fast_path_cameras", {})[camera_id] = session_id

        return jsonify({
            "ok": True,
            "session_id": session_id,
            "client_id": client_id,
            "camera_id": camera_id,
            "epoch": epoch,
            "mode": "live-fast-path",
            "fast_path_ready": True,
            "vp_verification_default": False,
            "basic_verification_only": True,
            "status": "active",
        })

    @app.get("/live/fast-path/state")
    def live_fast_path_state():
        sessions = state.setdefault("live_fast_path_sessions", {})
        return jsonify({
            "ok": True,
            "live_session_count": len(sessions),
            "live_sessions": sessions,
            "live_fast_path_cameras": dict(state.get("live_fast_path_cameras", {})),
        })


                                                                        
                                            
                                         
     
                                                                           
                                                                       
                     
                                    
                                      
                                        
                                                                        

    @app.post("/client/charm-bootstrap")
    def client_charm_bootstrap():
        import base64 as _b64
        import re as _re

        data = request.get_json(force=True, silent=True) or {}

        client_id = str(data.get("client_id", "owner")).strip()
        camera_id = str(data.get("camera_id", "cam01")).strip()
        epoch = int(data.get("epoch", gateway.epoch_manager.current_epoch()))
        version = int(data.get("version", gateway.epoch_manager.current_version()))
        policy = str(data.get("policy", "")).strip()

        if client_id not in CLIENT_PROFILES:
            return jsonify({
                "ok": False,
                "error": f"unknown client_id: {client_id}",
                "known_clients": sorted(CLIENT_PROFILES.keys()),
            }), 400

        if _client_is_revoked(state, client_id):
            return jsonify({
                "ok": False,
                "error": "revoked client cannot receive ABE client key",
                "client_id": client_id,
                "revoked": True,
            }), 403

        camera_keyword = f"camera:{camera_id}"
        if not authorize_client_keyword(client_id, camera_keyword):
            return jsonify({
                "ok": False,
                "error": "camera not authorized for this client",
                "client_id": client_id,
                "camera_id": camera_id,
                "required_camera_keyword": camera_keyword,
                "allowed_patterns": CLIENT_PROFILES[client_id]["allowed_patterns"],
            }), 403

        abe = gateway.abe
        if abe is None or not hasattr(abe, "group"):
            return jsonify({
                "ok": False,
                "error": "Gateway is not using Charm ABE backend",
                "hint": "Start gateway_server.py without --mock-abe and ensure Charm-Crypto is installed.",
            }), 500

        if gateway.mpk is None or gateway.msk is None:
            return jsonify({
                "ok": False,
                "error": "Gateway ABE mpk/msk not initialized",
            }), 500

        if policy:
            attrs = parse_abe_attrs_from_policy(policy)
            if not attrs:
                return jsonify({
                    "ok": False,
                    "error": "policy contains no ABE attributes",
                    "policy": policy,
                }), 400
        else:
            attrs = abe_client_attrs(
                role="OWNER",
                purpose="SURVEILLANCE",
                mode="READ",
                scope=camera_id,
            )

        if client_id != "owner":
            return jsonify({
                "ok": False,
                "error": "Charm bootstrap currently supports the owner client profile only",
                "client_id": client_id,
            }), 403

        cap = _client_cap(state, gateway, client_id)
        ok_cap, cap_msg = validate_cap_u_for_bootstrap(cap)
        if not ok_cap:
            return jsonify({
                "ok": False,
                "error": cap_msg,
                "hint": "POST /client/cap-grant or /client/credential-setup first",
                "client_id": client_id,
            }), 403

        cap_attrs = set(cap.get("abe_attrs", []))
        if cap_attrs and not set(attrs).issubset(cap_attrs):
            return jsonify({
                "ok": False,
                "error": "requested ABE attrs exceed Cap_u abe_attrs",
                "requested_attrs": attrs,
                "cap_abe_attrs": sorted(cap_attrs),
            }), 403

        try:
            from charm.core.engine.util import objectToBytes

            sk_u = gateway._abe_keygen(attrs)

            mpk_b64 = _b64.b64encode(
                objectToBytes(gateway.mpk, abe.group)
            ).decode("ascii")

            sk_u_b64 = _b64.b64encode(
                objectToBytes(sk_u, abe.group)
            ).decode("ascii")

            return jsonify({
                "ok": True,
                "backend": "CharmBSW07",
                "group": getattr(abe, "group_name", "SS512"),
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": epoch,
                "version": version,
                "attrs": attrs,
                "Cap_u": cap,
                "Cred_u": {"Cap_u": cap},
                "mpk_b64": mpk_b64,
                "sk_u_b64": sk_u_b64,
                "decrypt_location": "client",
            })

        except Exception as exc:
            return jsonify({
                "ok": False,
                "error": "failed to serialize Charm client key",
                "reason": repr(exc),
            }), 500


    @app.post("/client/cap-grant")
    def client_cap_grant():
        data = request.get_json(force=True, silent=True) or {}

        client_id = str(data.get("client_id", "owner")).strip()
        camera_id = str(data.get("camera_id", "cam01")).strip()
        epoch_max = data.get("epoch_max")
        version_max = data.get("version_max")
        expires_at = int(data.get("expires_at", 0))

        if client_id not in CLIENT_PROFILES:
            return jsonify({
                "ok": False,
                "error": f"unknown client_id: {client_id}",
                "known_clients": sorted(CLIENT_PROFILES.keys()),
            }), 400

        if _client_is_revoked(state, client_id):
            return jsonify({
                "ok": False,
                "error": "revoked client cannot receive Cap_u lease",
                "client_id": client_id,
                "revoked": True,
            }), 403

        camera_keyword = f"camera:{camera_id}"
        if not authorize_client_keyword(client_id, camera_keyword):
            return jsonify({
                "ok": False,
                "error": "camera not authorized for this client",
                "client_id": client_id,
                "camera_id": camera_id,
            }), 403

        cap = _grant_client_cap(
            state,
            gateway,
            client_id=client_id,
            camera_id=camera_id,
            epoch_max=int(epoch_max) if epoch_max is not None else None,
            version_max=int(version_max) if version_max is not None else None,
            expires_at=expires_at,
        )

        return jsonify({
            "ok": True,
            "client_id": client_id,
            "camera_id": camera_id,
            "Cap_u": cap,
            "cap_u": cap,
        })

    @app.post("/client/credential-setup")
    def client_credential_setup():
        """
        Paper credential setup: Cred_u = (SK_u, Cap_u).

        Grants Cap_u and, when Charm ABE is enabled, issues SK_u in one step.
        """
        import base64 as _b64

        data = request.get_json(force=True, silent=True) or {}
        client_id = str(data.get("client_id", "owner")).strip()
        camera_id = str(data.get("camera_id", "cam01")).strip()
        epoch_max = data.get("epoch_max")
        version_max = data.get("version_max")
        expires_at = int(data.get("expires_at", 0))

        if client_id not in CLIENT_PROFILES:
            return jsonify({
                "ok": False,
                "error": f"unknown client_id: {client_id}",
            }), 400

        if _client_is_revoked(state, client_id):
            return jsonify({
                "ok": False,
                "error": "revoked client cannot receive credentials",
                "revoked": True,
            }), 403

        camera_keyword = f"camera:{camera_id}"
        if not authorize_client_keyword(client_id, camera_keyword):
            return jsonify({
                "ok": False,
                "error": "camera not authorized for this client",
                "camera_id": camera_id,
            }), 403

        cap = _grant_client_cap(
            state,
            gateway,
            client_id=client_id,
            camera_id=camera_id,
            epoch_max=int(epoch_max) if epoch_max is not None else None,
            version_max=int(version_max) if version_max is not None else None,
            expires_at=expires_at,
        )
        attrs = list(cap.get("abe_attrs", []))

        resp: dict[str, Any] = {
            "ok": True,
            "client_id": client_id,
            "camera_id": camera_id,
            "Cap_u": cap,
            "Cred_u": {"Cap_u": cap},
            "attrs": attrs,
            "retrieval_mode": "IdxCap_u-offline" if cap.get("IdxCap_u") else "on-demand",
        }

        abe = gateway.abe
        if abe is not None and hasattr(abe, "group") and gateway.mpk is not None:
            try:
                from charm.core.engine.util import objectToBytes

                sk_u = gateway._abe_keygen(attrs)
                resp["backend"] = "CharmBSW07"
                resp["group"] = getattr(abe, "group_name", "SS512")
                resp["mpk_b64"] = _b64.b64encode(
                    objectToBytes(gateway.mpk, abe.group)
                ).decode("ascii")
                resp["sk_u_b64"] = _b64.b64encode(
                    objectToBytes(sk_u, abe.group)
                ).decode("ascii")
                resp["Cred_u"]["SK_u"] = "issued"
            except Exception as exc:
                resp["sk_error"] = repr(exc)

        return jsonify(resp)


                                                                        
                          
                                                                        

    @app.get("/admin/revocation/state")
    def revocation_state():
        em = gateway.epoch_manager
        return jsonify({
            "ok": True,
            "current_epoch": em.current_epoch(),
            "current_version": em.current_version(),
            "epoch_duration_s": getattr(em, "epoch_duration_s", DEFAULT_EPOCH_DURATION_S),
            "epoch_started_at": getattr(em, "epoch_started_at", None),
            "epoch_ends_at": em.epoch_ends_at(),
            "seconds_until_rotation": em.seconds_until_rotation(),
            "protocol_defaults": {
                "segment_duration_s": DEFAULT_SEGMENT_DURATION_S,
                "epoch_duration_s": DEFAULT_EPOCH_DURATION_S,
                "capture_fps": DEFAULT_CAPTURE_FPS,
                "aus_per_segment": default_aus_per_segment(),
            },
            "revoked_clients": sorted(state.get("revoked_clients", set())),
            "client_leases": state.get("client_leases", {}),
        })

    @app.post("/admin/revoke")
    def admin_revoke():
        data = request.get_json(force=True, silent=True) or {}
        client_id = data.get("client_id", "guest")

        state.setdefault("revoked_clients", set()).add(client_id)
        state.setdefault("client_leases", {})[client_id] = {
            "type": "Cap_u",
            "status": "revoked",
            "client_id": client_id,
            "revoked_at": int(time.time()),
            "epoch_at_revocation": gateway.epoch_manager.current_epoch(),
            "version_at_revocation": gateway.epoch_manager.current_version(),
        }
        gateway.client_caps.pop(client_id, None)

        return jsonify({
            "ok": True,
            "action": "revoke",
            "client_id": client_id,
            "revoked_clients": sorted(state.get("revoked_clients", set())),
            "current_epoch": gateway.epoch_manager.current_epoch(),
            "current_version": gateway.epoch_manager.current_version(),
        })

    @app.post("/admin/unrevoke")
    def admin_unrevoke():
        data = request.get_json(force=True, silent=True) or {}
        client_id = data.get("client_id", "guest")

        state.setdefault("revoked_clients", set()).discard(client_id)

        camera_id = str(data.get("camera_id", "cam01")).strip()
        cap = _grant_client_cap(
            state,
            gateway,
            client_id=client_id,
            camera_id=camera_id,
        )

        return jsonify({
            "ok": True,
            "action": "unrevoke",
            "client_id": client_id,
            "revoked_clients": sorted(state.get("revoked_clients", set())),
            "current_epoch": gateway.epoch_manager.current_epoch(),
            "current_version": gateway.epoch_manager.current_version(),
            "cap_u": cap,
        })

    @app.post("/admin/rotate-epoch")
    def admin_rotate_epoch():
        rotations = apply_scheduled_epoch_rotations(
            gateway,
            state,
            cloud,
            manual=True,
        )
        item = rotations[0] if rotations else {}
        return jsonify({
            "ok": True,
            "action": "rotate_epoch",
            "before_epoch": item.get("before_epoch"),
            "before_version": item.get("before_version"),
            "after_epoch": gateway.epoch_manager.current_epoch(),
            "after_version": gateway.epoch_manager.current_version(),
            "manual": True,
            "revoked_clients": sorted(state.get("revoked_clients", set())),
        })




    @app.post("/admin/lazy-rewrap-benchmark")
    def admin_lazy_rewrap_benchmark():
        """
        Benchmark lazy historical re-wrapping.

        Semantics:
          - Do not re-encrypt video ciphertext.
          - For each historical record:
              1. reuse the historical epoch key EKe,
              2. build a new policy with target version,
              3. generate a new ABE capsule kappa',
              4. recompute policy_digest and capsule_digest,
              5. recompute record binding hash,
              6. re-sign the binding with gateway key.

        This is a benchmark endpoint. It does not mutate cloud records.
        """
        import hashlib
        import json as _json
        import re
        import time as _time
        from core.epoch import build_policy

        obj = request.get_json(force=True, silent=True) or {}
        records = obj.get("records", [])
        target_version = int(obj.get("target_version", gateway.epoch_manager.current_version()))
        repeat = int(obj.get("repeat", 1))

        if not isinstance(records, list) or not records:
            return jsonify({"ok": False, "error": "records must be a non-empty list"}), 400

        def _lp(x: bytes) -> bytes:
            return len(x).to_bytes(8, "big") + x

        def _u64(x: int) -> bytes:
            return int(x).to_bytes(8, "big")

        def _sha256(x: bytes) -> bytes:
            return hashlib.sha256(x).digest()

        def _hash_parts(*parts: bytes) -> bytes:
            h = hashlib.sha256()
            for part in parts:
                h.update(_lp(part))
            return h.digest()

        def _as_bytes(x):
            if isinstance(x, bytes):
                return x
            if isinstance(x, str):
                return x.encode("utf-8")
            return _json.dumps(x, sort_keys=True, separators=(",", ":")).encode("utf-8")

        def _extract_attr(policy: str, name: str, default: str) -> str:
            m = re.search(r"\b" + re.escape(name) + r"_([A-Za-z0-9_:-]+)\b", policy)
            return m.group(1) if m else default

        def _ciphertext_digest(rec: dict) -> bytes:
            return _sha256(
                bytes.fromhex(rec["nonce"])
                + bytes.fromhex(rec["ciphertext"])
                + bytes.fromhex(rec["tag"])
            )

        def _binding_hash(rec: dict, new_policy_digest: bytes, new_capsule_digest: bytes) -> bytes:
            ssi = rec["SSi"]
            return _hash_parts(
                b"CamShield.record.binding.v1",
                bytes.fromhex(rec["rid"]),
                bytes.fromhex(ssi["gamma"]),
                _ciphertext_digest(rec),
                bytes.fromhex(rec["index_digest"]),
                new_policy_digest,
                new_capsule_digest,
                str(rec["a"]).encode("utf-8"),
                _u64(int(rec["epoch"])),
                str(ssi["cid"]).encode("utf-8"),
                str(ssi["sid"]).encode("utf-8"),
                _u64(int(ssi["seq"])),
            )

        total_count = 0
        abe_ms_total = 0.0
        binding_ms_total = 0.0
        output_bytes = 0

        t_all0 = _time.perf_counter()

        for _ in range(repeat):
            for rec in records:
                epoch = int(rec["epoch"])
                old_policy = rec.get("policy", "")

                role = _extract_attr(old_policy, "ROLE", "owner")
                purpose = _extract_attr(old_policy, "PURPOSE", "evidence")
                mode = _extract_attr(old_policy, "MODE", "read")
                scope = _extract_attr(old_policy, "SCOPE", rec.get("SSi", {}).get("cid", "cam01"))

                new_policy = build_policy(
                    role=role,
                    purpose=purpose,
                    mode=mode,
                    scope=scope,
                    epoch=epoch,
                    version=target_version,
                )

                try:
                    EKe = gateway.epoch_manager.epoch_key(epoch)
                except Exception as exc:
                    return jsonify({
                        "ok": False,
                        "error": "historical epoch key unavailable",
                        "epoch": epoch,
                        "detail": str(exc),
                    }), 400

                t0 = _time.perf_counter()
                new_kappa = gateway._abe_encrypt_epoch_key(new_policy, EKe)
                t1 = _time.perf_counter()

                new_kappa_b = _as_bytes(new_kappa)
                new_policy_digest = _sha256(new_policy.encode("utf-8"))
                new_capsule_digest = _sha256(new_kappa_b)

                t2 = _time.perf_counter()
                new_binding = _binding_hash(rec, new_policy_digest, new_capsule_digest)
                new_sig = sign(gateway.skG, new_binding)
                t3 = _time.perf_counter()

                abe_ms_total += (t1 - t0) * 1000.0
                binding_ms_total += (t3 - t2) * 1000.0
                total_count += 1

                output_bytes += len(new_kappa_b)
                output_bytes += len(new_policy.encode("utf-8"))
                output_bytes += len(new_policy_digest)
                output_bytes += len(new_capsule_digest)
                output_bytes += len(new_binding)
                output_bytes += len(new_sig)

        t_all1 = _time.perf_counter()
        total_ms = (t_all1 - t_all0) * 1000.0

        return jsonify({
            "ok": True,
            "operation": "lazy_historical_rewrap_benchmark",
            "record_count": len(records),
            "repeat": repeat,
            "total_operations": total_count,
            "target_version": target_version,
            "total_ms": total_ms,
            "avg_ms_per_record": total_ms / total_count if total_count else None,
            "abe_reencapsulation_ms_total": abe_ms_total,
            "abe_reencapsulation_ms_per_record": abe_ms_total / total_count if total_count else None,
            "binding_resign_ms_total": binding_ms_total,
            "binding_resign_ms_per_record": binding_ms_total / total_count if total_count else None,
            "output_metadata_bytes_total": output_bytes,
            "output_metadata_bytes_per_record": output_bytes / total_count if total_count else None,
            "mutates_cloud": False,
        })



    @app.post("/admin/lazy-rewrap-access-benchmark")
    def admin_lazy_rewrap_access_benchmark():
        """
        Benchmark lazy historical re-wrapping under multiple access classes.

        Semantics:
          - Do not re-encrypt video ciphertext.
          - For each historical record and each access class:
              1. reuse the historical epoch key EKe,
              2. build a class-specific updated policy,
              3. generate a new ABE capsule kappa',
              4. recompute policy_digest and capsule_digest,
              5. recompute record binding hash with class-specific access label,
              6. re-sign the binding with gateway key.

        This endpoint is for measurement only. It does not mutate cloud records.
        """
        import hashlib
        import json as _json
        import re
        import time as _time
        from core.epoch import build_policy

        obj = request.get_json(force=True, silent=True) or {}

        records = obj.get("records", [])
        access_class_count = int(obj.get("access_class_count", 1))
        repeat = int(obj.get("repeat", 1))
        target_version = int(obj.get("target_version", gateway.epoch_manager.current_version()))

        if not isinstance(records, list) or not records:
            return jsonify({"ok": False, "error": "records must be a non-empty list"}), 400

        if access_class_count < 1:
            return jsonify({"ok": False, "error": "access_class_count must be >= 1"}), 400

        if repeat < 1:
            return jsonify({"ok": False, "error": "repeat must be >= 1"}), 400

        def _lp(x: bytes) -> bytes:
            return len(x).to_bytes(8, "big") + x

        def _u64(x: int) -> bytes:
            return int(x).to_bytes(8, "big")

        def _sha256(x: bytes) -> bytes:
            return hashlib.sha256(x).digest()

        def _hash_parts(*parts: bytes) -> bytes:
            h = hashlib.sha256()
            for part in parts:
                h.update(_lp(part))
            return h.digest()

        def _as_bytes(x):
            if isinstance(x, bytes):
                return x
            if isinstance(x, str):
                return x.encode("utf-8")
            return _json.dumps(x, sort_keys=True, separators=(",", ":")).encode("utf-8")

        def _extract_attr(policy: str, name: str, default: str) -> str:
            m = re.search(r"\b" + re.escape(name) + r"_([A-Za-z0-9_:-]+)\b", policy)
            return m.group(1) if m else default

        def _ciphertext_digest(rec: dict) -> bytes:
            return _sha256(
                bytes.fromhex(rec["nonce"])
                + bytes.fromhex(rec["ciphertext"])
                + bytes.fromhex(rec["tag"])
            )

        def _binding_hash(rec: dict, access_label: str, new_policy_digest: bytes, new_capsule_digest: bytes) -> bytes:
            ssi = rec["SSi"]
            return _hash_parts(
                b"CamShield.record.binding.v1",
                bytes.fromhex(rec["rid"]),
                bytes.fromhex(ssi["gamma"]),
                _ciphertext_digest(rec),
                bytes.fromhex(rec["index_digest"]),
                new_policy_digest,
                new_capsule_digest,
                str(access_label).encode("utf-8"),
                _u64(int(rec["epoch"])),
                str(ssi["cid"]).encode("utf-8"),
                str(ssi["sid"]).encode("utf-8"),
                _u64(int(ssi["seq"])),
            )

        total_count = 0
        abe_ms_total = 0.0
        binding_ms_total = 0.0
        output_bytes = 0

        t_all0 = _time.perf_counter()

        for _ in range(repeat):
            for rec in records:
                epoch = int(rec["epoch"])
                old_policy = rec.get("policy", "")

                role = _extract_attr(old_policy, "ROLE", "owner")
                purpose = _extract_attr(old_policy, "PURPOSE", "evidence")
                mode = _extract_attr(old_policy, "MODE", "read")
                scope = _extract_attr(old_policy, "SCOPE", rec.get("SSi", {}).get("cid", "cam01"))

                try:
                    EKe = gateway.epoch_manager.epoch_key(epoch)
                except Exception as exc:
                    return jsonify({
                        "ok": False,
                        "error": "historical epoch key unavailable",
                        "epoch": epoch,
                        "detail": str(exc),
                    }), 400

                for j in range(access_class_count):
                    class_id = j + 1
                    class_tag = f"AC{class_id}"

                                                                          
                                                                                  
                    class_purpose = f"{purpose}_{class_tag}"
                    access_label = f"{rec.get('a', 'access')}_{class_tag}"

                    new_policy = build_policy(
                        role=role,
                        purpose=class_purpose,
                        mode=mode,
                        scope=scope,
                        epoch=epoch,
                        version=target_version,
                    )

                    t0 = _time.perf_counter()
                    new_kappa = gateway._abe_encrypt_epoch_key(new_policy, EKe)
                    t1 = _time.perf_counter()

                    new_kappa_b = _as_bytes(new_kappa)
                    new_policy_digest = _sha256(new_policy.encode("utf-8"))
                    new_capsule_digest = _sha256(new_kappa_b)

                    t2 = _time.perf_counter()
                    new_binding = _binding_hash(rec, access_label, new_policy_digest, new_capsule_digest)
                    new_sig = sign(gateway.skG, new_binding)
                    t3 = _time.perf_counter()

                    abe_ms_total += (t1 - t0) * 1000.0
                    binding_ms_total += (t3 - t2) * 1000.0
                    total_count += 1

                    output_bytes += len(new_kappa_b)
                    output_bytes += len(new_policy.encode("utf-8"))
                    output_bytes += len(new_policy_digest)
                    output_bytes += len(new_capsule_digest)
                    output_bytes += len(new_binding)
                    output_bytes += len(new_sig)

        t_all1 = _time.perf_counter()
        total_ms = (t_all1 - t_all0) * 1000.0

        return jsonify({
            "ok": True,
            "operation": "lazy_historical_rewrap_access_benchmark",
            "record_count": len(records),
            "access_class_count": access_class_count,
            "repeat": repeat,
            "total_operations": total_count,
            "target_version": target_version,
            "total_ms": total_ms,
            "avg_ms_per_record": total_ms / (len(records) * repeat) if records else None,
            "avg_ms_per_access_record": total_ms / total_count if total_count else None,
            "abe_reencapsulation_ms_total": abe_ms_total,
            "abe_reencapsulation_ms_per_access_record": abe_ms_total / total_count if total_count else None,
            "binding_resign_ms_total": binding_ms_total,
            "binding_resign_ms_per_access_record": binding_ms_total / total_count if total_count else None,
            "output_metadata_bytes_total": output_bytes,
            "output_metadata_bytes_per_access_record": output_bytes / total_count if total_count else None,
            "mutates_cloud": False,
        })


                                                                        
                                                                    
                                                                        

    @app.post("/debug/charm-decrypt-record")
    def debug_charm_decrypt_record():
        """
        Demo-only endpoint.

        It verifies the real Charm CP-ABE path inside the Gateway process:
            kappa --Charm.Dec(SKu)--> EKe
            EKe + rid + epoch --> ki
            AES-GCM.Dec(ki, ci, aad) --> mi
            sha256(mi) == hi
        """
        import re
        import hashlib
        import base64
        import requests as _requests
        from core import aes_gcm as _aes_gcm
        from core.epoch import derive_record_key as _derive_record_key

        data = request.get_json(force=True, silent=True) or {}
        rid_hex = data.get("rid")
        client_id = data.get("client_id", "owner")

        if not rid_hex:
            return jsonify({"ok": False, "error": "missing rid"}), 400

                                           
        cloud_record_url = f"{cloud_url.rstrip('/')}/record/{rid_hex}"
        rr = _requests.get(cloud_record_url, timeout=10)
        if rr.status_code != 200:
            return jsonify({
                "ok": False,
                "error": "cloud record fetch failed",
                "status": rr.status_code,
                "body": rr.text[:500],
            }), 502

        rec_resp = rr.json()
        record = rec_resp.get("record", rec_resp)

        policy = record["policy"]
        required_attrs = set(
            t.strip().upper()
            for t in re.findall(r"\b(?:ROLE|PURPOSE|MODE|SCOPE|EPOCH|VER)_[A-Za-z0-9_:-]+\b", policy)
        )

                                                                             
                                                                    
        if client_id == "owner":
            attrs = sorted(required_attrs)
        else:
            attrs = []

        sk_u = gateway._abe_keygen(attrs)

        kappa = bytes.fromhex(record["kappa"])
        EKe = gateway.abe.decrypt(sk_u, kappa)

        if EKe is None:
            return jsonify({
                "ok": False,
                "stage": "Charm CP-ABE decrypt",
                "error": "Charm ABE decrypt failed",
                "client_id": client_id,
                "policy": policy,
                "attrs": attrs,
            }), 403

        rid = bytes.fromhex(record["rid"])
        epoch = int(record["epoch"])
        ssi = record["SSi"]

        ki = _derive_record_key(EKe, rid, epoch)

        aad = _aes_gcm.build_associated_data(
            rid=rid,
            cid=ssi["cid"],
            sid=ssi["sid"],
            seq=int(ssi["seq"]),
            timestamp=int(ssi["timestamp"]),
            epoch=epoch,
            gamma=bytes.fromhex(ssi["gamma"]),
        )

        plaintext = _aes_gcm.decrypt(
            key=ki,
            nonce=bytes.fromhex(record["nonce"]),
            ciphertext=bytes.fromhex(record["ciphertext"]),
            tag=bytes.fromhex(record["tag"]),
            associated_data=aad,
        )

        hi_actual = hashlib.sha256(plaintext).hexdigest()
        hi_expected = ssi["hi"]

        return jsonify({
            "ok": hi_actual == hi_expected,
            "client_id": client_id,
            "rid": rid_hex,
            "epoch": epoch,
            "policy": policy,
            "attrs": attrs,
            "charm_abe_decrypt": True,
            "EKe_len": len(EKe),
            "aes_gcm_decrypt": True,
            "plaintext_len": len(plaintext),
            "hi_expected": hi_expected,
            "hi_actual": hi_actual,
            "hash_match": hi_actual == hi_expected,
            "result": "PASS" if hi_actual == hi_expected else "CHECK",
            "plaintext_b64": base64.b64encode(plaintext).decode("ascii") if data.get("include_plaintext_b64") else None,
        })


    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--mock-abe", action="store_true", help="Use MockCPABE instead of Charm")
    parser.add_argument(
        "--cloud-url",
        default=None,
        help="Remote Cloud Server base URL, e.g. http://1.2.3.4:8100",
    )
    parser.add_argument(
        "--epoch-duration-s",
        type=int,
        default=None,
        help=f"Epoch window Δe in seconds (default {DEFAULT_EPOCH_DURATION_S}; env CAMSHIELD_EPOCH_DURATION_S)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    app = create_app(
        use_charm=not args.mock_abe,
        cloud_url=args.cloud_url,
        epoch_duration_s=args.epoch_duration_s,
    )

    print(f"[Gateway] listening on http://{args.host}:{args.port}")
    print(f"[Gateway] ABE backend: {'MockCPABE' if args.mock_abe else 'CharmCPABE'}")
    if args.cloud_url:
        print(f"[Gateway] Remote Cloud URL: {args.cloud_url}")
    else:
        print("[Gateway] Remote Cloud URL: disabled")

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
