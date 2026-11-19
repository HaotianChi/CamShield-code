"""
Gateway HTTP service for distributed deployment.
"""

from __future__ import annotations
import os

import argparse
import bisect
import base64
import copy
from collections import deque
import json
import shutil
import threading
import time
import traceback
from pathlib import Path
from typing import Any

import requests
from flask import Flask, g, jsonify, request
from requests.adapters import HTTPAdapter

from core.cloud import Cloud
from core.gateway import Gateway
from core.gateway_persistence import (
    GatewayGroupedDurableStore,
    append_gateway_journal_event,
    compact_gateway_journal,
    gateway_persistence_metrics,
    load_pending_upload_payload,
    load_or_init_gateway_state,
    replay_gateway_transaction_store,
    remove_pending_upload_payload,
    save_gateway_state,
)
from core.epoch import EpochManager
from core.abe import get_cpabe
from core.ed25519_sig import load_public_key, public_key_bytes, sign
from core.models import CHECKPOINT_CHAIN_GENESIS, compute_checkpoint_chain_value
from core.ordered_merkle import (
    build_ordered_merkle_root,
    make_real_token_id,
    posting_digest_hex_from_sorted_record_ids,
)
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


# Keep TLS/TCP connections warm across archival uploads.
_cloud_http_session = requests.Session()
_cloud_http_adapter = HTTPAdapter(pool_connections=4, pool_maxsize=16)
_cloud_http_session.mount("http://", _cloud_http_adapter)
_cloud_http_session.mount("https://", _cloud_http_adapter)
_cloud_http_local = threading.local()


def _cloud_http_client() -> requests.Session:
    """Return one keep-alive pool per parallel uploader thread."""
    worker_count = max(
        1,
        min(16, int(os.environ.get("CAMSHIELD_CLOUD_UPLOAD_WORKERS", "1"))),
    )
    if worker_count == 1:
        return _cloud_http_session
    session = getattr(_cloud_http_local, "session", None)
    if session is None:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=4,
            pool_maxsize=4,
            max_retries=0,
            pool_block=True,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _cloud_http_local.session = session
    return session



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
    api_token = os.environ.get("CAMSHIELD_API_TOKEN", "").strip()
    if api_token:
        headers = dict(kwargs.get("headers") or {})
        headers.setdefault("Authorization", f"Bearer {api_token}")
        kwargs["headers"] = headers

    for attempt in range(1, attempts + 1):
        try:
            resp = _cloud_http_client().post(*args, **kwargs)
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
    return _cloud_http_client().post(*args, **kwargs)









CLIENT_PROFILES = {
    "owner": {
        "abe_role": "OWNER",
        "abe_purpose": "SURVEILLANCE",
        "abe_mode": "READ",
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
        "abe_role": "AUDITOR",
        "abe_purpose": "SURVEILLANCE",
        "abe_mode": "READ",
        "allowed_patterns": [
            "camera:*",
            "location:*",
            "event:recorded",
            "time:*",
        ]
    },
    "guest": {
        "abe_role": "GUEST",
        "abe_purpose": "SURVEILLANCE",
        "abe_mode": "READ",
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


def profile_abe_attrs(client_id: str, camera_id: str) -> list[str]:
    profile = CLIENT_PROFILES.get(client_id, {})
    return abe_client_attrs(
        role=str(profile.get("abe_role", client_id or "GUEST")),
        purpose=str(profile.get("abe_purpose", "SURVEILLANCE")),
        mode=str(profile.get("abe_mode", "READ")),
        scope=camera_id,
    )


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
        abe_attrs = profile_abe_attrs(client_id, camera_id)
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
    checkpoint_type: str = "camshield-ordered-checkpoint-v2",
) -> bytes:
    """
    Bytes signed by Gateway for ordered checkpoint.

    Client Web will use the same canonical format later to verify signature.
    """
    return canonical_json_bytes(
        {
            "type": checkpoint_type,
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


def _resolve_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be one of 1/0, true/false, yes/no, on/off")


def rebuild_ordered_checkpoint_caches(state: dict[str, Any]) -> None:
    """Recreate non-authoritative Merkle caches from persisted postings.

    The persisted ``token_to_record_ids_by_epoch`` mapping is the Gateway's
    authoritative index state.  Digest, token-order, and sorted-posting
    values are purely engineering caches and must never survive independently
    of that mapping.  In particular, this is required after journal replay:
    an old derived cache must not influence a newly signed protocol root.
    """
    by_epoch = state.get("token_to_record_ids_by_epoch", {})
    if not isinstance(by_epoch, dict):
        by_epoch = {}
        state["token_to_record_ids_by_epoch"] = by_epoch

    digests: dict[str, dict[str, str]] = {}
    orders: dict[str, list[str]] = {}
    sorted_postings_by_epoch: dict[str, dict[str, list[str]]] = {}
    for raw_epoch, raw_postings in by_epoch.items():
        epoch_key = str(raw_epoch)
        postings = raw_postings if isinstance(raw_postings, dict) else {}
        sorted_postings: dict[str, list[str]] = {
            str(token): sorted(str(rid) for rid in record_ids)
            for token, record_ids in postings.items()
        }
        sorted_postings_by_epoch[epoch_key] = sorted_postings
        digests[epoch_key] = {
            token: posting_digest_hex_from_sorted_record_ids(record_ids)
            for token, record_ids in sorted_postings.items()
        }
        orders[epoch_key] = sorted(
            make_real_token_id(token) for token in sorted_postings
        )

    state["_posting_digest_cache_by_epoch"] = digests
    state["_ordered_token_ids_cache_by_epoch"] = orders
    state["_sorted_posting_ids_cache_by_epoch"] = sorted_postings_by_epoch


def _finalize_epoch_checkpoint(state: dict[str, Any], cloud: Cloud, epoch: int) -> None:
    checkpoint = state.get("last_ordered_checkpoint")
    if checkpoint and int(checkpoint.get("epoch", -1)) == int(epoch):
        state["final_epoch_checkpoints"][str(epoch)] = checkpoint
    cloud.close_epoch(epoch)
    # Once FEC_e is fixed, the remote Cloud is the authoritative store for
    # that epoch's postings and proof material. The
    # Gateway retains the signed final checkpoint and chain value, but no
    # longer needs the finalized posting working set to build new roots.
    epoch_key = str(epoch)
    state.setdefault("token_to_record_ids_by_epoch", {}).pop(epoch_key, None)
    state.setdefault("_posting_digest_cache_by_epoch", {}).pop(epoch_key, None)
    state.setdefault("_ordered_token_ids_cache_by_epoch", {}).pop(epoch_key, None)
    state.setdefault("_sorted_posting_ids_cache_by_epoch", {}).pop(epoch_key, None)
    state["token_to_record_ids"] = {}


def apply_scheduled_epoch_rotations(
    gateway: Gateway,
    state: dict[str, Any],
    cloud: Cloud,
    *,
    manual: bool = False,
) -> list[dict[str, Any]]:
    """Apply manual rotation or every scheduled transition that is currently due."""
    summaries: list[dict[str, Any]] = []
    durable_store = state.get("_gateway_durable_store")
    gateway_state_path = Path(state.get(
        "_gateway_state_path", ".camshield_gateway_state.json"
    ))
    rotation_due = manual or gateway.epoch_manager.seconds_until_rotation() == 0
    if rotation_due and isinstance(durable_store, GatewayGroupedDurableStore):
        # No epoch snapshot may include an in-memory transition whose shared
        # durability barrier has not completed yet.
        durable_store.flush()

    if manual:
        before_epoch = gateway.epoch_manager.current_epoch()
        before_version = gateway.epoch_manager.current_version()
        _finalize_epoch_checkpoint(state, cloud, before_epoch)
        gateway.rotate_epoch(manual=True)
        compact_gateway_journal(gateway, state, gateway_state_path)
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
        compact_gateway_journal(gateway, state, gateway_state_path)
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
    include_record_locator_tags: bool | None = None,
) -> Flask:
    app = Flask(__name__)
    application_request_count_lock = threading.Lock()
    application_active_requests = 0

    @app.before_request
    def capture_application_entry_time() -> None:
        """Record the Flask entry point for transport diagnosis only.

        The value is emitted as an HTTP response header below.  It is not
        consulted by any admission, checkpoint, signing, or ACK transition.
        """
        nonlocal application_active_requests
        with application_request_count_lock:
            application_active_requests += 1
            active_at_entry = application_active_requests
        g.camshield_application_started_wall_ns = time.time_ns()
        g.camshield_application_active_at_entry = active_at_entry
        g.camshield_application_thread_id = threading.get_ident()

    @app.after_request
    def add_ingest_transport_timing_headers(response):
        """Expose transport timings without changing an ingest receipt.

        These headers provide operational observability. They are deliberately
        excluded from signed records, postings, checkpoints, and the JSON ACK
        body, so a camera's protocol transition is identical with or without
        this instrumentation.
        """
        timing = getattr(g, "camshield_ingest_transport_timing", None)
        if isinstance(timing, dict):
            handler_started = timing.get("handler_started")
            if isinstance(handler_started, (int, float)):
                timing["server_handler_ms"] = max(
                    0.0,
                    (time.perf_counter() - float(handler_started)) * 1000.0,
                )

            response.headers["X-CamShield-Transport-Timing-Version"] = "v1"
            header_fields = {
                "X-CamShield-Request-Body-Ms": "request_body_receive_ms",
                "X-CamShield-JSON-Loads-Ms": "request_json_loads_ms",
                "X-CamShield-Segment-Decode-Ms": "request_segment_decode_ms",
            "X-CamShield-Sequence-Order-Wait-Ms": "sequence_order_wait_ms",
            "X-CamShield-Global-Commit-Lock-Wait-Ms": (
                "global_commit_lock_wait_ms"
            ),
                "X-CamShield-Lock-Wait-Ms": "lock_wait_ms",
                "X-CamShield-Gateway-Protocol-Ms": (
                    "gateway_protocol_and_durable_commit_ms"
                ),
                "X-CamShield-Handler-Ms": "server_handler_ms",
                "X-CamShield-Request-Bytes": "request_body_bytes",
            }
            server_timing = []
            for header, field in header_fields.items():
                value = timing.get(field)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                response.headers[header] = f"{float(value):.3f}"
                if field != "request_body_bytes":
                    metric = field.replace("_ms", "").replace("_", "-")
                    server_timing.append(f"{metric};dur={float(value):.3f}")
            if server_timing:
                response.headers["Server-Timing"] = ", ".join(server_timing)

        application_started_wall_ns = getattr(
            g,
            "camshield_application_started_wall_ns",
            None,
        )
        if isinstance(application_started_wall_ns, int):
            # Wall-clock headers expose observation timestamps only. A client
            # may calibrate its clock against /health before estimating
            # Gunicorn/WSGI queueing for an /ingest request.
            response.headers["X-CamShield-App-Started-Wall-Ns"] = str(
                application_started_wall_ns
            )
            response.headers["X-CamShield-App-Responded-Wall-Ns"] = str(
                time.time_ns()
            )
            response.headers["X-CamShield-Worker-Pid"] = str(os.getpid())
            response.headers["X-CamShield-App-Thread-Id"] = str(
                getattr(g, "camshield_application_thread_id", "")
            )
            response.headers["X-CamShield-App-Active-At-Entry"] = str(
                getattr(g, "camshield_application_active_at_entry", "")
            )
        nonlocal application_active_requests
        with application_request_count_lock:
            application_active_requests = max(0, application_active_requests - 1)
        return response

    abe = get_cpabe(use_charm=use_charm)
    app.config["ABE_BACKEND_NAME"] = type(abe).__name__
    resolved_epoch_duration = _resolve_epoch_duration_s(epoch_duration_s)
    resolved_record_locator_tags = (
        _resolve_bool_env("CAMSHIELD_INDEX_RECORD_LOCATOR_TAGS", True)
        if include_record_locator_tags is None
        else bool(include_record_locator_tags)
    )
    gateway = Gateway(
        gateway_id="gateway-001",
        abe=abe,
        epoch_manager=EpochManager(epoch_duration_s=resolved_epoch_duration),
        include_record_locator_tags=resolved_record_locator_tags,
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
        # Live fast-path delivery is operationally distinct from the durable
        # archival record queue. Keep its counters separate so capacity audits
        # never mistake display traffic for acknowledged archival uploads.
        "live_cloud_uploads": 0,
        "last_live_cloud_upload": None,
        "cloud_upload_ms_samples": [],
        "cloud_worker_upload_ms_samples": [],
        "ingest_phase_ms_samples": {},
        "last_cloud_error": None,






        "live_fast_path_sessions": {},
        "live_fast_path_cameras": {},


        "token_to_record_ids": {},
        "token_to_record_ids_by_epoch": {},
        "ordered_checkpoint_version": 0,
        "ordered_checkpoint_version_by_epoch": {},
        "last_checkpoint_chain_by_epoch": {},
        "final_epoch_checkpoints": {},


        "revoked_clients": set(),
        "client_leases": {},
        "accepted_segments": {},
        "record_catalog": {},
        "pending_cloud_uploads": {},
        "_pending_cloud_payload_count": 0,
        "_pending_cloud_payload_bytes": 0,
        # Derived cache only. The authoritative posting lists remain in
        # token_to_record_ids_by_epoch and are persisted normally.
        "_posting_digest_cache_by_epoch": {},
        # Derived ordering only; strict v2 leaves and the signed root remain
        # byte-for-byte unchanged.
        "_ordered_token_ids_cache_by_epoch": {},
        # Keep a derived sorted posting list for each active token. The
        # authoritative set remains token_to_record_ids_by_epoch; this cache
        # only removes repeated sorting before calculating the same D(PL).
        "_sorted_posting_ids_cache_by_epoch": {},
    }
    gateway_state_path = Path(os.environ.get(
        "CAMSHIELD_GATEWAY_STATE",
        ".camshield_gateway_state.json",
    ))
    state["_gateway_state_path"] = gateway_state_path
    # The strict checkpoint transition is global: every accepted segment
    # advances its signed checkpoint version.  It must therefore remain
    # serialized, independently of HTTP/Gunicorn concurrency.
    ingest_lock = threading.RLock()
    ingest_phase_samples_lock = threading.Lock()
    # Per-camera conditions separate predecessor waiting from the global
    # transition. A cam02 seq=i+1 may never advance before cam02 seq=i, but
    # it must not occupy a Gunicorn thread behind cam01's predecessor.  These
    # conditions protect no protocol state; the global ingest_lock still
    # protects every registry/checkpoint/journal state transition.
    ingest_order_conditions_lock = threading.Lock()
    ingest_order_conditions: dict[str, threading.Condition] = {}
    ingest_order_waiters_lock = threading.Lock()
    ingest_order_waiters: dict[str, int] = {}
    ingest_order_wait_limit_s = max(
        1.0,
        min(
            120.0,
            float(os.environ.get("CAMSHIELD_INGEST_ORDER_WAIT_S", "25")),
        ),
    )
    ingest_log_every = max(
        0,
        int(os.environ.get("CAMSHIELD_INGEST_LOG_EVERY", "0")),
    )

    def _log_ingest_progress(segment: Any, message: str) -> None:
        """Rate-limit informational ingest logs without suppressing errors."""
        if ingest_log_every and int(segment.seq) % ingest_log_every == 0:
            print(message)

    def _camera_order_condition(cid: str) -> threading.Condition:
        with ingest_order_conditions_lock:
            condition = ingest_order_conditions.get(cid)
            if condition is None:
                condition = threading.Condition(threading.RLock())
                ingest_order_conditions[cid] = condition
            return condition

    def _notify_camera_order_waiters(cid: str) -> None:
        # Notify only after releasing ingest_lock.  This preserves a clear
        # lock order and lets a waiter re-check its expected sequence under the
        # authoritative global transition lock.
        condition = _camera_order_condition(cid)
        with condition:
            condition.notify_all()

    def _increment_ingest_order_waiter(cid: str) -> None:
        with ingest_order_waiters_lock:
            ingest_order_waiters[cid] = ingest_order_waiters.get(cid, 0) + 1

    def _decrement_ingest_order_waiter(cid: str) -> None:
        with ingest_order_waiters_lock:
            remaining = ingest_order_waiters.get(cid, 1) - 1
            if remaining > 0:
                ingest_order_waiters[cid] = remaining
            else:
                ingest_order_waiters.pop(cid, None)

    def _ingest_order_waiter_total() -> int:
        with ingest_order_waiters_lock:
            return sum(ingest_order_waiters.values())


    load_or_init_gateway_state(gateway, state, gateway_state_path)
    persistence_mode = os.environ.get(
        "CAMSHIELD_GATEWAY_PERSISTENCE_MODE", "legacy-files"
    ).strip()
    durable_store: GatewayGroupedDurableStore | None = None
    if persistence_mode == GatewayGroupedDurableStore.MODE:
        durable_store = GatewayGroupedDurableStore(
            gateway_state_path,
            batch_max=int(os.environ.get(
                "CAMSHIELD_GATEWAY_DURABLE_BATCH_MAX", "16"
            )),
            batch_wait_ms=float(os.environ.get(
                "CAMSHIELD_GATEWAY_DURABLE_BATCH_WAIT_MS", "2"
            )),
        )
        replay_metrics = replay_gateway_transaction_store(
            gateway, state, gateway_state_path
        )
        state["_gateway_durable_store"] = durable_store
        state["gateway_persistence_mode"] = persistence_mode
        state["gateway_transaction_replay"] = replay_metrics
    elif persistence_mode != "legacy-files":
        raise ValueError(
            "CAMSHIELD_GATEWAY_PERSISTENCE_MODE must be legacy-files or "
            f"{GatewayGroupedDurableStore.MODE}"
        )
    else:
        state["gateway_persistence_mode"] = persistence_mode

    # Only authoritative posting state is persisted.  Recreate every derived
    # root-construction cache after all journal/WAL recovery has completed.
    rebuild_ordered_checkpoint_caches(state)

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
                with ingest_lock:
                    for item in apply_scheduled_epoch_rotations(
                        gateway, state, cloud
                    ):
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

    app.config["CAMSHIELD_GATEWAY"] = gateway
    app.config["CAMSHIELD_GATEWAY_STATE"] = state
    cloud_upload_worker_count = max(
        1,
        min(16, int(os.environ.get("CAMSHIELD_CLOUD_UPLOAD_WORKERS", "1"))),
    )
    # A transport batch only groups already-durable, individually signed
    # protocol payloads.  It never changes a record, ΔPL, checkpoint, or the
    # retry unit stored on disk.
    cloud_upload_batch_max_payloads = max(
        1,
        min(64, int(os.environ.get("CAMSHIELD_CLOUD_UPLOAD_BATCH_MAX", "1"))),
    )
    cloud_upload_batch_wait_s = max(
        0.0,
        min(
            1.0,
            float(os.environ.get("CAMSHIELD_CLOUD_UPLOAD_BATCH_WAIT_MS", "0"))
            / 1000.0,
        ),
    )
    cloud_upload_queue = deque(state.get("pending_cloud_uploads", {}).keys())
    cloud_upload_queued = set(cloud_upload_queue)
    cloud_upload_inflight: set[str] = set()
    cloud_upload_inflight_batches: dict[int, int] = {}
    # Only one worker may collect a timed batch at a time. Without this gate,
    # many idle workers each take one record and defeat transport coalescing.
    cloud_upload_batch_collecting = False
    cloud_upload_condition = threading.Condition()
    state["cloud_upload_worker_count"] = cloud_upload_worker_count

    def _queue_cloud_upload(rid: str) -> None:
        with cloud_upload_condition:
            if rid in cloud_upload_queued or rid in cloud_upload_inflight:
                return
            cloud_upload_queue.append(rid)
            cloud_upload_queued.add(rid)
            cloud_upload_condition.notify()

    @app.get("/health")
    def health():
        em = gateway.epoch_manager
        disk = shutil.disk_usage(os.environ.get("CAMSHIELD_DATA_DIR", "."))
        disk_percent = round((disk.used / disk.total) * 100.0, 2)
        persistence = gateway_persistence_metrics(
            gateway_state_path, state=state
        )
        with cloud_upload_condition:
            upload_queue_depth = len(cloud_upload_queue)
            upload_inflight = len(cloud_upload_inflight)
            upload_inflight_requests = len(cloud_upload_inflight_batches)
        durable_fatal = durable_store.fatal_error if durable_store else None
        return jsonify(
            {
                "ok": durable_fatal is None,
                "use_charm": use_charm,
                "gateway_persistence_mode": persistence_mode,
                "gateway_durable_error": (
                    str(durable_fatal) if durable_fatal is not None else None
                ),
                "enrolled": sorted(state["enrolled"]),
                "record_count": state["record_count"],
                "cloud_url": state["cloud_url"],
                "cloud_uploads": state["cloud_uploads"],
                "last_cloud_upload": state["last_cloud_upload"],
                "live_cloud_uploads": state.get("live_cloud_uploads", 0),
                "last_live_cloud_upload": state.get("last_live_cloud_upload"),
                "last_cloud_error": state["last_cloud_error"],
                "has_ordered_checkpoint": state["last_ordered_checkpoint"] is not None,
                "ordered_checkpoint_type": (
                    state["last_ordered_checkpoint"].get("type")
                    if state["last_ordered_checkpoint"]
                    else None
                ),
                "ordered_leaf_format": (
                    state["last_ordered_checkpoint"].get("leaf_format")
                    if state["last_ordered_checkpoint"]
                    else None
                ),
                "current_epoch": em.current_epoch(),
                "current_version": em.current_version(),
                "epoch_duration_s": em.epoch_duration_s,
                "epoch_started_at": em.epoch_started_at,
                "epoch_ends_at": em.epoch_ends_at(),
                "seconds_until_rotation": em.seconds_until_rotation(),
                "pending_cloud_uploads": len(state.get("pending_cloud_uploads", {})),
                "cloud_upload_worker_count": cloud_upload_worker_count,
                "cloud_upload_batch_max_payloads": cloud_upload_batch_max_payloads,
                "cloud_upload_batch_wait_ms": int(cloud_upload_batch_wait_s * 1000),
                "cloud_upload_queue_depth": upload_queue_depth,
                "cloud_upload_inflight_requests": upload_inflight_requests,
                "cloud_upload_inflight_records": upload_inflight,
                "cloud_upload_inflight": upload_inflight,
                "accepted_segment_count": len(state.get("accepted_segments", {})),
                "ingest_sequence_waiters": _ingest_order_waiter_total(),
                "ingest_order_wait_limit_s": ingest_order_wait_limit_s,
                "gateway_current_epoch_token_count": len(
                    state.get("token_to_record_ids", {})
                ),
                "index_record_locator_tags": gateway.include_record_locator_tags,
                "index_tag_profile": (
                    "full-record-locators"
                    if gateway.include_record_locator_tags
                    else "bounded-structured-tags"
                ),
                "gateway_retained_posting_epoch_count": len(
                    state.get("token_to_record_ids_by_epoch", {})
                ),
                **persistence,
                "disk_percent": disk_percent,
                "disk_state": (
                    "critical" if disk_percent >= 90
                    else "high" if disk_percent >= 80
                    else "ok"
                ),
                "camera_resume": {
                    cid: {
                        "expected_seq": entry.expected_seq,
                        "last_gamma_hex": entry.last_gamma.hex(),
                    }
                    for cid, entry in gateway.camera_registry.cameras.items()
                },
            }
        )

    @app.post("/enroll")
    def enroll():
        obj = request.get_json(force=True)

        cid = obj["cid"]
        pk_bytes = b64d(obj["camera_public_key_b64"])
        expected_seq = int(obj.get("expected_seq", 1))
        initial_gamma_hex = str(obj.get("initial_gamma_hex", "00" * 32))
        initial_gamma = bytes.fromhex(initial_gamma_hex)
        resume = bool(obj.get("resume", False))

        pk = load_public_key(pk_bytes)
        with ingest_lock:
            existing = gateway.camera_registry.cameras.get(cid)
            if existing is not None and resume:
                if public_key_bytes(existing.public_key) != pk_bytes:
                    return jsonify({
                        "ok": False,
                        "error": "camera public key changed; explicit chain reset required",
                        "cid": cid,
                    }), 409
                enrolled_expected_seq = existing.expected_seq
                resumed = True
            else:
                gateway.enroll_camera(
                    cid=cid,
                    camera_public_key=pk,
                    initial_gamma=initial_gamma,
                    expected_seq=expected_seq,
                )
                enrolled_expected_seq = expected_seq
                resumed = False

            state["enrolled"].add(cid)
            import base64 as _camshield_b64
            state.setdefault("camera_public_keys", {})[cid] = (
                _camshield_b64.b64encode(pk_bytes).decode("ascii")
            )
            compact_gateway_journal(gateway, state, gateway_state_path)
        _notify_camera_order_waiters(cid)

        print(
            f"[ENROLL] cid={cid}, expected_seq={enrolled_expected_seq}, "
            f"resumed={resumed}"
        )

        return jsonify(
            {
                "ok": True,
                "cid": cid,
                "expected_seq": enrolled_expected_seq,
                "resumed": resumed,
            }
        )

    @app.post("/admin/camera/reset")
    def reset_camera_registry():
        obj = request.get_json(force=True, silent=True) or {}
        cid = str(obj.get("camera_id", obj.get("cid", ""))).strip()
        if not cid:
            return jsonify({"ok": False, "error": "camera_id is required"}), 400
        with ingest_lock:
            existing = gateway.camera_registry.cameras.pop(cid, None)
            state["enrolled"].discard(cid)
            state["camera_public_keys"].pop(cid, None)
            state.get("live_fast_path_cameras", {}).pop(cid, None)
            compact_gateway_journal(gateway, state, gateway_state_path)
        _notify_camera_order_waiters(cid)
        return jsonify({
            "ok": True,
            "camera_id": cid,
            "registry_removed": existing is not None,
            "next_enrollment_starts_new_chain": True,
        })

    def update_remote_index_state(record: Any) -> dict[str, set[str]]:
        """
        Update Gateway-side posting snapshot for remote Cloud.

        record.index_tokens is expected to be list[bytes].
        record.rid is expected to be bytes.
        """
        rid_hex = record.rid.hex()

        by_epoch = state.setdefault("token_to_record_ids_by_epoch", {})
        epoch_map: dict[str, set[str]] = by_epoch.setdefault(str(record.epoch), {})

        digest_by_epoch = state.setdefault("_posting_digest_cache_by_epoch", {})
        digest_cache: dict[str, str] = digest_by_epoch.setdefault(
            str(record.epoch), {}
        )

        order_by_epoch = state.setdefault("_ordered_token_ids_cache_by_epoch", {})
        ordered_token_ids: list[str] | None = order_by_epoch.get(str(record.epoch))
        if ordered_token_ids is None:
            ordered_token_ids = sorted(
                make_real_token_id(token_hex) for token_hex in epoch_map
            )
            order_by_epoch[str(record.epoch)] = ordered_token_ids

        sorted_postings_by_epoch = state.setdefault(
            "_sorted_posting_ids_cache_by_epoch", {}
        )
        sorted_postings: dict[str, list[str]] = sorted_postings_by_epoch.setdefault(
            str(record.epoch), {}
        )

        for token in record.index_tokens:
            token_hex = token.hex()
            is_new_token = token_hex not in epoch_map
            posting = epoch_map.setdefault(token_hex, set())
            is_new_record = rid_hex not in posting
            posting.add(rid_hex)
            sorted_posting = sorted_postings.get(token_hex)
            if sorted_posting is None:
                # The cache is not persisted. Rebuild it once after a Gateway
                # restart, then maintain it incrementally for this epoch.
                sorted_posting = sorted(str(value) for value in posting)
                sorted_postings[token_hex] = sorted_posting
            elif is_new_record:
                bisect.insort(sorted_posting, rid_hex)
            digest_cache[token_hex] = posting_digest_hex_from_sorted_record_ids(
                sorted_posting
            )
            if is_new_token:
                bisect.insort(ordered_token_ids, make_real_token_id(token_hex))

        state["token_to_record_ids"] = epoch_map
        return epoch_map

    def build_signed_ordered_checkpoint(
        *,
        epoch: int,
        token_to_record_ids: dict[str, set[str]],
    ) -> dict[str, Any]:
        versions = state.setdefault("ordered_checkpoint_version_by_epoch", {})
        epoch_key = str(epoch)
        versions[epoch_key] = int(versions.get(epoch_key, 0)) + 1
        version = int(versions[epoch_key])
        state["ordered_checkpoint_version"] = version
        timestamp = int(time.time())

        digest_cache = state.setdefault(
            "_posting_digest_cache_by_epoch", {}
        ).setdefault(epoch_key, {})
        order_by_epoch = state.setdefault("_ordered_token_ids_cache_by_epoch", {})
        ordered_token_ids = order_by_epoch.get(epoch_key)
        if ordered_token_ids is None:
            ordered_token_ids = sorted(
                make_real_token_id(token_hex) for token_hex in token_to_record_ids
            )
            order_by_epoch[epoch_key] = ordered_token_ids
        root_hex = build_ordered_merkle_root(
            token_to_record_ids,
            posting_digest_by_token=digest_cache,
            checkpoint_version=version,
            sorted_real_token_ids=ordered_token_ids,
        )

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
            checkpoint_type="camshield-ordered-checkpoint-v2",
        )

        signature = sign(gateway.skG, signed_bytes)

        signed_checkpoint = {
            "type": "camshield-ordered-checkpoint-v2",
            "leaf_format": "ordered-token-leaf-v2",
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

    # Metrics are out-of-band and do not enter records, postings, or checkpoints.
    def _record_ingest_phase_samples(values: dict[str, Any]) -> None:
        with ingest_phase_samples_lock:
            samples_by_phase = state.setdefault("ingest_phase_ms_samples", {})
            for name, value in values.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                samples = samples_by_phase.setdefault(str(name), [])
                samples.append(float(value))
                if len(samples) > 5000:
                    del samples[:-2500]

    def _phase_summary(values: list[float]) -> dict[str, Any]:
        import math

        if not values:
            return {"count": 0}
        ordered = sorted(float(value) for value in values)

        def percentile(q: float) -> float:
            index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
            return ordered[index]

        return {
            "count": len(ordered),
            "mean_ms": sum(ordered) / len(ordered),
            "p50_ms": percentile(0.50),
            "p95_ms": percentile(0.95),
            "max_ms": ordered[-1],
        }

    @app.get("/debug/ingest-phase-timing")
    def debug_ingest_phase_timing():
        with ingest_phase_samples_lock:
            phase_snapshot = {
                name: list(values)
                for name, values in state.get(
                    "ingest_phase_ms_samples", {}
                ).items()
            }
        return jsonify({
            "ok": True,
            "protocol_implementation_unchanged": True,
            "samples": {
                name: _phase_summary(values)
                for name, values in sorted(
                    phase_snapshot.items()
                )
            },
        })

    @app.post("/debug/ingest-phase-timing/reset")
    def reset_ingest_phase_timing():
        with ingest_phase_samples_lock:
            state["ingest_phase_ms_samples"] = {}
        state["cloud_upload_ms_samples"] = []
        return jsonify({"ok": True, "reset": "ingest_phase_ms_samples"})

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
        return send_remote_cloud_payload(
            build_remote_cloud_payload(
                record=record,
                signed_checkpoint=signed_checkpoint,
            )
        )

    def build_remote_cloud_payload(
        *,
        record: Any,
        signed_checkpoint: dict[str, Any],
    ) -> dict[str, Any]:
        rid_hex = record.rid.hex()
        return {
            "epoch": int(record.epoch),
            "records": [
                {
                    "rid": rid_hex,
                    "record": to_jsonable(record),
                }
            ],
            "posting_updates": [
                {
                    "token": token.hex(),
                    "rid": rid_hex,
                }
                for token in record.index_tokens
            ],
            "signed_checkpoint": signed_checkpoint,
        }

    def send_remote_cloud_payload(payload: dict[str, Any]) -> dict[str, Any]:
        return send_remote_cloud_payloads([payload])

    def send_remote_cloud_payloads(
        payloads: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not normalized_cloud_url:
            return {
                "ok": True,
                "skipped": True,
                "reason": "cloud_url not configured",
            }

        if not payloads:
            raise ValueError("at least one Cloud payload is required")
        batched = len(payloads) > 1
        url = normalized_cloud_url + (
            "/store-batch-many" if batched else "/store-batch"
        )
        request_body: dict[str, Any] = (
            {"batches": payloads} if batched else payloads[0]
        )

        import time as _cloud_time
        _cloud_upload_t0 = _cloud_time.perf_counter()
        resp = camshield_requests_post_with_retries(
            url,
            json=request_body,
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
        data["client_roundtrip_ms"] = cloud_upload_ms
        data["transport_batch_payloads"] = len(payloads)

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
        state.setdefault("live_cloud_upload_ms_samples", []).append(cloud_upload_ms)
        state["last_live_cloud_upload_ms"] = cloud_upload_ms
        state["live_cloud_uploads"] = int(
            state.get("live_cloud_uploads", 0)
        ) + 1
        state["last_live_cloud_upload"] = {
            "timestamp": int(time.time()),
            "url": url,
            "rid": rid_hex,
            "mode": "live-fast-path",
            "response": data,
        }
        state["last_cloud_error"] = None

        return data

    def make_live_record(archival_record: Any) -> Any:
        if hasattr(archival_record, "model_copy"):
            live_record = archival_record.model_copy(deep=True)
        else:
            live_record = archival_record.copy(deep=True)
        live_record.index_tokens = []
        live_record.index_digest = b""
        live_record.binding_hash = live_record.compute_live_binding_hash()
        live_record.gateway_signature = sign(
            gateway.skG,
            live_record.binding_hash,
        )
        return live_record

    def _take_cloud_upload_batch() -> list[str]:
        """Take a bounded batch without changing the durable retry boundary."""
        nonlocal cloud_upload_batch_collecting
        with cloud_upload_condition:
            while True:
                while not cloud_upload_queue:
                    cloud_upload_condition.wait(timeout=1.0)
                if not cloud_upload_batch_collecting:
                    cloud_upload_batch_collecting = True
                    break
                cloud_upload_condition.wait(timeout=1.0)
            try:
                rids = [cloud_upload_queue.popleft()]
                cloud_upload_queued.discard(rids[0])
                deadline = time.monotonic() + cloud_upload_batch_wait_s
                while len(rids) < cloud_upload_batch_max_payloads:
                    if cloud_upload_queue:
                        rid = cloud_upload_queue.popleft()
                        cloud_upload_queued.discard(rid)
                        rids.append(rid)
                        continue
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    cloud_upload_condition.wait(timeout=remaining)
                cloud_upload_inflight.update(rids)
                return rids
            finally:
                cloud_upload_batch_collecting = False
                cloud_upload_condition.notify_all()

    def _cloud_upload_worker(worker_index: int) -> None:
        retry_delay_s = 1.0
        while True:
            rids = _take_cloud_upload_batch()
            with cloud_upload_condition:
                cloud_upload_inflight_batches[worker_index] = len(rids)
            with ingest_lock:
                items = [
                    (rid, state.setdefault("pending_cloud_uploads", {}).get(rid))
                    for rid in rids
                ]
            items = [(rid, item) for rid, item in items if isinstance(item, dict)]
            if not items:
                with cloud_upload_condition:
                    cloud_upload_inflight.difference_update(rids)
                    cloud_upload_inflight_batches.pop(worker_index, None)
                continue

            upload_started = time.perf_counter()
            try:
                payloads = [
                    load_pending_upload_payload(item, gateway_state_path)
                    for _, item in items
                ]
                result = send_remote_cloud_payloads(payloads)
                elapsed_ms = (time.perf_counter() - upload_started) * 1000.0
                # Cloud acknowledgement only retires a retry payload; it does
                # not alter any checkpoint. A crash before the asynchronous
                # WAL update simply replays the same idempotent Cloud upload.
                if durable_store is not None:
                    durable_store.mark_uploaded([rid for rid, _ in items])
                else:
                    for _, item in items:
                        remove_pending_upload_payload(item, gateway_state_path)
                ack_lock_started = time.perf_counter()
                with ingest_lock:
                    ack_lock_wait_ms = (
                        time.perf_counter() - ack_lock_started
                    ) * 1000.0
                    ack_state_started = time.perf_counter()
                    for rid, item in items:
                        completed_item = state.setdefault(
                            "pending_cloud_uploads", {}
                        ).pop(rid, None)
                        state["_pending_cloud_payload_count"] = max(
                            0,
                            int(state.get("_pending_cloud_payload_count", 0)) - 1,
                        )
                        state["_pending_cloud_payload_bytes"] = max(
                            0,
                            int(state.get("_pending_cloud_payload_bytes", 0))
                            - int((completed_item or item).get("payload_bytes", 0)),
                        )
                        accepted = state.setdefault("accepted_segments", {}).get(
                            str(item.get("segment_key", ""))
                        )
                        if isinstance(accepted, dict):
                            accepted["cloud_upload"] = result
                    state["cloud_uploads"] = int(state.get("cloud_uploads", 0)) + len(items)
                    last_upload = {
                        "timestamp": int(time.time()),
                        "url": normalized_cloud_url + (
                            "/store-batch-many" if len(items) > 1 else "/store-batch"
                        ),
                        "rid": items[-1][0],
                        "rids": [rid for rid, _ in items],
                        "transport_batch_payloads": len(items),
                        "response": result,
                    }
                    state["last_cloud_upload"] = last_upload
                    state["last_cloud_error"] = None
                    _record_ingest_phase_samples({
                        "cloud_worker_upload_roundtrip_ms": elapsed_ms,
                        "cloud_worker_transport_batch_payloads": len(items),
                        "cloud_worker_ack_lock_wait_ms": ack_lock_wait_ms,
                        "cloud_worker_ack_state_ms": (
                            time.perf_counter() - ack_state_started
                        ) * 1000.0,
                        **{
                            f"cloud_worker_server_{name}": value
                            for name, value in result.get(
                                "server_timing_ms", {}
                            ).items()
                            if isinstance(value, (int, float))
                            and not isinstance(value, bool)
                        },
                    })
                with cloud_upload_condition:
                    cloud_upload_inflight.difference_update(rids)
                    cloud_upload_inflight_batches.pop(worker_index, None)
                retry_delay_s = 1.0
            except Exception as exc:
                with ingest_lock:
                    for rid, _ in items:
                        current = state.setdefault("pending_cloud_uploads", {}).get(rid)
                        if isinstance(current, dict):
                            current["attempts"] = int(current.get("attempts", 0)) + 1
                            current["last_error"] = str(exc)
                    state["last_cloud_error"] = str(exc)
                with cloud_upload_condition:
                    cloud_upload_inflight.difference_update(rids)
                    cloud_upload_inflight_batches.pop(worker_index, None)
                print(
                    f"[CLOUD worker={worker_index}] queued upload retry "
                    f"records={len(items)} error={exc}"
                )
                time.sleep(retry_delay_s)
                with ingest_lock:
                    retry_rids = [
                        rid for rid, _ in items
                        if rid in state.setdefault("pending_cloud_uploads", {})
                    ]
                for rid in retry_rids:
                    _queue_cloud_upload(rid)
                retry_delay_s = min(30.0, retry_delay_s * 2.0)

    def _gateway_compaction_worker() -> None:
        compact_every = int(os.environ.get(
            "CAMSHIELD_GATEWAY_COMPACT_EVERY", "10000"
        ))
        if compact_every <= 0:
            return
        compact_every = max(1000, compact_every)
        last_compacted = int(state.get("record_count", 0))
        while True:
            time.sleep(1.0)
            current = int(state.get("record_count", 0))
            if current - last_compacted < compact_every:
                continue
            with ingest_lock:
                compact_started = time.perf_counter()
                compact_gateway_journal(gateway, state, gateway_state_path)
                _record_ingest_phase_samples({
                    "gateway_journal_compact_ms": (
                        time.perf_counter() - compact_started
                    ) * 1000.0,
                })
                last_compacted = int(state.get("record_count", 0))

    if normalized_cloud_url:
        for worker_index in range(cloud_upload_worker_count):
            threading.Thread(
                target=_cloud_upload_worker,
                args=(worker_index + 1,),
                name=f"camshield-cloud-upload-worker-{worker_index + 1}",
                daemon=True,
            ).start()
        threading.Thread(
            target=_gateway_compaction_worker,
            name="camshield-gateway-compaction",
            daemon=True,
        ).start()

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
        request_started = time.perf_counter()
        g.camshield_ingest_transport_timing = {
            "handler_started": request_started,
        }
        # Reading a request body can wait on the sender. It is independent of
        # Gateway protocol state, so do it before the strict checkpoint lock.
        # The lock still serializes every stateful protocol transition below.
        try:
            body_started = time.perf_counter()
            raw_body = request.get_data(cache=True)
            request_body_receive_ms = (
                time.perf_counter() - body_started
            ) * 1000.0

            json_started = time.perf_counter()
            obj = json.loads(raw_body)
            request_json_loads_ms = (
                time.perf_counter() - json_started
            ) * 1000.0

            segment_started = time.perf_counter()
            segment = camera_segment_from_json(obj["segment"])
            request_segment_decode_ms = (
                time.perf_counter() - segment_started
            ) * 1000.0
        except Exception as exc:
            traceback.print_exc()
            return jsonify({"ok": False, "error": str(exc)}), 500
        wire_phase_ms = {
            "request_body_receive_ms": request_body_receive_ms,
            "request_json_loads_ms": request_json_loads_ms,
            "request_segment_decode_ms": request_segment_decode_ms,
            "request_body_bytes": len(raw_body),
        }
        g.camshield_ingest_transport_timing.update(wire_phase_ms)
        request_decode_ms = request_json_loads_ms + request_segment_decode_ms
        ordering_started = time.perf_counter()
        waiting_registered = False
        camera_condition = _camera_order_condition(segment.cid)
        try:
            while True:
                response = None
                global_lock_started = time.perf_counter()
                with ingest_lock:
                    global_commit_lock_wait_ms = (
                        time.perf_counter() - global_lock_started
                    ) * 1000.0
                    try:
                        expected_seq = int(
                            gateway.camera_registry.get(segment.cid).expected_seq
                        )
                    except Exception:
                        # Preserve the established un-enrolled-camera error
                        # path instead of inventing a new transport outcome.
                        wire_phase_ms["sequence_order_wait_ms"] = (
                            time.perf_counter() - ordering_started
                        ) * 1000.0
                        wire_phase_ms["global_commit_lock_wait_ms"] = (
                            global_commit_lock_wait_ms
                        )
                        g.camshield_ingest_transport_timing.update(wire_phase_ms)
                        response = _ingest_locked(
                            request_started=request_started,
                            lock_wait_ms=0.0,
                            lock_acquired=time.perf_counter(),
                            obj=obj,
                            segment=segment,
                            request_decode_ms=request_decode_ms,
                            wire_phase_ms=wire_phase_ms,
                        )
                    else:
                        if int(segment.seq) <= expected_seq:
                            wire_phase_ms["sequence_order_wait_ms"] = (
                                time.perf_counter() - ordering_started
                            ) * 1000.0
                            wire_phase_ms["global_commit_lock_wait_ms"] = (
                                global_commit_lock_wait_ms
                            )
                            g.camshield_ingest_transport_timing.update(wire_phase_ms)
                            response = _ingest_locked(
                                request_started=request_started,
                                lock_wait_ms=0.0,
                                lock_acquired=time.perf_counter(),
                                obj=obj,
                                segment=segment,
                                request_decode_ms=request_decode_ms,
                                wire_phase_ms=wire_phase_ms,
                            )

                if response is not None:
                    durable_ticket = getattr(
                        g, "camshield_gateway_durable_ticket", None
                    )
                    if durable_ticket is not None:
                        try:
                            durable_result = durable_ticket.wait(timeout=30.0)
                        except Exception as exc:
                            state["last_cloud_error"] = str(exc)
                            _notify_camera_order_waiters(segment.cid)
                            return jsonify({
                                "ok": False,
                                "error": "Gateway durable commit failed",
                                "retryable": True,
                                "cid": segment.cid,
                                "seq": int(segment.seq),
                            }), 503
                        phase_ms = getattr(
                            g, "camshield_gateway_pending_phase_ms", {}
                        )
                        phase_ms.update(durable_result)
                        phase_ms["gateway_journal_commit_ms"] = float(
                            durable_result.get(
                                "gateway_durable_commit_amortized_ms", 0.0
                            )
                        )
                        phase_ms["ingest_total_ms"] = (
                            time.perf_counter() - request_started
                        ) * 1000.0
                        phase_ms["gateway_protocol_and_durable_commit_ms"] = max(
                            0.0,
                            phase_ms["ingest_total_ms"]
                            - phase_ms["request_body_receive_ms"]
                            - phase_ms["request_json_loads_ms"]
                            - phase_ms["request_segment_decode_ms"]
                            - phase_ms["lock_wait_ms"],
                        )
                        _record_ingest_phase_samples(phase_ms)
                        g.camshield_ingest_transport_timing.update(phase_ms)
                        _queue_cloud_upload(
                            str(getattr(g, "camshield_gateway_durable_rid"))
                        )
                    _notify_camera_order_waiters(segment.cid)
                    return response

                elapsed_s = time.perf_counter() - ordering_started
                remaining_s = ingest_order_wait_limit_s - elapsed_s
                if remaining_s <= 0:
                    wire_phase_ms["sequence_order_wait_ms"] = elapsed_s * 1000.0
                    g.camshield_ingest_transport_timing.update(wire_phase_ms)
                    return jsonify({
                        "ok": False,
                        "error": (
                            "predecessor segment did not reach durable "
                            "Gateway processing before order-wait timeout"
                        ),
                        "cid": segment.cid,
                        "seq": int(segment.seq),
                        "expected_seq": expected_seq,
                        "retryable": True,
                    }), 503

                # Double-check the expected sequence while holding this
                # camera's condition. A predecessor can commit between the
                # global check above and condition.wait(); re-checking avoids a
                # missed notification without coupling unrelated cameras.
                with camera_condition:
                    with ingest_lock:
                        try:
                            current_expected_seq = int(
                                gateway.camera_registry.get(segment.cid).expected_seq
                            )
                        except Exception:
                            # A concurrent administrative reset removes the
                            # registry entry. Return through the pre-existing
                            # un-enrolled path on the next outer iteration.
                            continue
                    if int(segment.seq) <= current_expected_seq:
                        continue
                    if not waiting_registered:
                        _increment_ingest_order_waiter(segment.cid)
                        waiting_registered = True
                    camera_condition.wait(timeout=remaining_s)
        finally:
            if waiting_registered:
                _decrement_ingest_order_waiter(segment.cid)

    def _ingest_locked(
        *,
        request_started: float,
        lock_wait_ms: float,
        lock_acquired: float,
        obj: dict[str, Any],
        segment: Any,
        request_decode_ms: float,
        wire_phase_ms: dict[str, Any],
    ):
        processed_record = None
        registry_before = None
        record_count_incremented = False
        checkpoint_state_before = None
        posting_rollback_tokens: list[str] = []
        recovered_incomplete_ack = False
        phase_ms: dict[str, Any] = {
            "lock_wait_ms": lock_wait_ms,
            "ingest_request_decode_ms": request_decode_ms,
        }
        phase_ms.update(wire_phase_ms)
        try:
            segment_key = f"{segment.cid}:{segment.seq}:{segment.sid}"
            cached = state.setdefault("accepted_segments", {}).get(segment_key)
            if cached is not None:
                duplicate_response = dict(cached)
                duplicate_response["duplicate"] = True
                phase_ms["ingest_total_ms"] = (
                    time.perf_counter() - request_started
                ) * 1000.0
                phase_ms["ingest_lock_hold_ms"] = (
                    time.perf_counter() - lock_acquired
                ) * 1000.0
                phase_ms["gateway_protocol_and_durable_commit_ms"] = max(
                    0.0,
                    phase_ms["ingest_total_ms"]
                    - phase_ms["request_body_receive_ms"]
                    - phase_ms["request_json_loads_ms"]
                    - phase_ms["request_segment_decode_ms"]
                    - phase_ms["lock_wait_ms"],
                )
                g.camshield_ingest_transport_timing.update(phase_ms)
                return jsonify(duplicate_response)

            phase_started = time.perf_counter()
            extra_keywords = obj.get(
                "extra_keywords",
                ["event:motion", "location:lab", "object:person"],
            )

            role = obj.get("role", "OWNER")
            purpose = obj.get("purpose", "SURVEILLANCE")
            mode = obj.get("mode", "READ")
            scope = obj.get("scope", segment.cid)
            access_class = obj.get("access_class", "RAW")

            _log_ingest_progress(
                segment,
                f"[INGEST] cid={segment.cid} sid={segment.sid} "
                f"seq={segment.seq} bytes={len(segment.raw_payload)}",
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




            scale_prefix = os.environ.get("CAMSHIELD_SCALE_TAG_PREFIX", "")
            if scale_prefix:



                bounds_raw = os.environ.get(
                    "CAMSHIELD_SCALE_TAG_BOUNDS",
                    "5,10,20,40,60",
                )
                bounds = [int(x.strip()) for x in bounds_raw.split(",") if x.strip()]
                for bound in bounds:
                    if seq <= bound:
                        dynamic_tags.append(f"{scale_prefix}{bound}")




            qtype_prefix = os.environ.get("CAMSHIELD_QUERY_TAG_PREFIX", "")
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
            registry_entry = gateway.camera_registry.get(segment.cid)

            if segment.seq < registry_entry.expected_seq:
                can_replay_last_transition = (
                    segment.seq == registry_entry.expected_seq - 1
                    and segment.gamma == registry_entry.last_gamma
                )
                if not can_replay_last_transition:
                    raise ValueError(
                        f"Unexpected sequence number for {segment.cid}: "
                        f"got {segment.seq}, expected "
                        f"{registry_entry.expected_seq}"
                    )

                catalog_match = any(
                    item.get("cid") == segment.cid
                    and int(item.get("seq", -1)) == int(segment.seq)
                    and item.get("sid") == segment.sid
                    for item in state.get("record_catalog", {}).values()
                )
                if catalog_match:
                    raise RuntimeError(
                        "accepted segment receipt is missing although the "
                        "record catalog is committed; refusing to create a "
                        "second checkpoint"
                    )

                print(
                    f"[INGEST] recovering incomplete acknowledgement "
                    f"cid={segment.cid} seq={segment.seq}"
                )
                registry_entry.last_gamma = segment.gamma_prev
                registry_entry.expected_seq = segment.seq
                recovered_incomplete_ack = True

            registry_before = (
                registry_entry,
                registry_entry.last_gamma,
                registry_entry.expected_seq,
            )
            phase_ms["ingest_admission_prepare_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0

            phase_started = time.perf_counter()
            apply_scheduled_epoch_rotations(gateway, state, cloud)
            phase_ms["epoch_rotation_check_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0

            phase_started = time.perf_counter()
            record = gateway.process_segment(
                segment=segment,
                extra_keywords=extra_keywords,
                role=role,
                purpose=purpose,
                mode=mode,
                scope=scope,
                access_class=access_class,
                live=False,
                # The service owns the strict finalization/rotation boundary.
                # Calling Gateway's convenience auto-rotation here could
                # cross a wall-clock boundary after the service-level check.
                auto_rotate_epoch=False,
            )
            phase_ms["gateway_process_segment_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0
            phase_ms.update(gateway.last_process_phase_ms)
            processed_record = record

            state["record_count"] += 1
            record_count_incremented = True

            live_upload_result = None
            if live_mode:
                live_record = make_live_record(record)
                live_upload_result = upload_live_record_to_remote_cloud(
                    record=live_record,
                    camera_id=segment.cid,
                    session_id=live_session_id,
                )

                print(
                    f"[OK] live record rid={live_record.rid.hex()[:32]}... "
                    f"epoch={record.epoch} session={live_session_id}"
                )

                if normalized_cloud_url:
                    print(
                        f"[CLOUD] live uploaded rid={record.rid.hex()[:32]}... "
                        f"to {normalized_cloud_url}"
                    )

            phase_started = time.perf_counter()
            # Keep an exact in-memory transaction snapshot until the record
            # and its signed checkpoint have crossed the Gateway durability
            # boundary.  If journal/WAL submission fails, no unsigned or
            # un-uploadable ΔPL element may remain in the next root.
            checkpoint_state_before = {
                "last_checkpoint": state.get("last_checkpoint"),
                "last_ordered_checkpoint": state.get("last_ordered_checkpoint"),
                "ordered_checkpoint_version": state.get("ordered_checkpoint_version"),
                "ordered_checkpoint_version_by_epoch": copy.deepcopy(
                    state.get("ordered_checkpoint_version_by_epoch", {})
                ),
                "last_checkpoint_chain_by_epoch": copy.deepcopy(
                    state.get("last_checkpoint_chain_by_epoch", {})
                ),
            }
            token_to_record_ids = update_remote_index_state(record)
            posting_rollback_tokens = list(dict.fromkeys(
                token.hex() for token in record.index_tokens
            ))
            phase_ms["posting_update_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0

            phase_started = time.perf_counter()
            signed_ordered_checkpoint = build_signed_ordered_checkpoint(
                epoch=record.epoch,
                token_to_record_ids=token_to_record_ids,
            )
            phase_ms["checkpoint_root_chain_sign_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0
            # The ordered checkpoint is the single protocol checkpoint used by
            # both archival binding and remote proof generation.
            state["last_checkpoint"] = signed_ordered_checkpoint

            _log_ingest_progress(
                segment,
                f"[OK] record rid={record.rid.hex()[:32]}... "
                f"epoch={record.epoch} "
                f"ordered_checkpoint={signed_ordered_checkpoint['root_hex'][:32]}...",
            )

            phase_started = time.perf_counter()
            cloud_payload = build_remote_cloud_payload(
                record=record,
                signed_checkpoint=signed_ordered_checkpoint,
            )
            phase_ms["gateway_cloud_payload_build_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0
            cloud_upload_result = (
                {
                    "ok": True,
                    "queued": True,
                    "rid": record.rid.hex(),
                }
                if normalized_cloud_url
                else {
                    "ok": True,
                    "skipped": True,
                    "reason": "cloud_url not configured",
                }
            )

            response_obj = {
                "ok": True,
                "mode": "live-and-archive" if live_mode else "archive",
                "live": live_mode,
                "session_id": live_session_id,
                "rid": record.rid.hex(),
                "epoch": record.epoch,
                "index_token_count": len(record.index_tokens),
                "binding_hash": record.binding_hash.hex(),
                "checkpoint_root": signed_ordered_checkpoint["root_hex"],
                "ordered_checkpoint_root": signed_ordered_checkpoint["root_hex"],
                "ordered_checkpoint_version": signed_ordered_checkpoint["version"],
                "record_count": state["record_count"],
                "cloud_upload": cloud_upload_result,
                "live_cloud_upload": live_upload_result,
                "recovered_incomplete_ack": recovered_incomplete_ack,
            }
            state["accepted_segments"][segment_key] = response_obj
            catalog_entry = {
                "rid": record.rid.hex(),
                "cid": segment.cid,
                "sid": segment.sid,
                "seq": int(segment.seq),
                "timestamp": int(segment.timestamp),
                "epoch": int(record.epoch),
                "tokens": [token.hex() for token in record.index_tokens],
            }
            state.setdefault("record_catalog", {})[
                record.rid.hex()
            ] = catalog_entry

            if normalized_cloud_url:
                pending_upload = {
                    "rid": record.rid.hex(),
                    "segment_key": segment_key,
                    "payload": cloud_payload,
                    "created_at": time.time(),
                    "attempts": 0,
                    "last_error": "",
                }
                state.setdefault("pending_cloud_uploads", {})[
                    record.rid.hex()
                ] = pending_upload
                durability_event = {
                    "type": "ingest-commit-v1",
                    "camera_id": segment.cid,
                    "expected_seq": int(registry_entry.expected_seq),
                    "last_gamma_hex": registry_entry.last_gamma.hex(),
                    "record_count": int(state["record_count"]),
                    "segment_key": segment_key,
                    "response": response_obj,
                    "catalog": catalog_entry,
                    "posting_updates": cloud_payload["posting_updates"],
                    "signed_checkpoint": signed_ordered_checkpoint,
                    "pending_upload": pending_upload,
                }
                phase_started = time.perf_counter()
                if durable_store is not None:
                    durable_ticket = durable_store.submit_ingest(
                        durability_event
                    )
                    g.camshield_gateway_durable_ticket = durable_ticket
                    g.camshield_gateway_durable_rid = record.rid.hex()
                else:
                    append_gateway_journal_event(
                        durability_event,
                        gateway_state_path,
                        timings=phase_ms,
                    )
                state["_pending_cloud_payload_count"] = int(
                    state.get("_pending_cloud_payload_count", 0)
                ) + 1
                state["_pending_cloud_payload_bytes"] = int(
                    state.get("_pending_cloud_payload_bytes", 0)
                ) + int(pending_upload.get("payload_bytes", 0))
                phase_ms["gateway_journal_commit_ms"] = (
                    time.perf_counter() - phase_started
                ) * 1000.0
                if durable_store is None:
                    _queue_cloud_upload(record.rid.hex())
            else:
                phase_started = time.perf_counter()
                save_gateway_state(gateway, state, gateway_state_path)
                phase_ms["gateway_state_persist_ms"] = (
                    time.perf_counter() - phase_started
                ) * 1000.0

            if len(state["accepted_segments"]) > 10000:
                oldest_keys = list(state["accepted_segments"].keys())[:-5000]
                for old_key in oldest_keys:
                    state["accepted_segments"].pop(old_key, None)
            if len(state["record_catalog"]) > 10000:
                oldest_rids = list(state["record_catalog"].keys())[:-5000]
                for old_rid in oldest_rids:
                    state["record_catalog"].pop(old_rid, None)
            phase_ms["ingest_total_ms"] = (
                time.perf_counter() - request_started
            ) * 1000.0
            phase_ms["ingest_lock_hold_ms"] = (
                time.perf_counter() - lock_acquired
            ) * 1000.0
            phase_ms["gateway_protocol_and_durable_commit_ms"] = max(
                0.0,
                phase_ms["ingest_total_ms"]
                - phase_ms["request_body_receive_ms"]
                - phase_ms["request_json_loads_ms"]
                - phase_ms["request_segment_decode_ms"]
                - phase_ms["lock_wait_ms"],
            )
            if durable_store is not None and normalized_cloud_url:
                # The shared transaction wait happens after releasing the
                # strict checkpoint lock. The outer handler records the final
                # terminal-ACK timing only after that transaction commits.
                g.camshield_gateway_pending_phase_ms = phase_ms
            else:
                _record_ingest_phase_samples(phase_ms)
            g.camshield_ingest_transport_timing.update(phase_ms)
            return jsonify(response_obj)

        except Exception as exc:
            traceback.print_exc()
            if processed_record is not None and posting_rollback_tokens:
                epoch_map = state.setdefault("token_to_record_ids_by_epoch", {}).get(
                    str(processed_record.epoch), {}
                )
                for token_hex in posting_rollback_tokens:
                    posting = epoch_map.get(token_hex)
                    if isinstance(posting, set):
                        posting.discard(processed_record.rid.hex())
                        if not posting:
                            epoch_map.pop(token_hex, None)
                    elif isinstance(posting, list):
                        remaining = [
                            rid for rid in posting
                            if rid != processed_record.rid.hex()
                        ]
                        if remaining:
                            epoch_map[token_hex] = remaining
                        else:
                            epoch_map.pop(token_hex, None)
                state["token_to_record_ids"] = epoch_map
                rebuild_ordered_checkpoint_caches(state)
            if checkpoint_state_before is not None:
                state.update(checkpoint_state_before)
            if processed_record is not None and record_count_incremented:
                state["record_count"] = max(0, int(state["record_count"]) - 1)
            if registry_before is not None:
                entry, old_gamma, old_expected_seq = registry_before
                entry.last_gamma = old_gamma
                entry.expected_seq = old_expected_seq
            try:
                save_gateway_state(gateway, state, gateway_state_path)
            except Exception:
                pass
            phase_ms["failed_ingest_total_ms"] = (
                time.perf_counter() - request_started
            ) * 1000.0
            phase_ms["failed_ingest_lock_hold_ms"] = (
                time.perf_counter() - lock_acquired
            ) * 1000.0
            phase_ms["gateway_protocol_and_durable_commit_ms"] = max(
                0.0,
                phase_ms["failed_ingest_total_ms"]
                - phase_ms["request_body_receive_ms"]
                - phase_ms["request_json_loads_ms"]
                - phase_ms["request_segment_decode_ms"]
                - phase_ms["lock_wait_ms"],
            )
            _record_ingest_phase_samples(phase_ms)
            g.camshield_ingest_transport_timing.update(phase_ms)
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

    @app.post("/live/fast-path/stop")
    def live_fast_path_stop():
        """End a temporary live bridge without touching archival state."""
        data = request.get_json(force=True, silent=True) or {}
        session_id = str(data.get("session_id", "")).strip()
        if not session_id:
            return jsonify({
                "ok": False,
                "error": "session_id is required",
            }), 400

        with ingest_lock:
            sessions = state.setdefault("live_fast_path_sessions", {})
            session = sessions.get(session_id)
            if not isinstance(session, dict):
                return jsonify({
                    "ok": False,
                    "error": "unknown live fast-path session",
                    "session_id": session_id,
                }), 404

            camera_id = str(session.get("camera_id", ""))
            session["status"] = "stopped"
            session["stopped_at"] = int(time.time())
            cameras = state.setdefault("live_fast_path_cameras", {})
            if cameras.get(camera_id) == session_id:
                cameras.pop(camera_id, None)

        return jsonify({
            "ok": True,
            "session_id": session_id,
            "camera_id": camera_id,
            "status": "stopped",
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
            attrs = profile_abe_attrs(client_id, camera_id)

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
        Credential setup: Cred_u = (SK_u, Cap_u).

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
        with ingest_lock:
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
    print(f"[Gateway] ABE backend: {app.config['ABE_BACKEND_NAME']}")
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
