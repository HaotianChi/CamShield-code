"""Remote Cloud HTTP service."""

from __future__ import annotations
from flask import request

import argparse
import json
import urllib.request
import urllib.error
import os
from pathlib import Path
import threading
import time
from typing import Any

from flask import Flask, jsonify, request

from core.ordered_merkle import (
    build_ordered_merkle_root,
    build_ordered_merkle_snapshot,
    make_real_token_id,
    posting_digest_hex,
)
from core.cloud_sqlite import CloudSQLiteStore, SQLiteRecordMapping


def _ordered_leaf_checkpoint_version(checkpoint: dict[str, Any] | None) -> int | None:
    """Return the committed version only for protocol-aligned v2 leaves."""
    if not checkpoint:
        return None
    if (
        checkpoint.get("type") == "camshield-ordered-checkpoint-v2"
        or checkpoint.get("leaf_format") == "ordered-token-leaf-v2"
    ):
        return int(checkpoint["version"])
    return None


def now_ts() -> int:
    return int(time.time())


class CloudState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        legacy_path = os.environ.get("CAMSHIELD_CLOUD_STATE")
        default_db = (
            str(Path(legacy_path).with_suffix(".sqlite3"))
            if legacy_path
            else ".camshield_cloud.sqlite3"
        )
        self.store = CloudSQLiteStore(
            os.environ.get("CAMSHIELD_CLOUD_DB", default_db)
        )
        self.records = SQLiteRecordMapping(self.store)

                                     
                                                          
        self.token_to_record_ids: dict[str, list[str]] = {}
        self.posting_membership_by_token: dict[str, set[str]] = {}
        self.posting_digest_by_token: dict[str, str] = {}
        self.loaded_posting_epoch: int | None = None

                                                       
                          
                                                                   
        self.latest_checkpoint: dict[str, Any] | None = None

                                                                            
        self.snapshot = None

        # `store_batches` counts HTTP transport requests.  The protocol-level
        # records within those requests are tracked separately because the
        # Gateway may safely coalesce already-signed records for transport.
        self.store_batches = 0
        self.store_payloads = 0

                                        
                                              
                                                                             
                                                                       
        self.live_sessions = self.store.load_live_sessions()

        # camera_id -> latest session_id while live fast path is active on Cloud
        self.live_fast_path_cameras = {
            str(session["camera_id"]): session_id
            for session_id, session in self.live_sessions.items()
        }

        epochs = self.store.list_epochs()
        if epochs:
            latest_epoch = int(epochs[0]["epoch"])
            self.token_to_record_ids = self.store.epoch_postings(latest_epoch)
            self.posting_membership_by_token = {
                token: set(record_ids)
                for token, record_ids in self.token_to_record_ids.items()
            }
            self.posting_digest_by_token = {
                token: posting_digest_hex(record_ids)
                for token, record_ids in self.token_to_record_ids.items()
            }
            self.loaded_posting_epoch = latest_epoch
            self.latest_checkpoint = self.store.checkpoint(latest_epoch)

    def rebuild_snapshot(self) -> None:
        self.snapshot = build_ordered_merkle_snapshot(
            self.token_to_record_ids,
            checkpoint_version=_ordered_leaf_checkpoint_version(
                self.latest_checkpoint
            ),
        )


def create_app() -> Flask:
    app = Flask(__name__)
    state = CloudState()
    root_verify_mode = os.environ.get(
        "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE", "deferred"
    ).strip().lower()
    if root_verify_mode not in {"deferred", "synchronous"}:
        raise ValueError(
            "CAMSHIELD_CLOUD_ROOT_VERIFY_MODE must be deferred or synchronous"
        )

                                                
    app.config["CAMSHIELD_CLOUD_STATE"] = state
    app.config["CAMSHIELD_CLOUD_ROOT_VERIFY_MODE"] = root_verify_mode

    @app.before_request
    def _require_api_token():
        configured = os.environ.get("CAMSHIELD_API_TOKEN", "").strip()
        if not configured or request.path == "/health":
            return None
        supplied = request.headers.get("Authorization", "")
        if supplied != f"Bearer {configured}":
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        return None

    @app.get("/health")
    def health():
        with state.lock:
            return jsonify(
                {
                    "ok": True,
                    "service": "camshield-cloud-server",
                    "pid": os.getpid(),
                    "record_count": len(state.records),
                    "live_record_count": state.store.live_record_count(),
                    "token_count": len(state.token_to_record_ids),
                    "has_checkpoint": state.latest_checkpoint is not None,
                    "checkpoint_type": (
                        state.latest_checkpoint.get("type")
                        if state.latest_checkpoint
                        else None
                    ),
                    "leaf_format": (
                        state.latest_checkpoint.get("leaf_format")
                        if state.latest_checkpoint
                        else None
                    ),
                    "root_verify_mode": root_verify_mode,
                    "store_batches": state.store_batches,
                    "store_payloads": state.store_payloads,
                    "database_path": str(state.store.path),
                    "database_bytes": (
                        state.store.path.stat().st_size
                        if state.store.path.exists()
                        else 0
                    ),
                }
            )

    @app.get("/epochs")
    def epochs():
        with state.lock:
            return jsonify({
                "ok": True,
                "epochs": state.store.list_epochs(),
                "retention_days": int(
                    os.environ.get("CAMSHIELD_CLOUD_RETENTION_DAYS", "2")
                ),
            })

    @app.get("/records/range")
    def records_range():
        camera_id = str(request.args.get("camera_id", "cam01")).strip()
        try:
            start_ts = int(request.args["start"])
            end_ts = int(request.args["end"])
            limit = min(1000, int(request.args.get("limit", "300")))
        except Exception:
            return jsonify({
                "ok": False,
                "error": "start, end and limit must be integers",
            }), 400
        with state.lock:
            records = state.store.records_in_range(
                camera_id=camera_id,
                start_ts=start_ts,
                end_ts=end_ts,
                limit=limit,
            )
        return jsonify({
            "ok": True,
            "mode": "direct-replay",
            "camera_id": camera_id,
            "start": start_ts,
            "end": end_ts,
            "record_ids": [rid for rid, _ in records],
            "records": [{"rid": rid, "record": record} for rid, record in records],
            "retrieval_proof_required": False,
        })

    @app.get("/admin/retention/status")
    def retention_status():
        with state.lock:
            status = state.store.retention_status()
        status.update({
            "ok": True,
            "retention_days": int(
                os.environ.get("CAMSHIELD_CLOUD_RETENTION_DAYS", "2")
            ),
        })
        return jsonify(status)

    @app.post("/admin/retention/run")
    def retention_run():
        obj = request.get_json(force=True, silent=True) or {}
        configured_days = float(
            obj.get(
                "days",
                os.environ.get("CAMSHIELD_CLOUD_RETENTION_DAYS", "2"),
            )
        )
        requested_cutoff = obj.get("cutoff")
        cutoff = (
            int(requested_cutoff)
            if requested_cutoff is not None
            else int(time.time() - max(0.0, configured_days) * 86400)
        )
        with state.lock:
            epochs_available = state.store.list_epochs()
            keep_epoch = (
                max(int(item["epoch"]) for item in epochs_available)
                if epochs_available
                else None
            )
            result = state.store.expire_before(
                cutoff,
                reason=str(obj.get("reason", "retention")),
                keep_epoch=keep_epoch,
            )
        return jsonify({
            "ok": True,
            "retention_days": configured_days,
            "cutoff_source": "explicit" if requested_cutoff is not None else "days",
            **result,
        })

    @app.post("/admin/retention/reap")
    def retention_reap():
        """Physically reclaim a small retired-data batch without long lock holds."""
        obj = request.get_json(force=True, silent=True) or {}
        try:
            record_limit = min(512, max(1, int(obj.get("record_limit", 128))))
            posting_limit = min(4096, max(1, int(obj.get("posting_limit", 1024))))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "invalid reclaim limits"}), 400
        with state.lock:
            result = state.store.reap_expired_batches(
                record_limit=record_limit,
                posting_limit=posting_limit,
            )
        return jsonify(result)

    def _store_payload_locked(
        obj: dict[str, Any], *, commit: bool
    ) -> tuple[dict[str, Any], int]:
        """Apply one exact Gateway payload while ``state.lock`` is held.

        A transport batch is deliberately only a container around original
        protocol payloads.  Each nested payload retains its own record, ΔPL,
        and signed checkpoint, so batching changes neither the evidence
        construction nor checkpoint/record-binding semantics.
        """
        records = obj.get("records", [])
        token_to_record_ids = obj.get("token_to_record_ids")
        posting_updates = obj.get("posting_updates", [])
        signed_checkpoint = obj.get("signed_checkpoint")

        if signed_checkpoint is None:
            return {"ok": False, "error": "missing signed_checkpoint"}, 400

        if not isinstance(records, list):
            return {"ok": False, "error": "records must be a list"}, 400

        try:
            epoch = int(obj.get("epoch", signed_checkpoint.get("epoch", 0)))
            checkpoint_epoch = int(signed_checkpoint.get("epoch", 0))
            checkpoint_version = int(signed_checkpoint.get("version", 0))
        except (TypeError, ValueError):
            return {"ok": False, "error": "invalid checkpoint epoch or version"}, 400
        if checkpoint_epoch != epoch:
            return {
                "ok": False,
                "error": "checkpoint epoch does not match payload epoch",
            }, 400
        if token_to_record_ids is not None and not isinstance(token_to_record_ids, dict):
            return {"ok": False, "error": "token_to_record_ids must be a dict"}, 400
        if not isinstance(posting_updates, list):
            return {"ok": False, "error": "posting_updates must be a list"}, 400

        request_started = time.perf_counter()
        server_timing_ms: dict[str, float] = {}
        existing_checkpoint = state.store.checkpoint(epoch)
        if (
            existing_checkpoint is not None
            and checkpoint_version == int(existing_checkpoint.get("version", 0))
            and str(signed_checkpoint.get("root_hex", ""))
            != str(existing_checkpoint.get("root_hex", ""))
        ):
            return {
                "ok": False,
                "error": "checkpoint version conflict",
                "epoch": epoch,
                "version": checkpoint_version,
            }, 409

        phase_started = time.perf_counter()
        stored = 0
        try:
            for item in records:
                rid = str(item["rid"])
                rec = item["record"]
                state.store.put_record(rid, rec)
                stored += 1
        except (KeyError, TypeError, ValueError) as exc:
            return {"ok": False, "error": f"invalid record payload: {exc}"}, 400
        server_timing_ms["record_store_ms"] = (
            time.perf_counter() - phase_started
        ) * 1000.0

        phase_started = time.perf_counter()
        if token_to_record_ids is not None:
            normalized_index: dict[str, list[str]] = {}
            for token_hex, rid_list in token_to_record_ids.items():
                normalized_index[str(token_hex)] = sorted(str(x) for x in rid_list)
            state.store.replace_epoch_postings(epoch, normalized_index)
            state.token_to_record_ids = normalized_index
            state.posting_membership_by_token = {
                token: set(record_ids) for token, record_ids in normalized_index.items()
            }
            state.posting_digest_by_token = {
                token: posting_digest_hex(record_ids)
                for token, record_ids in normalized_index.items()
            }
            state.loaded_posting_epoch = epoch
        else:
            state.store.apply_posting_updates(epoch, posting_updates)
        server_timing_ms["posting_update_ms"] = (
            time.perf_counter() - phase_started
        ) * 1000.0

        phase_started = time.perf_counter()
        # Mirror delta posting-list updates in memory instead of reloading the
        # complete epoch posting state from SQLite after every segment.
        if token_to_record_ids is None:
            if state.loaded_posting_epoch != epoch:
                state.token_to_record_ids = state.store.epoch_postings(epoch)
                state.posting_membership_by_token = {
                    token: set(record_ids)
                    for token, record_ids in state.token_to_record_ids.items()
                }
                state.posting_digest_by_token = {
                    token: posting_digest_hex(record_ids)
                    for token, record_ids in state.token_to_record_ids.items()
                }
                state.loaded_posting_epoch = epoch
            for update in posting_updates:
                token = str(update["token"])
                rid = str(update["rid"])
                posting = state.token_to_record_ids.setdefault(token, [])
                membership = state.posting_membership_by_token.get(token)
                if membership is None:
                    membership = set(posting)
                    state.posting_membership_by_token[token] = membership
                if rid not in membership:
                    posting.append(rid)
                    membership.add(rid)
                if root_verify_mode == "synchronous":
                    state.posting_digest_by_token[token] = posting_digest_hex(posting)
        server_timing_ms["posting_state_sync_ms"] = (
            time.perf_counter() - phase_started
        ) * 1000.0

        uploaded_root = str(signed_checkpoint.get("root_hex", ""))
        if not uploaded_root:
            return {"ok": False, "error": "missing checkpoint root"}, 400

        # The full equality check remains mandatory at query time in deferred
        # mode; synchronous mode is retained for diagnostics.
        checkpoint_root_verification = "deferred-to-query"
        if root_verify_mode == "synchronous":
            phase_started = time.perf_counter()
            computed_root = build_ordered_merkle_root(
                state.token_to_record_ids,
                posting_digest_by_token=state.posting_digest_by_token,
                checkpoint_version=_ordered_leaf_checkpoint_version(signed_checkpoint),
            )
            server_timing_ms["checkpoint_root_verify_ms"] = (
                time.perf_counter() - phase_started
            ) * 1000.0
            checkpoint_root_verification = "synchronous"
            if computed_root != uploaded_root:
                return {
                    "ok": False,
                    "error": "checkpoint root mismatch",
                    "computed_root": computed_root,
                    "uploaded_root": uploaded_root,
                }, 400

        phase_started = time.perf_counter()
        checkpoint_advanced = state.store.save_checkpoint_if_newer(
            dict(signed_checkpoint)
        )
        effective_checkpoint = state.store.checkpoint(epoch)
        if effective_checkpoint is None:
            return {"ok": False, "error": "checkpoint persistence failed"}, 500
        current_latest = state.latest_checkpoint
        candidate_key = (
            int(effective_checkpoint.get("epoch", 0)),
            int(effective_checkpoint.get("version", 0)),
        )
        latest_key = (
            int(current_latest.get("epoch", 0)),
            int(current_latest.get("version", 0)),
        ) if isinstance(current_latest, dict) else (-1, -1)
        if candidate_key >= latest_key:
            state.latest_checkpoint = dict(effective_checkpoint)
        if commit:
            state.store.conn.commit()
        server_timing_ms["checkpoint_commit_ms"] = (
            time.perf_counter() - phase_started
        ) * 1000.0
        state.snapshot = None
        server_timing_ms["total_ms"] = (
            time.perf_counter() - request_started
        ) * 1000.0
        return {
            "ok": True,
            "stored_records": stored,
            "record_count": len(state.records),
            "token_count": len(state.token_to_record_ids),
            "checkpoint_root": effective_checkpoint.get("root_hex"),
            "checkpoint_version": effective_checkpoint.get("version"),
            "checkpoint_advanced": checkpoint_advanced,
            "uploaded_checkpoint_root": uploaded_root,
            "uploaded_checkpoint_version": checkpoint_version,
            "epoch": epoch,
            "checkpoint_root_verification": checkpoint_root_verification,
            "server_timing_ms": server_timing_ms,
        }, 200

    def _reload_posting_cache_after_rollback() -> None:
        epochs = state.store.list_epochs()
        if not epochs:
            state.token_to_record_ids = {}
            state.posting_membership_by_token = {}
            state.posting_digest_by_token = {}
            state.loaded_posting_epoch = None
            state.latest_checkpoint = None
            state.snapshot = None
            return
        epoch = int(epochs[0]["epoch"])
        state.token_to_record_ids = state.store.epoch_postings(epoch)
        state.posting_membership_by_token = {
            token: set(record_ids)
            for token, record_ids in state.token_to_record_ids.items()
        }
        state.posting_digest_by_token = {
            token: posting_digest_hex(record_ids)
            for token, record_ids in state.token_to_record_ids.items()
        }
        state.loaded_posting_epoch = epoch
        state.latest_checkpoint = state.store.checkpoint(epoch)
        state.snapshot = None

    @app.post("/store-batch")
    def store_batch():
        """Store one original protocol payload (legacy-compatible endpoint)."""
        obj = request.get_json(force=True)
        if not isinstance(obj, dict):
            return jsonify({"ok": False, "error": "JSON object required"}), 400
        with state.lock:
            try:
                result, status = _store_payload_locked(obj, commit=True)
            except Exception as exc:
                state.store.conn.rollback()
                _reload_posting_cache_after_rollback()
                return jsonify({
                    "ok": False,
                    "error": "store payload failed",
                    "reason": repr(exc),
                }), 500
            if status != 200:
                state.store.conn.rollback()
                _reload_posting_cache_after_rollback()
                return jsonify(result), status
            state.store_batches += 1
            state.store_payloads += 1
            return jsonify(result), status

    @app.post("/store-batch-many")
    def store_batch_many():
        """Atomically persist multiple original Gateway protocol payloads.

        This is a transport and SQLite-transaction optimization only.  It does
        not create a compound CamShield record or a compound checkpoint.
        """
        obj = request.get_json(force=True)
        batches = obj.get("batches") if isinstance(obj, dict) else None
        max_payloads = max(
            1, min(64, int(os.environ.get("CAMSHIELD_CLOUD_BATCH_MAX_PAYLOADS", "32")))
        )
        if not isinstance(batches, list) or not batches:
            return jsonify({"ok": False, "error": "batches must be a non-empty list"}), 400
        if len(batches) > max_payloads:
            return jsonify({
                "ok": False,
                "error": "too many protocol payloads in one transport batch",
                "max_payloads": max_payloads,
            }), 400
        if not all(isinstance(item, dict) for item in batches):
            return jsonify({"ok": False, "error": "every batch item must be an object"}), 400

        with state.lock:
            started = time.perf_counter()
            results: list[dict[str, Any]] = []
            try:
                for index, payload in enumerate(batches):
                    result, status = _store_payload_locked(payload, commit=False)
                    if status != 200:
                        state.store.conn.rollback()
                        _reload_posting_cache_after_rollback()
                        return jsonify({
                            "ok": False,
                            "error": "transport batch rolled back",
                            "failed_index": index,
                            "payload_error": result,
                        }), status
                    results.append(result)
                state.store.conn.commit()
            except Exception as exc:
                state.store.conn.rollback()
                _reload_posting_cache_after_rollback()
                return jsonify({
                    "ok": False,
                    "error": "transport batch failed and rolled back",
                    "reason": repr(exc),
                }), 500
            state.snapshot = None
            state.store_batches += 1
            state.store_payloads += len(results)
            final = results[-1]
            aggregate_timing: dict[str, float] = {}
            for result in results:
                for name, value in result.get("server_timing_ms", {}).items():
                    aggregate_timing[name] = aggregate_timing.get(name, 0.0) + float(value)
            aggregate_timing["transport_batch_total_ms"] = (
                time.perf_counter() - started
            ) * 1000.0
            return jsonify({
                "ok": True,
                "transport": "store-batch-many-v1",
                "transport_batch_payloads": len(results),
                "stored_records": sum(int(item["stored_records"]) for item in results),
                "record_count": len(state.records),
                "token_count": len(state.token_to_record_ids),
                "checkpoint_root": final["checkpoint_root"],
                "checkpoint_version": final["checkpoint_version"],
                "checkpoint_advanced_count": sum(
                    1 for item in results if item["checkpoint_advanced"]
                ),
                "checkpoint_root_verification": final[
                    "checkpoint_root_verification"
                ],
                "server_timing_ms": aggregate_timing,
            })

    @app.post("/store-live")
    def store_live():
        """
        Gateway uploads live encrypted records (LER) during an active fast path.

        Live records skip inverted-index and checkpoint updates on Cloud.
        """
        obj = request.get_json(force=True)

        records = obj.get("records", [])
        camera_id = str(obj.get("camera_id", obj.get("cid", ""))).strip()
        session_id = str(obj.get("session_id", "")).strip()

        if not camera_id:
            return jsonify({"ok": False, "error": "camera_id is required"}), 400

        if not isinstance(records, list) or len(records) == 0:
            return jsonify({"ok": False, "error": "records must be a non-empty list"}), 400

        with state.lock:
            active_session = state.live_fast_path_cameras.get(camera_id)
            if active_session is None:
                return jsonify({
                    "ok": False,
                    "error": "live fast path is not active for camera",
                    "camera_id": camera_id,
                }), 403

            if session_id and session_id != active_session:
                return jsonify({
                    "ok": False,
                    "error": "session_id does not match active live fast path",
                    "camera_id": camera_id,
                    "active_session_id": active_session,
                    "session_id": session_id,
                }), 403

            stored = 0
            for item in records:
                rid = str(item["rid"])
                rec = item["record"]
                state.store.put_live_record(active_session, rid, rec)
                stored += 1
            state.store.conn.commit()

            return jsonify({
                "ok": True,
                "mode": "live-fast-path",
                "stored_records": stored,
                "record_count": len(state.records),
                "camera_id": camera_id,
                "session_id": active_session,
            })

    @app.get("/checkpoint/latest")
    def checkpoint_latest():
        with state.lock:
            epoch_raw = request.args.get("epoch")
            if epoch_raw is not None and state.store.is_expired(int(epoch_raw)):
                return jsonify({
                    "ok": False,
                    "error": "epoch expired by retention policy",
                    "epoch": int(epoch_raw),
                }), 410
            checkpoint = (
                state.store.checkpoint(int(epoch_raw))
                if epoch_raw is not None
                else state.latest_checkpoint
            )
            if checkpoint is None:
                return jsonify({"ok": False, "error": "no checkpoint"}), 404

            return jsonify(
                {
                    "ok": True,
                    "signed_checkpoint": checkpoint,
                }
            )

    @app.post("/admin/checkpoint/verify")
    def verify_checkpoint():
        """Verify one persisted epoch against its Gateway-signed root.

        This is intentionally a read-only, epoch-boundary audit.  Deferred
        mode still avoids an O(|PL|) reconstruction on every upload, while a
        closed epoch cannot be reported as valid or retired until the exact
        protocol leaf/root construction agrees with its signed checkpoint.
        """
        obj = request.get_json(force=True, silent=True) or {}
        try:
            epoch = int(obj["epoch"])
        except (KeyError, TypeError, ValueError):
            return jsonify({"ok": False, "error": "epoch is required"}), 400

        with state.lock:
            if state.store.is_expired(epoch):
                return jsonify({
                    "ok": False,
                    "error": "epoch expired by retention policy",
                    "epoch": epoch,
                }), 410
            checkpoint = state.store.checkpoint(epoch)
            if checkpoint is None:
                return jsonify({"ok": False, "error": "no checkpoint", "epoch": epoch}), 404
            postings = state.store.epoch_postings(epoch)
            computed_root = build_ordered_merkle_root(
                postings,
                checkpoint_version=_ordered_leaf_checkpoint_version(checkpoint),
            )
            signed_root = str(checkpoint.get("root_hex", ""))
            result = {
                "ok": computed_root == signed_root,
                "epoch": epoch,
                "checkpoint_version": int(checkpoint.get("version", 0)),
                "signed_root": signed_root,
                "computed_root": computed_root,
                "posting_token_count": len(postings),
                "verification_stage": "epoch-boundary",
            }
            if not result["ok"]:
                result["error"] = "stored posting state does not match signed checkpoint"
                return jsonify(result), 409
            return jsonify(result)

    @app.get("/record/<rid>")
    def get_record(rid: str):
        with state.lock:
            epoch = state.store.record_epoch(rid)
            if epoch is not None and state.store.is_expired(epoch):
                return jsonify({
                    "ok": False,
                    "error": "epoch expired by retention policy",
                    "epoch": epoch,
                }), 410
            rec = state.records.get(rid)
            if rec is None:
                return jsonify({"ok": False, "error": "record not found", "rid": rid}), 404

            return jsonify(
                {
                    "ok": True,
                    "rid": rid,
                    "record": rec,
                }
            )

    @app.post("/search")
    def search():
        """
        Search by encrypted token IDs.

        Expected JSON:
        {
          "query_token_ids": ["<token hex>", "..."],
          "operator": "AND" or "OR"
        }

        Response includes:
          - result_record_ids
          - membership_proofs
          - non_membership_proofs
          - verified posting lists from current Cloud snapshot
          - signed checkpoint
        """
        obj = request.get_json(force=True)

        query_token_ids = obj.get("query_token_ids", [])
        operator = str(obj.get("operator", "AND")).upper()
        epoch_raw = obj.get("epoch")

        if operator not in ("AND", "OR"):
            return jsonify({"ok": False, "error": "operator must be AND or OR"}), 400

        if not isinstance(query_token_ids, list):
            return jsonify({"ok": False, "error": "query_token_ids must be a list"}), 400
        if epoch_raw is None:
            return jsonify({"ok": False, "error": "epoch is required"}), 400
        epoch = int(epoch_raw)

        with state.lock:
            if state.store.is_expired(epoch):
                return jsonify({
                    "ok": False,
                    "error": "epoch expired by retention policy",
                    "epoch": epoch,
                }), 410
            signed_checkpoint = state.store.checkpoint(epoch)
            token_to_record_ids = state.store.epoch_postings(epoch)
            if signed_checkpoint is None:
                return jsonify({"ok": False, "error": "no checkpoint", "epoch": epoch}), 404
            snapshot = build_ordered_merkle_snapshot(
                token_to_record_ids,
                checkpoint_version=_ordered_leaf_checkpoint_version(
                    signed_checkpoint
                ),
            )
            committed_root = str(signed_checkpoint.get("root_hex", ""))
            if snapshot.root_hex != committed_root:
                return jsonify({
                    "ok": False,
                    "error": "stored posting state does not match signed checkpoint",
                    "epoch": epoch,
                    "computed_root": snapshot.root_hex,
                    "signed_root": committed_root,
                    "verification_stage": "query",
                }), 409

            membership_proofs: dict[str, Any] = {}
            non_membership_proofs: dict[str, Any] = {}
            postings: dict[str, list[str]] = {}

            posting_sets: list[set[str]] = []

            for raw_query_token in query_token_ids:
                raw_query_token = str(raw_query_token)
                token_id = make_real_token_id(raw_query_token)

                                                                      
                raw_token_hex = raw_query_token[2:] if raw_query_token.startswith("1:") else raw_query_token

                if token_id in snapshot.leaves and raw_token_hex in token_to_record_ids:
                    rid_list = sorted(token_to_record_ids.get(raw_token_hex, []))
                    postings[raw_query_token] = rid_list

                    proof = snapshot.membership_proof(token_id)
                    membership_proofs[raw_query_token] = proof.to_dict()

                    posting_sets.append(set(rid_list))

                else:
                    postings[raw_query_token] = []

                    proof = snapshot.non_membership_proof(token_id)
                    non_membership_proofs[raw_query_token] = proof.to_dict()

                    posting_sets.append(set())

            if not posting_sets:
                result = set()
            elif operator == "AND":
                result = set.intersection(*posting_sets)
            else:
                result = set.union(*posting_sets)

            result_record_ids = sorted(result)

            return jsonify(
                {
                    "ok": True,
                    "operator": operator,
                    "query_token_ids": query_token_ids,
                    "result_record_ids": result_record_ids,
                    "postings": postings,
                    "membership_proofs": membership_proofs,
                    "non_membership_proofs": non_membership_proofs,
                    "signed_checkpoint": signed_checkpoint,
                    "checkpoint_root_hex": signed_checkpoint.get("root_hex"),
                    "epoch": epoch,
                    "record_count": len(state.records),
                    "token_count": len(token_to_record_ids),
                }
            )

                                                                        
                                    
                            
     
                   
                                             
                               
                                                         
                                                                            
                                                             
                                                                        

    def _post_json_stdlib(url: str, payload: dict, timeout: int = 10) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                return resp.status, json.loads(body)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            try:
                obj = json.loads(body)
            except Exception:
                obj = {"ok": False, "raw_text": body}
            return e.code, obj
        except urllib.error.URLError as e:
            return 599, {
                "ok": False,
                "error": "gateway notification network error",
                "reason": str(e),
            }
        except Exception as e:
            return 598, {
                "ok": False,
                "error": "gateway notification exception",
                "reason": repr(e),
            }

    def _latest_record_for_camera_locked(camera_id: str, epoch: int | None = None):
        return state.store.latest_record(camera_id, epoch)

    @app.post("/live/start")
    def live_start():
        obj = request.get_json(force=True, silent=True) or {}

        client_id = str(obj.get("client_id", "owner"))
        camera_id = str(obj.get("camera_id", obj.get("cid", "cam01"))).strip()
        epoch_raw = obj.get("epoch", None)
        epoch = int(epoch_raw) if epoch_raw is not None else None

        client_coordinated = bool(obj.get("client_coordinated", False))
        gateway_url = str(obj.get("gateway_url", obj.get("gateway", ""))).rstrip("/")
        if not gateway_url and not client_coordinated:
            return jsonify({
                "ok": False,
                "error": "gateway_url is required unless client_coordinated is enabled",
            }), 400

        if not camera_id:
            return jsonify({
                "ok": False,
                "error": "camera_id is required",
            }), 400

        session_id = f"live-{camera_id}-{int(time.time() * 1000)}-{os.getpid()}"

        notify_payload = {
            "session_id": session_id,
            "client_id": client_id,
            "camera_id": camera_id,
            "epoch": epoch,
            "cloud_url": request.host_url.rstrip("/"),
            "mode": "live-fast-path",
            "fast_path_ready": True,
            "vp_verification_default": False,
            "basic_verification_only": True,
        }

        if client_coordinated:
            status, gw_resp = 200, {
                "ok": True,
                "deferred_to_client": True,
            }
        else:
            status, gw_resp = _post_json_stdlib(
                gateway_url + "/live/fast-path/start",
                notify_payload,
                timeout=10,
            )

            if status != 200 or not gw_resp.get("ok"):
                return jsonify({
                    "ok": False,
                    "error": "gateway live fast path notification failed",
                    "gateway_url": gateway_url,
                    "gateway_status": status,
                    "gateway_response": gw_resp,
                }), 502

        with state.lock:
            rid, rec = _latest_record_for_camera_locked(camera_id, epoch=epoch)
            start_after_seq = _record_sequence(rec) if rec is not None else -1
            state.live_sessions[session_id] = {
                "session_id": session_id,
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": epoch,
                "gateway_url": gateway_url,
                "created_at": int(time.time()),
                "mode": "live-fast-path",
                "fast_path_ready": not client_coordinated,
                "client_coordinated": client_coordinated,
                "vp_verification_default": False,
                "basic_verification_only": True,
                "latest_rid_at_start": rid,
                "start_after_seq": start_after_seq,
            }
            state.live_fast_path_cameras[camera_id] = session_id
            state.store.save_live_session(state.live_sessions[session_id])

        return jsonify({
            "ok": True,
            "session_id": session_id,
            "client_id": client_id,
            "camera_id": camera_id,
            "epoch": epoch,
            "mode": "live-fast-path",
            "fast_path_ready": not client_coordinated,
            "client_coordinated": client_coordinated,
            "vp_verification_default": False,
            "basic_verification_only": True,
            "gateway_notified": not client_coordinated,
            "gateway_response": gw_resp,
            "rid": rid,
            "start_after_seq": start_after_seq,
            "has_record": rid is not None,
        })


                                     
                                                 
     
                                                                               
                                                                         
     
                                
                                                                           
                                          

    def _deep_find_values(obj: Any, names: set[str], depth: int = 0):
        if depth > 8:
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k) in names:
                    yield v
                if isinstance(v, (dict, list)):
                    yield from _deep_find_values(v, names, depth + 1)

        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    yield from _deep_find_values(item, names, depth + 1)


    def _to_int(v: Any) -> int | None:
        try:
            if v is None:
                return None
            return int(v)
        except Exception:
            return None


    def _record_sequence(rec: dict[str, Any]) -> int | None:
        if not isinstance(rec, dict):
            return None

        seq_names = {
            "seq",
            "sequence",
            "segment_seq",
            "segment_index",
            "segment_no",
            "segment_number",
            "sid_seq",
        }

        for v in _deep_find_values(rec, seq_names):
            x = _to_int(v)
            if x is not None:
                return x

        sid_names = {
            "sid",
            "segment_id",
            "segment_descriptor_id",
            "segmentId",
        }

        for sid in _deep_find_values(rec, sid_names):
            sid = str(sid)
            if "-seg-" in sid:
                tail = sid.rsplit("-seg-", 1)[1]
                try:
                    return int(tail)
                except Exception:
                    pass

                                       
            digits = ""
            for ch in reversed(sid):
                if ch.isdigit():
                    digits = ch + digits
                elif digits:
                    break

            if digits:
                try:
                    return int(digits)
                except Exception:
                    pass

        return None


    def _record_rid(rec: dict[str, Any], default: Any = None) -> str | None:
        if isinstance(rec, dict):
            for k in ("rid", "record_id", "id"):
                v = rec.get(k)
                if v:
                    return str(v)

            for v in _deep_find_values(rec, {"rid", "record_id", "id"}):
                if v:
                    return str(v)

        return str(default) if default is not None else None


    def _iter_records_locked():
        """
        Directly scan state.records.

        Expected common formats:
          state.records[rid] = record
          state.records[rid] = {"record": record, ...}
        """
        records = getattr(state, "records", None)

        if hasattr(records, "items"):
            for k, v in records.items():
                if isinstance(v, dict) and isinstance(v.get("record"), dict):
                    rec = v["record"]
                    rid = _record_rid(rec, v.get("rid", k))
                    yield rid, rec
                elif isinstance(v, dict):
                    rec = v
                    rid = _record_rid(rec, k)
                    yield rid, rec

        elif isinstance(records, list):
            for item in records:
                if isinstance(item, dict) and isinstance(item.get("record"), dict):
                    rec = item["record"]
                    rid = _record_rid(rec, item.get("rid"))
                    yield rid, rec
                elif isinstance(item, dict):
                    rec = item
                    rid = _record_rid(rec)
                    yield rid, rec


    @app.get("/live/next/<session_id>")
    def live_next(session_id: str):
        after_seq_raw = request.args.get("after_seq", None)

        try:
            after_seq = int(after_seq_raw) if after_seq_raw is not None else -1
        except Exception:
            return jsonify({
                "ok": False,
                "error": "invalid after_seq",
                "after_seq": after_seq_raw,
            }), 400

        with state.lock:
            sess = state.live_sessions.get(session_id)
            if sess is None:
                return jsonify({
                    "ok": False,
                    "error": "unknown live session",
                    "session_id": session_id,
                }), 404

            rid, rec = state.store.next_live_record(session_id, after_seq)
            if rec is None:
                return jsonify({
                    "ok": True,
                    "ready": False,
                    "fast_path_ready": False,
                    "session_id": session_id,
                    "after_seq": after_seq,
                    "mode": "live-fast-path",
                    "message": "no next record yet",
                    "record_count": state.store.live_record_count(),
                }), 202

            seq = _record_sequence(rec)

            return jsonify({
                "ok": True,
                "ready": True,
                "fast_path_ready": True,
                "session_id": session_id,
                "client_id": sess.get("client_id"),
                "camera_id": sess.get("camera_id"),
                "epoch": sess.get("epoch"),
                "mode": "live-fast-path",
                "vp_verification_default": False,
                "basic_verification_only": True,
                "after_seq": after_seq,
                "seq": seq,
                "rid": rid,
                "record": rec,
            })



    @app.get("/live/latest/<session_id>")
    def live_latest(session_id: str):
        with state.lock:
            sess = state.live_sessions.get(session_id)
            if sess is None:
                return jsonify({
                    "ok": False,
                    "error": "unknown live session",
                    "session_id": session_id,
                }), 404

            camera_id = sess["camera_id"]
            epoch = sess.get("epoch")
            rid, rec = state.store.latest_live_record(session_id)

            if rid is None:
                return jsonify({
                    "ok": True,
                    "ready": False,
                    "message": "waiting for first live record",
                    "session_id": session_id,
                    "camera_id": camera_id,
                    "epoch": epoch,
                }), 202

            return jsonify({
                "ok": True,
                "session_id": session_id,
                "client_id": sess["client_id"],
                "camera_id": camera_id,
                "epoch": epoch,
                "mode": "live-fast-path",
                "vp_verification_default": False,
                "basic_verification_only": True,
                "rid": rid,
                "record": rec,
            })

    @app.get("/live/state")
    def live_state():
        with state.lock:
            return jsonify({
                "ok": True,
                "live_session_count": len(state.live_sessions),
                "live_sessions": state.live_sessions,
                "live_fast_path_cameras": dict(state.live_fast_path_cameras),
            })


    @app.get("/debug/state")
    def debug_state():
        with state.lock:
            return jsonify(
                {
                    "ok": True,
                    "record_ids": sorted(state.records.keys()),
                    "token_to_record_ids": state.token_to_record_ids,
                    "latest_checkpoint": state.latest_checkpoint,
                    "snapshot_root": state.snapshot.root_hex if state.snapshot else None,
                    "snapshot_token_ids": state.snapshot.sorted_token_ids if state.snapshot else [],
                }
            )

    return app


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8100)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    app = create_app()

    print("[Cloud] CamShield Cloud Server")
    print(f"[Cloud] listening on http://{args.host}:{args.port}")
    print(f"[Cloud] pid={os.getpid()}")

    app.run(
        host=args.host,
        port=args.port,
        debug=False,
        threaded=True,
    )


if __name__ == "__main__":
    main()
