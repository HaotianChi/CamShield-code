"""Remote Cloud HTTP service."""

from __future__ import annotations
from core.cloud_persistence import load_cloud_state, save_cloud_state
from flask import request

import argparse
import json
import urllib.request
import urllib.error
import os
import threading
import time
from typing import Any

from flask import Flask, jsonify, request

from core.ordered_merkle import (
    build_ordered_merkle_snapshot,
    make_real_token_id,
)


def now_ts() -> int:
    return int(time.time())


class CloudState:
    def __init__(self) -> None:
        self.lock = threading.Lock()

                                                  
        self.records: dict[str, dict[str, Any]] = {}

                                     
                                                          
        self.token_to_record_ids: dict[str, list[str]] = {}

                                                       
                          
                                                                   
        self.latest_checkpoint: dict[str, Any] | None = None

                                                                            
        self.snapshot = None

        self.store_batches = 0

                                        
                                              
                                                                             
                                                                       
        self.live_sessions: dict[str, dict[str, Any]] = {}

        # camera_id -> session_id while live fast path is active on Cloud
        self.live_fast_path_cameras: dict[str, str] = {}

    def rebuild_snapshot(self) -> None:
        self.snapshot = build_ordered_merkle_snapshot(self.token_to_record_ids)


def create_app() -> Flask:
    app = Flask(__name__)
    state = CloudState()

                                               
    load_cloud_state(state)

    @app.after_request
    def _camshield_persist_cloud_after_request(response):
        """
        Save Cloud encrypted storage after successful mutating requests.

        Main mutating endpoint is /store-batch. Saving after each successful
        POST keeps records/index/checkpoint durable across cloud_server restarts.
        """
        try:
            if request.method in ("POST", "PUT", "DELETE") and response.status_code < 400:
                save_cloud_state(state)
        except Exception as exc:
            print(f"[CLOUD-PERSIST] save failed: {exc}")
        return response
                                             

    @app.get("/health")
    def health():
        with state.lock:
            return jsonify(
                {
                    "ok": True,
                    "service": "camshield-cloud-server",
                    "pid": os.getpid(),
                    "record_count": len(state.records),
                    "token_count": len(state.token_to_record_ids),
                    "has_checkpoint": state.latest_checkpoint is not None,
                    "store_batches": state.store_batches,
                }
            )

    @app.post("/store-batch")
    def store_batch():
        """
        Gateway uploads encrypted records and the current signed checkpoint.

        Expected JSON:
        {
          "records": [
            {
              "rid": "<rid hex>",
              "record": {...}
            }
          ],
          "token_to_record_ids": {
              "<token hex>": ["<rid hex>", ...]
          },
          "signed_checkpoint": {
              "epoch": 1,
              "version": 1,
              "timestamp": 123456,
              "root_hex": "...",
              "signature_b64": "...",
              ...
          }
        }

        Gateway uploads the token_to_record_ids snapshot together with the
        signed checkpoint so Cloud proof generation is deterministic.
        """
        obj = request.get_json(force=True)

        records = obj.get("records", [])
        token_to_record_ids = obj.get("token_to_record_ids", {})
        signed_checkpoint = obj.get("signed_checkpoint")

        if signed_checkpoint is None:
            return jsonify({"ok": False, "error": "missing signed_checkpoint"}), 400

        if not isinstance(records, list):
            return jsonify({"ok": False, "error": "records must be a list"}), 400

        if not isinstance(token_to_record_ids, dict):
            return jsonify({"ok": False, "error": "token_to_record_ids must be a dict"}), 400

        with state.lock:
                            
            stored = 0
            for item in records:
                rid = str(item["rid"])
                rec = item["record"]
                state.records[rid] = rec
                stored += 1

                                                                      
            normalized_index: dict[str, list[str]] = {}
            for token_hex, rid_list in token_to_record_ids.items():
                token_hex = str(token_hex)
                normalized_index[token_hex] = sorted(str(x) for x in rid_list)

            state.token_to_record_ids = normalized_index
            state.rebuild_snapshot()

            computed_root = state.snapshot.root_hex
            uploaded_root = str(signed_checkpoint.get("root_hex", ""))

            if computed_root != uploaded_root:
                return jsonify(
                    {
                        "ok": False,
                        "error": "checkpoint root mismatch",
                        "computed_root": computed_root,
                        "uploaded_root": uploaded_root,
                    }
                ), 400

            state.latest_checkpoint = dict(signed_checkpoint)
            state.store_batches += 1

            return jsonify(
                {
                    "ok": True,
                    "stored_records": stored,
                    "record_count": len(state.records),
                    "token_count": len(state.token_to_record_ids),
                    "checkpoint_root": computed_root,
                    "checkpoint_version": state.latest_checkpoint.get("version"),
                }
            )

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
                state.records[rid] = rec
                stored += 1

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
            if state.latest_checkpoint is None:
                return jsonify({"ok": False, "error": "no checkpoint"}), 404

            return jsonify(
                {
                    "ok": True,
                    "signed_checkpoint": state.latest_checkpoint,
                }
            )

    @app.get("/record/<rid>")
    def get_record(rid: str):
        with state.lock:
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

        if operator not in ("AND", "OR"):
            return jsonify({"ok": False, "error": "operator must be AND or OR"}), 400

        if not isinstance(query_token_ids, list):
            return jsonify({"ok": False, "error": "query_token_ids must be a list"}), 400

        with state.lock:
            if state.latest_checkpoint is None or state.snapshot is None:
                return jsonify({"ok": False, "error": "no checkpoint"}), 404

            membership_proofs: dict[str, Any] = {}
            non_membership_proofs: dict[str, Any] = {}
            postings: dict[str, list[str]] = {}

            posting_sets: list[set[str]] = []

            for raw_query_token in query_token_ids:
                raw_query_token = str(raw_query_token)
                token_id = make_real_token_id(raw_query_token)

                                                                      
                raw_token_hex = raw_query_token[2:] if raw_query_token.startswith("1:") else raw_query_token

                if token_id in state.snapshot.leaves and raw_token_hex in state.token_to_record_ids:
                    rid_list = sorted(state.token_to_record_ids.get(raw_token_hex, []))
                    postings[raw_query_token] = rid_list

                    proof = state.snapshot.membership_proof(token_id)
                    membership_proofs[raw_query_token] = proof.to_dict()

                    posting_sets.append(set(rid_list))

                else:
                    postings[raw_query_token] = []

                    proof = state.snapshot.non_membership_proof(token_id)
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
                    "signed_checkpoint": state.latest_checkpoint,
                    "checkpoint_root_hex": state.latest_checkpoint.get("root_hex"),
                    "record_count": len(state.records),
                    "token_count": len(state.token_to_record_ids),
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
        best_rid = None
        best_rec = None
        best_key = None

        for rid, rec in state.records.items():
            ssi = rec.get("SSi", {}) if isinstance(rec, dict) else {}
            cid = str(ssi.get("cid", ""))
            if cid != camera_id:
                continue

            if epoch is not None:
                try:
                    if int(rec.get("epoch", -1)) != int(epoch):
                        continue
                except Exception:
                    continue

            try:
                seq = int(ssi.get("seq", 0))
            except Exception:
                seq = 0

            try:
                ts = int(ssi.get("timestamp", 0))
            except Exception:
                ts = 0

            key = (ts, seq, str(rid))
            if best_key is None or key > best_key:
                best_key = key
                best_rid = str(rid)
                best_rec = rec

        return best_rid, best_rec

    @app.post("/live/start")
    def live_start():
        obj = request.get_json(force=True, silent=True) or {}

        client_id = str(obj.get("client_id", "owner"))
        camera_id = str(obj.get("camera_id", obj.get("cid", "cam01"))).strip()
        epoch_raw = obj.get("epoch", None)
        epoch = int(epoch_raw) if epoch_raw is not None else None

        gateway_url = str(obj.get("gateway_url", obj.get("gateway", ""))).rstrip("/")
        if not gateway_url:
            return jsonify({
                "ok": False,
                "error": "gateway_url is required so Cloud can notify Gateway",
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
            state.live_sessions[session_id] = {
                "session_id": session_id,
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": epoch,
                "gateway_url": gateway_url,
                "created_at": int(time.time()),
                "mode": "live-fast-path",
                "fast_path_ready": True,
                "vp_verification_default": False,
                "basic_verification_only": True,
                "latest_rid_at_start": rid,
            }
            state.live_fast_path_cameras[camera_id] = session_id

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
            "gateway_notified": True,
            "gateway_response": gw_resp,
            "rid": rid,
            "has_record": rid is not None,
        })


                                     
                                                 
     
                                                                               
                                                                         
     
                                
                                                                           
                                          

    def _fig5c_deep_find_values(obj: Any, names: set[str], depth: int = 0):
        if depth > 8:
            return

        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k) in names:
                    yield v
                if isinstance(v, (dict, list)):
                    yield from _fig5c_deep_find_values(v, names, depth + 1)

        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    yield from _fig5c_deep_find_values(item, names, depth + 1)


    def _fig5c_to_int(v: Any) -> int | None:
        try:
            if v is None:
                return None
            return int(v)
        except Exception:
            return None


    def _fig5c_record_seq(rec: dict[str, Any]) -> int | None:
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

        for v in _fig5c_deep_find_values(rec, seq_names):
            x = _fig5c_to_int(v)
            if x is not None:
                return x

        sid_names = {
            "sid",
            "segment_id",
            "segment_descriptor_id",
            "segmentId",
        }

        for sid in _fig5c_deep_find_values(rec, sid_names):
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


    def _fig5c_record_rid(rec: dict[str, Any], fallback: Any = None) -> str | None:
        if isinstance(rec, dict):
            for k in ("rid", "record_id", "id"):
                v = rec.get(k)
                if v:
                    return str(v)

            for v in _fig5c_deep_find_values(rec, {"rid", "record_id", "id"}):
                if v:
                    return str(v)

        return str(fallback) if fallback is not None else None


    def _fig5c_iter_records_locked():
        """
        Directly scan state.records.

        Expected common formats:
          state.records[rid] = record
          state.records[rid] = {"record": record, ...}
        """
        records = getattr(state, "records", None)

        if isinstance(records, dict):
            for k, v in records.items():
                if isinstance(v, dict) and isinstance(v.get("record"), dict):
                    rec = v["record"]
                    rid = _fig5c_record_rid(rec, v.get("rid", k))
                    yield rid, rec
                elif isinstance(v, dict):
                    rec = v
                    rid = _fig5c_record_rid(rec, k)
                    yield rid, rec

        elif isinstance(records, list):
            for item in records:
                if isinstance(item, dict) and isinstance(item.get("record"), dict):
                    rec = item["record"]
                    rid = _fig5c_record_rid(rec, item.get("rid"))
                    yield rid, rec
                elif isinstance(item, dict):
                    rec = item
                    rid = _fig5c_record_rid(rec)
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

            candidates = []

            for rid, rec in _fig5c_iter_records_locked():
                seq = _fig5c_record_seq(rec)

                if seq is None:
                    continue

                if seq <= after_seq:
                    continue

                candidates.append((seq, rid, rec))

            if not candidates:
                return jsonify({
                    "ok": True,
                    "ready": False,
                    "fast_path_ready": False,
                    "session_id": session_id,
                    "after_seq": after_seq,
                    "mode": "live-fast-path",
                    "message": "no next record yet",
                    "record_count": len(getattr(state, "records", {}) or {}),
                }), 202

            seq, rid, rec = min(candidates, key=lambda x: x[0])

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
            rid, rec = _latest_record_for_camera_locked(camera_id, epoch=epoch)

            if rid is None:
                return jsonify({
                    "ok": False,
                    "error": "no live record for session camera",
                    "session_id": session_id,
                    "camera_id": camera_id,
                    "epoch": epoch,
                }), 404

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
