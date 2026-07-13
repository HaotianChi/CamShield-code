from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from flask import Flask, jsonify, request, send_from_directory

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = Path(__file__).resolve().parent / "client_tools"
RUNS_DIR = PROJECT_ROOT / "web_runs"

DEFAULT_GATEWAY_URL = "http://127.0.0.1:8000"
DEFAULT_CLOUD_URL = "http://127.0.0.1:8100"
DEFAULT_CAMERA_URL = ""
DEFAULT_TEE_URL = "http://127.0.0.1:9000"


def esc(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def pretty(obj: Any) -> str:
    try:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(obj)


def split_items(s: str) -> list[str]:
    return [x.strip() for x in re.split(r"[\s,]+", s.strip()) if x.strip()]


def safe_name(s: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(s)).strip("_")
    return out or "x"


@dataclass
class HttpResult:
    ok: bool
    status: int | None
    data: dict[str, Any]
    error: str = ""
    latency_ms: float | None = None


def request_json(method: str, url: str, *, payload: dict[str, Any] | None = None, timeout: int = 15) -> HttpResult:
    t0 = time.perf_counter()
    try:
        if method.upper() == "GET":
            r = requests.get(url, timeout=timeout)
        else:
            r = requests.post(url, json=payload or {}, timeout=timeout)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        try:
            data = r.json()
        except Exception:
            data = {"ok": False, "raw_text": r.text}
        return HttpResult(
            ok=bool(r.ok and (data.get("ok", True) is not False)),
            status=r.status_code,
            data=data,
            latency_ms=latency_ms,
        )
    except Exception as exc:
        latency_ms = (time.perf_counter() - t0) * 1000.0
        return HttpResult(ok=False, status=None, data={}, error=f"{type(exc).__name__}: {exc}", latency_ms=latency_ms)


def post_json_retry(url: str, payload: dict[str, Any], timeout: int = 30, attempts: int = 3) -> HttpResult:
    last = None
    for i in range(1, attempts + 1):
        res = request_json("POST", url, payload=payload, timeout=timeout)
        if res.ok:
            return res
        last = res
        if i < attempts:
            time.sleep(1.0 * i)
    return last if last is not None else HttpResult(False, None, {}, "unknown error")


def walk_epoch(x: Any) -> int | None:
    if isinstance(x, dict):
        for k, v in x.items():
            if str(k).lower() in ("epoch", "current_epoch", "gateway_epoch"):
                try:
                    return int(v)
                except Exception:
                    pass
            ans = walk_epoch(v)
            if ans is not None:
                return ans
    elif isinstance(x, list):
        for y in x:
            ans = walk_epoch(y)
            if ans is not None:
                return ans
    return None


def get_current_epoch(gateway_url: str, fallback: int = 239) -> int:
    for path in ["/admin/revocation/state", "/admin/status"]:
        res = request_json("GET", gateway_url.rstrip("/") + path, timeout=5)
        if res.status == 200 and res.data:
            ans = walk_epoch(res.data)
            if ans is not None:
                return ans
    return fallback


CAP_CACHE_DIR = RUNS_DIR / ".cap_u_cache"


def cap_u_cache_path(client_id: str, camera_id: str) -> Path:
    return CAP_CACHE_DIR / f"{safe_name(client_id)}_{safe_name(camera_id)}.json"


def load_cached_cap_u(client_id: str, camera_id: str) -> dict[str, Any] | None:
    path = cap_u_cache_path(client_id, camera_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        cap = data.get("Cap_u") or data.get("cap_u") or data
        return cap if isinstance(cap, dict) else None
    except Exception:
        return None


def save_cap_u_cache(
    client_id: str,
    camera_id: str,
    cap_u: dict[str, Any],
    *,
    run_dir: Path | None = None,
) -> Path:
    CAP_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = cap_u_cache_path(client_id, camera_id)
    payload = {
        "client_id": client_id,
        "camera_id": camera_id,
        "Cap_u": cap_u,
        "saved_at": time.time(),
    }
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")
    if run_dir is not None:
        (run_dir / "cap_u.json").write_text(text, encoding="utf-8")
    return path


def fetch_cap_u_from_gateway(
    gateway_url: str,
    client_id: str,
    camera_id: str,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    res = post_json_retry(
        gateway_url.rstrip("/") + "/client/credential-setup",
        {"client_id": client_id, "camera_id": camera_id},
        timeout=30,
        attempts=3,
    )
    data = res.data or {"ok": False, "error": res.error, "status": res.status}
    if res.status == 200 and data.get("ok"):
        cap = data.get("Cap_u") or (data.get("Cred_u") or {}).get("Cap_u")
        if isinstance(cap, dict):
            return cap, data
    return None, data


def load_or_fetch_cap_u(
    gateway_url: str,
    client_id: str,
    camera_id: str,
    *,
    run_dir: Path | None = None,
) -> tuple[dict[str, Any] | None, str, dict[str, Any]]:
    cached = load_cached_cap_u(client_id, camera_id)
    if cached and cached.get("IdxCap_u"):
        return cached, "cache", {}

    cap, setup_resp = fetch_cap_u_from_gateway(gateway_url, client_id, camera_id)
    if cap:
        save_cap_u_cache(client_id, camera_id, cap, run_dir=run_dir)
        return cap, "credential-setup", setup_resp

    return cached, "cache-miss", setup_resp


def derive_search_tokens(
    *,
    cap_u: dict[str, Any] | None,
    gateway_url: str,
    client_id: str,
    camera_id: str,
    epoch: int,
    keywords: list[str],
) -> tuple[list[str], dict[str, Any], str]:
    """
    Default: derive query_token_ids offline from IdxCap_u in Cap_u.
    Fallback: POST /search-tokens when IdxCap_u is missing or epoch out of lease.
    """
    offline_err = "Cap_u missing IdxCap_u"
    if cap_u and cap_u.get("IdxCap_u"):
        try:
            from core.idx_cap_u import search_token_hex_from_cap_u

            query_token_ids = search_token_hex_from_cap_u(
                cap_u,
                client_id=client_id,
                camera_id=camera_id,
                epoch=epoch,
                keywords=keywords,
            )
            keyword_to_token_id = {
                kw: tok for kw, tok in zip(keywords, query_token_ids)
            }
            token_data = {
                "ok": True,
                "mode": "IdxCap_u-offline",
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": epoch,
                "keywords": keywords,
                "query_token_ids": query_token_ids,
                "keyword_to_token_id": keyword_to_token_id,
            }
            return query_token_ids, token_data, "IdxCap_u-offline"
        except (PermissionError, ValueError) as exc:
            offline_err = str(exc)

    token_payload = {
        "client_id": client_id,
        "camera_id": camera_id,
        "keywords": keywords,
        "epoch": epoch,
    }
    token_res = post_json_retry(
        gateway_url.rstrip("/") + "/search-tokens",
        token_payload,
        timeout=20,
        attempts=3,
    )
    token_data = token_res.data or {
        "ok": False,
        "error": token_res.error,
        "status": token_res.status,
    }
    token_data["mode"] = "on-demand"
    if not token_data.get("ok"):
        token_data["offline_fallback_reason"] = offline_err
    query_token_ids = token_data.get("query_token_ids", []) if token_data.get("ok") else []
    return query_token_ids, token_data, "on-demand"


def status_probe(name: str, url: str, paths: list[str], timeout: int = 5, optional: bool = False) -> dict[str, Any]:
    if not url:
        return {"name": name, "configured": False, "ok": False, "note": "URL not configured"}

    base = url.rstrip("/")
    first_response = None

    for path in paths:
        res = request_json("GET", base + path, timeout=timeout)
        item = {
            "name": name,
            "configured": True,
            "ok": bool(res.ok),
            "url": base + path,
            "status": res.status,
            "latency_ms": res.latency_ms,
            "data": res.data,
            "error": res.error,
        }

        if first_response is None and res.status is not None:
            first_response = item

        if res.ok:
            return item

    if first_response is not None:
        return first_response

    if optional:
        return {
            "name": name,
            "configured": False,
            "ok": False,
            "url": url,
            "error": "optional endpoint not available",
        }

    return {"name": name, "configured": True, "ok": False, "url": url, "error": "no endpoint responded"}


def run_cmd(args: list[str], timeout: int = 180) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            args,
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        return {
            "ok": proc.returncode == 0 and "RESULT: PASS" in out,
            "returncode": proc.returncode,
            "output": out,
            "latency_ms": (time.perf_counter() - t0) * 1000.0,
            "cmd": args,
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "output": f"{type(exc).__name__}: {exc}",
            "latency_ms": (time.perf_counter() - t0) * 1000.0,
            "cmd": args,
        }


def load_retrieval_helpers():
    from core.client_tools.retrieval_proof_verify import (
        verify_checkpoint_signature,
        verify_membership_proof,
        verify_non_membership_proof,
        verify_result_set,
    )
    return verify_checkpoint_signature, verify_membership_proof, verify_non_membership_proof, verify_result_set


def verify_retrieval_response(search_data: dict[str, Any], query_token_ids: list[str], operator: str, epoch: int) -> dict[str, Any]:
    verify_checkpoint_signature, verify_membership_proof, verify_non_membership_proof, verify_result_set = load_retrieval_helpers()

    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, msg: str = ""):
        checks.append({"name": name, "ok": bool(ok), "message": msg})

    if not search_data.get("ok"):
        add("cloud search ok", False, pretty(search_data))
        return {"ok": False, "checks": checks, "result_record_ids": []}

    root_hex = search_data.get("checkpoint_root_hex")
    signed_checkpoint = search_data.get("signed_checkpoint") or {}
    if not root_hex:
        root_hex = signed_checkpoint.get("root_hex")

    if not root_hex:
        add("checkpoint root present", False, "missing checkpoint_root_hex")
        return {"ok": False, "checks": checks, "result_record_ids": search_data.get("result_record_ids", [])}

    add("checkpoint root present", True, root_hex)

    root_match = signed_checkpoint.get("root_hex") == root_hex
    add("checkpoint root matches response", root_match, "ok" if root_match else "root mismatch")

    try:
        epoch_match = int(signed_checkpoint.get("epoch", -1)) == int(epoch)
    except Exception:
        epoch_match = False
    add("checkpoint epoch matches query", epoch_match, f"checkpoint={signed_checkpoint.get('epoch')}, query={epoch}")

    try:
        sig_ok, sig_msg = verify_checkpoint_signature(signed_checkpoint)
    except Exception as exc:
        sig_ok, sig_msg = False, repr(exc)
    add("gateway checkpoint signature", sig_ok, sig_msg)

    postings = search_data.get("postings", {}) or {}
    membership_proofs = search_data.get("membership_proofs", {}) or {}
    non_membership_proofs = search_data.get("non_membership_proofs", {}) or {}
    result_record_ids = [str(x) for x in search_data.get("result_record_ids", [])]

    for tok in query_token_ids:
        posting = postings.get(tok, []) or []
        if posting:
            proof = membership_proofs.get(tok)
            if not proof:
                add(f"membership proof {tok[:16]}...", False, "missing membership proof")
                continue
            try:
                ok, msg = verify_membership_proof(
                    root_hex=root_hex,
                    token_hex=tok,
                    posting_record_ids=posting,
                    proof=proof,
                )
            except Exception as exc:
                ok, msg = False, repr(exc)
            add(f"membership proof {tok[:16]}...", ok, msg)
        else:
            proof = non_membership_proofs.get(tok)
            if not proof:
                add(f"non-membership proof {tok[:16]}...", False, "missing non-membership proof")
                continue
            try:
                ok, msg = verify_non_membership_proof(
                    root_hex=root_hex,
                    token_hex=tok,
                    proof=proof,
                )
            except Exception as exc:
                ok, msg = False, repr(exc)
            add(f"non-membership proof {tok[:16]}...", ok, msg)

    try:
        rs_ok, rs_msg = verify_result_set(operator, query_token_ids, postings, result_record_ids)
    except Exception as exc:
        rs_ok, rs_msg = False, repr(exc)
    add("result set equals posting-list evaluation", rs_ok, rs_msg)

    return {
        "ok": all(c["ok"] for c in checks),
        "checks": checks,
        "result_record_ids": result_record_ids,
    }


def fetch_records(cloud_url: str, rids: list[str], limit: int | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    fetched = []
    reports = []
    ids = rids if limit is None or limit <= 0 else rids[:limit]
    for rid in ids:
        res = request_json("GET", cloud_url.rstrip("/") + f"/record/{rid}", timeout=30)
        record = None
        if res.data:
            record = res.data.get("record", res.data)
        ok = bool(res.status == 200 and res.data and res.data.get("ok", True) is not False and record)
        reports.append({
            "rid": rid,
            "ok": ok,
            "status": res.status,
            "latency_ms": res.latency_ms,
            "error": res.error,
        })
        fetched.append({
            "rid": rid,
            "http_status": res.status,
            "ok": ok,
            "response": res.data,
            "record": record,
        })
    return fetched, reports


def get_json_retry(url: str, timeout: int = 30, attempts: int = 3) -> HttpResult:
    last = None
    for i in range(1, attempts + 1):
        res = request_json("GET", url, timeout=timeout)
        if res.ok:
            return res
        last = res
        if i < attempts:
            time.sleep(1.0 * i)
    return last if last is not None else HttpResult(False, None, {}, "unknown error")


def poll_live_latest(
    cloud_url: str,
    session_id: str,
    *,
    timeout_s: float = 30.0,
    interval_s: float = 0.25,
) -> HttpResult:
    deadline = time.time() + timeout_s
    last: HttpResult | None = None
    url = cloud_url.rstrip("/") + f"/live/latest/{session_id}"

    while time.time() < deadline:
        res = request_json("GET", url, timeout=15)
        last = res
        if res.status == 200 and res.data.get("ok") and res.data.get("record"):
            return res
        time.sleep(interval_s)

    return last if last is not None else HttpResult(False, None, {}, "live poll timeout")


def write_live_fetched_json(
    *,
    run_dir: Path,
    client_id: str,
    camera_id: str,
    epoch: int,
    live_start: dict[str, Any],
    live_latest: dict[str, Any],
    fetched_records: list[dict[str, Any]],
) -> Path:
    obj = {
        "client_id": client_id,
        "camera_id": camera_id,
        "mode": "live-fast-path",
        "epoch": epoch,
        "live_start_response": live_start,
        "live_latest_response": live_latest,
        "fetched_records": fetched_records,
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "fetched_records.json"
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def write_evidence_package(
    *,
    run_dir: Path,
    client_id: str,
    camera_id: str,
    keywords: list[str],
    epoch: int,
    operator: str,
    query_token_ids: list[str],
    token_resp: dict[str, Any],
    search_resp: dict[str, Any],
    fetched_records: list[dict[str, Any]],
) -> Path:
    search_response = dict(search_resp)
    search_response["query_token_ids"] = query_token_ids
    pkg = {
        "type": "camshield-evidence-package-v1",
        "client_id": client_id,
        "camera_id": camera_id,
        "keyword": keywords[0] if keywords else "",
        "keywords": keywords,
        "epoch": epoch,
        "operator": operator,
        "search_response": search_response,
        "gateway_token_response": token_resp,
        "fetched_records": fetched_records,
    }
    path = run_dir / "evidence_package.json"
    path.write_text(json.dumps(pkg, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def run_record_verification_pipeline(
    result: dict[str, Any],
    *,
    json_path: Path,
    run_dir: Path,
    gateway_url: str,
    client_id: str,
    camera_id: str,
    epoch: int,
    decrypt_limit: int,
    playback_limit: int,
) -> None:
    if not json_path.exists():
        result["decrypt_output"] = "Skipped: fetched_records.json not found."
        result["binding_output"] = result["decrypt_output"]
        result["camera_output"] = result["decrypt_output"]
        result["playback_report"] = result["decrypt_output"]
        return

    decrypt_script = TOOLS_DIR / "client_charm_local_decrypt.py"
    if decrypt_script.exists():
        dec = run_cmd([
            sys.executable,
            str(decrypt_script),
            "--input",
            str(json_path),
            "--gateway-url",
            gateway_url,
            "--client-id",
            client_id,
            "--camera-id",
            camera_id,
            "--epoch",
            str(epoch),
            "--limit",
            str(decrypt_limit),
        ], timeout=240)
    else:
        dec = {
            "ok": False,
            "output": f"missing decrypt tool: {decrypt_script}",
        }
    result["decrypt_ok"] = bool(dec.get("ok"))
    result["decrypt_output"] = dec.get("output", "")

    binding_script = TOOLS_DIR / "record_binding_strict_verify.py"
    bind = run_cmd(
        [sys.executable, str(binding_script), str(json_path)],
        timeout=180,
    )
    binding_output = bind.get("output", "")
    result["binding_ok"] = binding_ok_from_output(binding_output, bool(bind.get("ok")))
    result["binding_output"] = binding_output

    cam_script = TOOLS_DIR / "camera_origin_verify.py"
    cam = run_cmd([sys.executable, str(cam_script), str(json_path)], timeout=180)
    result["camera_ok"] = bool(cam.get("ok"))
    result["camera_output"] = cam.get("output", "")

    playback = export_playback_video(
        json_path=json_path,
        run_dir=run_dir,
        gateway_url=gateway_url,
        client_id=client_id,
        camera_id=camera_id,
        epoch=epoch,
        max_segments=playback_limit,
        fps=10,
    )
    result["playback_ok"] = bool(playback.get("ok"))
    result["playback_report"] = playback
    if playback.get("ok"):
        result["video_url"] = str(playback.get("video_url")) + "?t=" + str(int(time.time()))
        result["video_path"] = playback.get("mp4_path", "")


def binding_ok_from_output(binding_output: str, bind_cmd_ok: bool) -> bool:
    if bind_cmd_ok:
        return True
    if "signature verifies over stored hash" in binding_output:
        if "True" in binding_output.split("signature verifies over stored hash")[-1][:40]:
            return True
    return False


def count_fetched_records(json_path: Path) -> int:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    return len(data.get("fetched_records", []))


def run_full_evidence_verification(
    *,
    run_dir: Path,
    json_path: Path,
    gateway_url: str,
    client_id: str,
    camera_id: str,
    epoch: int,
    source_mode: str,
) -> dict[str, Any]:
    """
    Full evidence verification for all records in a retrieval or live run.
    """
    record_count = count_fetched_records(json_path)
    if record_count <= 0:
        return {
            "workflow_mode": "evidence-full",
            "source_mode": source_mode,
            "run_dir": str(run_dir),
            "json_path": str(json_path),
            "overall_ok": False,
            "error": "no fetched records in run directory",
        }

    result: dict[str, Any] = {
        "workflow_mode": "evidence-full",
        "source_mode": source_mode,
        "run_dir": str(run_dir),
        "json_path": str(json_path),
        "result_count": record_count,
        "fetched_count": record_count,
        "evidence_retrieval_ok": False,
        "evidence_binding_ok": False,
        "evidence_camera_ok": False,
        "evidence_decrypt_ok": False,
        "overall_ok": False,
        "error": "",
    }

    if source_mode == "retrieval":
        package_path = run_dir / "evidence_package.json"
        result["evidence_package_path"] = str(package_path)
        if package_path.exists():
            from core.client_tools.verify_evidence_package import verify_retrieval_from_package

            pkg = json.loads(package_path.read_text(encoding="utf-8"))
            checks = verify_retrieval_from_package(pkg)
            evidence_checks = [{"name": name, "ok": ok, "message": msg} for name, ok, msg in checks]
            result["evidence_report"] = {
                "ok": all(c["ok"] for c in evidence_checks),
                "checks": evidence_checks,
            }
            result["evidence_retrieval_ok"] = bool(result["evidence_report"]["ok"])
        else:
            result["evidence_report"] = {
                "ok": False,
                "checks": [{"name": "evidence package", "ok": False, "message": "evidence_package.json not found"}],
            }
    else:
        result["evidence_report"] = {
            "ok": True,
            "checks": [{
                "name": "retrieval proof",
                "ok": True,
                "message": "not applicable for live access; verifying all fetched LER records",
            }],
        }
        result["evidence_retrieval_ok"] = True

    pipeline: dict[str, Any] = {}
    run_record_verification_pipeline(
        pipeline,
        json_path=json_path,
        run_dir=run_dir,
        gateway_url=gateway_url,
        client_id=client_id,
        camera_id=camera_id,
        epoch=epoch,
        decrypt_limit=record_count,
        playback_limit=record_count,
    )

    result["decrypt_ok"] = bool(pipeline.get("decrypt_ok"))
    result["decrypt_output"] = pipeline.get("decrypt_output", "")
    result["binding_ok"] = bool(pipeline.get("binding_ok"))
    result["binding_output"] = pipeline.get("binding_output", "")
    result["camera_ok"] = bool(pipeline.get("camera_ok"))
    result["camera_output"] = pipeline.get("camera_output", "")
    result["playback_ok"] = bool(pipeline.get("playback_ok"))
    result["playback_report"] = pipeline.get("playback_report", "")
    if pipeline.get("video_url"):
        result["video_url"] = pipeline["video_url"]
        result["video_path"] = pipeline.get("video_path", "")

    result["evidence_decrypt_ok"] = result["decrypt_ok"]
    result["evidence_binding_ok"] = result["binding_ok"]
    result["evidence_camera_ok"] = result["camera_ok"]

    if source_mode == "retrieval":
        result["overall_ok"] = bool(
            result["evidence_retrieval_ok"]
            and result["evidence_decrypt_ok"]
            and result["evidence_binding_ok"]
            and result["evidence_camera_ok"]
        )
    else:
        result["overall_ok"] = bool(
            result["evidence_decrypt_ok"]
            and result["evidence_binding_ok"]
            and result["evidence_camera_ok"]
        )

    summary_path = run_dir / "evidence_full_summary.json"
    summary_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    result["evidence_full_summary_path"] = str(summary_path)
    return result


def write_fetched_json(
    *,
    run_dir: Path,
    client_id: str,
    camera_id: str,
    keywords: list[str],
    epoch: int,
    operator: str,
    token_resp: dict[str, Any],
    search_resp: dict[str, Any],
    fetched_records: list[dict[str, Any]],
) -> Path:
    obj = {
        "client_id": client_id,
        "camera_id": camera_id,
        "keyword": " ".join(keywords),
        "keywords": keywords,
        "epoch": epoch,
        "operator": operator,
        "gateway_token_response": token_resp,
        "cloud_search_response": search_resp,
        "fetched_records": fetched_records,
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "fetched_records.json"
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def pill(ok: bool, text: str) -> str:
    cls = "pass" if ok else "fail"
    val = "PASS" if ok else "CHECK"
    return f'<span class="pill {cls}">{esc(text)}: {val}</span>'


def render_status_card(statuses: list[dict[str, Any]]) -> str:
    parts = ['<div class="card"><h2>System Status</h2>']
    for st in statuses:
        name = st.get("name", "service")
        if not st.get("configured", True):
            parts.append(f'<span class="pill warn">{esc(name)}: NOT CONFIGURED</span>')
            continue
        parts.append(pill(bool(st.get("ok")), name))
        if st.get("url"):
            lat = st.get("latency_ms")
            lat_s = f", {lat:.1f} ms" if isinstance(lat, (int, float)) else ""
            parts.append(f'<div class="small">{esc(name)} URL: {esc(st.get("url"))}, status={esc(st.get("status"))}{lat_s}</div>')
        if st.get("error"):
            parts.append(f'<pre>{esc(st.get("error"))}</pre>')
    parts.append('</div>')
    return "\n".join(parts)


def render_page(defaults: dict[str, Any], result: dict[str, Any] | None, statuses: list[dict[str, Any]]) -> str:
    gateway_url = defaults.get("gateway_url", DEFAULT_GATEWAY_URL)
    cloud_url = defaults.get("cloud_url", DEFAULT_CLOUD_URL)
    camera_url = defaults.get("camera_url", DEFAULT_CAMERA_URL)
    tee_url = defaults.get("tee_url", DEFAULT_TEE_URL)
    client_id = defaults.get("client_id", "owner")
    camera_id = defaults.get("camera_id", "cam01")
    keywords_text = defaults.get("keywords_text", "event:webdemo")
    epoch = defaults.get("epoch", "239")
    operator = defaults.get("operator", "AND")
    fetch_limit = defaults.get("fetch_limit", "10")
    decrypt_limit = defaults.get("decrypt_limit", "3")
    playback_limit = defaults.get("playback_limit", "10")
    live_timeout = defaults.get("live_timeout", "30")
    package_path = defaults.get("package_path", "")

    body = f"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CamShield Web Console</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; margin: 32px; background: #f8f9fa; color: #202124; }}
    h1 {{ margin-bottom: 6px; font-size: 42px; }}
    h2 {{ margin-top: 0; }}
    .subtitle {{ color: #5f6368; margin-top: 0; font-size: 19px; }}
    .card {{ background: white; border: 1px solid #dadce0; border-radius: 14px; padding: 20px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,.06); }}
    .result-layout {{ display: grid; grid-template-columns: minmax(520px, 1fr) minmax(520px, 1fr); gap: 18px; align-items: start; }}
    .result-layout .card {{ margin-bottom: 18px; }}
    .summary-card {{ min-height: 420px; }}
    .playback-card {{ min-height: 420px; }}
    .playback-card video {{ width: 100%; max-height: 520px; background: #000; border-radius: 12px; display: block; }}
    .playback-empty {{ color: #5f6368; background: #f1f3f4; border-radius: 12px; padding: 18px; }}
    .pill-wrap {{ display: flex; flex-wrap: wrap; gap: 8px 10px; margin-bottom: 16px; }}
    .path-text {{ overflow-wrap: anywhere; word-break: break-word; }}
    @media (max-width: 1150px) {{
      .result-layout {{ grid-template-columns: 1fr; }}
    }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(300px, 1fr)); gap: 14px 24px; }}
    label {{ display: block; margin-top: 10px; font-weight: 650; }}
    input, select, textarea {{ width: 100%; padding: 10px; margin-top: 6px; border: 1px solid #dadce0; border-radius: 8px; font-size: 14px; box-sizing: border-box; }}
    textarea {{ height: 70px; font-family: monospace; }}
    button {{ margin-top: 18px; padding: 11px 18px; border: 0; border-radius: 8px; background: #1a73e8; color: white; font-weight: 800; cursor: pointer; font-size: 15px; }}
    pre {{ background: #202124; color: #e8eaed; padding: 14px; border-radius: 10px; overflow-x: auto; white-space: pre-wrap; font-size: 13px; line-height: 1.35; }}
    details {{ margin-top: 12px; }}
    summary {{ cursor: pointer; font-weight: 700; }}
    .pill {{ display: inline-block; padding: 8px 13px; border-radius: 999px; font-weight: 800; margin: 5px 8px 5px 0; }}
    .pass {{ color: #137333; background: #e6f4ea; }}
    .fail {{ color: #b3261e; background: #fce8e6; }}
    .warn {{ color: #8a5a00; background: #fef7e0; }}
    .small {{ color: #5f6368; font-size: 13px; margin-top: 6px; }}
    .kv {{ margin: 6px 0; color: #3c4043; }}
  </style>
</head>
<body>
  <h1>CamShield Web Console</h1>
  <p class="subtitle">Interact with Gateway, Cloud, camera/TEE status endpoints, and run client-side verification.</p>

  {render_status_card(statuses)}

  <div class="card">
    <h2>Token-based Retrieval</h2>
    <p class="small">Gateway search tokens → Cloud encrypted search → retrieval proof verification → record fetch → decrypt, binding, camera-origin checks, and archival replay playback.</p>
    <form method="post" action="/verify">
      <div class="grid">
        <div><label>Gateway URL</label><input name="gateway_url" value="{esc(gateway_url)}"></div>
        <div><label>Cloud URL</label><input name="cloud_url" value="{esc(cloud_url)}"></div>
        <div><label>Camera URL, optional</label><input name="camera_url" value="{esc(camera_url)}"></div>
        <div><label>TEE URL, optional</label><input name="tee_url" value="{esc(tee_url)}"></div>
        <div><label>client_id</label><input name="client_id" value="{esc(client_id)}"></div>
        <div><label>camera_id</label><input name="camera_id" value="{esc(camera_id)}"></div>
        <div><label>epoch</label><input name="epoch" value="{esc(epoch)}"></div>
        <div><label>operator</label><select name="operator"><option value="AND" {'selected' if operator == 'AND' else ''}>AND</option><option value="OR" {'selected' if operator == 'OR' else ''}>OR</option></select></div>
        <div><label>fetch limit, 0 = all</label><input name="fetch_limit" value="{esc(fetch_limit)}"></div>
        <div><label>decrypt limit</label><input name="decrypt_limit" value="{esc(decrypt_limit)}"></div>
        <div><label>playback segments</label><input name="playback_limit" value="{esc(playback_limit)}"></div>
      </div>
      <label>keywords, spaces/commas/new lines</label>
      <textarea name="keywords_text">{esc(keywords_text)}</textarea>
      <button type="submit">Run Retrieval + Replay Verify</button>
    </form>
    <p class="small">Recommended current dataset: owner / cam01 / event:webdemo / {esc(epoch)}. Case tag: use the case:web_demo_* tag printed by the camera script</p>
  </div>

  <div class="card">
    <h2>Live Access</h2>
    <p class="small">Client requests live via Cloud; Cloud notifies Gateway; both sides enable live fast path. Gateway ingests LER records without index tags.</p>
    <form method="post" action="/live-access">
      <div class="grid">
        <div><label>Gateway URL</label><input name="gateway_url" value="{esc(gateway_url)}"></div>
        <div><label>Cloud URL</label><input name="cloud_url" value="{esc(cloud_url)}"></div>
        <div><label>client_id</label><input name="client_id" value="{esc(client_id)}"></div>
        <div><label>camera_id</label><input name="camera_id" value="{esc(camera_id)}"></div>
        <div><label>epoch</label><input name="epoch" value="{esc(epoch)}"></div>
        <div><label>live poll timeout (s)</label><input name="live_timeout" value="{esc(live_timeout)}"></div>
        <div><label>decrypt limit</label><input name="decrypt_limit" value="{esc(decrypt_limit)}"></div>
        <div><label>playback segments</label><input name="playback_limit" value="{esc(playback_limit)}"></div>
      </div>
      <button type="submit">Start Live Access + Verify</button>
    </form>
    <p class="small">Start this before or while the camera is ingesting. If no LER exists yet, the console polls Cloud /live/latest until timeout.</p>
  </div>

  <div class="card">
    <h2>Evidence Package (Advanced)</h2>
    <p class="small">Optional: verify a saved package by path. After retrieval or live access, use the <b>Run Full Evidence Verification</b> button in the result section instead.</p>
    <form method="post" action="/evidence-verify">
      <div class="grid">
        <div><label>Gateway URL</label><input name="gateway_url" value="{esc(gateway_url)}"></div>
        <div><label>Cloud URL</label><input name="cloud_url" value="{esc(cloud_url)}"></div>
        <div><label>package path</label><input name="package_path" value="{esc(package_path)}" placeholder="20260101_120000_owner_cam01_event_webdemo/evidence_package.json"></div>
      </div>
      <button type="submit">Verify Evidence Package</button>
    </form>
    <p class="small">Use a run directory under web_runs/ from a prior retrieval run, or the full path to evidence_package.json.</p>
  </div>
"""

    if result:
        overall_ok = bool(result.get("overall_ok"))

        body += '<div class="result-layout">'

                    
        body += '<div class="card summary-card"><h2>Summary</h2>'
        body += f'<div class="kv"><b>Mode:</b> {esc(result.get("workflow_mode", "retrieval"))}</div>'
        if result.get("source_mode"):
            body += f'<div class="kv"><b>Source:</b> {esc(result.get("source_mode"))}</div>'
        mode = result.get("workflow_mode", "retrieval")
        can_full_evidence = (
            result.get("run_dir")
            and result.get("json_path")
            and mode in ("retrieval", "live")
            and Path(str(result.get("json_path"))).exists()
        )
        body += '<div class="pill-wrap">'
        if mode == "live":
            body += pill(bool(result.get("live_start_ok")), "Live Start")
            body += pill(bool(result.get("live_fetch_ok")), "Live Fetch")
            body += pill(bool(result.get("decrypt_ok")), "Client CP-ABE/AES Decrypt")
            body += pill(bool(result.get("binding_ok")), "Record Binding")
            body += pill(bool(result.get("camera_ok")), "Camera-Origin")
            body += pill(bool(result.get("playback_ok")), "Replay Playback")
        elif mode == "evidence-full":
            body += pill(bool(result.get("evidence_retrieval_ok")), "Retrieval Proof")
            body += pill(bool(result.get("evidence_decrypt_ok")), "Full Decrypt")
            body += pill(bool(result.get("evidence_binding_ok")), "Full Record Binding")
            body += pill(bool(result.get("evidence_camera_ok")), "Full Camera-Origin")
            if result.get("playback_ok") is not None:
                body += pill(bool(result.get("playback_ok")), "Replay Playback")
        elif mode == "evidence":
            body += pill(bool(result.get("evidence_retrieval_ok")), "Package Retrieval Proof")
            body += pill(bool(result.get("evidence_binding_ok")), "Package Record Binding")
            body += pill(bool(result.get("evidence_camera_ok")), "Package Camera-Origin")
        else:
            body += pill(bool(result.get("token_ok")), "Gateway Token")
            body += pill(bool(result.get("search_ok")), "Cloud Search")
            body += pill(bool(result.get("retrieval_ok")), "Retrieval Proof")
            body += pill(bool(result.get("fetch_ok")), "Record Fetch")
            body += pill(bool(result.get("decrypt_ok")), "Client CP-ABE/AES Decrypt")
            body += pill(bool(result.get("binding_ok")), "Record Binding")
            body += pill(bool(result.get("camera_ok")), "Camera-Origin")
            body += pill(bool(result.get("playback_ok")), "Replay Playback")
        body += pill(overall_ok, "Overall")
        body += '</div>'

        body += f'<div class="kv"><b>Result count:</b> {esc(result.get("result_count"))}</div>'
        body += f'<div class="kv"><b>Fetched records:</b> {esc(result.get("fetched_count"))}</div>'
        body += f'<div class="kv"><b>Run dir:</b> {esc(result.get("run_dir"))}</div>'
        body += f'<div class="kv path-text"><b>Fetched JSON:</b> {esc(result.get("json_path"))}</div>'
        if result.get("evidence_package_path"):
            body += f'<div class="kv path-text"><b>Evidence package:</b> {esc(result.get("evidence_package_path"))}</div>'

        if result.get("error"):
            body += f'<pre>{esc(result.get("error"))}</pre>'

        body += '</div>'

        body += '<div class="card playback-card"><h2>Replay Playback</h2>'

        if result.get("video_url"):
            body += f"""
          <video controls preload="metadata">
            <source src="{esc(result.get('video_url'))}" type="video/mp4">
            Your browser does not support MP4 playback.
          </video>
          <div class="small path-text">MP4: {esc(result.get('video_path'))}</div>
            """
        else:
            body += """
          <div class="playback-empty">
            No playable video has been generated for this run yet.
            Run Search + Fetch + Verify with valid records and a positive playback segment count.
          </div>
            """

        body += '</div>'
        body += '</div>'

        if can_full_evidence and mode not in ("evidence-full", "evidence"):
            body += f"""
        <div class="card">
          <h2>Full Evidence Verification</h2>
          <p class="small">Run complete verification on <b>all</b> records fetched in this run (decrypt, binding, camera-origin; plus retrieval proof for token-based retrieval).</p>
          <form method="post" action="/evidence-verify-run">
            <input type="hidden" name="run_dir" value="{esc(result.get('run_dir'))}">
            <input type="hidden" name="source_mode" value="{esc(result.get('workflow_mode'))}">
            <input type="hidden" name="gateway_url" value="{esc(result.get('gateway_url', gateway_url))}">
            <input type="hidden" name="cloud_url" value="{esc(result.get('cloud_url', cloud_url))}">
            <input type="hidden" name="client_id" value="{esc(result.get('client_id', client_id))}">
            <input type="hidden" name="camera_id" value="{esc(result.get('camera_id', camera_id))}">
            <input type="hidden" name="epoch" value="{esc(result.get('epoch', epoch))}">
            <button type="submit">Run Full Evidence Verification on This Run</button>
          </form>
        </div>
            """

        for title, key in [
            ("Gateway Token Response", "token_data"),
            ("Cloud Search Response", "search_data"),
            ("Live Start Response", "live_start_data"),
            ("Live Latest Response", "live_latest_data"),
            ("Retrieval Proof Checks", "retrieval_report"),
            ("Evidence Package Checks", "evidence_report"),
            ("Record Fetch Report", "fetch_report"),
            ("Client-side CP-ABE/AES Decrypt", "decrypt_output"),
            ("Record Binding Verification", "binding_output"),
            ("Camera-Origin Verification", "camera_output"),
            ("Replay Playback Export", "playback_report"),
        ]:
            val = result.get(key)
            if val is None:
                continue
            if isinstance(val, str):
                content = val
            else:
                content = pretty(val)
            body += f'<div class="card"><h2>{esc(title)}</h2><pre>{esc(content)}</pre></div>'

    body += """
</body>
</html>
"""
    return body


def build_statuses(gateway_url: str, cloud_url: str, camera_url: str, tee_url: str) -> list[dict[str, Any]]:
    return [
        status_probe("Gateway status", gateway_url, ["/admin/revocation/state", "/bootstrap/trust", "/health", "/admin/status"]),
        status_probe("Gateway revocation", gateway_url, ["/admin/revocation/state"]),
        status_probe("Gateway trust", gateway_url, ["/bootstrap/trust"]),
        status_probe("Cloud health", cloud_url, ["/health"]),
        status_probe("Camera", camera_url, ["/health", "/status"], optional=True),
        status_probe("TEE", tee_url, ["/health", "/status"], optional=True),
    ]


def ffmpeg_exe() -> str:
    try:
        return subprocess.check_output([
            sys.executable,
            "-c",
            "import imageio_ffmpeg; print(imageio_ffmpeg.get_ffmpeg_exe())",
        ], text=True).strip()
    except Exception:
        return "ffmpeg"


def export_playback_video(
    *,
    json_path: Path,
    run_dir: Path,
    gateway_url: str,
    client_id: str,
    camera_id: str,
    epoch: int,
    max_segments: int,
    fps: int = 10,
) -> dict[str, Any]:
    """
    Export a browser-playable MP4 from the fresh fetched_records.json of this web run.
    This uses the same client-side Charm CP-ABE + AES-GCM decrypt logic as the verifier.
    """
    t0 = time.perf_counter()

    try:
        from core.client_tools.client_charm_local_decrypt import LocalCharmClient, records_from_json

        records = records_from_json(json_path)
        if not records:
            return {
                "ok": False,
                "error": "no encrypted records found in fetched_records.json",
            }

        def seq_of(rec: dict[str, Any]) -> int:
            try:
                return int(rec.get("SSi", {}).get("seq", 0))
            except Exception:
                return 0

        records = sorted(records, key=seq_of)

        if max_segments > 0:
            records = records[:max_segments]

        client = LocalCharmClient.bootstrap(
            gateway_url=gateway_url,
            client_id=client_id,
            camera_id=camera_id,
        )

        seg_dir = run_dir / "playback_segments"
        seg_dir.mkdir(parents=True, exist_ok=True)

        saved_segments: list[Path] = []
        decrypt_reports: list[dict[str, Any]] = []

        for i, rec in enumerate(records, start=1):
            ok, plaintext, info = client.decrypt_record(rec)

            rid = str(rec.get("rid", ""))
            seq = seq_of(rec)
            sid = str(rec.get("SSi", {}).get("sid", "seg"))

            item = {
                "index": i,
                "rid": rid,
                "seq": seq,
                "sid": sid,
                "ok": bool(ok),
                "info": info,
            }

            if not ok or plaintext is None:
                decrypt_reports.append(item)
                return {
                    "ok": False,
                    "error": f"decrypt failed at segment {i}, rid={rid[:16]}",
                    "decrypt_reports": decrypt_reports,
                }

            out_h264 = seg_dir / f"{seq:06d}_{sid}_{rid[:12]}.h264"
            out_h264.write_bytes(plaintext)
            saved_segments.append(out_h264)

            item["plaintext_len"] = len(plaintext)
            item["path"] = str(out_h264)
            decrypt_reports.append(item)

        concat_h264 = run_dir / "playback_concat.h264"
        with concat_h264.open("wb") as f:
            for sf in sorted(saved_segments):
                f.write(sf.read_bytes())

        mp4 = run_dir / "playback.mp4"
        ffmpeg = ffmpeg_exe()

                                                
        cmd1 = [
            ffmpeg,
            "-y",
            "-f", "h264",
            "-r", str(fps),
            "-i", str(concat_h264),
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            "-movflags", "+faststart",
            str(mp4),
        ]

        proc = subprocess.run(
            cmd1,
            text=True,
            capture_output=True,
            timeout=180,
        )

                                                       
        if proc.returncode != 0 or not mp4.exists() or mp4.stat().st_size == 0:
            cmd2 = [
                ffmpeg,
                "-y",
                "-f", "h264",
                "-r", str(fps),
                "-i", str(concat_h264),
                "-c:v", "mpeg4",
                str(mp4),
            ]
            proc2 = subprocess.run(
                cmd2,
                text=True,
                capture_output=True,
                timeout=180,
            )
            ffmpeg_output = (proc.stdout or "") + (proc.stderr or "") + "\n\n--- fallback ---\n\n" + (proc2.stdout or "") + (proc2.stderr or "")
            ffmpeg_cmd = cmd2
            ffmpeg_returncode = proc2.returncode
        else:
            ffmpeg_output = (proc.stdout or "") + (proc.stderr or "")
            ffmpeg_cmd = cmd1
            ffmpeg_returncode = proc.returncode

        if not mp4.exists() or mp4.stat().st_size == 0 or ffmpeg_returncode != 0:
            return {
                "ok": False,
                "error": "ffmpeg failed to produce playback.mp4",
                "ffmpeg_cmd": ffmpeg_cmd,
                "ffmpeg_output": ffmpeg_output[-4000:],
                "decrypt_reports": decrypt_reports,
            }

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "ok": True,
            "video_url": f"/web_runs/{run_dir.name}/playback.mp4",
            "mp4_path": str(mp4),
            "mp4_bytes": mp4.stat().st_size,
            "concat_h264": str(concat_h264),
            "segments": len(saved_segments),
            "fps": fps,
            "elapsed_ms": elapsed_ms,
            "ffmpeg_cmd": ffmpeg_cmd,
            "ffmpeg_output_tail": ffmpeg_output[-2000:],
            "decrypt_reports": decrypt_reports,
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def create_app(default_gateway_url: str, default_cloud_url: str, default_camera_url: str, default_tee_url: str) -> Flask:
    app = Flask(__name__)

    @app.get("/web_runs/<run_id>/<path:filename>")
    def serve_web_run_file(run_id: str, filename: str):
        return send_from_directory(RUNS_DIR / safe_name(run_id), filename)

    @app.get("/api/status")
    def api_status():
        gateway_url = request.args.get("gateway_url", default_gateway_url).rstrip("/")
        cloud_url = request.args.get("cloud_url", default_cloud_url).rstrip("/")
        camera_url = request.args.get("camera_url", default_camera_url).rstrip("/")
        tee_url = request.args.get("tee_url", default_tee_url).rstrip("/")
        return jsonify({"ok": True, "statuses": build_statuses(gateway_url, cloud_url, camera_url, tee_url)})

    @app.get("/")
    def index():
        gateway_url = default_gateway_url.rstrip("/")
        cloud_url = default_cloud_url.rstrip("/")
        camera_url = default_camera_url.rstrip("/")
        tee_url = default_tee_url.rstrip("/")
        epoch = get_current_epoch(gateway_url, fallback=239)
        defaults = {
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "camera_url": camera_url,
            "tee_url": tee_url,
            "client_id": "owner",
            "camera_id": "cam01",
            "keywords_text": "event:webdemo",
            "epoch": str(epoch),
            "operator": "AND",
            "fetch_limit": "10",
            "decrypt_limit": "3",
            "playback_limit": "10",
            "live_timeout": "30",
            "package_path": "",
        }
        return render_page(defaults, None, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

    @app.post("/verify")
    def verify():
        gateway_url = request.form.get("gateway_url", default_gateway_url).strip().rstrip("/")
        cloud_url = request.form.get("cloud_url", default_cloud_url).strip().rstrip("/")
        camera_url = request.form.get("camera_url", default_camera_url).strip().rstrip("/")
        tee_url = request.form.get("tee_url", default_tee_url).strip().rstrip("/")
        client_id = request.form.get("client_id", "owner").strip() or "owner"
        camera_id = request.form.get("camera_id", "cam01").strip() or "cam01"
        keywords_text = request.form.get("keywords_text", "event:fig6ret_single")
        keywords = split_items(keywords_text)
        operator = request.form.get("operator", "AND").strip().upper()
        epoch_text = request.form.get("epoch", "").strip()

        try:
            epoch = int(epoch_text)
        except Exception:
            epoch = get_current_epoch(gateway_url, fallback=239)
            epoch_text = str(epoch)

        try:
            fetch_limit = int(request.form.get("fetch_limit", "10"))
        except Exception:
            fetch_limit = 10
        try:
            decrypt_limit = int(request.form.get("decrypt_limit", "3"))
        except Exception:
            decrypt_limit = 3

        try:
            playback_limit = int(request.form.get("playback_limit", "10"))
        except Exception:
            playback_limit = 10

        run_id = time.strftime("%Y%m%d_%H%M%S") + "_" + safe_name(client_id) + "_" + safe_name(camera_id) + "_" + safe_name("_".join(keywords))
        run_dir = RUNS_DIR / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        defaults = {
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "camera_url": camera_url,
            "tee_url": tee_url,
            "client_id": client_id,
            "camera_id": camera_id,
            "keywords_text": keywords_text,
            "epoch": epoch_text,
            "operator": operator,
            "fetch_limit": str(fetch_limit),
            "decrypt_limit": str(decrypt_limit),
            "playback_limit": str(playback_limit),
        }

        result: dict[str, Any] = {
            "workflow_mode": "retrieval",
            "run_dir": str(run_dir),
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "client_id": client_id,
            "camera_id": camera_id,
            "epoch": epoch,
            "token_ok": False,
            "search_ok": False,
            "retrieval_ok": False,
            "fetch_ok": False,
            "decrypt_ok": False,
            "binding_ok": False,
            "camera_ok": False,
            "playback_ok": False,
            "overall_ok": False,
            "result_count": 0,
            "fetched_count": 0,
            "error": "",
        }

                                   
        cap_u, cap_u_source, cap_setup_resp = load_or_fetch_cap_u(
            gateway_url,
            client_id,
            camera_id,
            run_dir=run_dir,
        )
        result["cap_u_source"] = cap_u_source
        if cap_setup_resp:
            result["cap_setup_resp"] = cap_setup_resp

        query_token_ids, token_data, retrieval_mode = derive_search_tokens(
            cap_u=cap_u,
            gateway_url=gateway_url,
            client_id=client_id,
            camera_id=camera_id,
            epoch=epoch,
            keywords=keywords,
        )
        result["retrieval_mode"] = retrieval_mode
        result["token_data"] = token_data
        result["token_ok"] = bool(token_data.get("ok"))

                          
        search_data: dict[str, Any] = {}
        if result["token_ok"]:
            search_payload = {
                "query_token_ids": query_token_ids,
                "operator": operator,
                "epoch": epoch,
            }
            search_res = post_json_retry(cloud_url + "/search", search_payload, timeout=45, attempts=3)
            search_data = search_res.data or {"ok": False, "error": search_res.error, "status": search_res.status}
            result["search_data"] = search_data
            result["search_ok"] = bool(search_res.status == 200 and search_data.get("ok"))
        else:
            result["search_data"] = {"ok": False, "skipped": "gateway token failed"}

                                          
        retrieval_report = {"ok": False, "checks": [], "result_record_ids": []}
        if result["search_ok"]:
            try:
                retrieval_report = verify_retrieval_response(search_data, query_token_ids, operator, epoch)
            except Exception as exc:
                retrieval_report = {"ok": False, "checks": [{"name": "retrieval verifier exception", "ok": False, "message": repr(exc)}], "result_record_ids": []}
        else:
            retrieval_report = {"ok": False, "checks": [{"name": "retrieval skipped", "ok": False, "message": "cloud search failed"}], "result_record_ids": []}

        result["retrieval_report"] = retrieval_report
        result["retrieval_ok"] = bool(retrieval_report.get("ok"))
        rids = [str(x) for x in retrieval_report.get("result_record_ids", [])]
        result["result_count"] = len(rids)

                                                                 
        fetched_records: list[dict[str, Any]] = []
        fetch_report: list[dict[str, Any]] = []
        json_path = run_dir / "fetched_records.json"
        if result["search_ok"] and rids:
            fetched_records, fetch_report = fetch_records(cloud_url, rids, limit=fetch_limit)
            fetched_count = sum(1 for x in fetched_records if x.get("ok"))
            result["fetched_count"] = fetched_count
            expected = min(len(rids), fetch_limit) if fetch_limit > 0 else len(rids)
            result["fetch_ok"] = fetched_count == expected and expected > 0
            json_path = write_fetched_json(
                run_dir=run_dir,
                client_id=client_id,
                camera_id=camera_id,
                keywords=keywords,
                epoch=epoch,
                operator=operator,
                token_resp=token_data,
                search_resp=search_data,
                fetched_records=fetched_records,
            )
            result["json_path"] = str(json_path)
        else:
            result["fetch_ok"] = False
            result["json_path"] = str(json_path)
            if not rids:
                fetch_report = [{"ok": False, "message": "no result_record_ids; record fetch skipped"}]
            else:
                fetch_report = [{"ok": False, "message": "cloud search failed; record fetch skipped"}]
        result["fetch_report"] = fetch_report

        if result["fetch_ok"] and json_path.exists():
            run_record_verification_pipeline(
                result,
                json_path=json_path,
                run_dir=run_dir,
                gateway_url=gateway_url,
                client_id=client_id,
                camera_id=camera_id,
                epoch=epoch,
                decrypt_limit=decrypt_limit,
                playback_limit=playback_limit,
            )
            if result["search_ok"] and query_token_ids:
                package_path = write_evidence_package(
                    run_dir=run_dir,
                    client_id=client_id,
                    camera_id=camera_id,
                    keywords=keywords,
                    epoch=epoch,
                    operator=operator,
                    query_token_ids=query_token_ids,
                    token_resp=token_data,
                    search_resp=search_data,
                    fetched_records=fetched_records,
                )
                result["evidence_package_path"] = str(package_path)
        else:
            result["decrypt_output"] = "Skipped: no fresh fetched_records.json from this run."
            result["binding_output"] = result["decrypt_output"]
            result["camera_output"] = result["decrypt_output"]
            result["playback_report"] = result["decrypt_output"]

        result["overall_ok"] = bool(
            result["token_ok"]
            and result["search_ok"]
            and result["retrieval_ok"]
            and result["fetch_ok"]
            and result["decrypt_ok"]
            and result["binding_ok"]
            and result["camera_ok"]
            and result["playback_ok"]
        )

        summary_path = run_dir / "web_result_summary.json"
        summary_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

        statuses = build_statuses(gateway_url, cloud_url, camera_url, tee_url)
        return render_page(defaults, result, statuses)

    @app.post("/live-access")
    def live_access():
        gateway_url = request.form.get("gateway_url", default_gateway_url).strip().rstrip("/")
        cloud_url = request.form.get("cloud_url", default_cloud_url).strip().rstrip("/")
        camera_url = request.form.get("camera_url", default_camera_url).strip().rstrip("/")
        tee_url = request.form.get("tee_url", default_tee_url).strip().rstrip("/")
        client_id = request.form.get("client_id", "owner").strip() or "owner"
        camera_id = request.form.get("camera_id", "cam01").strip() or "cam01"
        epoch_text = request.form.get("epoch", "").strip()

        try:
            epoch = int(epoch_text)
        except Exception:
            epoch = get_current_epoch(gateway_url, fallback=1)
            epoch_text = str(epoch)

        try:
            live_timeout = float(request.form.get("live_timeout", "30"))
        except Exception:
            live_timeout = 30.0
        try:
            decrypt_limit = int(request.form.get("decrypt_limit", "1"))
        except Exception:
            decrypt_limit = 1
        try:
            playback_limit = int(request.form.get("playback_limit", "1"))
        except Exception:
            playback_limit = 1

        run_id = time.strftime("%Y%m%d_%H%M%S") + "_live_" + safe_name(client_id) + "_" + safe_name(camera_id)
        run_dir = RUNS_DIR / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        defaults = {
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "camera_url": camera_url,
            "tee_url": tee_url,
            "client_id": client_id,
            "camera_id": camera_id,
            "keywords_text": "",
            "epoch": epoch_text,
            "operator": "AND",
            "fetch_limit": "1",
            "decrypt_limit": str(decrypt_limit),
            "playback_limit": str(playback_limit),
            "live_timeout": str(live_timeout),
            "package_path": "",
        }

        result: dict[str, Any] = {
            "workflow_mode": "live",
            "run_dir": str(run_dir),
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "client_id": client_id,
            "camera_id": camera_id,
            "epoch": epoch,
            "live_start_ok": False,
            "live_fetch_ok": False,
            "decrypt_ok": False,
            "binding_ok": False,
            "camera_ok": False,
            "playback_ok": False,
            "overall_ok": False,
            "result_count": 0,
            "fetched_count": 0,
            "error": "",
        }

        live_start_res = post_json_retry(
            cloud_url + "/live/start",
            {
                "client_id": client_id,
                "camera_id": camera_id,
                "epoch": epoch,
                "gateway_url": gateway_url,
            },
            timeout=30,
            attempts=3,
        )
        live_start_data = live_start_res.data or {"ok": False, "error": live_start_res.error}
        result["live_start_data"] = live_start_data
        result["live_start_ok"] = bool(
            live_start_res.status == 200
            and live_start_data.get("ok")
            and live_start_data.get("fast_path_ready")
        )

        session_id = str(live_start_data.get("session_id", ""))
        if not result["live_start_ok"] or not session_id:
            result["error"] = live_start_data.get("error") or "live start failed"
            return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

        latest_res = poll_live_latest(cloud_url, session_id, timeout_s=live_timeout)
        live_latest_data = latest_res.data or {"ok": False, "error": latest_res.error}
        result["live_latest_data"] = live_latest_data
        record = live_latest_data.get("record")
        rid = str(live_latest_data.get("rid") or "")
        result["live_fetch_ok"] = bool(latest_res.status == 200 and live_latest_data.get("ok") and record and rid)
        result["result_count"] = 1 if result["live_fetch_ok"] else 0
        result["fetched_count"] = 1 if result["live_fetch_ok"] else 0

        json_path = run_dir / "fetched_records.json"
        if result["live_fetch_ok"]:
            fetched_records = [{
                "rid": rid,
                "http_status": latest_res.status,
                "ok": True,
                "response": live_latest_data,
                "record": record,
            }]
            json_path = write_live_fetched_json(
                run_dir=run_dir,
                client_id=client_id,
                camera_id=camera_id,
                epoch=epoch,
                live_start=live_start_data,
                live_latest=live_latest_data,
                fetched_records=fetched_records,
            )
            result["json_path"] = str(json_path)
            run_record_verification_pipeline(
                result,
                json_path=json_path,
                run_dir=run_dir,
                gateway_url=gateway_url,
                client_id=client_id,
                camera_id=camera_id,
                epoch=epoch,
                decrypt_limit=decrypt_limit,
                playback_limit=playback_limit,
            )
        else:
            result["json_path"] = str(json_path)
            result["error"] = live_latest_data.get("error") or "no live record available before timeout"
            result["decrypt_output"] = "Skipped: live fetch failed."
            result["binding_output"] = result["decrypt_output"]
            result["camera_output"] = result["decrypt_output"]
            result["playback_report"] = result["decrypt_output"]

        result["overall_ok"] = bool(
            result["live_start_ok"]
            and result["live_fetch_ok"]
            and result["decrypt_ok"]
            and result["binding_ok"]
            and result["camera_ok"]
            and result["playback_ok"]
        )

        summary_path = run_dir / "web_result_summary.json"
        summary_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

    @app.post("/evidence-verify")
    def evidence_verify():
        gateway_url = request.form.get("gateway_url", default_gateway_url).strip().rstrip("/")
        cloud_url = request.form.get("cloud_url", default_cloud_url).strip().rstrip("/")
        camera_url = request.form.get("camera_url", default_camera_url).strip().rstrip("/")
        tee_url = request.form.get("tee_url", default_tee_url).strip().rstrip("/")
        package_input = request.form.get("package_path", "").strip()

        defaults = {
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "camera_url": camera_url,
            "tee_url": tee_url,
            "client_id": "owner",
            "camera_id": "cam01",
            "keywords_text": "",
            "epoch": str(get_current_epoch(gateway_url, fallback=1)),
            "operator": "AND",
            "fetch_limit": "10",
            "decrypt_limit": "3",
            "playback_limit": "10",
            "live_timeout": "30",
            "package_path": package_input,
        }

        result: dict[str, Any] = {
            "workflow_mode": "evidence",
            "run_dir": "",
            "evidence_retrieval_ok": False,
            "evidence_binding_ok": False,
            "evidence_camera_ok": False,
            "overall_ok": False,
            "error": "",
        }

        if not package_input:
            result["error"] = "package path is required"
            return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

        package_path = Path(package_input).expanduser()
        if not package_path.is_absolute():
            package_path = RUNS_DIR / package_path
        if package_path.is_dir():
            package_path = package_path / "evidence_package.json"

        if not package_path.exists():
            result["error"] = f"evidence package not found: {package_path}"
            return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

        from core.client_tools.verify_evidence_package import verify_retrieval_from_package

        pkg = json.loads(package_path.read_text(encoding="utf-8"))
        result["run_dir"] = str(package_path.parent)
        checks = verify_retrieval_from_package(pkg)
        evidence_checks = [{"name": name, "ok": ok, "message": msg} for name, ok, msg in checks]
        result["evidence_report"] = {"ok": all(c["ok"] for c in evidence_checks), "checks": evidence_checks}
        result["evidence_retrieval_ok"] = bool(result["evidence_report"]["ok"])

        tmp_records = package_path.parent / f".tmp_records_from_{package_path.stem}.json"
        tmp_records.write_text(
            json.dumps(pkg.get("fetched_records", []), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        binding_script = TOOLS_DIR / "record_binding_strict_verify.py"
        bind = run_cmd([sys.executable, str(binding_script), str(tmp_records)], timeout=180)
        binding_output = bind.get("output", "")
        result["evidence_binding_ok"] = binding_ok_from_output(binding_output, bool(bind.get("ok")))
        result["binding_output"] = binding_output

        cam_script = TOOLS_DIR / "camera_origin_verify.py"
        cam = run_cmd([sys.executable, str(cam_script), str(tmp_records)], timeout=180)
        result["evidence_camera_ok"] = bool(cam.get("ok"))
        result["camera_output"] = cam.get("output", "")

        result["overall_ok"] = bool(
            result["evidence_retrieval_ok"]
            and result["evidence_binding_ok"]
            and result["evidence_camera_ok"]
        )
        result["json_path"] = str(tmp_records)
        result["evidence_package_path"] = str(package_path)

        return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

    @app.post("/evidence-verify-run")
    def evidence_verify_run():
        gateway_url = request.form.get("gateway_url", default_gateway_url).strip().rstrip("/")
        cloud_url = request.form.get("cloud_url", default_cloud_url).strip().rstrip("/")
        camera_url = request.form.get("camera_url", default_camera_url).strip().rstrip("/")
        tee_url = request.form.get("tee_url", default_tee_url).strip().rstrip("/")
        client_id = request.form.get("client_id", "owner").strip() or "owner"
        camera_id = request.form.get("camera_id", "cam01").strip() or "cam01"
        source_mode = request.form.get("source_mode", "retrieval").strip() or "retrieval"
        run_dir_raw = request.form.get("run_dir", "").strip()

        try:
            epoch = int(request.form.get("epoch", "1"))
        except Exception:
            epoch = get_current_epoch(gateway_url, fallback=1)

        defaults = {
            "gateway_url": gateway_url,
            "cloud_url": cloud_url,
            "camera_url": camera_url,
            "tee_url": tee_url,
            "client_id": client_id,
            "camera_id": camera_id,
            "keywords_text": "",
            "epoch": str(epoch),
            "operator": "AND",
            "fetch_limit": "10",
            "decrypt_limit": "3",
            "playback_limit": "10",
            "live_timeout": "30",
            "package_path": "",
        }

        if not run_dir_raw:
            result = {"workflow_mode": "evidence-full", "overall_ok": False, "error": "run_dir is required"}
            return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

        run_dir = Path(run_dir_raw).expanduser()
        if not run_dir.is_absolute():
            run_dir = RUNS_DIR / run_dir
        json_path = run_dir / "fetched_records.json"

        if not json_path.exists():
            result = {
                "workflow_mode": "evidence-full",
                "overall_ok": False,
                "error": f"fetched_records.json not found under {run_dir}",
            }
            return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

        result = run_full_evidence_verification(
            run_dir=run_dir,
            json_path=json_path,
            gateway_url=gateway_url,
            client_id=client_id,
            camera_id=camera_id,
            epoch=epoch,
            source_mode=source_mode,
        )
        result["gateway_url"] = gateway_url
        result["cloud_url"] = cloud_url
        result["client_id"] = client_id
        result["camera_id"] = camera_id
        result["epoch"] = epoch

        return render_page(defaults, result, build_statuses(gateway_url, cloud_url, camera_url, tee_url))

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    parser.add_argument("--cloud-url", default=DEFAULT_CLOUD_URL)
    parser.add_argument("--camera-url", default=DEFAULT_CAMERA_URL)
    parser.add_argument("--tee-url", default=DEFAULT_TEE_URL)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    app = create_app(
        default_gateway_url=args.gateway_url.rstrip("/"),
        default_cloud_url=args.cloud_url.rstrip("/"),
        default_camera_url=args.camera_url.rstrip("/"),
        default_tee_url=args.tee_url.rstrip("/"),
    )

    print("[CamShield Web Console]")
    print(f"Gateway URL: {args.gateway_url.rstrip('/')}")
    print(f"Cloud URL  : {args.cloud_url.rstrip('/')}")
    print(f"Camera URL : {args.camera_url.rstrip('/') if args.camera_url else '(not configured)'}")
    print(f"TEE URL    : {args.tee_url.rstrip('/') if args.tee_url else '(not configured)'}")
    print(f"Open       : http://{args.host}:{args.port}")

    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
