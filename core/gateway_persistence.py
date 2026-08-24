from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
import zlib
from collections import deque
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from core.ed25519_sig import load_public_key, public_key_bytes


# Crash-safe append-only runtime transitions for asynchronous archival delivery.
DEFAULT_STATE_PATH = Path(os.environ.get(
    "CAMSHIELD_GATEWAY_STATE",
    ".camshield_gateway_state.json",
))


def gateway_journal_path(path: Path = DEFAULT_STATE_PATH) -> Path:
    path = Path(path)
    return path.with_suffix(path.suffix + ".journal.jsonl")


def gateway_pending_upload_dir(path: Path = DEFAULT_STATE_PATH) -> Path:
    """Directory containing one durable Cloud payload per pending record."""
    path = Path(path)
    return path.parent / f"{path.name}.pending-cloud"


def gateway_transaction_db_path(path: Path = DEFAULT_STATE_PATH) -> Path:
    """SQLite WAL containing atomic ingest recovery events and Cloud payloads."""
    path = Path(path)
    return path.with_suffix(path.suffix + ".transactions.sqlite3")


def _encode_durable_payload(payload_json: bytes) -> tuple[str, bytes]:
    """Compact only the local retry representation, never the Cloud payload."""
    compressed = zlib.compress(payload_json, level=1)
    if len(compressed) + 16 < len(payload_json):
        return "zlib-json-v1", compressed
    return "json-v1", payload_json


def _decode_durable_payload(payload_raw: bytes, codec: str) -> bytes:
    if codec == "json-v1":
        return payload_raw
    if codec == "zlib-json-v1":
        return zlib.decompress(payload_raw)
    raise ValueError(f"unsupported durable payload codec: {codec}")


class GatewayDurableTicket:
    """Completion handle for one terminal-ACK durability boundary."""

    def __init__(self) -> None:
        self._done = threading.Event()
        self.result: dict[str, Any] | None = None
        self.error: BaseException | None = None

    def finish(
        self,
        *,
        result: dict[str, Any] | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self._done.set()

    def wait(self, timeout: float | None = None) -> dict[str, Any]:
        if not self._done.wait(timeout):
            raise TimeoutError("Gateway durable commit timed out")
        if self.error is not None:
            raise RuntimeError("Gateway durable commit failed") from self.error
        return dict(self.result or {})


class GatewayGroupedDurableStore:
    """Group-fsync WAL for protocol transitions and exact Cloud retries.

    Protocol transitions are still prepared in strict checkpoint order. This
    class only combines their physical durability barrier. Every ticket is
    completed after the SQLite transaction containing its exact event and
    protected Cloud payload commits successfully.
    """

    MODE = "sqlite-group-wal-v1"

    def __init__(
        self,
        path: Path = DEFAULT_STATE_PATH,
        *,
        batch_max: int = 16,
        batch_wait_ms: float = 2.0,
    ) -> None:
        self.state_path = Path(path)
        self.db_path = gateway_transaction_db_path(self.state_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Larger groups preserve the same ACK-after-commit boundary while
        # amortizing one SD-card flush over more independent transitions.
        self.batch_max = max(1, min(128, int(batch_max)))
        self.batch_wait_s = max(0.0, min(0.050, float(batch_wait_ms) / 1000.0))
        self._condition = threading.Condition()
        self._operations: deque[dict[str, Any]] = deque()
        self._pending_ingest = 0
        self._fatal_error: BaseException | None = None
        self._initialize_database()
        self._thread = threading.Thread(
            target=self._run,
            name="camshield-gateway-durable-commit",
            daemon=True,
        )
        self._thread.start()

    @property
    def fatal_error(self) -> BaseException | None:
        with self._condition:
            return self._fatal_error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA busy_timeout=30000")
        # The default 1,000-page checkpoint fires on the ingest writer often
        # enough to create avoidable latency spikes. A committed WAL remains
        # crash-recoverable; this only defers checkpoint work out of the hot
        # ACK path.
        connection.execute("PRAGMA wal_autocheckpoint=16384")
        connection.execute("PRAGMA journal_size_limit=134217728")
        return connection

    def _initialize_database(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS ingest_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rid TEXT NOT NULL UNIQUE,
                    event_json BLOB NOT NULL,
                    payload_json BLOB,
                    payload_codec TEXT NOT NULL DEFAULT 'json-v1',
                    payload_bytes INTEGER NOT NULL,
                    uploaded INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_ingest_uploaded "
                "ON ingest_transactions(uploaded, id)"
            )
            columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(ingest_transactions)")
            }
            if "payload_codec" not in columns:
                connection.execute(
                    "ALTER TABLE ingest_transactions "
                    "ADD COLUMN payload_codec TEXT NOT NULL DEFAULT 'json-v1'"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS durable_metadata ("
                "key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT OR IGNORE INTO durable_metadata(key, value) "
                "VALUES ('uploaded_total', 0)"
            )
        finally:
            connection.close()

    def submit_ingest(self, event: dict[str, Any]) -> GatewayDurableTicket:
        pending = event.get("pending_upload")
        if not isinstance(pending, dict) or not isinstance(
            pending.get("payload"), dict
        ):
            raise ValueError("grouped durable ingest requires an inline payload")
        rid = str(pending["rid"])
        payload_json = json.dumps(
            pending["payload"],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        payload_codec, durable_payload = _encode_durable_payload(payload_json)
        event_copy = dict(event)
        pending_copy = dict(pending)
        pending_copy.pop("payload", None)
        pending_copy["payload_store"] = self.MODE
        pending_copy["payload_bytes"] = len(payload_json)
        event_copy["pending_upload"] = pending_copy
        event_json = json.dumps(
            event_copy,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        pending["payload_store"] = self.MODE
        pending["payload_bytes"] = len(payload_json)

        ticket = GatewayDurableTicket()
        operation = {
            "kind": "ingest",
            "rid": rid,
            "event_json": event_json,
            "payload_json": durable_payload,
            "payload_codec": payload_codec,
            "payload_bytes": len(payload_json),
            "created_at": float(pending.get("created_at", time.time())),
            "submitted_at": time.perf_counter(),
            "ticket": ticket,
        }
        with self._condition:
            if self._fatal_error is not None:
                raise RuntimeError("Gateway durable store is unavailable") from self._fatal_error
            self._operations.append(operation)
            self._pending_ingest += 1
            self._condition.notify()
        return ticket

    def mark_uploaded(self, rids: list[str]) -> None:
        normalized = [str(rid) for rid in rids if str(rid)]
        if not normalized:
            return
        with self._condition:
            if self._fatal_error is not None:
                return
            self._operations.append({"kind": "uploaded", "rids": normalized})
            self._condition.notify()

    def flush(self, timeout: float = 30.0) -> None:
        ticket = GatewayDurableTicket()
        with self._condition:
            if self._fatal_error is not None:
                raise RuntimeError("Gateway durable store is unavailable") from self._fatal_error
            self._operations.append({"kind": "barrier", "ticket": ticket})
            self._condition.notify()
        ticket.wait(timeout)

    def close(self, timeout: float = 5.0) -> None:
        ticket = GatewayDurableTicket()
        with self._condition:
            if self._fatal_error is not None:
                self._thread.join(timeout=timeout)
                return
            self._operations.append({"kind": "stop", "ticket": ticket})
            self._condition.notify()
        ticket.wait(timeout)
        self._thread.join(timeout=timeout)

    def prune_uploaded(self) -> None:
        self.flush()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM ingest_transactions WHERE uploaded = 1"
            )
            connection.execute("COMMIT")
            connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            connection.close()

    def metrics(self) -> dict[str, Any]:
        files = [
            self.db_path,
            Path(str(self.db_path) + "-wal"),
            Path(str(self.db_path) + "-shm"),
        ]
        total_bytes = 0
        for item in files:
            try:
                total_bytes += item.stat().st_size
            except FileNotFoundError:
                pass
        with self._condition:
            queued = len(self._operations)
            pending_ingest = self._pending_ingest
        return {
            "gateway_transaction_store_bytes": total_bytes,
            "gateway_durable_commit_queue_depth": queued,
            "gateway_durable_commit_pending_ingest": pending_ingest,
            "gateway_durable_batch_max": self.batch_max,
            "gateway_durable_batch_wait_ms": int(self.batch_wait_s * 1000),
            "gateway_durable_payload_codec": "zlib-json-v1-if-smaller",
        }

    def _take_batch(self) -> list[dict[str, Any]]:
        with self._condition:
            while not self._operations:
                self._condition.wait(timeout=1.0)
            deadline = time.monotonic() + self.batch_wait_s
            while len(self._operations) < self.batch_max:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
            batch = []
            while self._operations and len(batch) < self.batch_max:
                batch.append(self._operations.popleft())
            return batch

    def _run(self) -> None:
        connection = self._connect()
        try:
            while True:
                batch = self._take_batch()
                started = time.perf_counter()
                ingest_operations = [
                    item for item in batch if item.get("kind") == "ingest"
                ]
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    for operation in batch:
                        kind = operation.get("kind")
                        if kind == "ingest":
                            connection.execute(
                                """
                                INSERT INTO ingest_transactions(
                                    rid, event_json, payload_json, payload_codec,
                                    payload_bytes, uploaded, created_at
                                ) VALUES (?, ?, ?, ?, ?, 0, ?)
                                """,
                                (
                                    operation["rid"],
                                    operation["event_json"],
                                    operation["payload_json"],
                                    operation["payload_codec"],
                                    operation["payload_bytes"],
                                    operation["created_at"],
                                ),
                            )
                        elif kind == "uploaded":
                            changes_before = connection.total_changes
                            connection.executemany(
                                "UPDATE ingest_transactions SET "
                                "uploaded = 1, payload_json = NULL "
                                "WHERE rid = ? AND uploaded = 0",
                                [(rid,) for rid in operation["rids"]],
                            )
                            newly_uploaded = (
                                connection.total_changes - changes_before
                            )
                            if newly_uploaded:
                                connection.execute(
                                    "UPDATE durable_metadata SET value = value + ? "
                                    "WHERE key = 'uploaded_total'",
                                    (newly_uploaded,),
                                )
                    connection.execute("COMMIT")
                    elapsed_ms = (time.perf_counter() - started) * 1000.0
                    batch_records = len(ingest_operations)
                    for operation in batch:
                        ticket = operation.get("ticket")
                        if not isinstance(ticket, GatewayDurableTicket):
                            continue
                        ticket.finish(result={
                            "gateway_durable_batch_commit_ms": elapsed_ms,
                            "gateway_durable_batch_records": batch_records,
                            "gateway_durable_commit_amortized_ms": (
                                elapsed_ms / max(1, batch_records)
                            ),
                            "gateway_durable_queue_wait_ms": (
                                (time.perf_counter() - operation.get(
                                    "submitted_at", started
                                )) * 1000.0
                                if operation.get("kind") == "ingest"
                                else 0.0
                            ),
                        })
                    with self._condition:
                        self._pending_ingest = max(
                            0, self._pending_ingest - batch_records
                        )
                    if any(item.get("kind") == "stop" for item in batch):
                        return
                except BaseException as exc:
                    try:
                        connection.execute("ROLLBACK")
                    except Exception:
                        pass
                    with self._condition:
                        self._fatal_error = exc
                        self._pending_ingest = max(
                            0, self._pending_ingest - len(ingest_operations)
                        )
                    for operation in batch:
                        ticket = operation.get("ticket")
                        if isinstance(ticket, GatewayDurableTicket):
                            ticket.finish(error=exc)
                    with self._condition:
                        while self._operations:
                            operation = self._operations.popleft()
                            ticket = operation.get("ticket")
                            if isinstance(ticket, GatewayDurableTicket):
                                ticket.finish(error=exc)
                    return
        finally:
            connection.close()


def _pending_payload_name(rid: str) -> str:
    safe = "".join(ch for ch in str(rid) if ch.isalnum() or ch in "-_.")
    if not safe or safe != str(rid) or len(safe) > 160:
        safe = hashlib.sha256(str(rid).encode("utf-8")).hexdigest()
    return f"{safe}.json"


def _pending_payload_path(item: dict[str, Any], path: Path) -> Path:
    name = str(item.get("payload_file") or _pending_payload_name(str(item["rid"])))
    if Path(name).name != name:
        raise ValueError("invalid pending Cloud payload filename")
    return gateway_pending_upload_dir(path) / name


def externalize_pending_upload_payload(
    item: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
    *,
    staged: bool = False,
) -> dict[str, Any]:
    """Persist a queued Cloud payload separately from the compact journal."""
    path = Path(path)
    if item.get("payload_store") == GatewayGroupedDurableStore.MODE:
        return item
    payload = item.get("payload")
    if payload is None:
        return item
    directory = gateway_pending_upload_dir(path)
    directory.mkdir(parents=True, exist_ok=True)
    payload_path = directory / _pending_payload_name(str(item["rid"]))
    staged_path = payload_path.with_suffix(payload_path.suffix + ".staged")
    temp = staged_path.with_suffix(staged_path.suffix + ".tmp")
    envelope = {
        "type": "camshield-pending-cloud-v2",
        "rid": str(item["rid"]),
        "segment_key": str(item.get("segment_key", "")),
        "created_at": float(item.get("created_at", 0.0)),
        "attempts": int(item.get("attempts", 0)),
        "last_error": str(item.get("last_error", "")),
        "payload": payload,
    }
    encoded = json.dumps(
        envelope,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        _write_all(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    temp.replace(staged_path)
    if not staged:
        staged_path.replace(payload_path)
    if not staged:
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    # A staged file is deliberately not recoverable yet. Its content is
    # already fsynced above; directory durability is required only after the
    # ingest journal is fsynced and commit_staged_pending_upload_payload()
    # publishes it. Skipping this pre-commit directory fsync preserves the
    # ACK-after-durable-enqueue invariant while removing one needless sync.
    item.pop("payload", None)
    item["payload_file"] = payload_path.name
    item["payload_bytes"] = len(encoded)
    if staged:
        item["staged_payload_file"] = staged_path.name
    else:
        item.pop("staged_payload_file", None)
    return item


def commit_staged_pending_upload_payload(
    item: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    """Publish a payload only after its ingest journal record is durable."""
    path = Path(path)
    payload_path = _pending_payload_path(item, path)
    staged_name = str(
        item.get("staged_payload_file") or f"{payload_path.name}.staged"
    )
    if Path(staged_name).name != staged_name:
        raise ValueError("invalid staged pending Cloud payload filename")
    staged_path = payload_path.parent / staged_name
    if not payload_path.exists():
        # A later durable Cloud acknowledgement is represented by removal of
        # the payload file. Replaying the older ingest event must not recreate
        # or requeue that already-acknowledged upload.
        if not staged_path.exists():
            item.pop("staged_payload_file", None)
            return
        staged_path.replace(payload_path)
    item.pop("staged_payload_file", None)
    directory_fd = os.open(payload_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def load_pending_upload_payload(
    item: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
) -> dict[str, Any]:
    payload = item.get("payload")
    if isinstance(payload, dict):
        return payload
    payload_path = _pending_payload_path(item, Path(path))
    stored = json.loads(payload_path.read_text(encoding="utf-8"))
    if (
        isinstance(stored, dict)
        and stored.get("type") == "camshield-pending-cloud-v2"
    ):
        payload = stored.get("payload")
        if not isinstance(payload, dict):
            raise ValueError("invalid pending Cloud payload envelope")
        return payload
    # Backward compatibility with the original payload-only spool files.
    if not isinstance(stored, dict):
        raise ValueError("invalid pending Cloud payload")
    return stored


def recover_pending_uploads(
    path: Path = DEFAULT_STATE_PATH,
    defaults: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Rebuild the in-memory O(1) queue index from durable payload files."""
    path = Path(path)
    directory = gateway_pending_upload_dir(path)
    defaults = defaults or {}
    recovered: dict[str, dict[str, Any]] = {}
    if not directory.is_dir():
        return recovered

    for payload_path in sorted(directory.glob("*.json")):
        try:
            stored = json.loads(payload_path.read_text(encoding="utf-8"))
            if (
                isinstance(stored, dict)
                and stored.get("type") == "camshield-pending-cloud-v2"
            ):
                rid = str(stored["rid"])
                item = {
                    "rid": rid,
                    "segment_key": str(stored.get("segment_key", "")),
                    "created_at": float(stored.get("created_at", 0.0)),
                    "attempts": int(stored.get("attempts", 0)),
                    "last_error": str(stored.get("last_error", "")),
                }
            else:
                # Legacy files contain only the /store-batch payload.
                records = stored.get("records", []) if isinstance(stored, dict) else []
                rid = str(records[0].get("rid", payload_path.stem)) if records else payload_path.stem
                item = dict(defaults.get(rid, {}))
                item.setdefault("rid", rid)
                item.setdefault("segment_key", "")
                item.setdefault("created_at", 0.0)
                item.setdefault("attempts", 0)
                item.setdefault("last_error", "")
            item["payload_file"] = payload_path.name
            item["payload_bytes"] = payload_path.stat().st_size
            recovered[rid] = item
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"invalid pending Cloud spool file: {payload_path}"
            ) from exc
    return recovered


def remove_pending_upload_payload(
    item: dict[str, Any] | None,
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    if (
        not isinstance(item, dict)
        or item.get("payload_store") == GatewayGroupedDurableStore.MODE
        or not item.get("payload_file")
    ):
        return
    payload_path = _pending_payload_path(item, Path(path))
    try:
        payload_path.unlink()
    except FileNotFoundError:
        return
    directory_fd = os.open(payload_path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def externalize_pending_uploads(
    state: dict[str, Any] | None,
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    if state is None:
        return
    for item in state.setdefault("pending_cloud_uploads", {}).values():
        if isinstance(item, dict):
            externalize_pending_upload_payload(item, Path(path))


def gateway_persistence_metrics(
    path: Path = DEFAULT_STATE_PATH,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return bounded persistence sizes without loading protocol state."""
    path = Path(path)
    journal = gateway_journal_path(path)
    pending_dir = gateway_pending_upload_dir(path)
    pending_file_count = int(
        state.get("_pending_cloud_payload_count", -1)
        if state is not None
        else -1
    )
    pending_file_bytes = int(
        state.get("_pending_cloud_payload_bytes", -1)
        if state is not None
        else -1
    )
    cached_metrics = pending_file_count >= 0 and pending_file_bytes >= 0
    if not cached_metrics:
        pending_file_count = 0
        pending_file_bytes = 0
    if not cached_metrics and pending_dir.is_dir():
        for item in pending_dir.glob("*.json"):
            try:
                if not item.is_file():
                    continue
                size = item.stat().st_size
            except FileNotFoundError:
                # The upload worker may acknowledge and remove a payload
                # between directory enumeration and stat(). Health metrics
                # must tolerate that normal transition.
                continue
            pending_file_count += 1
            pending_file_bytes += size
    result = {
        "gateway_state_bytes": path.stat().st_size if path.exists() else 0,
        "gateway_journal_bytes": journal.stat().st_size if journal.exists() else 0,
        "pending_cloud_payload_count": pending_file_count,
        "pending_cloud_payload_bytes": pending_file_bytes,
    }
    durable_store = state.get("_gateway_durable_store") if state else None
    if isinstance(durable_store, GatewayGroupedDurableStore):
        result.update(durable_store.metrics())
    return result


def _write_all(fd: int, data: bytes) -> int:
    """Write the complete journal record even if the OS returns a short write."""
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("Gateway journal write made no progress")
        offset += written
    return offset


def _b64e(x: bytes) -> str:
    return base64.b64encode(x).decode("ascii")


def _b64d(x: str) -> bytes:
    return base64.b64decode(x.encode("ascii"))


def _sk_to_raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_simple(v: Any):
    if isinstance(v, bytes):
        return {"__type__": "bytes", "b64": _b64e(v)}

    if isinstance(v, (str, int, float, bool)) or v is None:
        return v

    if isinstance(v, list):
        out = []
        for x in v:
            sx = _serialize_simple(x)
            if sx is not None:
                out.append(sx)
        return {"__type__": "list", "items": out}

    if isinstance(v, tuple):
        out = []
        for x in v:
            sx = _serialize_simple(x)
            if sx is not None:
                out.append(sx)
        return {"__type__": "tuple", "items": out}

    if isinstance(v, set):
        out = []
        for x in sorted(v, key=str):
            sx = _serialize_simple(x)
            if sx is not None:
                out.append(sx)
        return {"__type__": "set", "items": out}

    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if not isinstance(k, (str, int, float, bool)):
                continue
            sx = _serialize_simple(x)
            if sx is not None:
                out[str(k)] = sx
        return {"__type__": "dict", "items": out}

    return None


def _deserialize_simple(v: Any):
    if isinstance(v, dict) and "__type__" in v:
        t = v["__type__"]

        if t == "bytes":
            return _b64d(v["b64"])

        if t == "list":
            return [_deserialize_simple(x) for x in v.get("items", [])]

        if t == "tuple":
            return tuple(_deserialize_simple(x) for x in v.get("items", []))

        if t == "set":
            return {_deserialize_simple(x) for x in v.get("items", [])}

        if t == "dict":
            out = {}
            for k, x in v.get("items", {}).items():
                                                            
                                                                                  
                if isinstance(k, str) and k.isdigit():
                    kk = int(k)
                else:
                    kk = k
                out[kk] = _deserialize_simple(x)
            return out

    return v


def _serialize_epoch_manager(epoch_manager: Any) -> dict[str, Any]:
    """
    Persist epoch and index-key state.

    This catches bytes/int fields such as Kidx, Krid, EKe, current_epoch,
    current_version, etc., without trying to serialize Charm ABE objects.
    """
    if epoch_manager is None or not hasattr(epoch_manager, "__dict__"):
        return {}

    out = {}
    for k, v in vars(epoch_manager).items():
        if k.startswith("_") and not isinstance(v, (bytes, int, str, bool, dict, list, tuple)):
            continue
        sv = _serialize_simple(v)
        if sv is not None:
            out[k] = sv

    return out


def _restore_epoch_manager(epoch_manager: Any, data: dict[str, Any]) -> None:
    if epoch_manager is None:
        return

    for k, v in data.items():
        try:
            setattr(epoch_manager, k, _deserialize_simple(v))
        except Exception:
            pass


def _serialize_camera_registry(gateway: Any) -> dict[str, Any]:
    registry = getattr(gateway, "camera_registry", None)
    cameras = getattr(registry, "cameras", {}) if registry is not None else {}

    out = {}
    for cid, entry in cameras.items():
        pk = getattr(entry, "public_key", None)
        last_gamma = getattr(entry, "last_gamma", b"\x00" * 32)
        expected_seq = getattr(entry, "expected_seq", 1)

        if pk is None:
            continue

        out[str(cid)] = {
            "public_key_b64": _b64e(public_key_bytes(pk)),
            "last_gamma_b64": _b64e(last_gamma),
            "expected_seq": int(expected_seq),
        }

    return out


def _restore_camera_registry(gateway: Any, camera_registry_data: dict[str, Any], state: dict[str, Any] | None) -> None:
    if state is not None:
        state.setdefault("camera_public_keys", {})
        state.setdefault("enrolled", set())

    for cid, item in camera_registry_data.items():
        try:
            pk_raw = _b64d(item["public_key_b64"])
            pk = load_public_key(pk_raw)
            last_gamma = _b64d(item.get("last_gamma_b64", _b64e(b"\x00" * 32)))
            expected_seq = int(item.get("expected_seq", 1))

            gateway.enroll_camera(
                cid=str(cid),
                camera_public_key=pk,
                initial_gamma=last_gamma,
                expected_seq=expected_seq,
            )

            if state is not None:
                state["camera_public_keys"][str(cid)] = item["public_key_b64"]
                state["enrolled"].add(str(cid))

        except Exception as exc:
            print(f"[PERSIST] failed to restore camera {cid}: {exc}")


def _serialize_abe(gateway: Any) -> dict[str, Any]:
    abe = getattr(gateway, "abe", None)
    mpk = getattr(gateway, "mpk", None)
    msk = getattr(gateway, "msk", None)
    if abe is None or mpk is None or msk is None:
        return {}

    group = getattr(abe, "group", None)
    if group is not None:
        from charm.core.engine.util import objectToBytes

        return {
            "type": "charm-object-bytes-v1",
            "group_name": getattr(abe, "group_name", "SS512"),
            "mpk_b64": _b64e(objectToBytes(mpk, group)),
            "msk_b64": _b64e(objectToBytes(msk, group)),
        }

    return {
        "type": "simple-v1",
        "mpk": _serialize_simple(mpk),
        "msk": _serialize_simple(msk),
    }


def _restore_abe(gateway: Any, data: dict[str, Any]) -> None:
    if not data:
        return

    abe = getattr(gateway, "abe", None)
    if data.get("type") == "charm-object-bytes-v1":
        if abe is None or getattr(abe, "group", None) is None:
            raise RuntimeError("saved Charm ABE state requires Charm backend")
        from charm.core.engine.util import bytesToObject

        gateway.mpk = bytesToObject(_b64d(data["mpk_b64"]), abe.group)
        gateway.msk = bytesToObject(_b64d(data["msk_b64"]), abe.group)
    elif data.get("type") == "simple-v1":
        gateway.mpk = _deserialize_simple(data.get("mpk"))
        gateway.msk = _deserialize_simple(data.get("msk"))

    if abe is not None:
        abe.mpk = gateway.mpk
        abe.msk = gateway.msk


PERSISTED_RUNTIME_KEYS = (
    "record_count",
    "last_checkpoint",
    "last_ordered_checkpoint",
    "cloud_uploads",
    "last_cloud_upload",
    "live_cloud_uploads",
    "last_live_cloud_upload",
    "last_cloud_error",
    "token_to_record_ids",
    "token_to_record_ids_by_epoch",
    "ordered_checkpoint_version",
    "ordered_checkpoint_version_by_epoch",
    "last_checkpoint_chain_by_epoch",
    "final_epoch_checkpoints",
    "revoked_clients",
    "client_leases",
    "accepted_segments",
    "record_catalog",
    "live_fast_path_sessions",
    "live_fast_path_cameras",
)


def _serialize_runtime_state(state: dict[str, Any] | None) -> dict[str, Any]:
    if state is None:
        return {}
    out = {}
    for key in PERSISTED_RUNTIME_KEYS:
        if key in state:
            value = _serialize_simple(state[key])
            if value is not None:
                out[key] = value
    return out


def _restore_runtime_state(state: dict[str, Any] | None, data: dict[str, Any]) -> None:
    if state is None:
        return
    for key, value in data.items():
        state[key] = _deserialize_simple(value)


def _checkpoint_is_newer(candidate: dict[str, Any], current: Any) -> bool:
    if not isinstance(current, dict):
        return True
    candidate_key = (
        int(candidate.get("epoch", 0)),
        int(candidate.get("version", 0)),
    )
    current_key = (
        int(current.get("epoch", 0)),
        int(current.get("version", 0)),
    )
    return candidate_key >= current_key


def _apply_gateway_journal_event(
    gateway: Any,
    state: dict[str, Any],
    event: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    event_type = str(event.get("type", ""))
    if event_type == "ingest-commit-v1":
        cid = str(event["camera_id"])
        entry = gateway.camera_registry.cameras.get(cid)
        if entry is not None:
            expected_seq = int(event["expected_seq"])
            if expected_seq >= int(entry.expected_seq):
                entry.expected_seq = expected_seq
                entry.last_gamma = bytes.fromhex(str(event["last_gamma_hex"]))

        state["record_count"] = max(
            int(state.get("record_count", 0)),
            int(event.get("record_count", 0)),
        )
        checkpoint = dict(event["signed_checkpoint"])
        if _checkpoint_is_newer(
            checkpoint, state.get("last_ordered_checkpoint")
        ):
            state["last_checkpoint"] = checkpoint
            state["last_ordered_checkpoint"] = checkpoint

        epoch = int(checkpoint["epoch"])
        version = int(checkpoint["version"])
        epoch_key = str(epoch)
        versions = state.setdefault("ordered_checkpoint_version_by_epoch", {})
        versions[epoch_key] = max(int(versions.get(epoch_key, 0)), version)
        state["ordered_checkpoint_version"] = max(
            int(state.get("ordered_checkpoint_version", 0)), version
        )
        state.setdefault("last_checkpoint_chain_by_epoch", {})[epoch_key] = str(
            checkpoint["chain_hex"]
        )

        by_epoch = state.setdefault("token_to_record_ids_by_epoch", {})
        epoch_map = by_epoch.setdefault(epoch_key, {})
        for update in event.get("posting_updates", []):
            token = str(update["token"])
            rid = str(update["rid"])
            posting = epoch_map.setdefault(token, set())
            if not isinstance(posting, set):
                posting = set(posting)
                epoch_map[token] = posting
            posting.add(rid)
        state["token_to_record_ids"] = epoch_map

        segment_key = str(event["segment_key"])
        response = dict(event["response"])
        state.setdefault("accepted_segments", {})[segment_key] = response
        catalog = dict(event["catalog"])
        state.setdefault("record_catalog", {})[str(catalog["rid"])] = catalog

        pending = dict(event["pending_upload"])
        if pending.get("payload_store") == GatewayGroupedDurableStore.MODE:
            if isinstance(pending.get("payload"), dict):
                state.setdefault("pending_cloud_uploads", {})[
                    str(pending["rid"])
                ] = pending
            return
        if pending.get("staged_payload_file"):
            commit_staged_pending_upload_payload(pending, Path(path))
        else:
            externalize_pending_upload_payload(pending, Path(path))
        payload_path = _pending_payload_path(pending, Path(path))
        if payload_path.exists():
            state.setdefault("pending_cloud_uploads", {})[
                str(pending["rid"])
            ] = pending
        return

    if event_type == "cloud-upload-ack-v1":
        rid = str(event["rid"])
        pending = state.setdefault("pending_cloud_uploads", {}).pop(rid, None)
        remove_pending_upload_payload(pending, Path(path))
        state["cloud_uploads"] = max(
            int(state.get("cloud_uploads", 0)),
            int(event.get("cloud_uploads", 0)),
        )
        state["last_cloud_upload"] = event.get("last_cloud_upload")
        state["last_cloud_error"] = None
        segment_key = str(event.get("segment_key", ""))
        accepted = state.setdefault("accepted_segments", {}).get(segment_key)
        if isinstance(accepted, dict):
            accepted["cloud_upload"] = event.get("cloud_result", {})
        return


def replay_gateway_transaction_store(
    gateway: Any,
    state: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
) -> dict[str, int]:
    """Replay committed grouped-WAL transitions in strict database order."""
    db_path = gateway_transaction_db_path(Path(path))
    if not db_path.exists():
        return {
            "transaction_events": 0,
            "pending_payloads": 0,
            "pending_payload_bytes": 0,
            "uploaded_events": 0,
        }
    connection = sqlite3.connect(str(db_path), timeout=30.0)
    transaction_events = 0
    pending_payloads = 0
    pending_payload_bytes = 0
    uploaded_events = 0
    try:
        metadata_row = connection.execute(
            "SELECT value FROM durable_metadata WHERE key = 'uploaded_total'"
        ).fetchone()
        uploaded_total = int(metadata_row[0]) if metadata_row else 0
        rows = connection.execute(
            "SELECT event_json, payload_json, payload_codec, payload_bytes, uploaded "
            "FROM ingest_transactions ORDER BY id"
        )
        for event_raw, payload_raw, payload_codec, payload_bytes, uploaded in rows:
            event = json.loads(bytes(event_raw).decode("utf-8"))
            pending = event.get("pending_upload")
            if isinstance(pending, dict):
                pending["payload_store"] = GatewayGroupedDurableStore.MODE
                pending["payload_bytes"] = int(payload_bytes or 0)
                if not int(uploaded) and payload_raw is not None:
                    pending["payload"] = json.loads(
                        _decode_durable_payload(
                            bytes(payload_raw),
                            str(payload_codec or "json-v1"),
                        ).decode("utf-8")
                    )
                    pending_payloads += 1
                    pending_payload_bytes += int(payload_bytes or 0)
                else:
                    uploaded_events += 1
            _apply_gateway_journal_event(gateway, state, event, Path(path))
            transaction_events += 1
        state["cloud_uploads"] = max(
            int(state.get("cloud_uploads", 0)), uploaded_total
        )
        state["_pending_cloud_payload_count"] = pending_payloads
        state["_pending_cloud_payload_bytes"] = pending_payload_bytes
    finally:
        connection.close()
    return {
        "transaction_events": transaction_events,
        "pending_payloads": pending_payloads,
        "pending_payload_bytes": pending_payload_bytes,
        "uploaded_events": uploaded_events,
    }


def append_gateway_journal_event(
    event: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
    *,
    timings: dict[str, float] | None = None,
) -> int:
    """Durably append one idempotent Gateway runtime transition."""
    if str(event.get("type", "")) == "ingest-commit-v1":
        pending = event.get("pending_upload")
        if isinstance(pending, dict):
            started = time.perf_counter()
            externalize_pending_upload_payload(
                pending,
                Path(path),
                staged=True,
            )
            if timings is not None:
                timings["gateway_pending_stage_ms"] = (
                    time.perf_counter() - started
                ) * 1000.0
    journal = gateway_journal_path(path)
    journal.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    encoded = (
        json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if timings is not None:
        timings["gateway_journal_encode_ms"] = (
            time.perf_counter() - started
        ) * 1000.0
    started = time.perf_counter()
    fd = os.open(journal, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        written = _write_all(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    if timings is not None:
        timings["gateway_journal_append_fsync_ms"] = (
            time.perf_counter() - started
        ) * 1000.0
    if str(event.get("type", "")) == "ingest-commit-v1":
        pending = event.get("pending_upload")
        if isinstance(pending, dict):
            started = time.perf_counter()
            commit_staged_pending_upload_payload(pending, Path(path))
            if timings is not None:
                timings["gateway_pending_publish_ms"] = (
                    time.perf_counter() - started
                ) * 1000.0
    return written


def replay_gateway_journal(
    gateway: Any,
    state: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
) -> int:
    journal = gateway_journal_path(path)
    if not journal.exists():
        return 0
    count = 0
    truncate_at: int | None = None
    with journal.open("rb") as handle:
        line_number = 0
        while True:
            line_start = handle.tell()
            raw_bytes = handle.readline()
            if not raw_bytes:
                break
            line_number += 1
            if not raw_bytes.endswith(b"\n"):
                truncate_at = line_start
                break
            try:
                raw = raw_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise RuntimeError(
                    f"invalid Gateway journal encoding at line {line_number}"
                ) from exc
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"invalid Gateway journal entry at line {line_number}"
                ) from exc
            _apply_gateway_journal_event(gateway, state, event, Path(path))
            count += 1
    if truncate_at is not None:
        fd = os.open(journal, os.O_WRONLY)
        try:
            os.ftruncate(fd, truncate_at)
            os.fsync(fd)
        finally:
            os.close(fd)
    accepted = state.setdefault("accepted_segments", {})
    if len(accepted) > 5000:
        for key in list(accepted)[:-5000]:
            accepted.pop(key, None)
    catalog = state.setdefault("record_catalog", {})
    if len(catalog) > 5000:
        for rid in list(catalog)[:-5000]:
            catalog.pop(rid, None)
    return count


def compact_gateway_journal(
    gateway: Any,
    state: dict[str, Any],
    path: Path = DEFAULT_STATE_PATH,
) -> None:
    """Snapshot current state, then atomically replace the replay journal."""
    durable_store = state.get("_gateway_durable_store")
    if isinstance(durable_store, GatewayGroupedDurableStore):
        durable_store.flush()
    save_gateway_state(gateway, state, path)
    journal = gateway_journal_path(path)
    journal.parent.mkdir(parents=True, exist_ok=True)
    tmp = journal.with_suffix(journal.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp.replace(journal)
    directory_fd = os.open(journal.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if isinstance(durable_store, GatewayGroupedDurableStore):
        # The durable snapshot now contains every uploaded transition. Keep
        # only rows whose exact Cloud payload may still need retrying.
        durable_store.prune_uploaded()


def save_gateway_state(gateway: Any, state: dict[str, Any] | None = None, path: Path = DEFAULT_STATE_PATH) -> None:
    path = Path(path)
    externalize_pending_uploads(state, path)

    data = {
        "type": "camshield-gateway-state-v1",
        "gateway_signing_key_raw_b64": _b64e(_sk_to_raw(gateway.skG)),
        "gateway_public_key_b64": _b64e(public_key_bytes(gateway.pkG)),
        "abe": _serialize_abe(gateway),
        "epoch_manager": _serialize_epoch_manager(getattr(gateway, "epoch_manager", None)),
        "camera_registry": _serialize_camera_registry(gateway),
        "runtime_state": _serialize_runtime_state(state),
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        _write_all(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    tmp.replace(path)
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(f"[PERSIST] saved Gateway state to {path}")


def load_or_init_gateway_state(gateway: Any, state: dict[str, Any] | None = None, path: Path = DEFAULT_STATE_PATH) -> None:
    path = Path(path)

    if not path.exists():
        print(f"[PERSIST] no existing state at {path}; creating a new one")
        save_gateway_state(gateway, state, path)
        return

    data = json.loads(path.read_text(encoding="utf-8"))

    raw_sk = _b64d(data["gateway_signing_key_raw_b64"])
    gateway.skG = Ed25519PrivateKey.from_private_bytes(raw_sk)
    gateway.pkG = gateway.skG.public_key()

    _restore_abe(gateway, data.get("abe", {}))
    _restore_epoch_manager(
        getattr(gateway, "epoch_manager", None),
        data.get("epoch_manager", {}),
    )

    _restore_camera_registry(
        gateway,
        data.get("camera_registry", {}),
        state,
    )
    _restore_runtime_state(state, data.get("runtime_state", {}))
    legacy_pending = dict(state.get("pending_cloud_uploads", {}))
    externalize_pending_uploads(state, path)

    replayed = 0
    if state is not None:
        replayed = replay_gateway_journal(gateway, state, path)
        state["pending_cloud_uploads"] = recover_pending_uploads(
            path,
            defaults={
                **legacy_pending,
                **state.get("pending_cloud_uploads", {}),
            },
        )
        state["_pending_cloud_payload_count"] = len(
            state["pending_cloud_uploads"]
        )
        state["_pending_cloud_payload_bytes"] = sum(
            int(item.get("payload_bytes", 0))
            for item in state["pending_cloud_uploads"].values()
        )
        # The legacy file spool represents Cloud acknowledgement by deleting
        # one payload file. The grouped durable store keeps payloads and
        # acknowledgements in its SQLite WAL, whose replay routine is the sole
        # source of that count. Applying the legacy approximation would
        # misclassify pending records as uploaded after a restart.
        if not gateway_transaction_db_path(path).exists():
            state["cloud_uploads"] = max(
                int(state.get("cloud_uploads", 0)),
                int(state.get("record_count", 0))
                - len(state["pending_cloud_uploads"]),
            )

    print(
        f"[PERSIST] loaded Gateway state from {path}; "
        f"journal_events={replayed}"
    )
