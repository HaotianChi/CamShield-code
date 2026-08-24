"""SQLite persistence for the long-running CamShield Cloud service."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA auto_vacuum=INCREMENTAL;

CREATE TABLE IF NOT EXISTS records (
    rid TEXT PRIMARY KEY,
    epoch INTEGER NOT NULL,
    camera_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    is_live INTEGER NOT NULL DEFAULT 0,
    record_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_epoch ON records(epoch);
CREATE INDEX IF NOT EXISTS idx_records_range
    ON records(camera_id, timestamp, seq);

CREATE TABLE IF NOT EXISTS postings (
    epoch INTEGER NOT NULL,
    token TEXT NOT NULL,
    rid TEXT NOT NULL,
    PRIMARY KEY (epoch, token, rid),
    FOREIGN KEY (rid) REFERENCES records(rid) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_postings_lookup ON postings(epoch, token);
-- SQLite checks this child table whenever a parent ``records`` row is
-- reclaimed.  The lookup index above cannot serve a rid-only foreign-key
-- probe, so without this index bounded retention deletes degrade to a full
-- postings-table scan per record.
CREATE INDEX IF NOT EXISTS idx_postings_rid ON postings(rid);

CREATE TABLE IF NOT EXISTS checkpoints (
    epoch INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    checkpoint_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS expired_epochs (
    epoch INTEGER PRIMARY KEY,
    expired_at INTEGER NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS live_sessions (
    session_id TEXT PRIMARY KEY,
    camera_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    session_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_live_sessions_camera
    ON live_sessions(camera_id, created_at);

CREATE TABLE IF NOT EXISTS live_records (
    session_id TEXT NOT NULL,
    rid TEXT NOT NULL,
    camera_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    record_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, rid)
);
CREATE INDEX IF NOT EXISTS idx_live_records_next
    ON live_records(session_id, seq);

CREATE TABLE IF NOT EXISTS retention_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at INTEGER NOT NULL,
    cutoff INTEGER NOT NULL,
    deleted_epochs_json TEXT NOT NULL,
    deleted_records INTEGER NOT NULL,
    reason TEXT NOT NULL
);
"""


def _record_fields(record: dict[str, Any]) -> tuple[int, str, int, int, int]:
    ssi = record.get("SSi", {}) if isinstance(record, dict) else {}
    return (
        int(record.get("epoch", 0)),
        str(ssi.get("cid", "")),
        int(ssi.get("seq", 0)),
        int(ssi.get("timestamp", 0)),
        int(not record.get("index_tokens")),
    )


class CloudSQLiteStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            timeout=30,
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def put_record(self, rid: str, record: dict[str, Any]) -> None:
        epoch, camera_id, seq, timestamp, is_live = _record_fields(record)
        self.conn.execute(
            """
            INSERT INTO records(
                rid, epoch, camera_id, seq, timestamp, is_live,
                record_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rid) DO UPDATE SET
                epoch=excluded.epoch,
                camera_id=excluded.camera_id,
                seq=excluded.seq,
                timestamp=excluded.timestamp,
                is_live=excluded.is_live,
                record_json=excluded.record_json
            """,
            (
                str(rid),
                epoch,
                camera_id,
                seq,
                timestamp,
                is_live,
                json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                int(time.time()),
            ),
        )

    def get_record(self, rid: str) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT record_json FROM records WHERE rid=?",
            (str(rid),),
        ).fetchone()
        return json.loads(row["record_json"]) if row else None

    def record_epoch(self, rid: str) -> int | None:
        row = self.conn.execute(
            "SELECT epoch FROM records WHERE rid=?",
            (str(rid),),
        ).fetchone()
        return int(row["epoch"]) if row is not None else None

    def delete_record(self, rid: str) -> None:
        self.conn.execute("DELETE FROM records WHERE rid=?", (str(rid),))

    def record_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM records").fetchone()[0])

    def record_ids(self) -> list[str]:
        rows = self.conn.execute("SELECT rid FROM records ORDER BY rid").fetchall()
        return [str(row["rid"]) for row in rows]

    def record_items(self) -> list[tuple[str, dict[str, Any]]]:
        rows = self.conn.execute(
            "SELECT rid, record_json FROM records ORDER BY rid"
        ).fetchall()
        return [(str(row["rid"]), json.loads(row["record_json"])) for row in rows]

    def apply_posting_updates(
        self,
        epoch: int,
        updates: list[dict[str, Any]],
    ) -> None:
        for update in updates:
            self.conn.execute(
                "INSERT OR IGNORE INTO postings(epoch, token, rid) VALUES(?, ?, ?)",
                (int(epoch), str(update["token"]), str(update["rid"])),
            )

    def replace_epoch_postings(
        self,
        epoch: int,
        token_to_record_ids: dict[str, list[str]],
    ) -> None:
        self.conn.execute("DELETE FROM postings WHERE epoch=?", (int(epoch),))
        self.apply_posting_updates(
            epoch,
            [
                {"token": token, "rid": rid}
                for token, rids in token_to_record_ids.items()
                for rid in rids
            ],
        )

    def epoch_postings(self, epoch: int) -> dict[str, list[str]]:
        rows = self.conn.execute(
            """
            SELECT token, rid FROM postings
            WHERE epoch=?
            ORDER BY token, rid
            """,
            (int(epoch),),
        ).fetchall()
        out: dict[str, list[str]] = {}
        for row in rows:
            out.setdefault(str(row["token"]), []).append(str(row["rid"]))
        return out

    def save_checkpoint(self, checkpoint: dict[str, Any]) -> None:
        epoch = int(checkpoint["epoch"])
        version = int(checkpoint["version"])
        self.conn.execute(
            """
            INSERT INTO checkpoints(epoch, version, checkpoint_json, updated_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(epoch) DO UPDATE SET
                version=excluded.version,
                checkpoint_json=excluded.checkpoint_json,
                updated_at=excluded.updated_at
            """,
            (
                epoch,
                version,
                json.dumps(checkpoint, ensure_ascii=False, separators=(",", ":")),
                int(time.time()),
            ),
        )

    def save_checkpoint_if_newer(self, checkpoint: dict[str, Any]) -> bool:
        """Advance an epoch checkpoint monotonically under parallel delivery."""
        epoch = int(checkpoint["epoch"])
        version = int(checkpoint["version"])
        cursor = self.conn.execute(
            """
            INSERT INTO checkpoints(epoch, version, checkpoint_json, updated_at)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(epoch) DO UPDATE SET
                version=excluded.version,
                checkpoint_json=excluded.checkpoint_json,
                updated_at=excluded.updated_at
            WHERE excluded.version > checkpoints.version
            """,
            (
                epoch,
                version,
                json.dumps(checkpoint, ensure_ascii=False, separators=(",", ":")),
                int(time.time()),
            ),
        )
        return cursor.rowcount > 0

    def checkpoint(self, epoch: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT checkpoint_json FROM checkpoints WHERE epoch=?",
            (int(epoch),),
        ).fetchone()
        return json.loads(row["checkpoint_json"]) if row else None

    def is_expired(self, epoch: int) -> bool:
        return (
            self.conn.execute(
                "SELECT 1 FROM expired_epochs WHERE epoch=?",
                (int(epoch),),
            ).fetchone()
            is not None
        )

    def save_live_session(self, session: dict[str, Any]) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO live_sessions(
                session_id, camera_id, created_at, session_json
            ) VALUES(?, ?, ?, ?)
            """,
            (
                str(session["session_id"]),
                str(session["camera_id"]),
                int(session.get("created_at", time.time())),
                json.dumps(session, ensure_ascii=False, separators=(",", ":")),
            ),
        )
        self.conn.execute(
            """
            DELETE FROM live_sessions
            WHERE session_id IN (
                SELECT session_id FROM live_sessions
                ORDER BY created_at DESC LIMIT -1 OFFSET 100
            )
            """
        )
        self.conn.commit()

    def load_live_sessions(self) -> dict[str, dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT session_id, session_json FROM live_sessions ORDER BY created_at"
        ).fetchall()
        return {
            str(row["session_id"]): json.loads(row["session_json"])
            for row in rows
        }

    def put_live_record(
        self,
        session_id: str,
        rid: str,
        record: dict[str, Any],
        *,
        window_seconds: int = 120,
    ) -> None:
        epoch, camera_id, seq, timestamp, _ = _record_fields(record)
        now = int(time.time())
        self.conn.execute(
            """
            INSERT OR REPLACE INTO live_records(
                session_id, rid, camera_id, epoch, seq, timestamp,
                record_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(session_id),
                str(rid),
                camera_id,
                epoch,
                seq,
                timestamp,
                json.dumps(record, ensure_ascii=False, separators=(",", ":")),
                now,
            ),
        )
        self.conn.execute(
            "DELETE FROM live_records WHERE created_at < ?",
            (now - max(60, int(window_seconds)),),
        )

    def next_live_record(
        self,
        session_id: str,
        after_seq: int,
    ) -> tuple[str | None, dict[str, Any] | None]:
        row = self.conn.execute(
            """
            SELECT rid, record_json FROM live_records
            WHERE session_id=? AND seq>? AND created_at>=?
            ORDER BY seq LIMIT 1
            """,
            (str(session_id), int(after_seq), int(time.time()) - 120),
        ).fetchone()
        if row is None:
            return None, None
        return str(row["rid"]), json.loads(row["record_json"])

    def latest_live_record(
        self,
        session_id: str,
    ) -> tuple[str | None, dict[str, Any] | None]:
        row = self.conn.execute(
            """
            SELECT rid, record_json FROM live_records
            WHERE session_id=? AND created_at>=?
            ORDER BY seq DESC LIMIT 1
            """,
            (str(session_id), int(time.time()) - 120),
        ).fetchone()
        if row is None:
            return None, None
        return str(row["rid"]), json.loads(row["record_json"])

    def live_record_count(self) -> int:
        return int(
            self.conn.execute("SELECT COUNT(*) FROM live_records").fetchone()[0]
        )

    def list_epochs(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT r.epoch,
                   COUNT(*) AS record_count,
                   MIN(r.timestamp) AS start_ts,
                   MAX(r.timestamp) AS end_ts,
                   c.version AS checkpoint_version
            FROM records r
            LEFT JOIN checkpoints c ON c.epoch=r.epoch
            WHERE NOT EXISTS (
                SELECT 1 FROM expired_epochs x WHERE x.epoch=r.epoch
            )
            GROUP BY r.epoch
            ORDER BY r.epoch DESC
            """
        ).fetchall()
        return [
            {
                "epoch": int(row["epoch"]),
                "record_count": int(row["record_count"]),
                "start_ts": int(row["start_ts"]),
                "end_ts": int(row["end_ts"]),
                "checkpoint_version": (
                    int(row["checkpoint_version"])
                    if row["checkpoint_version"] is not None
                    else None
                ),
            }
            for row in rows
        ]

    def records_in_range(
        self,
        *,
        camera_id: str,
        start_ts: int,
        end_ts: int,
        limit: int,
    ) -> list[tuple[str, dict[str, Any]]]:
        rows = self.conn.execute(
            """
            SELECT rid, record_json FROM records
            WHERE camera_id=? AND timestamp>=? AND timestamp<=? AND is_live=0
              AND NOT EXISTS (
                  SELECT 1 FROM expired_epochs x WHERE x.epoch=records.epoch
              )
            ORDER BY timestamp, seq
            LIMIT ?
            """,
            (camera_id, int(start_ts), int(end_ts), max(1, int(limit))),
        ).fetchall()
        return [(str(row["rid"]), json.loads(row["record_json"])) for row in rows]

    def expire_before(
        self,
        cutoff: int,
        *,
        reason: str = "retention",
        keep_epoch: int | None = None,
    ) -> dict[str, Any]:
        """Logically retire whole epochs without a large delete transaction.

        Retired epochs immediately become unavailable to retrieval APIs. Their
        rows are reclaimed later in bounded transactions so active uploads do
        not wait behind a multi-gigabyte SQLite WAL write.
        """
        params: list[Any] = [int(cutoff)]
        where = "HAVING MAX(timestamp) < ?"
        if keep_epoch is not None:
            where += " AND epoch <> ?"
            params.append(int(keep_epoch))
        rows = self.conn.execute(
            f"""
            SELECT epoch, COUNT(*) AS count
            FROM records
            WHERE NOT EXISTS (
                SELECT 1 FROM expired_epochs x WHERE x.epoch=records.epoch
            )
            GROUP BY epoch
            {where}
            ORDER BY epoch
            """,
            params,
        ).fetchall()
        epochs = [int(row["epoch"]) for row in rows]
        now = int(time.time())
        for epoch in epochs:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO expired_epochs(epoch, expired_at, reason)
                VALUES(?, ?, ?)
                """,
                (epoch, now, reason),
            )
        self.conn.execute(
            """
            INSERT INTO retention_runs(
                run_at, cutoff, deleted_epochs_json, deleted_records, reason
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (now, int(cutoff), json.dumps(epochs), 0, reason),
        )
        self.conn.commit()
        return {
            "deleted_epochs": epochs,
            "deleted_records": 0,
            "physical_reclaim_pending": bool(epochs),
            "cutoff": int(cutoff),
            "reason": reason,
        }

    def reap_expired_batches(
        self,
        *,
        record_limit: int = 32,
        posting_limit: int = 256,
    ) -> dict[str, Any]:
        """Reclaim a bounded amount of physically retired epoch data."""
        # Keep the expiry marker after physical deletion so every old-epoch
        # search continues to return HTTP 410.  Select only a marker that
        # still owns reclaimable SQLite rows, otherwise an already-empty
        # oldest epoch would starve newer expired epochs forever.
        row = self.conn.execute(
            """
            SELECT x.epoch FROM expired_epochs x
            WHERE EXISTS (SELECT 1 FROM postings p WHERE p.epoch=x.epoch)
               OR EXISTS (SELECT 1 FROM records r WHERE r.epoch=x.epoch)
               OR EXISTS (SELECT 1 FROM checkpoints c WHERE c.epoch=x.epoch)
            ORDER BY x.epoch LIMIT 1
            """
        ).fetchone()
        if row is None:
            return {
                "ok": True,
                "reclaimed_epoch": None,
                "deleted_records": 0,
                "deleted_postings": 0,
                "complete": True,
            }
        epoch = int(row["epoch"])
        deleted_postings = self.conn.execute(
            """
            DELETE FROM postings WHERE rowid IN (
                SELECT rowid FROM postings WHERE epoch=? LIMIT ?
            )
            """,
            (epoch, max(1, int(posting_limit))),
        ).rowcount
        deleted_records = 0
        if deleted_postings == 0:
            deleted_records = self.conn.execute(
                """
                DELETE FROM records WHERE rowid IN (
                    SELECT rowid FROM records WHERE epoch=? LIMIT ?
                )
                """,
                (epoch, max(1, int(record_limit))),
            ).rowcount
        remaining_postings = int(
            self.conn.execute(
                "SELECT COUNT(*) FROM postings WHERE epoch=?", (epoch,)
            ).fetchone()[0]
        )
        remaining_records = int(
            self.conn.execute(
                "SELECT COUNT(*) FROM records WHERE epoch=?", (epoch,)
            ).fetchone()[0]
        )
        complete = remaining_postings == 0 and remaining_records == 0
        if complete:
            self.conn.execute("DELETE FROM checkpoints WHERE epoch=?", (epoch,))
        self.conn.commit()
        return {
            "ok": True,
            "reclaimed_epoch": epoch,
            "deleted_records": max(0, int(deleted_records)),
            "deleted_postings": max(0, int(deleted_postings)),
            "remaining_records": remaining_records,
            "remaining_postings": remaining_postings,
            "complete": complete,
        }

    def latest_record(
        self,
        camera_id: str,
        epoch: int | None = None,
    ) -> tuple[str | None, dict[str, Any] | None]:
        if epoch is None:
            row = self.conn.execute(
                """
                SELECT rid, record_json FROM records
                WHERE camera_id=? AND NOT EXISTS (
                    SELECT 1 FROM expired_epochs x WHERE x.epoch=records.epoch
                )
                ORDER BY timestamp DESC, seq DESC LIMIT 1
                """,
                (camera_id,),
            ).fetchone()
        else:
            row = self.conn.execute(
                """
                SELECT rid, record_json FROM records
                WHERE camera_id=? AND epoch=? AND NOT EXISTS (
                    SELECT 1 FROM expired_epochs x WHERE x.epoch=records.epoch
                )
                ORDER BY timestamp DESC, seq DESC LIMIT 1
                """,
                (camera_id, int(epoch)),
            ).fetchone()
        if row is None:
            return None, None
        return str(row["rid"]), json.loads(row["record_json"])

    def prune_before(
        self,
        cutoff: int,
        *,
        reason: str = "retention",
        keep_epoch: int | None = None,
        max_epochs: int | None = None,
    ) -> dict[str, Any]:
        params: list[Any] = [int(cutoff)]
        where = "HAVING MAX(timestamp) < ?"
        if keep_epoch is not None:
            where += " AND epoch <> ?"
            params.append(int(keep_epoch))
        rows = self.conn.execute(
            f"""
            SELECT epoch, COUNT(*) AS count
            FROM records
            GROUP BY epoch
            {where}
            ORDER BY epoch
            """,
            params,
        ).fetchall()
        if max_epochs is not None:
            rows = rows[: max(0, int(max_epochs))]

        epochs = [int(row["epoch"]) for row in rows]
        deleted_records = sum(int(row["count"]) for row in rows)
        now = int(time.time())
        for epoch in epochs:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO expired_epochs(epoch, expired_at, reason)
                VALUES(?, ?, ?)
                """,
                (epoch, now, reason),
            )
            self.conn.execute("DELETE FROM records WHERE epoch=?", (epoch,))
            self.conn.execute("DELETE FROM postings WHERE epoch=?", (epoch,))
            self.conn.execute("DELETE FROM checkpoints WHERE epoch=?", (epoch,))

        self.conn.execute(
            """
            INSERT INTO retention_runs(
                run_at, cutoff, deleted_epochs_json, deleted_records, reason
            ) VALUES(?, ?, ?, ?, ?)
            """,
            (now, int(cutoff), json.dumps(epochs), deleted_records, reason),
        )
        self.conn.commit()
        self.conn.execute("PRAGMA incremental_vacuum(2000)")
        return {
            "deleted_epochs": epochs,
            "deleted_records": deleted_records,
            "cutoff": int(cutoff),
            "reason": reason,
        }

    def retention_status(self) -> dict[str, Any]:
        row = self.conn.execute(
            """
            SELECT run_at, cutoff, deleted_epochs_json, deleted_records, reason
            FROM retention_runs ORDER BY id DESC LIMIT 1
            """
        ).fetchone()
        last_run = None
        if row:
            last_run = {
                "run_at": int(row["run_at"]),
                "cutoff": int(row["cutoff"]),
                "deleted_epochs": json.loads(row["deleted_epochs_json"]),
                "deleted_records": int(row["deleted_records"]),
                "reason": str(row["reason"]),
            }
        return {
            "database_path": str(self.path),
            "database_bytes": self.path.stat().st_size if self.path.exists() else 0,
            "record_count": self.record_count(),
            "expired_epoch_count": int(
                self.conn.execute("SELECT COUNT(*) FROM expired_epochs").fetchone()[0]
            ),
            "physical_reclaim_pending": int(
                self.conn.execute(
                    """
                    SELECT COUNT(*) FROM records r
                    WHERE EXISTS (
                        SELECT 1 FROM expired_epochs x WHERE x.epoch=r.epoch
                    )
                    """
                ).fetchone()[0]
            ),
            "last_run": last_run,
        }


class SQLiteRecordMapping(MutableMapping[str, dict[str, Any]]):
    """Compatibility mapping used by attack-demo mutation hooks."""

    def __init__(self, store: CloudSQLiteStore):
        self.store = store

    def __getitem__(self, key: str) -> dict[str, Any]:
        value = self.store.get_record(str(key))
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        self.store.put_record(str(key), value)
        self.store.conn.commit()

    def __delitem__(self, key: str) -> None:
        if self.store.get_record(str(key)) is None:
            raise KeyError(key)
        self.store.delete_record(str(key))
        self.store.conn.commit()

    def __iter__(self) -> Iterator[str]:
        return iter(self.store.record_ids())

    def __len__(self) -> int:
        return self.store.record_count()

    def items(self):
        return self.store.record_items()

    def pop(self, key: str, default=None):
        value = self.store.get_record(str(key))
        if value is None:
            return default
        self.store.delete_record(str(key))
        self.store.conn.commit()
        return value
