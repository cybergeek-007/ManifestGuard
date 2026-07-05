"""ManifestGuard v5 — SQLite Persistence Layer.

Replaces the per-scan JSON-file registry with a single SQLite database.
Also hosts the extension fingerprint store (clone detection) and the
watchlist (continuous monitoring).

Design notes:
- Thread-safe via a threading.Lock around all SQLite operations
  (same pattern as delta_cache.py).
- Scan payloads are stored as JSON blobs in the shape produced by
  write_json_report: {"scan": {...summary...}, "extensions": [...detail...]},
  which ScanRecord.from_dict already knows how to parse.
- On first startup, legacy backend/data/<scan_id>/<scan_id>.json reports
  are migrated into the database automatically.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_HEX_DIR = re.compile(r"^[a-f0-9]{12,32}$")


class Database:
    """SQLite-backed store for scans, fingerprints, and the watchlist."""

    def __init__(self, db_path: str | None = None) -> None:
        default_path = str(Path(__file__).resolve().parent / "data" / "manifestguard.db")
        self._db_path = db_path or default_path
        self._lock = threading.Lock()
        self._init_db()

    # ── Setup ──────────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        source TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_scans_created
                    ON scans(created_at DESC)
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS extension_fingerprints (
                        extension_id TEXT NOT NULL,
                        version TEXT NOT NULL,
                        name TEXT NOT NULL,
                        simhash TEXT NOT NULL,
                        file_hashes_json TEXT NOT NULL,
                        js_file_count INTEGER NOT NULL,
                        total_js_bytes INTEGER NOT NULL,
                        recorded_at TEXT NOT NULL,
                        PRIMARY KEY (extension_id, version)
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS watchlist (
                        extension_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        added_at TEXT NOT NULL,
                        last_version TEXT,
                        last_checked TEXT,
                        last_verdict TEXT,
                        alerts_json TEXT NOT NULL DEFAULT '[]'
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS watchlist_baseline (
                        extension_id TEXT PRIMARY KEY,
                        permissions_json TEXT NOT NULL DEFAULT '[]',
                        domains_json TEXT NOT NULL DEFAULT '[]',
                        has_obfuscation INTEGER NOT NULL DEFAULT 0,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.commit()
            finally:
                conn.close()

    # ── Scans ──────────────────────────────────────────────

    def save_scan(
        self,
        scan_id: str,
        created_at: str,
        status: str,
        source: str,
        payload: dict[str, Any],
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO scans
                       (scan_id, created_at, status, source, payload_json)
                       VALUES (?, ?, ?, ?, ?)""",
                    (scan_id, created_at, status, source, json.dumps(payload)),
                )
                conn.commit()
            finally:
                conn.close()

    def load_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT payload_json FROM scans WHERE scan_id = ?", (scan_id,)
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    def load_all_scans(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT payload_json FROM scans ORDER BY created_at ASC"
                ).fetchall()
            finally:
                conn.close()
        payloads: list[dict[str, Any]] = []
        for (raw,) in rows:
            try:
                payloads.append(json.loads(raw))
            except Exception:
                continue
        return payloads

    def scan_stats(self) -> dict[str, Any]:
        """Lightweight aggregate stats for the fleet overview / public stats."""
        with self._lock:
            conn = self._connect()
            try:
                scan_count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                fingerprint_count = conn.execute(
                    "SELECT COUNT(DISTINCT extension_id) FROM extension_fingerprints"
                ).fetchone()[0]
                watchlist_count = conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
            finally:
                conn.close()
        return {
            "totalScans": scan_count,
            "uniqueExtensionsFingerprinted": fingerprint_count,
            "watchlistSize": watchlist_count,
        }

    # ── Extension fingerprints (clone detection) ───────────

    def save_fingerprint(
        self,
        extension_id: str,
        version: str,
        name: str,
        simhash: str,
        file_hashes: list[str],
        js_file_count: int,
        total_js_bytes: int,
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO extension_fingerprints
                       (extension_id, version, name, simhash, file_hashes_json,
                        js_file_count, total_js_bytes, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        extension_id,
                        version,
                        name,
                        simhash,
                        json.dumps(file_hashes),
                        js_file_count,
                        total_js_bytes,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def load_all_fingerprints(self, exclude_extension_id: str | None = None) -> list[dict[str, Any]]:
        """Load the latest fingerprint per extension (optionally excluding one ID)."""
        query = """
            SELECT extension_id, version, name, simhash, file_hashes_json,
                   js_file_count, total_js_bytes
            FROM extension_fingerprints f
            WHERE recorded_at = (
                SELECT MAX(recorded_at) FROM extension_fingerprints
                WHERE extension_id = f.extension_id
            )
        """
        params: tuple[Any, ...] = ()
        if exclude_extension_id:
            query += " AND extension_id != ?"
            params = (exclude_extension_id,)
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(query, params).fetchall()
            finally:
                conn.close()
        results: list[dict[str, Any]] = []
        for row in rows:
            try:
                results.append(
                    {
                        "extension_id": row[0],
                        "version": row[1],
                        "name": row[2],
                        "simhash": row[3],
                        "file_hashes": json.loads(row[4]),
                        "js_file_count": row[5],
                        "total_js_bytes": row[6],
                    }
                )
            except Exception:
                continue
        return results

    # ── Watchlist ──────────────────────────────────────────

    def watchlist_add(self, extension_id: str, name: str, version: str | None, verdict: str | None) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO watchlist
                       (extension_id, name, added_at, last_version, last_checked, last_verdict, alerts_json)
                       VALUES (?, ?, ?, ?, NULL, ?, '[]')""",
                    (
                        extension_id,
                        name,
                        datetime.now(timezone.utc).isoformat(),
                        version,
                        verdict,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def watchlist_remove(self, extension_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                cursor = conn.execute("DELETE FROM watchlist WHERE extension_id = ?", (extension_id,))
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    def watchlist_all(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """SELECT extension_id, name, added_at, last_version,
                              last_checked, last_verdict, alerts_json
                       FROM watchlist ORDER BY added_at DESC"""
                ).fetchall()
            finally:
                conn.close()
        entries: list[dict[str, Any]] = []
        for row in rows:
            try:
                alerts = json.loads(row[6])
            except Exception:
                alerts = []
            entries.append(
                {
                    "extensionId": row[0],
                    "name": row[1],
                    "addedAt": row[2],
                    "lastVersion": row[3],
                    "lastChecked": row[4],
                    "lastVerdict": row[5],
                    "alerts": alerts,
                }
            )
        return entries

    def watchlist_update(
        self,
        extension_id: str,
        version: str | None,
        verdict: str | None,
        new_alerts: list[dict[str, Any]],
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT alerts_json FROM watchlist WHERE extension_id = ?", (extension_id,)
                ).fetchone()
                if row is None:
                    return
                try:
                    alerts = json.loads(row[0])
                except Exception:
                    alerts = []
                alerts = (new_alerts + alerts)[:50]  # newest first, cap history
                conn.execute(
                    """UPDATE watchlist
                       SET last_version = COALESCE(?, last_version),
                           last_verdict = COALESCE(?, last_verdict),
                           last_checked = ?,
                           alerts_json = ?
                       WHERE extension_id = ?""",
                    (version, verdict, now, json.dumps(alerts), extension_id),
                )
                conn.commit()
            finally:
                conn.close()

    def watchlist_set_baseline(
        self,
        extension_id: str,
        permissions: list[str],
        domains: list[str],
        has_obfuscation: bool,
    ) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO watchlist_baseline
                       (extension_id, permissions_json, domains_json, has_obfuscation, updated_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        extension_id,
                        json.dumps(permissions),
                        json.dumps(domains),
                        1 if has_obfuscation else 0,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def watchlist_get_baseline(self, extension_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """SELECT permissions_json, domains_json, has_obfuscation
                       FROM watchlist_baseline WHERE extension_id = ?""",
                    (extension_id,),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        try:
            return {
                "permissions": json.loads(row[0]),
                "domains": json.loads(row[1]),
                "has_obfuscation": bool(row[2]),
            }
        except Exception:
            return None

    # ── Legacy migration ───────────────────────────────────

    def migrate_legacy_reports(self, data_dir: Path) -> int:
        """Import legacy per-scan JSON reports into SQLite (idempotent).

        Legacy layout: backend/data/<scan_id>/<scan_id>.json with the shape
        {"scan": {...}, "extensions": [...]}. Existing scan_ids are skipped.
        """
        migrated = 0
        for report_file in sorted(data_dir.glob("*/*.json")):
            if not _HEX_DIR.match(report_file.parent.name):
                continue
            scan_id = report_file.parent.name
            if self.load_scan(scan_id) is not None:
                continue
            try:
                payload = json.loads(report_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            scan_meta = payload.get("scan", payload)
            self.save_scan(
                scan_id=str(scan_meta.get("scanId", scan_id)),
                created_at=str(scan_meta.get("createdAt", datetime.now(timezone.utc).isoformat())),
                status=str(scan_meta.get("status", "completed")),
                source=str(scan_meta.get("source", "online_scan")),
                payload=payload,
            )
            migrated += 1
        if migrated:
            log.info("Migrated %d legacy JSON scan report(s) into SQLite", migrated)
        return migrated


# Module-level singleton
database = Database()
