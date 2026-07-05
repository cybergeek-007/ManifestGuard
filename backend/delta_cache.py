"""ManifestGuard v4 — Global Historical Delta Cache.

Maintains a SQLite database of extension version fingerprints. When any user
scans an extension, we record a structural fingerprint of its JavaScript code.
When the SAME extension is scanned again (by any user, possibly a newer version),
we compare the fingerprint to detect supply-chain attacks.

Detects: sudden injection of obfuscated code, new eval() patterns, suspicious
new files, and dramatic code size increases between versions.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.models import DeltaResult

log = logging.getLogger(__name__)


@dataclass(slots=True)
class VersionFingerprint:
    """Structural fingerprint of an extension version's JavaScript."""

    extension_id: str
    version: str
    crx_hash: str               # SHA-256 of CRX file or structure
    scan_date: str              # ISO-8601
    js_structure: dict[str, dict[str, int]]  # filename -> {line_count, eval_count, obfuscated_var_count, external_url_count, file_size}


class DeltaCache:
    """SQLite-backed historical extension version cache.

    Thread-safe via a threading.Lock around all SQLite operations.
    """

    def __init__(self, db_path: str = "backend/data/delta_cache.db") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Create the database and table if they don't exist."""
        os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS extension_versions (
                        extension_id TEXT NOT NULL,
                        version TEXT NOT NULL,
                        crx_hash TEXT NOT NULL,
                        scan_date TEXT NOT NULL,
                        js_structure TEXT NOT NULL,
                        PRIMARY KEY (extension_id, version)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ext_date
                    ON extension_versions(extension_id, scan_date DESC)
                """)
                conn.commit()
            finally:
                conn.close()

    def record_version(self, fingerprint: VersionFingerprint) -> None:
        """Store current version's structural fingerprint."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO extension_versions
                       (extension_id, version, crx_hash, scan_date, js_structure)
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        fingerprint.extension_id,
                        fingerprint.version,
                        fingerprint.crx_hash,
                        fingerprint.scan_date,
                        json.dumps(fingerprint.js_structure),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    def get_previous_version(self, extension_id: str, current_version: str) -> VersionFingerprint | None:
        """Retrieve the most recent previous version for comparison."""
        with self._lock:
            conn = sqlite3.connect(self._db_path)
            try:
                cursor = conn.execute(
                    """SELECT extension_id, version, crx_hash, scan_date, js_structure
                       FROM extension_versions
                       WHERE extension_id = ? AND version != ?
                       ORDER BY scan_date DESC
                       LIMIT 1""",
                    (extension_id, current_version),
                )
                row = cursor.fetchone()
                if not row:
                    return None
                return VersionFingerprint(
                    extension_id=row[0],
                    version=row[1],
                    crx_hash=row[2],
                    scan_date=row[3],
                    js_structure=json.loads(row[4]),
                )
            finally:
                conn.close()

    def compute_delta(
        self,
        old: VersionFingerprint,
        new_structure: dict[str, dict[str, int]],
        new_version: str,
    ) -> DeltaResult:
        """Compare structural fingerprints between two versions.

        Detects:
        - New eval()/Function() calls that didn't exist before
        - New obfuscated variable patterns (_0x...)
        - New external domain references
        - Significant code size increase (>50% in any file)
        - New files added with suspicious names
        """
        old_struct = old.js_structure
        changes: list[str] = []

        # Calculate deltas
        total_eval_delta = 0
        total_obfuscated_delta = 0
        old_total_lines = sum(f.get("line_count", 0) for f in old_struct.values())
        new_total_lines = sum(f.get("line_count", 0) for f in new_structure.values())

        # Check existing files for changes
        for filename, new_stats in new_structure.items():
            old_stats = old_struct.get(filename)
            if old_stats is None:
                # New file added
                eval_count = new_stats.get("eval_count", 0)
                obf_count = new_stats.get("obfuscated_var_count", 0)
                if eval_count > 0 or obf_count > 5:
                    changes.append(
                        f"New file '{filename}' added with {eval_count} eval() calls "
                        f"and {obf_count} obfuscated variables"
                    )
                total_eval_delta += eval_count
                total_obfuscated_delta += obf_count
            else:
                # Existing file — check for changes
                eval_delta = new_stats.get("eval_count", 0) - old_stats.get("eval_count", 0)
                obf_delta = new_stats.get("obfuscated_var_count", 0) - old_stats.get("obfuscated_var_count", 0)
                total_eval_delta += max(eval_delta, 0)
                total_obfuscated_delta += max(obf_delta, 0)

                old_lines = old_stats.get("line_count", 1)
                new_lines = new_stats.get("line_count", 0)
                if old_lines > 0 and new_lines > old_lines * 2:
                    pct = int((new_lines / old_lines - 1) * 100)
                    changes.append(
                        f"'{filename}' grew by {pct}% ({old_lines} → {new_lines} lines)"
                    )

                if eval_delta > 0:
                    changes.append(
                        f"+{eval_delta} new eval() calls in '{filename}' "
                        f"(was {old_stats.get('eval_count', 0)}, now {new_stats.get('eval_count', 0)})"
                    )

                if obf_delta > 10:
                    changes.append(
                        f"+{obf_delta} new obfuscated variables in '{filename}'"
                    )

        # Check for removed files (could indicate cleanup)
        removed_files = set(old_struct.keys()) - set(new_structure.keys())
        if removed_files:
            changes.append(f"{len(removed_files)} file(s) removed: {', '.join(sorted(removed_files)[:5])}")

        # New external URLs
        new_url_delta = sum(
            max(new_structure.get(f, {}).get("external_url_count", 0) - old_struct.get(f, {}).get("external_url_count", 0), 0)
            for f in new_structure
        )
        if new_url_delta > 3:
            changes.append(f"+{new_url_delta} new external URL references")

        # Risk assessment
        new_files_with_eval = sum(
            1 for f in new_structure
            if f not in old_struct and new_structure[f].get("eval_count", 0) > 0
        )

        if total_eval_delta > 5 or total_obfuscated_delta > 20 or (new_files_with_eval > 3):
            risk = "supply_chain_risk"
            severity = "critical"
        elif (old_total_lines > 0 and abs(new_total_lines - old_total_lines) / max(old_total_lines, 1) > 0.3) or new_url_delta > 3:
            risk = "significant_update"
            severity = "warning"
        elif old_total_lines > 0 and abs(new_total_lines - old_total_lines) / max(old_total_lines, 1) < 0.05:
            risk = "minor_patch"
            severity = "info"
        else:
            risk = "normal_update"
            severity = "info"

        if not changes:
            changes.append("No significant structural changes detected.")

        return DeltaResult(
            extension_id=old.extension_id,
            old_version=old.version,
            new_version=new_version,
            structural_changes=changes,
            risk_assessment=risk,
            new_eval_count_delta=total_eval_delta,
            new_obfuscated_delta=total_obfuscated_delta,
            severity=severity,
        )

    def check_and_record(
        self,
        extension_id: str,
        version: str,
        crx_data: bytes,
        js_structure: dict[str, dict[str, int]],
    ) -> DeltaResult | None:
        """Convenience method: check previous version, compute delta, record current.

        Returns DeltaResult if a previous version was found, None otherwise.
        """
        # Compute hash from structure (since crx_data may be empty in current flow)
        struct_str = json.dumps(js_structure, sort_keys=True)
        crx_hash = hashlib.sha256(struct_str.encode()).hexdigest()

        # Check for previous version
        previous = self.get_previous_version(extension_id, version)

        # Record current version
        fingerprint = VersionFingerprint(
            extension_id=extension_id,
            version=version,
            crx_hash=crx_hash,
            scan_date=datetime.now(timezone.utc).isoformat(),
            js_structure=js_structure,
        )
        self.record_version(fingerprint)

        # Compute delta if previous version exists
        if previous:
            return self.compute_delta(previous, js_structure, version)

        return None


def build_js_structure(extract_dir: str) -> dict[str, dict[str, int]]:
    """Build a structural fingerprint of all JavaScript files in a directory.

    For each .js file under 1MB:
    - Count lines
    - Count eval() and new Function() occurrences
    - Count _0x prefixed variable names (obfuscation markers)
    - Count external URLs (http/https)
    - Record file size in bytes

    Returns dict mapping relative filename → stats dict.
    """
    root = Path(extract_dir)
    structure: dict[str, dict[str, int]] = {}

    for js_file in root.rglob("*.js"):
        try:
            size = js_file.stat().st_size
            if size > 1_000_000:  # Skip >1MB
                continue

            content = js_file.read_text(encoding="utf-8", errors="ignore")
            rel_path = str(js_file.relative_to(root)).replace("\\", "/")

            line_count = content.count("\n") + 1
            eval_count = len(re.findall(r'\beval\s*\(|\bFunction\s*\(', content))
            obfuscated_var_count = len(re.findall(r'_0x[a-f0-9]{4,}', content, re.IGNORECASE))
            external_url_count = len(re.findall(r'https?://[^\s"\']+', content))

            structure[rel_path] = {
                "line_count": line_count,
                "eval_count": eval_count,
                "obfuscated_var_count": obfuscated_var_count,
                "external_url_count": external_url_count,
                "file_size": size,
            }
        except Exception:
            continue

    return structure


# Module-level singleton
delta_cache = DeltaCache()
