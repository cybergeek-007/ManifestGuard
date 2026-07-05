"""Offline unit tests for ManifestGuard core engines.

These tests exercise the deterministic scoring, clone-detection, collusion,
and SQLite persistence logic without any network access, so they are safe to
run in CI.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from backend.collusion import analyze_collusion
from backend.database import Database
from backend.scanner import (
    choose_verdict,
    compute_anomaly_score,
    compute_reach_score,
)
from backend.similarity import fingerprint_directory, find_clones


class ReachScoreTests(unittest.TestCase):
    def test_broad_access_scores_higher_than_narrow(self) -> None:
        narrow = compute_reach_score(["storage"], [])
        broad = compute_reach_score(
            ["tabs", "cookies", "webRequest", "scripting"],
            ["<all_urls>"],
        )
        self.assertGreater(broad, narrow)
        self.assertGreaterEqual(narrow, 0)
        self.assertLessEqual(broad, 100)


class VerdictLadderTests(unittest.TestCase):
    def test_clean_low_reach_is_not_malicious(self) -> None:
        verdict, _ = choose_verdict(
            reach_score=10, anomaly_score=0, intel_count=0,
            store_status="active",
        )
        self.assertIn(verdict, {"trusted", "low_concern"})

    def test_threat_intel_forces_known_malicious(self) -> None:
        verdict, sub = choose_verdict(
            reach_score=50, anomaly_score=40, intel_count=2,
            store_status="active",
        )
        self.assertEqual(verdict, "known_malicious")

    def test_anomaly_from_signals_is_bounded(self) -> None:
        score = compute_anomaly_score([], 0, "active")
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)


class CollusionTests(unittest.TestCase):
    def test_shared_external_endpoint_creates_edge(self) -> None:
        extensions = [
            {"id": "a" * 32, "name": "Alpha", "permissions": ["cookies", "tabs"]},
            {"id": "b" * 32, "name": "Beta", "permissions": ["webRequest"]},
        ]
        manifests = {
            "a" * 32: {
                "externally_connectable": {"ids": ["b" * 32]},
            },
            "b" * 32: {
                "externally_connectable": {"ids": ["a" * 32]},
            },
        }
        report = analyze_collusion(extensions, manifests)
        self.assertTrue(
            any(
                {e.source_id, e.target_id} == {"a" * 32, "b" * 32}
                for e in report.edges
            ),
            "expected a collusion edge between mutually connectable extensions",
        )

    def test_unrelated_extensions_have_no_edges(self) -> None:
        extensions = [
            {"id": "c" * 32, "name": "Gamma"},
            {"id": "d" * 32, "name": "Delta"},
        ]
        manifests = {"c" * 32: {}, "d" * 32: {}}
        report = analyze_collusion(extensions, manifests)
        self.assertEqual(report.edges, [])


class CloneDetectionTests(unittest.TestCase):
    def _write_ext(self, root: Path, body: str) -> Path:
        root.mkdir(parents=True, exist_ok=True)
        (root / "manifest.json").write_text('{"name":"x","version":"1.0.0"}', encoding="utf-8")
        (root / "background.js").write_text(body, encoding="utf-8")
        return root

    def test_identical_code_is_flagged_as_clone(self) -> None:
        body = "function main(){\n  const x = fetch('https://example.com/a');\n  return x;\n}\nmain();\n" * 20
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            original = self._write_ext(base / "orig", body)
            duplicate = self._write_ext(base / "dupe", body)

            fp_original = fingerprint_directory(original, "o" * 32, "1.0.0", "Original")
            fp_duplicate = fingerprint_directory(duplicate, "p" * 32, "1.0.0", "Duplicate")
            self.assertIsNotNone(fp_original)
            self.assertIsNotNone(fp_duplicate)

            matches = find_clones(fp_duplicate, [fp_original.to_record()])
            self.assertTrue(matches, "identical code should register as a clone")
            self.assertGreaterEqual(matches[0].similarity, 0.85)


class DatabaseTests(unittest.TestCase):
    def test_scan_roundtrip_and_watchlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "test.db")

            db.save_scan(
                scan_id="scan1",
                created_at="2024-01-01T00:00:00+00:00",
                status="completed",
                source="online_scan",
                payload={"scan": {"scanId": "scan1"}, "extensions": []},
            )
            scans = db.load_all_scans()
            self.assertEqual(len(scans), 1)

            db.watchlist_add("e" * 32, "Example", "1.0.0", "low_concern")
            watched = db.watchlist_all()
            self.assertEqual(len(watched), 1)
            self.assertEqual(watched[0]["extensionId"], "e" * 32)

            self.assertTrue(db.watchlist_remove("e" * 32))
            self.assertEqual(db.watchlist_all(), [])


if __name__ == "__main__":
    unittest.main()
