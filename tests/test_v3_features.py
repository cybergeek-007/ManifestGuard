from __future__ import annotations

import unittest

from backend.allowlist import get_all_categories, get_alternatives_for_category, is_trusted
from backend.crx_analyzer import _strip_crx_header
from backend.recommendations import get_recommendations, infer_category
from backend.reputation import compute_reputation_adjustment
from backend.scanner import choose_verdict, compute_suspicion_score


class V3FeaturesTests(unittest.TestCase):
    def test_reputation_adjustment(self) -> None:
        # High reputation should lower the score significantly
        self.assertEqual(compute_reputation_adjustment(95), 0.60)
        self.assertEqual(compute_reputation_adjustment(75), 0.75)
        # Mid reputation should have slight/no effect
        self.assertEqual(compute_reputation_adjustment(65), 0.85)
        self.assertEqual(compute_reputation_adjustment(45), 1.0)
        # Low reputation should amplify the score
        self.assertEqual(compute_reputation_adjustment(35), 1.10)
        self.assertEqual(compute_reputation_adjustment(10), 1.25)

    def test_category_inference(self) -> None:
        # Based on text
        self.assertEqual(
            infer_category("AdBlock Pro", "Blocks ads on websites"),
            "ad_blocker",
        )
        self.assertEqual(
            infer_category("Safe Password Manager", "Store your passwords securely"),
            "password_manager",
        )
        self.assertEqual(
            infer_category("React Developer Tools", "Tools for React debugging"),
            "developer_tool",
        )

    def test_recommendations(self) -> None:
        # Ad blocker recommendations
        recs = get_recommendations("Suspicious AdBlocker", "blocks ads", "ad_blocker")
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("uBlock Origin" in r.name for r in recs) or any("AdGuard" in r.name for r in recs) or any("AdBlock" in r.name for r in recs))
        
        # Password manager recommendations
        pw_recs = get_recommendations("Bad Password Tool", "manager", "password_manager")
        self.assertGreater(len(pw_recs), 0)
        self.assertTrue(any("Bitwarden" in r.name for r in pw_recs) or any("1Password" in r.name for r in pw_recs))

    def test_scanner_verdict_logic_with_reputation(self) -> None:
        # Test suspicion logic
        score = compute_suspicion_score(
            signals=[],
            intel_count=0,
            store_status="listed",
            extension_id="unknown_id",
            category="ad_blocker",
            permissions=["webRequest", "webRequestBlocking", "<all_urls>"]
        )
        # It's an ad_blocker, so it gets a pass on webRequest (in logic, broad_host_cookie_combo ignored)
        self.assertEqual(score, 0)
        
        score_bad = compute_suspicion_score(
            signals=[],
            intel_count=0,
            store_status="unavailable_or_removed",
            extension_id="unknown_id",
            category="productivity",
            permissions=["webRequest", "webRequestBlocking", "<all_urls>"]
        )
        # removed from store = high suspicion
        self.assertGreaterEqual(score_bad, 20)

    def test_choose_verdict(self) -> None:
        # Intel match = known_malicious
        self.assertEqual(choose_verdict("enabled", 0, 0, 1, "listed", "some_id", -1), "known_malicious")
        
        # Suspicion > 40 = suspicious
        self.assertEqual(choose_verdict("enabled", 0, 45, 0, "listed", "some_id", -1), "suspicious")
        
        # Suspicion >= 25 and power >= 50 = moderate_risk
        self.assertEqual(choose_verdict("enabled", 55, 30, 0, "listed", "some_id", -1), "moderate_risk")
        
        # Power > 40 = powerful_but_expected
        self.assertEqual(choose_verdict("enabled", 65, 0, 0, "listed", "some_id", -1), "powerful_but_expected")
        
        # Trusted ID override (only works if suspicion < 40)
        # "cjpalhdlnbpafiamejdnhcphjbkeiagm" is uBlock Origin
        self.assertEqual(choose_verdict("enabled", 90, 10, 0, "listed", "cjpalhdlnbpafiamejdnhcphjbkeiagm", 95), "trusted")
        
        # High reputation (>=80) combined with lower base suspicion (after adjustment) -> powerful_but_expected
        self.assertEqual(choose_verdict("enabled", 80, 20, 0, "listed", "some_id", 85), "powerful_but_expected")

    def test_crx_header_stripping(self) -> None:
        # Mock ZIP data
        zip_payload = b"PK\x03\x04mock_zip_content"
        
        # Test just ZIP
        self.assertEqual(_strip_crx_header(zip_payload), zip_payload)
        
        # Test CRX3 header
        import struct
        # "Cr24" (4) + version 3 (4) + header length (4) + mock header (8) + ZIP
        crx3_data = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 8) + b"mock_hdr" + zip_payload
        self.assertEqual(_strip_crx_header(crx3_data), zip_payload)


if __name__ == "__main__":
    unittest.main()
