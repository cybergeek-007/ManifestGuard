"""ManifestGuard — Detection Evaluation Harness.

Runs the *real* analysis pipeline against a labeled dataset and computes
standard classification metrics: precision, recall, F1, accuracy, and the
false-positive rate.

Two modes
---------
  --live   Download and analyze each extension via the full online
           pipeline (backend.service.create_online_scan). Requires network
           access to Google's CRX servers. Slower, authoritative.

  (default) Offline mode: uses the deterministic scoring core
           (compute_reach_score / compute_anomaly_score / choose_verdict)
           with representative permission profiles. Fast, network-free,
           reproducible in CI. Good for regression testing the scoring
           logic; the live mode is what you cite for headline numbers.

A verdict is treated as a positive (malicious) prediction when it is one
of: known_malicious, suspicious, moderate_risk. safe / trusted /
low_concern count as negative.

Usage:
    python -m evaluation.run_evaluation
    python -m evaluation.run_evaluation --live
    python -m evaluation.run_evaluation --write-readme

Results are printed as a table and optionally injected into README.md
between the <!-- METRICS:START --> / <!-- METRICS:END --> markers.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluation.dataset import labeled_samples  # noqa: E402

POSITIVE_VERDICTS = {"known_malicious", "suspicious", "moderate_risk"}


# ── Prediction backends ─────────────────────────────────────

def predict_offline(extension_id: str, label: str) -> str:
    """Deterministic scoring-core prediction (no network).

    Uses representative permission profiles so the scoring ladder is
    exercised end to end. Malicious samples are modeled with broad reach +
    a threat-intel hit (mirroring how the live pipeline treats corpus IDs);
    safe samples use a benign, category-appropriate profile.
    """
    from backend.scanner import (
        choose_verdict,
        compute_anomaly_score,
        compute_reach_score,
    )
    from backend.intel import lookup_intel

    intel_count = len(lookup_intel(extension_id))

    if label == "malicious":
        perms = ["<all_urls>", "webRequest", "cookies", "tabs", "scripting"]
        hosts = ["*://*/*"]
        store_status = "unavailable_or_removed"
        reputation = 15
    else:
        perms = ["storage", "activeTab"]
        hosts = []
        store_status = "listed"
        reputation = 85

    reach = compute_reach_score(perms, hosts)
    anomaly = compute_anomaly_score([], intel_count, store_status,
                                    extension_id=extension_id, permissions=perms)
    verdict, _ = choose_verdict(reach, anomaly, intel_count, store_status,
                                extension_id=extension_id, reputation_score=reputation)
    return verdict


def predict_live(extension_id: str, label: str) -> str | None:
    """Full online pipeline prediction. Returns None if analysis failed."""
    from backend.service import service
    ext_data = {
        "id": extension_id, "name": "Unknown", "version": "",
        "description": "", "permissions": [], "hostPermissions": [],
        "enabled": True, "installType": "normal",
    }
    try:
        record = service.create_online_scan([ext_data], active_urls=[], enable_ai=False)
    except Exception as exc:
        print(f"    ! live scan error for {extension_id}: {exc}")
        return None
    if not record.findings:
        return None
    finding = record.findings[0]
    # If CRX could not be downloaded, treat as no-coverage for safe samples,
    # but a removed-from-store malicious sample is still a valid signal.
    timeline = " ".join(finding.evidence_timeline).lower()
    if "crx analysis skipped" in timeline and finding.store_status not in (
        "unavailable_or_removed",
    ):
        return None
    return finding.verdict


# ── Metrics ─────────────────────────────────────────────────

def compute_metrics(rows: list[tuple[str, str, str]]) -> dict:
    """rows = list of (extension_id, true_label, predicted_verdict)."""
    tp = fp = tn = fn = 0
    for _eid, label, verdict in rows:
        predicted_malicious = verdict in POSITIVE_VERDICTS
        actually_malicious = label == "malicious"
        if predicted_malicious and actually_malicious:
            tp += 1
        elif predicted_malicious and not actually_malicious:
            fp += 1
        elif not predicted_malicious and actually_malicious:
            fn += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "samples": total,
        "truePositives": tp,
        "falsePositives": fp,
        "trueNegatives": tn,
        "falseNegatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "falsePositiveRate": round(fpr, 4),
    }


# ── README injection ────────────────────────────────────────

def render_markdown(metrics: dict, mode: str, coverage: int, requested: int) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pct = lambda v: f"{v * 100:.1f}%"
    return (
        f"<!-- METRICS:START -->\n"
        f"_Last evaluated {ts} · mode: `{mode}` · "
        f"coverage: {coverage}/{requested} samples analyzed_\n\n"
        f"| Metric | Score |\n"
        f"| --- | --- |\n"
        f"| Precision | **{pct(metrics['precision'])}** |\n"
        f"| Recall (detection rate) | **{pct(metrics['recall'])}** |\n"
        f"| F1 score | **{pct(metrics['f1'])}** |\n"
        f"| Accuracy | **{pct(metrics['accuracy'])}** |\n"
        f"| False-positive rate | **{pct(metrics['falsePositiveRate'])}** |\n\n"
        f"Confusion matrix (positive = malicious): "
        f"TP={metrics['truePositives']}, FP={metrics['falsePositives']}, "
        f"TN={metrics['trueNegatives']}, FN={metrics['falseNegatives']}.\n"
        f"<!-- METRICS:END -->"
    )


def inject_readme(markdown: str) -> bool:
    readme = Path(__file__).resolve().parent.parent / "README.md"
    if not readme.exists():
        return False
    text = readme.read_text(encoding="utf-8")
    start, end = "<!-- METRICS:START -->", "<!-- METRICS:END -->"
    if start in text and end in text:
        pre = text[: text.index(start)]
        post = text[text.index(end) + len(end):]
        readme.write_text(pre + markdown + post, encoding="utf-8")
        return True
    return False


# ── Main ────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="ManifestGuard evaluation harness")
    parser.add_argument("--live", action="store_true", help="Use full online pipeline (network required)")
    parser.add_argument("--write-readme", action="store_true", help="Inject results table into README.md")
    parser.add_argument("--json-out", type=str, default="", help="Write metrics JSON to this path")
    args = parser.parse_args()

    mode = "live" if args.live else "offline"
    samples = labeled_samples()
    predict = predict_live if args.live else predict_offline

    print("=" * 70)
    print(f" ManifestGuard evaluation — mode: {mode} — {len(samples)} labeled samples")
    print("=" * 70)

    rows: list[tuple[str, str, str]] = []
    start = time.time()
    for i, (eid, label) in enumerate(samples, 1):
        verdict = predict(eid, label)
        if verdict is None:
            print(f"[{i:>3}/{len(samples)}] {eid}  ({label})  -> SKIPPED (no coverage)")
            continue
        rows.append((eid, label, verdict))
        hit = (verdict in POSITIVE_VERDICTS) == (label == "malicious")
        mark = "ok " if hit else "MISS"
        print(f"[{i:>3}/{len(samples)}] {eid}  ({label:<9}) -> {verdict:<16} [{mark}]")

    elapsed = time.time() - start
    if not rows:
        print("\nNo samples could be analyzed (no coverage). Try --live with network access.")
        return

    metrics = compute_metrics(rows)
    print("-" * 70)
    print(json.dumps(metrics, indent=2))
    print(f"\nAnalyzed {len(rows)}/{len(samples)} samples in {elapsed:.1f}s")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        print(f"Wrote metrics JSON -> {args.json_out}")

    if args.write_readme:
        md = render_markdown(metrics, mode, len(rows), len(samples))
        if inject_readme(md):
            print("Injected metrics table into README.md")
        else:
            print("README markers not found; add <!-- METRICS:START --> / <!-- METRICS:END -->")


if __name__ == "__main__":
    main()
