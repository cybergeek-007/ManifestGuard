from __future__ import annotations

import csv
import html
import io
import json
import re
from pathlib import Path

from backend.models import ExtensionFinding, ScanRecord


def write_csv_report(scan: ScanRecord, destination: Path) -> Path:
    fieldnames = [
        "extension_id",
        "name",
        "version",
        "profile",
        "browser_channel",
        "enabled_state",
        "install_source",
        "verdict",
        "store_status",
        "power_score",
        "suspicion_score",
        "permissions",
        "host_permissions",
    ]
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in scan.findings:
            for profile in finding.profiles:
                writer.writerow(
                    {
                        "extension_id": finding.id,
                        "name": finding.name,
                        "version": finding.version,
                        "profile": profile.profile_name,
                        "browser_channel": profile.browser_channel,
                        "enabled_state": profile.enabled_state,
                        "install_source": profile.install_source,
                        "verdict": finding.verdict,
                        "store_status": finding.store_status,
                        "power_score": finding.power_score,
                        "suspicion_score": finding.suspicion_score,
                        "permissions": ";".join(finding.permissions),
                        "host_permissions": ";".join(finding.host_permissions),
                    }
                )
    return destination


def write_json_report(scan: ScanRecord, destination: Path) -> Path:
    payload = {
        "scan": scan.to_summary_dict(),
        "extensions": [finding.to_detail_dict() for finding in scan.findings],
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination


def build_html_report(scan: ScanRecord) -> str:
    cards = []
    summary = scan.summary()
    for key, value in summary["verdictDistribution"].items():
        cards.append(
            f"<div class='metric'><span class='metric-label'>{html.escape(key)}</span>"
            f"<strong>{value}</strong></div>"
        )

    rows = []
    for finding in scan.findings:
        signal_badges = "".join(
            f"<span class='badge signal'>{html.escape(signal.title)}</span>"
            for signal in finding.suspicious_signals[:3]
        ) or "<span class='muted'>No strong suspicious signals</span>"
        profiles = ", ".join(html.escape(profile.profile_name) for profile in finding.profiles)
        rows.append(
            "<tr>"
            f"<td><div class='name'>{html.escape(finding.name)}</div><div class='muted'>{html.escape(finding.id)}</div></td>"
            f"<td>{html.escape(finding.verdict)}</td>"
            f"<td>{finding.power_score}</td>"
            f"<td>{finding.suspicion_score}</td>"
            f"<td>{html.escape(finding.store_status)}</td>"
            f"<td>{html.escape(profiles)}</td>"
            f"<td>{signal_badges}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ManifestGuard Report {html.escape(scan.scan_id)}</title>
  <style>
    :root {{
      --bg: #f4efe6;
      --panel: #fffdf7;
      --ink: #1f2721;
      --accent: #0f766e;
      --warn: #d97706;
      --danger: #b91c1c;
      --line: #ded7ca;
    }}
    body {{
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #fff9ef, var(--bg));
      color: var(--ink);
    }}
    .shell {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px;
    }}
    .hero, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 24px;
      box-shadow: 0 18px 42px rgba(31, 39, 33, 0.08);
    }}
    .hero {{
      padding: 28px 32px;
      margin-bottom: 24px;
      background-image: linear-gradient(135deg, rgba(15,118,110,0.08), transparent 55%);
    }}
    .eyebrow {{
      color: var(--accent);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 12px;
      font-weight: 700;
    }}
    h1 {{
      margin: 10px 0 8px;
      font-size: 40px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-top: 20px;
    }}
    .metric {{
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255,255,255,0.7);
    }}
    .metric-label {{
      display: block;
      color: #58645b;
      margin-bottom: 6px;
      text-transform: capitalize;
    }}
    .panel {{
      padding: 20px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      text-align: left;
      padding: 14px 10px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }}
    th {{
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #66756d;
    }}
    .name {{
      font-weight: 700;
    }}
    .muted {{
      color: #66756d;
      font-size: 12px;
      margin-top: 4px;
    }}
    .badge {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      background: #efe7d7;
      margin: 0 8px 8px 0;
      font-size: 12px;
    }}
    .signal {{
      background: rgba(217, 119, 6, 0.12);
      color: var(--warn);
    }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="eyebrow">ManifestGuard v2</div>
      <h1>Extension Evidence Report</h1>
      <p>Scan {html.escape(scan.scan_id)} completed with {summary["totalExtensions"]} unique extensions.</p>
      <div class="grid">
        {''.join(cards)}
      </div>
    </section>
    <section class="panel">
      <table>
        <thead>
          <tr>
            <th>Extension</th>
            <th>Verdict</th>
            <th>Power</th>
            <th>Suspicion</th>
            <th>Store</th>
            <th>Profiles</th>
            <th>Top Signals</th>
          </tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </section>
  </div>
</body>
</html>"""


def write_html_report(scan: ScanRecord, destination: Path) -> Path:
    destination.write_text(build_html_report(scan), encoding="utf-8")
    return destination


def _html_to_plain_lines(document: str) -> list[str]:
    text = re.sub(r"<style.*?</style>", "", document, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = html.unescape(text)
    lines = [re.sub(r"\s+", " ", line).strip() for line in text.splitlines()]
    return [line for line in lines if line]


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_text_pdf(lines: list[str]) -> bytes:
    page_width = 612
    page_height = 792
    font_size = 10
    leading = 14
    max_lines = 48

    pages = [lines[index:index + max_lines] for index in range(0, len(lines), max_lines)] or [["ManifestGuard report was empty."]]
    objects: list[bytes] = []

    catalog_id = 1
    pages_id = 2
    font_id = 3
    next_id = 4
    page_ids: list[int] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for page_lines in pages:
        content_stream = io.StringIO()
        content_stream.write("BT\n/F1 10 Tf\n36 756 Td\n")
        for index, line in enumerate(page_lines):
            if index:
                content_stream.write(f"0 -{leading} Td\n")
            content_stream.write(f"({_escape_pdf_text(line[:110])}) Tj\n")
        content_stream.write("ET\n")
        encoded = content_stream.getvalue().encode("utf-8")
        content_id = next_id
        page_id = next_id + 1
        next_id += 2
        objects.append(f"<< /Length {len(encoded)} >>\nstream\n".encode("utf-8") + encoded + b"endstream")
        objects.append(
            (
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {page_width} {page_height}] "
                f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("utf-8")
        )
        page_ids.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("utf-8")

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, start=1):
        offsets.append(buffer.tell())
        buffer.write(f"{index} 0 obj\n".encode("utf-8"))
        buffer.write(obj)
        buffer.write(b"\nendobj\n")
    xref_offset = buffer.tell()
    buffer.write(f"xref\n0 {len(objects) + 1}\n".encode("utf-8"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("utf-8"))
    buffer.write(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("utf-8")
    )
    return buffer.getvalue()


def write_pdf_report(scan: ScanRecord, destination: Path) -> Path:
    html_report = build_html_report(scan)
    destination.write_bytes(_build_text_pdf(_html_to_plain_lines(html_report)))
    return destination
