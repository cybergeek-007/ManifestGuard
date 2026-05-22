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
        "reputation_score",
        "category",
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
                        "reputation_score": finding.reputation_score,
                        "category": finding.category,
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
        rep_str = str(finding.reputation_score) if finding.reputation_score >= 0 else "N/A"
        cat_str = html.escape(finding.category) if finding.category else ""
        rows.append(
            "<tr>"
            f"<td><div class='name'>{html.escape(finding.name)}</div><div class='muted'>{html.escape(finding.id)}</div></td>"
            f"<td>{html.escape(finding.verdict)}</td>"
            f"<td>{finding.power_score}</td>"
            f"<td>{finding.suspicion_score}</td>"
            f"<td>{rep_str}</td>"
            f"<td>{cat_str}</td>"
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
      <div class="eyebrow">ManifestGuard v3</div>
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
            <th>Reputation</th>
            <th>Category</th>
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


def _escape_pdf(value: str) -> str:
    """Escape special characters for PDF text strings and strip non-latin1."""
    clean = value.encode("latin-1", errors="replace").decode("latin-1")
    return clean.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap_text(text: str, max_chars: int) -> list[str]:
    """Word-wrap text to fit within max_chars per line."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > max_chars:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines or [""]


class _PdfWriter:
    """Zero-dependency PDF writer with proper layout, headers, tables, and page management."""

    PAGE_W = 612
    PAGE_H = 792
    MARGIN_L = 50
    MARGIN_R = 50
    MARGIN_T = 50
    MARGIN_B = 60
    USABLE_W = PAGE_W - MARGIN_L - MARGIN_R

    def __init__(self) -> None:
        self._objects: list[bytes] = []
        self._page_streams: list[str] = []
        self._page_ids: list[int] = []
        self._stream = ""
        self._y = self.PAGE_H - self.MARGIN_T
        self._page_num = 0
        self._total_pages = 0
        self._new_page()

    # ── Page management ──────────────────────────────────────
    def _new_page(self) -> None:
        if self._stream:
            self._page_streams.append(self._stream)
        self._stream = ""
        self._y = self.PAGE_H - self.MARGIN_T
        self._page_num += 1

    def _ensure_space(self, needed: float) -> None:
        if self._y - needed < self.MARGIN_B:
            self._new_page()

    # ── Text primitives ──────────────────────────────────────
    def _text(self, x: float, y: float, text: str, size: float = 10, bold: bool = False) -> None:
        font = "/F2" if bold else "/F1"
        self._stream += f"BT {font} {size} Tf {x:.1f} {y:.1f} Td ({_escape_pdf(text)}) Tj ET\n"

    def _line(self, x1: float, y1: float, x2: float, y2: float, width: float = 0.5) -> None:
        self._stream += f"{width:.1f} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S\n"

    def _rect_fill(self, x: float, y: float, w: float, h: float, r: float, g: float, b: float) -> None:
        self._stream += f"{r:.2f} {g:.2f} {b:.2f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f\n0 0 0 rg\n"

    # ── High-level layout helpers ────────────────────────────
    def _heading(self, text: str, size: float = 16) -> None:
        self._ensure_space(size + 20)
        self._text(self.MARGIN_L, self._y, text, size=size, bold=True)
        self._y -= size + 6
        self._line(self.MARGIN_L, self._y, self.PAGE_W - self.MARGIN_R, self._y, 1.0)
        self._y -= 12

    def _subheading(self, text: str) -> None:
        self._ensure_space(28)
        self._y -= 6
        self._text(self.MARGIN_L, self._y, text, size=11, bold=True)
        self._y -= 16

    def _body_line(self, text: str, indent: float = 0, size: float = 9) -> None:
        leading = size + 3
        for line in _wrap_text(text, 90 - int(indent / 5)):
            self._ensure_space(leading + 4)
            self._text(self.MARGIN_L + indent, self._y, line, size=size)
            self._y -= leading

    def _blank(self, height: float = 8) -> None:
        self._y -= height

    def _key_value(self, key: str, value: str, indent: float = 0) -> None:
        self._ensure_space(14)
        self._text(self.MARGIN_L + indent, self._y, f"{key}:", size=9, bold=True)
        self._text(self.MARGIN_L + indent + len(key) * 5.4 + 12, self._y, value[:80], size=9)
        self._y -= 13

    # ── Table rendering ──────────────────────────────────────
    def _table_header(self, columns: list[tuple[str, float]]) -> None:
        self._ensure_space(28)
        # Header background
        total_w = sum(w for _, w in columns)
        self._rect_fill(self.MARGIN_L, self._y - 4, total_w, 16, 0.92, 0.90, 0.86)
        x = self.MARGIN_L
        for label, width in columns:
            self._text(x + 4, self._y, label.upper(), size=7, bold=True)
            x += width
        self._y -= 18

    def _table_row(self, columns: list[tuple[str, float]], values: list[str], highlight: bool = False) -> None:
        row_h = 14
        self._ensure_space(row_h + 4)
        if highlight:
            total_w = sum(w for _, w in columns)
            self._rect_fill(self.MARGIN_L, self._y - 3, total_w, row_h, 0.98, 0.95, 0.92)
        x = self.MARGIN_L
        for (_, width), val in zip(columns, values):
            max_chars = int(width / 5.2)
            display = val[:max_chars]
            self._text(x + 4, self._y, display, size=8)
            x += width
        self._y -= row_h
        # Row separator
        total_w = sum(w for _, w in columns)
        self._stream += "0.85 0.83 0.80 RG\n"
        self._line(self.MARGIN_L, self._y + 1, self.MARGIN_L + total_w, self._y + 1, 0.3)
        self._stream += "0 0 0 RG\n"

    # ── Build final PDF ──────────────────────────────────────
    def build(self) -> bytes:
        # Finalize last page
        if self._stream:
            self._page_streams.append(self._stream)

        self._total_pages = len(self._page_streams)

        # Add page number footers
        for i, stream in enumerate(self._page_streams):
            footer = f"Page {i + 1} of {self._total_pages}"
            stream += f"BT /F1 8 Tf {self.PAGE_W / 2 - 25:.1f} 30 Td ({_escape_pdf(footer)}) Tj ET\n"
            # Add footer line
            stream += f"0.85 0.83 0.80 RG 0.5 w {self.MARGIN_L:.1f} 42 m {self.PAGE_W - self.MARGIN_R:.1f} 42 l S\n0 0 0 RG\n"
            self._page_streams[i] = stream

        objects: list[bytes] = []
        catalog_id = 1
        pages_id = 2
        font1_id = 3
        font2_id = 4
        next_id = 5
        page_ids: list[int] = []

        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objects.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")

        for page_stream in self._page_streams:
            encoded = page_stream.encode("latin-1", errors="replace")
            content_id = next_id
            page_id = next_id + 1
            next_id += 2
            objects.append(f"<< /Length {len(encoded)} >>\nstream\n".encode() + encoded + b"endstream")
            objects.append(
                f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}] "
                f"/Resources << /Font << /F1 {font1_id} 0 R /F2 {font2_id} 0 R >> >> "
                f"/Contents {content_id} 0 R >>".encode()
            )
            page_ids.append(page_id)

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        objects[pages_id - 1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()

        buf = io.BytesIO()
        buf.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0]
        for idx, obj in enumerate(objects, start=1):
            offsets.append(buf.tell())
            buf.write(f"{idx} 0 obj\n".encode())
            buf.write(obj)
            buf.write(b"\nendobj\n")
        xref_pos = buf.tell()
        buf.write(f"xref\n0 {len(objects) + 1}\n".encode())
        buf.write(b"0000000000 65535 f \n")
        for off in offsets[1:]:
            buf.write(f"{off:010d} 00000 n \n".encode())
        buf.write(
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF".encode()
        )
        return buf.getvalue()


def _verdict_label(verdict: str) -> str:
    return verdict.replace("_", " ").title()


def write_pdf_report(scan: ScanRecord, destination: Path) -> Path:
    summary = scan.summary()
    pdf = _PdfWriter()

    # ── Page 1: Header ───────────────────────────────────────
    # Title bar
    pdf._rect_fill(0, pdf.PAGE_H - 85, pdf.PAGE_W, 85, 0.06, 0.46, 0.43)
    pdf._stream += "1 1 1 rg\n"
    pdf._text(pdf.MARGIN_L, pdf.PAGE_H - 40, "MANIFESTGUARD", size=22, bold=True)
    pdf._text(pdf.MARGIN_L, pdf.PAGE_H - 58, "Extension Security Audit Report", size=11)
    pdf._stream += "0 0 0 rg\n"
    pdf._y = pdf.PAGE_H - 105

    # Scan metadata
    pdf._key_value("Scan ID", scan.scan_id)
    pdf._key_value("Date", scan.created_at.strftime("%Y-%m-%d %H:%M UTC"))
    pdf._key_value("Source", scan.source)
    pdf._key_value("Total Extensions", str(summary["totalExtensions"]))
    pdf._key_value("Profiles Scanned", ", ".join(summary.get("profilesScanned", [])) or "N/A")
    pdf._key_value("Channels Scanned", ", ".join(summary.get("channelsScanned", [])) or "N/A")

    if scan.options:
        pdf._key_value("Live Store Checks", "Enabled" if scan.options.enable_live_checks else "Disabled")
        pdf._key_value("AI Explanations", "Enabled" if scan.options.enable_ai else "Disabled")

    pdf._blank(12)

    # ── Verdict Distribution ─────────────────────────────────
    pdf._heading("Verdict Distribution")
    distribution = summary.get("verdictDistribution", {})
    if distribution:
        for verdict, count in sorted(distribution.items(), key=lambda x: -x[1]):
            bar_max = 300
            bar_w = min((count / max(summary["totalExtensions"], 1)) * bar_max, bar_max)
            pdf._ensure_space(20)
            pdf._text(pdf.MARGIN_L, pdf._y, f"{_verdict_label(verdict)}:", size=9, bold=True)
            pdf._rect_fill(pdf.MARGIN_L + 160, pdf._y - 2, bar_w, 12, 0.06, 0.46, 0.43)
            pdf._stream += "1 1 1 rg\n"
            pdf._text(pdf.MARGIN_L + 162, pdf._y, str(count), size=9, bold=True)
            pdf._stream += "0 0 0 rg\n"
            pdf._y -= 18
    else:
        pdf._body_line("No extensions found in this scan.")

    pdf._blank(8)

    # ── Extension Inventory Table ────────────────────────────
    pdf._heading("Extension Inventory")

    table_cols: list[tuple[str, float]] = [
        ("Extension", 160),
        ("Verdict", 80),
        ("Power", 40),
        ("Susp.", 40),
        ("Rep.", 35),
        ("Store", 80),
        ("Profile", 77),
    ]
    pdf._table_header(table_cols)

    for idx, finding in enumerate(scan.findings):
        profile_names = ", ".join(p.profile_name for p in finding.profiles[:2])
        if len(finding.profiles) > 2:
            profile_names += f" +{len(finding.profiles) - 2}"

        pdf._table_row(
            table_cols,
            [
                finding.name,
                _verdict_label(finding.verdict),
                str(finding.power_score),
                str(finding.suspicion_score),
                str(finding.reputation_score) if finding.reputation_score >= 0 else "-",
                finding.store_status.replace("_", " "),
                profile_names,
            ],
            highlight=(idx % 2 == 0),
        )

    pdf._blank(12)

    # ── High-Risk Extension Details ──────────────────────────
    high_risk = [f for f in scan.findings if f.verdict in ("known_malicious", "suspicious", "removed_or_unavailable")]
    if high_risk:
        pdf._heading("High-Risk Extension Details")

        for finding in high_risk:
            pdf._ensure_space(80)
            pdf._subheading(f"{finding.name} ({finding.id[:20]}...)")
            pdf._key_value("Verdict", _verdict_label(finding.verdict), indent=10)
            pdf._key_value("Power Score", f"{finding.power_score}/100", indent=10)
            pdf._key_value("Suspicion Score", f"{finding.suspicion_score}/100", indent=10)
            if finding.reputation_score >= 0:
                pdf._key_value("Reputation Score", f"{finding.reputation_score}/100", indent=10)
            if finding.category:
                pdf._key_value("Category", finding.category.replace("_", " ").title(), indent=10)
            pdf._key_value("Store Status", finding.store_status.replace("_", " "), indent=10)
            pdf._key_value("Version", finding.version, indent=10)

            if finding.suspicious_signals:
                pdf._blank(4)
                pdf._body_line("Suspicious Signals:", indent=10, size=9)
                for signal in finding.suspicious_signals[:5]:
                    pdf._body_line(f"  [{signal.severity}] {signal.title}: {signal.detail}", indent=16, size=8)

            if finding.intel_matches:
                pdf._blank(4)
                pdf._body_line("Threat Intelligence Matches:", indent=10, size=9)
                for match in finding.intel_matches[:3]:
                    pdf._body_line(f"  [{match.confidence}] {match.label}: {match.detail}", indent=16, size=8)
                    pdf._body_line(f"  Source: {match.source}", indent=16, size=8)

            if finding.permissions:
                pdf._blank(4)
                pdf._body_line(f"Permissions: {', '.join(finding.permissions[:12])}", indent=10, size=8)

            if finding.ai_summary:
                pdf._blank(4)
                pdf._body_line("AI Assessment:", indent=10, size=9)
                for line in finding.ai_summary.split("\n")[:6]:
                    if line.strip():
                        pdf._body_line(line.strip(), indent=16, size=8)

            pdf._blank(10)
            pdf._line(pdf.MARGIN_L + 10, pdf._y, pdf.PAGE_W - pdf.MARGIN_R - 10, pdf._y, 0.3)
            pdf._blank(8)

    # ── Trusted Extensions Summary ───────────────────────────
    trusted = [f for f in scan.findings if f.verdict == "trusted"]
    if trusted:
        pdf._heading("Trusted Extensions")
        pdf._body_line(f"{len(trusted)} extensions matched the curated allowlist of known-good publishers.")
        pdf._blank(6)
        for finding in trusted:
            pdf._body_line(f"  {finding.name} (Power: {finding.power_score})", indent=10, size=9)

    # ── Footer on last page ──────────────────────────────────
    pdf._blank(20)
    pdf._ensure_space(30)
    pdf._line(pdf.MARGIN_L, pdf._y, pdf.PAGE_W - pdf.MARGIN_R, pdf._y, 0.5)
    pdf._y -= 14
    pdf._body_line("Generated by ManifestGuard v3 - Evidence-Driven Extension Auditor", size=8)
    pdf._body_line("This report is for informational purposes. Always verify findings with additional sources.", size=7)

    destination.write_bytes(pdf.build())
    return destination
