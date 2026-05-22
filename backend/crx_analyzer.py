"""Server-side CRX downloader and analyzer.

Downloads extension packages from Google's CRX update servers, extracts
the ZIP contents, and runs the behavioral code scanner on the extracted
source files.  This enables deep source-code analysis in online mode
without needing local filesystem access to the user's browser profile.
"""
from __future__ import annotations

import io
import os
import shutil
import ssl
import struct
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── CRX download endpoint ───────────────────────────────────
# Google's update server — returns a redirect to the actual CRX file.
CRX_DOWNLOAD_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=125.0.0.0"
    "&acceptformat=crx2,crx3"
    "&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
)

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0"


@dataclass(slots=True)
class CrxDownloadResult:
    """Result of a CRX download attempt."""

    extension_id: str
    success: bool
    extract_dir: Path | None = None
    manifest: dict[str, Any] | None = None
    error: str = ""
    file_count: int = 0


def _strip_crx_header(data: bytes) -> bytes:
    """Strip the CRX2/CRX3 header from a .crx file to get the ZIP payload.

    CRX3 format:
      - 4 bytes: magic number "Cr24"
      - 4 bytes: version (3)
      - 4 bytes: header length
      - N bytes: signed header protobuf
      - remaining: ZIP archive

    CRX2 format:
      - 4 bytes: magic number "Cr24"
      - 4 bytes: version (2)
      - 4 bytes: public key length
      - 4 bytes: signature length
      - N bytes: public key
      - M bytes: signature
      - remaining: ZIP archive
    """
    if len(data) < 16:
        return data

    magic = data[:4]
    if magic != b"Cr24":
        # Not a CRX file — maybe it's already a ZIP
        if data[:2] == b"PK":
            return data
        return data

    version = struct.unpack("<I", data[4:8])[0]

    if version == 3:
        # CRX3: header length at bytes 8-12
        header_length = struct.unpack("<I", data[8:12])[0]
        zip_start = 12 + header_length
        return data[zip_start:]
    elif version == 2:
        # CRX2: public key length + signature length
        pk_length = struct.unpack("<I", data[8:12])[0]
        sig_length = struct.unpack("<I", data[12:16])[0]
        zip_start = 16 + pk_length + sig_length
        return data[zip_start:]
    else:
        # Unknown version — try to find ZIP magic
        pk_offset = data.find(b"PK")
        if pk_offset > 0:
            return data[pk_offset:]
        return data


def download_crx(extension_id: str, timeout: float = 15.0) -> bytes | None:
    """Download a CRX file from Google's update servers.

    Returns the raw CRX bytes, or None if download fails.
    """
    url = CRX_DOWNLOAD_URL.format(extension_id=extension_id)
    request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    context = ssl.create_default_context()

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            # Follow redirects — urllib handles this automatically
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (404, 204):
            return None
        return None
    except Exception:
        return None


def extract_crx(crx_data: bytes, dest_dir: Path) -> bool:
    """Extract a CRX file to a destination directory.

    Strips the CRX header and extracts the ZIP payload.
    Returns True if extraction succeeded.
    """
    zip_data = _strip_crx_header(crx_data)

    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            # Security: skip files with absolute paths or path traversal
            for info in zf.infolist():
                if info.filename.startswith("/") or ".." in info.filename:
                    continue
                # Skip very large files (> 5MB) to prevent abuse
                if info.file_size > 5 * 1024 * 1024:
                    continue
                zf.extract(info, dest_dir)
        return True
    except (zipfile.BadZipFile, Exception):
        return False


def download_and_extract(extension_id: str) -> CrxDownloadResult:
    """Download a CRX from Google and extract it to a temp directory.

    Returns a CrxDownloadResult with the extraction directory and manifest.
    The caller is responsible for cleaning up the temp directory.
    """
    import json

    result = CrxDownloadResult(extension_id=extension_id, success=False)

    # Download
    crx_data = download_crx(extension_id)
    if not crx_data:
        result.error = "CRX download failed — extension may not be on Chrome Web Store"
        return result

    # Extract to temp directory
    temp_dir = Path(tempfile.mkdtemp(prefix=f"mg_crx_{extension_id[:8]}_"))
    if not extract_crx(crx_data, temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
        result.error = "Failed to extract CRX archive"
        return result

    # Read manifest
    manifest_path = temp_dir / "manifest.json"
    if not manifest_path.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)
        result.error = "No manifest.json found in CRX"
        return result

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        result.error = "Failed to parse manifest.json"
        return result

    # Count extracted files
    file_count = sum(1 for _ in temp_dir.rglob("*") if _.is_file())

    result.success = True
    result.extract_dir = temp_dir
    result.manifest = manifest
    result.file_count = file_count
    return result


def cleanup_extraction(extract_dir: Path | None) -> None:
    """Remove a temporary extraction directory."""
    if extract_dir and extract_dir.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)
