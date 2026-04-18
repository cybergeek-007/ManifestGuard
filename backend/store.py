from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


UPDATE_ENDPOINT = (
    "https://clients2.google.com/service/update2/crx?"
    "response=manifest&prodversion=125.0.0.0&acceptformat=crx2,crx3&x=id%3D{extension_id}%26uc"
)


@dataclass(slots=True)
class StoreLookupResult:
    status: str
    detail: str
    source_url: str

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "detail": self.detail, "sourceUrl": self.source_url}


def lookup_store_status(extension_id: str, timeout: float = 4.0) -> StoreLookupResult:
    url = UPDATE_ENDPOINT.format(extension_id=urllib.parse.quote(extension_id))
    request = urllib.request.Request(url, headers={"User-Agent": "ManifestGuard/2.0"})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return StoreLookupResult("unavailable_or_removed", "Update manifest returned 404.", url)
        return StoreLookupResult("lookup_failed", f"HTTP {exc.code} while checking store status.", url)
    except Exception as exc:  # pragma: no cover - network dependent
        return StoreLookupResult("lookup_failed", f"Lookup failed: {exc}", url)

    lowered = body.lower()
    if "<updatecheck" in lowered or "<app " in lowered:
        return StoreLookupResult("listed", "Extension update metadata is available.", url)
    if "error-unknownapplication" in lowered or "unknown application" in lowered:
        return StoreLookupResult("unavailable_or_removed", "Chrome update service reports the extension as unavailable.", url)

    return StoreLookupResult("lookup_failed", "Unable to determine Chrome Web Store availability.", url)


def serialize_store_result(result: StoreLookupResult) -> str:
    return json.dumps(result.to_dict(), sort_keys=True)
