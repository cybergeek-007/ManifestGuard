"""ManifestGuard v5 — Clone / Repackaging Detection.

Detects extensions whose JavaScript is a near-duplicate of another,
previously fingerprinted extension.  This catches a real, high-impact
attack class: attackers download a popular extension (e.g. "AdBlock"),
inject a malicious payload, and republish it under a slightly different
name.  The clone shares ~95%+ of its code with the original but is a
distinct listing with a distinct extension ID.

Technique
---------
1. Tokenize every JS file into overlapping k-token shingles.
2. Fold the shingle set into a 64-bit SimHash (Charikar's algorithm).
   SimHash is locality-sensitive: two near-identical codebases produce
   two hashes that differ in only a handful of bits (small Hamming
   distance), while unrelated code differs in ~32 bits on average.
3. Similarity = 1 - (hamming_distance / 64).
4. We also keep per-file SHA-256 hashes so we can report the exact
   percentage of byte-identical files shared between two extensions.

No third-party dependencies — pure Python, deterministic, explainable.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Number of tokens per shingle. 4 balances sensitivity vs. noise.
_SHINGLE_SIZE = 4
# SimHash bit width.
_HASH_BITS = 64
# Similarity at/above this is reported as a likely clone.
CLONE_THRESHOLD = 0.85
# Skip files larger than this to keep fingerprinting fast.
_MAX_JS_BYTES = 2_000_000
# Cap total JS processed per extension.
_MAX_TOTAL_BYTES = 12_000_000

# Simple JS tokenizer: identifiers/keywords, numbers, or single symbols.
_TOKEN_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*|\d+|\S")


@dataclass(slots=True)
class Fingerprint:
    """A code fingerprint for one extension version."""

    extension_id: str
    version: str
    name: str
    simhash: int
    file_hashes: set[str]
    js_file_count: int
    total_js_bytes: int

    def to_record(self) -> dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "version": self.version,
            "name": self.name,
            "simhash": format(self.simhash, "016x"),
            "file_hashes": sorted(self.file_hashes),
            "js_file_count": self.js_file_count,
            "total_js_bytes": self.total_js_bytes,
        }


@dataclass(slots=True)
class CloneMatch:
    """A detected near-duplicate relationship to another extension."""

    extension_id: str
    name: str
    version: str
    similarity: float           # 0.0 - 1.0 (SimHash based)
    shared_file_ratio: float    # 0.0 - 1.0 (byte-identical files)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "extensionId": self.extension_id,
            "name": self.name,
            "version": self.version,
            "similarity": round(self.similarity, 4),
            "sharedFileRatio": round(self.shared_file_ratio, 4),
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CloneMatch":
        return cls(
            extension_id=str(payload.get("extensionId", payload.get("extension_id", ""))),
            name=str(payload.get("name", "")),
            version=str(payload.get("version", "")),
            similarity=float(payload.get("similarity", 0.0)),
            shared_file_ratio=float(payload.get("sharedFileRatio", payload.get("shared_file_ratio", 0.0))),
            detail=str(payload.get("detail", "")),
        )


def _tokenize(source: str) -> list[str]:
    return _TOKEN_RE.findall(source)


def _shingles(tokens: list[str], size: int = _SHINGLE_SIZE) -> list[str]:
    if len(tokens) < size:
        return [" ".join(tokens)] if tokens else []
    return [" ".join(tokens[i : i + size]) for i in range(len(tokens) - size + 1)]


def _simhash(shingles: list[str]) -> int:
    """Charikar SimHash over a bag of shingles."""
    if not shingles:
        return 0
    vector = [0] * _HASH_BITS
    for shingle in shingles:
        h = int.from_bytes(
            hashlib.blake2b(shingle.encode("utf-8", "ignore"), digest_size=8).digest(),
            "big",
        )
        for bit in range(_HASH_BITS):
            if (h >> bit) & 1:
                vector[bit] += 1
            else:
                vector[bit] -= 1
    result = 0
    for bit in range(_HASH_BITS):
        if vector[bit] > 0:
            result |= 1 << bit
    return result


def _hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def simhash_similarity(a: int, b: int) -> float:
    """Similarity in [0, 1] derived from Hamming distance of two SimHashes."""
    return 1.0 - (_hamming(a, b) / _HASH_BITS)


def fingerprint_directory(
    extract_dir: Path,
    extension_id: str,
    version: str,
    name: str,
) -> Fingerprint | None:
    """Build a code fingerprint from an extracted extension directory.

    Returns None if the directory has no analyzable JavaScript.
    """
    all_shingles: list[str] = []
    file_hashes: set[str] = set()
    js_file_count = 0
    total_bytes = 0

    try:
        js_files = sorted(extract_dir.rglob("*.js"))
    except Exception:
        return None

    for js_file in js_files:
        try:
            size = js_file.stat().st_size
            if size == 0 or size > _MAX_JS_BYTES:
                continue
            if total_bytes + size > _MAX_TOTAL_BYTES:
                break
            raw = js_file.read_bytes()
        except Exception:
            continue

        total_bytes += size
        js_file_count += 1
        file_hashes.add(hashlib.sha256(raw).hexdigest())

        try:
            source = raw.decode("utf-8", "ignore")
        except Exception:
            continue
        tokens = _tokenize(source)
        all_shingles.extend(_shingles(tokens))

    if js_file_count == 0:
        return None

    return Fingerprint(
        extension_id=extension_id,
        version=version,
        name=name,
        simhash=_simhash(all_shingles),
        file_hashes=file_hashes,
        js_file_count=js_file_count,
        total_js_bytes=total_bytes,
    )


def _shared_file_ratio(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    smaller = min(len(a), len(b))
    return intersection / smaller if smaller else 0.0


def find_clones(
    fingerprint: Fingerprint,
    candidates: list[dict[str, Any]],
    threshold: float = CLONE_THRESHOLD,
) -> list[CloneMatch]:
    """Compare a fingerprint against previously stored fingerprints.

    `candidates` are rows from Database.load_all_fingerprints():
    dicts with extension_id, version, name, simhash (hex), file_hashes.
    Returns clone matches sorted by descending similarity.
    """
    matches: list[CloneMatch] = []
    my_hashes = fingerprint.file_hashes

    for cand in candidates:
        cand_id = str(cand.get("extension_id", ""))
        if not cand_id or cand_id == fingerprint.extension_id:
            continue
        try:
            cand_simhash = int(str(cand.get("simhash", "0")), 16)
        except ValueError:
            continue

        similarity = simhash_similarity(fingerprint.simhash, cand_simhash)
        cand_hashes = set(cand.get("file_hashes", []))
        shared = _shared_file_ratio(my_hashes, cand_hashes)

        # Report if either the fuzzy hash OR the exact-file overlap is high.
        if similarity >= threshold or shared >= 0.6:
            detail = (
                f"{int(similarity * 100)}% code similarity"
                + (f", {int(shared * 100)}% identical files" if shared else "")
                + f" to '{cand.get('name', cand_id)}'"
            )
            matches.append(
                CloneMatch(
                    extension_id=cand_id,
                    name=str(cand.get("name", cand_id)),
                    version=str(cand.get("version", "")),
                    similarity=similarity,
                    shared_file_ratio=shared,
                    detail=detail,
                )
            )

    matches.sort(key=lambda m: (m.similarity, m.shared_file_ratio), reverse=True)
    return matches[:5]
