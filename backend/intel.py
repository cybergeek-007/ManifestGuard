from __future__ import annotations

from backend.models import IntelMatch

INTEL_REGISTRY: dict[str, list[IntelMatch]] = {
    "pejdijmoenmkgeppbflobdenhhabjlaj": [
        IntelMatch(
            extension_id="pejdijmoenmkgeppbflobdenhhabjlaj",
            label="Cyberhaven compromised build window",
            source="CSA Singapore Alert AL-2024-147",
            source_url="https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2024-147/",
            confidence="medium",
            detail="Listed among extensions observed carrying malicious code in the December 30, 2024 advisory.",
        )
    ],
    "mdaboflcmhejfihjcbmdiebgfchigjcf": [
        IntelMatch(
            extension_id="mdaboflcmhejfihjcbmdiebgfchigjcf",
            label="Blipshot campaign cluster",
            source="GitLab Threat Intelligence 2025-02-13",
            source_url="https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/malicious-browser-extensions-feb-2025/",
            confidence="high",
            detail="Clustered with trojanized extensions that stripped CSP and supported second-stage payloads.",
        )
    ],
    "gaoflciahikhligngeccdecgfjngejlh": [
        IntelMatch(
            extension_id="gaoflciahikhligngeccdecgfjngejlh",
            label="Emoji Keyboard malicious cluster",
            source="GitLab Threat Intelligence 2025-02-13",
            source_url="https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/malicious-browser-extensions-feb-2025/",
            confidence="high",
            detail="Identified as part of a coordinated extension fraud and injection campaign.",
        )
    ],
}


def lookup_intel(extension_id: str) -> list[IntelMatch]:
    return [match for match in INTEL_REGISTRY.get(extension_id, [])]
