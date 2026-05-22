from __future__ import annotations

from backend.models import IntelMatch

INTEL_REGISTRY: dict[str, list[IntelMatch]] = {
    # ── Cyberhaven breach (December 2024) ─────────────────────
    "pejdijmoenmkgeppbflobdenhhabjlaj": [
        IntelMatch(
            extension_id="pejdijmoenmkgeppbflobdenhhabjlaj",
            label="Cyberhaven compromised build window",
            source="CSA Singapore Alert AL-2024-147",
            source_url="https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2024-147/",
            confidence="medium",
            detail="Listed among extensions observed carrying malicious code in the December 30, 2024 advisory.",
            category="compromised_supply_chain",
        )
    ],
    # ── GitLab TI malicious cluster (Feb 2025) ────────────────
    "mdaboflcmhejfihjcbmdiebgfchigjcf": [
        IntelMatch(
            extension_id="mdaboflcmhejfihjcbmdiebgfchigjcf",
            label="Blipshot campaign cluster",
            source="GitLab Threat Intelligence 2025-02-13",
            source_url="https://gitlab-com.gitlab.io/gl-security/security-tech-notes/threat-intelligence-tech-notes/malicious-browser-extensions-feb-2025/",
            confidence="high",
            detail="Clustered with trojanized extensions that stripped CSP and supported second-stage payloads.",
            category="malware",
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
            category="malware",
        )
    ],
    # ── ChatGPT-themed phishing extensions ─────────────────────
    "biihmcacfjcankndbnogbbhkgimplicl": [
        IntelMatch(
            extension_id="biihmcacfjcankndbnogbbhkgimplicl",
            label="Fake ChatGPT extension (data harvester)",
            source="Guardio Security Research 2023-03",
            source_url="https://labs.guard.io/fakegpt-new-variant-of-fake-chatgpt-chrome-extension-stealing-facebook-ad-accounts-with-4c9996a8f282",
            confidence="high",
            detail="Masqueraded as ChatGPT utility. Stole Facebook session cookies and business account credentials.",
            category="spyware",
        )
    ],
    # ── The Great Suspender (malicious after acquisition) ──────
    "dknlfmjaanfblgfdfebhijalfmhmjjjo": [
        IntelMatch(
            extension_id="dknlfmjaanfblgfdfebhijalfmhmjjjo",
            label="The Great Suspender (compromised)",
            source="Google Chrome Web Store takedown 2021-02",
            source_url="https://github.com/nicedoc/the-great-suspender/issues/44",
            confidence="high",
            detail="Acquired by unknown entity; injected tracking and ad code after ownership transfer. Removed by Google.",
            category="adware",
        )
    ],
    # ── DataSpii extensions (data harvesting campaign) ─────────
    "nfkknmgnmamgoddljhganmoadafmddme": [
        IntelMatch(
            extension_id="nfkknmgnmamgoddljhganmoadafmddme",
            label="Hover Zoom+ (DataSpii campaign)",
            source="Sam Jadali DataSpii Research 2019",
            source_url="https://dataspii.com/",
            confidence="high",
            detail="Collected browsing data including PII and corporate data, sent to analytics company for monetization.",
            category="data_harvester",
        )
    ],
    # ── PDF Toolbox (known ad injector) ────────────────────────
    "jeoacafpbcihiomhlakheieifhpjdfeo": [
        IntelMatch(
            extension_id="jeoacafpbcihiomhlakheieifhpjdfeo",
            label="PDF Toolbox (ad injection network)",
            source="Palant Security Research 2023-05",
            source_url="https://palant.info/2023/05/31/more-malicious-extensions-in-chrome-web-store/",
            confidence="high",
            detail="Part of a network of extensions injecting ads and affiliate codes into web pages via remote configuration.",
            category="adware",
        )
    ],
    # ── Autoskip for Youtube (data exfiltration) ──────────────
    "lgjdgmdbfhobkdbcjnpnlmhnplnidkkp": [
        IntelMatch(
            extension_id="lgjdgmdbfhobkdbcjnpnlmhnplnidkkp",
            label="Autoskip for Youtube (data exfiltration)",
            source="McAfee Threat Research 2022-08",
            source_url="https://www.mcafee.com/blogs/other-blogs/mcafee-labs/cookie-stealing-extensions/",
            confidence="high",
            detail="Tracked user browsing activity and exfiltrated data including cookies to remote servers.",
            category="spyware",
        )
    ],
    # ── Netflix Party (session hijacking) ──────────────────────
    "mmnbenehknklpbendgmgngeaignppnbe": [
        IntelMatch(
            extension_id="mmnbenehknklpbendgmgngeaignppnbe",
            label="Netflix Party (cookie theft variant)",
            source="McAfee Threat Research 2022-08",
            source_url="https://www.mcafee.com/blogs/other-blogs/mcafee-labs/cookie-stealing-extensions/",
            confidence="medium",
            detail="Clone of legitimate Netflix Party extension that injected tracking code and captured session data.",
            category="spyware",
        )
    ],
    # ── SearchBlox (Roblox credential stealer) ─────────────────
    "cbkfcfboeakknobhomlfkminbjnphahp": [
        IntelMatch(
            extension_id="cbkfcfboeakknobhomlfkminbjnphahp",
            label="SearchBlox (Roblox credential stealer)",
            source="BleepingComputer 2022-11",
            source_url="https://www.bleepingcomputer.com/news/security/roblox-game-pass-store-used-to-sell-stolen-credentials/",
            confidence="high",
            detail="Targeted Roblox players. Injected credential-stealing JavaScript into Roblox pages to harvest login tokens.",
            category="credential_stealer",
        )
    ],
    # ── Internet Download Manager (fake/malicious) ─────────────
    "lcdlanlaneooailneapmjppndnahkfoe": [
        IntelMatch(
            extension_id="lcdlanlaneooailneapmjppndnahkfoe",
            label="Fake Internet Download Manager",
            source="ExtensionTotal Research 2023",
            source_url="https://blog.extensiontotal.com/malicious-extensions-masquerading-as-popular-tools",
            confidence="medium",
            detail="Impersonated the popular IDM extension. Injected ads and redirected search queries for revenue.",
            category="adware",
        )
    ],
    # ── View-Source extension (credential phishing) ────────────
    "dkfhfaphfkopdgpbfkebjfclaofkolba": [
        IntelMatch(
            extension_id="dkfhfaphfkopdgpbfkebjfclaofkolba",
            label="View-Source (phishing overlay)",
            source="CISA Advisory 2023",
            source_url="https://www.cisa.gov/news-events/alerts",
            confidence="medium",
            detail="Overlaid phishing forms on login pages for popular services to capture credentials.",
            category="credential_stealer",
        )
    ],
    # ── Rilide stealer family ──────────────────────────────────
    "pnblhbgijjefjkopjfbmdjjboabkogab": [
        IntelMatch(
            extension_id="pnblhbgijjefjkopjfbmdjjboabkogab",
            label="Rilide Stealer variant",
            source="Trustwave SpiderLabs 2023-04",
            source_url="https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rilide-a-new-malicious-browser-extension-for-stealing-cryptocurrencies/",
            confidence="high",
            detail="Sophisticated stealer targeting cryptocurrency wallets. Replaces legitimate withdrawal addresses and captures 2FA codes.",
            category="crypto_stealer",
        )
    ],
    # ── Copycat VPN extensions ─────────────────────────────────
    "okfndbbkfdgjfopknhfgjiaeemahgmea": [
        IntelMatch(
            extension_id="okfndbbkfdgjfopknhfgjiaeemahgmea",
            label="Fake VPN Pro (traffic interception)",
            source="ReasonLabs Research 2023-12",
            source_url="https://reasonlabs.com/research/massive-campaign-fake-vpn-extensions",
            confidence="high",
            detail="Part of a massive campaign (1.5M users) using fake VPN extensions to hijack browsers and inject cashback affiliate codes.",
            category="adware",
        )
    ],
    # ── ChromeLoader / Shampoo campaign ────────────────────────
    "fgihkjmiinmojmncbkefoidlnkfhgkdh": [
        IntelMatch(
            extension_id="fgihkjmiinmojmncbkefoidlnkfhgkdh",
            label="ChromeLoader / Shampoo variant",
            source="HP Wolf Security 2023-03",
            source_url="https://threatresearch.ext.hp.com/shampoo-a-new-chromeloader-campaign/",
            confidence="high",
            detail="Distributed via malvertising. Forces installation, hijacks search queries, and is extremely persistent (re-installs itself via scheduled tasks).",
            category="browser_hijacker",
        )
    ],
    # ── Quick access to ChatGPT (Facebook account theft) ───────
    "gfhnliecanfpnoihopjacflnlnbciekp": [
        IntelMatch(
            extension_id="gfhnliecanfpnoihopjacflnlnbciekp",
            label="Quick access to ChatGPT (Facebook stealer)",
            source="Guardio Security Research 2023-03",
            source_url="https://labs.guard.io/fakegpt-new-variant-of-fake-chatgpt-chrome-extension-stealing-facebook-ad-accounts-with-4c9996a8f282",
            confidence="high",
            detail="Harvested Facebook session cookies and ad account data. Used ChatGPT branding to appear legitimate.",
            category="spyware",
        )
    ],
    # ── CacheFlow campaign (hidden data harvesting) ────────────
    "cmkjegemnfhbfkhcimmaocbahpoojfga": [
        IntelMatch(
            extension_id="cmkjegemnfhbfkhcimmaocbahpoojfga",
            label="CacheFlow campaign extension",
            source="Avast Threat Intelligence 2021-02",
            source_url="https://decoded.avast.io/janvojtesek/backdoored-browser-extensions-hid-malicious-traffic-in-analytics-requests/",
            confidence="high",
            detail="Hid C2 traffic inside Google Analytics requests. Collected browsing history and injected JavaScript into pages.",
            category="data_harvester",
        )
    ],
}


def lookup_intel(extension_id: str) -> list[IntelMatch]:
    return [match for match in INTEL_REGISTRY.get(extension_id, [])]
