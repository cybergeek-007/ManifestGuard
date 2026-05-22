<div align="center">

```
 ███╗   ███╗ █████╗ ███╗   ██╗██╗███████╗███████╗ ██████╗████████╗
 ████╗ ████║██╔══██╗████╗  ██║██║██╔════╝██╔════╝██╔════╝╚══██╔══╝
 ██╔████╔██║███████║██╔██╗ ██║██║█████╗  █████╗  ╚█████╗    ██║
 ██║╚██╔╝██║██╔══██║██║╚██╗██║██║██╔══╝  ██╔══╝   ╚═══██╗   ██║
 ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║██║     ███████╗██████╔╝   ██║
 ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═════╝    ╚═╝
              ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
             ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
             ██║  ██╗ ██║   ██║███████║██████╔╝██║  ██║
             ██║  ╚██╗██║   ██║██╔══██║██╔══██╗██║  ██║
             ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
              ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

### `> Evidence-Driven Extension Auditor_`

<br>

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  "Know which extensions are merely powerful, and which are   │
│   actually suspicious."                                      │
│                                                              │
│  [ ANALYZING... ]  ████████████████████████████░░  93%        │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

<br>

![Python](https://img.shields.io/badge/python-3.14+-00ff41?style=for-the-badge&logo=python&logoColor=00ff41&labelColor=0d1117)
![FastAPI](https://img.shields.io/badge/fastapi-v3_backend-00ff41?style=for-the-badge&logo=fastapi&logoColor=00ff41&labelColor=0d1117)
![React](https://img.shields.io/badge/react-typescript_ui-00ff41?style=for-the-badge&logo=react&logoColor=00ff41&labelColor=0d1117)
![Cloud Ready](https://img.shields.io/badge/deployment-render_ready-00ff41?style=for-the-badge&labelColor=0d1117)
![Status](https://img.shields.io/badge/status-ACTIVE-00ff41?style=for-the-badge&labelColor=0d1117)

</div>

---

```
root@manifestguard:~# cat /etc/motd
```

## `> ./overview.sh`

Most extension scanners stop at **permissions**. That creates noise. Security tools, password managers, OSINT helpers, and developer extensions often need broad access to do legitimate work.

**ManifestGuard v3** introduces a true multi-layered approach to extension security, separating legitimate power from actual malice using deep behavioral analysis, publisher reputation, and curated intelligence.

```diff
+ Online backend for deep source-code analysis (CRX extraction)
+ CWS Reputation Engine (scoring extensions 0-100 based on users, ratings, badges)
+ Safe Alternative Recommendations (powered by a 200+ curated allowlist)
+ Tiered Verdicts (including the new `moderate_risk` bucket)
- "all high permissions = malware"
- noisy false positives on popular trusted tools
```

It now operates as a robust API service ready for cloud deployment (e.g., Render), integrating seamlessly with a companion extension.

---

## `> cat features.log`

```
┌──────────────────────────────────────────────────────────────────┐
│  MODULE                  │ STATUS  │ DESCRIPTION                 │
├──────────────────────────────────────────────────────────────────┤
│  backend/scanner.py      │ [LIVE]  │ Core static code analyzer   │
│  backend/crx_analyzer.py │ [NEW]   │ Online CRX downloader & ext │
│  backend/reputation.py   │ [NEW]   │ CWS Reputation Scorer       │
│  backend/recommendations.│ [NEW]   │ Safe Alternatives Engine    │
│  backend/allowlist.py    │ [NEW]   │ 200+ Trusted Publishers     │
│  backend/reports.py      │ [LIVE]  │ Zero-dependency PDF/HTML/CSV│
│  frontend/src/App.tsx    │ [LIVE]  │ React audit dashboard       │
└──────────────────────────────────────────────────────────────────┘
```

| Feature | Detail |
|:--------|:-------|
| 🧭 **Tiered Verdicts** | `low_concern`, `powerful_but_expected`, `moderate_risk`, `suspicious`, `known_malicious`, `removed_or_unavailable`, `disabled_by_chrome`, `unknown` |
| 🧠 **Multi-Dimensional Scoring** | `powerScore` (reach), `suspicionScore` (behavior), and `reputationScore` (trust) |
| 🛡️ **Safe Recommendations** | Suggests trusted alternatives (e.g., uBlock Origin) when scanning malicious tools |
| 📦 **Deep Source Analysis** | Downloads CRX packages directly from Google to analyze actual source code |
| 🌍 **Online Architecture** | Designed as a central backend service accessible via API for companion extensions |
| 📄 **Rich Reports** | CSV for inventory, JSON for automation, HTML/PDF for shareable review |

---

## `> cat detection.engine`

### Classification Strategy

```
POWER SCORE        → "How much browser/data access does this extension have?"
REPUTATION SCORE   → "How trusted is this publisher in the Chrome Web Store?"
SUSPICION SCORE    → "Does the code contain indicators of compromise? (Adjusted by Reputation)"
VERDICT            → "What should the user actually think about it?"
```

### Suspicious Signals Checked

```
[01] Remote config / heartbeat fetching
[02] Remote script injection into page context
[03] CSP or header tampering patterns
[04] Heavy obfuscation / eval / Function usage
[05] Broad host access + cookie/session-sensitive perms
[06] Purpose-permission mismatch
[07] Potential cryptocurrency mining
[08] Clipboard tampering / Credential harvesting
```

### Intelligence Inputs

```
DEEP SOURCE CODE ANALYSIS [PRIMARY]
CHROME WEB STORE REPUTATION [PRIMARY]
CURATED ALLOWLIST / REGISTRY [PRIMARY]
AI EXPLANATION LAYER [OPTIONAL, NON-AUTHORITATIVE]
```

---

## `> cat architecture.md`

```mermaid
graph TD
    UI[Frontend Dashboard<br/>React/Vite] --> API[FastAPI Backend]
    Companion[Companion Extension<br/>(Future)] --> API
    
    subgraph "Backend Engine"
        API --> Scanner[Core Scanner Engine]
        API --> CRX[CRX Downloader/Extractor]
        
        CRX --> CWS[Chrome Web Store]
        
        Scanner --> Rep[Reputation Engine]
        Scanner --> Recs[Recommendation Engine]
        Scanner --> Intel[Threat Intel]
        Scanner --> AI[AI Summarizer]
        
        Rep --> CWS
        Recs --> Allowlist[(205+ Trusted Allowlist)]
    end
    
    Scanner --> DB[(Local JSON DB / Reports)]
```

### Data & API Layer
- **`api.py`**: Defines the REST routes. The most critical route is `/api/scans/online`, which accepts an extension payload and triggers the cloud analysis pipeline.
- **`models.py`**: Strict Pydantic data validation for all inputs and outputs.
- **`service.py`**: Handles state persistence, saving scan results so they survive server restarts.

### Analysis & Classification Engine
- **`crx_analyzer.py`**: A highly sophisticated module that bypasses the need for local filesystem access. It constructs Google API URLs to download `.crx` files directly, strips CRX2/CRX3 protobuf headers, and extracts the raw ZIP payload into memory for static analysis.
- **`scanner.py`**: The core classification engine. It calculates two distinct metrics: **Power Score** (reach/permissions) and **Suspicion Score** (dangerous code indicators). It then factors in the Reputation Score to assign a final, deterministic verdict.

### Enrichment Modules
- **`reputation.py`**: Scrapes the Chrome Web Store to gather user counts, ratings, and developer badges, translating these into a `0-100` Reputation Score. This dynamically adjusts the suspicion score (suppressing false positives for trusted tools).
- **`recommendations.py` & `allowlist.py`**: Infers the category of a scanned extension and cross-references a curated dataset of **205+ verified extensions** to propose safe alternatives.
- **`ai.py`**: An optional LLM integration (Groq/OpenAI) that translates raw security data into a conversational executive summary.

### Reporting
- **`reports.py`**: Generates JSON, CSV, HTML, and features a custom `_PdfWriter` to export styled PDF reports without relying on heavy external dependencies.

---

## `> ./install.sh`

### Requirements

```
[✓] Python 3.14+
[✓] Node.js / npm
[✓] Optional AI keys for summaries (Groq API supported)
```

### Backend (Local / Render)

```bash
pip install -r requirements.txt
python backend/main.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Default Ports

```text
API      → http://127.0.0.1:8000
WEB UI   → http://127.0.0.1:5173
```

---

## `> cat windows.shortcuts`

```powershell
.\start-backend.ps1
.\start-frontend.ps1
```

Detached startup:

```powershell
.\start-dev.ps1 -Detached
```

If your backend shell exits unexpectedly:

```powershell
.\start-backend.ps1 -Detached -WaitForHealth
```

> On this machine, `npm.cmd` is the reliable frontend launcher instead of bare `npm`.

---

## `> curl /api/routes`

```text
POST   /api/scans/online   (v3 Online scan trigger)
POST   /api/scans          (Local filesystem scan)
GET    /api/scans
GET    /api/scans/{scanId}
GET    /api/scans/{scanId}/extensions
GET    /api/scans/{scanId}/extensions/{extensionId}/recommendations
GET    /api/scans/{scanId}/reports/{format}
POST   /api/imports/csv
GET    /api/health
```

---

## `> cat report.formats`

```
CSV   → flat extension inventory
JSON  → full structured evidence export
HTML  → shareable styled audit report
PDF   → locally rendered printable summary (Zero-dependencies!)
```

Stored scan artifacts live in:

```text
backend/data/
```

---

## `> cat ai.conf`

AI is optional and does **not** decide the final verdict.

Supported environment variables:

```text
MANIFESTGUARD_AI_API_KEY
MANIFESTGUARD_AI_BASE_URL
MANIFESTGUARD_AI_MODEL
groq_api_key
```

Use AI for:

```
[✓] plain-English explanations
[✓] summarizing why an extension was flagged
[✓] user-friendly remediation guidance
[x] overriding deterministic classification
```

---

## `> cat notes.txt`

```diff
+ Online backend downloads source code independently (no filesystem access needed)
+ Reputation Engine suppresses false positives for trusted tools automatically
+ Safe Alternatives Engine guides users to better choices
- "lookup_failed" does NOT mean removed
- A powerful extension is NOT automatically malicious
```

---

## `> cat roadmap.todo`

```text
[x] Replace Streamlit prototype with FastAPI + React
[x] Add profile-aware scanner
[x] Add store-status enrichment
[x] Add HTML / PDF / JSON reporting
[x] Add CRX extraction for online code analysis
[x] Add Reputation Engine
[x] Add Recommendation Engine + Allowlist
[ ] Scan-to-scan comparison view
[ ] One-click remediation actions via companion extension
```

---

## `> cat DISCLAIMER.txt`

```
ManifestGuard is an audit and triage tool.

It is designed to reduce false positives, not eliminate judgment.
A verdict of "powerful_but_expected" means the extension has broad
reach but currently lacks stronger malicious evidence.

Always review:
  → source trust
  → publisher reputation
  → store status
  → whether you still need the extension
```

---

<div align="center">

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  $ curl -X POST /api/scans/online                            │
│                                                              │
│  [✓] CRX downloaded & extracted                              │
│  [✓] Reputation scored                                       │
│  [✓] Safe alternatives mapped                                │
│                                                              │
│  Your browser is only as safe as the extensions you keep.    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

</div>
