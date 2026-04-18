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

### `> Evidence-Driven Local Extension Auditor_`

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
![FastAPI](https://img.shields.io/badge/fastapi-v2_backend-00ff41?style=for-the-badge&logo=fastapi&logoColor=00ff41&labelColor=0d1117)
![React](https://img.shields.io/badge/react-typescript_ui-00ff41?style=for-the-badge&logo=react&logoColor=00ff41&labelColor=0d1117)
![Local First](https://img.shields.io/badge/privacy-local--first-00ff41?style=for-the-badge&labelColor=0d1117)
![Status](https://img.shields.io/badge/status-ACTIVE-00ff41?style=for-the-badge&labelColor=0d1117)

</div>

---

```
root@manifestguard:~# cat /etc/motd
```

## `> ./overview.sh`

Most extension scanners stop at **permissions**. That creates noise. Security tools, password managers, OSINT helpers, and developer extensions often need broad access to do legitimate work.

**ManifestGuard v2** is built to separate:

```diff
+ powerful but expected access
+ suspicious implementation signals
+ known malicious / removed extension intelligence
- "all high permissions = malware"
- missing profile-aware inventory
- missing localized names and real extension identity
```

It now works like a real local audit system instead of a one-file prototype:

```
[*] Enumerates Chrome / Chromium profiles                ✓
[*] Resolves localized manifest names                    ✓
[*] Scores power vs suspicion separately                 ✓
[*] Tracks store status when live checks are enabled     ✓
[*] Persists past scans under backend/data               ✓
[*] Exports CSV / JSON / HTML / PDF reports              ✓
```

---

## `> cat features.log`

```
┌──────────────────────────────────────────────────────────────────┐
│  MODULE                  │ STATUS  │ DESCRIPTION                 │
├──────────────────────────────────────────────────────────────────┤
│  backend/scanner.py      │ [LIVE]  │ Multi-profile ext scanner   │
│  backend/service.py      │ [LIVE]  │ Scan persistence + reports  │
│  backend/store.py        │ [LIVE]  │ Chrome Web Store checks     │
│  backend/intel.py        │ [LIVE]  │ Curated bad-extension DB    │
│  backend/ai.py           │ [LIVE]  │ Optional AI explanations    │
│  frontend/src/App.tsx    │ [LIVE]  │ React audit dashboard       │
└──────────────────────────────────────────────────────────────────┘
```

| Feature | Detail |
|:--------|:-------|
| 🧭 **Tiered Verdicts** | `low_concern`, `powerful_but_expected`, `suspicious`, `known_malicious`, `removed_or_unavailable`, `disabled_by_chrome`, `unknown` |
| 🧠 **Dual Scoring** | `powerScore` measures reach, `suspicionScore` measures abnormal behavior |
| 🌍 **Profile-Aware Scans** | Scans `Default`, `Profile 1`, `Profile 2`, Beta/Dev/Chromium roots |
| 🈯 **Localized Names** | Resolves `__MSG_*__` via `_locales/.../messages.json` instead of showing `Localized Extension` |
| 📦 **Persistent History** | Reloads past scans from `backend/data/` on startup |
| 📄 **Rich Reports** | CSV for inventory, JSON for automation, HTML/PDF for shareable review |

---

## `> cat detection.engine`

### Classification Strategy

```
POWER SCORE        → "How much browser/data access does this extension have?"
SUSPICION SCORE    → "How much does its code/package behave like a malicious extension?"
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
```

### Intelligence Inputs

```
LOCAL ANALYSIS            [PRIMARY]
CHROME WEB STORE STATUS   [OPTIONAL]
CURATED THREAT REGISTRY   [OPTIONAL]
AI EXPLANATION LAYER      [OPTIONAL, NON-AUTHORITATIVE]
```

---

## `> cat architecture.md`

```
                  ┌──────────────────────────────────────────┐
                  │              M A N I F E S T G U A R D   │
                  └──────────────────────┬───────────────────┘
                                         │
                  ┌──────────────────────▼───────────────────┐
                  │              FASTAPI BACKEND             │
                  │  scan api │ import api │ report api      │
                  └──────────────────────┬───────────────────┘
                                         │
          ┌──────────────────────────────┼──────────────────────────────┐
          ▼                              ▼                              ▼
 ┌──────────────────┐         ┌──────────────────┐          ┌──────────────────┐
 │ PROFILE SCANNER  │         │ STORE ENRICHMENT │          │ INTEL MATCHER    │
 │ manifest parsing │         │ listed / removed │          │ known bad IDs    │
 └────────┬─────────┘         └────────┬─────────┘          └────────┬─────────┘
          └────────────────────────────┼─────────────────────────────┘
                                       ▼
                          ┌──────────────────────────┐
                          │ CLASSIFICATION ENGINE    │
                          │ power + suspicion +      │
                          │ deterministic verdict    │
                          └────────────┬─────────────┘
                                       ▼
                          ┌──────────────────────────┐
                          │ REACT + TYPESCRIPT UI    │
                          │ controls │ queue │ detail│
                          └──────────────────────────┘
```

### Project Layout

```text
backend/
  api.py
  main.py
  serve.py
  scanner.py
  service.py
  reports.py
  ai.py
  intel.py
  store.py
frontend/
  src/
tests/
app.py
start-backend.ps1
start-frontend.ps1
start-dev.ps1
```

---

## `> ./install.sh`

### Requirements

```
[✓] Python 3.14+
[✓] Node.js / npm.cmd
[✓] Chrome / Chromium installed locally
[✓] Optional AI key for summaries
```

### Backend

```bash
pip install -r requirements.txt
python app.py
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
POST   /api/scans
GET    /api/scans
GET    /api/scans/{scanId}
GET    /api/scans/{scanId}/extensions
GET    /api/scans/{scanId}/extensions/{extensionId}
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
PDF   → locally rendered printable summary
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
+ Live Chrome Web Store checks are optional
+ Scan history survives app restarts
+ Known bad IDs can promote verdicts immediately
- "lookup_failed" does NOT mean removed
- A powerful extension is NOT automatically malicious
```

---

## `> cat roadmap.todo`

```text
[x] Replace Streamlit prototype with FastAPI + React
[x] Add profile-aware scanner
[x] Resolve localized manifest strings
[x] Add store-status enrichment
[x] Add curated threat-intel registry
[x] Add persistent scan history
[x] Add HTML / PDF / JSON reporting
[ ] Scan-to-scan comparison view
[ ] One-click remediation actions
[ ] Multi-browser support (Edge / Brave / Opera)
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
│  $ manifestguard --scan --profiles all --live-checks         │
│                                                              │
│  [✓] inventory loaded                                        │
│  [✓] evidence classified                                     │
│  [✓] reports ready                                           │
│                                                              │
│  Your browser is only as safe as the extensions you keep.    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

</div>
