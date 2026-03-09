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

### `> AI-Powered Local Extension Auditor_`

<br>

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│  "Know what your browser extensions know about you."     │
│                                                          │
│  [ SCANNING... ]  ██████████████████████████░░  89%      │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

<br>

![Python 3.9+](https://img.shields.io/badge/python-3.9+-00ff41?style=for-the-badge&logo=python&logoColor=00ff41&labelColor=0d1117)
![Streamlit](https://img.shields.io/badge/streamlit-1.28+-00ff41?style=for-the-badge&logo=streamlit&logoColor=00ff41&labelColor=0d1117)
![Groq](https://img.shields.io/badge/Groq-LLM-00ff41?style=for-the-badge&logo=openai&logoColor=00ff41&labelColor=0d1117)
![License](https://img.shields.io/badge/license-MIT-00ff41?style=for-the-badge&labelColor=0d1117)
![Status](https://img.shields.io/badge/status-ACTIVE-00ff41?style=for-the-badge&labelColor=0d1117)

</div>

---

```
root@manifestguard:~# cat /etc/motd
```

## `> ./overview.sh`

Most users have **no idea** what their browser extensions can see. That password manager? It can read **every page you visit**. That cute tab organizer? It has access to your **entire browsing history**.

```diff
+ Extensions request powerful permissions
+ Most users click "Add to Chrome" without reading
- Your data is exposed by default
- There's no built-in audit tool in Chrome
```

**ManifestGuard** changes that. It's your local recon tool that:

```
[*] Scans your Chrome extensions directory         ✓
[*] Decodes manifest.json permission flags         ✓
[*] Calculates weighted risk scores (0-100)        ✓
[*] Uses Llama 3.3 to translate tech → English     ✓
[*] Runs 100% locally — your data never leaves     ✓
```

---

## `> cat features.log`

```
┌─────────────────────────────────────────────────────────────┐
│  MODULE              │  STATUS  │  DESCRIPTION              │
├─────────────────────────────────────────────────────────────┤
│  os_detect.py        │  [LIVE]  │  Auto-detects Win/Mac/Lin │
│  ext_scanner.py      │  [LIVE]  │  Enumerates all ext dirs  │
│  risk_engine.py      │  [LIVE]  │  0-100 weighted scoring   │
│  ai_analyzer.py      │  [LIVE]  │  Llama 3.3 via Groq API   │
│  manifest_parser.py  │  [LIVE]  │  JSON permission decoder  │
│  ui_renderer.py      │  [LIVE]  │  Streamlit dashboard      │
└─────────────────────────────────────────────────────────────┘
```

| Feature | Detail |
|:--------|:-------|
| 🖥️ **Zero-Input Audit** | Auto-scans Chrome extensions — no paths, no config |
| 📈 **Risk Scoring** | Weighted algorithm: CRITICAL (40) → HIGH (20) → MEDIUM (10) → LOW (5) |
| 🤖 **AI Translation** | Converts `"webRequestBlocking"` → *"Can intercept & modify every web request"* |
| 📋 **Deep Breakdown** | Permissions, host access, content scripts — all decoded |
| 🔒 **Offline-First** | Scanning is local. Only permission *names* go to AI — never your data |
| 🎯 **Color-Coded UI** | Risk levels are instantly visible with color indicators |

---

## `> ./demo.sh`

> **Note**: Full functionality requires local execution (Chrome must be installed).

**Try it live**: [manifestguard.streamlit.app](https://manifestguard.streamlit.app/)

```bash
# Or deploy your own instance:
docker build -t manifestguard . && docker run -p 8501:8501 manifestguard
```

[![Deploy to Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io/)

![Interface](screenshot.png)

---

## `> ./install.sh`

### Prerequisites

```
[✓] Python 3.9+
[✓] Groq API key (free tier → console.groq.com)
[✓] Chrome / Chromium browser installed
```

### Execution

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/manifestguard.git
cd manifestguard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch
streamlit run app.py

# 4. Enter your Groq API key in the sidebar
# 5. Hit "Start Extension Scan" → profit
```

---

## `> cat /var/log/risk_engine.conf`

### Threat Classification Matrix

```
╔════════════╦════════╦══════════════════════════════════════════╗
║  SEVERITY  ║ WEIGHT ║  PERMISSION FLAGS                        ║
╠════════════╬════════╬══════════════════════════════════════════╣
║  CRITICAL  ║   40   ║  all_urls, webRequestBlocking,           ║
║    [!!!!]  ║        ║  debugger, proxy, nativeMessaging        ║
╠════════════╬════════╬══════════════════════════════════════════╣
║  HIGH      ║   20   ║  history, bookmarks, cookies,            ║
║    [!!!]   ║        ║  tabs, storage, downloads                ║
╠════════════╬════════╬══════════════════════════════════════════╣
║  MEDIUM    ║   10   ║  notifications, clipboardRead,           ║
║    [!!]    ║        ║  geolocation, identity, webNavigation    ║
╠════════════╬════════╬══════════════════════════════════════════╣
║  LOW       ║    5   ║  alarms, idle, tts, contextMenus,        ║
║    [!]     ║        ║  printerProvider, fontSettings           ║
╚════════════╩════════╩══════════════════════════════════════════╝
```

### Risk Score Decoder

```
 SCORE        VERDICT              ASSESSMENT
───────────────────────────────────────────────────────
 70 - 100     ██████████  [!!!!]   HIGH RISK — extensive data access
 40 -  69     ██████░░░░  [!!!]    MEDIUM RISK — significant permissions
 20 -  39     ████░░░░░░  [!!]     LOW-MEDIUM — worth reviewing
  0 -  19     ██░░░░░░░░  [!]      LOW RISK — generally safe
```

---

## `> uname -a` — Platform Support

```
PLATFORM        CHROME EXTENSIONS PATH                                          STATUS
─────────────────────────────────────────────────────────────────────────────────────────
Windows         %LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions       [OK]
macOS           ~/Library/Application Support/Google/Chrome/Default/Extensions   [OK]
Linux           ~/.config/google-chrome/Default/Extensions                       [OK]
```

> *Also supports Chrome Beta, Dev, and Chromium variants.*

---

## `> cat architecture.md`

```
                    ┌─────────────────────────────────────────────┐
                    │           M A N I F E S T G U A R D         │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │            OS DETECTION LAYER               │
                    │    Win32 │ Darwin │ Linux → path resolver   │
                    └──────────────────┬──────────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────────┐
                    │           EXTENSION SCANNER                 │
                    │   enumerate dirs → locate manifest.json     │
                    └──────────────────┬──────────────────────────┘
                                       │
               ┌───────────────────────┼───────────────────────┐
               ▼                       ▼                       ▼
   ┌───────────────────┐  ┌────────────────────┐  ┌───────────────────┐
   │  MANIFEST PARSER  │  │  PERMISSION MAP    │  │  RISK CALCULATOR  │
   │  decode JSON      │  │  classify weights  │  │  score 0 → 100    │
   └─────────┬─────────┘  └──────────┬─────────┘  └─────────┬─────────┘
             └───────────────────────┼──────────────────────┘
                                     ▼
                    ┌───────────────────────────────────────────┐
                    │           AI ANALYSIS ENGINE              │
                    │    Groq API → Llama 3.3 70B inference     │
                    │    "webRequestBlocking" → human english   │
                    └──────────────────┬────────────────────────┘
                                       ▼
                    ┌───────────────────────────────────────────┐
                    │          STREAMLIT DASHBOARD              │
                    │   tables │ risk bars │ detail panels      │
                    └───────────────────────────────────────────┘
```

### Tech Stack

```
COMPONENT       TECHNOLOGY              VERSION
──────────────────────────────────────────────────
Language        Python                  3.9+
Framework       Streamlit               1.28+
AI Model        Llama 3.3 70B           via Groq
API Client      openai (compatible)     latest
Data            pandas                  latest
IO              pathlib, json           stdlib
```

---

## `> cat roadmap.todo`

```
[x] Core extension scanner
[x] Risk scoring engine
[x] AI-powered analysis via Groq
[x] Streamlit dashboard
[ ] Multi-browser support (Edge, Brave, Opera)        # PLANNED
[ ] Behavioral monitoring of background scripts        # FUTURE
[ ] Privacy-focused alternative suggestions            # FUTURE
[ ] Historical permission change tracking              # FUTURE
[ ] Export PDF/JSON audit reports                       # FUTURE
[ ] Cross-reference with malicious extension DBs       # FUTURE
```

---

## `> cat CONTRIBUTING.md`

```diff
+ Contributions welcome. Areas of interest:
```

- 🌍 Additional browser support (Firefox `manifest.json` v3, Safari)
- 🧪 Test coverage for cross-OS Chrome configurations
- 📚 Improved permission classification weights
- 🎨 UI/UX upgrades & dark-mode terminal theme
- 🌐 i18n / localization

---

## `> cat DISCLAIMER.txt`

```
⚠ IMPORTANT ⚠

ManifestGuard is an EDUCATIONAL / AUDIT tool.

A high risk score does NOT mean an extension is malicious.
It means the extension has powerful permissions that COULD
be misused. Many legitimate tools (password managers, ad
blockers, VPNs) REQUIRE extensive permissions to function.

ALWAYS:
  → Install extensions only from trusted sources
  → Review permissions BEFORE clicking "Add to Chrome"
  → Remove extensions you no longer use
  → Keep extensions updated

You are responsible for your own security decisions.
```

---

## `> cat LICENSE`

```
MIT License — free to use, modify, and distribute.
See LICENSE file for full text.
```

---

## `> cat credits.conf`

```
[dependencies]
groq        = "Fast LLM inference"     # https://groq.com
streamlit   = "Web app framework"      # https://streamlit.io
chrome_team = "Extension docs"         # https://developer.chrome.com

[acknowledgments]
llama_3.3   = "Meta AI open model"
python      = "The language that glues it all"
```

---

<div align="center">

```
┌──────────────────────────────────────────────────────┐
│                                                      │
│   $ manifestguard --scan --all                       │
│                                                      │
│   [✓] 23 extensions found                            │
│   [✓] Manifests parsed                               │
│   [✓] Risk scores calculated                         │
│   [✓] AI analysis complete                           │
│                                                      │
│   Your browser is only as safe as its extensions.    │
│                                                      │
│   Stay paranoid. Stay safe.   ████████████████████   │
│                                                      │
└──────────────────────────────────────────────────────┘
```

**`> echo "Happy (and safe) browsing" | sha256sum`**

`4a6f8b2c...your_security_is_in_your_hands`

</div>
