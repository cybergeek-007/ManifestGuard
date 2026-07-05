# ManifestGuard Companion (Chrome Extension)

An MV3 browser extension that audits **every other extension installed in your
browser** with one click. It is the ironic, end-to-end front door to
ManifestGuard: *an extension that audits your extensions.*

## What it does

1. Enumerates installed extensions using the `chrome.management` API.
2. Collects your active tab URLs (used only for AI attack-simulation context).
3. Sends the metadata to your ManifestGuard backend (`POST /api/scans/online`),
   which downloads each extension's source (CRX) and runs the full detection
   pipeline: reach vs. anomaly scoring, reputation, collusion graph, live threat
   intel, and repackaged-clone detection.
4. Deep-links you into the ManifestGuard dashboard at `/?scan=<scanId>` for the
   full report.

## Privacy

- No data is sent anywhere except the backend URL **you** configure.
- BYOK AI keys are handled by the backend and never stored by this extension.
- Default backend is `http://localhost:8000` for fully local use.

## Load it (unpacked)

1. Start the ManifestGuard backend and frontend (see the repo root README).
2. Open `chrome://extensions`.
3. Toggle **Developer mode** (top right).
4. Click **Load unpacked** and select this `extension/` folder.
5. Pin **ManifestGuard Companion** and click it → **Audit my extensions**.

## Configuration

- **Backend URL** — where your ManifestGuard API is running. When set to a
  `:8000` origin, the popup opens the dashboard on `:5173` (Vite dev server);
  for a deployed instance it uses the same origin.
- **Enable AI verdict explanation** — opt-in; uses the API key configured in
  your backend.

## Files

| File | Purpose |
| --- | --- |
| `manifest.json` | MV3 manifest, permissions (`management`, `tabs`, `storage`) |
| `popup.html/.css/.js` | The one-click audit UI |
| `background.js` | Badges a `!` hint when your extension set changes |
| `icons/` | Toolbar/store icons |
