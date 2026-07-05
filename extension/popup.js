/* ManifestGuard companion popup logic.
 *
 * Flow:
 *   1. Enumerate installed extensions via chrome.management.
 *   2. Collect the active tab URLs (for AI attack simulation context).
 *   3. POST them to the ManifestGuard backend /api/scans/online.
 *   4. Deep-link into the dashboard at <frontend>/?scan=<scanId>.
 */

const DEFAULT_BACKEND = "http://localhost:8000";

const els = {
  intro: document.getElementById("intro"),
  progress: document.getElementById("progress"),
  result: document.getElementById("result"),
  error: document.getElementById("error"),
  backendUrl: document.getElementById("backend-url"),
  enableAi: document.getElementById("enable-ai"),
  scanBtn: document.getElementById("scan-btn"),
  countHint: document.getElementById("count-hint"),
  progressText: document.getElementById("progress-text"),
  resultBadge: document.getElementById("result-badge"),
  resultText: document.getElementById("result-text"),
  openReport: document.getElementById("open-report"),
  rescan: document.getElementById("rescan"),
  errorText: document.getElementById("error-text"),
  retry: document.getElementById("retry"),
};

let lastReportUrl = null;

function show(panel) {
  for (const p of [els.intro, els.progress, els.result, els.error]) {
    p.classList.add("hidden");
  }
  panel.classList.remove("hidden");
}

function normalizeBase(url) {
  return (url || DEFAULT_BACKEND).trim().replace(/\/+$/, "");
}

/** Derive the dashboard URL from the backend URL.
 *  Backend on :8000 -> frontend on :5173 (Vite dev) by convention;
 *  for same-origin/prod deployments we just use the backend origin. */
function deriveFrontendUrl(backendBase) {
  try {
    const u = new URL(backendBase);
    if (u.port === "8000") {
      u.port = "5173";
      return u.origin;
    }
    return u.origin;
  } catch {
    return backendBase;
  }
}

async function loadSettings() {
  const stored = await chrome.storage.local.get(["backendUrl", "enableAi"]);
  els.backendUrl.value = stored.backendUrl || DEFAULT_BACKEND;
  els.enableAi.checked = Boolean(stored.enableAi);
  await refreshCount();
}

async function refreshCount() {
  try {
    const all = await chrome.management.getAll();
    const count = all.filter(
      (e) => e.type === "extension" && e.id !== chrome.runtime.id,
    ).length;
    els.countHint.textContent = `${count} extension${count === 1 ? "" : "s"} ready to audit.`;
  } catch {
    els.countHint.textContent = "";
  }
}

async function collectExtensions() {
  const all = await chrome.management.getAll();
  return all
    .filter((e) => e.type === "extension" && e.id !== chrome.runtime.id)
    .map((e) => ({
      id: e.id,
      name: e.name,
      version: e.version,
      description: e.description || "",
      permissions: e.permissions || [],
      hostPermissions: e.hostPermissions || [],
      enabled: e.enabled,
      installType: e.installType || "normal",
      homepageUrl: e.homepageUrl || "",
    }));
}

async function collectActiveUrls() {
  try {
    const tabs = await chrome.tabs.query({ active: true });
    return tabs
      .map((t) => t.url)
      .filter((u) => u && /^https?:/.test(u))
      .slice(0, 10);
  } catch {
    return [];
  }
}

function verdictToClass(verdict) {
  if (["known_malicious", "suspicious"].includes(verdict)) return "danger";
  if (["moderate_risk", "low_risk"].includes(verdict)) return "moderate";
  return "safe";
}

function summarize(scan) {
  const summary = scan.summary || {};
  const counts = summary.verdictDistribution || {};
  const bad =
    (counts.known_malicious || 0) + (counts.suspicious || 0);
  const moderate = (counts.moderate_risk || 0) + (counts.low_risk || 0);
  const total = summary.totalExtensions ?? 0;

  if (bad > 0) {
    return {
      cls: "danger",
      label: "Action needed",
      text: `${bad} of ${total} extensions flagged as suspicious or malicious.`,
    };
  }
  if (moderate > 0) {
    return {
      cls: "moderate",
      label: "Review",
      text: `${moderate} of ${total} extensions have elevated risk worth reviewing.`,
    };
  }
  return {
    cls: "safe",
    label: "Looks clean",
    text: `All ${total} extensions passed with no suspicious behavior detected.`,
  };
}

async function runScan() {
  const backendBase = normalizeBase(els.backendUrl.value);
  const enableAi = els.enableAi.checked;
  await chrome.storage.local.set({ backendUrl: backendBase, enableAi });

  chrome.runtime.sendMessage({ type: "audit-started" }).catch(() => {});
  show(els.progress);
  els.progressText.textContent = "Collecting installed extensions…";

  try {
    const [extensions, activeUrls] = await Promise.all([
      collectExtensions(),
      collectActiveUrls(),
    ]);

    if (extensions.length === 0) {
      throw new Error("No other extensions found to audit.");
    }

    els.progressText.textContent = `Analyzing ${extensions.length} extensions (downloading source, running detectors)…`;

    const resp = await fetch(`${backendBase}/api/scans/online`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ extensions, activeUrls, enableAi }),
    });

    if (!resp.ok) {
      const detail = await resp.text();
      throw new Error(`Backend responded ${resp.status}: ${detail.slice(0, 140)}`);
    }

    const scan = await resp.json();
    const scanId = scan.scanId || scan.scan_id || scan.id;
    if (!scanId) throw new Error("Scan completed but no scan ID was returned.");

    const frontend = deriveFrontendUrl(backendBase);
    lastReportUrl = `${frontend}/?scan=${encodeURIComponent(scanId)}`;

    const summary = summarize(scan);
    els.resultBadge.className = `result-badge ${summary.cls}`;
    els.resultBadge.textContent = summary.label;
    els.resultText.textContent = summary.text;
    show(els.result);
  } catch (err) {
    els.errorText.textContent =
      err instanceof Error ? err.message : "Something went wrong during the scan.";
    show(els.error);
  }
}

els.scanBtn.addEventListener("click", runScan);
els.retry.addEventListener("click", () => show(els.intro));
els.rescan.addEventListener("click", () => show(els.intro));
els.openReport.addEventListener("click", () => {
  if (lastReportUrl) chrome.tabs.create({ url: lastReportUrl });
});

loadSettings();
