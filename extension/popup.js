/**
 * ManifestGuard Companion Extension — Popup Logic
 */

const $ = (id) => document.getElementById(id);

// Elements
const apiUrlInput = $("apiUrl");
const saveUrlBtn = $("saveUrl");
const scanBtn = $("scanBtn");
const statusArea = $("statusArea");
const statusText = $("statusText");
const resultsArea = $("resultsArea");
const errorArea = $("errorArea");
const errorText = $("errorText");
const retryBtn = $("retryBtn");
const viewReportBtn = $("viewReport");
const enableDeepScan = $("enableDeepScan");
const enableAi = $("enableAi");

let lastScanId = null;

// ── Init ────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  // Load saved API URL
  chrome.runtime.sendMessage({ action: "getApiUrl" }, (response) => {
    if (response?.url) {
      apiUrlInput.value = response.url;
    }
  });
});

// ── Event Handlers ──────────────────────────────────────────

saveUrlBtn.addEventListener("click", () => {
  const url = apiUrlInput.value.trim().replace(/\/+$/, "");
  if (!url) return;
  chrome.runtime.sendMessage({ action: "setApiUrl", url }, () => {
    saveUrlBtn.textContent = "✓";
    saveUrlBtn.classList.add("saved");
    setTimeout(() => {
      saveUrlBtn.textContent = "✓";
      saveUrlBtn.classList.remove("saved");
    }, 1500);
  });
});

scanBtn.addEventListener("click", startScan);
retryBtn.addEventListener("click", startScan);

viewReportBtn.addEventListener("click", () => {
  if (lastScanId) {
    const apiUrl = apiUrlInput.value.trim().replace(/\/+$/, "");
    // Open the web dashboard in a new tab
    const dashboardUrl = apiUrl.replace("/api", "").replace(":8000", ":5173");
    chrome.tabs.create({ url: `${dashboardUrl}?scan=${lastScanId}` });
  }
});

// ── Scan Logic ──────────────────────────────────────────────

async function startScan() {
  showStatus("Discovering installed extensions...");

  const options = {
    enableDeepScan: enableDeepScan.checked,
    enableAi: enableAi.checked,
  };

  // Update status as we progress
  setTimeout(() => {
    if (!statusArea.classList.contains("hidden")) {
      showStatus("Analyzing extensions...");
    }
  }, 2000);

  setTimeout(() => {
    if (!statusArea.classList.contains("hidden")) {
      showStatus("Running deep scan — this may take a minute...");
    }
  }, 8000);

  chrome.runtime.sendMessage(
    { action: "scan", options },
    (response) => {
      if (chrome.runtime.lastError) {
        showError(`Extension error: ${chrome.runtime.lastError.message}`);
        return;
      }

      if (!response) {
        showError("No response from background worker.");
        return;
      }

      if (response.success) {
        lastScanId = response.scanId;
        showResults(response.result);
      } else {
        showError(response.error || "Scan failed.");
      }
    }
  );
}

// ── UI State Management ─────────────────────────────────────

function showStatus(text) {
  statusArea.classList.remove("hidden");
  resultsArea.classList.add("hidden");
  errorArea.classList.add("hidden");
  scanBtn.disabled = true;
  scanBtn.textContent = "Scanning...";
  statusText.textContent = text;
}

function showResults(result) {
  statusArea.classList.add("hidden");
  resultsArea.classList.remove("hidden");
  errorArea.classList.add("hidden");
  scanBtn.disabled = false;
  scanBtn.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
    Scan Again`;

  // Parse verdict distribution from the result
  const dist = result.verdictDistribution || result.verdict_distribution || {};
  const total = result.totalExtensions || result.total_extensions || 0;

  $("totalCount").textContent = `${total} extensions`;
  $("trustedCount").textContent = (dist.trusted || 0) + (dist.low_concern || 0);
  $("lowCount").textContent = dist.powerful_but_expected || 0;
  $("moderateCount").textContent = dist.moderate_risk || 0;
  $("suspiciousCount").textContent = dist.suspicious || 0;
  $("maliciousCount").textContent =
    (dist.known_malicious || 0) +
    (dist.removed_or_unavailable || 0) +
    (dist.disabled_by_chrome || 0);
}

function showError(message) {
  statusArea.classList.add("hidden");
  resultsArea.classList.add("hidden");
  errorArea.classList.remove("hidden");
  scanBtn.disabled = false;
  scanBtn.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
    Scan My Extensions`;
  errorText.textContent = message;
}
