/**
 * ManifestGuard Companion Extension — Background Service Worker
 *
 * Handles:
 * 1. Enumerating installed extensions via chrome.management.getAll()
 * 2. Sending extension data to the ManifestGuard backend API
 * 3. Returning scan results to the popup
 */

// Default API URL — can be changed in popup settings
const DEFAULT_API_URL = "http://localhost:8000";

/**
 * Get the configured API URL from storage
 */
async function getApiUrl() {
  const result = await chrome.storage.local.get("apiUrl");
  return result.apiUrl || DEFAULT_API_URL;
}

/**
 * Enumerate all installed extensions using chrome.management API
 * Filters out themes, hosted apps, and this extension itself.
 */
async function getInstalledExtensions() {
  const allExtensions = await chrome.management.getAll();

  return allExtensions
    .filter((ext) => {
      // Only include actual extensions (not themes, apps, etc.)
      if (ext.type !== "extension") return false;
      // Exclude this companion extension itself
      if (ext.id === chrome.runtime.id) return false;
      return true;
    })
    .map((ext) => ({
      id: ext.id,
      name: ext.name || "Unknown",
      version: ext.versionName || ext.version || "",
      description: ext.description || "",
      permissions: ext.permissions || [],
      hostPermissions: ext.hostPermissions || [],
      enabled: ext.enabled,
      installType: ext.installType || "normal",
      homepageUrl: ext.homepageUrl || "",
      updateUrl: ext.updateUrl || "",
      offlineEnabled: ext.offlineEnabled || false,
      mayDisable: ext.mayDisable !== false,
    }));
}

/**
 * Send extension data to ManifestGuard backend and get scan results
 */
async function runScan(options = {}) {
  const apiUrl = await getApiUrl();
  const extensions = await getInstalledExtensions();

  if (extensions.length === 0) {
    return {
      success: false,
      error: "No extensions found to scan.",
      extensions: [],
    };
  }

  try {
    const response = await fetch(`${apiUrl}/api/scans/online`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        extensions: extensions,
        enableAi: options.enableAi || false,
        enableDeepScan: options.enableDeepScan || false,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Server error ${response.status}: ${errorText}`);
    }

    const result = await response.json();
    return {
      success: true,
      scanId: result.scanId || result.scan_id,
      extensionCount: extensions.length,
      result: result,
    };
  } catch (err) {
    return {
      success: false,
      error: `Failed to connect to ManifestGuard: ${err.message}`,
      extensions: extensions,
    };
  }
}

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "scan") {
    runScan(message.options || {})
      .then(sendResponse)
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep the message channel open for async response
  }

  if (message.action === "getExtensions") {
    getInstalledExtensions()
      .then((extensions) => sendResponse({ success: true, extensions }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (message.action === "getApiUrl") {
    getApiUrl().then((url) => sendResponse({ url }));
    return true;
  }

  if (message.action === "setApiUrl") {
    chrome.storage.local.set({ apiUrl: message.url }).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }
});
