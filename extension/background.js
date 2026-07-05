/* ManifestGuard companion background service worker.
 *
 * Reacts to extension install/uninstall/enable events so the badge can hint
 * that a re-audit is worthwhile after the extension landscape changes.
 */

function markStale() {
  chrome.action.setBadgeText({ text: "!" });
  chrome.action.setBadgeBackgroundColor({ color: "#f59e0b" });
}

function clearBadge() {
  chrome.action.setBadgeText({ text: "" });
}

chrome.runtime.onInstalled.addListener(() => {
  clearBadge();
});

if (chrome.management?.onInstalled) {
  chrome.management.onInstalled.addListener(markStale);
  chrome.management.onUninstalled.addListener(markStale);
  chrome.management.onEnabled.addListener(markStale);
}

// Clear the stale badge once the user opens the popup to run an audit.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === "audit-started") clearBadge();
});
