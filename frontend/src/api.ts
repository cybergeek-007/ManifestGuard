import type { ExtensionFinding, Recommendation, ScanRecord, WatchEntry } from "./types";
import { getAIHeaders } from "./components/AISettings";

const API_BASE = import.meta.env.VITE_MANIFESTGUARD_API_URL ?? "http://127.0.0.1:8000/api";

/**
 * Local extension scanning reads Chrome's on-disk extension directory, so it
 * only works when the backend runs on the user's own machine. On a hosted
 * deployment (e.g. Render) the request can never succeed and would return a
 * 400, so we detect a remote backend and guide the user instead of firing it.
 */
export function isLocalScanSupported(): boolean {
  try {
    const host = new URL(API_BASE, window.location.origin).hostname;
    return host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  } catch {
    return false;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export function listScans(): Promise<ScanRecord[]> {
  return request<ScanRecord[]>("/scans");
}

export function createOnlineScan(payload: {
  extensions: Array<{
    id: string;
    name: string;
    version: string;
    description: string;
    permissions: string[];
    hostPermissions: string[];
    enabled: boolean;
    installType: string;
  }>;
  enableAi: boolean;
}): Promise<ScanRecord> {
  return request<ScanRecord>("/scans/online", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAIHeaders() },
    body: JSON.stringify(payload),
  });
}

export function fetchScan(scanId: string): Promise<ScanRecord> {
  return request<ScanRecord>(`/scans/${scanId}`);
}

export function fetchExtensions(scanId: string): Promise<ExtensionFinding[]> {
  return request<ExtensionFinding[]>(`/scans/${scanId}/extensions`);
}

export function fetchExtension(scanId: string, extensionId: string): Promise<ExtensionFinding> {
  return request<ExtensionFinding>(`/scans/${scanId}/extensions/${extensionId}`);
}

export function fetchRecommendations(scanId: string, extensionId: string): Promise<Recommendation[]> {
  return request<Recommendation[]>(`/scans/${scanId}/extensions/${extensionId}/recommendations`);
}

export function reportUrl(scanId: string, formatName: "csv" | "json" | "html" | "pdf"): string {
  return `${API_BASE}/scans/${scanId}/reports/${formatName}`;
}

export function chatWithExtension(scanId: string, extensionId: string, message: string): Promise<{reply: string}> {
  return request<{reply: string}>(`/scans/${scanId}/extensions/${extensionId}/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAIHeaders() },
    body: JSON.stringify({ message }),
  });
}
export async function scanLocalExtensions(enableAi: boolean = false): Promise<ScanRecord> {
  const res = await fetch(`${API_BASE}/scans/local`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAIHeaders() },
    body: JSON.stringify({ enableAi })
  });
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: 'Server error' }));
    throw new Error(error.detail || `Server error: ${res.status}`);
  }
  return res.json();
}

export async function scanSingleExtension(extensionId: string, enableAi: boolean = false): Promise<ScanRecord> {
  const res = await fetch(`${API_BASE}/scans/single`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...getAIHeaders() },
    body: JSON.stringify({ extensionId, enableAi }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(err.detail || 'Scan failed');
  }
  return res.json();
}

// ── Watchlist / continuous monitoring ──────────────────────

export function listWatchlist(): Promise<WatchEntry[]> {
  return request<WatchEntry[]>("/watchlist");
}

export function addToWatchlist(extensionId: string): Promise<{ status: string; name?: string }> {
  return request("/watchlist", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAIHeaders() },
    body: JSON.stringify({ extensionId }),
  });
}

export function removeFromWatchlist(extensionId: string): Promise<{ status: string }> {
  return request(`/watchlist/${extensionId}`, { method: "DELETE" });
}

export function checkWatchedExtension(extensionId: string): Promise<{
  extensionId: string;
  name: string;
  version: string;
  verdict: string;
  newAlerts: Array<{ type: string; severity: string; message: string; at: string }>;
}> {
  return request(`/watchlist/${extensionId}/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...getAIHeaders() },
  });
}

/** Extract extension ID from CWS URL or raw ID */
export function parseExtensionInput(input: string): string | null {
  const trimmed = input.trim();
  // Match raw 32-char ID (a-p lowercase)
  if (/^[a-p]{32}$/.test(trimmed)) return trimmed;
  // Match Chrome Web Store URL
  const urlMatch = trimmed.match(/chrome\.google\.com\/webstore\/detail\/[^/]*\/([a-p]{32})/);
  if (urlMatch) return urlMatch[1];
  // Match new CWS URL format
  const newUrlMatch = trimmed.match(/chromewebstore\.google\.com\/detail\/[^/]*\/([a-p]{32})/);
  if (newUrlMatch) return newUrlMatch[1];
  // Try to find any 32-char ID in the string
  const idMatch = trimmed.match(/([a-p]{32})/);
  if (idMatch) return idMatch[1];
  return null;
}
