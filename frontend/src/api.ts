import type { ExtensionFinding, ScanRecord } from "./types";

const API_BASE = import.meta.env.VITE_MANIFESTGUARD_API_URL ?? "http://127.0.0.1:8000/api";

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

export function createScan(payload: {
  profiles: string[];
  channels: string[];
  enableLiveChecks: boolean;
  enableAi: boolean;
}): Promise<ScanRecord> {
  return request<ScanRecord>("/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
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

export async function importCsv(file: File): Promise<ScanRecord> {
  const body = new FormData();
  body.append("file", file);
  const response = await fetch(`${API_BASE}/imports/csv`, {
    method: "POST",
    body,
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json() as Promise<ScanRecord>;
}

export function reportUrl(scanId: string, formatName: "csv" | "json" | "html" | "pdf"): string {
  return `${API_BASE}/scans/${scanId}/reports/${formatName}`;
}
