import { useEffect, useState } from 'react';
import { fetchExtension, fetchScan, listScans } from './api';
import type { ExtensionFinding, ScanRecord } from './types';

import Header from './components/Header';
import HeroSearch from './components/HeroSearch';
import ScanSummary from './components/ScanSummary';
import InventoryTable from './components/InventoryTable';
import ExtensionDetail from './components/ExtensionDetail';
import ReportExport from './components/ReportExport';
import EmptyState from './components/EmptyState';
import LoadingSkeleton from './components/LoadingSkeleton';
import AISettings, { getAIConfig } from './components/AISettings';

type Filters = {
  verdict: string;
  storeStatus: string;
  query: string;
};

function App() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);
  const [extensions, setExtensions] = useState<ExtensionFinding[]>([]);
  const [selectedExtension, setSelectedExtension] = useState<ExtensionFinding | null>(null);
  const [filters, setFilters] = useState<Filters>({ verdict: 'all', storeStatus: 'all', query: '' });
  const [enableAi, setEnableAi] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showAiSettings, setShowAiSettings] = useState(false);

  // On mount: load scans + handle ?scan= deep-link from companion extension
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const scanParam = params.get('scan');
    void refreshScans(scanParam ?? undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function refreshScans(preferredScanId?: string) {
    try {
      setError(null);
      const nextScans = await listScans();
      setScans(nextScans);

      const candidate = preferredScanId ?? activeScan?.scanId ?? nextScans[0]?.scanId;
      if (candidate) {
        await openScan(candidate);
      } else {
        setActiveScan(null);
        setExtensions([]);
        setSelectedExtension(null);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to load scans.');
    }
  }

  async function openScan(scanId: string) {
    try {
      setLoading(true);
      setError(null);
      const detail = await fetchScan(scanId);
      setActiveScan(detail);
      const nextExtensions = detail.extensions ?? [];
      setExtensions(nextExtensions);

      const preferredExtensionId = selectedExtension?.id;
      const fallback = nextExtensions.find(e => e.id === preferredExtensionId) ?? nextExtensions[0];
      if (fallback) {
        const fullDetail = await fetchExtension(scanId, fallback.id);
        setSelectedExtension(fullDetail);
      } else {
        setSelectedExtension(null);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to open scan.');
    } finally {
      setLoading(false);
    }
  }

  async function handleSelectExtension(extensionId: string) {
    if (!activeScan) return;
    try {
      const detail = await fetchExtension(activeScan.scanId, extensionId);
      setSelectedExtension(detail);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Failed to load extension details.');
    }
  }

  async function handleScanComplete(scanId: string) {
    await refreshScans(scanId);
  }

  return (
    <div className="app-shell">
      <Header
        scans={scans}
        activeScanId={activeScan?.scanId ?? null}
        onSelectScan={id => void openScan(id)}
        onRefresh={() => void refreshScans()}
        loading={loading}
        onOpenAiSettings={() => setShowAiSettings(true)}
      />

      {error && <div className="error-banner" style={{ maxWidth: 720, margin: '0 auto 24px' }}>{error}</div>}

      <HeroSearch
        enableAi={enableAi}
        onEnableAiChange={v => {
          if (v && !getAIConfig()) {
            setShowAiSettings(true);
            return;
          }
          setEnableAi(v);
        }}
        onScanComplete={id => void handleScanComplete(id)}
      />

      {loading && !activeScan && <LoadingSkeleton variant="summary" />}

      {activeScan && (
        <ScanSummary scan={activeScan} extensions={extensions} />
      )}

      {activeScan && (
        <div className="main-content">
          <InventoryTable
            extensions={extensions}
            filters={filters}
            onFilterChange={setFilters}
            onSelectExtension={id => void handleSelectExtension(id)}
            selectedExtensionId={selectedExtension?.id ?? null}
          />

          {selectedExtension ? (
            <ExtensionDetail
              extension={selectedExtension}
              scanId={activeScan.scanId}
              onClose={() => setSelectedExtension(null)}
            />
          ) : (
            <EmptyState
              title="Select an extension"
              description="Pick an extension from the inventory to inspect its security evidence."
            />
          )}
        </div>
      )}

      {activeScan && (
        <ReportExport scanId={activeScan.scanId} />
      )}

      {!activeScan && !loading && scans.length === 0 && (
        <EmptyState
          title="No scans yet"
          description="Paste an extension URL above or use the ManifestGuard browser extension to scan your installed extensions."
        />
      )}

      <AISettings isOpen={showAiSettings} onClose={() => {
        setShowAiSettings(false);
        if (getAIConfig()) setEnableAi(true);
      }} />
    </div>
  );
}

export default App;
