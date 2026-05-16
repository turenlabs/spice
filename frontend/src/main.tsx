import { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { FindingsTable } from './components/FindingsTable';
import { InventoryPanel } from './components/InventoryPanel';
import { PreviewPane } from './components/PreviewPane';
import { ScanStrip } from './components/ScanStrip';
import { SettingsPanel } from './components/SettingsPanel';
import { Sidebar } from './components/Sidebar';
import type {
  AppSettings,
  DetectionStatus,
  FilePreview,
  Finding,
  FindingAction,
  InventoryRequest,
  InventoryResult,
  Mode,
  ScanFindingPayload,
  ScanProfile,
  ScanProgress,
  ScanResult,
} from './types';
import {
  appendUniqueFinding,
  devSeverityCounts,
  elapsed,
  findingKey,
  formatDateTime,
  loadFindingActions,
  normalizeScanProgress,
} from './utils';
import './style.css';

declare global {
  interface Window {
    go?: {
      main?: {
        App?: {
          Scan: (request: { paths: string[]; deep?: boolean; excludedDirs?: string[]; profile?: ScanProfile }) => Promise<ScanResult>;
          PickDirectory: () => Promise<string>;
          PreviewFile: (request: { path: string }) => Promise<FilePreview>;
          DeletePath: (request: { path: string }) => Promise<{ path: string; deletedAt: string }>;
          Inventory: (request: InventoryRequest) => Promise<InventoryResult>;
          StopScan: () => Promise<void>;
          DetectionStatus: () => Promise<DetectionStatus>;
          RefreshDetections: () => Promise<DetectionStatus>;
          LastScan: () => Promise<ScanResult>;
          Settings: () => Promise<AppSettings>;
          SaveSettings: (settings: AppSettings) => Promise<AppSettings>;
          ClearLocalData: () => Promise<void>;
        };
      };
    };
    runtime?: {
      EventsOn?: (event: string, callback: (payload: unknown) => void) => () => void;
    };
  }
}

const api = () => window.go?.main?.App;
const scanProgressEvents = ['scan:progress'];
const defaultInventoryRequest: InventoryRequest = {
  limit: 100,
  offset: 0,
  query: '',
  ecosystem: 'all',
  sourceKind: 'all',
};
const emptyInventory: InventoryResult = {
  packages: [],
  total: 0,
  limit: defaultInventoryRequest.limit,
  offset: 0,
  ecosystemCounts: [],
  sourceKindCounts: [],
};
const defaultSettings: AppSettings = { excludedDirs: [] };
const defaultScanScopes: Record<ScanProfile, string> = {
  project: '~',
  'shai-hulud': '~/.npm, ~/.pnpm-store, ~/.yarn, ~/.cache/pip, ~/.cache/pypoetry, ~/.config/gh, ~/.local/bin, ~/Library/LaunchAgents, ~/.config/systemd/user, ~/.npmrc, ~/.pypirc, ~/.vscode, ~/.claude',
  deep: '~',
};

function App() {
  const [mode, setMode] = useState<Mode>('scan');
  const [pathText, setPathText] = useState(defaultScanScopes.project);
  const [scanProfile, setScanProfile] = useState<ScanProfile>('project');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [scanCompletedThisSession, setScanCompletedThisSession] = useState(false);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [busy, setBusy] = useState<'scan' | 'detections' | null>(null);
  const [error, setError] = useState('');
  const [findingActions, setFindingActions] = useState<Record<string, FindingAction>>(() => loadFindingActions());
  const [preview, setPreview] = useState<FilePreview | null>(null);
  const [previewFinding, setPreviewFinding] = useState<Finding | null>(null);
  const [detectionStatus, setDetectionStatus] = useState<DetectionStatus | null>(null);
  const [inventoryRequest, setInventoryRequest] = useState<InventoryRequest>(defaultInventoryRequest);
  const [inventory, setInventory] = useState<InventoryResult>(emptyInventory);
  const [inventoryLoading, setInventoryLoading] = useState(false);
  const [settings, setSettings] = useState<AppSettings>(defaultSettings);

  const paths = useMemo(() => pathText.split(/[\n,]/).map((path) => path.trim()).filter(Boolean), [pathText]);
  const hasWails = Boolean(api());
  const findings = scanResult?.findings ?? liveFindings;
  const openFindings = findings.filter((finding) => {
    const action = findingActions[findingKey(finding)];
    return action !== 'ignored' && action !== 'deleted';
  });
  const ignoredFindings = findings.filter((finding) => findingActions[findingKey(finding)] === 'ignored');
  const scanDuration = scanResult ? elapsed(scanResult.startedAt, scanResult.finishedAt) : 'never';
  const isScanRunning = Boolean(scanProgress?.running);
  const counts = devSeverityCounts(openFindings);

  useEffect(() => {
    if (!hasWails) return;
    api()?.DetectionStatus().then(setDetectionStatus).catch(() => undefined);
    api()?.Settings().then((loaded) => setSettings({
      excludedDirs: loaded?.excludedDirs ?? [],
    })).catch(() => undefined);
    api()?.LastScan().then((result) => {
      if (result?.finishedAt) {
        setScanResult(result);
        setLiveFindings(result.findings ?? []);
      }
    }).catch(() => undefined);
  }, [hasWails]);

  useEffect(() => {
    if (!hasWails) return;
    loadInventory(inventoryRequest);
  }, [hasWails, inventoryRequest]);

  useEffect(() => {
    localStorage.setItem('spice:finding-actions', JSON.stringify(findingActions));
  }, [findingActions]);

  useEffect(() => {
    if (!hasWails) return;
    const offs = scanProgressEvents
      .map((eventName) => window.runtime?.EventsOn?.(eventName, (payload) => {
        setScanProgress((current) => normalizeScanProgress(payload, current));
      }))
      .filter(Boolean);
    return () => {
      offs.forEach((off) => off?.());
    };
  }, [hasWails]);

  useEffect(() => {
    if (!hasWails) return;
    const off = window.runtime?.EventsOn?.('detections:status', (payload) => {
      setDetectionStatus(payload as DetectionStatus);
    });
    return () => {
      if (off) off();
    };
  }, [hasWails]);

  useEffect(() => {
    if (!hasWails) return;
    const off = window.runtime?.EventsOn?.('scan:finding', (payload) => {
      const event = payload as ScanFindingPayload;
      if (!event.finding) return;
      setScanProgress((current) => {
        if (current?.scanId && event.scanId && current.scanId !== event.scanId) return current;
        setLiveFindings((existing) => appendUniqueFinding(existing, event.finding!));
        return current;
      });
    });
    return () => {
      if (off) off();
    };
  }, [hasWails]);

  async function runScan() {
    if (!api()) return;
    setMode('scan');
    setBusy('scan');
    setError('');
    setScanResult(null);
    setScanCompletedThisSession(false);
    setLiveFindings([]);
    setScanProgress({
      current: paths.join(', ') || 'No paths selected',
      findings: 0,
      phase: 'starting',
      percent: 0,
      processed: 0,
      running: true,
      scanId: '',
      scanned: 0,
      seq: 0,
      skipped: 0,
      status: 'Preparing selected paths',
    });
    try {
      const result = await api()!.Scan({ paths, deep: scanProfile === 'deep', excludedDirs: settings.excludedDirs, profile: scanProfile });
      setScanResult(result);
      setScanCompletedThisSession(true);
      setLiveFindings(result.findings ?? []);
      await loadInventory(inventoryRequest);
      const canceled = result.status === 'canceled';
      setScanProgress((current) => ({
        current: current?.current || result.roots.join(', '),
        findings: result.findings.length,
        phase: 'done',
        percent: canceled ? (current?.percent ?? 0) : 100,
        processed: current?.processed ?? current?.total ?? 0,
        running: false,
        scanId: current?.scanId ?? '',
        scanned: current?.scanned ?? result.findings.length,
        seq: current?.seq ?? 0,
        skipped: current?.skipped ?? 0,
        status: canceled ? 'Scan stopped' : 'Scan completed',
        total: current?.total,
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setScanProgress((current) => current ? { ...current, running: false, status: 'Scan failed' } : null);
    } finally {
      setBusy(null);
    }
  }

  async function pickDirectory() {
    if (!api()) return;
    const selected = await api()!.PickDirectory();
    if (selected) setPathText(selected);
  }

  async function refreshDetections() {
    if (!api()) return;
    setBusy('detections');
    setError('');
    try {
      setDetectionStatus(await api()!.RefreshDetections());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  async function saveSettings(next: AppSettings) {
    if (!api()) {
      setSettings(next);
      return;
    }
    setError('');
    try {
      const saved = await api()!.SaveSettings(next);
      setSettings({ excludedDirs: saved.excludedDirs ?? [] });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function pickExcludeDirectory() {
    if (!api()) return;
    const selected = await api()!.PickDirectory();
    if (!selected) return;
    const current = settings.excludedDirs ?? [];
    if (current.includes(selected)) return;
    await saveSettings({ ...settings, excludedDirs: [...current, selected] });
  }

  async function clearLocalData() {
    if (!api()) return;
    const confirmed = window.confirm('Clear local scan history, cached findings, and package inventory? Detection packs and Settings excludes will be kept.');
    if (!confirmed) return;
    setError('');
    try {
      await api()!.ClearLocalData();
      setScanResult(null);
      setLiveFindings([]);
      setScanCompletedThisSession(false);
      setScanProgress(null);
      setFindingActions({});
      setInventory(emptyInventory);
      setInventoryRequest(defaultInventoryRequest);
      setPreview(null);
      setPreviewFinding(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function loadInventory(request: InventoryRequest) {
    if (!api()) return;
    setInventoryLoading(true);
    try {
      const result = await api()!.Inventory(request);
      setInventory({
        packages: result.packages ?? [],
        total: result.total ?? 0,
        limit: result.limit || request.limit,
        offset: result.offset || request.offset,
        ecosystemCounts: result.ecosystemCounts ?? [],
        sourceKindCounts: result.sourceKindCounts ?? [],
      });
    } catch {
      setInventory(emptyInventory);
    } finally {
      setInventoryLoading(false);
    }
  }

  async function stopScan() {
    if (!api()) return;
    await api()!.StopScan();
    setScanProgress((current) => current ? { ...current, status: 'Stopping after current files', running: true } : current);
  }

  function chooseScanProfile(profile: ScanProfile) {
    setScanProfile(profile);
    setPathText(defaultScanScopes[profile]);
    setScanCompletedThisSession(false);
    setScanProgress(null);
  }

  function resetScanWizard() {
    setScanCompletedThisSession(false);
    setScanProgress(null);
    setError('');
  }

  async function viewFinding(finding: Finding) {
    if (!api()) return;
    setError('');
    setPreviewFinding(finding);
    setPreview(null);
    setFindingActions((current) => ({ ...current, [findingKey(finding)]: 'open' }));
    try {
      setPreview(await api()!.PreviewFile({ path: finding.path }));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  function ignoreFinding(finding: Finding) {
    setFindingActions((current) => ({ ...current, [findingKey(finding)]: 'ignored' }));
  }

  function restoreFinding(finding: Finding) {
    setFindingActions((current) => ({ ...current, [findingKey(finding)]: 'open' }));
  }

  async function deleteFinding(finding: Finding) {
    if (!api()) return;
    const confirmed = window.confirm(`Delete this file from disk? Matches are triage evidence, not proof of compromise.\n\n${finding.path}`);
    if (!confirmed) return;
    setError('');
    try {
      await api()!.DeletePath({ path: finding.path });
      setFindingActions((current) => ({ ...current, [findingKey(finding)]: 'deleted' }));
      if (previewFinding && findingKey(previewFinding) === findingKey(finding)) {
        setPreview(null);
        setPreviewFinding(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="stage" id="stage">
      <div className="app-shell">
        <Sidebar mode={mode} onModeChange={setMode} />

        <section className="main">
          <div className="main-scroll">
            {!hasWails && (
              <div className="alert warning">
                Wails bindings are unavailable in this browser context. Open the native app or use the Wails dev URL to run scans.
              </div>
            )}
            {error && <div className="alert danger">{error}</div>}

            {mode === 'settings' ? (
              <SettingsPanel
                detectionStatus={detectionStatus}
                findingActions={findingActions}
                ignoredFindings={ignoredFindings}
                settings={settings}
                onAddExcludeDirectory={pickExcludeDirectory}
                onClearLocalData={clearLocalData}
                onRefreshDetections={refreshDetections}
                onRestoreFinding={restoreFinding}
                onSaveSettings={saveSettings}
                refreshBusy={busy === 'detections'}
              />
            ) : mode === 'inventory' ? (
              <InventoryPanel
                inventory={inventory}
                loading={inventoryLoading}
                request={inventoryRequest}
                onRequestChange={setInventoryRequest}
              />
            ) : mode === 'findings' ? (
              <>
                <section className="findingsIntro">
                  <div>
                    <span className="eyebrow">RESULTS · LAST SCAN</span>
                    <h1>Triage Evidence</h1>
                    <p>
                      Review open detections separately from scan control. Matches show exposure evidence from loaded packs, not proof of compromise.
                    </p>
                  </div>
                  <div className="findingSummary">
                    <span><b>{openFindings.length}</b> open matches</span>
                    <span><b>{counts.critical}</b> high-confidence</span>
                    <span><b>{scanResult ? formatDateTime(scanResult.finishedAt) : 'never'}</b> last scan</span>
                  </div>
                </section>
                <FindingsTable
                  findings={openFindings}
                  actions={findingActions}
                  scanned={Boolean(scanResult)}
                  onDelete={deleteFinding}
                  onIgnore={ignoreFinding}
                  onView={viewFinding}
                />
              </>
            ) : (
              <ScanStrip
                disabled={!hasWails || Boolean(busy && busy !== 'scan') || isScanRunning}
                duration={scanDuration}
                findingsCount={openFindings.length}
                pathText={pathText}
                paths={paths}
                progress={scanProgress}
                scanProfile={scanProfile}
                scanned={scanCompletedThisSession}
                onCheckResults={() => setMode('findings')}
                onPathText={setPathText}
                onPickDirectory={pickDirectory}
                onReset={resetScanWizard}
                onRunScan={runScan}
                onScanProfileChange={chooseScanProfile}
                onStopScan={stopScan}
              />
            )}
          </div>
          {previewFinding && (
            <PreviewPane
              finding={previewFinding}
              preview={preview}
              onClose={() => {
                setPreview(null);
                setPreviewFinding(null);
              }}
            />
          )}
        </section>
      </div>
    </div>
  );
}

createRoot(document.getElementById('root')!).render(<App />);
