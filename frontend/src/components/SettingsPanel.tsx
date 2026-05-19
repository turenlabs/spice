import { AlertTriangle, CheckCircle2, DatabaseZap, FolderPlus, RefreshCw, Trash2, X } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { Button, Spinner } from './Common';
import type { AppSettings, ClearLocalDataProgress, DetectionStatus, Finding, FindingAction } from '../types';
import { countActions, defaultRemoteLabel, devKind, devReason, formatOptionalDate } from '../utils';

export function SettingsPanel({
  detectionStatus,
  findingActions,
  ignoredFindings,
  onAddExcludeDirectory,
  onClearLocalData,
  onRefreshDetections,
  onRestoreFinding,
  onSaveSettings,
  refreshBusy,
  clearBusy,
  clearProgress,
  clearLog,
  settings,
}: {
  detectionStatus: DetectionStatus | null;
  findingActions: Record<string, FindingAction>;
  ignoredFindings: Finding[];
  settings: AppSettings;
  onAddExcludeDirectory: () => void;
  onClearLocalData: () => Promise<void>;
  onRefreshDetections: () => void;
  onRestoreFinding: (finding: Finding) => void;
  onSaveSettings: (settings: AppSettings) => void;
  refreshBusy: boolean;
  clearBusy: boolean;
  clearProgress: ClearLocalDataProgress | null;
  clearLog: string[];
}) {
  const actionCounts = countActions(findingActions);
  const excludedDirs = settings.excludedDirs ?? [];
  const [clearConfirming, setClearConfirming] = useState(false);
  const clearFailed = clearProgress?.phase === 'failed';

  async function confirmClear() {
    setClearConfirming(false);
    await onClearLocalData();
  }

  return (
    <div className="settingsGrid">
      <section className="card settingsCard">
        <div className="panelHeader">
          <div>
            <h2>Detection packs</h2>
            <p>Spice updates package, file, hash, and IOC checks from remote incident packs. Cached packs are used when offline.</p>
          </div>
          <Button onClick={onRefreshDetections} disabled={refreshBusy} icon={refreshBusy ? <Spinner /> : <RefreshCw size={16} />}>
            Refresh
          </Button>
        </div>
        <div className="settingsRows">
          <SettingRow label="Loaded from" value={detectionSourceLabel(detectionStatus?.source)} />
          <SettingRow label="Update URL" value={detectionStatus?.remoteUrl ?? defaultRemoteLabel()} mono />
          <SettingRow label="Trust guardrails" value={detectionStatus?.trustPolicy ?? 'HTTPS GitHub content pinned to turenlabs/spice-detections main'} />
          <SettingRow label="Fetch status" value={detectionFetchLabel(detectionStatus)} />
          <SettingRow label="Loaded packs" value={String(detectionStatus?.packCount ?? 0)} />
          <SettingRow label="Last attempt" value={formatOptionalDate(detectionStatus?.lastAttemptAt)} />
          <SettingRow label="Last success" value={formatOptionalDate(detectionStatus?.lastSuccessAt)} />
          {detectionStatus?.error && <SettingRow label="Error" value={detectionStatus.error} />}
        </div>
      </section>

      <section className="card settingsCard">
        <div className="panelHeader">
          <div>
            <h2>Triage workflow</h2>
            <p>Your View, Ignore, and Delete choices for the loaded scan are kept locally on this workstation between app reloads.</p>
          </div>
        </div>
        <div className="settingsRows compact">
          <SettingRow label="Open" value={String(actionCounts.open ?? 0)} />
          <SettingRow label="Ignored" value={String(actionCounts.ignored ?? 0)} />
          <SettingRow label="Deleted" value={String(actionCounts.deleted ?? 0)} />
        </div>
      </section>

      <section className="card settingsCard settingsWide">
        <div className="panelHeader">
          <div>
            <h2>Local data</h2>
            <p>Clear scan history, cached findings, package inventory, and triage choices. Detection packs and settings are kept.</p>
          </div>
          <Button onClick={() => setClearConfirming(true)} disabled={clearBusy || clearConfirming} icon={clearBusy ? <Spinner /> : <DatabaseZap size={16} />}>
            {clearBusy ? 'Clearing data' : clearConfirming ? 'Confirm clear' : 'Clear local data'}
          </Button>
        </div>
        {(clearConfirming || clearBusy || clearProgress) && (
          <div className={`clearProgress ${clearFailed ? 'failed' : ''}`}>
            {clearConfirming && !clearBusy && (
              <div className="clearConfirm">
                <AlertTriangle size={18} />
                <div>
                  <strong>Clear local cache data?</strong>
                  <span>This removes scan history, findings, file index rows, inventory rows, and local triage choices. Detection packs and settings stay.</span>
                </div>
                <div className="clearConfirmActions">
                  <button type="button" className="btn btn-ghost" onClick={() => setClearConfirming(false)}>
                    <X size={15} />
                    <span>Cancel</span>
                  </button>
                  <button type="button" className="btn btn-primary" onClick={() => void confirmClear()}>
                    <DatabaseZap size={15} />
                    <span>Clear now</span>
                  </button>
                </div>
              </div>
            )}
            <div className="clearProgressTop">
              <span>{clearConfirming && !clearBusy ? 'Waiting for confirmation' : clearProgress?.status ?? 'Waiting to clear local data'}</span>
              <strong>{Math.round(clearProgress?.percent ?? 0)}%</strong>
            </div>
            <div className="clearProgressTrack" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(clearProgress?.percent ?? 0)}>
              <div style={{ width: `${Math.round(clearProgress?.percent ?? 0)}%` }} />
            </div>
            <span className="clearProgressHint">
              {clearBusy ? 'Large inventories can take a moment while SQLite drops and compacts local cache tables.' : clearProgress?.done ? 'The next scan will rebuild the file index and inventory from scratch.' : ''}
            </span>
            {clearLog.length > 0 && (
              <div className="clearLog" aria-label="Local data clear log">
                {clearLog.map((line, index) => (
                  <span key={`${line}-${index}`}>{line}</span>
                ))}
              </div>
            )}
          </div>
        )}
      </section>

      <section className="card settingsCard settingsWide">
        <div className="panelHeader">
          <div>
            <h2>Scan excludes</h2>
            <p>Skipped folders are left out while Spice builds the file index. Use this for large caches, training sets, or directories you know you do not want scanned.</p>
          </div>
          <Button onClick={onAddExcludeDirectory} icon={<FolderPlus size={16} />}>
            Add folder
          </Button>
        </div>
        <ExcludeDirectories dirs={excludedDirs} onSave={(dirs) => onSaveSettings({ ...settings, excludedDirs: dirs })} />
      </section>

      <section className="card settingsCard settingsWide">
        <div className="panelHeader">
          <div>
            <h2>Ignored matches</h2>
            <p>Ignored matches are hidden from scan results. Restore one if you want it back in the main triage list.</p>
          </div>
          <span>{ignoredFindings.length} hidden</span>
        </div>
        <IgnoredFindingsTable findings={ignoredFindings} onRestore={onRestoreFinding} />
      </section>
    </div>
  );
}

function ExcludeDirectories({ dirs, onSave }: { dirs: string[]; onSave: (dirs: string[]) => void }) {
  const [draft, setDraft] = useState(dirs.join('\n'));
  const parsed = useMemo(() => parseDirList(draft), [draft]);
  const changed = parsed.join('\n') !== parseDirList(dirs.join('\n')).join('\n');

  useEffect(() => {
    setDraft(dirs.join('\n'));
  }, [dirs]);

  return (
    <div className="excludeBox">
      <textarea
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
        spellCheck={false}
        placeholder="~/Library/Caches&#10;~/Downloads/old-fixtures&#10;/tmp/large-dataset"
      />
      <div className="excludeFooter">
        <span>{parsed.length} {parsed.length === 1 ? 'directory' : 'directories'} excluded from future scans</span>
        <Button onClick={() => onSave(parsed)} disabled={!changed}>Save excludes</Button>
      </div>
      {dirs.length > 0 && (
        <div className="excludeChips">
          {dirs.map((dir) => (
            <button key={dir} type="button" onClick={() => onSave(dirs.filter((item) => item !== dir))} title={`Remove ${dir}`}>
              <span>{dir}</span>
              <Trash2 size={13} />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function parseDirList(value: string) {
  const seen = new Set<string>();
  const dirs: string[] = [];
  for (const line of value.split('\n')) {
    const path = line.trim();
    if (!path || seen.has(path)) continue;
    seen.add(path);
    dirs.push(path);
  }
  return dirs;
}

function detectionSourceLabel(source?: string) {
  if (source === 'remote') return 'Remote GitHub';
  if (source === 'cache') return 'Cached detection packs';
  if (source === 'mixed') return 'Remote plus cached files';
  if (source === 'refreshing') return 'Refreshing';
  if (source === 'none') return 'No rules loaded';
  if (source) return source;
  return 'No rules loaded';
}

function detectionFetchLabel(status: DetectionStatus | null) {
  if (!status) return 'not checked';
  if (status.usedRemote && status.usedCache) return 'remote fetched with cache fallback';
  if (status.usedRemote) return 'remote fetched';
  if (status.usedCache) return 'cache fallback';
  return 'not loaded';
}

function SettingRow({ label, mono, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div className="settingRow">
      <span>{label}</span>
      <strong className={mono ? 'monoValue' : ''}>{value || 'never'}</strong>
    </div>
  );
}

function IgnoredFindingsTable({ findings, onRestore }: { findings: Finding[]; onRestore: (finding: Finding) => void }) {
  if (findings.length === 0) {
    return (
      <div className="emptyState small">
        <CheckCircle2 size={24} />
        <strong>No ignored matches</strong>
        <span>Ignored triage evidence will show up here.</span>
      </div>
    );
  }
  return (
    <div className="tableWrap ignoredTable">
      <table>
        <thead>
          <tr>
            <th>Why</th>
            <th>Type</th>
            <th>Path</th>
            <th>What matched</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding, index) => (
            <tr key={`${finding.path}-${finding.evidence}-${index}`}>
              <td>
                <div className="detection">{devReason(finding)}</div>
                <div className="detectionId">{finding.detectionId}</div>
              </td>
              <td>{devKind(finding.kind)}</td>
              <td className="path">{finding.path}</td>
              <td>{finding.evidence}</td>
              <td>
                <button type="button" className="restoreButton" onClick={() => onRestore(finding)}>Restore</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
