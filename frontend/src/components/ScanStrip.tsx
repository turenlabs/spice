import { CheckCircle2, FolderOpen, PackageSearch, Power, Radar, RotateCcw, Search, ShieldAlert } from 'lucide-react';
import type { ScanProfile, ScanProgress } from '../types';
import { progressLabel } from '../utils';

export function ScanStrip({
  disabled,
  duration,
  findingsCount,
  onCheckResults,
  onPathText,
  onPickDirectory,
  onReset,
  onRunScan,
  onScanProfileChange,
  onStopScan,
  pathText,
  paths,
  progress,
  scanProfile,
  scanned,
}: {
  disabled: boolean;
  duration: string;
  findingsCount: number;
  onCheckResults: () => void;
  onPathText: (value: string) => void;
  onPickDirectory: () => void;
  onReset: () => void;
  onRunScan: () => void;
  onScanProfileChange: (value: ScanProfile) => void;
  onStopScan: () => void;
  pathText: string;
  paths: string[];
  progress: ScanProgress | null;
  scanProfile: ScanProfile;
  scanned: boolean;
}) {
  const running = Boolean(progress?.running);
  const done = !running && scanned;
  const phase = running ? phaseFromProgress(progress) : done ? 'done' : 'ready';
  const stopped = done && progress ? /stopped|canceled|cancelled/i.test(progress.status) : false;
  const showPercent = phase === 'scanning' || phase === 'done';
  const displayPercent = running && progress && showPercent ? Math.min(99, Math.round(progress.percent)) : done ? 100 : 0;
  const processedLabel = progress?.total ? `${progress.processed.toLocaleString()} / ${progress.total.toLocaleString()}` : progress ? progress.processed.toLocaleString() : 'not started';
  const phaseTitle = phase === 'indexing' ? 'Indexing file tree' : phase === 'scanning' ? 'Checking candidates' : stopped ? 'Scan stopped' : phase === 'done' ? 'Scan complete' : 'Ready to scan';
  const selectedProfile = scanProfiles.find((item) => item.id === scanProfile) ?? scanProfiles[0];

  return (
    <section className="scan wizard" aria-live="polite">
      <div className="wizard-head">
        <div>
          <h2>Scan wizard</h2>
          <p>Choose how much disk to cover. Results are exposure signals from the loaded incident packs.</p>
        </div>
        {running ? (
          <button className="btn btn-ghost" type="button" onClick={onStopScan}>Stop</button>
        ) : done ? (
          <button className="btn btn-ghost" type="button" onClick={onReset}><RotateCcw size={14} /> New scan</button>
        ) : null}
      </div>

      <div className="wizard-steps">
        <Step active={phase === 'indexing'} complete={phase === 'scanning' || phase === 'done'} label="Indexing" />
        <Step active={phase === 'scanning'} complete={phase === 'done'} label="Scanning" />
        <Step active={phase === 'done'} complete={phase === 'done'} label="Done" />
      </div>

      {!running && !done ? (
        <>
          <div className="scan-type-grid" role="radiogroup" aria-label="Scan type">
            {scanProfiles.map((profile) => (
              <button
                key={profile.id}
                className="scan-type-card"
                data-active={scanProfile === profile.id}
                type="button"
                role="radio"
                aria-checked={scanProfile === profile.id}
                onClick={() => onScanProfileChange(profile.id)}
              >
                <profile.icon size={18} />
                <strong>{profile.title}</strong>
                <span>{profile.copy}</span>
              </button>
            ))}
          </div>

          <div className="scan-row">
            <label className="scan-path">
              <span className="glyph">$</span>
              <input value={pathText} onChange={(event) => onPathText(event.target.value)} placeholder="path to scan" spellCheck={false} />
              <span className="tail">{paths.length} {paths.length === 1 ? 'path' : 'paths'} queued</span>
            </label>
            <button className="btn btn-ghost btn-icon" type="button" onClick={onPickDirectory} title="Pick folder">
              <FolderOpen size={15} />
            </button>
            <button className="btn btn-primary" type="button" onClick={onRunScan} disabled={disabled}>
              <Search size={15} />
              <span>Scan</span>
            </button>
          </div>

          <div className="scan-plan">
            <div>
              <strong>{selectedProfile.planTitle}</strong>
              <span>{selectedProfile.planCopy}</span>
            </div>
            <ul>
              {selectedProfile.checks.map((check) => <li key={check}>{check}</li>)}
            </ul>
          </div>

        </>
      ) : running && progress ? (
        <div className="wizard-live">
          {showPercent ? (
            <div className="wizard-meter">
              <span>{displayPercent}%</span>
              <div className="live-bar"><i style={{ width: `${displayPercent}%` }} /></div>
            </div>
          ) : (
            <div className="wizard-meter indexing">
              <span>...</span>
              <div className="live-bar indeterminate"><i /></div>
            </div>
          )}
          <div className="wizard-status">
            <strong>{phaseTitle}</strong>
            <em>{progressLabel(progress.phase, progress.status)}</em>
            <span title={progress.current}>{progress.current}</span>
          </div>
          <div className="wizard-stats">
            <span><b>{processedLabel}</b> processed</span>
            {phase === 'scanning' ? (
              <>
                <span><b>{progress.scanned.toLocaleString()}</b> scanned</span>
                <span><b>{progress.skipped.toLocaleString()}</b> cached</span>
                <span><b>{progress.findings.toLocaleString()}</b> matches</span>
              </>
            ) : (
              <span><b>{progress.total?.toLocaleString() ?? progress.processed.toLocaleString()}</b> files indexed</span>
            )}
          </div>
        </div>
      ) : (
        <div className="wizard-done">
          <CheckCircle2 size={26} />
          <div>
            <strong>{findingsCount === 0 ? 'No open matches' : `${findingsCount} open ${findingsCount === 1 ? 'match' : 'matches'}`}</strong>
            <span>{stopped ? 'Stopped early. Results shown are from files checked before the stop completed.' : findingsCount === 0 ? 'Nothing matched the loaded detection packs in the selected paths.' : 'Review the matched packages, files, and install behavior as triage evidence.'}</span>
          </div>
          <button className="btn btn-primary" type="button" onClick={onCheckResults}>
            Check results
          </button>
        </div>
      )}
    </section>
  );
}

const scanProfiles: Array<{
  id: ScanProfile;
  title: string;
  copy: string;
  planTitle: string;
  planCopy: string;
  checks: string[];
  icon: typeof PackageSearch;
}> = [
  {
    id: 'project',
    title: 'Project scan',
    copy: 'Fast checks for manifests, lockfiles, install hooks, package archives, and incident artifacts.',
    planTitle: 'Project checks',
    planCopy: 'Best default for a repo or workspace before install, build, or release. Uses every loaded pack.',
    checks: ['Affected package versions', 'Install lifecycle scripts', 'Known incident files', 'Local package inventory'],
    icon: PackageSearch,
  },
  {
    id: 'shai-hulud',
    title: 'Incident sweep',
    copy: 'Targets common dependency caches, developer config, IDE residue, and persistence paths for all packs.',
    planTitle: 'Targeted incident checks',
    planCopy: 'Looks across npm, Python, developer tooling, startup paths, token configs, and known incident artifacts.',
    checks: ['Affected package versions', 'Lifecycle loaders', 'Persistence paths', 'C2 and exfil composites', 'IDE and package-cache residue'],
    icon: ShieldAlert,
  },
  {
    id: 'startup',
    title: 'Startup items',
    copy: 'Checks login agents, systemd units, autostart entries, shell startup files, and known persistence paths.',
    planTitle: 'Persistence checks',
    planCopy: 'Use this before rotating credentials when a pack mentions persistence or token-monitor behavior.',
    checks: ['macOS LaunchAgents', 'macOS LaunchDaemons', 'systemd user and system units', 'Linux autostart entries', 'Shell startup files'],
    icon: Power,
  },
  {
    id: 'deep',
    title: 'Deep disk scan',
    copy: 'Broad content scan for IOC strings, hashes, archives, composite rules, and system startup locations.',
    planTitle: 'Deep checks',
    planCopy: 'Reads more file contents and includes system startup paths outside your home directory.',
    checks: ['Known file hashes', 'IOC strings', 'Package archives', 'Startup files', 'Text files across selected paths'],
    icon: Radar,
  },
];

function Step({ active, complete, label }: { active: boolean; complete: boolean; label: string }) {
  return (
    <div className="wizard-step" data-active={active} data-complete={complete}>
      <span />
      <b>{label}</b>
    </div>
  );
}

function phaseFromProgress(progress: ScanProgress | null): 'ready' | 'indexing' | 'scanning' | 'done' {
  if (!progress) return 'ready';
  if (progress.phase === 'indexing' || progress.phase === 'starting') return 'indexing';
  if (progress.phase === 'done') return 'done';
  return 'scanning';
}
