import type { Finding, FindingAction, ScanProgress, ScanProgressPayload } from './types';

export function normalizeScanProgress(payload: unknown, current: ScanProgress | null): ScanProgress {
  const progress = (payload && typeof payload === 'object' ? payload : {}) as ScanProgressPayload;
  const seq = firstNumber(progress.seq, 0) ?? 0;
  const scanId = firstText(progress.scanId, current?.scanId, '');
  if (current?.scanId && progress.scanId && progress.scanId !== current.scanId) return current;
  if (current && seq > 0 && current.seq > 0 && seq <= current.seq) return current;
  const total = firstNumber(progress.total, progress.filesTotal, current?.total);
  const processed = firstNumber(
    progress.processed,
    progress.completed,
    typeof progress.current === 'number' ? progress.current : undefined,
    current?.processed,
    0,
  ) ?? 0;
  const scanned = firstNumber(progress.scanned, progress.filesScanned, current?.scanned, 0) ?? 0;
  const skipped = firstNumber(progress.skipped, current?.skipped, 0) ?? 0;
  const findings = firstNumber(progress.findings, current?.findings, 0) ?? 0;
  const rawPercent = firstNumber(progress.percent, progress.percentage);
  const calculatedPercent = total && total > 0 ? (processed / total) * 100 : undefined;
  const phase = firstText(progress.phase, current?.phase, 'scanning');
  const status = firstText(progress.status, progress.message, current?.status, 'Scanning selected paths');
  const done = progress.done === true || /completed|complete|finished|done/i.test(status);
  const nextPercent = done ? 100 : normalizePercent(rawPercent ?? calculatedPercent ?? current?.percent ?? 0);
  const percent = current && !done ? Math.max(current.percent, nextPercent) : nextPercent;
  const currentFile = firstText(
    progress.currentFile,
    progress.currentPath,
    progress.path,
    progress.file,
    typeof progress.current === 'string' ? progress.current : undefined,
    current?.current,
    'Waiting for scan progress',
  );

  return {
    current: currentFile,
    findings,
    phase,
    percent,
    processed,
    running: done ? false : current?.running ?? true,
    scanId,
    scanned,
    seq,
    skipped,
    status,
    total,
  };
}

export function appendUniqueFinding(findings: Finding[], finding: Finding) {
  const key = findingKey(finding);
  if (findings.some((existing) => findingKey(existing) === key)) return findings;
  return [...findings, finding];
}

export function loadFindingActions(): Record<string, FindingAction> {
  try {
    const parsed = JSON.parse(localStorage.getItem('spice:finding-actions') || '{}') as Record<string, FindingAction>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

export function findingKey(finding: Finding) {
  return `${finding.detectionId}\0${finding.severity}\0${finding.kind}\0${finding.path}\0${finding.evidence}`;
}

export function countActions(actions: Record<string, FindingAction>) {
  return Object.values(actions).reduce<Record<FindingAction, number>>((counts, action) => {
    counts[action] = (counts[action] ?? 0) + 1;
    return counts;
  }, { open: 0, ignored: 0, deleted: 0 });
}

export function devSeverityBucket(severity: string): 'critical' | 'review' | 'worth' {
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'review';
  return 'worth';
}

export function devSeverityCounts(findings: Finding[]) {
  return findings.reduce((counts, finding) => {
    counts[devSeverityBucket(finding.severity)] += 1;
    return counts;
  }, { critical: 0, review: 0, worth: 0 });
}

export function devKind(kind: string) {
  switch (kind) {
    case 'affected-package':
      return 'package version';
    case 'known-malware-hash':
      return 'matched bad file';
    case 'campaign-artifact':
      return 'suspicious file';
    case 'suspicious-install-hook':
      return 'install script';
    case 'ioc-string':
      return 'matched text';
    case 'persistence':
      return 'startup item';
    default:
      return kind.replaceAll('-', ' ');
  }
}

export function devReason(finding: Finding) {
  switch (finding.kind) {
    case 'affected-package':
      return 'This dependency version was reported as compromised.';
    case 'known-malware-hash':
      return 'This file exactly matches a known unsafe file.';
    case 'campaign-artifact':
      return 'This file has a suspicious name plus matching behavior or content.';
    case 'suspicious-install-hook':
      return 'This package runs code during install.';
    case 'ioc-string':
      return 'This file contains text seen in public reports.';
    case 'persistence':
      return 'This file can run code automatically after login or startup.';
    default:
      return finding.campaign || finding.detectionId;
  }
}

export function defaultRemoteLabel() {
  return 'https://api.github.com/repos/turenlabs/spice-detections/contents/manifest.json?ref=main';
}

export function progressLabel(phase: string, status: string) {
  if (phase === 'indexing' || phase === 'enumerating') return 'Indexing file tree';
  if (phase === 'scanning') return 'Scanning and caching files';
  if (phase === 'done') return 'Scan completed';
  return status;
}

export function formatDateTime(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

export function formatOptionalDate(value?: string) {
  return value ? formatDateTime(value) : 'never';
}

export function formatBytes(value: number) {
  if (!Number.isFinite(value)) return 'unknown';
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

export function elapsed(start: string, end: string) {
  const startMs = new Date(start).getTime();
  const endMs = new Date(end).getTime();
  if (Number.isNaN(startMs) || Number.isNaN(endMs)) return 'unknown';
  const ms = Math.max(0, endMs - startMs);
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
}

function firstNumber(...values: Array<number | undefined>) {
  return values.find((value) => typeof value === 'number' && Number.isFinite(value));
}

function firstText(...values: Array<string | undefined>) {
  return values.find((value) => typeof value === 'string' && value.trim().length > 0)?.trim() ?? '';
}

function normalizePercent(value: number) {
  const percent = value <= 1 ? value * 100 : value;
  return Math.max(0, Math.min(100, percent));
}
