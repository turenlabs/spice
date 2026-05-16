import React, { useMemo, useState } from 'react';
import { Ban, CheckCircle2, Eye, Search, Trash2 } from 'lucide-react';
import type { Finding, FindingAction } from '../types';
import { devFindingBucket, devFindingLabel, devKind, devReason, devSeverityCounts, findingKey } from '../utils';

export function FindingsTable({ actions, findings, onDelete, onIgnore, onView, scanned }: {
  actions: Record<string, FindingAction>;
  findings: Finding[];
  onDelete: (finding: Finding) => void;
  onIgnore: (finding: Finding) => void;
  onView: (finding: Finding) => void;
  scanned: boolean;
}) {
  const [filter, setFilter] = useState<'all' | 'critical' | 'review' | 'worth'>('all');
  const [query, setQuery] = useState('');
  const [openKey, setOpenKey] = useState<string | null>(null);
  const counts = devSeverityCounts(findings);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings.filter((finding) => {
      if (filter !== 'all' && devFindingBucket(finding) !== filter) return false;
      if (!needle) return true;
      return [finding.path, finding.evidence, finding.kind, finding.campaign, finding.detectionId, finding.confidence, finding.context]
        .join(' ')
        .toLowerCase()
        .includes(needle);
    });
  }, [filter, findings, query]);
  if (findings.length === 0) {
    return (
      <div className="emptyState">
        <CheckCircle2 size={28} />
        <strong>{scanned ? 'Scan completed: nothing to review' : 'No scan has run'}</strong>
        <span>{scanned ? 'No loaded detection pack matched the selected paths. That is not a guarantee of safety.' : 'Run Scan against a project, home directory, or mounted volume.'}</span>
      </div>
    );
  }
  return (
    <section className="issues">
      <div className="issues-head">
        <h2 className="issues-title">Triage evidence</h2>
        <span className="issues-meta">{filtered.length} of {findings.length} shown · exposure signals, not proof of compromise</span>
      </div>
      <div className="filter-row">
        <button className="chip" data-active={filter === 'all'} type="button" onClick={() => setFilter('all')}>All <span className="count">{findings.length}</span></button>
        <button className="chip" data-active={filter === 'critical'} type="button" onClick={() => setFilter('critical')}><span className="sev-dot critical" /> High-confidence <span className="count">{counts.critical}</span></button>
        <button className="chip" data-active={filter === 'review'} type="button" onClick={() => setFilter('review')}><span className="sev-dot review" /> Needs triage <span className="count">{counts.review}</span></button>
        <button className="chip" data-active={filter === 'worth'} type="button" onClick={() => setFilter('worth')}><span className="sev-dot worth" /> Context <span className="count">{counts.worth}</span></button>
        <label className="finding-search">
          <Search size={14} />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search package, file, path" spellCheck={false} />
        </label>
      </div>
      <div className="findings-grid">
        <div className="col-head">
          <span>Package / file</span>
          <span>What matched</span>
          <span>Where</span>
          <span>Actions</span>
        </div>
        {filtered.map((finding, index) => {
          const key = findingKey(finding);
          const action = actions[key] ?? 'open';
          const open = openKey === key;
          const bucket = devFindingBucket(finding);
          const subject = findingSubject(finding);
          const where = findingWhere(finding.path);
          return (
            <React.Fragment key={`${finding.path}-${finding.evidence}-${index}`}>
              <button className="finding-row" data-open={open} type="button" onClick={() => setOpenKey(open ? null : key)}>
                <span className="row-subject">
                  <span className="row-title"><i className="row-sev" data-sev={bucket} />{subject.title}</span>
                  <span className="row-subtitle">{devFindingLabel(finding)} · {subject.subtitle}</span>
                </span>
                <span className="row-finding">
                  <b>{devKind(finding.kind)}</b>
                  <em>{finding.evidence}</em>
                </span>
                <span className="row-where" title={finding.path}>
                  <b>{where.file}</b>
                  <em>{where.dir}</em>
                </span>
                <span className="row-actions" aria-hidden="true">
                  <Eye size={14} />
                  <span className="row-caret">›</span>
                </span>
              </button>
              {open && (
                <div className="detail">
                  <div className="detail-rail" />
                  <div className="detail-body">
                    <div className="detail-desc">{devReason(finding)}</div>
                    <div className="detail-desc">{finding.remediation}</div>
                    {finding.context && <div className="detail-snip" data-label="Context">{finding.context}</div>}
                    <div className="detail-snip" data-label="Matched evidence">{finding.evidence}</div>
                    <div className="detail-actions">
                      <span className="ph">{action}</span>
                      <button className="btn btn-primary" type="button" onClick={() => onView(finding)}><Eye size={14} /> View</button>
                      <button className="btn btn-ghost" type="button" onClick={() => onIgnore(finding)}><Ban size={14} /> Ignore</button>
                      <button className="btn btn-ghost danger" type="button" onClick={() => onDelete(finding)}><Trash2 size={14} /> Delete</button>
                    </div>
                  </div>
                </div>
              )}
            </React.Fragment>
          );
        })}
      </div>
    </section>
  );
}

function findingSubject(finding: Finding) {
  const packageMatch = finding.evidence.match(/^((?:@[^/\s@]+\/)?[^@\s]+)@([^\s]+)\s+in\s+(.+)$/);
  if (packageMatch) {
    return {
      title: packageMatch[1],
      subtitle: `${packageMatch[2]} · ${packageMatch[3]}`,
    };
  }
  const file = basename(finding.path);
  return {
    title: file || finding.detectionId,
    subtitle: devKind(finding.kind),
  };
}

function findingWhere(path: string) {
  const normalized = path.replaceAll('\\', '/');
  const index = normalized.lastIndexOf('/');
  if (index < 0) return { file: normalized, dir: '.' };
  return {
    file: normalized.slice(index + 1) || normalized,
    dir: normalized.slice(0, index) || '/',
  };
}

function basename(path: string) {
  return findingWhere(path).file;
}
