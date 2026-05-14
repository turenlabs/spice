import { FileText, X } from 'lucide-react';
import { Spinner } from './Common';
import type { FilePreview, Finding } from '../types';
import { formatBytes, formatDateTime } from '../utils';

export function PreviewPane({ finding, onClose, preview }: { finding: Finding; onClose: () => void; preview: FilePreview | null }) {
  return (
    <aside className="previewPane">
      <div className="previewHeader">
        <div>
          <h2><FileText size={16} /> File view</h2>
          <p>{finding.path}</p>
        </div>
        <button type="button" onClick={onClose} aria-label="Close preview"><X size={16} /></button>
      </div>
      {!preview ? (
        <div className="previewLoading"><Spinner /> Loading preview</div>
      ) : (
        <>
          <div className="previewMeta">
            <span>{preview.mode}</span>
            <span>{formatBytes(preview.size)}</span>
            <span>{formatDateTime(preview.modified)}</span>
            {preview.truncated && <span>truncated</span>}
          </div>
          {preview.encoding === 'base64' ? (
            <div className="binaryPreview">Binary preview shown as base64. Use external forensic tooling before deleting.</div>
          ) : (
            <pre>{preview.content}</pre>
          )}
        </>
      )}
    </aside>
  );
}
