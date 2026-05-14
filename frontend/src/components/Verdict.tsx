export function Verdict({ counts, duration, lastRun, status }: {
  counts: { critical: number; review: number; worth: number };
  duration: string;
  lastRun: string;
  status: 'idle' | 'scanning';
}) {
  const total = counts.critical + counts.review + counts.worth;
  const isClean = total === 0;
  const eyeClass = status === 'scanning' ? 'scanning' : isClean ? 'clean' : counts.critical > 0 ? 'crit' : '';
  const dotClass = status === 'scanning' ? 'scanning' : isClean ? 'clean' : '';
  const eyebrow = isClean ? 'LAST PASS · NOTHING WORTH WAKING YOU' : '>_ LOCAL DEPENDENCY SAFETY';

  return (
    <header className="verdict">
      <div className="verdict-line">
        {status !== 'scanning' && (
          <div className={`verdict-eyebrow ${dotClass}`}>
            <span className="dot" />
            <span className="eyebrow">{eyebrow}</span>
          </div>
        )}
        <h1 className="verdict-head">
          {status === 'scanning' ? (
            <>
              <span className="n">...</span>
              <span>Scanning</span>
            </>
          ) : isClean ? (
            <>
              <span className="n clean">0</span>
              <span>open. <i>Sleep.</i></span>
            </>
          ) : (
            <>
              <span className="n">{total}</span>
              <span>open. <i>{counts.critical + counts.review} need eyes.</i></span>
            </>
          )}
        </h1>
        <p className="verdict-sub">
          {status === 'scanning'
            ? 'Looking through package lockfiles, install scripts, cached tarballs and startup files using the loaded incident packs.'
            : isClean
              ? 'Nothing in the scanned paths matches the loaded package, file, hash, IOC, or persistence checks.'
              : 'Matched package versions, install scripts, hashes, IOCs, or files from loaded incident packs.'}
        </p>
        {!isClean && status !== 'scanning' && (
          <div className="pill-row">
            <span className="pill" data-sev="critical"><i className="d" /><b>{counts.critical}</b> critical</span>
            <span className="pill" data-sev="review"><i className="d" /><b>{counts.review}</b> need review</span>
            <span className="pill" data-sev="worth"><i className="d" /><b>{counts.worth}</b> worth checking</span>
          </div>
        )}
        <div className="verdict-meta">
          <span>Last scan <span className="mono"><b>{lastRun}</b></span></span>
          <span>Duration <span className="mono"><b>{duration}</b></span></span>
          <span>Cache <span className="mono"><b>on</b></span></span>
        </div>
      </div>
      <div className="verdict-eye">
        <div className={`orb ${eyeClass}`} aria-hidden="true" />
      </div>
    </header>
  );
}
