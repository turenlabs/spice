import { CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, Copy, FolderSearch, LoaderCircle, Search, X } from 'lucide-react';
import { Fragment, useEffect, useState } from 'react';
import type { MouseEvent } from 'react';
import type { InventoryBin, InventoryLocation, InventoryLocationsResult, InventoryRequest, InventoryResult, PackageRef } from '../types';

type InventoryPanelProps = {
  inventory: InventoryResult;
  request: InventoryRequest;
  loading?: boolean;
  onLoadLocations: (request: {
    ecosystem: string;
    name: string;
    version: string;
    sourceKind: string;
    sourceId?: string;
    sourcePath?: string;
    limit: number;
  }) => Promise<InventoryLocationsResult>;
  onRequestChange: (request: InventoryRequest) => void;
};

type LocationState = {
  loading: boolean;
  locations: InventoryLocation[];
  total: number;
  error?: string;
};

export function InventoryPanel({ inventory, loading, onLoadLocations, onRequestChange, request }: InventoryPanelProps) {
  const packages = inventory.packages ?? [];
  const total = inventory.total ?? 0;
  const limit = inventory.limit || request.limit;
  const offset = inventory.offset || request.offset;
  const currentPage = total === 0 ? 0 : Math.floor(offset / limit) + 1;
  const pageCount = total === 0 ? 0 : Math.ceil(total / limit);
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [locationCache, setLocationCache] = useState<Record<string, LocationState>>({});
  const [queryDraft, setQueryDraft] = useState(request.query);

  useEffect(() => {
    setQueryDraft(request.query);
  }, [request.query]);

  useEffect(() => {
    if (queryDraft === request.query) return;
    const timer = window.setTimeout(() => {
      onRequestChange({ ...request, query: queryDraft, offset: 0, skipFacets: true });
    }, 180);
    return () => window.clearTimeout(timer);
  }, [onRequestChange, queryDraft, request]);

  const patchRequest = (patch: Partial<InventoryRequest>, facets = false) => {
    onRequestChange({ ...request, ...patch, skipFacets: !facets });
  };
  const resetFilters = () => {
    setQueryDraft('');
    onRequestChange({ ...request, offset: 0, query: '', ecosystem: 'all', sourceKind: 'all', skipFacets: false });
  };
  const addFilterToken = (token: string) => {
    const next = [queryDraft.trim(), token].filter(Boolean).join(' ');
    setQueryDraft(next);
    onRequestChange({ ...request, query: next, offset: 0, skipFacets: true });
  };
  const goPage = (direction: -1 | 1) => {
    const nextOffset = Math.max(0, Math.min(Math.max(total - limit, 0), offset + direction * limit));
    patchRequest({ offset: nextOffset });
  };
  const toggleRow = async (pkg: PackageRef) => {
    const key = packageKey(pkg);
    if (openKey === key) {
      setOpenKey(null);
      return;
    }
    setOpenKey(key);
    if (locationCache[key]) return;
    setLocationCache((current) => ({ ...current, [key]: { loading: true, locations: [], total: pkg.sourceCount ?? 0 } }));
    try {
      const result = await onLoadLocations({
        ecosystem: pkg.ecosystem,
        name: pkg.name,
        version: pkg.version,
        sourceKind: pkg.sourceKind,
        sourceId: pkg.sourceId,
        sourcePath: pkg.sourcePath,
        limit: 50,
      });
      setLocationCache((current) => ({
        ...current,
        [key]: { loading: false, locations: result.locations ?? [], total: result.total ?? 0 },
      }));
    } catch (err) {
      setLocationCache((current) => ({
        ...current,
        [key]: { loading: false, locations: [], total: 0, error: err instanceof Error ? err.message : String(err) },
      }));
    }
  };

  if (loading && packages.length === 0 && total === 0) {
    return (
      <section className="card dataPanel inventoryLoadingPanel">
        <LoaderCircle className="spin" size={30} />
        <strong>Loading local inventory</strong>
        <span>Reading the package index from local SQLite.</span>
      </section>
    );
  }

  if (total === 0 && !request.query && request.ecosystem === 'all' && request.sourceKind === 'all') {
    return (
      <div className="emptyState">
        <CheckCircle2 size={28} />
        <strong>No local inventory yet</strong>
        <span>Run a scan to collect package manifests, Python requirements, and Docker base images.</span>
      </div>
    );
  }

  return (
    <section className="card dataPanel">
      <div className="panelHeader">
        <div>
          <h2>Local inventory</h2>
          <p>Packages and container bases Spice has seen on this workstation.</p>
        </div>
        <span>{loading ? <><LoaderCircle className="spin inlineSpin" size={13} /> Loading</> : `${total.toLocaleString()} rows`}</span>
      </div>
      <div className="inventoryTools">
        <label className="inventorySearch">
          <Search size={15} />
          <input
            value={queryDraft}
            onChange={(event) => setQueryDraft(event.target.value)}
            placeholder="Filter packages: react ecosystem:npm source:package-lock path:node_modules"
            spellCheck={false}
          />
          {queryDraft ? (
            <button type="button" onClick={() => {
              setQueryDraft('');
              patchRequest({ query: '', offset: 0 });
            }} aria-label="Clear inventory search">
              <X size={14} />
            </button>
          ) : null}
        </label>
        <select
          className="inventoryPageSize"
          value={request.limit}
          onChange={(event) => patchRequest({ limit: Number(event.target.value), offset: 0 })}
          aria-label="Inventory page size"
        >
          <option value={50}>50 rows</option>
          <option value={100}>100 rows</option>
          <option value={250}>250 rows</option>
          <option value={500}>500 rows</option>
        </select>
        <button className="chip" type="button" onClick={resetFilters} disabled={!queryDraft && request.ecosystem === 'all' && request.sourceKind === 'all'}>
          Reset
        </button>
      </div>
      <div className="inventoryQueryHelp" aria-label="Inventory filter examples">
        <span>Filters</span>
        {['ecosystem:npm', 'ecosystem:pypi', 'source:package-lock', 'source:requirements', 'name:react', 'version:1.', 'path:node_modules'].map((token) => (
          <button type="button" key={token} onClick={() => addFilterToken(token)}>{token}</button>
        ))}
      </div>
      <InventoryFilter
        active={request.ecosystem}
        bins={inventory.ecosystemCounts ?? []}
        label="Ecosystem"
        onChange={(ecosystem) => patchRequest({ ecosystem, offset: 0 }, true)}
      />
      <InventoryFilter
        active={request.sourceKind}
        bins={inventory.sourceKindCounts ?? []}
        label="Source"
        onChange={(sourceKind) => patchRequest({ sourceKind, offset: 0 }, true)}
      />
      <div className="inventoryPager">
        <button className="btn btn-ghost btn-icon" type="button" onClick={() => goPage(-1)} disabled={offset === 0} aria-label="Previous inventory page">
          <ChevronLeft size={15} />
        </button>
        <span>
          {loading ? 'Loading' : total === 0 ? 'No matches' : `Page ${currentPage.toLocaleString()} of ${pageCount.toLocaleString()}`}
        </span>
        <button className="btn btn-ghost btn-icon" type="button" onClick={() => goPage(1)} disabled={offset + limit >= total} aria-label="Next inventory page">
          <ChevronRight size={15} />
        </button>
      </div>
      <div className="tableWrap inventoryTable">
        {loading && packages.length > 0 ? (
          <div className="inventoryLoadingVeil">
            <LoaderCircle className="spin" size={18} />
            <span>Refreshing inventory</span>
          </div>
        ) : null}
        <table>
          <colgroup>
            <col className="inventoryColEco" />
            <col className="inventoryColName" />
            <col className="inventoryColVersion" />
            <col className="inventoryColKind" />
            <col className="inventoryColLocations" />
          </colgroup>
          <thead>
            <tr>
              <th>Ecosystem</th>
              <th>Name</th>
              <th>Version</th>
              <th>Kind</th>
              <th>Locations</th>
            </tr>
          </thead>
          <tbody>
            {packages.map((pkg, index) => {
              const key = packageKey(pkg);
              const open = openKey === key;
              const details = locationCache[key];
              const count = pkg.sourceCount || 1;
              return (
                <Fragment key={`${key}-${offset + index}`}>
                  <tr key={`${key}-row-${offset + index}`} className="inventoryRow" data-open={open} onClick={() => void toggleRow(pkg)}>
                    <td><span className="inventoryBadge">{pkg.ecosystem || 'unknown'}</span></td>
                    <td className="inventoryName" title={pkg.name}>
                      <span className="inventoryExpander">{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
                      {pkg.name}
                    </td>
                    <td className="monoValue inventoryVersion" title={pkg.version || 'unknown'}>{pkg.version || 'unknown'}</td>
                    <td className="inventoryKind">{pkg.sourceKind || 'unknown'}</td>
                    <td className="inventoryLocationCell" title={pkg.sourcePath}>
                      <b>{count.toLocaleString()}</b>
                      <span>{count === 1 ? 'location' : 'locations'}</span>
                      <em>{compactPath(pkg.sourcePath)}</em>
                    </td>
                  </tr>
                  {open ? (
                    <tr key={`${key}-detail`} className="inventoryDetailRow">
                      <td colSpan={5}>
                        <InventoryDetails pkg={pkg} details={details} />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        {packages.length === 0 ? (
          <div className="inventoryNoResults">
            <strong>No packages match those filters</strong>
            <span>Clear the search or switch the ecosystem/source chips.</span>
          </div>
        ) : null}
      </div>
    </section>
  );
}

function InventoryDetails({ details, pkg }: { details?: LocationState; pkg: PackageRef }) {
  const count = pkg.sourceCount || details?.total || 1;
  const sourceIDLabel = pkg.sourceId && looksLikeSHA256(pkg.sourceId) ? 'Source digest' : 'Source key';
  return (
    <div className="inventoryDetails">
      <div className="inventoryDetailMeta">
        <span><b>Package</b>{pkg.name}</span>
        <span><b>Version</b>{pkg.version || 'unknown'}</span>
        <span><b>Source type</b>{pkg.sourceKind || 'unknown'}</span>
        <span><b>Seen in</b>{count.toLocaleString()} {count === 1 ? 'location' : 'locations'}</span>
        {pkg.sourceId ? <span><b>{sourceIDLabel}</b>{shortDigest(pkg.sourceId)}</span> : null}
        {pkg.discoveredAt ? <span><b>Last indexed</b>{formatInventoryDate(pkg.discoveredAt)}</span> : null}
      </div>
      <div className="inventoryLocationHead">
        <strong><FolderSearch size={14} /> Source locations</strong>
        {details?.total && details.total > details.locations.length ? <span>showing {details.locations.length} of {details.total}</span> : null}
      </div>
      {details?.loading ? (
        <div className="inventoryLocationStatus"><LoaderCircle className="spin inlineSpin" size={13} /> Loading locations...</div>
      ) : details?.error ? (
        <div className="inventoryLocationStatus">Could not load locations: {details.error}</div>
      ) : details?.locations.length ? (
        <div className="inventoryLocations">
          {details.locations.map((location) => (
            <div className="inventoryLocation" key={`${location.sourcePath}-${location.sourceSha256}`}>
              <span className="path" title={location.sourcePath}>{location.sourcePath}</span>
              <button type="button" onClick={(event) => copyPath(event, location.sourcePath)} title="Copy path">
                <Copy size={13} />
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="inventoryLocations">
          <div className="inventoryLocation">
            <span className="path" title={pkg.sourcePath}>{pkg.sourcePath}</span>
            <button type="button" onClick={(event) => copyPath(event, pkg.sourcePath)} title="Copy path">
              <Copy size={13} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function packageKey(pkg: PackageRef) {
  return [pkg.ecosystem, pkg.name, pkg.version, pkg.sourceKind, pkg.sourceId || pkg.sourcePath].join('\0');
}

function compactPath(path: string) {
  const normalized = path.replaceAll('\\', '/');
  const parts = normalized.split('/').filter(Boolean);
  if (parts.length <= 3) return path;
  return `.../${parts.slice(-3).join('/')}`;
}

function shortDigest(value: string) {
  return value.length > 18 ? `${value.slice(0, 12)}...${value.slice(-6)}` : value;
}

function looksLikeSHA256(value: string) {
  return /^[a-f0-9]{64}$/i.test(value);
}

function formatInventoryDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function copyPath(event: MouseEvent<HTMLButtonElement>, path: string) {
  event.stopPropagation();
  void navigator.clipboard?.writeText(path);
}

function InventoryFilter({ active, bins, label, onChange }: {
  active: string;
  bins: InventoryBin[];
  label: string;
  onChange: (value: string) => void;
}) {
  const total = bins.reduce((sum, bin) => sum + bin.count, 0);
  return (
    <div className="inventoryFilters" aria-label={`Inventory ${label.toLowerCase()} filters`}>
      <span className="filterLabel">{label}</span>
      <button className="chip" data-active={active === 'all'} type="button" onClick={() => onChange('all')}>
        All <span className="count">{total.toLocaleString()}</span>
      </button>
      {bins.map((bin) => (
        <button className="chip" data-active={active === bin.value} type="button" key={bin.value} onClick={() => onChange(bin.value)}>
          {bin.value} <span className="count">{bin.count.toLocaleString()}</span>
        </button>
      ))}
    </div>
  );
}
