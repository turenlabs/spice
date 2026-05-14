import { CheckCircle2, ChevronLeft, ChevronRight, Search, X } from 'lucide-react';
import type { InventoryBin, InventoryRequest, InventoryResult } from '../types';

type InventoryPanelProps = {
  inventory: InventoryResult;
  request: InventoryRequest;
  loading?: boolean;
  onRequestChange: (request: InventoryRequest) => void;
};

export function InventoryPanel({ inventory, loading, onRequestChange, request }: InventoryPanelProps) {
  const packages = inventory.packages ?? [];
  const total = inventory.total ?? 0;
  const limit = inventory.limit || request.limit;
  const offset = inventory.offset || request.offset;
  const currentPage = total === 0 ? 0 : Math.floor(offset / limit) + 1;
  const pageCount = total === 0 ? 0 : Math.ceil(total / limit);

  const patchRequest = (patch: Partial<InventoryRequest>) => {
    onRequestChange({ ...request, ...patch });
  };
  const resetFilters = () => {
    onRequestChange({ ...request, offset: 0, query: '', ecosystem: 'all', sourceKind: 'all' });
  };
  const goPage = (direction: -1 | 1) => {
    const nextOffset = Math.max(0, Math.min(Math.max(total - limit, 0), offset + direction * limit));
    patchRequest({ offset: nextOffset });
  };

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
        <span>{total.toLocaleString()} rows</span>
      </div>
      <div className="inventoryTools">
        <label className="inventorySearch">
          <Search size={15} />
          <input
            value={request.query}
            onChange={(event) => patchRequest({ query: event.target.value, offset: 0 })}
            placeholder="Search package, version, or path"
            spellCheck={false}
          />
          {request.query ? (
            <button type="button" onClick={() => patchRequest({ query: '', offset: 0 })} aria-label="Clear inventory search">
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
        <button className="chip" type="button" onClick={resetFilters} disabled={!request.query && request.ecosystem === 'all' && request.sourceKind === 'all'}>
          Reset
        </button>
      </div>
      <InventoryFilter
        active={request.ecosystem}
        bins={inventory.ecosystemCounts ?? []}
        label="Ecosystem"
        onChange={(ecosystem) => patchRequest({ ecosystem, offset: 0 })}
      />
      <InventoryFilter
        active={request.sourceKind}
        bins={inventory.sourceKindCounts ?? []}
        label="Source"
        onChange={(sourceKind) => patchRequest({ sourceKind, offset: 0 })}
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
        <table>
          <colgroup>
            <col className="inventoryColEco" />
            <col className="inventoryColName" />
            <col className="inventoryColVersion" />
            <col className="inventoryColKind" />
            <col className="inventoryColSource" />
          </colgroup>
          <thead>
            <tr>
              <th>Ecosystem</th>
              <th>Name</th>
              <th>Version</th>
              <th>Kind</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {packages.map((pkg, index) => (
              <tr key={`${pkg.ecosystem}-${pkg.name}-${pkg.version}-${pkg.sourcePath}-${offset + index}`}>
                <td><span className="inventoryBadge">{pkg.ecosystem || 'unknown'}</span></td>
                <td className="inventoryName" title={pkg.name}>{pkg.name}</td>
                <td className="monoValue inventoryVersion" title={pkg.version || 'unknown'}>{pkg.version || 'unknown'}</td>
                <td className="inventoryKind">{pkg.sourceKind || 'unknown'}</td>
                <td className="path inventoryPath" title={pkg.sourcePath}>{pkg.sourcePath}</td>
              </tr>
            ))}
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
