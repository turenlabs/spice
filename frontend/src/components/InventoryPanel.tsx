import { CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, Copy, FolderSearch, LoaderCircle, Search, X } from 'lucide-react';
import { Fragment, useEffect, useMemo, useState } from 'react';
import type { MouseEvent } from 'react';
import type { InventoryBin, InventoryLocation, InventoryLocationsResult, InventoryRequest, InventoryResult, PackageRef } from '../types';

type InventoryPanelProps = {
  className?: string;
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

type FilterKey = 'ecosystem' | 'source' | 'name' | 'version' | 'path';

type FilterOption = {
  label: string;
  value: string;
};

type InventoryRecipe = {
  label: string;
  query: string;
};

type FilterMenuItem = {
  label: string;
  token: string;
  meta?: string;
  value?: string;
};

type FilterMenuSection = {
  title: string;
  items: FilterMenuItem[];
};

const inventoryRecipes: InventoryRecipe[] = [
  { label: 'JavaScript packages', query: 'ecosystem:npm' },
  { label: 'Python packages', query: 'ecosystem:pypi' },
  { label: 'Lockfiles', query: 'source:package-lock' },
  { label: 'Node modules', query: 'path:node_modules' },
  { label: 'Docker bases', query: 'ecosystem:docker' },
];

export function InventoryPanel({ className, inventory, loading, onLoadLocations, onRequestChange, request }: InventoryPanelProps) {
  const packages = inventory.packages ?? [];
  const total = inventory.total ?? 0;
  const limit = inventory.limit || request.limit;
  const offset = inventory.offset ?? request.offset;
  const currentPage = total === 0 ? 0 : Math.floor(offset / limit) + 1;
  const pageCount = total === 0 ? 0 : Math.ceil(total / limit);
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [locationCache, setLocationCache] = useState<Record<string, LocationState>>({});
  const [queryDraft, setQueryDraft] = useState(request.query);
  const [filterMenuOpen, setFilterMenuOpen] = useState(false);
  const filterOptions = useMemo(() => buildFilterOptions(inventory, packages), [inventory, packages]);
  const activeFilters = useMemo(() => structuredFilters(queryDraft), [queryDraft]);
  const freeTextDraft = useMemo(() => freeTextQuery(queryDraft), [queryDraft]);

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
  const runQuery = (query: string, facets = false) => {
    setQueryDraft(query);
    onRequestChange({
      ...request,
      query,
      ecosystem: 'all',
      sourceKind: 'all',
      offset: 0,
      skipFacets: !facets,
    });
  };
  const addFilterToken = (token: string) => {
    const separator = token.indexOf(':');
    const key = separator > 0 ? canonicalFilterKey(token.slice(0, separator)) : null;
    const next = key
      ? replaceStructuredFilter(queryDraft, key, token)
      : [queryDraft.trim(), token].filter(Boolean).join(' ');
    runQuery(next);
  };
  const removeStructuredFilter = (key: FilterKey) => {
    const next = replaceStructuredFilter(queryDraft, key, '');
    runQuery(next);
  };
  const updateFreeText = (value: string) => {
    const filters = structuredFilters(queryDraft).map(filterToken).join(' ');
    setQueryDraft([filters, value].map((part) => part.trim()).filter(Boolean).join(' '));
  };
  const closeFilterMenu = () => {
    window.setTimeout(() => setFilterMenuOpen(false), 120);
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
    <section className={['card dataPanel inventoryPanel', className].filter(Boolean).join(' ')}>
      <div className="panelHeader">
        <div>
          <h2>Local inventory</h2>
          <p>Find packages by ecosystem, source file, version, or path. Open a row to see where Spice found it.</p>
        </div>
        <span>{loading ? <><LoaderCircle className="spin inlineSpin" size={13} /> Loading</> : `${total.toLocaleString()} rows`}</span>
      </div>
      <div className="inventoryTools">
        <div className="inventoryFilterControl">
          <div className="inventorySearch" onClick={() => setFilterMenuOpen(true)} onBlur={closeFilterMenu}>
            <Search size={15} />
            {activeFilters.map((filter) => (
              <button
                className="inventorySearchToken"
                type="button"
                key={filter.key}
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => removeStructuredFilter(filter.key)}
                title="Remove filter"
              >
                <span>{filterChipLabel(filter)}</span>
                <X size={12} />
              </button>
            ))}
            <input
              value={freeTextDraft}
              onChange={(event) => updateFreeText(event.target.value)}
              onFocus={() => setFilterMenuOpen(true)}
              placeholder={activeFilters.length > 0 ? 'Search within results' : 'Filter inventory'}
              spellCheck={false}
            />
            {queryDraft ? (
              <button className="inventorySearchClear" type="button" onMouseDown={(event) => event.preventDefault()} onClick={() => runQuery('')} aria-label="Clear inventory search">
                <X size={14} />
              </button>
            ) : (
              <ChevronDown size={14} />
            )}
          </div>
          {filterMenuOpen ? (
            <InventoryFilterMenu
              filterOptions={filterOptions}
              onSelect={(token) => {
                addFilterToken(token);
                setFilterMenuOpen(false);
              }}
            />
          ) : null}
        </div>
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
      </div>
      <div className="inventoryPager">
        <button className="btn btn-ghost btn-icon" type="button" onClick={() => goPage(-1)} disabled={offset === 0} aria-label="Previous inventory page">
          <ChevronLeft size={15} />
        </button>
        <span>
          {loading ? 'Loading' : total === 0 ? 'No matches' : `Page ${currentPage.toLocaleString()} of ${pageCount.toLocaleString()}`}
        </span>
        {loading && packages.length > 0 ? (
          <span className="inventoryRefreshStatus">
            <LoaderCircle className="spin" size={13} />
            Refreshing
          </span>
        ) : null}
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

function InventoryFilterMenu({ filterOptions, onSelect }: {
  filterOptions: Record<FilterKey, FilterOption[]>;
  onSelect: (token: string) => void;
}) {
  const sections = buildFilterMenuSections(filterOptions);
  return (
    <div className="inventoryFilterMenu" onMouseDown={(event) => event.preventDefault()}>
      {sections.map((section) => (
        <div className="inventoryFilterMenuSection" key={section.title}>
          <span>{section.title}</span>
          <div>
            {section.items.map((item) => (
              <button type="button" key={`${section.title}-${item.token}`} onClick={() => onSelect(item.token)}>
                <span>{item.meta ?? section.title}</span>
                <b>{item.label}</b>
                {item.value ? <em>{item.value}</em> : null}
              </button>
            ))}
          </div>
        </div>
      ))}
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

function buildFilterOptions(inventory: InventoryResult, packages: PackageRef[]): Record<FilterKey, FilterOption[]> {
  return {
    ecosystem: binsToOptions(inventory.ecosystemCounts ?? []),
    source: binsToOptions(inventory.sourceKindCounts ?? []),
    name: packageFieldOptions(packages, 'name'),
    version: packageFieldOptions(packages, 'version'),
    path: packages
      .map((pkg) => ({ value: pkg.sourcePath, label: compactPath(pkg.sourcePath) }))
      .filter(uniqueOption)
      .slice(0, 80),
  };
}

function buildFilterMenuSections(filterOptions: Record<FilterKey, FilterOption[]>): FilterMenuSection[] {
  const sections: FilterMenuSection[] = [
    {
      title: 'Suggested',
      items: inventoryRecipes.map((recipe) => ({
        label: recipe.label,
        token: recipe.query,
        meta: filterTokenMeta(recipe.query),
        value: filterTokenValue(recipe.query),
      })),
    },
  ];
  const specs: Array<{ title: string; key: FilterKey; limit: number }> = [
    { title: 'Ecosystem', key: 'ecosystem', limit: 8 },
    { title: 'Source type', key: 'source', limit: 8 },
    { title: 'Package name', key: 'name', limit: 10 },
    { title: 'Version', key: 'version', limit: 8 },
    { title: 'Path contains', key: 'path', limit: 8 },
  ];
  for (const spec of specs) {
    const items = filterOptions[spec.key].slice(0, spec.limit).map((option) => ({
      label: option.label,
      token: `${spec.key}:${quoteFilterValue(option.value)}`,
      value: option.value,
    }));
    if (items.length > 0) {
      sections.push({ title: spec.title, items });
    }
  }
  return sections;
}

function filterTokenMeta(token: string) {
  const separator = token.indexOf(':');
  if (separator <= 0) return token;
  const key = canonicalFilterKey(token.slice(0, separator));
  if (!key) return token;
  return filterKeyLabel(key);
}

function filterTokenValue(token: string) {
  const separator = token.indexOf(':');
  if (separator <= 0) return '';
  return token.slice(separator + 1);
}

function binsToOptions(bins: InventoryBin[]) {
  return bins
    .filter((bin) => bin.value)
    .map((bin) => ({ value: bin.value, label: `${bin.value} (${bin.count.toLocaleString()})` }));
}

function packageFieldOptions(packages: PackageRef[], field: 'name' | 'version') {
  return packages
    .map((pkg) => pkg[field])
    .filter(Boolean)
    .map((value) => ({ value, label: value }))
    .filter(uniqueOption)
    .slice(0, 80);
}

function uniqueOption(option: FilterOption, index: number, options: FilterOption[]) {
  return options.findIndex((candidate) => candidate.value === option.value) === index;
}

function structuredFilters(query: string): Array<{ key: FilterKey; value: string }> {
  const filters: Array<{ key: FilterKey; value: string }> = [];
  for (const token of splitQueryTokens(query)) {
    const separator = token.indexOf(':');
    if (separator <= 0) continue;
    const key = canonicalFilterKey(token.slice(0, separator));
    if (!key) continue;
    filters.push({ key, value: unquoteFilterValue(token.slice(separator + 1)) });
  }
  return filters;
}

function replaceStructuredFilter(query: string, key: FilterKey, token: string) {
  const tokens = splitQueryTokens(query).filter((existing) => {
    const separator = existing.indexOf(':');
    if (separator <= 0) return true;
    return canonicalFilterKey(existing.slice(0, separator)) !== key;
  });
  if (token) tokens.push(token);
  return tokens.join(' ');
}

function freeTextQuery(query: string) {
  return splitQueryTokens(query).filter((token) => {
    const separator = token.indexOf(':');
    if (separator <= 0) return true;
    return canonicalFilterKey(token.slice(0, separator)) === null;
  }).join(' ');
}

function filterToken(filter: { key: FilterKey; value: string }) {
  return `${filter.key}:${quoteFilterValue(filter.value)}`;
}

function canonicalFilterKey(raw: string): FilterKey | null {
  switch (raw.trim().toLowerCase()) {
    case 'ecosystem':
    case 'eco':
      return 'ecosystem';
    case 'source':
    case 'kind':
    case 'type':
      return 'source';
    case 'name':
    case 'pkg':
    case 'package':
      return 'name';
    case 'version':
    case 'ver':
      return 'version';
    case 'path':
    case 'file':
    case 'location':
      return 'path';
    default:
      return null;
  }
}

function splitQueryTokens(query: string) {
  const tokens: string[] = [];
  let current = '';
  let quote = '';
  let escaped = false;
  for (const char of query) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = '';
      else current += char;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current.trim()) tokens.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  if (current.trim()) tokens.push(current.trim());
  return tokens;
}

function quoteFilterValue(value: string) {
  return /\s/.test(value) ? `"${value.replaceAll('"', '\\"')}"` : value;
}

function unquoteFilterValue(value: string) {
  return value.replaceAll('\\"', '"');
}

function filterChipLabel(filter: { key: FilterKey; value: string }) {
  return `${filterKeyLabel(filter.key)} is ${filter.value}`;
}

function filterKeyLabel(key: FilterKey) {
  switch (key) {
    case 'ecosystem':
      return 'Ecosystem';
    case 'source':
      return 'Source type';
    case 'name':
      return 'Package';
    case 'version':
      return 'Version';
    case 'path':
      return 'Path contains';
    default:
      return key;
  }
}
