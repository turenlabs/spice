export type Mode = 'scan' | 'findings' | 'inventory' | 'settings';

export type Finding = {
  detectionId: string;
  campaign: string;
  severity: string;
  confidence?: string;
  context?: string;
  kind: string;
  path: string;
  evidence: string;
  remediation: string;
};

export type ScanResult = {
  startedAt: string;
  finishedAt: string;
  roots: string[];
  findings: Finding[];
  indexed?: boolean;
  status?: string;
};

export type AppSettings = {
  excludedDirs: string[];
};

export type ScanProfile = 'project' | 'shai-hulud' | 'startup' | 'deep';

export type ScanProgress = {
  current: string;
  findings: number;
  phase: string;
  percent: number;
  processed: number;
  running: boolean;
  scanId: string;
  scanned: number;
  seq: number;
  skipped: number;
  status: string;
  total?: number;
};

export type ScanProgressPayload = Partial<{
  completed: number;
  current: string | number;
  currentFile: string;
  currentPath: string;
  done: boolean;
  file: string;
  filesScanned: number;
  filesTotal: number;
  message: string;
  path: string;
  percent: number;
  percentage: number;
  phase: string;
  processed: number;
  scanId: string;
  scanned: number;
  seq: number;
  skipped: number;
  findings: number;
  status: string;
  total: number;
}>;

export type ClearLocalDataProgress = {
  phase: string;
  status: string;
  percent: number;
  done?: boolean;
};

export type ScanFindingPayload = {
  scanId?: string;
  seq?: number;
  finding?: Finding;
};

export type FindingAction = 'open' | 'ignored' | 'deleted';

export type FilePreview = {
  path: string;
  name: string;
  size: number;
  mode: string;
  modified: string;
  content: string;
  encoding: string;
  truncated: boolean;
};

export type DetectionStatus = {
  remoteUrl: string;
  source: string;
  trustPolicy: string;
  usedCache: boolean;
  usedRemote: boolean;
  lastAttemptAt: string;
  lastSuccessAt: string;
  error?: string;
  packCount: number;
};

export type PackageRef = {
  ecosystem: string;
  name: string;
  version: string;
  sourcePath: string;
  sourceKind: string;
  sourceId?: string;
  sourceCount?: number;
  discoveredAt?: string;
};

export type InventoryBin = {
  value: string;
  count: number;
};

export type InventoryRequest = {
  limit: number;
  offset: number;
  query: string;
  ecosystem: string;
  sourceKind: string;
  skipFacets?: boolean;
};

export type InventoryResult = {
  packages: PackageRef[];
  total: number;
  limit: number;
  offset: number;
  ecosystemCounts: InventoryBin[];
  sourceKindCounts: InventoryBin[];
};

export type InventoryLocationRequest = {
  ecosystem: string;
  name: string;
  version: string;
  sourceKind: string;
  sourceId?: string;
  sourcePath?: string;
  limit: number;
};

export type InventoryLocation = {
  sourcePath: string;
  sourceKind: string;
  sourceSha256: string;
  discoveredAt: string;
};

export type InventoryLocationsResult = {
  locations: InventoryLocation[];
  total: number;
  limit: number;
};
