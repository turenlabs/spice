package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
)

type ScanIndex struct {
	db *sql.DB
}

type FileIndex = ScanIndex

type ClearLocalDataProgress struct {
	Phase   string `json:"phase"`
	Status  string `json:"status"`
	Percent int    `json:"percent"`
	Done    bool   `json:"done"`
}

type CachedFileScan struct {
	Findings     []Finding
	SHA256       string
	PackageCount int
	Indexed      bool
}

type indexedFile struct {
	Path          string
	Size          int64
	MTimeUnixNano int64
	SHA256        string
	EngineVersion string
	PackageCount  int
	LastScannedAt time.Time
}

const scanEngineVersion = "2026-06-26-leo-rstreams-hades"
const inventoryFTSVersion = "2026-05-16-inventory-fts-v1"

const createPackageInventoryFTS = `CREATE VIRTUAL TABLE IF NOT EXISTS package_inventory_fts USING fts5(
			ecosystem,
			name,
			version,
			source_kind,
			source_path,
			source_sha256,
			content='package_inventory',
			content_rowid='id'
		)`

var packageInventoryTriggers = []string{
	`CREATE TRIGGER IF NOT EXISTS package_inventory_ai AFTER INSERT ON package_inventory BEGIN
			INSERT INTO package_inventory_fts(rowid, ecosystem, name, version, source_kind, source_path, source_sha256)
			VALUES (new.id, new.ecosystem, new.name, new.version, new.source_kind, new.source_path, new.source_sha256);
		END`,
	`CREATE TRIGGER IF NOT EXISTS package_inventory_ad AFTER DELETE ON package_inventory BEGIN
			INSERT INTO package_inventory_fts(package_inventory_fts, rowid, ecosystem, name, version, source_kind, source_path, source_sha256)
			VALUES ('delete', old.id, old.ecosystem, old.name, old.version, old.source_kind, old.source_path, old.source_sha256);
		END`,
	`CREATE TRIGGER IF NOT EXISTS package_inventory_au AFTER UPDATE ON package_inventory BEGIN
			INSERT INTO package_inventory_fts(package_inventory_fts, rowid, ecosystem, name, version, source_kind, source_path, source_sha256)
			VALUES ('delete', old.id, old.ecosystem, old.name, old.version, old.source_kind, old.source_path, old.source_sha256);
			INSERT INTO package_inventory_fts(rowid, ecosystem, name, version, source_kind, source_path, source_sha256)
			VALUES (new.id, new.ecosystem, new.name, new.version, new.source_kind, new.source_path, new.source_sha256);
		END`,
}

func OpenScanIndex(dbPath string) (*ScanIndex, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	idx := &ScanIndex{db: db}
	if err := idx.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return idx, nil
}

func OpenFileIndex() (*FileIndex, error) {
	path, err := DefaultScanIndexPath()
	if err != nil {
		return nil, err
	}
	return OpenScanIndex(path)
}

func DefaultScanIndexPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Spice", "scan-index.sqlite"), nil
}

func (idx *ScanIndex) Close() error {
	if idx == nil || idx.db == nil {
		return nil
	}
	return idx.db.Close()
}

func (idx *ScanIndex) migrate(ctx context.Context) error {
	stmts := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA temp_store = MEMORY`,
		`PRAGMA cache_size = -20000`,
		`CREATE TABLE IF NOT EXISTS file_index (
			path TEXT PRIMARY KEY,
			size INTEGER NOT NULL,
			mtime_unix_nano INTEGER NOT NULL,
			sha256 TEXT NOT NULL,
			engine_version TEXT NOT NULL DEFAULT '',
			package_count INTEGER NOT NULL DEFAULT -1,
			last_scanned_at TEXT NOT NULL
		)`,
		`ALTER TABLE file_index ADD COLUMN engine_version TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE file_index ADD COLUMN package_count INTEGER NOT NULL DEFAULT -1`,
		`CREATE TABLE IF NOT EXISTS file_findings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_path TEXT NOT NULL,
			detection_id TEXT NOT NULL,
			campaign TEXT NOT NULL,
			severity TEXT NOT NULL,
			kind TEXT NOT NULL,
			path TEXT NOT NULL,
			evidence TEXT NOT NULL,
			remediation TEXT NOT NULL,
			FOREIGN KEY(file_path) REFERENCES file_index(path) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_file_findings_file_path ON file_findings(file_path)`,
		`CREATE TABLE IF NOT EXISTS package_inventory (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ecosystem TEXT NOT NULL,
			name TEXT NOT NULL,
			version TEXT NOT NULL,
			source_path TEXT NOT NULL,
			source_kind TEXT NOT NULL,
			source_sha256 TEXT NOT NULL DEFAULT '',
			discovered_at TEXT NOT NULL,
			UNIQUE(ecosystem, name, version, source_path, source_kind)
		)`,
		`ALTER TABLE package_inventory ADD COLUMN source_sha256 TEXT NOT NULL DEFAULT ''`,
		`UPDATE package_inventory
			SET source_sha256 = COALESCE((SELECT sha256 FROM file_index WHERE file_index.path = package_inventory.source_path), '')
			WHERE source_sha256 = ''`,
		`CREATE INDEX IF NOT EXISTS idx_package_inventory_name ON package_inventory(ecosystem, name)`,
		`CREATE INDEX IF NOT EXISTS idx_package_inventory_source_path ON package_inventory(source_path)`,
		`CREATE INDEX IF NOT EXISTS idx_package_inventory_source_hash ON package_inventory(source_sha256)`,
		`CREATE INDEX IF NOT EXISTS idx_package_inventory_dedup ON package_inventory(ecosystem, name, version, source_kind, source_sha256, source_path)`,
		`CREATE INDEX IF NOT EXISTS idx_package_inventory_filter ON package_inventory(ecosystem, source_kind, name, version)`,
		createPackageInventoryFTS,
		`CREATE TABLE IF NOT EXISTS scan_runs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			roots_json TEXT NOT NULL,
			findings_json TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'completed'
		)`,
		`ALTER TABLE scan_runs ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'`,
		`CREATE TABLE IF NOT EXISTS app_settings (
			key TEXT PRIMARY KEY,
			value_json TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
	}
	stmts = append(stmts, packageInventoryTriggers...)
	for _, stmt := range stmts {
		if _, err := idx.db.ExecContext(ctx, stmt); err != nil {
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return err
		}
	}
	if err := idx.rebuildInventoryFTSIfNeeded(ctx); err != nil {
		return err
	}
	return nil
}

func (idx *ScanIndex) rebuildInventoryFTSIfNeeded(ctx context.Context) error {
	var version string
	err := idx.db.QueryRowContext(ctx, `SELECT value_json FROM app_settings WHERE key = ?`, "inventory_fts_version").Scan(&version)
	if err == nil && version == inventoryFTSVersion {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var inventoryRows int
	if err := idx.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_inventory`).Scan(&inventoryRows); err != nil {
		return err
	}
	if inventoryRows > 0 {
		if _, err := idx.db.ExecContext(ctx, `INSERT INTO package_inventory_fts(package_inventory_fts) VALUES('rebuild')`); err != nil {
			return err
		}
	}
	_, err = idx.db.ExecContext(ctx, `INSERT INTO app_settings (key, value_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
		"inventory_fts_version", inventoryFTSVersion, time.Now().Format(time.RFC3339Nano))
	return err
}

func (idx *ScanIndex) LoadSettings() (AppSettings, error) {
	if idx == nil || idx.db == nil {
		return AppSettings{}, nil
	}
	var raw string
	err := idx.db.QueryRowContext(context.Background(), `SELECT value_json FROM app_settings WHERE key = ?`, "settings").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return AppSettings{}, nil
	}
	if err != nil {
		return AppSettings{}, err
	}
	var settings AppSettings
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		return AppSettings{}, err
	}
	settings.ExcludedDirs = normalizePathList(settings.ExcludedDirs, false)
	return settings, nil
}

func (idx *ScanIndex) SaveSettings(settings AppSettings) error {
	if idx == nil || idx.db == nil {
		return nil
	}
	settings.ExcludedDirs = normalizePathList(settings.ExcludedDirs, false)
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	_, err = idx.db.ExecContext(context.Background(), `INSERT INTO app_settings (key, value_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET
			value_json = excluded.value_json,
			updated_at = excluded.updated_at`,
		"settings", string(data), time.Now().Format(time.RFC3339Nano))
	return err
}

func (idx *ScanIndex) SaveScanRun(result ScanResult) error {
	if idx == nil || idx.db == nil {
		return nil
	}
	rootsJSON, err := json.Marshal(result.Roots)
	if err != nil {
		return err
	}
	findingsJSON, err := json.Marshal(result.Findings)
	if err != nil {
		return err
	}
	status := strings.TrimSpace(result.Status)
	if status == "" {
		status = "completed"
	}
	_, err = idx.db.ExecContext(context.Background(), `INSERT INTO scan_runs (started_at, finished_at, roots_json, findings_json, status)
		VALUES (?, ?, ?, ?, ?)`, result.StartedAt, result.FinishedAt, string(rootsJSON), string(findingsJSON), status)
	return err
}

func (idx *ScanIndex) ClearLocalData() error {
	return idx.ClearLocalDataWithProgress(nil)
}

func (idx *ScanIndex) ClearLocalDataWithProgress(progress func(ClearLocalDataProgress)) error {
	if idx == nil || idx.db == nil {
		return nil
	}
	emit := func(phase, status string, percent int, done bool) {
		if progress != nil {
			progress(ClearLocalDataProgress{Phase: phase, Status: status, Percent: percent, Done: done})
		}
	}
	ctx := context.Background()
	emit("preparing", "Preparing local database", 5, false)
	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	emit("dropping", "Removing scan cache tables", 20, false)
	for _, stmt := range []string{
		`DROP TRIGGER IF EXISTS package_inventory_ai`,
		`DROP TRIGGER IF EXISTS package_inventory_ad`,
		`DROP TRIGGER IF EXISTS package_inventory_au`,
	} {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	emit("dropping", "Dropping file index and inventory", 45, false)
	for _, stmt := range []string{
		`DROP TABLE IF EXISTS package_inventory_fts`,
		`DROP TABLE IF EXISTS file_findings`,
		`DROP TABLE IF EXISTS file_index`,
		`DROP TABLE IF EXISTS package_inventory`,
		`DROP TABLE IF EXISTS scan_runs`,
		`DROP TABLE IF EXISTS temp_aff`,
	} {
		if _, err = tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	emit("schema", "Rebuilding empty local tables", 65, false)
	if _, err = tx.ExecContext(ctx, `INSERT INTO app_settings (key, value_json, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at`,
		"inventory_fts_version", inventoryFTSVersion, time.Now().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	emit("schema", "Recreating indexes", 75, false)
	if err = idx.migrate(ctx); err != nil {
		return err
	}
	emit("compact", "Compacting local database", 90, false)
	_, _ = idx.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	_, _ = idx.db.ExecContext(ctx, `VACUUM`)
	emit("done", "Local data cleared", 100, true)
	return nil
}

func (idx *ScanIndex) LastScanRun() (ScanResult, bool, error) {
	if idx == nil || idx.db == nil {
		return ScanResult{}, false, nil
	}
	var result ScanResult
	var rootsJSON string
	var findingsJSON string
	err := idx.db.QueryRowContext(context.Background(), `SELECT started_at, finished_at, roots_json, findings_json, status
		FROM scan_runs ORDER BY id DESC LIMIT 1`).Scan(&result.StartedAt, &result.FinishedAt, &rootsJSON, &findingsJSON, &result.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return ScanResult{}, false, nil
	}
	if err != nil {
		return ScanResult{}, false, err
	}
	if err := json.Unmarshal([]byte(rootsJSON), &result.Roots); err != nil {
		return ScanResult{}, false, err
	}
	if err := json.Unmarshal([]byte(findingsJSON), &result.Findings); err != nil {
		return ScanResult{}, false, err
	}
	result.Indexed = true
	if result.Status == "" {
		result.Status = "completed"
	}
	return result, true, nil
}

func (idx *ScanIndex) ReplacePackagesForSource(sourcePath string, packages []PackageRef) error {
	if idx == nil || idx.db == nil {
		return nil
	}
	ctx := context.Background()
	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = replacePackagesTx(ctx, tx, sourcePath, "", packages, time.Now().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

type PackageRef struct {
	Ecosystem    string `json:"ecosystem"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	SourcePath   string `json:"sourcePath"`
	SourceKind   string `json:"sourceKind"`
	SourceID     string `json:"sourceId,omitempty"`
	SourceCount  int    `json:"sourceCount,omitempty"`
	DiscoveredAt string `json:"discoveredAt,omitempty"`
}

type InventoryBin struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

func (idx *ScanIndex) ListPackageInventory(req InventoryRequest) (InventoryResult, error) {
	if idx == nil || idx.db == nil {
		return InventoryResult{}, nil
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}
	where, args := inventoryWhere(req)
	var total int
	if err := idx.db.QueryRowContext(context.Background(), dedupInventoryCountSQL(where), args...).Scan(&total); err != nil {
		return InventoryResult{}, err
	}
	if total == 0 {
		offset = 0
	} else if maxOffset := ((total - 1) / limit) * limit; offset > maxOffset {
		offset = maxOffset
	}
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := idx.db.QueryContext(context.Background(), `SELECT
			ecosystem,
			name,
			version,
			MIN(source_path) AS source_path,
			source_kind,
			CASE WHEN source_sha256 = '' THEN source_path ELSE source_sha256 END AS source_id,
			COUNT(*) AS source_count,
			MAX(discovered_at) AS discovered_at
		FROM package_inventory`+where+`
		GROUP BY ecosystem, name, version, source_kind, source_id
		ORDER BY ecosystem, name, version, source_path
		LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		return InventoryResult{}, err
	}
	defer rows.Close()

	var packages []PackageRef
	for rows.Next() {
		var pkg PackageRef
		if err := rows.Scan(&pkg.Ecosystem, &pkg.Name, &pkg.Version, &pkg.SourcePath, &pkg.SourceKind, &pkg.SourceID, &pkg.SourceCount, &pkg.DiscoveredAt); err != nil {
			return InventoryResult{}, err
		}
		packages = append(packages, pkg)
	}
	if err := rows.Err(); err != nil {
		return InventoryResult{}, err
	}
	var ecosystemCounts []InventoryBin
	var sourceKindCounts []InventoryBin
	if !req.SkipFacets {
		ecosystemCounts, err = idx.inventoryBins("ecosystem")
		if err != nil {
			return InventoryResult{}, err
		}
		sourceKindCounts, err = idx.inventoryBins("source_kind")
		if err != nil {
			return InventoryResult{}, err
		}
	}
	return InventoryResult{
		Packages:         packages,
		Total:            total,
		Limit:            limit,
		Offset:           offset,
		EcosystemCounts:  ecosystemCounts,
		SourceKindCounts: sourceKindCounts,
	}, nil
}

func (idx *ScanIndex) ListPackageLocations(req InventoryLocationsRequest) (InventoryLocationsResult, error) {
	if idx == nil || idx.db == nil {
		return InventoryLocationsResult{}, nil
	}
	limit := req.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	sourceID := strings.TrimSpace(req.SourceID)
	if sourceID == "" {
		sourceID = strings.TrimSpace(req.SourcePath)
	}
	where := `ecosystem = ? AND name = ? AND version = ? AND source_kind = ? AND CASE WHEN source_sha256 = '' THEN source_path ELSE source_sha256 END = ?`
	args := []any{req.Ecosystem, req.Name, req.Version, req.SourceKind, sourceID}
	var total int
	if err := idx.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM package_inventory WHERE `+where, args...).Scan(&total); err != nil {
		return InventoryLocationsResult{}, err
	}
	rows, err := idx.db.QueryContext(context.Background(), `SELECT source_path, source_kind, source_sha256, discovered_at
		FROM package_inventory
		WHERE `+where+`
		ORDER BY source_path
		LIMIT ?`, append(args, limit)...)
	if err != nil {
		return InventoryLocationsResult{}, err
	}
	defer rows.Close()
	var locations []InventoryLocation
	for rows.Next() {
		var location InventoryLocation
		if err := rows.Scan(&location.SourcePath, &location.SourceKind, &location.SourceSHA256, &location.DiscoveredAt); err != nil {
			return InventoryLocationsResult{}, err
		}
		locations = append(locations, location)
	}
	if err := rows.Err(); err != nil {
		return InventoryLocationsResult{}, err
	}
	return InventoryLocationsResult{Locations: locations, Total: total, Limit: limit}, nil
}

func inventoryWhere(req InventoryRequest) (string, []any) {
	var clauses []string
	var args []any
	if req.Ecosystem != "" && req.Ecosystem != "all" {
		clauses = append(clauses, "ecosystem = ?")
		args = append(args, req.Ecosystem)
	}
	if req.SourceKind != "" && req.SourceKind != "all" {
		clauses = append(clauses, "source_kind = ?")
		args = append(args, req.SourceKind)
	}
	query := parseInventoryQuery(req.Query)
	for _, filter := range query.Filters {
		switch filter.Field {
		case "ecosystem":
			clauses = append(clauses, "ecosystem = ? COLLATE NOCASE")
			args = append(args, filter.Value)
		case "name":
			clauses = append(clauses, `name LIKE ? ESCAPE '\' COLLATE NOCASE`)
			args = append(args, inventoryLike(filter.Value))
		case "version":
			clauses = append(clauses, `version LIKE ? ESCAPE '\' COLLATE NOCASE`)
			args = append(args, inventoryLike(filter.Value))
		case "source_kind":
			clauses = append(clauses, `source_kind LIKE ? ESCAPE '\' COLLATE NOCASE`)
			args = append(args, inventoryLike(filter.Value))
		case "source_path":
			if match := inventoryPathFTSQuery(filter.Value); match != "" {
				clauses = append(clauses, `id IN (SELECT rowid FROM package_inventory_fts WHERE package_inventory_fts MATCH ?)`)
				args = append(args, match)
			} else {
				clauses = append(clauses, `source_path LIKE ? ESCAPE '\' COLLATE NOCASE`)
				args = append(args, inventoryLike(filter.Value))
			}
		case "source_sha256":
			clauses = append(clauses, `source_sha256 LIKE ? ESCAPE '\' COLLATE NOCASE`)
			args = append(args, inventoryLike(filter.Value))
		}
	}
	if len(query.Terms) > 0 {
		match := inventoryFTSQuery(query.Terms)
		if match != "" {
			clauses = append(clauses, `id IN (SELECT rowid FROM package_inventory_fts WHERE package_inventory_fts MATCH ?)`)
			args = append(args, match)
		}
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

type inventoryQuery struct {
	Terms   []string
	Filters []inventoryQueryFilter
}

type inventoryQueryFilter struct {
	Field string
	Value string
}

func parseInventoryQuery(raw string) inventoryQuery {
	tokens := splitInventoryQuery(raw)
	out := inventoryQuery{}
	for _, token := range tokens {
		key, value, ok := strings.Cut(token, ":")
		if !ok || strings.TrimSpace(value) == "" {
			out.Terms = append(out.Terms, token)
			continue
		}
		field, ok := inventoryQueryField(key)
		if !ok {
			out.Terms = append(out.Terms, token)
			continue
		}
		out.Filters = append(out.Filters, inventoryQueryFilter{Field: field, Value: strings.TrimSpace(value)})
	}
	return out
}

func splitInventoryQuery(raw string) []string {
	var tokens []string
	var current strings.Builder
	var quote rune
	escaped := false
	for _, r := range raw {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if token := strings.TrimSpace(current.String()); token != "" {
				tokens = append(tokens, token)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if token := strings.TrimSpace(current.String()); token != "" {
		tokens = append(tokens, token)
	}
	return tokens
}

func inventoryQueryField(key string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "ecosystem", "eco":
		return "ecosystem", true
	case "name", "pkg", "package":
		return "name", true
	case "version", "ver":
		return "version", true
	case "source", "kind", "type":
		return "source_kind", true
	case "path", "file", "location":
		return "source_path", true
	case "hash", "digest", "sha", "sha256":
		return "source_sha256", true
	default:
		return "", false
	}
}

func inventoryLike(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `%`, `\%`)
	value = strings.ReplaceAll(value, `_`, `\_`)
	return "%" + value + "%"
}

func inventoryFTSQuery(terms []string) string {
	parts := make([]string, 0, len(terms))
	for _, term := range terms {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		for _, piece := range strings.FieldsFunc(term, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			piece = strings.TrimSpace(piece)
			if piece == "" {
				continue
			}
			parts = append(parts, quoteFTSTerm(piece)+"*")
		}
	}
	return strings.Join(parts, " AND ")
}

func inventoryPathFTSQuery(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	pieces := make([]string, 0, 2)
	for _, piece := range strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		piece = strings.TrimSpace(piece)
		if len([]rune(piece)) < 3 {
			return ""
		}
		pieces = append(pieces, quoteFTSTerm(piece)+"*")
	}
	if len(pieces) == 0 {
		return ""
	}
	return "source_path : (" + strings.Join(pieces, " AND ") + ")"
}

func quoteFTSTerm(term string) string {
	return `"` + strings.ReplaceAll(term, `"`, `""`) + `"`
}

func dedupInventoryCountSQL(where string) string {
	return `SELECT COUNT(*) FROM (
		SELECT 1
		FROM package_inventory` + where + `
		GROUP BY ecosystem, name, version, source_kind, CASE WHEN source_sha256 = '' THEN source_path ELSE source_sha256 END
	)`
}

func (idx *ScanIndex) inventoryBins(column string) ([]InventoryBin, error) {
	var query string
	switch column {
	case "ecosystem":
		query = `SELECT ecosystem, COUNT(*) FROM (
			SELECT ecosystem, source_kind
			FROM package_inventory
			GROUP BY ecosystem, name, version, source_kind, CASE WHEN source_sha256 = '' THEN source_path ELSE source_sha256 END
		) GROUP BY ecosystem ORDER BY ecosystem`
	case "source_kind":
		query = `SELECT source_kind, COUNT(*) FROM (
			SELECT ecosystem, source_kind
			FROM package_inventory
			GROUP BY ecosystem, name, version, source_kind, CASE WHEN source_sha256 = '' THEN source_path ELSE source_sha256 END
		) GROUP BY source_kind ORDER BY source_kind`
	default:
		return nil, fmt.Errorf("invalid inventory count column: %s", column)
	}
	rows, err := idx.db.QueryContext(context.Background(), query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bins []InventoryBin
	for rows.Next() {
		var bin InventoryBin
		if err := rows.Scan(&bin.Value, &bin.Count); err != nil {
			return nil, err
		}
		bins = append(bins, bin)
	}
	return bins, rows.Err()
}

func ExtractPackages(path string) []PackageRef {
	return ExtractPackagesFromBytes(path, nil)
}

func ExtractPackagesFromBytes(path string, data []byte) []PackageRef {
	base := filepath.Base(path)
	switch {
	case base == "package.json":
		return extractPackageJSONPackages(path, data)
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		return extractPackageLockPackages(path, data)
	case base == "pnpm-lock.yaml":
		return extractPnpmLockPackages(path, data)
	case base == "yarn.lock":
		return extractYarnLockPackages(path, data)
	case base == "composer.lock":
		return extractComposerLockPackages(path, data)
	case base == "composer.json":
		return extractComposerJSONPackages(path, data)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return extractRequirementsPackages(path, data)
	case base == "METADATA":
		return extractPythonMetadataPackage(path, data)
	case base == "go.mod":
		return extractGoModPackages(path, data)
	case base == "Cargo.toml":
		return extractCargoTomlPackages(path, data)
	case base == "Cargo.lock":
		return extractCargoLockPackages(path, data)
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		return extractDockerfilePackages(path, data)
	default:
		return nil
	}
}

func extractPackageLockPackages(path string, dataBytes []byte) []PackageRef {
	var data map[string]any
	if dataBytes != nil {
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return nil
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		if err := json.NewDecoder(file).Decode(&data); err != nil {
			return nil
		}
	}
	var packages []PackageRef
	if deps, ok := data["dependencies"].(map[string]any); ok {
		for name, raw := range deps {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			version := strings.TrimSpace(fmt.Sprint(item["version"]))
			packages = append(packages, PackageRef{Ecosystem: "npm", Name: name, Version: version, SourcePath: path, SourceKind: "package-lock"})
		}
	}
	if lockPackages, ok := data["packages"].(map[string]any); ok {
		for key, raw := range lockPackages {
			if key == "" {
				continue
			}
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := packageNameFromLockPath(key)
			if name == "" {
				continue
			}
			version := strings.TrimSpace(fmt.Sprint(item["version"]))
			packages = append(packages, PackageRef{Ecosystem: "npm", Name: name, Version: version, SourcePath: path, SourceKind: "package-lock"})
		}
	}
	return packages
}

func extractPnpmLockPackages(path string, data []byte) []PackageRef {
	return extractRegexPackages(path, data, "npm", "pnpm-lock", regexp.MustCompile(`^\s*/((?:@[^/\s]+/)?[^/@\s]+)@([^:\s]+):\s*$`))
}

func extractYarnLockPackages(path string, data []byte) []PackageRef {
	return extractRegexPackages(path, data, "npm", "yarn-lock", regexp.MustCompile(`^"?((?:@[^/\s]+/)?[^@\s",]+)@[^",]*"?\s*:\s*$`))
}

func extractComposerLockPackages(path string, dataBytes []byte) []PackageRef {
	var data map[string]any
	if dataBytes != nil {
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return nil
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		if err := json.NewDecoder(file).Decode(&data); err != nil {
			return nil
		}
	}
	var packages []PackageRef
	for _, section := range []string{"packages", "packages-dev"} {
		items, ok := data[section].([]any)
		if !ok {
			continue
		}
		for _, raw := range items {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			name := strings.TrimSpace(fmt.Sprint(item["name"]))
			version := normalizeVersion(fmt.Sprint(item["version"]))
			if name == "" || version == "" || name == "<nil>" || version == "<nil>" {
				continue
			}
			packages = append(packages, PackageRef{Ecosystem: "composer", Name: name, Version: version, SourcePath: path, SourceKind: "composer-lock"})
		}
	}
	return packages
}

func extractComposerJSONPackages(path string, dataBytes []byte) []PackageRef {
	var data map[string]any
	if dataBytes != nil {
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return nil
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		if err := json.NewDecoder(file).Decode(&data); err != nil {
			return nil
		}
	}
	var packages []PackageRef
	for _, section := range []string{"require", "require-dev"} {
		deps, ok := data[section].(map[string]any)
		if !ok {
			continue
		}
		for name, rawVersion := range deps {
			version := normalizeVersion(fmt.Sprint(rawVersion))
			if name == "" || version == "" || strings.HasPrefix(name, "php") {
				continue
			}
			packages = append(packages, PackageRef{Ecosystem: "composer", Name: name, Version: version, SourcePath: path, SourceKind: section})
		}
	}
	return packages
}

func extractPythonMetadataPackage(path string, data []byte) []PackageRef {
	content := data
	if content == nil {
		var err error
		content, err = os.ReadFile(path)
		if err != nil {
			return nil
		}
	}
	var name string
	var version string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "name:"):
			name = normalizePythonName(strings.TrimSpace(line[len("name:"):]))
		case strings.HasPrefix(lower, "version:"):
			version = strings.TrimSpace(line[len("version:"):])
		}
		if name != "" && version != "" {
			return []PackageRef{{Ecosystem: "pypi", Name: name, Version: version, SourcePath: path, SourceKind: "dist-info"}}
		}
	}
	return nil
}

func extractGoModPackages(path string, data []byte) []PackageRef {
	return extractRegexPackages(path, data, "go", "go.mod", regexp.MustCompile(`^\s*([A-Za-z0-9_.~!$&'()*+,;=:@%/-]+\.[A-Za-z0-9_.~!$&'()*+,;=:@%/-]+)\s+(v[^\s]+)`))
}

func extractCargoTomlPackages(path string, data []byte) []PackageRef {
	return extractRegexPackages(path, data, "cargo", "Cargo.toml", regexp.MustCompile(`^\s*([A-Za-z0-9_.-]+)\s*=\s*"?([^"\s{]+)"?`))
}

func extractCargoLockPackages(path string, data []byte) []PackageRef {
	content := data
	if content == nil {
		var err error
		content, err = os.ReadFile(path)
		if err != nil {
			return nil
		}
	}
	var packages []PackageRef
	var name string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "[[package]]" {
			name = ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "name = ")), `"`)
			continue
		}
		if strings.HasPrefix(line, "version = ") && name != "" {
			version := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version = ")), `"`)
			packages = append(packages, PackageRef{Ecosystem: "cargo", Name: name, Version: version, SourcePath: path, SourceKind: "Cargo.lock"})
			name = ""
		}
	}
	return packages
}

func extractRegexPackages(path string, data []byte, ecosystem string, sourceKind string, pattern *regexp.Regexp) []PackageRef {
	var scanner *bufio.Scanner
	if data != nil {
		scanner = bufio.NewScanner(bytes.NewReader(data))
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}
	var packages []PackageRef
	for scanner.Scan() {
		match := pattern.FindStringSubmatch(scanner.Text())
		if len(match) < 3 {
			continue
		}
		name := strings.TrimSpace(match[1])
		version := strings.Trim(strings.TrimSpace(match[2]), `"`)
		if name == "" || version == "" || strings.HasPrefix(name, "#") {
			continue
		}
		packages = append(packages, PackageRef{Ecosystem: ecosystem, Name: name, Version: version, SourcePath: path, SourceKind: sourceKind})
	}
	return packages
}

func packageNameFromLockPath(path string) string {
	path = strings.TrimPrefix(path, "node_modules/")
	parts := strings.Split(path, "/node_modules/")
	return parts[len(parts)-1]
}

func extractPackageJSONPackages(path string, dataBytes []byte) []PackageRef {
	var data map[string]any
	if dataBytes != nil {
		if err := json.Unmarshal(dataBytes, &data); err != nil {
			return nil
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		if err := json.NewDecoder(file).Decode(&data); err != nil {
			return nil
		}
	}
	var packages []PackageRef
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		deps, ok := data[section].(map[string]any)
		if !ok {
			continue
		}
		for name, rawVersion := range deps {
			packages = append(packages, PackageRef{
				Ecosystem:  "npm",
				Name:       name,
				Version:    strings.TrimSpace(strings.Trim(fmt.Sprint(rawVersion), `"`)),
				SourcePath: path,
				SourceKind: section,
			})
		}
	}
	return packages
}

func extractRequirementsPackages(path string, data []byte) []PackageRef {
	var scanner *bufio.Scanner
	if data != nil {
		scanner = bufio.NewScanner(bytes.NewReader(data))
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}
	var packages []PackageRef
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.SplitN(line, "#", 2)[0]
		line = strings.SplitN(line, ";", 2)[0]
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		packages = append(packages, PackageRef{
			Ecosystem:  "pypi",
			Name:       normalizePythonName(strings.TrimSpace(parts[0])),
			Version:    strings.TrimSpace(parts[1]),
			SourcePath: path,
			SourceKind: "requirements",
		})
	}
	return packages
}

func extractDockerfilePackages(path string, data []byte) []PackageRef {
	var scanner *bufio.Scanner
	if data != nil {
		scanner = bufio.NewScanner(bytes.NewReader(data))
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}
	var packages []PackageRef
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToUpper(fields[0]) != "FROM" {
			continue
		}
		image := fields[1]
		version := "latest"
		name := image
		if idx := strings.LastIndex(image, ":"); idx > strings.LastIndex(image, "/") {
			name = image[:idx]
			version = image[idx+1:]
		}
		packages = append(packages, PackageRef{
			Ecosystem:  "docker",
			Name:       name,
			Version:    version,
			SourcePath: path,
			SourceKind: "Dockerfile",
		})
	}
	return packages
}

func (idx *ScanIndex) unchanged(ctx context.Context, path string, size int64, mtimeUnixNano int64, engineVersion string) (bool, error) {
	_, unchanged, err := idx.cachedSHA256(ctx, path, size, mtimeUnixNano, engineVersion)
	return unchanged, err
}

func (idx *ScanIndex) cachedSHA256(ctx context.Context, path string, size int64, mtimeUnixNano int64, engineVersion string) (string, bool, error) {
	if idx == nil || idx.db == nil {
		return "", false, nil
	}
	var sha256 string
	err := idx.db.QueryRowContext(ctx, `SELECT sha256 FROM file_index WHERE path = ? AND size = ? AND mtime_unix_nano = ? AND engine_version = ?`, path, size, mtimeUnixNano, engineVersion).Scan(&sha256)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return sha256, sha256 != "", nil
}

func (idx *ScanIndex) findingsForPath(ctx context.Context, path string) ([]Finding, error) {
	if idx == nil || idx.db == nil {
		return nil, nil
	}
	rows, err := idx.db.QueryContext(ctx, `SELECT detection_id, campaign, severity, kind, path, evidence, remediation FROM file_findings WHERE file_path = ? ORDER BY id`, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var finding Finding
		if err := rows.Scan(&finding.DetectionID, &finding.Campaign, &finding.Severity, &finding.Kind, &finding.Path, &finding.Evidence, &finding.Remediation); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (idx *ScanIndex) packageCacheCountForPath(ctx context.Context, path string) (int, error) {
	if idx == nil || idx.db == nil {
		return 0, nil
	}
	var expected int
	var actual int
	if err := idx.db.QueryRowContext(ctx, `SELECT fi.package_count, COUNT(pi.id)
		FROM file_index fi
		LEFT JOIN package_inventory pi ON pi.source_path = fi.path
		WHERE fi.path = ?
		GROUP BY fi.path, fi.package_count`, path).Scan(&expected, &actual); err != nil {
		return 0, err
	}
	if expected < 0 || actual < expected {
		return -1, nil
	}
	return actual, nil
}

func (idx *ScanIndex) updateFile(ctx context.Context, file indexedFile, findings []Finding) error {
	if idx == nil || idx.db == nil {
		return nil
	}
	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if err = replaceFileScanTx(ctx, tx, file, findings); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceFileScanTx(ctx context.Context, tx *sql.Tx, file indexedFile, findings []Finding) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO file_index (path, size, mtime_unix_nano, sha256, engine_version, package_count, last_scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			size = excluded.size,
			mtime_unix_nano = excluded.mtime_unix_nano,
			sha256 = excluded.sha256,
			engine_version = excluded.engine_version,
			package_count = excluded.package_count,
			last_scanned_at = excluded.last_scanned_at`,
		file.Path, file.Size, file.MTimeUnixNano, file.SHA256, file.EngineVersion, file.PackageCount, file.LastScannedAt.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM file_findings WHERE file_path = ?`, file.Path); err != nil {
		return err
	}
	for _, finding := range findings {
		_, err = tx.ExecContext(ctx, `INSERT INTO file_findings (file_path, detection_id, campaign, severity, kind, path, evidence, remediation)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			file.Path, finding.DetectionID, finding.Campaign, finding.Severity, finding.Kind, finding.Path, finding.Evidence, finding.Remediation)
		if err != nil {
			return err
		}
	}
	return nil
}

func replacePackagesTx(ctx context.Context, tx *sql.Tx, sourcePath string, sourceSHA256 string, packages []PackageRef, discoveredAt string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM package_inventory WHERE source_path = ?`, sourcePath); err != nil {
		return err
	}
	for _, pkg := range packages {
		if pkg.Name == "" {
			continue
		}
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO package_inventory (ecosystem, name, version, source_path, source_kind, source_sha256, discovered_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			pkg.Ecosystem, pkg.Name, pkg.Version, sourcePath, pkg.SourceKind, sourceSHA256, discoveredAt)
		if err != nil {
			return err
		}
	}
	return nil
}

func (idx *ScanIndex) UpsertBatch(writes []indexWrite, engineVersion string) error {
	return idx.UpsertBatchContext(context.Background(), writes, engineVersion)
}

func (idx *ScanIndex) UpsertBatchContext(ctx context.Context, writes []indexWrite, engineVersion string) error {
	if idx == nil || idx.db == nil || len(writes) == 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().Format(time.RFC3339Nano)
	fileIndexStmt, err := tx.PrepareContext(ctx, `INSERT INTO file_index (path, size, mtime_unix_nano, sha256, engine_version, package_count, last_scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			size = excluded.size,
			mtime_unix_nano = excluded.mtime_unix_nano,
			sha256 = excluded.sha256,
			engine_version = excluded.engine_version,
			package_count = excluded.package_count,
			last_scanned_at = excluded.last_scanned_at`)
	if err != nil {
		return err
	}
	defer fileIndexStmt.Close()
	deleteFindingsStmt, err := tx.PrepareContext(ctx, `DELETE FROM file_findings WHERE file_path = ?`)
	if err != nil {
		return err
	}
	defer deleteFindingsStmt.Close()
	insertFindingStmt, err := tx.PrepareContext(ctx, `INSERT INTO file_findings (file_path, detection_id, campaign, severity, kind, path, evidence, remediation)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insertFindingStmt.Close()
	deletePackagesStmt, err := tx.PrepareContext(ctx, `DELETE FROM package_inventory WHERE source_path = ?`)
	if err != nil {
		return err
	}
	defer deletePackagesStmt.Close()
	insertPackageStmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO package_inventory (ecosystem, name, version, source_path, source_kind, source_sha256, discovered_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer insertPackageStmt.Close()
	for _, write := range writes {
		if err = ctx.Err(); err != nil {
			return err
		}
		if _, err = fileIndexStmt.ExecContext(ctx,
			write.entry.path,
			write.entry.size,
			write.entry.mtimeUnixNano,
			write.digest,
			engineVersion,
			packageCount(write.packages),
			now,
		); err != nil {
			return err
		}
		if _, err = deleteFindingsStmt.ExecContext(ctx, write.entry.path); err != nil {
			return err
		}
		for _, finding := range write.findings {
			if err = ctx.Err(); err != nil {
				return err
			}
			if _, err = insertFindingStmt.ExecContext(ctx,
				write.entry.path,
				finding.DetectionID,
				finding.Campaign,
				finding.Severity,
				finding.Kind,
				finding.Path,
				finding.Evidence,
				finding.Remediation,
			); err != nil {
				return err
			}
		}
		if _, err = deletePackagesStmt.ExecContext(ctx, write.entry.path); err != nil {
			return err
		}
		for _, pkg := range write.packages {
			if err = ctx.Err(); err != nil {
				return err
			}
			if pkg.Name == "" {
				continue
			}
			if _, err = insertPackageStmt.ExecContext(ctx, pkg.Ecosystem, pkg.Name, pkg.Version, write.entry.path, pkg.SourceKind, write.digest, now); err != nil {
				return err
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return tx.Commit()
}

func packageCount(packages []PackageRef) int {
	count := 0
	for _, pkg := range packages {
		if pkg.Name != "" {
			count++
		}
	}
	return count
}

func (idx *ScanIndex) GetUnchanged(path string, size int64, mtimeUnixNano int64, engineVersion string) (CachedFileScan, bool, error) {
	return idx.GetUnchangedContext(context.Background(), path, size, mtimeUnixNano, engineVersion)
}

func (idx *ScanIndex) GetUnchangedContext(ctx context.Context, path string, size int64, mtimeUnixNano int64, engineVersion string) (CachedFileScan, bool, error) {
	if idx == nil {
		return CachedFileScan{}, false, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sha256, unchanged, err := idx.cachedSHA256(ctx, path, size, mtimeUnixNano, engineVersion)
	if err != nil || !unchanged {
		return CachedFileScan{}, false, err
	}
	findings, err := idx.findingsForPath(ctx, path)
	if err != nil {
		return CachedFileScan{}, false, err
	}
	packageCount, err := idx.packageCacheCountForPath(ctx, path)
	if err != nil {
		return CachedFileScan{}, false, err
	}
	return CachedFileScan{Findings: findings, SHA256: sha256, PackageCount: packageCount, Indexed: true}, true, nil
}

func (idx *ScanIndex) LoadCachedScans(entries []scanFileEntry, engineVersion string) (map[string]CachedFileScan, error) {
	return idx.LoadCachedScansContext(context.Background(), entries, engineVersion)
}

func (idx *ScanIndex) LoadCachedScansContext(ctx context.Context, entries []scanFileEntry, engineVersion string) (map[string]CachedFileScan, error) {
	cached := make(map[string]CachedFileScan)
	if idx == nil || idx.db == nil || len(entries) == 0 {
		return cached, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx, `DROP TABLE IF EXISTS temp.scan_candidates`); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TEMP TABLE scan_candidates (
		path TEXT PRIMARY KEY,
		size INTEGER NOT NULL,
		mtime_unix_nano INTEGER NOT NULL
	)`); err != nil {
		return nil, err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO scan_candidates (path, size, mtime_unix_nano) VALUES (?, ?, ?)`)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			_ = stmt.Close()
			return nil, err
		}
		if _, err = stmt.ExecContext(ctx, entry.path, entry.size, entry.mtimeUnixNano); err != nil {
			_ = stmt.Close()
			return nil, err
		}
	}
	if err = stmt.Close(); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT fi.path, fi.sha256, fi.package_count, COUNT(pi.id)
		FROM scan_candidates sc
		CROSS JOIN file_index fi ON fi.path = sc.path
			AND fi.size = sc.size
			AND fi.mtime_unix_nano = sc.mtime_unix_nano
			AND fi.engine_version = ?
		LEFT JOIN package_inventory pi ON pi.source_path = fi.path
		GROUP BY fi.path, fi.sha256, fi.package_count`, engineVersion)
	if err != nil {
		return nil, err
	}
	var paths []string
	for rows.Next() {
		if err = ctx.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		var path string
		var sha256 string
		var expectedPackageCount int
		var actualPackageCount int
		if err = rows.Scan(&path, &sha256, &expectedPackageCount, &actualPackageCount); err != nil {
			_ = rows.Close()
			return nil, err
		}
		packageCount := actualPackageCount
		if expectedPackageCount < 0 || actualPackageCount < expectedPackageCount {
			packageCount = -1
		}
		cached[path] = CachedFileScan{SHA256: sha256, PackageCount: packageCount, Indexed: true}
		paths = append(paths, path)
	}
	if err = ctx.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if len(paths) > 0 {
		rows, err = tx.QueryContext(ctx, `SELECT ff.file_path, ff.detection_id, ff.campaign, ff.severity, ff.kind, ff.path, ff.evidence, ff.remediation
			FROM scan_candidates sc
			CROSS JOIN file_index fi ON fi.path = sc.path
				AND fi.size = sc.size
				AND fi.mtime_unix_nano = sc.mtime_unix_nano
				AND fi.engine_version = ?
			JOIN file_findings ff ON ff.file_path = fi.path
			ORDER BY ff.id`, engineVersion)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			if err = ctx.Err(); err != nil {
				_ = rows.Close()
				return nil, err
			}
			var filePath string
			var finding Finding
			if err = rows.Scan(&filePath, &finding.DetectionID, &finding.Campaign, &finding.Severity, &finding.Kind, &finding.Path, &finding.Evidence, &finding.Remediation); err != nil {
				_ = rows.Close()
				return nil, err
			}
			entry := cached[filePath]
			entry.Findings = append(entry.Findings, finding)
			cached[filePath] = entry
		}
		if err = ctx.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err = rows.Close(); err != nil {
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return cached, nil
}

func (idx *ScanIndex) Upsert(path string, info os.FileInfo, digest string, findings []Finding) error {
	if idx == nil || info == nil {
		return nil
	}
	return idx.updateFile(context.Background(), indexedFile{
		Path:          path,
		Size:          info.Size(),
		MTimeUnixNano: info.ModTime().UnixNano(),
		SHA256:        digest,
		EngineVersion: scanEngineVersion,
		LastScannedAt: time.Now(),
	}, findings)
}

func HashFile(path string) (string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, handle); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func HashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
