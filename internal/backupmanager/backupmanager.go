// Package backupmanager provides functionalities for creating, managing, and restoring
// versioned backups of Helm chart configurations and their associated values.
//
// It is designed to be used before Helm install or upgrade operations to ensure
// that a snapshot of the chart and its specific configuration (values) is preserved.
// This allows for easy rollback or restoration to a previously known good state.
//
// Key Features:
//   - Automated Backup: Creates a backup of a chart directory and its deployment values.
//   - Versioning: Backups are versioned using unique, timestamp-based IDs.
//   - Metadata Storage: Each backup includes a metadata file (metadata.json)
//     containing details like backup ID, timestamp, release name, and chart information
//     extracted from the backed-up Chart.yaml.
//   - Value Preservation: The specific values.yaml used for the deployment is
//     also stored with each backup.
//   - Listing and Retrieval: Provides functions to list available backups for a release
//     and retrieve details (paths, metadata) of a specific backup.
//   - Restoration: Supports restoring a release to a backed-up state. This typically
//     involves uninstalling the current release (if any) and then installing the
//     chart from the backup using its stored values.
//   - Upgrade to Backup: Allows upgrading an existing release to the state defined by
//     a backup, using Helm's upgrade mechanism.
//   - Deletion and Pruning: Offers capabilities to delete specific backups or prune
//     older backups, keeping a specified number of recent ones.
//   - Filesystem Backend: The primary implementation, FileSystemBackupManager, uses the
//     local file system for storing backups. Backups are organized in a structured
//     directory: <baseBackupPath>/<releaseName>/<backupID>/.
//   - Extensible Interface: Defines a Manager interface, allowing for potential
//     future implementations with different storage backends (e.g., cloud storage).
//   - Logging: Supports configurable logging for its operations.
//
// Typical Usage Flow:
//  1. Initialize a Manager (e.g., NewFileSystemBackupManager).
//  2. Before a Helm install/upgrade: Call BackupRelease() to create a snapshot.
//  3. To view available backups: Call ListBackups().
//  4. To restore: Call RestoreRelease() with a specific backupID.
//  5. To upgrade to a backup state: Call UpgradeToBackup().
//  6. To manage storage: Call DeleteBackup() or PruneBackups().
//
// The package relies on helmutils for performing actual Helm operations during
// restore or upgrade-to-backup procedures.
package backupmanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go_k8s_helm/internal/helmutils"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/storage/driver"
)

const (
	backupDirName           = "chart"
	valuesFileName          = "values.yaml"
	metadataFileName        = "metadata.json"
	backupIDTimestampFormat = "20060102-150405.000000"
)

// BackupMetadata stores information about a single backup instance.
// This metadata is saved as metadata.json within each backup directory.
type BackupMetadata struct {
	BackupID     string    `json:"backupId"`
	Timestamp    time.Time `json:"timestamp"`
	ReleaseName  string    `json:"releaseName"`
	ChartName    string    `json:"chartName"`             // From the backed-up Chart.yaml
	ChartVersion string    `json:"chartVersion"`          // From the backed-up Chart.yaml
	AppVersion   string    `json:"appVersion,omitempty"`  // From the backed-up Chart.yaml
	Description  string    `json:"description,omitempty"` // From the backed-up Chart.yaml
}

// ChartYAML represents the structure of a Chart.yaml file for parsing.
// Simplified for backup metadata purposes.
// A more complete version might be needed if more Chart.yaml fields are required.
type ChartYAML struct {
	APIVersion   string `yaml:"apiVersion"`
	Name         string `yaml:"name"`
	Version      string `yaml:"version"`
	AppVersion   string `yaml:"appVersion,omitempty"`
	Description  string `yaml:"description,omitempty"`
	Dependencies []struct {
		Name       string `yaml:"name"`
		Version    string `yaml:"version"`
		Repository string `yaml:"repository"`
		Condition  string `yaml:"condition,omitempty"`
		Alias      string `yaml:"alias,omitempty"`
	} `yaml:"dependencies,omitempty"`
}

// Manager defines the interface for chart backup and restore operations.
// This interface facilitates managing versioned backups of Helm chart configurations
// and provides mechanisms to restore or rollback to specific versions.
type Manager interface {
	// BackupRelease creates a versioned backup of a Helm chart and its associated values
	// before a deployment (install or upgrade). It's intended to be called by higher-level
	// deployment functions.
	//
	// Parameters:
	//   - releaseName: The name of the Helm release for which the backup is being created.
	//   - chartSourcePath: The file system path to the chart directory that is to be backed up.
	//                    This should be the chart in its state ready for deployment (e.g., after any local templating if applicable).
	//   - values: A map of values that will be used for the deployment. These values are saved alongside the chart.
	//
	// Returns:
	//   - backupID: A unique identifier for this backup instance (typically timestamp-based).
	//   - error: An error if the backup operation fails.
	BackupRelease(releaseName string, chartSourcePath string, values map[string]interface{}) (string, error)

	// ListBackups retrieves a list of all available backup metadata for a given release name.
	// The list is typically sorted by timestamp in descending order (most recent first).
	//
	// Parameters:
	//   - releaseName: The name of the Helm release whose backups are to be listed.
	//
	// Returns:
	//   - []BackupMetadata: A slice of BackupMetadata objects, each representing a backup.
	//   - error: An error if listing backups fails (e.g., release not found or I/O errors).
	ListBackups(releaseName string) ([]BackupMetadata, error)

	// GetBackupDetails retrieves the file system paths to the backed-up chart directory and its
	// corresponding values.yaml file, along with the backup's metadata.
	//
	// Parameters:
	//   - releaseName: The name of the Helm release.
	//   - backupID: The unique identifier of the backup to retrieve.
	//
	// Returns:
	//   - chartPath: The absolute path to the backed-up chart directory.
	//   - valuesFilePath: The absolute path to the backed-up values.yaml file.
	//   - metadata: The BackupMetadata for the specified backup.
	//   - error: An error if the backup cannot be found or accessed.
	GetBackupDetails(releaseName string, backupID string) (chartPath string, valuesFilePath string, metadata BackupMetadata, err error)

	// RestoreRelease restores a Helm release to a state defined by a specific backup.
	// This operation typically involves uninstalling the current version of the release (if it exists)
	// and then installing the chart from the specified backup using its backed-up values.
	//
	// Parameters:
	//   - ctx: Context for the operation.
	//   - helmClient: An instance of helmutils.HelmClient to perform Helm operations.
	//   - namespace: The Kubernetes namespace where the release resides or will be installed.
	//   - releaseName: The name of the Helm release.
	//   - backupID: The ID of the backup to restore from.
	//   - createNamespace: Whether to create the namespace if it doesn't exist during install.
	//   - wait: Whether Helm should wait for resources to be ready after install.
	//   - timeout: Timeout duration for Helm operations.
	//
	// Returns:
	//   - *helmutils.ReleaseInfo: Information about the newly installed release.
	//   - error: An error if the restoration process fails.
	RestoreRelease(ctx context.Context, helmClient helmutils.HelmClient, namespace string, releaseName string, backupID string, createNamespace bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error)

	// UpgradeToBackup upgrades an existing Helm release to a state defined by a specific backup.
	// This is similar to a rollback but uses Helm's upgrade mechanism, potentially allowing for
	// a smoother transition or if Helm's upgrade lifecycle hooks are important.
	//
	// Parameters:
	//   - ctx: Context for the operation.
	//   - helmClient: An instance of helmutils.HelmClient to perform Helm operations.
	//   - namespace: The Kubernetes namespace where the release resides.
	//   - releaseName: The name of the Helm release to upgrade.
	//   - backupID: The ID of the backup to use as the source for the upgrade.
	//   - wait: Whether Helm should wait for resources to be ready after upgrade.
	//   - timeout: Timeout duration for Helm operations.
	//   - force: Whether to force the upgrade (e.g., replace resources).
	//
	// Returns:
	//   - *helmutils.ReleaseInfo: Information about the upgraded release.
	//   - error: An error if the upgrade process fails.
	UpgradeToBackup(ctx context.Context, helmClient helmutils.HelmClient, namespace string, releaseName string, backupID string, wait bool, timeout time.Duration, force bool) (*helmutils.ReleaseInfo, error)

	// DeleteBackup removes a specific backup for a release.
	//
	// Parameters:
	//   - releaseName: The name of the Helm release.
	//   - backupID: The unique identifier of the backup to delete.
	//
	// Returns:
	//   - error: An error if the deletion fails.
	DeleteBackup(releaseName string, backupID string) error

	// PruneBackups removes old backups for a release, keeping a specified number of recent backups.
	//
	// Parameters:
	//   - releaseName: The name of the Helm release.
	//   - keepCount: The number of most recent backups to retain.
	//
	// Returns:
	//   - int: The number of backups pruned.
	//   - error: An error if pruning fails.
	PruneBackups(releaseName string, keepCount int) (int, error)
}

// FileSystemBackupManager implements the Manager interface using the local file system.
// It stores backups in a directory structure: <baseBackupPath>/<releaseName>/<backupID>/.
// Each backupID directory contains the chart ('chart/' subdirectory), its values ('values.yaml'),
// and metadata ('metadata.json').
type FileSystemBackupManager struct {
	baseBackupPath string
	log            func(format string, v ...interface{}) // Logger function, e.g., log.Printf
}

// NewFileSystemBackupManager creates a new FileSystemBackupManager.
// baseBackupPath is the root directory where all backups will be stored.
// logger is a function for logging messages; if nil, log.Printf is used.
func NewFileSystemBackupManager(baseBackupPath string, logger func(format string, v ...interface{})) (*FileSystemBackupManager, error) {
	if baseBackupPath == "" {
		return nil, fmt.Errorf("baseBackupPath cannot be empty")
	}

	// Ensure the base backup path exists
	if err := os.MkdirAll(baseBackupPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base backup directory %s: %w", baseBackupPath, err)
	}

	actualLogger := logger
	if actualLogger == nil {
		actualLogger = log.Printf
	}

	return &FileSystemBackupManager{
		baseBackupPath: baseBackupPath,
		log:            actualLogger,
	}, nil
}

// BackupRelease creates a backup of the chart and its values.
func (m *FileSystemBackupManager) BackupRelease(releaseName string, chartSourcePath string, values map[string]interface{}) (string, error) {
	if releaseName == "" {
		return "", fmt.Errorf("releaseName cannot be empty")
	}
	if chartSourcePath == "" {
		return "", fmt.Errorf("chartSourcePath cannot be empty")
	}

	// Generate a unique backup ID (timestamp-based)
	backupID := time.Now().UTC().Format(backupIDTimestampFormat)

	releaseBackupPath := filepath.Join(m.baseBackupPath, releaseName)
	backupInstancePath := filepath.Join(releaseBackupPath, backupID)

	m.log("Creating backup for release ", releaseName, " with ID ", backupID, " at ", backupInstancePath)

	if err := os.MkdirAll(backupInstancePath, 0755); err != nil {
		return "", fmt.Errorf("failed to create backup instance directory %s: %w", backupInstancePath, err)
	}

	// 1. Copy the chart directory
	chartDestPath := filepath.Join(backupInstancePath, backupDirName)
	m.log("Copying chart from %s to %s", chartSourcePath, chartDestPath)
	if err := copyDirectory(chartSourcePath, chartDestPath); err != nil {
		// Attempt to clean up partially created backup directory
		_ = os.RemoveAll(backupInstancePath)
		return "", fmt.Errorf("failed to copy chart directory from %s to %s: %w", chartSourcePath, chartDestPath, err)
	}

	// 2. Read Chart.yaml from the backed-up chart to get metadata
	chartMeta := ChartYAML{Name: "unknown", Version: "unknown"} // Defaults
	chartYamlPath := filepath.Join(chartDestPath, "Chart.yaml")
	if _, err := os.Stat(chartYamlPath); err == nil {
		chartYamlBytes, errRead := os.ReadFile(chartYamlPath)
		if errRead != nil {
			m.log("Warning: failed to read Chart.yaml from backup at %s: %v", chartYamlPath, errRead)
		} else {
			if errUnmarshal := yaml.Unmarshal(chartYamlBytes, &chartMeta); errUnmarshal != nil {
				m.log("Warning: failed to unmarshal Chart.yaml from backup at %s: %v", chartYamlPath, errUnmarshal)
			}
		}
	} else {
		m.log("Warning: Chart.yaml not found in backed-up chart at %s", chartYamlPath)
	}

	// 3. Save the values map as values.yaml
	valuesFilePath := filepath.Join(backupInstancePath, valuesFileName)
	m.log("Saving values to %s", valuesFilePath)
	valuesBytes, err := yaml.Marshal(values)
	if err != nil {
		_ = os.RemoveAll(backupInstancePath)
		return "", fmt.Errorf("failed to marshal values to YAML: %w", err)
	}
	if err := os.WriteFile(valuesFilePath, valuesBytes, 0644); err != nil {
		_ = os.RemoveAll(backupInstancePath)
		return "", fmt.Errorf("failed to write values.yaml to %s: %w", valuesFilePath, err)
	}

	// 4. Create and save BackupMetadata
	metadata := BackupMetadata{
		BackupID:     backupID,
		Timestamp:    time.Now().UTC(),
		ReleaseName:  releaseName,
		ChartName:    chartMeta.Name,
		ChartVersion: chartMeta.Version,
		AppVersion:   chartMeta.AppVersion,
		Description:  chartMeta.Description,
	}
	metadataFilePath := filepath.Join(backupInstancePath, metadataFileName)
	m.log("Saving metadata to %s", metadataFilePath)
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		_ = os.RemoveAll(backupInstancePath)
		return "", fmt.Errorf("failed to marshal backup metadata to JSON: %w", err)
	}
	if err := os.WriteFile(metadataFilePath, metadataBytes, 0644); err != nil {
		_ = os.RemoveAll(backupInstancePath)
		return "", fmt.Errorf("failed to write metadata.json to %s: %w", metadataFilePath, err)
	}

	m.log("Backup successful for release %s, backup ID: %s", releaseName, backupID)
	return backupID, nil
}

// ListBackups retrieves metadata for all backups of a given release.
func (m *FileSystemBackupManager) ListBackups(releaseName string) ([]BackupMetadata, error) {
	releaseBackupPath := filepath.Join(m.baseBackupPath, releaseName)
	m.log("Listing backups for release %s from %s", releaseName, releaseBackupPath)

	entries, err := os.ReadDir(releaseBackupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []BackupMetadata{}, nil // No backups yet for this release
		}
		return nil, fmt.Errorf("failed to read backup directory for release %s: %w", releaseName, err)
	}

	var backups []BackupMetadata
	for _, entry := range entries {
		if entry.IsDir() {
			backupID := entry.Name()
			metadataFilePath := filepath.Join(releaseBackupPath, backupID, metadataFileName)
			if _, err := os.Stat(metadataFilePath); os.IsNotExist(err) {
				m.log("Warning: metadata.json not found in backup directory %s, skipping", filepath.Join(releaseBackupPath, backupID))
				continue
			}

			metadataBytes, err := os.ReadFile(metadataFilePath)
			if err != nil {
				m.log("Warning: failed to read metadata.json from %s: %v, skipping", metadataFilePath, err)
				continue
			}

			var metadata BackupMetadata
			if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
				m.log("Warning: failed to unmarshal metadata.json from %s: %v, skipping", metadataFilePath, err)
				continue
			}
			backups = append(backups, metadata)
		}
	}

	// Sort backups by timestamp, descending (most recent first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp.After(backups[j].Timestamp)
	})

	m.log("Found %d backups for release %s", len(backups), releaseName)
	return backups, nil
}

// GetBackupDetails retrieves paths and metadata for a specific backup.
func (m *FileSystemBackupManager) GetBackupDetails(releaseName string, backupID string) (string, string, BackupMetadata, error) {
	var metadata BackupMetadata
	backupInstancePath := filepath.Join(m.baseBackupPath, releaseName, backupID)
	m.log("Getting details for backup ID %s of release %s from %s", backupID, releaseName, backupInstancePath)

	metadataFilePath := filepath.Join(backupInstancePath, metadataFileName)
	chartPath := filepath.Join(backupInstancePath, backupDirName)
	valuesFilePath := filepath.Join(backupInstancePath, valuesFileName)

	if _, err := os.Stat(backupInstancePath); os.IsNotExist(err) {
		return "", "", metadata, fmt.Errorf("backup ID %s for release %s not found: %w", backupID, releaseName, err)
	}

	metadataBytes, err := os.ReadFile(metadataFilePath)
	if err != nil {
		return "", "", metadata, fmt.Errorf("failed to read metadata.json for backup %s: %w", backupID, err)
	}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return "", "", metadata, fmt.Errorf("failed to unmarshal metadata.json for backup %s: %w", backupID, err)
	}

	if _, err := os.Stat(chartPath); os.IsNotExist(err) {
		return "", "", metadata, fmt.Errorf("chart directory not found in backup %s: %w", backupID, err)
	}
	if _, err := os.Stat(valuesFilePath); os.IsNotExist(err) {
		return "", "", metadata, fmt.Errorf("values.yaml not found in backup %s: %w", backupID, err)
	}

	return chartPath, valuesFilePath, metadata, nil
}

// RestoreRelease restores a release by uninstalling the current and installing from backup.
func (m *FileSystemBackupManager) RestoreRelease(ctx context.Context, helmClient helmutils.HelmClient, namespace string, releaseName string, backupID string, createNamespace bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error) {
	m.log("Attempting to restore release %s in namespace %s from backup ID %s", releaseName, namespace, backupID)

	chartPath, valuesFilePath, metadata, err := m.GetBackupDetails(releaseName, backupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup details for restore: %w", err)
	}

	valuesBytes, err := os.ReadFile(valuesFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read values.yaml from backup %s: %w", valuesFilePath, err)
	}
	var valuesMap map[string]interface{}
	if err := yaml.Unmarshal(valuesBytes, &valuesMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal backed up values.yaml: %w", err)
	}

	// Attempt to uninstall the existing release first. Ignore "not found" errors.
	m.log("Uninstalling existing release %s in namespace %s (if it exists)", releaseName, namespace)
	_, uninstallErr := helmClient.UninstallRelease(namespace, releaseName, false, timeout)
	if uninstallErr != nil {
		if !errors.Is(uninstallErr, driver.ErrReleaseNotFound) && !strings.Contains(strings.ToLower(uninstallErr.Error()), "release: not found") {
			m.log("Warning: failed to uninstall existing release %s: %v. Proceeding with install attempt.", releaseName, uninstallErr)
			// Depending on strictness, one might choose to return error here.
		}
	} else {
		m.log("Successfully uninstalled existing release %s", releaseName)
	}

	m.log("Installing release %s from backed up chart %s (version %s) with backed up values", releaseName, metadata.ChartName, metadata.ChartVersion)
	// For InstallChart, chartName can be a path. Version from Chart.yaml in path will be used.
	// Pass empty string for chartVersion parameter to InstallChart when chartName is a path.
	installedRel, err := helmClient.InstallChart(namespace, releaseName, chartPath, "", valuesMap, createNamespace, wait, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to install chart from backup %s for release %s: %w", backupID, releaseName, err)
	}

	m.log("Successfully restored release %s from backup %s", releaseName, backupID)
	return installedRel, nil
}

// UpgradeToBackup upgrades a release using a backed-up chart and values.
func (m *FileSystemBackupManager) UpgradeToBackup(ctx context.Context, helmClient helmutils.HelmClient, namespace string, releaseName string, backupID string, wait bool, timeout time.Duration, force bool) (*helmutils.ReleaseInfo, error) {
	m.log("Attempting to upgrade release %s in namespace %s using backup ID %s", releaseName, namespace, backupID)

	chartPath, valuesFilePath, metadata, err := m.GetBackupDetails(releaseName, backupID)
	if err != nil {
		return nil, fmt.Errorf("failed to get backup details for upgrade: %w", err)
	}

	valuesBytes, err := os.ReadFile(valuesFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read values.yaml from backup %s: %w", valuesFilePath, err)
	}
	var valuesMap map[string]interface{}
	if err := yaml.Unmarshal(valuesBytes, &valuesMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal backed up values.yaml: %w", err)
	}

	m.log("Upgrading release %s using backed up chart %s (version %s) with backed up values", releaseName, metadata.ChartName, metadata.ChartVersion)
	// For UpgradeRelease, chartName can be a path. Version from Chart.yaml in path will be used.
	// Pass empty string for chartVersion parameter to UpgradeRelease when chartName is a path.
	// Set installIfMissing to true to ensure it works even if the release was previously uninstalled.
	upgradedRel, err := helmClient.UpgradeRelease(namespace, releaseName, chartPath, "", valuesMap, wait, timeout, true /*installIfMissing*/, force)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade release %s using backup %s: %w", releaseName, backupID, err)
	}

	m.log("Successfully upgraded release %s using backup %s", releaseName, backupID)
	return upgradedRel, nil
}

// DeleteBackup removes a specific backup for a release.
func (m *FileSystemBackupManager) DeleteBackup(releaseName string, backupID string) error {
	backupInstancePath := filepath.Join(m.baseBackupPath, releaseName, backupID)
	m.log("Deleting backup ID %s for release %s from %s", backupID, releaseName, backupInstancePath)

	if _, err := os.Stat(backupInstancePath); os.IsNotExist(err) {
		return fmt.Errorf("backup ID %s for release %s not found: %w", backupID, releaseName, err)
	}

	if err := os.RemoveAll(backupInstancePath); err != nil {
		return fmt.Errorf("failed to delete backup directory %s: %w", backupInstancePath, err)
	}

	m.log("Successfully deleted backup %s for release %s", backupID, releaseName)
	return nil
}

// PruneBackups removes old backups for a release, keeping a specified number of recent backups.
func (m *FileSystemBackupManager) PruneBackups(releaseName string, keepCount int) (int, error) {
	if keepCount < 0 {
		return 0, fmt.Errorf("keepCount must be non-negative")
	}

	m.log("Pruning backups for release %s, keeping %d most recent", releaseName, keepCount)
	backups, err := m.ListBackups(releaseName)
	if err != nil {
		return 0, fmt.Errorf("failed to list backups for pruning: %w", err)
	}

	if len(backups) <= keepCount {
		m.log("Number of backups (%d) is less than or equal to keepCount (%d). No backups pruned.", len(backups), keepCount)
		return 0, nil
	}

	// Backups are already sorted by ListBackups (most recent first)
	prunedCount := 0
	for i := keepCount; i < len(backups); i++ {
		backupToPrune := backups[i]
		m.log("Pruning backup ID %s (timestamp: %s) for release %s", backupToPrune.BackupID, backupToPrune.Timestamp, releaseName)
		if err := m.DeleteBackup(releaseName, backupToPrune.BackupID); err != nil {
			// Log error and continue trying to prune others, or return immediately?
			// For now, log and continue, then return a summary error if any failed.
			m.log("Error pruning backup %s: %v. Continuing...", backupToPrune.BackupID, err)
			// Consider collecting errors and returning a multi-error if needed.
		} else {
			prunedCount++
		}
	}

	m.log("Successfully pruned %d backups for release %s", prunedCount, releaseName)
	return prunedCount, nil
}

// --- Helper Functions ---

// copyFile copies a single file from src to dst.
// It creates the destination file with the same permissions as the source.
func copyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", src, err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("source %s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer source.Close()

	destination, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, sourceFileStat.Mode())
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		return fmt.Errorf("failed to copy data from %s to %s: %w", src, dst, err)
	}
	return nil
}

// copyDirectory recursively copies a directory from src to dst.
// It preserves file modes.
func copyDirectory(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source directory %s: %w", src, err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source %s is not a directory", src)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read source directory %s: %w", src, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		entryInfo, err := os.Stat(srcPath) // Get full FileInfo for symlinks etc.
		if err != nil {
			return fmt.Errorf("failed to stat entry %s: %w", srcPath, err)
		}

		switch entryInfo.Mode() & fs.ModeType {
		case fs.ModeDir:
			if err := copyDirectory(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to copy subdirectory %s: %w", srcPath, err)
			}
		case fs.ModeSymlink:
			link, err := os.Readlink(srcPath)
			if err != nil {
				return fmt.Errorf("failed to read symlink %s: %w", srcPath, err)
			}
			if err := os.Symlink(link, dstPath); err != nil {
				return fmt.Errorf("failed to create symlink %s -> %s: %w", dstPath, link, err)
			}
		default: // Regular file
			if err := copyFile(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to copy file %s: %w", srcPath, err)
			}
		}
	}
	return nil
}
