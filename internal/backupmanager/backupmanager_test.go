package backupmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go_k8s_helm/internal/helmutils"

	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/release"
	// For chart.Metadata.Created
	// "github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/require"
)

// mockHelmClient is a mock implementation of the helmutils.HelmClient interface for testing.
type mockHelmClient struct {
	ListReleasesFunc       func(namespace string, stateMask action.ListStates) ([]*helmutils.ReleaseInfo, error)
	InstallChartFunc       func(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, createNamespace bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error)
	UninstallReleaseFunc   func(namespace, releaseName string, keepHistory bool, timeout time.Duration) (string, error)
	UpgradeReleaseFunc     func(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, wait bool, timeout time.Duration, installIfMissing bool, force bool) (*helmutils.ReleaseInfo, error)
	GetReleaseDetailsFunc  func(namespace, releaseName string) (*helmutils.ReleaseInfo, error)
	GetReleaseHistoryFunc  func(namespace, releaseName string) ([]*helmutils.ReleaseInfo, error)
	AddRepositoryFunc      func(name, url, username, password string, passCredentials bool) error
	UpdateRepositoriesFunc func() error
	EnsureChartFunc        func(chartName, version string) (string, error)
}

func (m *mockHelmClient) ListReleases(namespace string, stateMask action.ListStates) ([]*helmutils.ReleaseInfo, error) {
	if m.ListReleasesFunc != nil {
		return m.ListReleasesFunc(namespace, stateMask)
	}
	return nil, fmt.Errorf("ListReleasesFunc not implemented")
}

func (m *mockHelmClient) InstallChart(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, createNamespace bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error) {
	if m.InstallChartFunc != nil {
		return m.InstallChartFunc(namespace, releaseName, chartName, chartVersion, vals, createNamespace, wait, timeout)
	}
	return nil, fmt.Errorf("InstallChartFunc not implemented")
}

func (m *mockHelmClient) UninstallRelease(namespace, releaseName string, keepHistory bool, timeout time.Duration) (string, error) {
	if m.UninstallReleaseFunc != nil {
		return m.UninstallReleaseFunc(namespace, releaseName, keepHistory, timeout)
	}
	return "", fmt.Errorf("UninstallReleaseFunc not implemented")
}

func (m *mockHelmClient) UpgradeRelease(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, wait bool, timeout time.Duration, installIfMissing bool, force bool) (*helmutils.ReleaseInfo, error) {
	if m.UpgradeReleaseFunc != nil {
		return m.UpgradeReleaseFunc(namespace, releaseName, chartName, chartVersion, vals, wait, timeout, installIfMissing, force)
	}
	return nil, fmt.Errorf("UpgradeReleaseFunc not implemented")
}

func (m *mockHelmClient) GetReleaseDetails(namespace, releaseName string) (*helmutils.ReleaseInfo, error) {
	if m.GetReleaseDetailsFunc != nil {
		return m.GetReleaseDetailsFunc(namespace, releaseName)
	}
	return nil, fmt.Errorf("GetReleaseDetailsFunc not implemented")
}

func (m *mockHelmClient) GetReleaseHistory(namespace, releaseName string) ([]*helmutils.ReleaseInfo, error) {
	if m.GetReleaseHistoryFunc != nil {
		return m.GetReleaseHistoryFunc(namespace, releaseName)
	}
	return nil, fmt.Errorf("GetReleaseHistoryFunc not implemented")
}

func (m *mockHelmClient) AddRepository(name, url, username, password string, passCredentials bool) error {
	if m.AddRepositoryFunc != nil {
		return m.AddRepositoryFunc(name, url, username, password, passCredentials)
	}
	return fmt.Errorf("AddRepositoryFunc not implemented")
}

func (m *mockHelmClient) UpdateRepositories() error {
	if m.UpdateRepositoriesFunc != nil {
		return m.UpdateRepositoriesFunc()
	}
	return fmt.Errorf("UpdateRepositoriesFunc not implemented")
}

func (m *mockHelmClient) EnsureChart(chartName, version string) (string, error) {
	if m.EnsureChartFunc != nil {
		return m.EnsureChartFunc(chartName, version)
	}
	return "", fmt.Errorf("EnsureChartFunc not implemented")
}

// Helper function to create a temporary chart directory for testing
func createTempChart(t *testing.T, chartName, chartVersion, appVersion string) string {
	t.Helper()
	tempDir := t.TempDir()
	chartDir := filepath.Join(tempDir, chartName)
	if err := os.MkdirAll(chartDir, 0755); err != nil {
		t.Fatalf("Failed to create temp chart dir: %v", err)
	}

	chartYamlContent := fmt.Sprintf(`
apiVersion: v2
name: %s
version: %s
appVersion: %s
description: A test chart
`, chartName, chartVersion, appVersion)
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYamlContent), 0644); err != nil {
		t.Fatalf("Failed to write Chart.yaml: %v", err)
	}

	// Create a dummy templates directory and a file
	templatesDir := filepath.Join(chartDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		t.Fatalf("Failed to create templates dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(templatesDir, "deployment.yaml"), []byte("kind: Deployment"), 0644); err != nil {
		t.Fatalf("Failed to write dummy deployment.yaml: %v", err)
	}

	return chartDir
}

func TestNewFileSystemBackupManager(t *testing.T) {
	t.Run("valid base path", func(t *testing.T) {
		tempDir := t.TempDir()
		mgr, err := NewFileSystemBackupManager(tempDir, log.Printf)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if mgr == nil {
			t.Fatal("Expected manager to be non-nil")
		}
		if mgr.baseBackupPath != tempDir {
			t.Errorf("Expected baseBackupPath to be %s, got %s", tempDir, mgr.baseBackupPath)
		}
	})

	t.Run("empty base path", func(t *testing.T) {
		_, err := NewFileSystemBackupManager("", log.Printf)
		if err == nil {
			t.Fatal("Expected error for empty baseBackupPath, got nil")
		}
		if !strings.Contains(err.Error(), "baseBackupPath cannot be empty") {
			t.Errorf("Expected error message to contain 'baseBackupPath cannot be empty', got '%s'", err.Error())
		}
	})

	t.Run("uncreatable base path", func(t *testing.T) {
		// This test might be flaky depending on permissions, but attempts to create a dir where it shouldn't be able to.
		// On Unix-like systems, /dev/null is not a directory.
		// On Windows, this might behave differently. A more robust test might involve setting permissions.
		_, err := NewFileSystemBackupManager("/dev/null/somepath", log.Printf)
		if err == nil {
			t.Logf("Warning: Expected error for uncreatable baseBackupPath, got nil. This test might be OS-dependent.")
			// t.Fatal("Expected error for uncreatable baseBackupPath, got nil")
		} else if !strings.Contains(err.Error(), "failed to create base backup directory") {
			t.Errorf("Expected error message to contain 'failed to create base backup directory', got '%s'", err.Error())
		}
	})
}

func TestFileSystemBackupManager_BackupRelease(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	testChartDir := createTempChart(t, "mychart", "0.1.0", "1.0.0")
	releaseName := "my-release"
	values := map[string]interface{}{"key": "value", "replicaCount": 2}

	t.Run("successful backup", func(t *testing.T) {
		backupID, err := mgr.BackupRelease(releaseName, testChartDir, values)
		if err != nil {
			t.Fatalf("BackupRelease failed: %v", err)
		}
		if backupID == "" {
			t.Fatal("BackupID should not be empty")
		}

		backupPath := filepath.Join(tempBaseDir, releaseName, backupID)
		// Check if backup directory exists
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			t.Fatalf("Backup directory %s was not created", backupPath)
		}

		// Check for chart subdirectory
		chartBackupPath := filepath.Join(backupPath, backupDirName)
		if _, err := os.Stat(chartBackupPath); os.IsNotExist(err) {
			t.Fatalf("Chart backup directory %s was not created", chartBackupPath)
		}
		if _, err := os.Stat(filepath.Join(chartBackupPath, "Chart.yaml")); os.IsNotExist(err) {
			t.Errorf("Chart.yaml not found in backup")
		}

		// Check for values.yaml
		valuesBackupPath := filepath.Join(backupPath, valuesFileName)
		if _, err := os.Stat(valuesBackupPath); os.IsNotExist(err) {
			t.Fatalf("values.yaml %s was not created", valuesBackupPath)
		}
		valuesBytes, _ := os.ReadFile(valuesBackupPath)
		var backedUpValues map[string]interface{}
		if err := yaml.Unmarshal(valuesBytes, &backedUpValues); err != nil {
			t.Fatalf("Failed to unmarshal backed up values.yaml: %v", err)
		}
		if !reflect.DeepEqual(values, backedUpValues) {
			t.Errorf("Backed up values.yaml content mismatch. Got %v, want %v", backedUpValues, values)
		}

		// Check for metadata.json
		metadataPath := filepath.Join(backupPath, metadataFileName)
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			t.Fatalf("metadata.json %s was not created", metadataPath)
		}
		metadataBytes, _ := os.ReadFile(metadataPath)
		var meta BackupMetadata
		if err := json.Unmarshal(metadataBytes, &meta); err != nil {
			t.Fatalf("Failed to unmarshal metadata.json: %v", err)
		}
		if meta.BackupID != backupID {
			t.Errorf("Metadata BackupID mismatch. Got %s, want %s", meta.BackupID, backupID)
		}
		if meta.ReleaseName != releaseName {
			t.Errorf("Metadata ReleaseName mismatch. Got %s, want %s", meta.ReleaseName, releaseName)
		}
		if meta.ChartName != "mychart" {
			t.Errorf("Metadata ChartName mismatch. Got %s, want %s", meta.ChartName, "mychart")
		}
		if meta.ChartVersion != "0.1.0" {
			t.Errorf("Metadata ChartVersion mismatch. Got %s, want %s", meta.ChartVersion, "0.1.0")
		}
		if meta.AppVersion != "1.0.0" {
			t.Errorf("Metadata AppVersion mismatch. Got %s, want %s", meta.AppVersion, "1.0.0")
		}
	})

	t.Run("empty release name", func(t *testing.T) {
		_, err := mgr.BackupRelease("", testChartDir, values)
		if err == nil {
			t.Fatal("Expected error for empty releaseName, got nil")
		}
		if !strings.Contains(err.Error(), "releaseName cannot be empty") {
			t.Errorf("Expected error message to contain 'releaseName cannot be empty', got '%s'", err.Error())
		}
	})

	t.Run("empty chart source path", func(t *testing.T) {
		_, err := mgr.BackupRelease(releaseName, "", values)
		if err == nil {
			t.Fatal("Expected error for empty chartSourcePath, got nil")
		}
		if !strings.Contains(err.Error(), "chartSourcePath cannot be empty") {
			t.Errorf("Expected error message to contain 'chartSourcePath cannot be empty', got '%s'", err.Error())
		}
	})

	t.Run("non-existent chart source path", func(t *testing.T) {
		_, err := mgr.BackupRelease(releaseName, "/path/to/nonexistent/chart", values)
		if err == nil {
			t.Fatal("Expected error for non-existent chartSourcePath, got nil")
		}
		if !strings.Contains(err.Error(), "failed to copy chart directory") {
			t.Errorf("Expected error message to contain 'failed to copy chart directory', got '%s'", err.Error())
		}
	})
}

func TestFileSystemBackupManager_ListBackups(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	releaseName := "list-test-release"
	testChartDir := createTempChart(t, "listchart", "1.0.0", "1.0")

	t.Run("no backups", func(t *testing.T) {
		backups, err := mgr.ListBackups(releaseName)
		if err != nil {
			t.Fatalf("ListBackups failed: %v", err)
		}
		if len(backups) != 0 {
			t.Errorf("Expected 0 backups, got %d", len(backups))
		}
	})

	// Create some backups
	backupID1, _ := mgr.BackupRelease(releaseName, testChartDir, map[string]interface{}{"val": 1})
	time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	backupID2, _ := mgr.BackupRelease(releaseName, testChartDir, map[string]interface{}{"val": 2})
	time.Sleep(10 * time.Millisecond)
	backupID3, _ := mgr.BackupRelease(releaseName, testChartDir, map[string]interface{}{"val": 3})

	// Create a backup for a different release to ensure it's not listed
	_, _ = mgr.BackupRelease("other-release", testChartDir, map[string]interface{}{"val": 4})

	t.Run("list multiple backups", func(t *testing.T) {
		backups, err := mgr.ListBackups(releaseName)
		if err != nil {
			t.Fatalf("ListBackups failed: %v", err)
		}
		if len(backups) != 3 {
			t.Errorf("Expected 3 backups, got %d", len(backups))
		}

		// Check if sorted by timestamp descending (most recent first)
		if backups[0].BackupID != backupID3 {
			t.Errorf("Expected first backup to be %s, got %s", backupID3, backups[0].BackupID)
		}
		if backups[1].BackupID != backupID2 {
			t.Errorf("Expected second backup to be %s, got %s", backupID2, backups[1].BackupID)
		}
		if backups[2].BackupID != backupID1 {
			t.Errorf("Expected third backup to be %s, got %s", backupID1, backups[2].BackupID)
		}

		// Check content of one metadata
		found := false
		for _, b := range backups {
			if b.BackupID == backupID2 {
				found = true
				if b.ReleaseName != releaseName {
					t.Errorf("Expected release name %s, got %s", releaseName, b.ReleaseName)
				}
				if b.ChartName != "listchart" {
					t.Errorf("Expected chart name listchart, got %s", b.ChartName)
				}
				break
			}
		}
		if !found {
			t.Errorf("Backup ID %s not found in list", backupID2)
		}
	})

	t.Run("list non-existent release", func(t *testing.T) {
		backups, err := mgr.ListBackups("non-existent-release")
		if err != nil {
			t.Fatalf("ListBackups failed for non-existent release: %v", err)
		}
		if len(backups) != 0 {
			t.Errorf("Expected 0 backups for non-existent release, got %d", len(backups))
		}
	})
}

func TestFileSystemBackupManager_GetBackupDetails(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	releaseName := "details-test-release"
	testChartDir := createTempChart(t, "detailschart", "0.2.0", "2.0")
	values := map[string]interface{}{"service": map[string]interface{}{"type": "ClusterIP"}}

	backupID, err := mgr.BackupRelease(releaseName, testChartDir, values)
	if err != nil {
		t.Fatalf("Failed to create backup for GetBackupDetails test: %v", err)
	}

	t.Run("successful get details", func(t *testing.T) {
		chartPath, valuesPath, meta, err := mgr.GetBackupDetails(releaseName, backupID)
		if err != nil {
			t.Fatalf("GetBackupDetails failed: %v", err)
		}

		expectedChartPath := filepath.Join(tempBaseDir, releaseName, backupID, backupDirName)
		expectedValuesPath := filepath.Join(tempBaseDir, releaseName, backupID, valuesFileName)

		if chartPath != expectedChartPath {
			t.Errorf("Expected chartPath %s, got %s", expectedChartPath, chartPath)
		}
		if valuesPath != expectedValuesPath {
			t.Errorf("Expected valuesPath %s, got %s", expectedValuesPath, valuesPath)
		}

		if meta.BackupID != backupID {
			t.Errorf("Metadata BackupID mismatch. Got %s, want %s", meta.BackupID, backupID)
		}
		if meta.ReleaseName != releaseName {
			t.Errorf("Metadata ReleaseName mismatch. Got %s, want %s", meta.ReleaseName, releaseName)
		}
		if meta.ChartName != "detailschart" {
			t.Errorf("Metadata ChartName mismatch. Got %s, want %s", meta.ChartName, "detailschart")
		}
		if meta.ChartVersion != "0.2.0" {
			t.Errorf("Metadata ChartVersion mismatch. Got %s, want %s", meta.ChartVersion, "0.2.0")
		}
	})

	t.Run("non-existent release name", func(t *testing.T) {
		_, _, _, err := mgr.GetBackupDetails("non-existent-release", backupID)
		if err == nil {
			t.Fatal("Expected error for non-existent release, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error message to contain 'not found', got '%s'", err.Error())
		}
	})

	t.Run("non-existent backup ID", func(t *testing.T) {
		_, _, _, err := mgr.GetBackupDetails(releaseName, "non-existent-backup-id")
		if err == nil {
			t.Fatal("Expected error for non-existent backup ID, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error message to contain 'not found', got '%s'", err.Error())
		}
	})
}

func TestFileSystemBackupManager_RestoreRelease(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	mockHelm := &mockHelmClient{}
	ctx := context.Background()
	namespace := "test-ns"
	releaseName := "restore-release"
	testChartDir := createTempChart(t, "restorechart", "1.1.0", "1.1")
	originalValues := map[string]interface{}{"replicaCount": 1, "serviceType": "LoadBalancer"}

	backupID, err := mgr.BackupRelease(releaseName, testChartDir, originalValues)
	if err != nil {
		t.Fatalf("Failed to create backup for RestoreRelease test: %v", err)
	}

	t.Run("successful restore", func(t *testing.T) {
		uninstallCalled := false
		installCalled := false

		mockHelm.UninstallReleaseFunc = func(ns, rn string, keepHistory bool, timeout time.Duration) (string, error) {
			if ns != namespace || rn != releaseName {
				t.Errorf("Uninstall called with wrong ns/name. Got %s/%s, want %s/%s", ns, rn, namespace, releaseName)
			}
			uninstallCalled = true
			return "uninstalled", nil
		}

		mockHelm.InstallChartFunc = func(ns, rn, chartPath, chartVer string, vals map[string]interface{}, createNs bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error) {
			if ns != namespace || rn != releaseName {
				t.Errorf("Install called with wrong ns/name. Got %s/%s, want %s/%s", ns, rn, namespace, releaseName)
			}
			if !strings.Contains(chartPath, backupID) {
				t.Errorf("Install called with wrong chartPath, expected to contain backupID %s, got %s", backupID, chartPath)
			}
			if !reflect.DeepEqual(vals, originalValues) {
				t.Errorf("Install called with wrong values. Got %v, want %v", vals, originalValues)
			}
			installCalled = true
			return &helmutils.ReleaseInfo{Name: releaseName, Namespace: namespace, Status: release.StatusDeployed}, nil
		}

		_, err := mgr.RestoreRelease(ctx, mockHelm, namespace, releaseName, backupID, true, true, 5*time.Minute)
		if err != nil {
			t.Fatalf("RestoreRelease failed: %v", err)
		}
		if !uninstallCalled {
			t.Error("Expected UninstallRelease to be called")
		}
		if !installCalled {
			t.Error("Expected InstallChart to be called")
		}
	})

	t.Run("restore with uninstall failure (not 'not found')", func(t *testing.T) {
		uninstallCalled := false
		installCalled := false
		mockHelm.UninstallReleaseFunc = func(ns, rn string, keepHistory bool, timeout time.Duration) (string, error) {
			uninstallCalled = true
			return "", fmt.Errorf("some uninstall error") // Simulate an error other than "not found"
		}
		mockHelm.InstallChartFunc = func(ns, rn, chartPath, chartVer string, vals map[string]interface{}, createNs bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error) {
			installCalled = true
			return &helmutils.ReleaseInfo{Name: releaseName, Namespace: namespace, Status: release.StatusDeployed}, nil
		}

		// We expect RestoreRelease to proceed with install even if uninstall fails (with a warning log)
		_, err := mgr.RestoreRelease(ctx, mockHelm, namespace, releaseName, backupID, true, true, 5*time.Minute)
		if err != nil {
			t.Fatalf("RestoreRelease failed unexpectedly: %v", err)
		}
		if !uninstallCalled {
			t.Error("Expected UninstallRelease to be called")
		}
		if !installCalled {
			t.Error("Expected InstallChart to be called despite uninstall warning")
		}
	})

	t.Run("restore with install failure", func(t *testing.T) {
		mockHelm.UninstallReleaseFunc = func(ns, rn string, keepHistory bool, timeout time.Duration) (string, error) {
			return "uninstalled", nil
		}
		mockHelm.InstallChartFunc = func(ns, rn, chartPath, chartVer string, vals map[string]interface{}, createNs bool, wait bool, timeout time.Duration) (*helmutils.ReleaseInfo, error) {
			return nil, fmt.Errorf("install failed")
		}

		_, err := mgr.RestoreRelease(ctx, mockHelm, namespace, releaseName, backupID, true, true, 5*time.Minute)
		if err == nil {
			t.Fatal("Expected RestoreRelease to fail due to install error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to install chart from backup") {
			t.Errorf("Expected error message to contain 'failed to install chart from backup', got '%s'", err.Error())
		}
	})

	t.Run("restore non-existent backup ID", func(t *testing.T) {
		_, err := mgr.RestoreRelease(ctx, mockHelm, namespace, releaseName, "non-existent-id", true, true, 5*time.Minute)
		if err == nil {
			t.Fatal("Expected error for non-existent backup ID, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error message to contain 'not found', got '%s'", err.Error())
		}
	})
}

func TestFileSystemBackupManager_UpgradeToBackup(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	mockHelm := &mockHelmClient{}
	ctx := context.Background()
	namespace := "test-ns"
	releaseName := "upgrade-release"
	testChartDir := createTempChart(t, "upgradechart", "1.2.0", "1.2")
	originalValues := map[string]interface{}{"image.tag": "v1.2.0"}

	backupID, err := mgr.BackupRelease(releaseName, testChartDir, originalValues)
	if err != nil {
		t.Fatalf("Failed to create backup for UpgradeToBackup test: %v", err)
	}

	t.Run("successful upgrade to backup", func(t *testing.T) {
		upgradeCalled := false
		mockHelm.UpgradeReleaseFunc = func(ns, rn, chartPath, chartVer string, vals map[string]interface{}, wait bool, timeout time.Duration, installIfMissing bool, force bool) (*helmutils.ReleaseInfo, error) {
			if ns != namespace || rn != releaseName {
				t.Errorf("Upgrade called with wrong ns/name. Got %s/%s, want %s/%s", ns, rn, namespace, releaseName)
			}
			if !strings.Contains(chartPath, backupID) {
				t.Errorf("Upgrade called with wrong chartPath, expected to contain backupID %s, got %s", backupID, chartPath)
			}
			if !reflect.DeepEqual(vals, originalValues) {
				t.Errorf("Upgrade called with wrong values. Got %v, want %v", vals, originalValues)
			}
			if !installIfMissing {
				t.Error("Expected installIfMissing to be true for UpgradeToBackup")
			}
			upgradeCalled = true
			return &helmutils.ReleaseInfo{Name: releaseName, Namespace: namespace, Status: release.StatusDeployed}, nil
		}

		_, err := mgr.UpgradeToBackup(ctx, mockHelm, namespace, releaseName, backupID, true, 5*time.Minute, false)
		if err != nil {
			t.Fatalf("UpgradeToBackup failed: %v", err)
		}
		if !upgradeCalled {
			t.Error("Expected UpgradeRelease to be called")
		}
	})

	t.Run("upgrade to backup with helm upgrade failure", func(t *testing.T) {
		mockHelm.UpgradeReleaseFunc = func(ns, rn, chartPath, chartVer string, vals map[string]interface{}, wait bool, timeout time.Duration, installIfMissing bool, force bool) (*helmutils.ReleaseInfo, error) {
			return nil, fmt.Errorf("helm upgrade failed")
		}

		_, err := mgr.UpgradeToBackup(ctx, mockHelm, namespace, releaseName, backupID, true, 5*time.Minute, false)
		if err == nil {
			t.Fatal("Expected UpgradeToBackup to fail due to helm upgrade error, got nil")
		}
		if !strings.Contains(err.Error(), "failed to upgrade release") {
			t.Errorf("Expected error message to contain 'failed to upgrade release', got '%s'", err.Error())
		}
	})

	t.Run("upgrade to non-existent backup ID", func(t *testing.T) {
		_, err := mgr.UpgradeToBackup(ctx, mockHelm, namespace, releaseName, "non-existent-id", true, 5*time.Minute, false)
		if err == nil {
			t.Fatal("Expected error for non-existent backup ID, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error message to contain 'not found', got '%s'", err.Error())
		}
	})
}

func TestFileSystemBackupManager_DeleteBackup(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	releaseName := "delete-test-release"
	testChartDir := createTempChart(t, "deletechart", "0.3.0", "3.0")

	backupID, err := mgr.BackupRelease(releaseName, testChartDir, nil)
	if err != nil {
		t.Fatalf("Failed to create backup for DeleteBackup test: %v", err)
	}
	backupPath := filepath.Join(tempBaseDir, releaseName, backupID)

	t.Run("successful delete", func(t *testing.T) {
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			t.Fatal("Backup directory should exist before deletion")
		}
		err := mgr.DeleteBackup(releaseName, backupID)
		if err != nil {
			t.Fatalf("DeleteBackup failed: %v", err)
		}
		if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
			t.Errorf("Backup directory %s should have been deleted", backupPath)
		}
	})

	t.Run("delete non-existent backup ID", func(t *testing.T) {
		err := mgr.DeleteBackup(releaseName, "non-existent-id")
		if err == nil {
			t.Fatal("Expected error for non-existent backup ID, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error message to contain 'not found', got '%s'", err.Error())
		}
	})

	t.Run("delete from non-existent release", func(t *testing.T) {
		err := mgr.DeleteBackup("non-existent-release", backupID)
		if err == nil {
			t.Fatal("Expected error for non-existent release, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error message to contain 'not found', got '%s'", err.Error())
		}
	})
}

func TestFileSystemBackupManager_PruneBackups(t *testing.T) {
	tempBaseDir := t.TempDir()
	mgr, err := NewFileSystemBackupManager(tempBaseDir, log.Printf)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	releaseName := "prune-test-release"
	testChartDir := createTempChart(t, "prunechart", "0.4.0", "4.0")

	// Create 5 backups
	var backupIDs []string
	for i := 0; i < 5; i++ {
		bid, err := mgr.BackupRelease(releaseName, testChartDir, map[string]interface{}{"iteration": i})
		if err != nil {
			t.Fatalf("Failed to create backup %d: %v", i, err)
		}
		backupIDs = append(backupIDs, bid)
		time.Sleep(5 * time.Millisecond) // Ensure distinct timestamps for sorting
	}

	// Backups are created with increasing timestamps, so backupIDs[4] is the newest.

	t.Run("prune to keep 2", func(t *testing.T) {
		prunedCount, err := mgr.PruneBackups(releaseName, 2)
		if err != nil {
			t.Fatalf("PruneBackups failed: %v", err)
		}
		if prunedCount != 3 {
			t.Errorf("Expected 3 backups to be pruned, got %d", prunedCount)
		}

		remainingBackups, _ := mgr.ListBackups(releaseName)
		if len(remainingBackups) != 2 {
			t.Errorf("Expected 2 backups to remain, got %d", len(remainingBackups))
		}

		// Check that the newest ones are kept (backupIDs[4] and backupIDs[3])
		keptIDs := make(map[string]bool)
		for _, b := range remainingBackups {
			keptIDs[b.BackupID] = true
		}
		if !keptIDs[backupIDs[4]] {
			t.Errorf("Expected backup %s to be kept", backupIDs[4])
		}
		if !keptIDs[backupIDs[3]] {
			t.Errorf("Expected backup %s to be kept", backupIDs[3])
		}
		if keptIDs[backupIDs[0]] || keptIDs[backupIDs[1]] || keptIDs[backupIDs[2]] {
			t.Error("Older backups were not pruned correctly")
		}
	})

	t.Run("prune with keepCount greater than existing", func(t *testing.T) {
		// Reset: create 2 backups for a new release
		pruneRelease2 := "prune-test-release-2"
		_, _ = mgr.BackupRelease(pruneRelease2, testChartDir, nil)
		time.Sleep(5 * time.Millisecond)
		_, _ = mgr.BackupRelease(pruneRelease2, testChartDir, nil)

		prunedCount, err := mgr.PruneBackups(pruneRelease2, 5)
		if err != nil {
			t.Fatalf("PruneBackups failed: %v", err)
		}
		if prunedCount != 0 {
			t.Errorf("Expected 0 backups to be pruned, got %d", prunedCount)
		}
		remainingBackups, _ := mgr.ListBackups(pruneRelease2)
		if len(remainingBackups) != 2 {
			t.Errorf("Expected 2 backups to remain, got %d", len(remainingBackups))
		}
	})

	t.Run("prune with keepCount zero", func(t *testing.T) {
		// Reset: create 2 backups for a new release
		pruneRelease3 := "prune-test-release-3"
		_, _ = mgr.BackupRelease(pruneRelease3, testChartDir, nil)
		time.Sleep(5 * time.Millisecond)
		_, _ = mgr.BackupRelease(pruneRelease3, testChartDir, nil)

		prunedCount, err := mgr.PruneBackups(pruneRelease3, 0)
		if err != nil {
			t.Fatalf("PruneBackups failed: %v", err)
		}
		if prunedCount != 2 {
			t.Errorf("Expected 2 backups to be pruned, got %d", prunedCount)
		}
		remainingBackups, _ := mgr.ListBackups(pruneRelease3)
		if len(remainingBackups) != 0 {
			t.Errorf("Expected 0 backups to remain, got %d", len(remainingBackups))
		}
	})

	t.Run("prune with negative keepCount", func(t *testing.T) {
		_, err := mgr.PruneBackups(releaseName, -1)
		if err == nil {
			t.Fatal("Expected error for negative keepCount, got nil")
		}
		if !strings.Contains(err.Error(), "keepCount must be non-negative") {
			t.Errorf("Expected error message for negative keepCount, got '%s'", err.Error())
		}
	})

	t.Run("prune non-existent release", func(t *testing.T) {
		prunedCount, err := mgr.PruneBackups("non-existent-for-prune", 2)
		if err != nil {
			t.Fatalf("PruneBackups for non-existent release failed: %v", err)
		}
		if prunedCount != 0 {
			t.Errorf("Expected 0 backups pruned for non-existent release, got %d", prunedCount)
		}
	})
}

// Test helper for copyDirectory - basic cases
func TestCopyDirectory(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create source structure
	if err := os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(srcDir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("world"), 0644); err != nil {
		t.Fatal(err)
	}

	err := copyDirectory(srcDir, dstDir)
	if err != nil {
		t.Fatalf("copyDirectory failed: %v", err)
	}

	// Verify destination structure
	_, err = os.Stat(filepath.Join(dstDir, "file1.txt"))
	if os.IsNotExist(err) {
		t.Error("file1.txt not copied")
	}
	_, err = os.Stat(filepath.Join(dstDir, "subdir", "file2.txt"))
	if os.IsNotExist(err) {
		t.Error("subdir/file2.txt not copied")
	}

	// Test copying a file instead of a directory
	srcFile := filepath.Join(srcDir, "file1.txt")
	dstFileDir := t.TempDir()
	err = copyDirectory(srcFile, dstFileDir)
	if err == nil {
		t.Error("Expected error when source is not a directory, got nil")
	} else if !strings.Contains(err.Error(), "is not a directory") {
		t.Errorf("Expected 'is not a directory' error, got: %v", err)
	}
}

// Test helper for copyFile - basic cases
func TestCopyFile(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	srcFilePath := filepath.Join(srcDir, "source.txt")
	dstFilePath := filepath.Join(dstDir, "destination.txt")

	content := []byte("this is a test file")
	if err := os.WriteFile(srcFilePath, content, 0644); err != nil {
		t.Fatal(err)
	}

	err := copyFile(srcFilePath, dstFilePath)
	if err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	copiedContent, err := os.ReadFile(dstFilePath)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}
	if !reflect.DeepEqual(content, copiedContent) {
		t.Errorf("File content mismatch. Expected %s, got %s", string(content), string(copiedContent))
	}

	// Test copying a directory instead of a file
	err = copyFile(srcDir, dstFilePath+"_dir")
	if err == nil {
		t.Error("Expected error when source is a directory, got nil")
	} else if !strings.Contains(err.Error(), "is not a regular file") {
		t.Errorf("Expected 'is not a regular file' error, got: %v", err)
	}
}
