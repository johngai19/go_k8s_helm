package helmutils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"time"

	"go_k8s_helm/internal/k8sutils"

	helmtime "helm.sh/helm/v3/pkg/time" // Import the Helm time package

	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/release"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// MockLogger is a simple logger for tests that stores log messages.
var mockLogMessages []string

func mockLogger(format string, v ...interface{}) {
	mockLogMessages = append(mockLogMessages, fmt.Sprintf(format, v...))
}

func resetMockLogger() {
	mockLogMessages = []string{}
}

// MockK8sAuthChecker provides a mock implementation of k8sutils.K8sAuthChecker.
type MockK8sAuthChecker struct {
	MockGetKubeConfig             func() (*rest.Config, error)
	MockGetClientset              func() (kubernetes.Interface, error)
	MockIsRunningInCluster        func() bool
	MockGetCurrentNamespace       func() (string, error)
	MockCheckNamespacePermissions func(ctx context.Context, namespace string, resource schema.GroupVersionResource, verbs []string) (map[string]bool, error)
	MockCanPerformClusterAction   func(ctx context.Context, resource schema.GroupVersionResource, verb string) (bool, error)
}

func (m *MockK8sAuthChecker) GetKubeConfig() (*rest.Config, error) {
	if m.MockGetKubeConfig != nil {
		return m.MockGetKubeConfig()
	}
	return &rest.Config{Host: "http://fake.cluster.local"}, nil
}

func (m *MockK8sAuthChecker) GetClientset() (kubernetes.Interface, error) {
	if m.MockGetClientset != nil {
		return m.MockGetClientset()
	}
	return nil, fmt.Errorf("GetClientset not mocked")
}

func (m *MockK8sAuthChecker) IsRunningInCluster() bool {
	if m.MockIsRunningInCluster != nil {
		return m.MockIsRunningInCluster()
	}
	return false
}

func (m *MockK8sAuthChecker) GetCurrentNamespace() (string, error) {
	if m.MockGetCurrentNamespace != nil {
		return m.MockGetCurrentNamespace()
	}
	return "test-default-ns-from-mock", nil
}

func (m *MockK8sAuthChecker) CheckNamespacePermissions(ctx context.Context, namespace string, resource schema.GroupVersionResource, verbs []string) (map[string]bool, error) {
	if m.MockCheckNamespacePermissions != nil {
		return m.MockCheckNamespacePermissions(ctx, namespace, resource, verbs)
	}
	return nil, fmt.Errorf("CheckNamespacePermissions not mocked")
}

func (m *MockK8sAuthChecker) CanPerformClusterAction(ctx context.Context, resource schema.GroupVersionResource, verb string) (bool, error) {
	if m.MockCanPerformClusterAction != nil {
		return m.MockCanPerformClusterAction(ctx, resource, verb)
	}
	return false, fmt.Errorf("CanPerformClusterAction not mocked")
}

func TestNewClient(t *testing.T) {
	resetMockLogger()

	tests := []struct {
		name               string
		authChecker        k8sutils.K8sAuthChecker
		defaultNamespace   string
		expectedSettingsNs string
		expectError        bool
		checkLog           bool
		expectedLogContent string
	}{
		{
			name: "Basic initialization with mock auth and default namespace",
			authChecker: &MockK8sAuthChecker{
				MockGetKubeConfig: func() (*rest.Config, error) {
					return &rest.Config{Host: "http://fake.cluster.local"}, nil
				},
				MockGetCurrentNamespace: func() (string, error) {
					return "mock-current-ns", nil
				},
			},
			defaultNamespace:   "helm-op-ns",
			expectedSettingsNs: "helm-op-ns",
			expectError:        false,
		},
		{
			name: "Initialization with mock auth, empty default namespace (uses authChecker's current ns)",
			authChecker: &MockK8sAuthChecker{
				MockGetKubeConfig: func() (*rest.Config, error) {
					return &rest.Config{Host: "http://fake.cluster.local"}, nil
				},
				MockGetCurrentNamespace: func() (string, error) {
					return "auth-current-ns", nil
				},
			},
			defaultNamespace:   "",
			expectedSettingsNs: "auth-current-ns",
			expectError:        false,
		},
		{
			name: "Initialization with mock auth, empty default ns, authChecker ns error (uses settings default)",
			authChecker: &MockK8sAuthChecker{
				MockGetKubeConfig: func() (*rest.Config, error) {
					return &rest.Config{Host: "http://fake.cluster.local"}, nil
				},
				MockGetCurrentNamespace: func() (string, error) {
					return "", fmt.Errorf("mock GetCurrentNamespace error")
				},
			},
			defaultNamespace:   "",
			expectedSettingsNs: "default", // cli.New() defaults to "default" if not overridden and KUBECONFIG doesn't specify
			expectError:        false,
			checkLog:           true,
			expectedLogContent: "Warning: could not determine current namespace via authChecker",
		},
		{
			name: "Error getting KubeConfig from authChecker",
			authChecker: &MockK8sAuthChecker{
				MockGetKubeConfig: func() (*rest.Config, error) {
					return nil, fmt.Errorf("mock GetKubeConfig error")
				},
			},
			defaultNamespace: "any-ns",
			expectError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetMockLogger()
			client, err := NewClient(tt.authChecker, tt.defaultNamespace, mockLogger)

			if tt.expectError {
				if err == nil {
					t.Errorf("NewClient() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("NewClient() unexpected error: %v", err)
			}

			if client == nil {
				t.Fatal("NewClient() returned nil client without error")
			}
			if client.settings == nil {
				t.Error("NewClient() did not initialize settings")
			}
			if client.Log == nil {
				t.Error("NewClient() did not assign a logger")
			}
			if client.baseKubeConfig == nil && tt.authChecker.(*MockK8sAuthChecker).MockGetKubeConfig == nil {
				t.Error("NewClient() did not assign baseKubeConfig")
			}

			if client.settings.Namespace() != tt.expectedSettingsNs {
				t.Errorf("client.settings.Namespace() = %q, want %q", client.settings.Namespace(), tt.expectedSettingsNs)
			}

			if tt.checkLog {
				foundLog := false
				for _, msg := range mockLogMessages {
					if strings.Contains(msg, tt.expectedLogContent) {
						foundLog = true
						break
					}
				}
				if !foundLog {
					t.Errorf("Expected log message containing %q, logs: %v", tt.expectedLogContent, mockLogMessages)
				}
			}
		})
	}

	t.Run("Nil logger uses default", func(t *testing.T) {
		authChecker := &MockK8sAuthChecker{
			MockGetKubeConfig: func() (*rest.Config, error) {
				return &rest.Config{Host: "http://fake.cluster.local"}, nil
			},
		}
		clientDefaultLog, errDefaultLog := NewClient(authChecker, "default", nil)
		if errDefaultLog != nil {
			t.Fatalf("NewClient() with nil logger error: %v", errDefaultLog)
		}
		if clientDefaultLog.Log == nil {
			t.Error("NewClient() with nil logger did not assign a default logger")
		}
	})
}

func TestConvertReleaseToInfo(t *testing.T) {

	tests := []struct {
		name     string
		rel      *release.Release
		wantInfo *ReleaseInfo
	}{
		{
			name:     "nil release",
			rel:      nil,
			wantInfo: nil,
		},
		{
			name: "basic release",
			rel: &release.Release{
				Name:      "my-release",
				Namespace: "default",
				Version:   1,
				Info: &release.Info{
					Status:       release.StatusDeployed, // Added Status for completeness
					LastDeployed: helmtime.Time{Time: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)},
					Description:  "A test release",
					Notes:        "Some notes",
				},
				Chart: &chart.Chart{
					Metadata: &chart.Metadata{
						Name:       "my-chart",
						Version:    "0.1.0",
						AppVersion: "1.0.0",
					},
					Values: map[string]interface{}{"defaultKey": "defaultValue"},
				},
				Config:   map[string]interface{}{"userKey": "userValue"},
				Manifest: "---\nkind: Pod",
			},
			wantInfo: &ReleaseInfo{
				Name:         "my-release",
				Namespace:    "default",
				Revision:     1,
				Updated:      time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
				Status:       release.StatusDeployed,
				ChartName:    "my-chart",
				ChartVersion: "0.1.0",
				AppVersion:   "1.0.0",
				Description:  "A test release",
				Notes:        "Some notes",
				Config:       map[string]interface{}{"defaultKey": "defaultValue"},
				Values:       map[string]interface{}{"userKey": "userValue"},
				Manifest:     "---\nkind: Pod",
			},
		},
		{
			name: "release with nil info and chart",
			rel: &release.Release{
				Name:      "minimal-release",
				Namespace: "kube-system",
				Version:   2,
				Info:      nil,
				Chart:     nil,
				Config:    map[string]interface{}{},
			},
			wantInfo: &ReleaseInfo{
				Name:      "minimal-release",
				Namespace: "kube-system",
				Revision:  2,
				Updated:   time.Time{},
				Status:    "",
				Config:    nil,
				Values:    map[string]interface{}{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotInfo := convertReleaseToInfo(tt.rel)
			if !reflect.DeepEqual(gotInfo, tt.wantInfo) {
				t.Errorf("convertReleaseToInfo() got = %#v, want %#v", gotInfo, tt.wantInfo)
			}
		})
	}
}

func getMockAuthChecker() k8sutils.K8sAuthChecker {
	return &MockK8sAuthChecker{
		MockGetKubeConfig: func() (*rest.Config, error) {
			return &rest.Config{Host: "http://fake.cluster.local"}, nil
		},
		MockGetCurrentNamespace: func() (string, error) {
			return "mock-ns-for-actions", nil
		},
	}
}

func TestClient_GetActionConfig(t *testing.T) {
	resetMockLogger()
	mockAuth := &MockK8sAuthChecker{
		MockGetKubeConfig: func() (*rest.Config, error) {
			return &rest.Config{
				Host: "http://fake-cluster.local",
			}, nil
		},
		MockGetCurrentNamespace: func() (string, error) {
			return "client-default-ns", nil
		},
	}

	client, err := NewClient(mockAuth, "client-default-ns", mockLogger)
	if err != nil {
		t.Fatalf("Failed to create client for TestClient_GetActionConfig: %v", err)
	}

	tests := []struct {
		name              string
		inputNamespace    string
		expectedNamespace string
		expectError       bool
	}{
		{
			name:              "Specific namespace provided",
			inputNamespace:    "test-ns-1",
			expectedNamespace: "test-ns-1",
			expectError:       false,
		},
		{
			name:              "Empty namespace provided, uses client's default",
			inputNamespace:    "",
			expectedNamespace: "client-default-ns",
			expectError:       false,
		},
	}

	originalHelmDriver := os.Getenv("HELM_DRIVER")
	os.Setenv("HELM_DRIVER", "memory")
	defer os.Setenv("HELM_DRIVER", originalHelmDriver)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actionCfg, err := client.getActionConfig(tt.inputNamespace)

			if tt.expectError {
				if err == nil {
					t.Errorf("getActionConfig() with namespace %q expected error, got nil", tt.inputNamespace)
				}
				return
			}

			if err != nil {
				t.Fatalf("getActionConfig() with namespace %q unexpected error: %v", tt.inputNamespace, err)
			}

			if actionCfg == nil {
				t.Fatal("getActionConfig() returned nil action.Configuration without error")
			}
		})
	}
}

func TestClient_ListReleases(t *testing.T) {
	t.Skip("ListReleases requires mocking Helm action.List.Run() or integration testing.")
}

func TestClient_InstallChart(t *testing.T) {
	tempDir := t.TempDir()
	dummyChartDir := filepath.Join(tempDir, "mychart")
	if err := os.MkdirAll(dummyChartDir, 0755); err != nil {
		t.Fatalf("Failed to create dummy chart dir: %v", err)
	}
	dummyChartFile := filepath.Join(dummyChartDir, "Chart.yaml")
	chartContent := []byte("apiVersion: v2\nname: mychart\nversion: 0.1.0\nappVersion: 1.0.0\ntype: application")
	if err := os.WriteFile(dummyChartFile, chartContent, 0644); err != nil {
		t.Fatalf("Failed to write dummy Chart.yaml: %v", err)
	}
	templatesDir := filepath.Join(dummyChartDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		t.Fatalf("Failed to create dummy templates dir: %v", err)
	}
	dummyTemplateFile := filepath.Join(templatesDir, "service.yaml")
	if err := os.WriteFile(dummyTemplateFile, []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: {{ .Release.Name }}-mychart"), 0644); err != nil {
		t.Fatalf("Failed to write dummy template: %v", err)
	}

	t.Skip("InstallChart requires extensive mocking of Helm action.Install.Run() or integration testing.")
}

func TestClient_UninstallRelease(t *testing.T) {
	t.Skip("UninstallRelease requires mocking Helm action.Uninstall.Run() or integration testing.")
}

func TestClient_UpgradeRelease(t *testing.T) {
	t.Skip("UpgradeRelease requires mocking Helm action.Upgrade.Run() or integration testing.")
}

func TestClient_GetReleaseDetails(t *testing.T) {
	t.Skip("GetReleaseDetails requires mocking Helm action.Get.Run() or integration testing.")
}

func TestClient_GetReleaseHistory(t *testing.T) {
	t.Skip("GetReleaseHistory requires mocking Helm action.History.Run() or integration testing.")
}

func TestClient_AddRepository(t *testing.T) {
	tempDir := t.TempDir()
	tempRepoFile := filepath.Join(tempDir, "repositories.yaml")

	originalRepoConfig := os.Getenv("HELM_REPOSITORY_CONFIG")
	os.Setenv("HELM_REPOSITORY_CONFIG", tempRepoFile)
	defer os.Setenv("HELM_REPOSITORY_CONFIG", originalRepoConfig)
	if originalRepoConfig == "" {
		defer os.Unsetenv("HELM_REPOSITORY_CONFIG")
	}

	t.Skip("AddRepository requires mocking network calls (DownloadIndexFile) and potentially file system interactions beyond HELM_REPOSITORY_CONFIG.")
}

func TestClient_UpdateRepositories(t *testing.T) {
	tempDir := t.TempDir()
	tempRepoFile := filepath.Join(tempDir, "repositories.yaml")
	originalRepoConfig := os.Getenv("HELM_REPOSITORY_CONFIG")
	os.Setenv("HELM_REPOSITORY_CONFIG", tempRepoFile)
	defer os.Setenv("HELM_REPOSITORY_CONFIG", originalRepoConfig)
	if originalRepoConfig == "" {
		defer os.Unsetenv("HELM_REPOSITORY_CONFIG")
	}

	initialRepoContent := `
apiVersion: ""
generated: "0001-01-01T00:00:00Z"
repositories:
- name: stable
  url: https://charts.helm.sh/stable
`
	if err := os.WriteFile(tempRepoFile, []byte(initialRepoContent), 0644); err != nil {
		t.Fatalf("Failed to write initial temp repo file: %v", err)
	}

	t.Skip("UpdateRepositories requires mocking network calls (DownloadIndexFile).")
}

func TestClient_EnsureChart(t *testing.T) {
	t.Skip("EnsureChart requires mocking action.ChartPathOptions.LocateChart and potentially UpdateRepositories if the chart is not found initially.")
}
