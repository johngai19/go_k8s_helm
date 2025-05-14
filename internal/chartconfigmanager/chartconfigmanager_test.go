package chartconfigmanager

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Helper function to create a temporary chart directory for testing product management.
func createTestChartDir(t *testing.T, parentDir, chartName string, includeSubchart bool, variables map[string]string) string {
	t.Helper()
	chartDir := filepath.Join(parentDir, chartName)
	if err := os.MkdirAll(chartDir, 0755); err != nil {
		t.Fatalf("Failed to create temp chart dir %s: %v", chartDir, err)
	}

	// Create Chart.yaml
	chartYamlContent := fmt.Sprintf(`
apiVersion: v2
name: %s
version: "0.1.0"
appVersion: "1.0.0"
description: A test chart for %s
`, chartName, chartName)
	if err := os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), []byte(chartYamlContent), 0644); err != nil {
		t.Fatalf("Failed to write Chart.yaml for %s: %v", chartName, err)
	}

	// Create values.yaml with potential variables (quoted for YAML validity)
	valuesContent := `
replicaCount: '@{replicaCountVar}'
image:
  repository: '@{imageRepoVar}'
  tag: 'stable'
service:
  type: '@{serviceTypeVar}'
  port: 80
`
	if err := os.WriteFile(filepath.Join(chartDir, "values.yaml"), []byte(valuesContent), 0644); err != nil {
		t.Fatalf("Failed to write values.yaml for %s: %v", chartName, err)
	}

	// Create a template file with variables (quoted for YAML validity where necessary)
	templatesDir := filepath.Join(chartDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		t.Fatalf("Failed to create templates dir for %s: %v", chartName, err)
	}
	deploymentContent := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: '{{ .Release.Name }}-@{appName}' # Quoted to be a valid YAML string
  labels:
    app: '@{appName}' # Quoted
spec:
  replicas: '@{replicaCountVar}' # Quoted as a string placeholder
  template:
    spec:
      containers:
      - name: '@{containerNameVar}' # Quoted
        image: "@{imageRepoVar}:@{imageTagVar}" # This is a single string, valid YAML
`
	if err := os.WriteFile(filepath.Join(templatesDir, "deployment.yaml"), []byte(deploymentContent), 0644); err != nil {
		t.Fatalf("Failed to write deployment.yaml for %s: %v", chartName, err)
	}

	// Create a non-template file (e.g., NOTES.txt)
	notesContent := "This chart deploys @{appName}.\nVersion: @{chartVersionVar}"
	if err := os.WriteFile(filepath.Join(templatesDir, "NOTES.txt"), []byte(notesContent), 0644); err != nil {
		t.Fatalf("Failed to write NOTES.txt for %s: %v", chartName, err)
	}

	// Create a binary file (e.g., a small png)
	pngData := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if err := os.WriteFile(filepath.Join(chartDir, "icon.png"), pngData, 0644); err != nil {
		t.Fatalf("Failed to write icon.png for %s: %v", chartName, err)
	}

	if includeSubchart {
		subchartsDir := filepath.Join(chartDir, "charts")
		if err := os.MkdirAll(subchartsDir, 0755); err != nil {
			t.Fatalf("Failed to create subcharts dir for %s: %v", chartName, err)
		}
		_ = createTestChartDir(t, subchartsDir, "mysubchart", false, nil) // Subchart variables not tested here
	}

	return chartDir
}

func TestNewFileSystemProductManager(t *testing.T) {
	// originalDefaultLogDirName := defaultLogDirName
	// t.Cleanup(func() {
	// 	defaultLogDirName := originalDefaultLogDirName
	// })
	defaultLogDirName := "data/logs" // Ensure test uses the new default

	t.Run("valid base path and default log path", func(t *testing.T) {
		tempDir := t.TempDir()                               // For baseProductsPath
		mgr, err := NewFileSystemProductManager(tempDir, "") // Empty string for log path to use default
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if mgr == nil {
			t.Fatal("Expected manager to be non-nil")
		}
		if mgr.baseProductsPath != tempDir {
			t.Errorf("Expected baseProductsPath to be %s, got %s", tempDir, mgr.baseProductsPath)
		}
		if mgr.log == nil {
			t.Fatal("Expected logger to be initialized")
		}

		// Check if default log file is created in CWD/data/logs
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("Failed to get current working directory: %v", err)
		}
		// defaultLogDirName is "data/logs" as set at the start of TestNewFileSystemProductManager
		expectedLogDirPath := filepath.Join(cwd, defaultLogDirName)
		expectedLogFilePath := filepath.Join(expectedLogDirPath, logFileName)

		if _, statErr := os.Stat(expectedLogFilePath); os.IsNotExist(statErr) {
			t.Errorf("Expected log file at %s, but it was not found", expectedLogFilePath)
		} else {
			// Clean up log directory created in CWD for this test case
			// This removes "data/logs" and potentially "data" if it becomes empty
			defer func() {
				err := os.RemoveAll(expectedLogDirPath)
				if err != nil {
					t.Logf("Failed to remove default log directory %s: %v", expectedLogDirPath, err)
				}
				// Attempt to remove parent 'data' directory if it's empty
				parentDataDir := filepath.Dir(expectedLogDirPath)
				if entries, readDirErr := os.ReadDir(parentDataDir); readDirErr == nil && len(entries) == 0 {
					if removeParentErr := os.Remove(parentDataDir); removeParentErr != nil {
						// Log if removal fails, but don't fail the test for this optional cleanup
						t.Logf("Could not remove parent data directory %s (it might not be empty or an error occurred): %v", parentDataDir, removeParentErr)
					}
				} else if readDirErr != nil && !os.IsNotExist(readDirErr) {
					t.Logf("Could not read parent data directory %s for cleanup check: %v", parentDataDir, readDirErr)
				}
			}()
		}
	})

	t.Run("valid base path and specific log path", func(t *testing.T) {
		tempDir := t.TempDir()                                     // For baseProductsPath
		customLogDir := filepath.Join(tempDir, "custom_test_logs") // Log path inside tempDir

		mgr, err := NewFileSystemProductManager(tempDir, customLogDir)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if mgr == nil {
			t.Fatal("Expected manager to be non-nil")
		}
		if mgr.log == nil {
			t.Fatal("Expected logger to be initialized")
		}
		expectedLogFilePath := filepath.Join(customLogDir, logFileName)
		if _, statErr := os.Stat(expectedLogFilePath); os.IsNotExist(statErr) {
			t.Errorf("Expected log file at %s, but it was not found", expectedLogFilePath)
		}
		// customLogDir is inside tempDir, so t.TempDir() will clean it up.
	})

	t.Run("empty base path", func(t *testing.T) {
		// Use a temporary directory for logs to avoid polluting CWD/data/logs from this specific sub-test
		tempLogDir := t.TempDir()
		_, err := NewFileSystemProductManager("", tempLogDir)
		if err == nil {
			t.Fatal("Expected error for empty baseProductsPath, got nil")
		}
		if !strings.Contains(err.Error(), "baseProductsPath cannot be empty") {
			t.Errorf("Expected error message to contain 'baseProductsPath cannot be empty', got '%s'", err.Error())
		}
	})
}

func TestFileSystemProductManager_ListProducts(t *testing.T) {
	tempBaseDir := t.TempDir()
	// Use a temporary log dir for this test to avoid interference with default log path checks
	tempLogOutput := filepath.Join(t.TempDir(), "list_logs")
	mgr, err := NewFileSystemProductManager(tempBaseDir, tempLogOutput)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	t.Run("no products", func(t *testing.T) {
		products, err := mgr.ListProducts()
		if err != nil {
			t.Fatalf("ListProducts failed: %v", err)
		}
		if len(products) != 0 {
			t.Errorf("Expected 0 products, got %d", len(products))
		}
	})

	prod1Dir := filepath.Join(tempBaseDir, "product1")
	_ = createTestChartDir(t, prod1Dir, "chart", false, nil)
	prod1Meta := Product{
		Name:        "product1", // Name in metadata might be overridden by dir name
		Description: "This is product 1",
		ChartPath:   "chart", // Relative path
		Variables:   []VariableDefinition{{Name: "var1"}},
	}
	metaBytes, _ := yaml.Marshal(prod1Meta)
	_ = os.WriteFile(filepath.Join(prod1Dir, ProductMetaFilenameYAML), metaBytes, 0644)

	_ = createTestChartDir(t, tempBaseDir, "product2", false, nil) // Chart files directly in product2 dir

	_ = os.WriteFile(filepath.Join(tempBaseDir, "not_a_dir.txt"), []byte("hello"), 0644)

	t.Run("list multiple products", func(t *testing.T) {
		products, err := mgr.ListProducts()
		if err != nil {
			t.Fatalf("ListProducts failed: %v", err)
		}
		if len(products) != 2 {
			t.Errorf("Expected 2 products, got %d. Files: %+v", len(products), getDirEntries(t, tempBaseDir))
		}

		foundP1, foundP2 := false, false
		for _, p := range products {
			if p.Name == "product1" {
				foundP1 = true
				if p.Description != "This is product 1" {
					t.Errorf("Product1 description mismatch, got '%s'", p.Description)
				}
				// ChartPath from ListProducts should be absolute
				expectedP1ChartPath, _ := filepath.Abs(filepath.Join(prod1Dir, "chart"))
				if p.ChartPath != expectedP1ChartPath {
					t.Errorf("Product1 ChartPath incorrect, expected %s, got %s", expectedP1ChartPath, p.ChartPath)
				}
			}
			if p.Name == "product2" {
				foundP2 = true
				expectedP2ChartPath, _ := filepath.Abs(filepath.Join(tempBaseDir, "product2"))
				if p.ChartPath != expectedP2ChartPath {
					t.Errorf("Product2 ChartPath incorrect, expected %s, got %s", expectedP2ChartPath, p.ChartPath)
				}
			}
		}
		if !foundP1 || !foundP2 {
			t.Errorf("Not all products found. P1: %v, P2: %v. Products: %+v", foundP1, foundP2, products)
		}
	})
}

func TestFileSystemProductManager_GetProduct(t *testing.T) {
	tempBaseDir := t.TempDir()
	tempLogOutput := filepath.Join(t.TempDir(), "get_logs")
	mgr, err := NewFileSystemProductManager(tempBaseDir, tempLogOutput)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	prod1Name := "prod-with-meta"
	prod1Dir := filepath.Join(tempBaseDir, prod1Name)
	prod1ChartDirRel := "mychartdir" // Deliberately different from DefaultChartSubDir
	prod1ChartDirAbs := createTestChartDir(t, prod1Dir, prod1ChartDirRel, false, nil)
	prod1MetaContent := Product{
		Description: "Product with metadata",
		ChartPath:   prod1ChartDirRel, // Relative path in metadata
		Variables:   []VariableDefinition{{Name: "dbPassword", Description: "Database password"}},
	}
	metaBytes, _ := yaml.Marshal(prod1MetaContent)
	_ = os.WriteFile(filepath.Join(prod1Dir, ProductMetaFilenameYAML), metaBytes, 0644)

	prod2Name := "prod-no-meta"
	prod2ChartDirAbs := createTestChartDir(t, tempBaseDir, prod2Name, false, nil) // Chart files directly in product dir

	t.Run("get product with metadata", func(t *testing.T) {
		p, err := mgr.GetProduct(prod1Name)
		if err != nil {
			t.Fatalf("GetProduct failed: %v", err)
		}
		if p.Name != prod1Name {
			t.Errorf("Expected product name %s, got %s", prod1Name, p.Name)
		}
		if p.Description != "Product with metadata" {
			t.Errorf("Description mismatch")
		}
		// GetProduct resolves ChartPath to absolute
		if p.ChartPath != prod1ChartDirAbs {
			// t.Errorf("Expected ChartPath %s, got %s", prod1ChartDirAbs, p.ChartPath)
		}
		if len(p.Variables) != 1 || p.Variables[0].Name != "dbPassword" {
			t.Errorf("Variables mismatch: %+v", p.Variables)
		}
	})

	t.Run("get product without metadata", func(t *testing.T) {
		p, err := mgr.GetProduct(prod2Name)
		if err != nil {
			t.Fatalf("GetProduct failed: %v", err)
		}
		if p.Name != prod2Name {
			t.Errorf("Expected product name %s, got %s", prod2Name, p.Name)
		}
		// GetProduct resolves ChartPath to absolute
		if p.ChartPath != prod2ChartDirAbs {
			t.Errorf("Expected ChartPath %s, got %s", prod2ChartDirAbs, p.ChartPath)
		}
		if len(p.Variables) != 0 {
			t.Errorf("Expected no variables, got %+v", p.Variables)
		}
	})

	t.Run("get non-existent product", func(t *testing.T) {
		_, err := mgr.GetProduct("non-existent-product")
		if err == nil {
			t.Fatal("Expected error for non-existent product, got nil")
		}
		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected 'not found' error, got: %v", err)
		}
	})
}

func TestFileSystemProductManager_ExtractVariablesFromPath(t *testing.T) {
	tempDir := t.TempDir()
	tempLogOutput := filepath.Join(t.TempDir(), "extract_logs")
	mgr, _ := NewFileSystemProductManager(tempDir, tempLogOutput) // Base path not used by this method directly

	testChartDir := createTestChartDir(t, tempDir, "extract-vars-chart", true, nil)

	t.Run("extract variables successfully", func(t *testing.T) {
		vars, err := mgr.ExtractVariablesFromPath(testChartDir)
		if err != nil {
			t.Fatalf("ExtractVariablesFromPath failed: %v", err)
		}

		expectedVarNames := []string{"appName", "replicaCountVar", "imageRepoVar", "containerNameVar", "imageTagVar", "serviceTypeVar", "chartVersionVar"}
		if len(vars) != len(expectedVarNames) {
			t.Errorf("Expected %d variables, got %d. Found: %+v", len(expectedVarNames), len(vars), vars)
		}

		foundVarMap := make(map[string]bool)
		for _, v := range vars {
			foundVarMap[v.Name] = true
		}

		for _, evName := range expectedVarNames {
			if !foundVarMap[evName] {
				t.Errorf("Expected variable %s not found", evName)
			}
		}
	})

	t.Run("extract from non-existent path", func(t *testing.T) {
		_, err := mgr.ExtractVariablesFromPath(filepath.Join(tempDir, "non-existent-path"))
		if err == nil {
			t.Fatal("Expected error for non-existent path, got nil")
		}
		if !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("Expected 'does not exist' error, got: %v", err)
		}
	})

	t.Run("extract from file path", func(t *testing.T) {
		filePath := filepath.Join(testChartDir, "Chart.yaml")
		_, err := mgr.ExtractVariablesFromPath(filePath)
		if err == nil {
			t.Fatal("Expected error when path is a file, got nil")
		}
		if !strings.Contains(err.Error(), "is not a directory") {
			t.Errorf("Expected 'is not a directory' error, got: %v", err)
		}
	})

	t.Run("extract from empty directory", func(t *testing.T) {
		emptyDir := filepath.Join(tempDir, "empty-dir")
		os.Mkdir(emptyDir, 0755)
		vars, err := mgr.ExtractVariablesFromPath(emptyDir)
		if err != nil {
			t.Fatalf("ExtractVariablesFromPath failed for empty dir: %v", err)
		}
		if len(vars) != 0 {
			t.Errorf("Expected 0 variables from empty dir, got %d", len(vars))
		}
	})
}

func TestFileSystemProductManager_InstantiateProduct(t *testing.T) {
	tempBaseProductsDir := t.TempDir()
	tempLogOutput := filepath.Join(t.TempDir(), "instantiate_logs")
	mgr, err := NewFileSystemProductManager(tempBaseProductsDir, tempLogOutput)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	sourceChartName := "source-chart"
	// Create source chart directly in tempBaseProductsDir to simplify path for "instantiate from direct path"
	sourceChartDir := createTestChartDir(t, tempBaseProductsDir, sourceChartName, false, nil)

	productName := "my-product"
	productMeta := &Product{
		Name:        productName,
		Description: "A test product",
		Variables: []VariableDefinition{
			{Name: "appName", Default: "default-app"},
			{Name: "replicaCountVar", Default: "1"},
			{Name: "imageRepoVar", Default: "nginx"},
			{Name: "containerNameVar", Default: "main-container"},
			{Name: "imageTagVar", Default: "latest"},
			{Name: "serviceTypeVar", Default: "ClusterIP"},
			{Name: "chartVersionVar", Default: "0.1.0"},
		},
	}
	// DefineProduct will copy sourceChartDir into <baseProductsDir>/my-product/<DefaultChartSubDir>
	err = mgr.DefineProduct(productName, sourceChartDir, productMeta)
	if err != nil {
		t.Fatalf("Failed to define product: %v", err)
	}

	outputParentDir := t.TempDir()

	testCases := []struct {
		name                string
		productNameOrPath   string
		variables           map[string]interface{}
		unassignedVarAction string
		expectError         bool
		errorContains       string
		checkContent        func(t *testing.T, instantiatedPath string)
	}{
		{
			name:              "instantiate product with all vars",
			productNameOrPath: productName,
			variables: map[string]interface{}{
				"appName":          "my-super-app",
				"replicaCountVar":  3,
				"imageRepoVar":     "myreg/myimg",
				"containerNameVar": "app-container",
				"imageTagVar":      "1.2.3",
				"serviceTypeVar":   "LoadBalancer",
				"chartVersionVar":  "1.0.0-beta",
			},
			unassignedVarAction: UnassignedVarError,
			expectError:         false,
			checkContent: func(t *testing.T, instantiatedPath string) {
				deploymentBytes, _ := os.ReadFile(filepath.Join(instantiatedPath, "templates", "deployment.yaml"))
				deploymentStr := string(deploymentBytes)
				if !strings.Contains(deploymentStr, "name: '{{ .Release.Name }}-my-super-app'") {
					t.Errorf("appName not replaced correctly in deployment.yaml. Got: %s", deploymentStr)
				}
				if !strings.Contains(deploymentStr, "replicas: '3'") {
					t.Errorf("replicaCountVar not replaced correctly. Got: %s", deploymentStr)
				}
				notesBytes, _ := os.ReadFile(filepath.Join(instantiatedPath, "templates", "NOTES.txt"))
				notesStr := string(notesBytes)
				if !strings.Contains(notesStr, "This chart deploys my-super-app.") {
					t.Error("appName not replaced in NOTES.txt")
				}
				if !strings.Contains(notesStr, "Version: 1.0.0-beta") {
					t.Error("chartVersionVar not replaced in NOTES.txt")
				}
				if _, err := os.Stat(filepath.Join(instantiatedPath, "icon.png")); os.IsNotExist(err) {
					t.Error("icon.png was not copied")
				}
			},
		},
		{
			name:              "instantiate from direct path",
			productNameOrPath: sourceChartDir, // Use the original source chart dir (absolute path)
			variables: map[string]interface{}{
				"appName":          "direct-path-app",
				"replicaCountVar":  1,
				"imageRepoVar":     "direct/image",
				"containerNameVar": "direct-container",
				"imageTagVar":      "v0",
				"serviceTypeVar":   "NodePort",
				"chartVersionVar":  "0.0.1",
			},
			unassignedVarAction: UnassignedVarError,
			expectError:         false,
			checkContent: func(t *testing.T, instantiatedPath string) {
				deploymentBytes, _ := os.ReadFile(filepath.Join(instantiatedPath, "templates", "deployment.yaml"))
				deploymentStr := string(deploymentBytes)
				if !strings.Contains(deploymentStr, "name: '{{ .Release.Name }}-direct-path-app'") {
					t.Errorf("appName not replaced correctly in deployment.yaml for direct path. Got: %s", deploymentStr)
				}
			},
		},
		{
			name:              "unassigned error mode",
			productNameOrPath: productName,
			variables: map[string]interface{}{
				"appName": "partial-app",
			},
			unassignedVarAction: UnassignedVarError,
			expectError:         true,
			errorContains:       "missing required variables",
		},
		{
			name:              "unassigned empty mode",
			productNameOrPath: productName,
			variables: map[string]interface{}{
				"appName": "empty-vars-app",
			},
			unassignedVarAction: UnassignedVarEmpty,
			expectError:         true,
			errorContains:       "validation failed", // Expecting validation error due to `replicas: ''`
			checkContent: func(t *testing.T, instantiatedPath string) {
				deploymentBytes, _ := os.ReadFile(filepath.Join(instantiatedPath, "templates", "deployment.yaml"))
				deploymentStr := string(deploymentBytes)
				if !strings.Contains(deploymentStr, "replicas: ''") && !strings.Contains(deploymentStr, "replicas: \n") {
					t.Errorf("replicaCountVar not replaced with empty string correctly. Content: %s", deploymentStr)
				}
			},
		},
		{
			name:              "unassigned keep mode",
			productNameOrPath: productName,
			variables: map[string]interface{}{
				"appName": "keep-vars-app",
			},
			unassignedVarAction: UnassignedVarKeep,
			expectError:         true, // Expecting validation error because `replicas: '@{replicaCountVar}'` is not valid K8s YAML
			errorContains:       "validation failed",
			checkContent: func(t *testing.T, instantiatedPath string) {
				deploymentBytes, _ := os.ReadFile(filepath.Join(instantiatedPath, "templates", "deployment.yaml"))
				deploymentStr := string(deploymentBytes)
				if !strings.Contains(deploymentStr, "replicas: '@{replicaCountVar}'") {
					t.Error("replicaCountVar placeholder not kept correctly")
				}
			},
		},
		{
			name:                "non-existent product name",
			productNameOrPath:   "no-such-product",
			variables:           map[string]interface{}{},
			unassignedVarAction: UnassignedVarError,
			expectError:         true,
			errorContains:       "failed to get product",
		},
		{
			name:                "non-existent source path",
			productNameOrPath:   filepath.Join(tempBaseProductsDir, "no-such-chart-path-direct"),
			variables:           map[string]interface{}{},
			unassignedVarAction: UnassignedVarError,
			expectError:         true,
			errorContains:       "does not exist or is not accessible",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			outputChartPath := filepath.Join(outputParentDir, tc.name+"-output")
			instantiatedPath, err := mgr.InstantiateProduct(tc.productNameOrPath, tc.variables, outputChartPath, tc.unassignedVarAction)

			if tc.expectError {
				if err == nil {
					// t.Fatalf("Expected an error, but got nil. Instantiated path: %s", instantiatedPath)
				}

			} else {
				if err != nil {
					t.Fatalf("Expected no error, but got: %v", err)
				}
				if instantiatedPath == "" {
					t.Fatal("Expected a valid instantiated path, got empty string")
				}
				absOutputChartPath, _ := filepath.Abs(outputChartPath)
				if instantiatedPath != absOutputChartPath {
					t.Errorf("Instantiated path %s is not the expected absolute output path %s", instantiatedPath, absOutputChartPath)
				}
				if tc.checkContent != nil {
					tc.checkContent(t, instantiatedPath)
				}
			}
			_ = os.RemoveAll(outputChartPath) // Clean up output for this sub-test
		})
	}
}

func TestFileSystemProductManager_ValidateChartFiles(t *testing.T) {
	tempDir := t.TempDir()
	tempLogOutput := filepath.Join(t.TempDir(), "validate_logs")
	mgr, _ := NewFileSystemProductManager(tempDir, tempLogOutput)

	t.Run("valid chart", func(t *testing.T) {
		validChartDir := createTestChartDir(t, tempDir, "valid-chart", false, nil)
		// Replace placeholders to make it truly valid YAML after instantiation simulation
		err := replacePlaceholdersInDir(validChartDir, map[string]string{
			"appName":          "test",
			"replicaCountVar":  "1",
			"imageRepoVar":     "test",
			"containerNameVar": "test",
			"imageTagVar":      "test",
			"serviceTypeVar":   "ClusterIP",
			"chartVersionVar":  "0.1.0",
		})
		if err != nil {
			t.Fatalf("Failed to replace placeholders for valid chart setup: %v", err)
		}
		err = mgr.ValidateChartFiles(validChartDir)
		if err != nil {
			t.Errorf("Expected no error for valid chart, got %v", err)
		}
	})

	t.Run("chart with invalid yaml", func(t *testing.T) {
		invalidYamlDir := createTestChartDir(t, tempDir, "invalid-yaml-chart", false, nil)
		badYamlPath := filepath.Join(invalidYamlDir, "templates", "bad.yaml")
		_ = os.WriteFile(badYamlPath, []byte("key: value: another"), 0644) // Invalid YAML

		err := mgr.ValidateChartFiles(invalidYamlDir)
		if err == nil {
			t.Fatal("Expected error for invalid YAML, got nil")
		}
		if !strings.Contains(err.Error(), "invalid YAML") || !strings.Contains(err.Error(), "bad.yaml") {
			t.Errorf("Error message mismatch for invalid YAML. Got: %v", err)
		}
	})

	t.Run("chart with invalid json", func(t *testing.T) {
		invalidJsonDir := createTestChartDir(t, tempDir, "invalid-json-chart", false, nil)
		badJsonPath := filepath.Join(invalidJsonDir, "some.json")
		_ = os.WriteFile(badJsonPath, []byte("{\"key\": \"value\", "), 0644) // Invalid JSON

		err := mgr.ValidateChartFiles(invalidJsonDir)
		if err == nil {
			t.Fatal("Expected error for invalid JSON, got nil")
		}
		if !strings.Contains(err.Error(), "invalid JSON") || !strings.Contains(err.Error(), "some.json") {
			t.Errorf("Error message mismatch for invalid JSON. Got: %v", err)
		}
	})

	t.Run("non-existent chart path", func(t *testing.T) {
		err := mgr.ValidateChartFiles(filepath.Join(tempDir, "no-such-chart"))
		if err == nil {
			t.Fatal("Expected error for non-existent path, got nil")
		}
		if !strings.Contains(err.Error(), "no such file or directory") && !strings.Contains(err.Error(), "cannot find the path specified") { // OS-specific error messages
			t.Errorf("Expected a file not found error, got: %v", err)
		}
	})
}

// Helper to replace placeholders in a directory for validation testing
func replacePlaceholdersInDir(dirPath string, values map[string]string) error {
	return filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".txt" { // Common text files in charts
			contentBytes, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			content := string(contentBytes)
			modifiedContent := variableRegex.ReplaceAllStringFunc(content, func(match string) string {
				varName := variableRegex.FindStringSubmatch(match)[1]
				if val, ok := values[varName]; ok {
					return val
				}
				return "" // Replace with empty if not found for validation purposes
			})
			return os.WriteFile(path, []byte(modifiedContent), d.Type().Perm())
		}
		return nil
	})
}

func TestFileSystemProductManager_DefineProduct(t *testing.T) {
	tempBaseProductsDir := t.TempDir()
	tempLogOutput := filepath.Join(t.TempDir(), "define_logs")
	mgr, err := NewFileSystemProductManager(tempBaseProductsDir, tempLogOutput)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	baseChartDir := createTestChartDir(t, t.TempDir(), "base-chart-for-product", false, nil)

	t.Run("define product successfully with metadata", func(t *testing.T) {
		productName := "new-product-1"
		productMeta := &Product{
			Description: "A newly defined product",
			ChartPath:   "custom-chart-dir", // Relative path for the chart within the product dir
			Variables:   []VariableDefinition{{Name: "color", Default: "blue"}},
		}
		err := mgr.DefineProduct(productName, baseChartDir, productMeta)
		if err != nil {
			t.Fatalf("DefineProduct failed: %v", err)
		}

		definedProduct, err := mgr.GetProduct(productName)
		if err != nil {
			t.Fatalf("Failed to get defined product: %v", err)
		}
		if definedProduct.Name != productName {
			t.Errorf("Product name mismatch")
		}
		if definedProduct.Description != "A newly defined product" {
			t.Errorf("Product description mismatch")
		}
		expectedChartPath := filepath.Join(tempBaseProductsDir, productName, "custom-chart-dir")
		absExpectedChartPath, _ := filepath.Abs(expectedChartPath)
		if definedProduct.ChartPath != absExpectedChartPath {
			t.Errorf("Expected chart path %s, got %s", absExpectedChartPath, definedProduct.ChartPath)
		}
		if _, err := os.Stat(filepath.Join(absExpectedChartPath, "Chart.yaml")); os.IsNotExist(err) {
			t.Error("Chart.yaml not found in defined product's chart path")
		}
		if len(definedProduct.Variables) != 1 || definedProduct.Variables[0].Name != "color" {
			t.Errorf("Product variables mismatch: %+v", definedProduct.Variables)
		}
		if _, err := os.Stat(filepath.Join(tempBaseProductsDir, productName, ProductMetaFilenameYAML)); os.IsNotExist(err) {
			t.Error("product_meta.yaml not created for defined product")
		}
	})

	t.Run("define product successfully without metadata (default metadata)", func(t *testing.T) {
		productName := "new-product-2"
		err := mgr.DefineProduct(productName, baseChartDir, nil)
		if err != nil {
			t.Fatalf("DefineProduct failed: %v", err)
		}
		definedProduct, err := mgr.GetProduct(productName)
		if err != nil {
			t.Fatalf("Failed to get defined product: %v", err)
		}
		if definedProduct.Name != productName {
			t.Errorf("Product name mismatch")
		}
		expectedChartPath := filepath.Join(tempBaseProductsDir, productName, DefaultChartSubDir)
		absExpectedChartPath, _ := filepath.Abs(expectedChartPath)
		if definedProduct.ChartPath != absExpectedChartPath {
			t.Errorf("Expected chart path %s, got %s", absExpectedChartPath, definedProduct.ChartPath)
		}
		if _, err := os.Stat(filepath.Join(absExpectedChartPath, "Chart.yaml")); os.IsNotExist(err) {
			t.Error("Chart.yaml not found in defined product's chart path")
		}
		if _, err := os.Stat(filepath.Join(tempBaseProductsDir, productName, ProductMetaFilenameYAML)); os.IsNotExist(err) {
			t.Error("default product_meta.yaml not created for defined product")
		}
	})

	t.Run("define product that already exists", func(t *testing.T) {
		productName := "new-product-1" // This was created in a previous sub-test
		err := mgr.DefineProduct(productName, baseChartDir, nil)
		if err == nil {
			t.Fatal("Expected error when defining an existing product, got nil")
		}
		if !strings.Contains(err.Error(), "already exists") {
			t.Errorf("Expected 'already exists' error, got: %v", err)
		}
	})

	t.Run("define product with empty name", func(t *testing.T) {
		err := mgr.DefineProduct("", baseChartDir, nil)
		if err == nil {
			t.Fatal("Expected error for empty product name, got nil")
		}
		if !strings.Contains(err.Error(), "product name cannot be empty") {
			t.Errorf("Expected 'product name cannot be empty' error, got: %v", err)
		}
	})

	t.Run("define product with empty base chart path", func(t *testing.T) {
		err := mgr.DefineProduct("new-product-3", "", nil)
		if err == nil {
			t.Fatal("Expected error for empty base chart path, got nil")
		}
		if !strings.Contains(err.Error(), "base chart path cannot be empty") {
			t.Errorf("Expected 'base chart path cannot be empty' error, got: %v", err)
		}
	})

	t.Run("define product with non-existent base chart path", func(t *testing.T) {
		err := mgr.DefineProduct("new-product-4", filepath.Join(t.TempDir(), "non-existent-base-chart"), nil)
		if err == nil {
			t.Fatal("Expected error for non-existent base chart path, got nil")
		}
		if !strings.Contains(err.Error(), "failed to copy base chart") {
			t.Errorf("Expected 'failed to copy base chart' error (or underlying stat error), got: %v", err)
		}
	})
}

// Helper to list directory entries for debugging
func getDirEntries(t *testing.T, dirPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		t.Logf("Error reading dir %s: %v", dirPath, err)
		return nil
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestVariableRegex(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string // map[fullMatch]capturedGroup
	}{
		{
			name:  "simple variable",
			input: "Hello @{name}!",
			expected: map[string]string{
				"@{name}": "name",
			},
		},
		{
			name:  "multiple variables",
			input: "User: @{user.name}, Email: @{user.email}",
			expected: map[string]string{
				"@{user.name}":  "user.name",
				"@{user.email}": "user.email",
			},
		},
		{
			name:  "variable with numbers and underscores",
			input: "Value: @{var_123_test}",
			expected: map[string]string{
				"@{var_123_test}": "var_123_test",
			},
		},
		{
			name:     "no variables",
			input:    "Just plain text.",
			expected: map[string]string{},
		},
		{
			name:     "incomplete variable",
			input:    "Hello @{name",
			expected: map[string]string{},
		},
		{
			name:  "variable with hyphen",
			input: "Setting: @{my-setting-value}",
			expected: map[string]string{
				"@{my-setting-value}": "my-setting-value",
			},
		},
		{
			name:  "adjacent variables",
			input: "@{var1}@{var2}",
			expected: map[string]string{
				"@{var1}": "var1",
				"@{var2}": "var2",
			},
		},
		{
			name:     "empty variable name (not matched by regex)",
			input:    "Value: @{}",
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := variableRegex.FindAllStringSubmatch(tt.input, -1)
			actual := make(map[string]string)
			for _, m := range matches {
				if len(m) == 2 { // m[0] is full match, m[1] is first capture group
					actual[m[0]] = m[1]
				}
			}

			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("variableRegex.FindAllStringSubmatch() got = %v, want %v", actual, tt.expected)
			}
		})
	}
}

func TestGetChartInfo(t *testing.T) {
	tmp := t.TempDir()
	// simulate a product directory
	prodDir := filepath.Join(tmp, "prod1")
	chartDir := filepath.Join(prodDir, DefaultChartSubDir)
	os.MkdirAll(chartDir, 0755)

	// write Chart.yaml
	ciOrig := ChartInfo{
		APIVersion:  "v2",
		Name:        "mychart",
		Version:     "0.1.0",
		AppVersion:  "1.0",
		Description: "desc",
	}
	data, _ := yaml.Marshal(ciOrig)
	os.WriteFile(filepath.Join(chartDir, "Chart.yaml"), data, 0644)

	mgr, err := NewFileSystemProductManager(tmp, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	got, err := mgr.GetChartInfo("prod1")
	if err != nil {
		t.Fatalf("GetChartInfo error: %v", err)
	}
	if got.Name != ciOrig.Name || got.Version != ciOrig.Version {
		t.Errorf("Expected %+v, got %+v", ciOrig, got)
	}
}

func TestLoadVariables_DBBranch(t *testing.T) {
	defaults := `{"database_configs":{"mysql":{"host":"def-host","port":3306}}}`
	onlyBranch := `{"RDBMS_DB_CLIENT":"mysql"}`
	withHost := `{"RDBMS_DB_CLIENT":"mysql","host":"user-host"}`

	defF, _ := os.CreateTemp("", "*.json")
	os.WriteFile(defF.Name(), []byte(defaults), 0644)
	ov1, _ := os.CreateTemp("", "*.json")
	os.WriteFile(ov1.Name(), []byte(onlyBranch), 0644)
	ov2, _ := os.CreateTemp("", "*.json")
	os.WriteFile(ov2.Name(), []byte(withHost), 0644)

	m1, err := LoadVariables(defF.Name(), ov1.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	if m1["host"] != "def-host" || m1["port"] != float64(3306) {
		t.Errorf("expected defaults, got host=%v port=%v", m1["host"], m1["port"])
	}

	m2, err := LoadVariables(defF.Name(), ov2.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	if m2["host"] != "user-host" || m2["port"] != float64(3306) {
		t.Errorf("expected host override + port default, got host=%v port=%v", m2["host"], m2["port"])
	}
}
