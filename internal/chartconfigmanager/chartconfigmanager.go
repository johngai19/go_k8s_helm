package chartconfigmanager

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// VariableDefinition describes a variable found in a chart.
type VariableDefinition struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"` // Optional description
	Default     string `json:"default,omitempty" yaml:"default,omitempty"`         // Optional default value
	// FilePath string `json:"filePath,omitempty"` // Optional: File where the variable was found
	// LineNumber int    `json:"lineNumber,omitempty"` // Optional: Line number where the variable was found
}

// Product represents a pre-configured chart template.
// It typically resides as a subdirectory in the baseProductsPath.
// It can have an optional metadata file (product_meta.yaml or product_meta.json)
// to describe itself and its variables.
// The ChartPath points to the actual chart files within the product directory (e.g., productDir/chart).
// If no specific chart subdirectory is used, ChartPath can be the same as the product directory itself.
type Product struct {
	Name        string               `json:"name" yaml:"name"`                                   // Name of the product (usually the directory name)
	Description string               `json:"description,omitempty" yaml:"description,omitempty"` // Description of the product
	ChartPath   string               `json:"chartPath" yaml:"chartPath"`                         // Path to the product's underlying chart template directory
	Variables   []VariableDefinition `json:"variables,omitempty" yaml:"variables,omitempty"`     // Variables defined or discovered for this product
}

// ChartInfo holds the contents of a Chart.yaml
type ChartInfo struct {
	APIVersion  string `yaml:"apiVersion" json:"apiVersion"`
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	AppVersion  string `yaml:"appVersion,omitempty" json:"appVersion,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// Manager defines the interface for managing chart products and variable extraction/replacement.
type Manager interface {
	// ListProducts lists all available products managed by this manager.
	// Products are typically discovered from a base directory.
	ListProducts() ([]Product, error)

	// GetProduct retrieves details for a specific product by its name.
	GetProduct(productName string) (*Product, error)

	// ExtractVariablesFromPath scans a given directory (e.g., a chart path or product template path)
	// and identifies all unique @{variable} placeholders.
	ExtractVariablesFromPath(path string) ([]VariableDefinition, error)

	// InstantiateProduct takes a product name (or a direct chart path), a set of variable values,
	// and an output path. It copies the product's chart to the output path and replaces
	// all @{variable} placeholders with the provided values.
	//
	// Parameters:
	//   - productNameOrPath: Name of a defined product or direct path to a chart template.
	//   - variables: A map where keys are variable names (without @{}).
	//   - outputPath: The directory where the instantiated chart will be created.
	//   - unassignedVarAction: How to handle variables found in templates but not in the 'variables' map.
	//     Supported actions: UnassignedVarError, UnassignedVarEmpty, UnassignedVarKeep.
	//
	// Returns:
	//   - string: The absolute path to the instantiated chart.
	//   - error: If any error occurs during instantiation.
	InstantiateProduct(productNameOrPath string, variables map[string]interface{}, outputPath string, unassignedVarAction string) (string, error)

	// ValidateChartFiles checks YAML and JSON files within a given chart path for structural validity.
	ValidateChartFiles(chartPath string) error

	// DefineProduct creates a new product definition. This might involve creating a directory structure,
	// copying a base chart, and generating a metadata file.
	// Parameters:
	//   - productName: The name for the new product.
	//   - baseChartPath: Path to an existing chart to use as a template for this product.
	//   - productMetadata: Optional Product struct containing metadata (description, predefined variables) to save.
	// Returns:
	//   - error: If the product definition fails.
	DefineProduct(productName string, baseChartPath string, productMetadata *Product) error

	// GetChartInfo retrieves the Chart.yaml information for a specific product.
	GetChartInfo(productName string) (*ChartInfo, error)
}

// FileSystemProductManager implements the Manager interface using the local file system.
// It expects products to be subdirectories within a baseProductsPath.
// Each product directory is considered a product. It should contain the chart files directly
// or in a subdirectory (e.g., 'chart').
// An optional 'product_meta.yaml' or 'product_meta.json' in the product directory can provide metadata.
type FileSystemProductManager struct {
	baseProductsPath string
	log              *log.Logger // Changed to *log.Logger
}

const (
	// ProductMetaFilenameYAML is the name of the YAML metadata file for a product.
	ProductMetaFilenameYAML = "product_meta.yaml"
	// ProductMetaFilenameJSON is the name of the JSON metadata file for a product.
	ProductMetaFilenameJSON = "product_meta.json"
	// DefaultChartSubDir is a potential subdirectory within a product dir that holds the chart.
	DefaultChartSubDir = "chart"

	// UnassignedVarError causes InstantiateProduct to return an error if a variable is not found.
	UnassignedVarError = "error"
	// UnassignedVarEmpty replaces unfound variables with an empty string.
	UnassignedVarEmpty = "empty"
	// UnassignedVarKeep leaves placeholders for unfound variables.
	UnassignedVarKeep = "keep"

	defaultLogDirName = "data/logs" // Changed default log directory
	logFileName       = "chartconfigmanager.log"
)

// variableRegex is a regular expression to find @{variableName} placeholders.
// It captures the 'variableName' part.
var variableRegex = regexp.MustCompile(`@{([a-zA-Z0-9_.-]+)}`)

// NewFileSystemProductManager creates a new FileSystemProductManager.
// baseProductsPath is the root directory where product chart templates are stored.
// logDirectoryPath is the directory where log files will be stored. If empty, "logs" in the current dir is used.
func NewFileSystemProductManager(baseProductsPath string, logDirectoryPath string) (*FileSystemProductManager, error) {
	if baseProductsPath == "" {
		return nil, fmt.Errorf("baseProductsPath cannot be empty")
	}

	// Ensure the base backup path exists, create if not.
	if err := os.MkdirAll(baseProductsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base products directory %s: %w", baseProductsPath, err)
	}

	effectiveLogDirPath := logDirectoryPath
	if effectiveLogDirPath == "" {
		effectiveLogDirPath = defaultLogDirName
	}

	if err := os.MkdirAll(effectiveLogDirPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory %s: %w", effectiveLogDirPath, err)
	}

	logFilePath := filepath.Join(effectiveLogDirPath, logFileName)
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file %s: %w", logFilePath, err)
	}

	logger := log.New(logFile, "CHARTCONFIGMAN: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Printf("ChartConfigManager initialized. Logging to %s", logFilePath)

	return &FileSystemProductManager{
		baseProductsPath: baseProductsPath,
		log:              logger,
	}, nil
}

// loadProductMetadata tries to load metadata from product_meta.json or product_meta.yaml from a product's root directory.
func (m *FileSystemProductManager) loadProductMetadata(productDirPath string) (Product, error) {
	var meta Product
	metaFilePathYAML := filepath.Join(productDirPath, ProductMetaFilenameYAML)
	metaFilePathJSON := filepath.Join(productDirPath, ProductMetaFilenameJSON)

	var metaFileToLoad string

	if _, err := os.Stat(metaFilePathYAML); err == nil {
		metaFileToLoad = metaFilePathYAML
	} else if _, err := os.Stat(metaFilePathJSON); err == nil {
		metaFileToLoad = metaFilePathJSON
	}

	if metaFileToLoad != "" {
		data, err := os.ReadFile(metaFileToLoad)
		if err != nil {
			return meta, fmt.Errorf("failed to read metadata file %s: %w", metaFileToLoad, err)
		}
		if strings.HasSuffix(metaFileToLoad, ".yaml") {
			if err := yaml.Unmarshal(data, &meta); err != nil {
				return meta, fmt.Errorf("failed to unmarshal YAML metadata from %s: %w", metaFileToLoad, err)
			}
		} else {
			if err := json.Unmarshal(data, &meta); err != nil {
				return meta, fmt.Errorf("failed to unmarshal JSON metadata from %s: %w", metaFileToLoad, err)
			}
		}
	}

	// If ChartPath is not set in metadata, determine it.
	// It could be the product directory itself or a 'chart' subdirectory.
	if meta.ChartPath == "" {
		chartSubDirPath := filepath.Join(productDirPath, DefaultChartSubDir)
		if _, err := os.Stat(filepath.Join(chartSubDirPath, "Chart.yaml")); err == nil {
			meta.ChartPath = chartSubDirPath
		} else {
			// Assume productDirPath is the chart path if Chart.yaml is present there
			if _, err := os.Stat(filepath.Join(productDirPath, "Chart.yaml")); err == nil {
				meta.ChartPath = productDirPath
			} else {
				// If no Chart.yaml found, ChartPath remains empty or could be an error depending on requirements.
				// For now, we'll set it to productDirPath as a fallback if it's a directory.
				info, statErr := os.Stat(productDirPath)
				if statErr == nil && info.IsDir() {
					meta.ChartPath = productDirPath
				}
			}
		}
	}

	return meta, nil
}

// ListProducts lists all available products (subdirectories in baseProductsPath).
func (m *FileSystemProductManager) ListProducts() ([]Product, error) {
	m.log.Printf("Listing products from base path: %s", m.baseProductsPath)
	entries, err := os.ReadDir(m.baseProductsPath)
	if err != nil {
		if os.IsNotExist(err) {
			m.log.Printf("Base products path %s does not exist. Returning empty list.", m.baseProductsPath)
			return []Product{}, nil
		}
		return nil, fmt.Errorf("failed to read base products directory %s: %w", m.baseProductsPath, err)
	}

	var products []Product
	for _, entry := range entries {
		if entry.IsDir() {
			productName := entry.Name()
			productDirPath := filepath.Join(m.baseProductsPath, productName)

			meta, _ := m.loadProductMetadata(productDirPath)

			// Ensure product name is from the directory, and ChartPath is absolute
			product := Product{
				Name:        productName,
				Description: meta.Description,
				ChartPath:   meta.ChartPath, // This should be an absolute path or resolved
				Variables:   meta.Variables,
			}
			if product.ChartPath == "" || !filepath.IsAbs(product.ChartPath) {
				// If ChartPath from metadata is relative or empty, resolve it based on productDirPath
				chartSubDirPath := filepath.Join(productDirPath, DefaultChartSubDir)
				if _, err := os.Stat(filepath.Join(chartSubDirPath, "Chart.yaml")); err == nil {
					product.ChartPath = chartSubDirPath
				} else if _, err := os.Stat(filepath.Join(productDirPath, "Chart.yaml")); err == nil {
					product.ChartPath = productDirPath
				} else {
					m.log.Printf("Warning: Could not determine ChartPath for product %s. Chart.yaml not found in standard locations.", productName)
					product.ChartPath = productDirPath // Fallback
				}
			}
			// Ensure ChartPath is absolute
			if product.ChartPath != "" && !filepath.IsAbs(product.ChartPath) {
				absChartPath, absErr := filepath.Abs(product.ChartPath)
				if absErr == nil {
					product.ChartPath = absChartPath
				} else {
					m.log.Printf("Warning: Could not make ChartPath absolute for product %s: %v", productName, absErr)
				}
			}

			products = append(products, product)
		}
	}
	m.log.Printf("Found %d products.", len(products))
	return products, nil
}

// GetProduct retrieves details for a specific product.
func (m *FileSystemProductManager) GetProduct(productName string) (*Product, error) {
	m.log.Printf("Getting product details for: %s", productName)
	productDirPath := filepath.Join(m.baseProductsPath, productName)

	info, err := os.Stat(productDirPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("product '%s' not found at %s: %w", productName, productDirPath, err)
	}
	if err != nil {
		return nil, fmt.Errorf("error accessing product directory %s: %w", productDirPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("product path %s is not a directory", productDirPath)
	}

	meta, err := m.loadProductMetadata(productDirPath)
	if err != nil {
		m.log.Printf("Warning: could not load metadata for product %s: %v. Returning basic info.", productName, err)
		// Fallback to basic product info if metadata is missing but directory exists
		chartPath := filepath.Join(productDirPath, DefaultChartSubDir)
		if _, statErr := os.Stat(filepath.Join(chartPath, "Chart.yaml")); statErr != nil {
			// If 'chart' subdir doesn't have Chart.yaml, assume productDirPath is the chart path
			chartPath = productDirPath
		}
		absChartPath, absErr := filepath.Abs(chartPath)
		if absErr != nil {
			m.log.Printf("Warning: could not make fallback ChartPath absolute for product %s: %v", productName, absErr)
		} else {
			chartPath = absChartPath
		}
		return &Product{
			Name:      productName,
			ChartPath: chartPath,
		}, nil
	}

	meta.Name = productName // Ensure name is from the directory
	// Ensure ChartPath is absolute and correct if not set by metadata
	if meta.ChartPath == "" {
		chartSubDirPath := filepath.Join(productDirPath, DefaultChartSubDir)
		if _, err := os.Stat(filepath.Join(chartSubDirPath, "Chart.yaml")); err == nil {
			meta.ChartPath = chartSubDirPath
		} else if _, err := os.Stat(filepath.Join(productDirPath, "Chart.yaml")); err == nil {
			meta.ChartPath = productDirPath
		} else {
			meta.ChartPath = productDirPath // Fallback, might not be a valid chart
			m.log.Printf("Warning: ChartPath for product %s could not be definitively determined from metadata or standard locations (fallback to product dir).", productName)
		}
	}

	if !filepath.IsAbs(meta.ChartPath) {
		absChartPath, absErr := filepath.Abs(meta.ChartPath)
		if absErr == nil {
			meta.ChartPath = absChartPath
		} else {
			m.log.Printf("Warning: could not make ChartPath absolute for product %s: %v", productName, absErr)
		}
	}

	return &meta, nil
}

// ExtractVariablesFromPath scans files in a directory for @{variable} placeholders.
func (m *FileSystemProductManager) ExtractVariablesFromPath(path string) ([]VariableDefinition, error) {
	m.log.Printf("Extracting variables from path: %s", path)
	foundVars := make(map[string]bool)

	// Check if path exists and is a directory
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("path %s does not exist", path)
	}
	if err != nil {
		return nil, fmt.Errorf("error accessing path %s: %w", path, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path %s is not a directory", path)
	}

	err = filepath.WalkDir(path, func(filePath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Log and continue if possible, or return error to stop
			m.log.Printf("Error accessing %s: %v", filePath, walkErr)
			return walkErr // Stop walking on access error
		}
		if d.IsDir() {
			dirName := filepath.Base(filePath)
			if dirName == ".git" || dirName == ".idea" || dirName == ".vscode" || dirName == "node_modules" || dirName == ".DS_Store" {
				m.log.Printf("Skipping directory: %s", filePath)
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(filePath))
		skipExtensions := map[string]bool{
			".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".exe": true, ".bin": true, ".zip": true, ".tar": true, ".gz": true, ".so": true, ".dll": true, ".DS_Store": true,
		}
		if skipExtensions[ext] {
			m.log.Printf("Skipping binary-like file by extension: %s", filePath)
			return nil
		}

		contentBytes, readErr := os.ReadFile(filePath)
		if readErr != nil {
			m.log.Printf("Warning: failed to read file %s: %v. Skipping.", filePath, readErr)
			return nil // Continue with other files
		}

		if bytesContainBinary(contentBytes) {
			m.log.Printf("Skipping likely binary file (contains null bytes): %s", filePath)
			return nil
		}

		matches := variableRegex.FindAllStringSubmatch(string(contentBytes), -1)
		for _, match := range matches {
			if len(match) > 1 {
				foundVars[match[1]] = true
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", path, err)
	}

	varDefs := make([]VariableDefinition, 0, len(foundVars))
	for v := range foundVars {
		varDefs = append(varDefs, VariableDefinition{Name: v})
	}
	sort.Slice(varDefs, func(i, j int) bool {
		return varDefs[i].Name < varDefs[j].Name
	})

	m.log.Printf("Found %d unique variables in %s", len(varDefs), path)
	return varDefs, nil
}

// bytesContainBinary is a simple heuristic to detect binary content.
func bytesContainBinary(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return true // Presence of null byte often indicates binary
		}
	}
	return false
}

// InstantiateProduct copies a chart template and replaces variables.
func (m *FileSystemProductManager) InstantiateProduct(productNameOrPath string, variables map[string]interface{}, outputPath string, unassignedVarAction string) (string, error) {
	m.log.Printf("Instantiating product/chart from '%s' to '%s' with action '%s' for unassigned variables", productNameOrPath, outputPath, unassignedVarAction)

	sourcePath := productNameOrPath
	// Check if productNameOrPath is a product name or a direct path
	if !filepath.IsAbs(productNameOrPath) && !strings.Contains(productNameOrPath, string(os.PathSeparator)) {
		// Assumed to be a product name relative to baseProductsPath
		product, err := m.GetProduct(productNameOrPath)
		if err != nil {
			return "", fmt.Errorf("failed to get product '%s': %w", productNameOrPath, err)
		}
		sourcePath = product.ChartPath // This should be absolute from GetProduct
		if sourcePath == "" {
			return "", fmt.Errorf("chart path for product '%s' is not defined or could not be resolved", productNameOrPath)
		}
	} else {
		// If it looks like a path, make it absolute if it's not already
		absPath, err := filepath.Abs(productNameOrPath)
		if err != nil {
			return "", fmt.Errorf("failed to get absolute path for '%s': %w", productNameOrPath, err)
		}
		sourcePath = absPath
	}

	m.log.Printf("Resolved source path for instantiation: %s", sourcePath)
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return "", fmt.Errorf("source chart path %s does not exist or is not accessible", sourcePath)
	}

	absOutputPath, err := filepath.Abs(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to get absolute path for output %s: %w", outputPath, err)
	}

	if _, err := os.Stat(absOutputPath); err == nil {
		m.log.Printf("Output path %s exists, removing it before instantiation.", absOutputPath)
		if err := os.RemoveAll(absOutputPath); err != nil {
			return "", fmt.Errorf("failed to remove existing output directory %s: %w", absOutputPath, err)
		}
	}

	if err := os.MkdirAll(absOutputPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory %s: %w", absOutputPath, err)
	}

	err = filepath.WalkDir(sourcePath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("error during walk at %s: %w", path, walkErr)
		}

		relPath, err := filepath.Rel(sourcePath, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", path, err)
		}
		destPath := filepath.Join(absOutputPath, relPath)

		if d.IsDir() {
			dirName := filepath.Base(path)
			if dirName == ".git" || dirName == ".idea" || dirName == ".vscode" || dirName == "node_modules" || dirName == ".DS_Store" {
				m.log.Printf("Skipping directory: %s", path)
				return filepath.SkipDir
			}
			return os.MkdirAll(destPath, 0755)
		}

		ext := strings.ToLower(filepath.Ext(path))
		skipExtensions := map[string]bool{
			".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".exe": true, ".bin": true, ".zip": true, ".tar": true, ".gz": true, ".so": true, ".dll": true, ".DS_Store": true,
		}
		if skipExtensions[ext] {
			m.log.Printf("Copying binary-like file without modification: %s to %s", path, destPath)
			return copyFile(path, destPath) // copyFile is a package-level helper
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read source file %s: %w", path, err)
		}

		if bytesContainBinary(contentBytes) {
			m.log.Printf("Copying likely binary file (contains null bytes) without modification: %s to %s", path, destPath)
			return copyFile(path, destPath) // copyFile is a package-level helper
		}

		content := string(contentBytes)
		modifiedContent := variableRegex.ReplaceAllStringFunc(content, func(match string) string {
			varName := variableRegex.FindStringSubmatch(match)[1]
			if val, ok := variables[varName]; ok {
				return fmt.Sprintf("%v", val)
			}
			m.log.Printf("Warning: variable '%s' not found in defaults or overrides; using empty string", varName)
			return ""
		})

		fileInfo, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat source file %s for permissions: %w", path, err)
		}

		err = os.WriteFile(destPath, []byte(modifiedContent), fileInfo.Mode().Perm())
		if err != nil {
			return fmt.Errorf("failed to write destination file %s: %w", destPath, err)
		}
		return nil
	})

	if err != nil {
		_ = os.RemoveAll(absOutputPath)
		return "", fmt.Errorf("error during chart instantiation processing files in %s: %w", sourcePath, err)
	}

	if err := m.ValidateChartFiles(absOutputPath); err != nil {
		return absOutputPath, fmt.Errorf("chart instantiated to %s, but validation failed: %w", absOutputPath, err)
	}

	m.log.Printf("Successfully instantiated chart to %s", absOutputPath)
	return absOutputPath, nil
}

// ValidateChartFiles checks YAML and JSON files within a given chart path for structural validity.
func (m *FileSystemProductManager) ValidateChartFiles(chartPath string) error {
	m.log.Printf("Validating chart files in: %s", chartPath)
	var validationErrors []string

	err := filepath.WalkDir(chartPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("error accessing %s: %v", path, walkErr))
			return nil
		}
		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("failed to read YAML file %s: %v", path, readErr))
				return nil
			}
			var data interface{}
			if unmarshalErr := yaml.Unmarshal(content, &data); unmarshalErr != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("invalid YAML in %s: %v", path, unmarshalErr))
			}
		} else if ext == ".json" {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("failed to read JSON file %s: %v", path, readErr))
				return nil
			}
			var data interface{}
			if unmarshalErr := json.Unmarshal(content, &data); unmarshalErr != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("invalid JSON in %s: %v", path, unmarshalErr))
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking directory %s for validation: %w", chartPath, err)
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("validation failed for one or more files:\n%s", strings.Join(validationErrors, "\n"))
	}

	m.log.Printf("Chart files in %s validated successfully.", chartPath)
	return nil
}

// DefineProduct creates a new product definition directory and optionally a metadata file.
func (m *FileSystemProductManager) DefineProduct(productName string, baseChartPath string, productMetadata *Product) error {
	m.log.Printf("Defining product '%s' from base chart '%s'", productName, baseChartPath)
	if productName == "" {
		return fmt.Errorf("product name cannot be empty")
	}
	if baseChartPath == "" {
		return fmt.Errorf("base chart path cannot be empty")
	}

	productDirPath := filepath.Join(m.baseProductsPath, productName)
	if _, err := os.Stat(productDirPath); err == nil {
		return fmt.Errorf("product '%s' already exists at %s", productName, productDirPath)
	}

	if err := os.MkdirAll(productDirPath, 0755); err != nil {
		return fmt.Errorf("failed to create product directory %s: %w", productDirPath, err)
	}

	chartDestSubDir := DefaultChartSubDir
	if productMetadata != nil && productMetadata.ChartPath != "" && !filepath.IsAbs(productMetadata.ChartPath) {
		// Use the relative path from metadata if provided and it's not intended to be absolute.
		// Note: productMetadata.ChartPath here is relative to productDirPath.
		chartDestSubDir = productMetadata.ChartPath
	}
	chartDestPath := filepath.Join(productDirPath, chartDestSubDir)

	m.log.Printf("Copying base chart from %s to %s", baseChartPath, chartDestPath)
	if err := copyDirectory(baseChartPath, chartDestPath); err != nil { // copyDirectory is a package-level helper
		_ = os.RemoveAll(productDirPath)
		return fmt.Errorf("failed to copy base chart to product directory: %w", err)
	}

	finalMeta := Product{}
	if productMetadata != nil {
		finalMeta = *productMetadata
	}
	finalMeta.Name = productName

	absChartDestPath, err := filepath.Abs(chartDestPath)
	if err != nil {
		m.log.Printf("Warning: could not determine absolute path for chart destination %s: %v", chartDestPath, err)
		finalMeta.ChartPath = chartDestPath // Keep as is if abs path fails
	} else {
		finalMeta.ChartPath = absChartDestPath
	}

	metaBytes, err := yaml.Marshal(finalMeta)
	if err != nil {
		_ = os.RemoveAll(productDirPath)
		return fmt.Errorf("failed to marshal product metadata to YAML: %w", err)
	}
	metaFilePath := filepath.Join(productDirPath, ProductMetaFilenameYAML)
	if err := os.WriteFile(metaFilePath, metaBytes, 0644); err != nil {
		_ = os.RemoveAll(productDirPath)
		return fmt.Errorf("failed to write product metadata file %s: %w", metaFilePath, err)
	}
	m.log.Printf("Created product metadata file: %s", metaFilePath)

	m.log.Printf("Successfully defined product '%s' at %s", productName, productDirPath)
	return nil
}

// GetChartInfo retrieves the Chart.yaml information for a specific product.
func (m *FileSystemProductManager) GetChartInfo(productName string) (*ChartInfo, error) {
	// reuse GetProduct to resolve ChartPath
	prod, err := m.GetProduct(productName)
	if err != nil {
		return nil, err
	}
	chartYaml := filepath.Join(prod.ChartPath, "Chart.yaml")
	data, err := os.ReadFile(chartYaml)
	if err != nil {
		return nil, fmt.Errorf("failed to read Chart.yaml for %s: %w", productName, err)
	}
	var ci ChartInfo
	if err := yaml.Unmarshal(data, &ci); err != nil {
		return nil, fmt.Errorf("invalid Chart.yaml for %s: %w", productName, err)
	}
	return &ci, nil
}

// --- Helper Functions (Consider moving to a shared utility package if used elsewhere) ---

// copyFile copies a single file from src to dst.
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

	// Ensure destination directory exists
	dstDir := filepath.Dir(dst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dstDir, err)
	}

	destination, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, sourceFileStat.Mode().Perm())
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
func copyDirectory(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("failed to stat source directory %s: %w", src, err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source %s is not a directory", src)
	}

	if err := os.MkdirAll(dst, srcInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to create destination directory %s: %w", dst, err)
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("failed to read source directory %s: %w", src, err)
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		entryInfo, err := os.Stat(srcPath)
		if err != nil {
			return fmt.Errorf("failed to stat entry %s: %w", srcPath, err)
		}

		switch entryInfo.Mode() & os.ModeType {
		case os.ModeDir:
			dirName := entry.Name()
			if dirName == ".git" || dirName == ".svn" || dirName == ".hg" || dirName == ".idea" || dirName == ".vscode" || dirName == "__pycache__" || dirName == "node_modules" || dirName == ".DS_Store" {
				continue
			}
			if err := copyDirectory(srcPath, dstPath); err != nil {
				return fmt.Errorf("failed to copy subdirectory %s: %w", srcPath, err)
			}
		case os.ModeSymlink:
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

// LoadVariables reads in, in order:
//  1. defaultsFile (JSON/YAML)—if missing, ignored
//  2. overrideFile (JSON/YAML)—must exist if non-empty
//  3. database_configs[ branch ] defaults, but only if overrideFile set RDBMS_DB_CLIENT
//     and only for fields the overrideFile did NOT supply
//  4. setValues “key=val,key2=val2”
//
// It returns the final map, ready for InstantiateProduct.
func LoadVariables(defaultsFile, overrideFile, setValues string) (map[string]interface{}, error) {
	vars := make(map[string]interface{})

	// 1) load defaultsFile
	if defaultsFile != "" {
		if b, err := os.ReadFile(defaultsFile); err == nil {
			if err := json.Unmarshal(b, &vars); err != nil {
				if err2 := yaml.Unmarshal(b, &vars); err2 != nil {
					return nil, fmt.Errorf("parsing defaults %s: json=%v yaml=%v", defaultsFile, err, err2)
				}
			}
		}
		// ignore read errors here
	}

	// 2) load overrideFile and track which keys it provided
	provided := make(map[string]bool)
	if overrideFile != "" {
		b, err := os.ReadFile(overrideFile)
		if err != nil {
			return nil, fmt.Errorf("reading override %s: %w", overrideFile, err)
		}
		tmp := make(map[string]interface{})
		if err := json.Unmarshal(b, &tmp); err != nil {
			if err2 := yaml.Unmarshal(b, &tmp); err2 != nil {
				return nil, fmt.Errorf("parsing override %s: json=%v yaml=%v", overrideFile, err, err2)
			}
		}
		for k, v := range tmp {
			vars[k] = v
			provided[k] = true
		}
	}

	// 3) apply database_configs[ branch ] defaults only if user provided RDBMS_DB_CLIENT
	if provided["RDBMS_DB_CLIENT"] {
		if branch, ok := vars["RDBMS_DB_CLIENT"].(string); ok {
			if dbcfgs, ok2 := vars["database_configs"].(map[string]interface{}); ok2 {
				if defBranch, ok3 := dbcfgs[branch].(map[string]interface{}); ok3 {
					for fld, def := range defBranch {
						// only fill if overrideFile did NOT supply fld
						if !provided[fld] {
							if cur, exists := vars[fld]; !exists || cur == "" {
								vars[fld] = def
							}
						}
					}
				}
			}
		}
	}

	// 4) apply setValues
	if setValues != "" {
		for _, pair := range strings.Split(setValues, ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid set %q, want key=val", pair)
			}
			vars[kv[0]] = kv[1]
		}
	}

	return vars, nil
}

// InstantiateProductWithFiles does exactly what InstantiateProduct does,
// but it takes two files + a --set string, merges them via LoadVariables,
// then calls InstantiateProduct under the covers.
func (m *FileSystemProductManager) InstantiateProductWithFiles(
	productNameOrPath string,
	defaultsFile string,
	overrideFile string,
	setValues string,
	outputPath string,
	unassignedVarAction string,
) (string, error) {
	vars, err := LoadVariables(defaultsFile, overrideFile, setValues)
	if err != nil {
		return "", fmt.Errorf("loading variables: %w", err)
	}
	return m.InstantiateProduct(productNameOrPath, vars, outputPath, unassignedVarAction)
}
