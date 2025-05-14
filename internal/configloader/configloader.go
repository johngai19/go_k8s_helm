// Package configloader provides utilities to load and parse application configurations
// from multiple .conf files. It supports variable substitution (e.g., ${VAR} or $VAR),
// structured grouping of database configurations, and customizable file sources.
// Configuration values are parsed with specific handling for quoted strings,
// unquoted strings (ending at the first space or comment), and comments.
package configloader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	logPrefixDefault = "[configloader] "
)

// logMessage prints an informational message to stderr.
func logMessage(msg string) {
	fmt.Fprintln(os.Stderr, logPrefixDefault+msg)
}

// logWarning prints a warning message to stderr.
func logWarning(msg string) {
	fmt.Fprintln(os.Stderr, logPrefixDefault+"[WARNING] "+msg)
}

// logError prints an error message to stderr (used internally before returning an error).
func logError(msg string) {
	fmt.Fprintln(os.Stderr, logPrefixDefault+"[ERROR] "+msg)
}

// Options defines the parameters for loading configurations.
type Options struct {
	// BasePath is the root directory for default file discovery or for resolving relative paths
	// in CustomFilePaths. Defaults to the current working directory if empty.
	BasePath string

	// CustomFilePaths is a list of specific files or directories to parse.
	// If a path is a directory, all .conf files within it will be parsed (non-recursively, sorted alphabetically).
	// If empty, default discovery logic is used (see DiscoverDefaultPaths).
	// Parsing order: files are processed in the order they appear in this list.
	// For directories, files within are sorted alphabetically.
	// Later definitions of the same variable overwrite earlier ones.
	CustomFilePaths []string

	// Environment is used for default file discovery (e.g., "dev" for "install-dev.conf").
	// Only used if CustomFilePaths is empty. See DiscoverDefaultPaths for behavior.
	Environment string

	// EnableDatabaseGrouping controls how database_*.conf files are handled.
	// If true (default is typically true, but should be explicitly set by caller),
	// variables from files like "database_mysql.conf" are grouped
	// under LoadedConfig.DatabaseConfigs["mysql"].
	// If false, variables from all database_*.conf files are merged into LoadedConfig.Main.
	EnableDatabaseGrouping bool
}

// LoadedConfig represents the fully parsed and resolved configuration.
// It's designed to be directly marshalable into the desired JSON output format.
type LoadedConfig struct {
	// Main configuration variables. If database grouping was disabled during load,
	// this will include variables from database configuration files as well.
	Main map[string]string `json:"main"`

	// DatabaseConfigs holds variables from database_*.conf files, grouped by DB type (e.g., "mysql").
	// This field is populated only if Options.EnableDatabaseGrouping was true during load.
	// If populated, variables here are distinct from those in the Main map.
	DatabaseConfigs map[string]map[string]string `json:"database_configs,omitempty"`

	// Metadata contains information about the loading process, such as source files used.
	Metadata map[string]interface{} `json:"metadata"`

	// --- internal fields not part of JSON output but used for processing ---
	// rawMainConfig stores variables before resolution, primarily from non-DB files or all files if DB grouping is off.
	rawMainConfig map[string]string
	// rawDatabaseConfigs stores variables from database_*.conf files before resolution, grouped by DB type.
	// Only used if EnableDatabaseGrouping is true.
	rawDatabaseConfigs map[string]map[string]string

	// Store original option values for metadata and potential re-processing
	opts Options
}

var dbFileRegex = regexp.MustCompile(`^database_(\w+)\.conf$`)

// NewLoadedConfig initializes a LoadedConfig structure.
func newLoadedConfig(opts Options) *LoadedConfig {
	return &LoadedConfig{
		Main:               make(map[string]string),
		DatabaseConfigs:    make(map[string]map[string]string), // Initialized even if grouping disabled, for consistency
		Metadata:           make(map[string]interface{}),
		rawMainConfig:      make(map[string]string),
		rawDatabaseConfigs: make(map[string]map[string]string),
		opts:               opts,
	}
}

// DiscoverDefaultPaths determines the set of configuration files to load based on
// conventional naming (install.conf, conf/ or install-<env>.conf, conf-<env>/).
// basePath: The root directory to search within.
// env: The environment name (e.g., "dev", "uat"). If empty, tries to find non-suffixed files.
// Returns:
//   - primaryConfFile: Path to the main install.conf or install-<env>.conf.
//   - generalConfDir: Path to the conf/ or conf-<env>/ directory.
//   - error: If essential paths cannot be determined (e.g., basePath is invalid).
//
// Note: This function does not error if the files/dirs themselves don't exist,
// as parsing handles that. It errors if basePath is unusable.
func DiscoverDefaultPaths(basePath string, env string) (primaryConfFile string, generalConfDir string, err error) {
	if basePath == "" {
		basePath, err = os.Getwd()
		if err != nil {
			return "", "", fmt.Errorf("failed to get current directory: %w", err)
		}
	}
	basePath = filepath.Clean(basePath)

	// Try environment-specific first if env is provided
	if env != "" {
		primaryConfFile = filepath.Join(basePath, fmt.Sprintf("install-%s.conf", env))
		generalConfDir = filepath.Join(basePath, fmt.Sprintf("conf-%s", env))
		// Check if these specific paths exist; if not, fall back to non-env paths
		// This behavior ensures that if `install-dev.conf` is requested but only `install.conf` exists,
		// it doesn't silently fail to find any primary.
		// However, typical use is: if env is specified, those files *must* exist.
		// Let's assume if env is given, those are the targets.
		// The caller of DiscoverDefaultPaths (like LoadWithDefaults) will decide if existence is mandatory.
		return primaryConfFile, generalConfDir, nil
	}

	// If no env, try default non-suffixed paths
	primaryConfFile = filepath.Join(basePath, "install.conf")
	generalConfDir = filepath.Join(basePath, "conf")
	return primaryConfFile, generalConfDir, nil
}

// LoadWithDefaults is a convenience function that loads configurations using the default
// file discovery mechanism (based on `install.conf` and `conf/` directories, or their
// environment-specific counterparts like `install-dev.conf`).
//
// Parameters:
//   - basePath: The root directory for file discovery. If empty, current working directory is used.
//   - env: The environment string (e.g., "dev", "uat"). If provided, it looks for
//     `install-<env>.conf` and `conf-<env>/`. If empty, it looks for `install.conf` and `conf/`.
//   - enableDBGrouping: See Options.EnableDatabaseGrouping.
//
// Returns the loaded configuration or an error.
func LoadWithDefaults(basePath string, env string, enableDBGrouping bool) (*LoadedConfig, error) {
	if basePath == "" {
		var err error
		basePath, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory for LoadWithDefaults: %w", err)
		}
	}

	opts := Options{
		BasePath:               basePath,
		Environment:            env, // Store env for metadata, DiscoverDefaultPaths will use it
		EnableDatabaseGrouping: enableDBGrouping,
		CustomFilePaths:        nil, // Indicate default discovery
	}
	return Load(opts)
}

// Load parses configuration files based on the provided options and returns the loaded configuration.
// It handles file discovery (default or custom), parsing of .conf files, variable resolution,
// and structuring of database configurations if enabled.
//
// Parameters:
//   - opts: Options struct defining how configurations should be loaded.
//
// Returns the loaded configuration or an error if critical issues occur (e.g., unreadable files).
func Load(opts Options) (*LoadedConfig, error) {
	lc := newLoadedConfig(opts)
	var filesToParse []string
	var discoveredPrimaryConf, discoveredGeneralConfDir string // For metadata

	if opts.BasePath == "" {
		var err error
		opts.BasePath, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current working directory: %w", err)
		}
	}
	opts.BasePath = filepath.Clean(opts.BasePath)

	if len(opts.CustomFilePaths) > 0 {
		for _, p := range opts.CustomFilePaths {
			absPath := p
			if !filepath.IsAbs(p) {
				absPath = filepath.Join(opts.BasePath, p)
			}
			stat, err := os.Stat(absPath)
			if err != nil {
				if os.IsNotExist(err) {
					logWarning(fmt.Sprintf("Custom path %s does not exist, skipping.", absPath))
					continue
				}
				return nil, fmt.Errorf("error stating custom path %s: %w", absPath, err)
			}
			if stat.IsDir() {
				dirFiles, err := filepath.Glob(filepath.Join(absPath, "*.conf"))
				if err != nil {
					return nil, fmt.Errorf("error globbing in custom directory %s: %w", absPath, err)
				}
				sort.Strings(dirFiles) // Ensure consistent order
				filesToParse = append(filesToParse, dirFiles...)
			} else {
				filesToParse = append(filesToParse, absPath)
			}
		}
	} else {
		// Default discovery
		primaryConfFile, generalConfDir, err := DiscoverDefaultPaths(opts.BasePath, opts.Environment)
		if err != nil {
			return nil, fmt.Errorf("failed to discover default paths: %w", err)
		}
		discoveredPrimaryConf = primaryConfFile
		discoveredGeneralConfDir = generalConfDir

		if _, err := os.Stat(primaryConfFile); err == nil {
			filesToParse = append(filesToParse, primaryConfFile)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("error stating primary config file %s: %w", primaryConfFile, err)
		} // else: primary file doesn't exist, might be fine if confDir has files.

		if _, err := os.Stat(generalConfDir); err == nil {
			dirFiles, globErr := filepath.Glob(filepath.Join(generalConfDir, "*.conf"))
			if globErr != nil {
				return nil, fmt.Errorf("error globbing in directory %s: %w", generalConfDir, globErr)
			}
			sort.Strings(dirFiles) // Ensure consistent order
			filesToParse = append(filesToParse, dirFiles...)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("error stating general config directory %s: %w", generalConfDir, err)
		}
	}

	// Parse all determined files
	for _, fpath := range filesToParse {
		filename := filepath.Base(fpath)
		dbMatch := dbFileRegex.FindStringSubmatch(filename)

		if opts.EnableDatabaseGrouping && len(dbMatch) == 2 {
			dbType := strings.ToLower(dbMatch[1])
			if _, ok := lc.rawDatabaseConfigs[dbType]; !ok {
				lc.rawDatabaseConfigs[dbType] = make(map[string]string)
			}
			err := parseConfFile(fpath, lc.rawDatabaseConfigs[dbType], "DB_"+strings.ToUpper(dbType), "")
			if err != nil {
				logError(fmt.Sprintf("Error parsing database config file %s: %v. Continuing...", fpath, err))
				// Decide if this should be a fatal error or just a warning
			}
		} else {
			// Either DB grouping is off, or it's not a DB file
			// All these go into rawMainConfig
			sectionName := "MAIN"
			if len(dbMatch) == 2 { // It's a DB file but grouping is off
				sectionName = "MAIN_FROM_DB_" + strings.ToUpper(dbMatch[1])
			}
			err := parseConfFile(fpath, lc.rawMainConfig, sectionName, "")
			if err != nil {
				logError(fmt.Sprintf("Error parsing main config file %s: %v. Continuing...", fpath, err))
			}
		}
	}

	// Resolve variables
	// 1. Resolve main config (it can reference itself)
	lc.Main = resolveConfigMap(lc.rawMainConfig, lc.rawMainConfig, "MAIN_RESOLVED", "")

	// 2. Resolve database configs (they can reference themselves and the resolved main config)
	if opts.EnableDatabaseGrouping {
		for dbType, rawDbConf := range lc.rawDatabaseConfigs {
			lc.DatabaseConfigs[dbType] = resolveConfigMap(rawDbConf, lc.Main, "DB_"+strings.ToUpper(dbType)+"_RESOLVED", "")
		}
	}
	// If DB grouping was disabled, their raw values are already in lc.rawMainConfig and thus resolved into lc.Main.

	// Populate Metadata
	if len(opts.CustomFilePaths) > 0 {
		lc.Metadata["source_type"] = "custom_paths"
		lc.Metadata["custom_paths_provided"] = opts.CustomFilePaths
		lc.Metadata["parsed_files"] = filesToParse
	} else {
		lc.Metadata["source_type"] = "default_discovery"
		lc.Metadata["source_base_path"] = opts.BasePath
		lc.Metadata["source_environment_specified"] = opts.Environment
		lc.Metadata["discovered_primary_config_path"] = discoveredPrimaryConf
		lc.Metadata["discovered_general_config_dir_path"] = discoveredGeneralConfDir
		lc.Metadata["parsed_files"] = filesToParse
	}
	lc.Metadata["database_grouping_enabled"] = opts.EnableDatabaseGrouping
	lc.Metadata["extraction_date"] = time.Now().UTC().Format(time.RFC3339)
	lc.Metadata["extractor_tool"] = "Go configloader package"
	if rdbmsClient, ok := lc.Main["RDBMS_DB_CLIENT"]; ok {
		lc.Metadata["rdbms_db_client_in_main_config"] = rdbmsClient
	}

	return lc, nil
}

// ToJSON marshals the LoadedConfig into a JSON string.
// Returns the JSON string and any error encountered during marshaling.
func (lc *LoadedConfig) ToJSON() (string, error) {
	b, err := json.MarshalIndent(lc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal LoadedConfig to JSON: %w", err)
	}
	return string(b), nil
}

// SaveAsJSON saves the LoadedConfig to a file at the specified filePath as a JSON document.
// Returns an error if saving fails.
func (lc *LoadedConfig) SaveAsJSON(filePath string) error {
	jsonData, err := lc.ToJSON()
	if err != nil {
		return err // Error already contextualized by ToJSON
	}
	err = os.WriteFile(filePath, []byte(jsonData), 0644)
	if err != nil {
		return fmt.Errorf("failed to write JSON to file %s: %w", filePath, err)
	}
	logMessage(fmt.Sprintf("Configuration successfully saved to %s", filePath))
	return nil
}

// ToMap converts the LoadedConfig into a map[string]interface{},
// mirroring the structure of the JSON output. This is useful for generic processing.
// Returns the map representation.
func (lc *LoadedConfig) ToMap() map[string]interface{} {
	outputMap := make(map[string]interface{})
	outputMap["main"] = lc.Main
	if lc.opts.EnableDatabaseGrouping && len(lc.DatabaseConfigs) > 0 {
		outputMap["database_configs"] = lc.DatabaseConfigs
	}
	outputMap["metadata"] = lc.Metadata
	return outputMap
}
