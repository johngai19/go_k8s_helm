/*
configloader is a small CLI tool that uses the internal/configloader package
to discover, parse, and resolve variables in .conf files. It supports:
  - Default discovery of install(.env).conf and conf(-env)/ directories
  - Custom file or directory lists
  - Variable substitution (${VAR} and $VAR)
  - Optional grouping of database_*.conf under separate sections
  - Output to a JSON file or stdout

This utility is intended as a one-time loader for historical default values
in specialized projects; most applications will not need to embed this as
a long-lived dependency.
*/
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go_k8s_helm/internal/configloader" // <<<< IMPORTANT: Replace with your actual Go module path
)

func main() {
	// Define command-line flags:
	// -basepath: root for default discovery or resolving relative custom paths
	basePathFlag := flag.String("basepath", "", "Base path for configuration discovery (default: current directory)")
	// -env: environment suffix, e.g., 'dev' to load install-dev.conf and conf-dev/
	envFlag := flag.String("env", "", "Environment (e.g., dev, uat) for default discovery (e.g., install-dev.conf)")
	// -files: comma-separated custom .conf files or directories (non-recursive)
	customFilesFlag := flag.String("files", "", "Comma-separated list of custom .conf files or directories to parse")
	// -dbgrouping: if true, group database_<type>.conf under database_configs[type]
	dbGroupingFlag := flag.Bool("dbgrouping", true, "Enable grouping of database_*.conf files (default: true)")
	// -output: destination JSON filename (relative to basepath if not absolute)
	outputFileFlag := flag.String("output", "all_variables.json", "Output JSON file name")
	// -help: display usage
	helpFlag := flag.Bool("help", false, "Show help message")

	flag.Parse()

	if *helpFlag {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(0)
	}

	var loadedCfg *configloader.LoadedConfig
	var err error

	opts := configloader.Options{
		BasePath:               *basePathFlag,
		Environment:            *envFlag,
		EnableDatabaseGrouping: *dbGroupingFlag,
	}
	if *customFilesFlag != "" {
		opts.CustomFilePaths = strings.Split(*customFilesFlag, ",")
	}

	// Determine effective base path for output file if not absolute
	effectiveBasePath := opts.BasePath
	if effectiveBasePath == "" {
		effectiveBasePath, _ = os.Getwd() // Ignore error as it's for output path construction
	}
	outputPath := *outputFileFlag
	if !filepath.IsAbs(outputPath) && effectiveBasePath != "" {
		outputPath = filepath.Join(effectiveBasePath, outputPath)
	}

	fmt.Fprintf(os.Stderr, "[CLI] Loading configuration with options:\n")
	fmt.Fprintf(os.Stderr, "[CLI]   BasePath: %s (effective: %s)\n", opts.BasePath, effectiveBasePath)
	fmt.Fprintf(os.Stderr, "[CLI]   Environment: %s\n", opts.Environment)
	fmt.Fprintf(os.Stderr, "[CLI]   CustomFiles: %v\n", opts.CustomFilePaths)
	fmt.Fprintf(os.Stderr, "[CLI]   DB Grouping: %t\n", opts.EnableDatabaseGrouping)
	fmt.Fprintf(os.Stderr, "[CLI]   Output File: %s (effective: %s)\n", *outputFileFlag, outputPath)

	if len(opts.CustomFilePaths) > 0 {
		loadedCfg, err = configloader.Load(opts)
	} else {
		// Use LoadWithDefaults if no custom files are specified, to leverage its specific discovery logic
		// Note: LoadWithDefaults internally calls Load, so this is mostly for semantic clarity
		// or if LoadWithDefaults had extra pre-processing not in Load(default_discovery_opts).
		// For this implementation, Load(opts) with empty CustomFilePaths achieves the same.
		loadedCfg, err = configloader.Load(opts) // Or: configloader.LoadWithDefaults(opts.BasePath, opts.Environment, opts.EnableDatabaseGrouping)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[CLI] Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[CLI] Configuration loaded successfully.\n")

	// Save the output
	err = loadedCfg.SaveAsJSON(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[CLI] Error saving configuration to %s: %v\n", outputPath, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "[CLI] Configuration saved to %s\n", outputPath)

	// Example of getting JSON string or map
	// jsonStr, _ := loadedCfg.ToJSON()
	// fmt.Fprintf(os.Stderr, "\n[CLI] JSON String Output:\n%s\n", jsonStr)

	// configMap := loadedCfg.ToMap()
	// fmt.Fprintf(os.Stderr, "\n[CLI] Map Output (Main keys): %v\n", configMap["main"])
}
