/*
productctl is a command-line interface (CLI) tool for managing Helm chart-based product templates.
It allows users to:
  - Define new products from base Helm charts.
  - List available products.
  - Get detailed information about a specific product.
  - Extract variable placeholders (e.g., @{variableName}) from chart templates.
  - Instantiate products or chart templates by providing values for placeholders,
    generating ready-to-use Helm charts.
  - Validate the YAML/JSON structure of chart files.

Global Flags:

	--products-dir: Specifies the root directory where product definitions are stored.
	                Defaults to "./chart_products" (relative to the execution directory).
	--output:       Sets the output format for commands like 'list', 'get', and 'extract-vars'.
	                Supported formats: "text" (default), "json", "yaml".

The tool uses a FileSystemProductManager from the chartconfigmanager package to interact
with product definitions stored on the local filesystem. Logging for the
chartconfigmanager operations is directed to a file (default: "data/logs/chartconfigmanager.log"
relative to the execution directory).

Usage:

	productctl [global options] <command> [command options] [arguments...]

Examples:

	productctl list
	./bin/productctl --products-dir ./data/charts/placeholder_charts/ list
	./bin/productctl --products-dir ./data/test_products_area get my-app-product
	./bin/productctl --products-dir ./data/charts/placeholder_charts/ get-chart appstack-alpha
	productctl define my-new-product --base-chart-path ./path/to/base-chart
	productctl instantiate my-new-product ./output/chart-instance --values ./values.yaml
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go_k8s_helm/internal/chartconfigmanager"

	"gopkg.in/yaml.v3"
)

// ChartInfo holds the contents of a Chart.yaml
type ChartInfo struct {
	APIVersion  string `yaml:"apiVersion" json:"apiVersion"`
	Name        string `yaml:"name" json:"name"`
	Version     string `yaml:"version" json:"version"`
	AppVersion  string `yaml:"appVersion,omitempty" json:"appVersion,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

var (
	// Subcommand flag sets
	listCmd        *flag.FlagSet
	getCmd         *flag.FlagSet
	getChartCmd    *flag.FlagSet
	extractVarsCmd *flag.FlagSet
	instantiateCmd *flag.FlagSet
	validateCmd    *flag.FlagSet
	defineCmd      *flag.FlagSet
)

// defaultProductsRoot is the default directory for storing product definitions,
// relative to where productctl is executed.
// const defaultProductsRoot = "./chart_products"

// main is the entry point for the productctl CLI application.
// It parses global flags, identifies the command to execute, initializes the
// product manager, and dispatches to the appropriate command handler.
func main() {
	defaultProductsRoot := "./chart_products"
	// Configure logger for productctl's own messages (e.g., fatal errors before manager init).
	// The chartconfigmanager has its own file-based logger.
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Usage = printMainUsage // Set custom usage function for the main command

	// Global flags for productctl
	productsDir := flag.String("products-dir", defaultProductsRoot, "Root directory for storing chart product definitions.")
	outputFormat := flag.String("output", "text", "Output format for list/get/extract-vars commands (text, json, yaml).")

	// --- Subcommands Definition ---

	// list command: Lists all available chart products.
	listCmd = flag.NewFlagSet("list", flag.ExitOnError)
	listCmd.Usage = func() { printSubcommandUsage(listCmd, "list", "Lists all available chart products.", "list") }

	// get command: Displays metadata of a specific chart product.
	getCmd = flag.NewFlagSet("get", flag.ExitOnError)
	getCmd.Usage = func() {
		printSubcommandUsage(getCmd, "get", "Displays metadata of a specific chart product.", "get <productName>")
	}

	// get-chart command: Displays Chart.yaml info for a specific product.
	getChartCmd = flag.NewFlagSet("get-chart", flag.ExitOnError)
	getChartCmd.Usage = func() {
		printSubcommandUsage(getChartCmd, "get-chart", "Displays Chart.yaml info for a specific product.", "get-chart <productName>")
	}

	// extract-vars command: Extracts @{variable} placeholders from a given chart path.
	extractVarsCmd = flag.NewFlagSet("extract-vars", flag.ExitOnError)
	extractVarsCmd.Usage = func() {
		printSubcommandUsage(extractVarsCmd, "extract-vars", "Extracts @{variable} placeholders from a given chart path.", "extract-vars <chartPath>")
	}

	// instantiate command: Instantiates a chart product or template.
	instantiateCmd = flag.NewFlagSet("instantiate", flag.ExitOnError)
	instantiateValuesFile := instantiateCmd.String("values", "", "Path to a YAML or JSON file containing variable values.")
	instantiateSetValues := instantiateCmd.String("set", "", "Set variable values on the command line (e.g., key1=val1,key2=val2).")
	instantiateUnassignedAction := instantiateCmd.String(
		"unassigned",
		chartconfigmanager.UnassignedVarEmpty,
		fmt.Sprintf(
			"Action for unassigned variables: %s, %s, %s.",
			chartconfigmanager.UnassignedVarError,
			chartconfigmanager.UnassignedVarEmpty,
			chartconfigmanager.UnassignedVarKeep,
		),
	)
	instantiateCmd.Usage = func() {
		printSubcommandUsage(instantiateCmd, "instantiate", "Instantiates a chart product or template to a specified output path, replacing variables.", "instantiate <productNameOrChartPath> <outputPath>")
	}

	// validate command: Validates the structure of YAML and JSON files within a given chart path.
	validateCmd = flag.NewFlagSet("validate", flag.ExitOnError)
	validateCmd.Usage = func() {
		printSubcommandUsage(validateCmd, "validate", "Validates the structure of YAML and JSON files within a given chart path.", "validate <chartPath>")
	}

	// define command: Defines a new chart product from a base chart.
	defineCmd = flag.NewFlagSet("define", flag.ExitOnError)
	defineBaseChartPath := defineCmd.String("base-chart-path", "", "Path to the base chart directory to use for the new product. (Required)")
	defineDescription := defineCmd.String("description", "", "Description for the new product.")
	defineVariablesFile := defineCmd.String("variables-file", "", "Path to a JSON or YAML file defining product variables metadata (array of VariableDefinition).")
	defineProductChartSubDir := defineCmd.String("product-chart-subdir", chartconfigmanager.DefaultChartSubDir, "Subdirectory within the product directory to store the chart files (e.g., 'chart').")
	defineCmd.Usage = func() {
		printSubcommandUsage(defineCmd, "define", "Defines a new chart product from a base chart.", "define <productName>")
	}

	// --- DEBUG: Print raw os.Args ---
	fmt.Fprintf(os.Stderr, "[DEBUG] Raw os.Args: %v\n", os.Args)

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Manually parse arguments to separate global flags from command and its arguments.
	var globalArgs []string
	var commandArgs []string
	command := ""
	inputArgs := os.Args[1:] // Arguments to process, excluding program name

	for i := 0; i < len(inputArgs); i++ {
		arg := inputArgs[i]

		if strings.HasPrefix(arg, "-") { // Argument is a flag
			globalArgs = append(globalArgs, arg) // Add flag to globalArgs

			// Check if this global flag expects a value (e.g., --products-dir, --output)
			// and the value is provided as the next argument (not in "flag=value" form).
			// The known global flags that take values are --products-dir and --output.
			if !strings.Contains(arg, "=") && (arg == "--products-dir" || arg == "--output") {
				if i+1 < len(inputArgs) && !strings.HasPrefix(inputArgs[i+1], "-") {
					// Next argument exists and is not a flag, so it's the value.
					globalArgs = append(globalArgs, inputArgs[i+1])
					i++ // Increment i to skip this value in the next iteration of the loop
				}
				// If a value is expected but not provided here (e.g., followed by another flag or end of args),
				// flag.CommandLine.Parse(globalArgs) will later report "flag needs an argument".
			}
		} else { // Argument is not a flag
			// This is the first non-flag argument encountered after processing any preceding flags.
			// It's considered the command.
			command = arg
			// All subsequent arguments are considered command arguments.
			if i+1 < len(inputArgs) {
				commandArgs = inputArgs[i+1:]
			}
			break // Command found, stop processing inputArgs for global flags or command.
		}
	}

	// --- DEBUG: Print parsed argument categories ---
	fmt.Fprintf(os.Stderr, "[DEBUG] Identified command: '%s'\n", command)
	fmt.Fprintf(os.Stderr, "[DEBUG] Collected globalArgs: %v\n", globalArgs)
	fmt.Fprintf(os.Stderr, "[DEBUG] Collected commandArgs: %v\n", commandArgs)

	// Parse the collected global flags.
	// Note: flag.Parse() should ideally be used, but because we allow global flags
	// anywhere, we use flag.CommandLine.Parse(). Subcommand flags are parsed later.
	if err := flag.CommandLine.Parse(globalArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing global flags: %v\n", err)
		flag.Usage()
		os.Exit(1)
	}

	// --- DEBUG: Print values of global flags after parsing ---
	fmt.Fprintf(os.Stderr, "[DEBUG] Parsed global flag --products-dir: '%s'\n", *productsDir)
	fmt.Fprintf(os.Stderr, "[DEBUG] Parsed global flag --output: '%s'\n", *outputFormat)

	if command == "" {
		fmt.Fprintln(os.Stderr, "Error: No command specified.")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize Product Manager
	// Pass an empty string for logDirectoryPath to use the default logging behavior
	// (logs to "data/logs" in the current working directory of productctl).
	// --- DEBUG: Print productsDir before passing to manager ---
	fmt.Fprintf(os.Stderr, "[DEBUG] Initializing Product Manager with productsDir: '%s'\n", *productsDir)
	pm, err := chartconfigmanager.NewFileSystemProductManager(*productsDir, "")
	if err != nil {
		// Use log.Fatalf for fatal errors which will print to stderr and exit.
		// The chartconfigmanager itself also logs to its file.
		log.Fatalf("Failed to initialize product manager: %v", err)
	}

	// Dispatch to the appropriate command handler.
	switch command {
	case "list":
		// --- DEBUG: Print commandArgs before parsing for 'list' ---
		fmt.Fprintf(os.Stderr, "[DEBUG] 'list' commandArgs before parse: %v\n", commandArgs)
		listCmd.Parse(commandArgs)
		products, err := pm.ListProducts()
		if err != nil {
			log.Fatalf("Error listing products: %v", err)
		}
		if len(products) == 0 {
			fmt.Println("No products found.")
			return
		}
		printAsFormat(products, *outputFormat)

	case "get":
		getCmd.Parse(commandArgs)
		if getCmd.NArg() < 1 {
			getCmd.Usage()
			log.Fatal("Error: productName argument is required for 'get' command.")
		}
		productName := getCmd.Arg(0)
		product, err := pm.GetProduct(productName)
		if err != nil {
			log.Fatalf("Error getting metadata: %v", err)
		}
		printAsFormat(product, *outputFormat)

	case "get-chart":
		getChartCmd.Parse(commandArgs)
		if getChartCmd.NArg() < 1 {
			getChartCmd.Usage()
			log.Fatal("Error: productName argument is required for 'get-chart' command.")
		}
		productName := getChartCmd.Arg(0)
		chartInfo, err := pm.GetChartInfo(productName)
		if err != nil {
			log.Fatalf("Error getting chart info: %v", err)
		}
		printAsFormat(chartInfo, *outputFormat)

	case "extract-vars":
		extractVarsCmd.Parse(commandArgs)
		if extractVarsCmd.NArg() < 1 {
			extractVarsCmd.Usage()
			log.Fatal("Error: chartPath argument is required for 'extract-vars' command.")
		}
		chartPath := extractVarsCmd.Arg(0)
		vars, err := pm.ExtractVariablesFromPath(chartPath)
		if err != nil {
			log.Fatalf("Error extracting variables from '%s': %v", chartPath, err)
		}
		if len(vars) == 0 {
			fmt.Printf("No variables found in %s.\n", chartPath)
			return
		}
		printAsFormat(vars, *outputFormat)

	case "instantiate":
		instantiateCmd.Parse(commandArgs)
		if instantiateCmd.NArg() < 2 {
			instantiateCmd.Usage()
			log.Fatal("Error: productNameOrChartPath and outputPath arguments are required for 'instantiate' command.")
		}
		productNameOrPath := instantiateCmd.Arg(0)
		outputPath := instantiateCmd.Arg(1)

		variables, err := loadValuesForInstantiation(*instantiateValuesFile, *instantiateSetValues)
		if err != nil {
			log.Fatalf("Error loading values for instantiation: %v", err)
		}

		instantiatedPath, err := pm.InstantiateProduct(productNameOrPath, variables, outputPath, *instantiateUnassignedAction)
		if err != nil {
			log.Fatalf("Error instantiating product/chart '%s': %v", productNameOrPath, err)
		}
		fmt.Printf("Successfully instantiated chart to: %s\n", instantiatedPath)

	case "validate":
		validateCmd.Parse(commandArgs)
		if validateCmd.NArg() < 1 {
			validateCmd.Usage()
			log.Fatal("Error: chartPath argument is required for 'validate' command.")
		}
		chartPath := validateCmd.Arg(0)
		if err := pm.ValidateChartFiles(chartPath); err != nil {
			log.Fatalf("Validation failed for chart at '%s': %v", chartPath, err)
		}
		fmt.Printf("Chart at '%s' validated successfully.\n", chartPath)

	case "define":
		defineCmd.Parse(commandArgs)
		if defineCmd.NArg() < 1 {
			defineCmd.Usage()
			log.Fatal("Error: productName argument is required for 'define' command.")
		}
		productName := defineCmd.Arg(0)
		if *defineBaseChartPath == "" {
			defineCmd.Usage()
			log.Fatal("Error: --base-chart-path is required for 'define' command.")
		}

		var productMeta chartconfigmanager.Product
		// Name will be set by DefineProduct based on productName argument for consistency.
		productMeta.Description = *defineDescription
		// ChartPath within the product directory. DefineProduct handles making this relative to the new product dir.
		productMeta.ChartPath = *defineProductChartSubDir

		if *defineVariablesFile != "" {
			varsData, err := os.ReadFile(*defineVariablesFile)
			if err != nil {
				log.Fatalf("Failed to read variables file %s: %v", *defineVariablesFile, err)
			}
			// The variables file should contain an array of VariableDefinition
			var varsDef []chartconfigmanager.VariableDefinition
			if err := yaml.Unmarshal(varsData, &varsDef); err != nil {
				if err := json.Unmarshal(varsData, &varsDef); err != nil {
					log.Fatalf("Failed to parse variables file %s as YAML or JSON array of VariableDefinition: %v", *defineVariablesFile, err)
				}
			}
			productMeta.Variables = varsDef
		}

		if err := pm.DefineProduct(productName, *defineBaseChartPath, &productMeta); err != nil {
			log.Fatalf("Error defining product '%s': %v", productName, err)
		}
		fmt.Printf("Successfully defined product '%s' in %s\n", productName, filepath.Join(*productsDir, productName))

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command '%s'\n\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

// loadValuesForInstantiation combines variable values from a specified file (YAML or JSON)
// and from command-line --set arguments. --set values override file values.
//
// Parameters:
//   - valuesFile: Path to the YAML or JSON file containing variable values.
//   - setValues: A comma-separated string of key=value pairs (e.g., "key1=val1,key2.subkey=val2").
//
// Returns:
//   - A map of variable names to their values.
//   - An error if reading or parsing fails, or if --set format is invalid.
func loadValuesForInstantiation(valuesFile string, setValues string) (map[string]interface{}, error) {
	base := make(map[string]interface{})

	// Load values from file if specified
	if valuesFile != "" {
		bytes, err := os.ReadFile(valuesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read values file %s: %w", valuesFile, err)
		}
		// Try YAML first, then JSON
		if errYaml := yaml.Unmarshal(bytes, &base); errYaml != nil {
			base = make(map[string]interface{}) // Reset base before trying JSON
			if errJson := json.Unmarshal(bytes, &base); errJson != nil {
				return nil, fmt.Errorf("failed to parse values file %s as YAML or JSON. YAML err: %v, JSON err: %v", valuesFile, errYaml, errJson)
			}
		}
	}

	// Override or add values from --set flags
	if setValues != "" {
		pairs := strings.Split(setValues, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid --set format: '%s'. Expected key=value", pair)
			}
			keys := strings.Split(kv[0], ".")
			currentMap := base
			for i, k := range keys {
				if i == len(keys)-1 { // Last key in the path
					currentMap[k] = kv[1] // Values from --set are treated as strings here.
					// For typed values (int, bool), a more sophisticated parsing mechanism would be needed,
					// similar to Helm's --set, which can interpret types or use type hints.
				} else { // Navigate or create nested maps
					if _, ok := currentMap[k]; !ok {
						currentMap[k] = make(map[string]interface{})
					}
					var typeOK bool
					currentMap, typeOK = currentMap[k].(map[string]interface{})
					if !typeOK {
						return nil, fmt.Errorf("invalid key structure in --set '%s': '%s' is not a map, but holds value '%v'", kv[0], k, currentMap[k])
					}
				}
			}
		}
	}
	return base, nil
}

// printAsFormat prints the given data to standard output in the specified format (text, json, yaml).
// For "text" format, it provides a basic, human-readable representation.
func printAsFormat(data interface{}, format string) {
	switch strings.ToLower(format) {
	case "json":
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling to JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	case "yaml":
		yamlData, err := yaml.Marshal(data)
		if err != nil {
			log.Fatalf("Error marshalling to YAML: %v", err)
		}
		fmt.Println(string(yamlData))
	case "text":
		fallthrough
	default:
		// Basic text output, can be improved based on data type
		switch v := data.(type) {
		case []chartconfigmanager.Product:
			if len(v) == 0 {
				fmt.Println("No products to display.")
				return
			}
			fmt.Printf("%-30s %-45s %s\n", "PRODUCT NAME", "DESCRIPTION", "CHART PATH")
			fmt.Println(strings.Repeat("-", 100))
			for _, p := range v {
				desc := p.Description
				if len(desc) > 42 {
					desc = desc[:39] + "..."
				}
				fmt.Printf("%-30s %-45s %s\n", p.Name, desc, p.ChartPath)
			}
		case *chartconfigmanager.Product:
			fmt.Printf("Name:        %s\n", v.Name)
			fmt.Printf("Description: %s\n", v.Description)
			fmt.Printf("Chart Path:  %s\n", v.ChartPath)
			if len(v.Variables) > 0 {
				fmt.Println("Variables:")
				for _, vari := range v.Variables {
					fmt.Printf("  - Name: %s\n", vari.Name)
					if vari.Description != "" {
						fmt.Printf("    Description: %s\n", vari.Description)
					}
					if vari.Default != "" {
						fmt.Printf("    Default: %s\n", vari.Default)
					}
				}
			} else {
				fmt.Println("Variables:   (No predefined variables in metadata)")
			}
		case []chartconfigmanager.VariableDefinition:
			if len(v) == 0 {
				fmt.Println("No variables to display.")
				return
			}
			fmt.Println("Found Variables:")
			for _, vari := range v {
				fmt.Printf("  - Name: %s\n", vari.Name)
				// Additional details like Description or Default could be printed if available
				// from VariableDefinition struct, though extract-vars primarily focuses on names.
			}
		default:
			// Fallback to JSON-like for unknown types in text mode for basic representation
			fmt.Printf("Data (type %T):\n", v)
			jsonData, err := json.MarshalIndent(data, "", "  ")
			if err != nil {
				fmt.Printf("  (Could not render as JSON: %v)\n", err)
			} else {
				fmt.Println(string(jsonData))
			}
		}
	}
}

// printMainUsage prints the main help message for productctl, including global options and available commands.
func printMainUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [global options] <command> [command options] [arguments...]\n\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(os.Stderr, "Manages chart products, variable extraction, and instantiation.")
	fmt.Fprintln(os.Stderr, "\nGlobal Options:")
	flag.CommandLine.PrintDefaults() // Prints global flags registered on flag.CommandLine

	fmt.Fprintln(os.Stderr, "\nAvailable Commands:")
	// Manually list commands for better formatting and descriptions
	fmt.Fprintln(os.Stderr, "  list                Lists all available chart products.")
	fmt.Fprintln(os.Stderr, "  get                 Displays metadata of a specific chart product.")
	fmt.Fprintln(os.Stderr, "  get-chart           Displays Chart.yaml info for a specific product.")
	fmt.Fprintln(os.Stderr, "  extract-vars        Extracts @{variable} placeholders from a given chart path.")
	fmt.Fprintln(os.Stderr, "  instantiate         Instantiates a chart product or template to a specified output path.")
	fmt.Fprintln(os.Stderr, "  validate            Validates the structure of YAML and JSON files within a given chart path.")
	fmt.Fprintln(os.Stderr, "  define              Defines a new chart product from a base chart.")
	fmt.Fprintln(os.Stderr, "\nUse \"productctl <command> --help\" for more information about a command.")
}

// printSubcommandUsage prints a detailed help message for a specific subcommand, including its options.
func printSubcommandUsage(fs *flag.FlagSet, command, description, usageExample string) {
	fmt.Fprintf(os.Stderr, "Usage: %s %s\n\n", filepath.Base(os.Args[0]), usageExample)
	fmt.Fprintf(os.Stderr, "%s\n\n", description)
	fmt.Fprintln(os.Stderr, "Options:")
	fs.PrintDefaults()
}
