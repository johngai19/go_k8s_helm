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

var (
	// Subcommand flag sets
	listCmd        *flag.FlagSet
	getCmd         *flag.FlagSet
	extractVarsCmd *flag.FlagSet
	instantiateCmd *flag.FlagSet
	validateCmd    *flag.FlagSet
	defineCmd      *flag.FlagSet
)

const defaultProductsRoot = "./chart_products" // Default directory for storing product definitions

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Usage = printMainUsage // Set custom usage function for the main command

	// Global flags for productctl
	productsDir := flag.String("products-dir", defaultProductsRoot, "Root directory for storing chart product definitions.")
	outputFormat := flag.String("output", "text", "Output format for list/get/extract-vars commands (text, json, yaml).")

	// --- Subcommands Definition ---

	// list command
	listCmd = flag.NewFlagSet("list", flag.ExitOnError)
	listCmd.Usage = func() { printSubcommandUsage(listCmd, "list", "Lists all available chart products.", "list") }

	// get command
	getCmd = flag.NewFlagSet("get", flag.ExitOnError)
	getCmd.Usage = func() {
		printSubcommandUsage(getCmd, "get", "Displays details of a specific chart product.", "get <productName>")
	}

	// extract-vars command
	extractVarsCmd = flag.NewFlagSet("extract-vars", flag.ExitOnError)
	extractVarsCmd.Usage = func() {
		printSubcommandUsage(extractVarsCmd, "extract-vars", "Extracts @{variable} placeholders from a given chart path.", "extract-vars <chartPath>")
	}

	// instantiate command
	instantiateCmd = flag.NewFlagSet("instantiate", flag.ExitOnError)
	instantiateValuesFile := instantiateCmd.String("values", "", "Path to a YAML or JSON file containing variable values.")
	instantiateSetValues := instantiateCmd.String("set", "", "Set variable values on the command line (e.g., key1=val1,key2=val2).")
	instantiateUnassignedAction := instantiateCmd.String("unassigned", chartconfigmanager.UnassignedVarError, fmt.Sprintf("Action for unassigned variables: %s, %s, %s.", chartconfigmanager.UnassignedVarError, chartconfigmanager.UnassignedVarEmpty, chartconfigmanager.UnassignedVarKeep))
	instantiateCmd.Usage = func() {
		printSubcommandUsage(instantiateCmd, "instantiate", "Instantiates a chart product or template to a specified output path, replacing variables.", "instantiate <productNameOrChartPath> <outputPath>")
	}

	// validate command
	validateCmd = flag.NewFlagSet("validate", flag.ExitOnError)
	validateCmd.Usage = func() {
		printSubcommandUsage(validateCmd, "validate", "Validates the structure of YAML and JSON files within a given chart path.", "validate <chartPath>")
	}

	// define command
	defineCmd = flag.NewFlagSet("define", flag.ExitOnError)
	defineBaseChartPath := defineCmd.String("base-chart-path", "", "Path to the base chart directory to use for the new product. (Required)")
	defineDescription := defineCmd.String("description", "", "Description for the new product.")
	defineVariablesFile := defineCmd.String("variables-file", "", "Path to a JSON or YAML file defining product variables metadata.")
	defineProductChartSubDir := defineCmd.String("product-chart-subdir", chartconfigmanager.DefaultChartSubDir, "Subdirectory within the product directory to store the chart files (e.g., 'chart').")
	defineCmd.Usage = func() {
		printSubcommandUsage(defineCmd, "define", "Defines a new chart product from a base chart.", "define <productName>")
	}

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Parse global flags first. Subcommand parsing will handle the rest.
	// We need to find where subcommand args start.
	var globalArgs []string
	var commandArgs []string
	command := ""

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if !strings.HasPrefix(arg, "-") && command == "" { // First non-flag argument is the command
			command = arg
			commandArgs = os.Args[i+1:]
			break
		} else {
			globalArgs = append(globalArgs, arg)
		}
	}

	flag.CommandLine.Parse(globalArgs) // Parse global flags

	if command == "" {
		fmt.Fprintln(os.Stderr, "Error: No command specified.")
		flag.Usage()
		os.Exit(1)
	}

	// Initialize Product Manager
	pm, err := chartconfigmanager.NewFileSystemProductManager(*productsDir, log.Printf)
	if err != nil {
		log.Fatalf("Failed to initialize product manager: %v", err)
	}

	switch command {
	case "list":
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
			log.Fatalf("Error getting product 	%s	: %v", productName, err)
		}
		printAsFormat(product, *outputFormat)

	case "extract-vars":
		extractVarsCmd.Parse(commandArgs)
		if extractVarsCmd.NArg() < 1 {
			extractVarsCmd.Usage()
			log.Fatal("Error: chartPath argument is required for 'extract-vars' command.")
		}
		chartPath := extractVarsCmd.Arg(0)
		vars, err := pm.ExtractVariablesFromPath(chartPath)
		if err != nil {
			log.Fatalf("Error extracting variables from 	%s	: %v", chartPath, err)
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
			log.Fatalf("Error instantiating product/chart 	%s	: %v", productNameOrPath, err)
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
			log.Fatalf("Validation failed for chart at 	%s	: %v", chartPath, err)
		}
		fmt.Printf("Chart at 	%s	 validated successfully.\n", chartPath)

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
		productMeta.Name = productName // Will be overridden by DefineProduct for consistency
		productMeta.Description = *defineDescription
		productMeta.ChartPath = *defineProductChartSubDir // This is relative to the product dir being created

		if *defineVariablesFile != "" {
			varsData, err := os.ReadFile(*defineVariablesFile)
			if err != nil {
				log.Fatalf("Failed to read variables file %s: %v", *defineVariablesFile, err)
			}
			// Try YAML first, then JSON for variables file
			if err := yaml.Unmarshal(varsData, &productMeta.Variables); err != nil {
				if err := json.Unmarshal(varsData, &productMeta.Variables); err != nil {
					log.Fatalf("Failed to parse variables file %s as YAML or JSON: %v", *defineVariablesFile, err)
				}
			}
		}

		if err := pm.DefineProduct(productName, *defineBaseChartPath, &productMeta); err != nil {
			log.Fatalf("Error defining product 	%s	: %v", productName, err)
		}
		fmt.Printf("Successfully defined product 	%s	 in %s\n", productName, filepath.Join(*productsDir, productName))

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command 	%s	\n\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

// loadValuesForInstantiation combines values from a file and --set flags.
func loadValuesForInstantiation(valuesFile string, setValues string) (map[string]interface{}, error) {
	base := make(map[string]interface{})

	if valuesFile != "" {
		bytes, err := os.ReadFile(valuesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read values file %s: %w", valuesFile, err)
		}
		// Try YAML first, then JSON
		if errYaml := yaml.Unmarshal(bytes, &base); errYaml != nil {
			// Reset base if YAML fails, before trying JSON
			base = make(map[string]interface{}) // Important to reset if YAML parsing modifies base partially on error
			if errJson := json.Unmarshal(bytes, &base); errJson != nil {
				return nil, fmt.Errorf("failed to parse values file %s as YAML or JSON. YAML err: %v, JSON err: %v", valuesFile, errYaml, errJson)
			}
		}
	}

	if setValues != "" {
		pairs := strings.Split(setValues, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid --set format: %s. Expected key=value", pair)
			}
			// Simple string assignment for --set values. For typed values, a more complex parser is needed.
			// Helm's --set parsing is quite sophisticated (e.g., key.subkey=value, key[0].name=value, value types)
			// This implementation is basic: it assumes top-level keys or simple dot notation.
			keys := strings.Split(kv[0], ".")
			currentMap := base
			for i, k := range keys {
				if i == len(keys)-1 {
					currentMap[k] = kv[1] // Assign as string. Could attempt to parse to bool/int/float.
				} else {
					if _, ok := currentMap[k]; !ok {
						currentMap[k] = make(map[string]interface{})
					}
					var typeOK bool
					currentMap, typeOK = currentMap[k].(map[string]interface{})
					if !typeOK {
						return nil, fmt.Errorf("invalid key structure in --set 	%s	: 	%s	 is not a map", kv[0], k)
					}
				}
			}
		}
	}
	return base, nil
}

// printAsFormat prints data in the specified format (text, json, yaml).
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
			fmt.Printf("%-25s %-40s %s\n", "PRODUCT NAME", "DESCRIPTION", "CHART PATH")
			for _, p := range v {
				fmt.Printf("%-25s %-40s %s\n", p.Name, p.Description, p.ChartPath)
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
			}
		case []chartconfigmanager.VariableDefinition:
			fmt.Println("Found Variables:")
			for _, vari := range v {
				fmt.Printf("  - %s\n", vari.Name)
			}
		default:
			// Fallback to JSON-like for unknown types in text mode
			jsonData, _ := json.MarshalIndent(data, "", "  ")
			fmt.Println(string(jsonData))
		}
	}
}

// printMainUsage prints the main usage help for productctl.
func printMainUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [global options] <command> [command options] [arguments...]\n\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(os.Stderr, "Manages chart products, variable extraction, and instantiation.")
	fmt.Fprintln(os.Stderr, "\nGlobal Options:")
	flag.PrintDefaults() // Prints global flags

	fmt.Fprintln(os.Stderr, "\nAvailable Commands:")
	fmt.Fprintln(os.Stderr, "  list                Lists all available chart products.")
	fmt.Fprintln(os.Stderr, "  get                 Displays details of a specific chart product.")
	fmt.Fprintln(os.Stderr, "  extract-vars        Extracts @{variable} placeholders from a given chart path.")
	fmt.Fprintln(os.Stderr, "  instantiate         Instantiates a chart product or template to a specified output path.")
	fmt.Fprintln(os.Stderr, "  validate            Validates the structure of YAML and JSON files within a given chart path.")
	fmt.Fprintln(os.Stderr, "  define              Defines a new chart product from a base chart.")
	fmt.Fprintln(os.Stderr, "\nUse \"productctl <command> --help\" for more information about a command.")
}

// printSubcommandUsage prints usage for a specific subcommand.
func printSubcommandUsage(fs *flag.FlagSet, command, description, usageExample string) {
	fmt.Fprintf(os.Stderr, "Usage: %s %s\n\n", filepath.Base(os.Args[0]), usageExample)
	fmt.Fprintf(os.Stderr, "%s\n\n", description)
	fmt.Fprintln(os.Stderr, "Options:")
	fs.PrintDefaults()
}
