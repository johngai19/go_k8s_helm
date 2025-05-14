/*
helmctl is a command-line utility to interact with Kubernetes clusters
and manage Helm chart deployments. It leverages the internal 'helmutils'
and 'k8sutils' packages of the 'go_k8s_helm' project.

This tool provides functionalities similar to the Helm CLI but is built using
the Helm SDK, demonstrating programmatic Helm operations in Go.

Build:

	(Navigate to the project root directory: d:\WSL\repos\johngai19\go_k8s_helm)
	go build -o helmctl ./cmd/htlmctl

Usage:

	./helmctl [global options] <command> [command options] [arguments...]

Global Options:

	--kubeconfig string       (Optional) Path to kubeconfig file for out-of-cluster execution.
	--helm-namespace string   Namespace for Helm operations (default: current kubeconfig context or 'default').
	                          This namespace is used as the default for commands unless overridden
	                          by command-specific flags (e.g., --all-namespaces for 'list').
	--output string           Output format for lists and details (text, json, yaml) (default "text").

Commands:

	list                      List Helm releases.
	install                   Install a Helm chart.
	uninstall <release-name>  Uninstall a Helm release.
	upgrade <release-name>    Upgrade a Helm release.
	details <release-name>    Get details of a Helm release.
	history <release-name>    Get history of a Helm release.
	repo-add                  Add a Helm chart repository.
	repo-update               Update Helm chart repositories.
	ensure-chart              Ensures a chart is available locally, downloading if necessary.

Examples:

 1. List all releases in the 'default' namespace (or the one specified by --helm-namespace):
    ./helmctl list
    ./helmctl --helm-namespace=my-apps list --output=json

 2. List all deployed releases across all namespaces:
    ./helmctl list --all-namespaces --deployed

 3. Install a chart from a repository:
    ./helmctl --helm-namespace=production install --name=my-nginx --chart=bitnami/nginx --version=15.0.0 --wait

 4. Install a local chart with custom values:
    ./helmctl install --name=local-app --chart=./path/to/local-chart --values=./path/to/values.yaml --set="image.tag=latest,replicaCount=3"

 5. Upgrade an existing release:
    ./helmctl upgrade my-nginx --chart=bitnami/nginx --version=15.0.1

 6. Get details of a release:
    ./helmctl details my-nginx --output=yaml

 7. Uninstall a release:
    ./helmctl uninstall my-nginx

 8. Add a chart repository:
    ./helmctl repo-add --name=bitnami --url=https://charts.bitnami.com/bitnami

 9. Update all chart repositories:
    ./helmctl repo-update

 10. Ensure a specific chart version is downloaded:
    ./helmctl ensure-chart --chart=bitnami/nginx --version=15.0.0

Testing with the Umbrella Chart:
This tool can be effectively tested using the 'umbrella-chart' provided within this project
(see 'd:\WSL\repos\johngai19\go_k8s_helm\umbrella-chart\'). The umbrella-chart is designed
for environment verification and as a test target for Helm operations.

Steps:

	a. First, ensure the 'umbrella-chart' is deployed to your Kubernetes cluster.
	   Follow the instructions in 'd:\WSL\repos\johngai19\go_k8s_helm\umbrella-chart\README.md'.
	   For example, you might deploy it as 'my-umbrella-release' in the 'dev' namespace.

	b. Once deployed, you can use 'helmctl' to interact with it:

	   - List the umbrella release (assuming --helm-namespace=dev or it's the current context):
	     ./helmctl list --filter my-umbrella-release

	   - Get details of the umbrella release:
	     ./helmctl details my-umbrella-release

	   - Upgrade the umbrella release (e.g., with different values or a new chart version):
	     ./helmctl upgrade my-umbrella-release --chart=../umbrella-chart --values=../umbrella-chart/values.yaml --set="prd.enabled=false,dv.replicaCount=2"
	     (Adjust paths to the umbrella-chart directory as needed from where you run helmctl)

	   - Uninstall the umbrella release:
	     ./helmctl uninstall my-umbrella-release

For detailed options for each command and global flags, run:

	./helmctl --help
	./helmctl <command> --help
*/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"go_k8s_helm/internal/helmutils"
	"go_k8s_helm/internal/k8sutils"

	"helm.sh/helm/v3/pkg/action"
	"sigs.k8s.io/yaml"
)

// declare subcommand flagsets at package scope so printUsage can refer to them
var (
	listCmd        *flag.FlagSet
	installCmd     *flag.FlagSet
	uninstallCmd   *flag.FlagSet
	upgradeCmd     *flag.FlagSet
	detailsCmd     *flag.FlagSet
	historyCmd     *flag.FlagSet
	repoAddCmd     *flag.FlagSet
	repoUpdateCmd  *flag.FlagSet
	ensureChartCmd *flag.FlagSet
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Usage = printUsage // Set custom usage function

	// Common flags for Helm client initialization
	kubeconfig := flag.String("kubeconfig", "", "(Optional) Path to kubeconfig file for out-of-cluster execution.")
	helmNamespace := flag.String("helm-namespace", "", "Namespace for Helm operations (default: current kubeconfig context or 'default').")
	outputFormat := flag.String("output", "text", "Output format for lists and details (text, json, yaml).")

	// List releases flags
	listCmd = flag.NewFlagSet("list", flag.ExitOnError)
	listAllNamespaces := listCmd.Bool("all-namespaces", false, "List releases in all namespaces.")
	listFilter := listCmd.String("filter", "", "Filter releases by name (substring match).")
	listDeployed := listCmd.Bool("deployed", false, "Show deployed releases. If no status flags are set, all are shown.")
	listUninstalled := listCmd.Bool("uninstalled", false, "Show uninstalled releases (if history is kept).")
	listUninstalling := listCmd.Bool("uninstalling", false, "Show releases that are currently uninstalling.")
	listPendingInstall := listCmd.Bool("pending-install", false, "Show pending install releases.")
	listPendingUpgrade := listCmd.Bool("pending-upgrade", false, "Show pending upgrade releases.")
	listPendingRollback := listCmd.Bool("pending-rollback", false, "Show pending rollback releases.")
	listFailed := listCmd.Bool("failed", false, "Show failed releases.")
	listSuperseded := listCmd.Bool("superseded", false, "Show superseded releases.")

	// Install chart flags
	installCmd = flag.NewFlagSet("install", flag.ExitOnError)
	installReleaseName := installCmd.String("name", "", "Release name. If empty, Helm will generate one.")
	installChart := installCmd.String("chart", "", "Chart to install (e.g., repo/chart, ./local-chart, http://...tgz). (Required)")
	installVersion := installCmd.String("version", "", "Specify chart version. If empty, latest is used.")
	installValuesFile := installCmd.String("values", "", "Path to a YAML file with values.")
	installSetValues := installCmd.String("set", "", "Set values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2).")
	installCreateNs := installCmd.Bool("create-namespace", false, "Create the release namespace if not present.")
	installWait := installCmd.Bool("wait", false, "Wait for resources to be ready.")
	installTimeoutStr := installCmd.String("timeout", "5m", "Time to wait for any individual Kubernetes operation (e.g., 5m, 10s).")

	// Uninstall release flags
	uninstallCmd = flag.NewFlagSet("uninstall", flag.ExitOnError)
	uninstallKeepHistory := uninstallCmd.Bool("keep-history", false, "Keep release history.")
	uninstallTimeoutStr := uninstallCmd.String("timeout", "5m", "Time to wait for any individual Kubernetes operation.")

	// Upgrade release flags
	upgradeCmd = flag.NewFlagSet("upgrade", flag.ExitOnError)
	upgradeChart := upgradeCmd.String("chart", "", "Chart to upgrade to. (Required)")
	upgradeVersion := upgradeCmd.String("version", "", "Specify chart version for upgrade.")
	upgradeValuesFile := upgradeCmd.String("values", "", "Path to a YAML file with values for upgrade.")
	upgradeSetValues := upgradeCmd.String("set", "", "Set values for upgrade.")
	upgradeInstall := upgradeCmd.Bool("install", false, "Install the chart if the release does not exist.")
	upgradeWait := upgradeCmd.Bool("wait", false, "Wait for resources to be ready after upgrade.")
	upgradeTimeoutStr := upgradeCmd.String("timeout", "5m", "Time to wait for any individual Kubernetes operation.")
	upgradeForce := upgradeCmd.Bool("force", false, "Force resource updates through a replacement strategy.")

	// Get release details flags
	detailsCmd = flag.NewFlagSet("details", flag.ExitOnError)

	// Get release history flags
	historyCmd = flag.NewFlagSet("history", flag.ExitOnError)

	// Repo add flags
	repoAddCmd = flag.NewFlagSet("repo-add", flag.ExitOnError)
	repoAddName := repoAddCmd.String("name", "", "Repository name. (Required)")
	repoAddURL := repoAddCmd.String("url", "", "Repository URL. (Required)")
	repoAddUsername := repoAddCmd.String("username", "", "Repository username for authentication.")
	repoAddPassword := repoAddCmd.String("password", "", "Repository password for authentication.")
	repoAddPassCreds := repoAddCmd.Bool("pass-credentials", false, "Pass credentials for all subsequent requests to this repo.")

	// Repo update flags
	repoUpdateCmd = flag.NewFlagSet("repo-update", flag.ExitOnError)

	// Ensure chart flags
	ensureChartCmd = flag.NewFlagSet("ensure-chart", flag.ExitOnError)
	ensureChartName := ensureChartCmd.String("chart", "", "Chart name to ensure (e.g., repo/chart). (Required)")
	ensureChartVersion := ensureChartCmd.String("version", "", "Chart version to ensure. If empty, latest is implied by Helm's LocateChart.")

	if len(os.Args) < 2 {
		flag.Usage() // Calls printUsage
		os.Exit(1)
	}

	flag.Parse() // Parse global flags. If -h or --help is present, flag.Usage() is called.

	args := flag.Args() // Get non-flag arguments after global flags are parsed.

	if len(args) == 0 {
		// This condition is met if:
		// 1. Only global flags were provided (e.g., "helmctl --kubeconfig /path").
		// 2. A global help flag (e.g. "helmctl --help") was used. flag.Usage() was already called by flag.Parse().
		//    In this case, we should exit cleanly.
		// We check if a help flag was likely the reason flag.Args() is empty.
		isHelpInvocation := false
		for _, arg := range os.Args[1:] { // Check original os.Args for help flags
			if arg == "-h" || arg == "-help" || arg == "--help" {
				// Check if this help flag is a global one (not for a subcommand)
				// This simple check assumes help flags are not subcommand names.
				isGlobalHelp := true
				allCmdSets := []*flag.FlagSet{listCmd, installCmd, uninstallCmd, upgradeCmd, detailsCmd, historyCmd, repoAddCmd, repoUpdateCmd, ensureChartCmd}
				for _, cmdSet := range allCmdSets {
					if cmdSet != nil && cmdSet.Name() == arg { // Unlikely, but defensive
						isGlobalHelp = false
						break
					}
				}
				if isGlobalHelp {
					isHelpInvocation = true
					break
				}
			}
		}
		if isHelpInvocation {
			os.Exit(0) // Exit cleanly as help was already displayed by flag.Usage()
		}

		// If not a help invocation but no command, then it's an error.
		fmt.Fprintln(os.Stderr, "Error: No command specified.")
		flag.Usage() // Calls printUsage
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	// K8s and Helm Client Initialization
	if *kubeconfig != "" {
		os.Setenv("KUBECONFIG", *kubeconfig)
	}
	k8sAuth, err := k8sutils.NewAuthUtil()
	if err != nil {
		log.Fatalf("Failed to initialize K8s auth: %v", err)
	}

	effectiveHelmNs := *helmNamespace
	if effectiveHelmNs == "" {
		currentNs, nsErr := k8sAuth.GetCurrentNamespace()
		if nsErr != nil {
			log.Printf("Warning: Could not determine current k8s namespace via auth util, defaulting Helm client to 'default': %v", nsErr)
			effectiveHelmNs = "default"
		} else {
			effectiveHelmNs = currentNs
		}
	}

	helmClient, err := helmutils.NewClient(k8sAuth, effectiveHelmNs, log.Printf)
	if err != nil {
		log.Fatalf("Failed to create Helm client: %v", err)
	}

	switch command {
	case "list":
		listCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		nsToList := effectiveHelmNs
		if *listAllNamespaces {
			nsToList = "" // Pass empty string to client for all namespaces
		}

		var stateMask action.ListStates
		if *listDeployed {
			stateMask |= action.ListDeployed
		}
		if *listUninstalled {
			stateMask |= action.ListUninstalled
		}
		if *listUninstalling {
			stateMask |= action.ListUninstalling
		}
		if *listPendingInstall {
			stateMask |= action.ListPendingInstall
		}
		if *listPendingUpgrade {
			stateMask |= action.ListPendingUpgrade
		}
		if *listPendingRollback {
			stateMask |= action.ListPendingRollback
		}
		if *listFailed {
			stateMask |= action.ListFailed
		}
		if *listSuperseded {
			stateMask |= action.ListSuperseded
		}
		if stateMask == 0 { // If no specific state flags were set, show all.
			stateMask = action.ListAll
		}

		releases, err := helmClient.ListReleases(nsToList, stateMask)
		if err != nil {
			log.Fatalf("Error listing releases: %v", err)
		}
		printOutput(releases, *outputFormat, *listFilter)

	case "install":
		installCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if *installChart == "" {
			log.Fatal("Missing required flag for install: --chart")
		}
		installTimeout, err := time.ParseDuration(*installTimeoutStr)
		if err != nil {
			log.Fatalf("Invalid install timeout duration: %v", err)
		}
		vals, err := loadValues(*installValuesFile, *installSetValues)
		if err != nil {
			log.Fatalf("Error loading values for install: %v", err)
		}
		// Use effectiveHelmNs directly as it already considers the --helm-namespace flag
		targetNs := effectiveHelmNs

		rel, err := helmClient.InstallChart(targetNs, *installReleaseName, *installChart, *installVersion, vals, *installCreateNs, *installWait, installTimeout)
		if err != nil {
			log.Fatalf("Error installing chart: %v", err)
		}
		fmt.Printf("Installed release: %s in namespace %s\n", rel.Name, rel.Namespace)
		printOutput(rel, *outputFormat, "")

	case "uninstall":
		uninstallCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if uninstallCmd.NArg() == 0 {
			log.Fatal("Missing release name for uninstall command.")
		}
		releaseToUninstall := uninstallCmd.Arg(0)
		uninstallTimeout, err := time.ParseDuration(*uninstallTimeoutStr)
		if err != nil {
			log.Fatalf("Invalid uninstall timeout duration: %v", err)
		}
		targetNs := effectiveHelmNs

		info, err := helmClient.UninstallRelease(targetNs, releaseToUninstall, *uninstallKeepHistory, uninstallTimeout)
		if err != nil {
			log.Fatalf("Error uninstalling release %s: %v", releaseToUninstall, err)
		}
		fmt.Println(info)

	case "upgrade":
		upgradeCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if upgradeCmd.NArg() == 0 {
			log.Fatal("Missing release name for upgrade command.")
		}
		releaseToUpgrade := upgradeCmd.Arg(0)
		if *upgradeChart == "" {
			log.Fatal("Missing required flag for upgrade: --chart")
		}
		upgradeTimeout, err := time.ParseDuration(*upgradeTimeoutStr)
		if err != nil {
			log.Fatalf("Invalid upgrade timeout duration: %v", err)
		}
		vals, err := loadValues(*upgradeValuesFile, *upgradeSetValues)
		if err != nil {
			log.Fatalf("Error loading values for upgrade: %v", err)
		}
		targetNs := effectiveHelmNs

		rel, err := helmClient.UpgradeRelease(targetNs, releaseToUpgrade, *upgradeChart, *upgradeVersion, vals, *upgradeWait, upgradeTimeout, *upgradeInstall, *upgradeForce)
		if err != nil {
			log.Fatalf("Error upgrading release: %v", err)
		}
		fmt.Printf("Upgraded release: %s in namespace %s\n", rel.Name, rel.Namespace)
		printOutput(rel, *outputFormat, "")

	case "details":
		detailsCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if detailsCmd.NArg() == 0 {
			log.Fatal("Missing release name for details command.")
		}
		releaseToDetail := detailsCmd.Arg(0)
		targetNs := effectiveHelmNs

		details, err := helmClient.GetReleaseDetails(targetNs, releaseToDetail)
		if err != nil {
			log.Fatalf("Error getting details for release %s: %v", releaseToDetail, err)
		}
		printOutput(details, *outputFormat, "")

	case "history":
		historyCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if historyCmd.NArg() == 0 {
			log.Fatal("Missing release name for history command.")
		}
		releaseForHistory := historyCmd.Arg(0)
		targetNs := effectiveHelmNs

		history, err := helmClient.GetReleaseHistory(targetNs, releaseForHistory)
		if err != nil {
			log.Fatalf("Error getting history for release %s: %v", releaseForHistory, err)
		}
		printOutput(history, *outputFormat, "")

	case "repo-add":
		repoAddCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if *repoAddName == "" || *repoAddURL == "" {
			log.Fatal("For repo-add, --name and --url are required.")
		}
		err := helmClient.AddRepository(*repoAddName, *repoAddURL, *repoAddUsername, *repoAddPassword, *repoAddPassCreds)
		if err != nil {
			log.Fatalf("Error adding repository: %v", err)
		}
		fmt.Printf("Repository %s added.\n", *repoAddName)

	case "repo-update":
		repoUpdateCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		err := helmClient.UpdateRepositories()
		if err != nil {
			log.Fatalf("Error updating repositories: %v", err)
		}
		fmt.Println("Repositories updated.")

	case "ensure-chart":
		ensureChartCmd.Parse(commandArgs) // Subcommand parsing handles its own --help
		if *ensureChartName == "" {
			log.Fatal("Missing required flag for ensure-chart: --chart")
		}
		chartPath, err := helmClient.EnsureChart(*ensureChartName, *ensureChartVersion)
		if err != nil {
			log.Fatalf("Error ensuring chart %s version %s: %v", *ensureChartName, *ensureChartVersion, err)
		}
		fmt.Printf("Chart %s version %s ensured/found at: %s\n", *ensureChartName, *ensureChartVersion, chartPath)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command %q\n", command)
		flag.Usage() // Calls printUsage
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: helmctl [global options] <command> [command options] [arguments...]")
	fmt.Fprintln(os.Stderr, "\nGlobal Options:")
	flag.CommandLine.SetOutput(os.Stderr) // Ensure global flags print to Stderr
	flag.PrintDefaults()                  // Print global flag defaults

	fmt.Fprintln(os.Stderr, "\nCommands:")
	commandHelp := []struct {
		name        string
		description string
		cmdSet      *flag.FlagSet
	}{
		{"list", "List Helm releases", listCmd},
		{"install", "Install a Helm chart", installCmd},
		{"uninstall", "Uninstall a Helm release. Args: <release-name>", uninstallCmd},
		{"upgrade", "Upgrade a Helm release. Args: <release-name>", upgradeCmd},
		{"details", "Get details of a Helm release. Args: <release-name>", detailsCmd},
		{"history", "Get history of a Helm release. Args: <release-name>", historyCmd},
		{"repo-add", "Add a Helm chart repository", repoAddCmd},
		{"repo-update", "Update Helm chart repositories", repoUpdateCmd},
		{"ensure-chart", "Ensures a chart is available locally, downloading if necessary", ensureChartCmd},
	}

	for _, ch := range commandHelp {
		fmt.Fprintf(os.Stderr, "  %s\n", ch.name)
		fmt.Fprintf(os.Stderr, "      %s\n", ch.description)
		ch.cmdSet.SetOutput(os.Stderr) // Ensure subcommand flags also print to Stderr for consistency
		ch.cmdSet.VisitAll(func(f *flag.Flag) {
			s := fmt.Sprintf("    --%s", f.Name) // Two spaces for flag, two for description
			name, usage := flag.UnquoteUsage(f)
			if len(name) > 0 {
				s += " " + name
			}
			s += "\n        "
			s += strings.ReplaceAll(usage, "\n", "\n        ")
			fmt.Fprintln(os.Stderr, s)
		})
		fmt.Fprintln(os.Stderr) // Add a blank line between commands
	}

	fmt.Fprintln(os.Stderr, "\nFor global options with a command, specify them before the command:")
	fmt.Fprintln(os.Stderr, "  e.g., helmctl --helm-namespace=my-ns list")
	fmt.Fprintln(os.Stderr, "\nRun 'helmctl <command> --help' for more information on a command.")
}

func loadValues(valuesFile string, setValues string) (map[string]interface{}, error) {
	mergedVals := make(map[string]interface{})

	if valuesFile != "" {
		bytes, err := os.ReadFile(valuesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read values file %s: %w", valuesFile, err)
		}
		var fileVals map[string]interface{}
		if err := yaml.Unmarshal(bytes, &fileVals); err != nil {
			return nil, fmt.Errorf("failed to parse values file %s: %w", valuesFile, err)
		}
		mergedVals = fileVals // Initialize with file values
	}

	if setValues != "" {
		rawSet := strings.Split(setValues, ",")
		for _, pair := range rawSet {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				keys := strings.Split(kv[0], ".")
				currentMap := mergedVals
				for i, k := range keys {
					k = strings.TrimSpace(k)
					if i == len(keys)-1 {
						currentMap[k] = strings.TrimSpace(kv[1])
					} else {
						if _, ok := currentMap[k]; !ok {
							currentMap[k] = make(map[string]interface{})
						}
						nextMap, ok := currentMap[k].(map[string]interface{})
						if !ok {
							return nil, fmt.Errorf("error setting value for %s: %s is not a map (it's a %T)", kv[0], k, currentMap[k])
						}
						currentMap = nextMap
					}
				}
			} else {
				log.Printf("Warning: Malformed --set value (expected key=value): %s", pair)
			}
		}
	}
	return mergedVals, nil
}

func printOutput(data interface{}, format string, nameFilter string) {
	var itemsToPrint []helmutils.ReleaseInfo
	var singleItem *helmutils.ReleaseInfo

	switch v := data.(type) {
	case *helmutils.ReleaseInfo:
		if v != nil {
			if nameFilter == "" || strings.Contains(strings.ToLower(v.Name), strings.ToLower(nameFilter)) {
				itemsToPrint = append(itemsToPrint, *v)
				singleItem = v
			}
		}
	case []*helmutils.ReleaseInfo:
		for _, item := range v {
			if item != nil {
				if nameFilter == "" || strings.Contains(strings.ToLower(item.Name), strings.ToLower(nameFilter)) {
					itemsToPrint = append(itemsToPrint, *item)
				}
			}
		}
	default:
		log.Printf("Unsupported data type for printing: %T", data)
		bytes, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Printf("Could not marshal unsupported data type to JSON: %v", err)
			fmt.Printf("%+v\n", data)
		} else {
			fmt.Println(string(bytes))
		}
		return
	}

	if len(itemsToPrint) == 0 {
		if nameFilter != "" {
			fmt.Println("No releases found matching filter.")
		} else {
			fmt.Println("No data to display.")
		}
		return
	}

	outputData := interface{}(itemsToPrint)
	if singleItem != nil && (format == "json" || format == "yaml") {
	}

	switch strings.ToLower(format) {
	case "json":
		bytes, err := json.MarshalIndent(outputData, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling to JSON: %v", err)
		}
		fmt.Println(string(bytes))
	case "yaml":
		bytes, err := yaml.Marshal(outputData)
		if err != nil {
			log.Fatalf("Error marshalling to YAML: %v", err)
		}
		fmt.Println(string(bytes))
	case "text":
		for i, item := range itemsToPrint {
			fmt.Printf("Name: %s\n", item.Name)
			fmt.Printf("  Namespace:    %s\n", item.Namespace)
			fmt.Printf("  Revision:     %d\n", item.Revision)
			fmt.Printf("  Status:       %s\n", item.Status)
			fmt.Printf("  Chart:        %s-%s\n", item.ChartName, item.ChartVersion)
			fmt.Printf("  App Version:  %s\n", item.AppVersion)
			if !item.Updated.IsZero() {
				fmt.Printf("  Updated:      %s\n", item.Updated.Format(time.RFC3339))
			}
			if item.Description != "" {
				fmt.Printf("  Description:  %s\n", item.Description)
			}
			currentCommand := ""
			if len(os.Args) > 1 {
				currentCommand = os.Args[1]
			}
			if currentCommand == "details" || currentCommand == "install" || currentCommand == "upgrade" {
				if item.Notes != "" {
					fmt.Printf("  Notes:        \n%s\n", indentString(item.Notes, "    "))
				}
			}
			if i < len(itemsToPrint)-1 {
				fmt.Println("---")
			}
		}
	default:
		log.Printf("Unknown output format: %s. Using text.", format)
		printOutput(data, "text", nameFilter)
	}
}

func indentString(s, indent string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}
