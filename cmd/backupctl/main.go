/*
backupctl is a command-line interface (CLI) tool for managing Helm chart backups.
It allows users to create backups of Helm charts and their values, list existing
backups, restore releases from backups, upgrade releases to a backup state,
delete specific backups, and prune old backups.

Usage:

	backupctl [global options] <command> [command options] [arguments...]

Global Options:

	--kubeconfig string       (Optional) Path to kubeconfig file for out-of-cluster execution.
	--backup-dir string       Root directory for storing chart backups (default "./chart_backups").
	--output string           Output format for list command (text, json, yaml) (default "text").
	--helm-namespace string   Default Kubernetes namespace for Helm operations if not specified
	                          by a command-specific --namespace flag (uses current context or
	                          'default' if empty and current context cannot be determined).

Commands:

	backup --chart-path <path> [--values <file>] [--set k=v,...] <releaseName>
	  Creates a backup of the specified chart and its values for a given release name.
	  Arguments:
	    releaseName: Name of the Helm release. (Must be the last argument for backup)
	  Options:
	    --chart-path string: Path to the chart directory to back up. (Required)
	    --values string:     Path to a YAML file with values to include in the backup.

	list <releaseName>
	  Lists all available backups for a given release name.
	  Arguments:
	    releaseName: Name of the Helm release.
	  (Uses global --output flag for formatting)

	restore <releaseName> <backupID> [--namespace <ns>] [--create-namespace] [--wait] [--timeout <duration>]
	  Restores a release to the state of a specific backup. This typically involves
	  uninstalling the current release and installing from the backup.
	  Arguments:
	    releaseName: Name of the Helm release.
	    backupID:    ID of the backup to restore from.
	  Options:
	    --namespace string:        Kubernetes namespace for the restore operation. Overrides
	                               global --helm-namespace. If not set, uses global
	                               --helm-namespace, then current context, then 'default'.
	    --create-namespace bool: Create the release namespace if not present during restore.
	    --wait bool:             Wait for resources to be ready after restore.
	    --timeout string:        Time to wait for Helm operations during restore (e.g., 5m, 10s)
	                             (default "5m").

	upgrade <releaseName> <backupID> [--namespace <ns>] [--wait] [--timeout <duration>] [--force]
	  Upgrades a release to the state of a specific backup. This uses Helm's upgrade mechanism.
	  Arguments:
	    releaseName: Name of the Helm release.
	    backupID:    ID of the backup to upgrade to.
	  Options:
	    --namespace string:        Kubernetes namespace for the upgrade operation. Overrides
	                               global --helm-namespace. If not set, uses global
	                               --helm-namespace, then current context, then 'default'.
	    --wait bool:             Wait for resources to be ready after upgrade.
	    --timeout string:        Time to wait for Helm operations during upgrade (e.g., 5m, 10s)
	                             (default "5m").
	    --force bool:            Force resource updates through a replacement strategy during upgrade.

	delete <releaseName> <backupID>
	  Deletes a specific backup for a release.
	  Arguments:
	    releaseName: Name of the Helm release.
	    backupID:    ID of the backup to delete.

	prune <releaseName> --keep <count>
	  Prunes old backups for a release, keeping the specified number of most recent backups.
	  Arguments:
	    releaseName: Name of the Helm release.
	  Options:
	    --keep int: Number of recent backups to keep (default 5).

Example Usage:

	backupctl --backup-dir /mnt/backups backup --chart-path ./charts/myapp --values ./prod-values.yaml myapp
	backupctl list myapp --output json
	backupctl restore myapp 20230101-120000.000000 --namespace prod --wait
	backupctl upgrade myapp 20230101-120000.000000 --namespace dev --timeout 10m
	backupctl prune myapp --keep 3
*/
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go_k8s_helm/internal/backupmanager"
	"go_k8s_helm/internal/helmutils"
	"go_k8s_helm/internal/k8sutils"

	"sigs.k8s.io/yaml"
)

var (
	backupCmd  *flag.FlagSet
	listCmd    *flag.FlagSet
	restoreCmd *flag.FlagSet
	upgradeCmd *flag.FlagSet
	deleteCmd  *flag.FlagSet
	pruneCmd   *flag.FlagSet
)

const defaultBackupRoot = "./chart_backups"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Usage = printUsage // Set custom usage function

	// Global flags
	kubeconfig := flag.String("kubeconfig", "", "(Optional) Path to kubeconfig file for out-of-cluster execution.")
	backupDir := flag.String("backup-dir", defaultBackupRoot, "Root directory for storing chart backups.")
	outputFormat := flag.String("output", "text", "Output format for list command (text, json, yaml).")
	helmNamespace := flag.String("helm-namespace", "", "Default Kubernetes namespace for Helm operations (uses current context or 'default' if empty).")

	// --- Subcommands Definition ---

	// Backup command
	backupCmd = flag.NewFlagSet("backup", flag.ExitOnError)
	backupChartPath := backupCmd.String("chart-path", "", "Path to the chart directory to back up. (Required)")
	backupValuesFile := backupCmd.String("values", "", "Path to a YAML file with values to include in the backup.")
	backupSetValues := backupCmd.String("set", "", "Set values on the command line (e.g., key1=val1,key2=val2) to include in the backup.")

	// List command
	listCmd = flag.NewFlagSet("list", flag.ExitOnError)

	// Restore command
	restoreCmd = flag.NewFlagSet("restore", flag.ExitOnError)
	restoreNamespace := restoreCmd.String("namespace", "", "Kubernetes namespace for the restore operation (overrides global --helm-namespace).")
	restoreCreateNamespace := restoreCmd.Bool("create-namespace", false, "Create the release namespace if not present during restore.")
	restoreWait := restoreCmd.Bool("wait", false, "Wait for resources to be ready after restore.")
	restoreTimeoutStr := restoreCmd.String("timeout", "5m", "Time to wait for Helm operations during restore (e.g., 5m, 10s).")

	// Upgrade command (similar to restore but uses upgrade)
	upgradeCmd = flag.NewFlagSet("upgrade", flag.ExitOnError)
	upgradeNamespace := upgradeCmd.String("namespace", "", "Kubernetes namespace for the upgrade operation (overrides global --helm-namespace).")
	upgradeWait := upgradeCmd.Bool("wait", false, "Wait for resources to be ready after upgrade.")
	upgradeTimeoutStr := upgradeCmd.String("timeout", "5m", "Time to wait for Helm operations during upgrade (e.g., 5m, 10s).")
	upgradeForce := upgradeCmd.Bool("force", false, "Force resource updates through a replacement strategy during upgrade.")

	// Delete command
	deleteCmd = flag.NewFlagSet("delete", flag.ExitOnError)

	// Prune command
	pruneCmd = flag.NewFlagSet("prune", flag.ExitOnError)
	pruneKeepCount := pruneCmd.Int("keep", 5, "Number of recent backups to keep.")

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	flag.Parse() // Parse global flags

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No command specified.")
		flag.Usage()
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	// Initialize Backup Manager
	bm, err := backupmanager.NewFileSystemBackupManager(*backupDir, log.Printf)
	if err != nil {
		log.Fatalf("Failed to initialize backup manager: %v", err)
	}

	// Initialize K8s and Helm clients (needed for restore/upgrade)
	var k8sAuth k8sutils.K8sAuthChecker
	var helmClient helmutils.HelmClient

	// Initialize Kubernetes and Helm clients only if needed by the command
	if command == "restore" || command == "upgrade" {
		if *kubeconfig != "" {
			os.Setenv("KUBECONFIG", *kubeconfig)
		}
		k8sAuth, err = k8sutils.NewAuthUtil()
		if err != nil {
			log.Fatalf("Failed to initialize K8s auth: %v", err)
		}

		effectiveHelmNs := *helmNamespace
		if effectiveHelmNs == "" {
			currentNs, nsErr := k8sAuth.GetCurrentNamespace()
			if nsErr != nil {
				log.Printf("Warning: Could not determine current k8s namespace, defaulting Helm client to 'default': %v", nsErr)
				effectiveHelmNs = "default"
			} else {
				effectiveHelmNs = currentNs
			}
		}

		helmClient, err = helmutils.NewClient(k8sAuth, effectiveHelmNs, log.Printf)
		if err != nil {
			log.Fatalf("Failed to create Helm client: %v", err)
		}
	}

	switch command {
	case "backup":
		log.Printf("DEBUG: commandArgs for backup: %v", commandArgs) // DEBUG LINE
		err := backupCmd.Parse(commandArgs)                          // Capture error from Parse
		if err != nil {
			log.Fatalf("Error parsing backup command flags: %v", err) // DEBUG LINE
		}

		log.Printf("DEBUG: backupCmd.NArg(): %d", backupCmd.NArg())     // DEBUG LINE
		log.Printf("DEBUG: backupCmd.Args(): %v", backupCmd.Args())     // DEBUG LINE
		log.Printf("DEBUG: *backupChartPath: '%s'", *backupChartPath)   // DEBUG LINE
		log.Printf("DEBUG: *backupValuesFile: '%s'", *backupValuesFile) // DEBUG LINE
		log.Printf("DEBUG: *backupSetValues: '%s'", *backupSetValues)   // DEBUG LINE

		if *backupChartPath == "" { // Check for required flags first
			log.Fatal("Error: --chart-path is required for backup command.")
		}
		if backupCmd.NArg() < 1 {
			log.Fatal("Usage: backupctl backup --chart-path <path> [--values <file>] [--set k=v,...] <releaseName>")
		}
		releaseName := backupCmd.Arg(0) // releaseName is the first positional argument after flags
		// The check for *backupChartPath == "" should ideally be before NArg check if it's a mandatory flag

		values, err := loadValues(*backupValuesFile, *backupSetValues)
		if err != nil {
			log.Fatalf("Error loading values for backup: %v", err)
		}

		backupID, err := bm.BackupRelease(releaseName, *backupChartPath, values)
		if err != nil {
			log.Fatalf("Error creating backup for release %s: %v", releaseName, err)
		}
		fmt.Printf("Successfully created backup for release '%s' with ID: %s\n", releaseName, backupID)

	case "list":
		listCmd.Parse(commandArgs)
		if listCmd.NArg() < 1 {
			log.Fatal("Usage: backupctl list <releaseName>")
		}
		releaseName := listCmd.Arg(0)
		backups, err := bm.ListBackups(releaseName)
		if err != nil {
			log.Fatalf("Error listing backups for release %s: %v", releaseName, err)
		}
		if len(backups) == 0 {
			fmt.Printf("No backups found for release '%s'.\n", releaseName)
			return
		}
		printBackupList(backups, *outputFormat, "")

	case "restore":
		restoreCmd.Parse(commandArgs)
		if restoreCmd.NArg() < 2 {
			log.Fatal("Usage: backupctl restore <releaseName> <backupID> [--namespace <ns>] [--create-namespace] [--wait] [--timeout <duration>]")
		}
		releaseName := restoreCmd.Arg(0)
		backupID := restoreCmd.Arg(1)
		timeout, err := time.ParseDuration(*restoreTimeoutStr)
		if err != nil {
			log.Fatalf("Invalid timeout duration for restore: %v", err)
		}

		// Determine namespace for restore operation
		var nsForRestore string
		if *restoreNamespace != "" { // Command-specific flag for restore
			nsForRestore = *restoreNamespace
		} else if *helmNamespace != "" { // Global --helm-namespace flag
			nsForRestore = *helmNamespace
		} else {
			// No namespace flag provided, try to get current k8s namespace
			// k8sAuth is guaranteed to be initialized here for "restore" command
			currentNs, nsErr := k8sAuth.GetCurrentNamespace()
			if nsErr != nil {
				log.Printf("Warning: Could not determine current k8s namespace for restore, using 'default': %v", nsErr)
				nsForRestore = "default"
			} else {
				nsForRestore = currentNs
			}
		}

		relInfo, err := bm.RestoreRelease(context.Background(), helmClient, nsForRestore, releaseName, backupID, *restoreCreateNamespace, *restoreWait, timeout)
		if err != nil {
			log.Fatalf("Error restoring release %s from backup %s: %v", releaseName, backupID, err)
		}
		fmt.Printf("Successfully restored release '%s' in namespace '%s' from backup ID '%s'. New revision: %d\n", relInfo.Name, relInfo.Namespace, backupID, relInfo.Revision)

	case "upgrade": // Similar to restore, but uses UpgradeToBackup
		upgradeCmd.Parse(commandArgs)
		if upgradeCmd.NArg() < 2 {
			log.Fatal("Usage: backupctl upgrade <releaseName> <backupID> [--namespace <ns>] [--wait] [--timeout <duration>] [--force]")
		}
		releaseName := upgradeCmd.Arg(0)
		backupID := upgradeCmd.Arg(1)
		timeout, err := time.ParseDuration(*upgradeTimeoutStr)
		if err != nil {
			log.Fatalf("Invalid timeout duration for upgrade: %v", err)
		}

		// Determine namespace for upgrade operation
		var nsForUpgrade string
		if *upgradeNamespace != "" { // Command-specific flag for upgrade
			nsForUpgrade = *upgradeNamespace
		} else if *helmNamespace != "" { // Global --helm-namespace flag
			nsForUpgrade = *helmNamespace
		} else {
			// No namespace flag provided, try to get current k8s namespace
			// k8sAuth is guaranteed to be initialized here for "upgrade" command
			currentNs, nsErr := k8sAuth.GetCurrentNamespace()
			if nsErr != nil {
				log.Printf("Warning: Could not determine current k8s namespace for upgrade, using 'default': %v", nsErr)
				nsForUpgrade = "default"
			} else {
				nsForUpgrade = currentNs
			}
		}

		relInfo, err := bm.UpgradeToBackup(context.Background(), helmClient, nsForUpgrade, releaseName, backupID, *upgradeWait, timeout, *upgradeForce)
		if err != nil {
			log.Fatalf("Error upgrading release %s using backup %s: %v", releaseName, backupID, err)
		}
		fmt.Printf("Successfully upgraded release '%s' in namespace '%s' using backup ID '%s'. New revision: %d\n", relInfo.Name, relInfo.Namespace, backupID, relInfo.Revision)

	case "delete":
		deleteCmd.Parse(commandArgs)
		if deleteCmd.NArg() < 2 {
			log.Fatal("Usage: backupctl delete <releaseName> <backupID>")
		}
		releaseName := deleteCmd.Arg(0)
		backupID := deleteCmd.Arg(1)

		err := bm.DeleteBackup(releaseName, backupID)
		if err != nil {
			log.Fatalf("Error deleting backup ID '%s' for release '%s': %v", backupID, releaseName, err)
		}
		fmt.Printf("Successfully deleted backup ID '%s' for release '%s'.\n", backupID, releaseName)

	case "prune":
		pruneCmd.Parse(commandArgs)
		if pruneCmd.NArg() < 1 {
			log.Fatal("Usage: backupctl prune <releaseName> --keep <count>")
		}
		releaseName := pruneCmd.Arg(0)

		prunedCount, err := bm.PruneBackups(releaseName, *pruneKeepCount)
		if err != nil {
			log.Fatalf("Error pruning backups for release %s: %v", releaseName, err)
		}
		fmt.Printf("Successfully pruned %d backup(s) for release '%s', keeping %d.\n", prunedCount, releaseName, *pruneKeepCount)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command '%s'\n\n", command)
		flag.Usage()
		os.Exit(1)
	}
}

// loadValues combines values from a file and --set flags.
// This is a simplified version. For full Helm compatibility, consider helm.MergeValues.
func loadValues(valuesFile string, setValues string) (map[string]interface{}, error) {
	base := map[string]interface{}{}

	if valuesFile != "" {
		bytes, err := os.ReadFile(valuesFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read values file %s: %w", valuesFile, err)
		}
		if err := yaml.Unmarshal(bytes, &base); err != nil {
			return nil, fmt.Errorf("failed to parse values file %s: %w", valuesFile, err)
		}
	}

	if setValues != "" {
		vals := map[string]interface{}{}
		pairs := strings.Split(setValues, ",")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid --set format: %s. Expected key=value", pair)
			}
			// This is a very basic parser. Helm's --set is more sophisticated.
			// For simplicity, we'll treat all values as strings here.
			// A more robust solution would parse types or use a library.
			keys := strings.Split(kv[0], ".")
			currentMap := vals
			for i, k := range keys {
				if i == len(keys)-1 {
					currentMap[k] = kv[1] // TODO: Parse value type (int, bool, etc.)
				} else {
					if _, ok := currentMap[k]; !ok {
						currentMap[k] = make(map[string]interface{})
					}
					var ok bool
					currentMap, ok = currentMap[k].(map[string]interface{}) // Type assertion
					if !ok {
						return nil, fmt.Errorf("invalid --set key structure: %s creates conflict at %s", kv[0], k)
					}
				}
			}
		}
		// Merge 'vals' into 'base'. For simplicity, this is a shallow merge.
		// Helm uses a more sophisticated merge (mergo library).
		for k, v := range vals {
			base[k] = v
		}
	}
	return base, nil
}

func printBackupList(backups []backupmanager.BackupMetadata, format string, filter string) {
	var filteredBackups []backupmanager.BackupMetadata
	if filter != "" {
		for _, b := range backups {
			if strings.Contains(b.BackupID, filter) || strings.Contains(b.ReleaseName, filter) || strings.Contains(b.ChartName, filter) {
				filteredBackups = append(filteredBackups, b)
			}
		}
	} else {
		filteredBackups = backups
	}

	if len(filteredBackups) == 0 {
		fmt.Println("No backups found matching the filter.")
		return
	}

	switch strings.ToLower(format) {
	case "json":
		data, err := json.MarshalIndent(filteredBackups, "", "  ")
		if err != nil {
			log.Fatalf("Error marshalling to JSON: %v", err)
		}
		fmt.Println(string(data))
	case "yaml":
		data, err := yaml.Marshal(filteredBackups)
		if err != nil {
			log.Fatalf("Error marshalling to YAML: %v", err)
		}
		fmt.Println(string(data))
	case "text":
		fallthrough
	default:
		fmt.Printf("%-30s %-25s %-20s %-15s %-10s %s\n", "BACKUP ID", "TIMESTAMP", "RELEASE NAME", "CHART NAME", "VERSION", "APP VERSION")
		for _, b := range filteredBackups {
			fmt.Printf("%-30s %-25s %-20s %-15s %-10s %s\n",
				b.BackupID,
				b.Timestamp.Format(time.RFC3339),
				b.ReleaseName,
				b.ChartName,
				b.ChartVersion,
				b.AppVersion)
		}
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [global options] <command> [command options] [arguments...]\n\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(os.Stderr, "A CLI tool for managing Helm chart backups and restores.")
	fmt.Fprintln(os.Stderr, "\nGlobal Options:")
	flag.PrintDefaults()

	fmt.Fprintln(os.Stderr, "\nCommands:")

	fmt.Fprintln(os.Stderr, "  backup --chart-path <path> [--values <file>] [--set k=v,...] <releaseName>")
	fmt.Fprintln(os.Stderr, "    Creates a backup of the specified chart and its values for a given release name.")
	backupCmd.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintln(os.Stderr, "  list <releaseName>")
	fmt.Fprintln(os.Stderr, "    Lists all available backups for a given release name.")
	listCmd.PrintDefaults() // No specific flags for list itself, but global --output applies
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintln(os.Stderr, "  restore <releaseName> <backupID> [--namespace <ns>] [--create-namespace] [--wait] [--timeout <duration>]")
	fmt.Fprintln(os.Stderr, "    Restores a release to the state of a specific backup. This typically involves uninstalling the current release and installing from the backup.")
	restoreCmd.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintln(os.Stderr, "  upgrade <releaseName> <backupID> [--namespace <ns>] [--wait] [--timeout <duration>] [--force]")
	fmt.Fprintln(os.Stderr, "    Upgrades a release to the state of a specific backup. This uses Helm's upgrade mechanism.")
	upgradeCmd.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintln(os.Stderr, "  delete <releaseName> <backupID>")
	fmt.Fprintln(os.Stderr, "    Deletes a specific backup for a release.")
	deleteCmd.PrintDefaults() // No specific flags for delete itself
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintln(os.Stderr, "  prune <releaseName> --keep <count>")
	fmt.Fprintln(os.Stderr, "    Prunes old backups for a release, keeping the specified number of most recent backups.")
	pruneCmd.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")

	fmt.Fprintln(os.Stderr, "Example Usage:")
	fmt.Fprintf(os.Stderr, "  %s --backup-dir /mnt/backups backup --chart-path ./charts/myapp --values ./prod-values.yaml myapp\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "  %s list myapp\n", filepath.Base(os.Args[0]))
	fmt.Fprintf(os.Stderr, "  %s --helm-namespace=prod restore myapp 20230101-120000.000000 --wait\n", filepath.Base(os.Args[0]))
}
