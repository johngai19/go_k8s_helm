/*
k8schecker is a command-line utility to interact with Kubernetes clusters
and check various states and permissions.

It can:
- Determine if it's running inside a Kubernetes cluster.
- Get the current Kubernetes namespace.
- Check permissions for specific resources within a namespace.
- Check permissions for cluster-level resources.

Build:

	go build -o k8schecker ./cmd/k8schecker

Usage:

	./k8schecker [flags]

Examples:

 1. Check if running in-cluster:
    ./k8schecker --check-in-cluster

 2. Get current namespace (will try in-cluster, then kubeconfig):
    ./k8schecker --get-current-namespace
    ./k8schecker --kubeconfig=/path/to/your/kubeconfig --get-current-namespace

 3. Check namespace permissions for 'pods' in 'default' namespace for 'get' and 'list' verbs:
    ./k8schecker --check-ns-perms \
    --perm-namespace=default \
    --perm-resource=pods \
    --perm-verbs=get,list
    (This uses core group "" and version "v1" by default for pods)

 4. Check namespace permissions for 'deployments' in 'kube-system' namespace for 'create':
    ./k8schecker --check-ns-perms \
    --perm-namespace=kube-system \
    --perm-resource=deployments \
    --perm-group=apps \
    --perm-version=v1 \
    --perm-verbs=create

 5. Check cluster-level permission to 'create' 'namespaces':
    ./k8schecker --check-cluster-perm \
    --cluster-perm-resource=namespaces \
    --cluster-perm-verb=create
    (This uses core group "" and version "v1" by default for namespaces)

 6. Check cluster-level permission to 'list' 'nodes':
    ./k8schecker --check-cluster-perm \
    --cluster-perm-resource=nodes \
    --cluster-perm-verb=list

Common Flags:

	--kubeconfig string   (Optional) Path to kubeconfig file. Only used if not in cluster and KUBECONFIG env var is not set.

For more details on flags, run:

	./k8schecker --help
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"go_k8s_helm/internal/k8sutils" // Adjust this import path based on your go.mod module name

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func main() {
	// Common flags
	kubeconfig := flag.String("kubeconfig", "", "(Optional) Path to kubeconfig file. Only used if not in cluster and KUBECONFIG env var is not set.")

	// Sub-commands or modes using flags
	checkInCluster := flag.Bool("check-in-cluster", false, "Check if running inside a Kubernetes cluster.")
	getCurrentNs := flag.Bool("get-current-namespace", false, "Get the current Kubernetes namespace.")

	// Namespace permission check flags
	checkNsPerms := flag.Bool("check-ns-perms", false, "Check permissions for specified verbs on a resource within a namespace.")
	permNs := flag.String("perm-namespace", "", "Namespace for permission check (required if --check-ns-perms).")
	permResource := flag.String("perm-resource", "", "Resource type (e.g., pods, deployments) for permission check (required if --check-ns-perms).")
	permGroup := flag.String("perm-group", "", "API group for the resource (e.g., 'apps' for deployments, empty '' for core resources like pods). Default is empty.")
	permVersion := flag.String("perm-version", "v1", "API version for the resource (e.g., v1). Default is 'v1'.")
	permVerbsStr := flag.String("perm-verbs", "get,list,watch", "Comma-separated verbs (e.g., get,list,create) for permission check. Default is 'get,list,watch'.")

	// Cluster permission check flags
	checkClusterPerm := flag.Bool("check-cluster-perm", false, "Check a cluster-level permission for a specific verb on a resource.")
	clusterPermResource := flag.String("cluster-perm-resource", "namespaces", "Cluster resource type (e.g., namespaces, nodes). Default is 'namespaces'.")
	clusterPermGroup := flag.String("cluster-perm-group", "", "API group for the cluster resource. Default is empty for core resources like namespaces.")
	clusterPermVersion := flag.String("cluster-perm-version", "v1", "API version for the cluster resource. Default is 'v1'.")
	clusterPermVerb := flag.String("cluster-perm-verb", "create", "Verb for cluster permission check (e.g., create,list). Default is 'create'.")

	flag.Parse()

	// If a kubeconfig path is provided via flag, set it as an environment variable
	// so that client-go can pick it up if NewAuthUtil relies on KUBECONFIG env var.
	// Note: NewAuthUtil in the provided snippet already checks KUBECONFIG env var.
	if *kubeconfig != "" {
		// It's generally better for NewAuthUtil to directly accept a kubeconfig path
		// or for the user to set KUBECONFIG env var themselves.
		// However, to keep NewAuthUtil simple for this example, we'll set the env var.
		err := os.Setenv("KUBECONFIG", *kubeconfig)
		if err != nil {
			log.Printf("Warning: Could not set KUBECONFIG environment variable: %v", err)
		}
		log.Printf("Using kubeconfig from flag: %s", *kubeconfig)
	}

	authUtil, err := k8sutils.NewAuthUtil()
	if err != nil {
		log.Fatalf("Error initializing K8s auth utilities: %v", err)
	}

	var actionTaken bool
	ctx := context.Background() // Create a background context for API calls

	if *checkInCluster {
		actionTaken = true
		if authUtil.IsRunningInCluster() {
			fmt.Println("Result: Running INSIDE a Kubernetes cluster.")
		} else {
			fmt.Println("Result: Running OUTSIDE a Kubernetes cluster.")
		}
	}

	if *getCurrentNs {
		actionTaken = true
		ns, errNs := authUtil.GetCurrentNamespace()
		if errNs != nil {
			// GetCurrentNamespace now returns an error if it defaults, so we check it.
			log.Printf("Info: Attempting to get current namespace: %v", errNs) // Log the error as info
			fmt.Printf("Result: Current namespace is '%s' (Note: %v).\n", ns, errNs)
		} else {
			fmt.Printf("Result: Current namespace is '%s'.\n", ns)
		}
	}

	if *checkNsPerms {
		actionTaken = true
		if *permNs == "" || *permResource == "" {
			log.Fatal("Error: For --check-ns-perms, both --perm-namespace and --perm-resource flags must be provided.")
		}
		verbs := strings.Split(*permVerbsStr, ",")
		gvr := schema.GroupVersionResource{
			Group:    *permGroup,
			Version:  *permVersion,
			Resource: *permResource,
		}
		fmt.Printf("Checking namespace permissions in '%s' for resource '%s' (Group: '%s', Version: '%s') for verbs: %v\n", *permNs, gvr.Resource, gvr.Group, gvr.Version, verbs)
		permissions, errPerms := authUtil.CheckNamespacePermissions(ctx, *permNs, gvr, verbs)
		if errPerms != nil {
			log.Fatalf("Error checking namespace permissions: %v", errPerms)
		}
		fmt.Println("Permission check results:")
		for verb, allowed := range permissions {
			fmt.Printf("  Verb '%s': %t\n", verb, allowed)
		}
	}

	if *checkClusterPerm {
		actionTaken = true
		if *clusterPermResource == "" || *clusterPermVerb == "" {
			log.Fatal("Error: For --check-cluster-perm, both --cluster-perm-resource and --cluster-perm-verb flags must be provided.")
		}
		gvr := schema.GroupVersionResource{
			Group:    *clusterPermGroup,
			Version:  *clusterPermVersion,
			Resource: *clusterPermResource,
		}
		fmt.Printf("Checking cluster permission for resource '%s' (Group: '%s', Version: '%s') for verb: '%s'\n", gvr.Resource, gvr.Group, gvr.Version, *clusterPermVerb)
		allowed, errPerm := authUtil.CanPerformClusterAction(ctx, gvr, *clusterPermVerb)
		if errPerm != nil {
			log.Fatalf("Error checking cluster permission: %v", errPerm)
		}
		fmt.Printf("Result: Permission to '%s' cluster resource '%s' (GVR: %s): %t\n", *clusterPermVerb, gvr.Resource, gvr.String(), allowed)
	}

	if !actionTaken {
		fmt.Println("No action specified. Use -h or --help for options.")
		flag.Usage() // Prints default usage message to stderr
	}
}
