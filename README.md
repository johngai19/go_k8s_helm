# Go Kubernetes & Helm Client Project

## Overview

This project is a Go application designed to interact with Kubernetes clusters and manage Helm chart deployments. It serves as an illustrative example of how to use the official Go client libraries for Kubernetes (`client-go`) and Helm SDK.

A key component used for initial setup verification and ongoing testing is the `umbrella-chart` located in the `umbrella-chart/` subdirectory.

## Prerequisites

Before you begin, ensure you have the following:

1.  **Go**: Version 1.18 or higher.
2.  **Kubernetes Cluster**: A running Kubernetes cluster (e.g., Minikube, Kind, Docker Desktop, or a cloud-managed cluster).
3.  **Helm CLI**: Helm v3 installed and configured to interact with your cluster.
4.  **kubectl**: The Kubernetes command-line tool, configured for your cluster.

## Getting Started: Environment Verification

To ensure your Kubernetes and Helm environment is correctly set up and capable of deploying applications, it is crucial to first test a basic deployment. We use the `my-umbrella-chart` for this purpose.

**Please follow the guide in the `umbrella-chart`'s README to deploy it to your cluster:**

➡️ **[Guide to Testing Umbrella Chart on Minikube](./umbrella-chart/README.md#guide-to-testing-umbrella-chart-on-minikube)**

Successfully deploying this chart will confirm that:
- Your `kubectl` is configured correctly.
- Helm can communicate with your cluster.
- Basic Kubernetes resources (Deployments, Services) can be created.

The `umbrella-chart` will also be utilized by this Go application for automated testing purposes.

## Project Structure (Simplified)

```
.
├── cmd/
│   └── k8schecker/
│       └── main.go     # CLI utility for K8s checks
├── internal/
│   └── k8sutils/
│       ├── auth.go     # K8s authentication and permission utilities
│       └── auth_test.go
├── umbrella-chart/     # Helm umbrella chart for environment testing and Go app tests
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── charts/
│   │   ├── dv/
│   │   └── prd/
│   ├── docs/
│   │   ├── check-secret-existence.md
│   │   └── cleanup-guide.md
│   ├── required-secret.yaml
│   └── README.md       # Detailed guide for deploying the umbrella chart
├── go.mod              # Go module file
├── go.sum
└── README.md           # This file
```

## Command-Line Utilities

### `k8schecker`

The `k8schecker` is a command-line utility built with this project to interact with Kubernetes clusters and verify various states and permissions.

**Location:** `cmd/k8schecker/main.go`

**Purpose:**
- Determine if running inside a Kubernetes cluster.
- Get the current Kubernetes namespace.
- Check permissions for specific resources within a namespace.
- Check permissions for cluster-level resources.

**Build:**
Navigate to the project root directory:
```bash
go build -o k8schecker ./cmd/k8schecker
```

**Usage & Examples:**
The utility uses flags to specify the action to perform.

1.  **Check if running in-cluster:**
    ```bash
    ./k8schecker --check-in-cluster
    ```

2.  **Get current namespace:**
    (Tries in-cluster, then kubeconfig)
    ```bash
    ./k8schecker --get-current-namespace
    ```
    With a specific kubeconfig:
    ```bash
    ./k8schecker --kubeconfig=/path/to/your/kubeconfig --get-current-namespace
    ```

3.  **Check namespace permissions:**
    (e.g., for 'pods' in 'default' namespace for 'get' and 'list' verbs)
    ```bash
    ./k8schecker --check-ns-perms \
                 --perm-namespace=default \
                 --perm-resource=pods \
                 --perm-verbs=get,list
    ```
    (For 'deployments' in 'kube-system' for 'create' verb, group 'apps', version 'v1')
    ```bash
    ./k8schecker --check-ns-perms \
                 --perm-namespace=kube-system \
                 --perm-resource=deployments \
                 --perm-group=apps \
                 --perm-version=v1 \
                 --perm-verbs=create
    ```

4.  **Check cluster-level permission:**
    (e.g., to 'create' 'namespaces')
    ```bash
    ./k8schecker --check-cluster-perm \
                 --cluster-perm-resource=namespaces \
                 --cluster-perm-verb=create
    ```

For more details on all available flags and options:
```bash
./k8schecker --help
```

## Internal Go Modules

### Kubernetes Utilities (`internal/k8sutils`)

This module provides helper functions for interacting with Kubernetes.

#### `auth.go`
**Location:** `internal/k8sutils/auth.go`

**Purpose:**
This file contains the `AuthUtil` type and associated methods to handle Kubernetes client configuration, authentication, and authorization checks. It simplifies tasks such as:
-   Initializing a Kubernetes client (either in-cluster or from a kubeconfig file).
-   Determining if the application is running inside a Kubernetes cluster.
-   Retrieving the current namespace.
-   Performing `SelfSubjectAccessReview` checks to determine if the current identity has specific permissions on namespaced resources (e.g., "can I 'get' pods in 'default' namespace?").
-   Performing `SelfSubjectAccessReview` checks for cluster-scoped resources (e.g., "can I 'create' namespaces?").

The functions in `auth.go` are well-documented with Go doc comments. Key functionalities include:
-   `NewAuthUtil()`: Creates and initializes the utility.
-   `IsRunningInCluster() bool`: Checks if running in-cluster.
-   `GetCurrentNamespace() (string, error)`: Gets the current namespace.
-   `CheckNamespacePermissions(...) (map[string]bool, error)`: Checks permissions for various verbs on a namespaced resource.
-   `CanPerformClusterAction(...) (bool, error)`: Checks permission for a verb on a cluster-scoped resource.

This utility is used by the `k8schecker` CLI tool and can be leveraged by other Go applications needing to perform these checks.

## Using the Go Application

*(Details on how to build, configure, and run the Go application will be added here as the project develops. This application will demonstrate tasks such as:*
*   *Listing Kubernetes resources.*
*   *Deploying Helm charts programmatically.*
*   *Managing Helm releases.*
*   *Interacting with custom resources.*)

## Testing with the Umbrella Chart

The `umbrella-chart` located in the `umbrella-chart/` directory is not only for initial manual environment verification but will also be used as a target for automated tests run by this Go application. This allows us to test the Go client's interactions with Helm and Kubernetes in a controlled manner.

*(Further details on running tests will be provided here.)*

## Contributing

*(Contribution guidelines will be added here.)*

## License

*(License information will be added here.)*