# Go Kubernetes & Helm Client Project

## Overview

This project is a Go application designed to interact with Kubernetes clusters and manage Helm chart deployments. It serves as an illustrative example of how to use the official Go client libraries for Kubernetes (`client-go`) and the Helm SDK. The project includes command-line utilities (`k8schecker`, `helmctl`) for direct interaction and testing, as well as internal utility packages (`k8sutils`, `helmutils`) that can be leveraged by other Go applications or within this project for more complex operations.

A key component used for initial setup verification and ongoing testing is the `umbrella-chart` located in the `umbrella-chart/` subdirectory.

## Prerequisites

Before you begin, ensure you have the following:

1.  **Go**: Version 1.18 or higher.
2.  **Kubernetes Cluster**: A running Kubernetes cluster (e.g., Minikube, Kind, Docker Desktop, or a cloud-managed cluster).
3.  **Helm CLI**: Helm v3 installed and configured to interact with your cluster.
4.  **kubectl**: The Kubernetes command-line tool, configured for your cluster.

## Getting Started: Environment Verification

To ensure your Kubernetes and Helm environment is correctly set up and capable of deploying applications, it is crucial to first test a basic deployment. We use the `umbrella-chart` for this purpose.

**Please follow the guide in the `umbrella-chart`'s README to deploy it to your cluster:**

➡️ **[Guide to Testing Umbrella Chart on Minikube](./umbrella-chart/README.md#guide-to-testing-umbrella-chart-on-minikube)**

Successfully deploying this chart will confirm that:
- Your `kubectl` is configured correctly.
- Helm can communicate with your cluster.
- Basic Kubernetes resources (Deployments, Services) can be created.

The `umbrella-chart` can also be utilized by the `helmctl` utility for testing Helm operations.

## Project Structure

```
.
├── cmd/
│   ├── k8schecker/
│   │   └── main.go     # CLI utility for K8s checks
│   └── helmctl/        # Corrected from htlmctl
│       └── main.go     # CLI utility for Helm operations
├── internal/
│   ├── k8sutils/
│   │   ├── auth.go     # K8s authentication and permission utilities
│   │   └── auth_test.go
│   └── helmutils/
│       ├── client.go   # Helm client operations
│       └── client_test.go
├── umbrella-chart/     # Helm umbrella chart for environment testing
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
├── TODO.md             # List of planned features and enhancements
└── README.md           # This file
```

## Command-Line Utilities

These utilities serve both as functional tools and as test harnesses for the underlying `internal` packages.

### `k8schecker`

The `k8schecker` is a command-line utility to interact with Kubernetes clusters and verify various states and permissions.

**Location:** `cmd/k8schecker/main.go`

**Purpose:**
- Determine if running inside a Kubernetes cluster.
- Get the current Kubernetes namespace.
- Check permissions for specific resources within a namespace.
- Check permissions for cluster-level resources.
- Leverages the `internal/k8sutils` package.

**Build:**
Navigate to the project root directory:
```bash
go build -o k8schecker ./cmd/k8schecker
```

**Usage & Examples:**
(Refer to the comment block in `cmd/k8schecker/main.go` for detailed examples or run `./k8schecker --help`)

### `helmctl`

The `helmctl` is a command-line utility to manage Helm chart deployments and interact with Helm functionalities.

**Location:** `cmd/helmctl/main.go` (Corrected from htlmctl)

**Purpose:**
- List Helm releases in specified or all namespaces.
- Install Helm charts from repositories or local paths.
- Uninstall Helm releases.
- Upgrade existing Helm releases.
- Get detailed information about a release.
- View the history of a release.
- Add and update Helm chart repositories.
- Ensure a chart is locally available.
- Leverages the `internal/helmutils` package, which in turn uses `internal/k8sutils`.

**Build:**
Navigate to the project root directory:
```bash
go build -o helmctl ./cmd/helmctl
```

**Usage & Examples:**
(Refer to the comment block in `cmd/helmctl/main.go` for detailed examples or run `./helmctl --help` and `./helmctl <command> --help`)

## Internal Go Modules

These modules are designed to be reusable and provide core functionalities.

### Kubernetes Utilities (`internal/k8sutils`)

This module provides helper functions for interacting with Kubernetes.

#### `auth.go`
**Location:** `internal/k8sutils/auth.go`

**Purpose:**
This file contains the `AuthUtil` type and associated methods to handle Kubernetes client configuration, authentication, and authorization checks. It simplifies tasks such as:
-   Initializing a Kubernetes client (either in-cluster or from a kubeconfig file).
-   Determining if the application is running inside a Kubernetes cluster.
-   Retrieving the current namespace.
-   Performing `SelfSubjectAccessReview` checks for namespaced and cluster-scoped resources.

This utility is used by both the `k8schecker` and `helmctl` (via `helmutils`) CLI tools.

### Helm Utilities (`internal/helmutils`)

This module provides a client for performing Helm operations programmatically.

#### `client.go`
**Location:** `internal/helmutils/client.go`

**Purpose:**
This file contains the `Client` type that implements the `HelmClient` interface, offering methods to manage Helm operations. It uses the Helm SDK and relies on `internal/k8sutils` for Kubernetes configuration and authentication context. Key functionalities include:
-   `NewClient()`: Creates and initializes the Helm client.
-   Listing releases (`ListReleases`) with various state filters.
-   Installing charts (`InstallChart`) with options for version, values, namespace creation, and waiting.
-   Uninstalling releases (`UninstallRelease`) with options for history retention.
-   Upgrading releases (`UpgradeRelease`) with options for chart version, values, and installation if missing.
-   Fetching release details (`GetReleaseDetails`) and history (`GetReleaseHistory`).
-   Managing Helm repositories (`AddRepository`, `UpdateRepositories`).
-   Ensuring a chart is locally available (`EnsureChart`).

This utility is used by the `helmctl` CLI tool.

## Testing with the Umbrella Chart

The `umbrella-chart` located in the `umbrella-chart/` directory is not only for initial manual environment verification but can also be used as a target for testing the `helmctl` utility and, by extension, the `helmutils` package.

For example, after deploying the `umbrella-chart` as `my-umbrella-release` in the `dev` namespace:
```bash
# Ensure helmctl is built and in your PATH or use ./helmctl
helmctl --helm-namespace=dev list --filter my-umbrella-release
helmctl --helm-namespace=dev details my-umbrella-release
# (Adjust paths if helmctl is run from a different directory than the project root)
helmctl --helm-namespace=dev upgrade my-umbrella-release --chart=./umbrella-chart --set="prd.enabled=false"
helmctl --helm-namespace=dev uninstall my-umbrella-release
```

## Future Enhancements / To-Do List

This project has several planned enhancements to expand its capabilities and provide a more comprehensive solution for Kubernetes and Helm management. These include advanced K8s interactions, sophisticated chart management, database integration, a RESTful API backend, and a web UI.

For a detailed breakdown of planned features and ongoing tasks, please see the:

➡️ **[Project To-Do List](./TODO.md)**

We aim to adopt suitable design patterns (e.g., Repository, Strategy, modular design) to ensure the packages remain independent, configurable, and maintainable as the project grows.