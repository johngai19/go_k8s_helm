# Go Kubernetes & Helm Client Project

## Overview

This project is a Go application designed to interact with Kubernetes clusters and manage Helm chart deployments. It serves as an illustrative example of how to use the official Go client libraries for Kubernetes (`client-go`) and the Helm SDK. The project includes command-line utilities (`k8schecker`, `helmctl`) for direct interaction and testing, as well as internal utility packages (`k8sutils`, `helmutils`) that can be leveraged by other Go applications or within this project for more complex operations.

The `umbrella-chart/` subdirectory currently serves as an example chart for initial setup verification and testing. In a production-like setup driven by the planned features, user-managed charts would reside within a dedicated data directory.

## Prerequisites

Before you begin, ensure you have the following:

1.  **Go**: Version 1.18 or higher.
2.  **Kubernetes Cluster**: A running Kubernetes cluster (e.g., Minikube, Kind, Docker Desktop, or a cloud-managed cluster).
3.  **Helm CLI**: Helm v3 installed and configured to interact with your cluster.
4.  **kubectl**: The Kubernetes command-line tool, configured for your cluster.
5.  **Docker**: (Optional, for building and running as a container) Docker installed.

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
├── bin/                  # Compiled binary executables
│   ├── k8schecker
│   └── helmctl
├── cmd/
│   ├── k8schecker/
│   │   └── main.go     # Source for k8schecker CLI
│   └── helmctl/
│       └── main.go     # Source for helmctl CLI
├── internal/
│   ├── k8sutils/
│   │   ├── auth.go     # K8s authentication and permission utilities
│   │   └── auth_test.go
│   └── helmutils/
│       ├── client.go   # Helm client operations
│       └── client_test.go
├── umbrella-chart/     # Example Helm chart for environment testing
│   ├── Chart.yaml
│   └── ... (other chart files)
├── data/                 # Application data root (created by the app if not present)
│   ├── charts/           # For storing managed Helm chart products
│   ├── backups/          # For Helm release backups
│   ├── config/           # For application configuration files
│   ├── database/         # For SQLite database file (if used)
│   └── public/           # For compiled frontend static assets (future)
├── Dockerfile            # For building the application Docker image (future)
├── deployment.yaml       # Example Kubernetes deployment manifest (future)
├── go.mod                # Go module file
├── go.sum
├── TODO.md               # List of planned features and enhancements
└── README.md             # This file
```

## Data Management

The application will use a primary data directory, typically `./data/` relative to its execution path (or a path configured via environment variables when containerized). This directory will house various subdirectories for persistent and operational data:

-   **`data/charts/`**: Stores Helm chart "products" managed by the application.
-   **`data/backups/`**: Contains backups of Helm releases before upgrades or changes.
-   **`data/config/`**: Holds application-specific configuration files.
-   **`data/database/`**: If using the default SQLite database, the database file will be stored here.
-   **`data/public/`**: (Future) Will store compiled static assets for the frontend UI.

The application should be designed to create these subdirectories if they do not exist at startup. When deploying in Kubernetes, this entire `./data` directory should be mapped to a PersistentVolume.

## Command-Line Utilities

These utilities serve both as functional tools and as test harnesses for the underlying `internal` packages. Binaries are built into the `./bin/` directory.

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
go build -o ./bin/k8schecker ./cmd/k8schecker
```

**Usage & Examples:**
(Refer to the comment block in `cmd/k8schecker/main.go` for detailed examples or run `./bin/k8schecker --help`)

### `helmctl`

The `helmctl` is a command-line utility to manage Helm chart deployments and interact with Helm functionalities.

**Location:** `cmd/helmctl/main.go`

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
go build -o ./bin/helmctl ./cmd/helmctl
```

**Usage & Examples:**
(Refer to the comment block in `cmd/helmctl/main.go` for detailed examples or run `./bin/helmctl --help` and `./bin/helmctl <command> --help`)

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
# Ensure helmctl is built (e.g., in ./bin/)
./bin/helmctl --helm-namespace=dev list --filter my-umbrella-release
./bin/helmctl --helm-namespace=dev details my-umbrella-release
# (Adjust paths if helmctl is run from a different directory than the project root)
# Note: For local chart paths, ensure the path is correct relative to where helmctl is run.
# The umbrella-chart is at the project root. If running helmctl from project root:
./bin/helmctl --helm-namespace=dev upgrade my-umbrella-release --chart=./umbrella-chart --set="prd.enabled=false"
./bin/helmctl --helm-namespace=dev uninstall my-umbrella-release
```

## Dockerization (Future)

A `Dockerfile` will be provided to build the Go application (primarily the backend server component) into a container image. This will facilitate deployment in various containerized environments, including Kubernetes.

**Build (Example):**
```bash
docker build -t your-repo/go-k8s-helm-app .
```

## Kubernetes Deployment (Future)

An example `deployment.yaml` (or a Helm chart for the application itself) will be provided to deploy the application to a Kubernetes cluster.

**Key considerations for deployment:**
-   **Persistent Data:** The application's data directory (e.g., `/app/data` inside the container, mapped from the host's `./data` or a PV) must be mounted using a PersistentVolumeClaim to ensure data persistence across pod restarts and redeployments.
-   **Configuration:** Database connection strings, API keys, and other sensitive or environment-specific configurations should be managed via Kubernetes Secrets and/or ConfigMaps, and exposed to the application as environment variables or mounted files.
-   **Networking:** A Kubernetes Service will expose the application (e.g., the Gin API). An Ingress resource might be used for external access.

**Deployment (Example):**
```bash
kubectl apply -f deployment.yaml
```

## Future Enhancements / To-Do List

This project has several planned enhancements to expand its capabilities and provide a more comprehensive solution for Kubernetes and Helm management. These include advanced K8s interactions, sophisticated chart management, database integration, a RESTful API backend, and a web UI.

For a detailed breakdown of planned features and ongoing tasks, please see the:

➡️ **[Project To-Do List](./TODO.md)**

We aim to adopt suitable design patterns (e.g., Repository, Strategy, modular design) to ensure the packages remain independent, configurable, and maintainable as the project grows.

## Contributing

*(Contribution guidelines will be added here.)*

## License

*(License information will be added here.)*
