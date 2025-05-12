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
├── umbrella-chart/     # Helm umbrella chart for environment testing and Go app tests
│   ├── Chart.yaml
│   ├── values.yaml
│   ├── charts/
│   │   ├── dv/
│   │   └── prd/
│   └── README.md       # Detailed guide for deploying the umbrella chart
├── main.go             # Example Go application entrypoint (to be developed)
├── go.mod              # Go module file
└── README.md           # This file
```

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