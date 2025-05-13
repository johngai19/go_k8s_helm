# Project To-Do List & Future Enhancements

This document outlines the planned features and enhancements for the Go Kubernetes & Helm Client project.

## I. Core Kubernetes & Helm Functionality

1.  **Advanced Helm Release Status & K8s Details:**
    *   **Description:** Enhance the ability to get detailed status for a Helm installation. This should go beyond basic Helm status and include information about the underlying Kubernetes resources.
    *   **Tasks:**
        *   Retrieve and display the status of running pods associated with a Helm release.
        *   Identify and report the status of dependent charts (subcharts).
        *   Provide a consolidated view of Deployment, StatefulSet, Service, Ingress, and other relevant K8s resource statuses tied to a release.
        *   Consider how to best integrate this into `helmutils` and expose it via `helmctl` or future APIs.

2.  **Helm Chart Pre-flight Checks & Value Templating:**
    *   **Description:** Implement a robust system for checking Helm charts before installation and for managing value templating. This aims to catch errors early and provide flexible value injection.
    *   **Tasks:**
        *   Develop a mechanism to replace placeholders (e.g., `@{variable}`(this is default format),`{{ .Values.some.path }}`, `%%PLACEHOLDER%%`, custom formats) in `values.yaml` and other YAML files within a chart.
        *   Support sourcing values from:
            *   Default `values.yaml`.
            *   Values files from dependent charts.
            *   A separate JSON file listing default values for placeholders.
            *   Runtime parameters.
        *   Implement checks for Helm chart format legality (e.g., required fields in `Chart.yaml`, template syntax).
        *   Generate a list of all required/available variables (see item #4).
        *   **Design Consideration:** Explore using Go's `text/template` or a dedicated templating engine.

3.  **Automatic Chart Backup & Versioned Restore/Rollback:**
    *   **Description:** Create a package for automatically backing up chart configurations before deployment and managing installation history for easy rollback or updates.
    *   **Tasks:**
        *   Before any install/upgrade, automatically copy the chart folder (with templated values applied) to a versioned backup directory (e.g., within the main data folder at `data/backups/<release-name>/<version-timestamp>/`).
        *   Maintain a history of these deployments (potentially in a database, see item #5).
        *   Allow listing installation history for a release.
        *   Default install/upgrade operations should use the latest processed chart from its backup/staging area.
        *   Implement rollback: Uninstall the current version and reinstall a selected historical version.
        *   Implement update-to-history: Similar to rollback, but allows "updating" to an older configuration as a new deployment.
        *   **Note:** This complements Helm's native history, especially if the strategy involves uninstall/reinstall for certain "upgrade" scenarios.

4.  **Chart Product Management & Variable Extraction:**
    *   **Description:** Develop a package to manage a local collection of Helm chart "products" (stored in `data/charts/`) and extract information from them.
    *   **Tasks:**
        *   Ability to list all available charts in the managed folder (`data/charts/`).
        *   For each chart, parse `Chart.yaml` and return its details (name, version, description, appVersion, etc.).
        *   Extract a list of all variables/placeholders that need to be filled for a chart:
            *   Prioritize a dedicated JSON file (e.g., `variables.json` or `schema.json`) within the chart folder that explicitly lists variables, their types, descriptions, and default values.
            *   If the JSON file doesn't exist, implement a fallback to walk through all `.yaml` files in the chart (templates, values files) to find placeholders (e.g., `@{variable}`(this is default format),`{{ .Values.some.path }}`, `%%PLACEHOLDER%%`, custom formats) and generate a preliminary list.
        *   API/function to add new charts to this managed folder, including support for unzipping `.zip` or `.tgz` chart archives.
        *   **Design Consideration:** This package would be crucial for UI-driven chart configuration.

## II. Backend & API Development

5.  **Database Integration (GORM):**
    *   **Description:** Integrate a database to store persistent application data.
    *   **Tasks:**
        *   Use GORM as the ORM.
        *   Default to SQLite (data file stored in `data/database/`) for ease of setup.
        *   Design for configurability to support external MSSQL, MySQL, and PostgreSQL instances.
        *   **Data to store:**
            *   Default values for chart variables (potentially encrypted if sensitive).
            *   User information (for authentication/authorization, see item #6).
            *   Kubernetes secrets or references to them (managed by the application).
            *   Installation history (release name, chart version, values used, timestamp, status, backup path from item #3).
            *   Chart metadata from the managed chart repository (item #4).
        *   Implement necessary encryption methods for sensitive data.
        *   **Design Consideration:** Repository pattern for database interactions to decouple business logic from GORM specifics. Strategy pattern for different database dialect support.

6.  **Gin Backend with RESTful API & JWT Authentication:**
    *   **Description:** Develop a RESTful API backend using the Gin framework.
    *   **Tasks:**
        *   Implement API endpoints for all functionalities currently in `helmctl` and planned features (chart management, deployment, history, status, etc.).
        *   Integrate Swagger/OpenAPI for API documentation.
        *   Implement JWT-based authentication and authorization.
        *   Define user roles (e.g., `admin`, `operator`, `viewer`) with different privileges for API endpoints.
        *   Secure API endpoints based on roles.

## III. Frontend Development

7.  **Next.js Frontend with Shadcn UI:**
    *   **Description:** Create a web-based user interface for interacting with the system.
    *   **Tasks:**
        *   Use Next.js for the frontend framework.
        *   Utilize Shadcn UI (or similar component library) for UI elements.
        *   Compiled frontend assets to be served from a static/public directory (e.g., `data/public/` if served by the Go backend, or managed by Next.js build process).
        *   **Features:**
            *   User login/logout (consuming JWT from backend).
            *   Dashboard to view a list of managed "products" (Helm releases/charts).
            *   View detailed information for each product/release (status, history, K8s resources).
            *   **Configuration Editing:**
                *   For general users/operators: Edit a defined list of variables (sourced from item #4's variable extraction).
                *   For admin users: Provide an interface to view and edit all files within a chart folder (e.g., a tree view of `values.yaml`, `Chart.yaml`, templates, etc.).
            *   **Deployment Workflow:**
                *   Allow users to deploy a chart (triggering backend processes: backup, value replacement, pre-flight checks, Helm install).
                *   Display real-time or polled deployment status.
                *   Options to upgrade an existing deployment (with new parameters/chart version).
                *   Options to roll back to a previous installation version.
                *   Option to uninstall a deployment.
            *   View deployment status and history.

## IV. Deployment & Operations

1.  **Dockerization:**
    *   **Description:** Package the application (Go backend) as a Docker image.
    *   **Tasks:**
        *   Create a multi-stage `Dockerfile` for building a lean production image.
        *   Ensure the image can be configured at runtime (e.g., via environment variables for database connections, data paths like the main `data` volume).
        *   Parameterize the data root folder path within the container.

2.  **Kubernetes Deployment Manifests:**
    *   **Description:** Provide Kubernetes manifests for deploying the application.
    *   **Tasks:**
        *   Develop a comprehensive Kubernetes deployment manifest (e.g., `deployment.yaml` or a Helm chart for the application itself).
        *   Include configurations for Deployment, Service, and potentially Ingress.
        *   Define `VolumeMounts` for the application's main data directory.
        *   Provide clear instructions on how to configure `PersistentVolumeClaims` (PVCs) to map to external `PersistentVolumes` (PVs) for persistent data storage.
        *   Ensure the application can gracefully handle being deployed in Kubernetes (e.g., readiness/liveness probes).

3.  **Configuration Management:**
    *   **Description:** Standardize application configuration.
    *   **Tasks:**
        *   Prioritize environment variables for configuration in containerized environments.
        *   Support configuration files (e.g., YAML) stored within the `data/config/` directory.
        *   Ensure configurations for database connections (including external ones), data paths, logging levels are easily managed.

## V. General & Architectural (Cross-Cutting Concerns & Best Practices)

*   **Modularity:** Design packages (`k8sutils`, `helmutils`, chart management, DB interaction, etc.) to be as independent and reusable as possible.
*   **Configurability:** Ensure components like database connections, logging levels, and potentially Helm driver types are configurable.
*   **Testing:** Expand unit and integration tests for all new packages and functionalities.
*   **Error Handling & Logging:** Implement consistent and robust error handling and logging throughout the application.
*   **CI/CD:** Set up a CI/CD pipeline for automated builds, testing, and potentially deployments.