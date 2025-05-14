# Go Kubernetes & Helm Client Project

## Overview

This project is a Go application that demonstrates interaction with Kubernetes clusters and Helm chart deployments. It includes:

- CLI tools:
  - **k8schecker**: verify cluster state & permissions  
  - **helmctl**: manage Helm releases  
  - **configloader**: one-time loader for `.conf` defaults  
- Internal utility packages:
  - **internal/k8sutils**  
  - **internal/helmutils**  
  - **internal/configloader**  
- An example Helm chart in `umbrella-chart/` for environment testing.

## Prerequisites

1. Go 1.18+  
2. Kubernetes cluster (Minikube, Kind, Docker Desktop, or cloud)  
3. Helm v3 CLI  
4. kubectl configured for your cluster  
5. Docker (optional—container builds)

## Getting Started

1. Clone the repo and `cd` into it.  
2. Build the CLIs:

   ```bash
   go build -o ./bin/k8schecker ./cmd/k8schecker
   go build -o ./bin/helmctl    ./cmd/helmctl
   go build -o ./bin/configloader ./cmd/configloader

   ```

3. Deploy the umbrella-chart to verify your setup:

   ```bash
   # follow instructions in umbrella-chart/README.md
   ```

4. Run any CLI with `--help` for usage examples.

## Project Structure

```bash
.
├── bin/                   
│   ├── k8schecker
│   ├── helmctl
│   └── configloader
├── cmd/
│   ├── k8schecker/        # CLI for K8s checks
│   ├── helmctl/           # CLI for Helm operations
│   └── configloader/      # CLI to load .conf defaults
├── internal/
│   ├── k8sutils/          # K8s client & auth helpers
│   ├── helmutils/         # Helm SDK wrappers
│   └── configloader/      # .conf parsing & variable resolution
├── umbrella-chart/        # Example chart for testing
├── data/                  # Persistent application data
│   ├── charts/
│   ├── backups/
│   ├── config/            # `configloader` default output:
│   │   └── all_variables.json
│   ├── database/
│   └── public/            # (future)
├── Dockerfile             # (future)
├── deployment.yaml        # (future)
├── go.mod
├── go.sum
├── TODO.md
└── README.md
```

## Data Management

At runtime, the application uses `./data/` (or a custom path) to store:

- `charts/` – managed Helm chart products  
- `backups/` – Helm release backups  
- `config/` – application `.conf` files & `all_variables.json`  
- `database/` – SQLite database file (if used)  
- `public/` – compiled static assets (future)  

Ensure these directories exist or are auto-created. In Kubernetes, map `./data` to a PersistentVolume.

## Command-Line Utilities

### k8schecker

Interact with Kubernetes and verify permissions.

```bash
go build -o ./bin/k8schecker ./cmd/k8schecker
./bin/k8schecker --help
```

### helmctl

Manage Helm releases programmatically.

```bash
go build -o ./bin/helmctl ./cmd/helmctl
./bin/helmctl <command> --help
```

### configloader

One-time loader for `.conf` defaults. It:

- Discovers `install(.env).conf` & `conf(-env)/`  
- Parses `key=value` (supports quotes, strips comments)  
- Substitutes `${VAR}` & `$VAR` (safe for circular refs)  
- Optionally groups `database_*.conf` under `database_configs`  
- Emits a single JSON blob

**Default output path:**

```bash
./data/config/all_variables.json
```

**Build & run:**

```bash
go build -o ./bin/configloader ./cmd/configloader
./bin/configloader \
  --basepath=./deployment \
  --env=dev \
  --files="override.conf,extra/" \
  --dbgrouping=true \
  --output=all_variables.json
```

**Sample `all_variables.json`:**

```json
{
  "main": {
    "KEY1": "value1",
    "KEY2": "value2"
  },
  "database_configs": {
    "mysql": {
      "MYSQL_HOST": "host",
      "DB_USER": "user"
    },
    "postgres": {
      "PG_HOST": "host",
      "DB_USER": "user"
    }
  },
  "metadata": {
    "source_type": "default_discovery",
    "parsed_files": ["install.conf","conf/app.conf"],
    "database_grouping_enabled": true,
    "extraction_date": "2025-05-14T12:34:56Z",
    "extractor_tool": "Go configloader package"
  }
}
```

## Internal Modules

### internal/k8sutils

Helpers for Kubernetes client, in-cluster vs kubeconfig, and auth checks.

### internal/helmutils

Wrappers around Helm SDK for installs, upgrades, repos, etc.

### internal/configloader

Parses and resolves `.conf` files with variable substitution and grouping.

## Testing with Umbrella Chart

Deploy `umbrella-chart/` in `dev` namespace:

```bash
./bin/helmctl --helm-namespace=dev install my-umbrella ./umbrella-chart
./bin/helmctl --helm-namespace=dev list --filter my-umbrella
./bin/helmctl --helm-namespace=dev uninstall my-umbrella
```

## Future Enhancements

See [TODO.md](./TODO.md) for planned features: API server, web UI, advanced DB integration, etc.

## Contributing

Contributions welcome—please open issues or pull requests.

## License

[MIT License](./LICENSE)
