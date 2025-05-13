# Umbrella Chart for Nginx Environments (umbrella-chart)

## Purpose

This Helm chart serves as a practical example of an **Umbrella Chart**. Its primary goal is to illustrate how to use Helm's umbrella chart pattern to manage deployments of an application (Nginx, in this case) across multiple distinct environments, such as Development (`dv`) and Production (`prd`), from a single top-level chart.

This approach helps in:
- Centralizing common configurations (e.g., image repository, default service ports).
- Managing multiple application components or environment-specific instances as dependencies (subcharts).
- Providing environment-specific overrides for tailored deployments.
- Simplifying the deployment lifecycle and promoting consistency across different stages.

## Prerequisites

- A running Kubernetes cluster.
- [Helm v3](https://helm.sh/docs/intro/install/) installed on your local machine.
- **Required Kubernetes Secret**: This chart, specifically the `prd` subchart, requires a Kubernetes Secret to be present in the cluster before installation. The default expected Secret name is `my-app-credentials` (configurable in `values.yaml` via `global.requiredSecretName`). You must create this Secret manually. See the "Create the Required Secret" section for methods to create it. If this Secret is not present and the check in `charts/prd/templates/service.yaml` is active, the installation will fail.

### Installing Helm (Example)

If you don't have Helm installed, you can use the script installation method (common for Linux/macOS):

1.  Download the installation script:
    ```bash
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    ```
2.  Add execution permissions:
    ```bash
    chmod 700 get_helm.sh
    ```
3.  Run the installation script:
    ```bash
    ./get_helm.sh
    ```
4.  Verify the installation:
    ```bash
    helm version
    ```
    You should see output similar to: `version.BuildInfo{Version:"v3.13.1", GitTreeState:"clean", GoVersion:"go1.20.8"}` (your version may vary).

### 2. Create the Required Secret (Important!)

Before installing the chart, you **must** create the required Kubernetes Secret in your cluster. The `prd` subchart's `service.yaml` template (`charts/prd/templates/service.yaml`) contains logic to check for this Secret (default name: `my-app-credentials` in the `default` namespace, as defined in `global.requiredSecretName` and `global.namespace` in `umbrella-chart/values.yaml`).

You can create this Secret in one of the following ways:

**Method 1: Using `kubectl create secret generic`**

Use the following command to create an example Secret. Adjust the Secret name, data, and namespace (`-n`) as needed:
```bash
kubectl create secret generic my-app-credentials \
  --from-literal=username='admin' \
  --from-literal=password='supersecret123' \
  --namespace default
```

**Method 2: Using a YAML manifest file**

A sample manifest file `required-secret.yaml` is provided in the `umbrella-chart` directory. You can customize it and then apply it:
```yaml
# umbrella-chart/required-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-app-credentials
  namespace: default
type: Opaque
data:
  username: YWRtaW4= # base64 encoded "admin"
  password: c3VwZXJzZWNyZXQxMjM= # base64 encoded "supersecret123"
```
Deploy it using:
```bash
kubectl apply -f ./umbrella-chart/required-secret.yaml
```

**Note on the Secret Check in `prd` subchart:**

The check for this Secret is implemented at the beginning of the `umbrella-chart/charts/prd/templates/service.yaml` file:
```helm
{{- $secretName := .Values.global.requiredSecretName -}}
{{- $namespace := .Values.global.namespace -}}
{{- $secret := lookup "v1" "Secret" $namespace $secretName }}
{{- if not $secret -}}
  {{- required (printf "The required Secret '%s' in namespace '%s' was not found. Please create it or comment out this check." $secretName $namespace) "" -}}
{{- end -}}
```

If you do not want this Secret dependency for the `prd` environment, or if you manage the Secret through other means and want to bypass this explicit Helm check, you can comment out this block in `umbrella-chart/charts/prd/templates/service.yaml`. To comment it out, modify the file as follows:

```helm
{{- /*
{{- $secretName := .Values.global.requiredSecretName -}}
{{- $namespace := .Values.global.namespace -}}
{{- $secret := lookup "v1" "Secret" $namespace $secretName }}
{{- if not $secret -}}
  {{- required (printf "The required Secret '%s' in namespace '%s' was not found. Please create it or comment out this check." $secretName $namespace) "" -}}
{{- end -}}
*/}}

apiVersion: v1
kind: Service
```
Remember to rebuild dependencies if you modify subchart templates directly, although for template changes `helm install/upgrade` usually picks them up.

## Chart Structure

This umbrella chart (`umbrella-chart`) manages two subcharts, one for each environment (`dv` and `prd`). The subcharts are located within the `charts/` directory of the umbrella chart.

```
umbrella-chart/
├── Chart.yaml          # Metadata for the umbrella chart. Defines dv and prd as dependencies.
├── values.yaml         # Global default values accessible by all subcharts.
├── charts/             # Directory containing subchart sources.
│   ├── dv/             # Subchart for the Development (dv) environment.
│   │   ├── Chart.yaml      # Metadata for the dv subchart.
│   │   ├── values.yaml     # dv-specific configuration values.
│   │   └── templates/      # dv-specific Kubernetes manifest templates.
│   │       ├── deployment.yaml
│   │       └── service.yaml
│   └── prd/            # Subchart for the Production (prd) environment.
│       ├── Chart.yaml      # Metadata for the prd subchart.
│       ├── values.yaml     # prd-specific configuration values.
│       └── templates/      # prd-specific Kubernetes manifest templates.
│           ├── deployment.yaml
│           └── service.yaml
└── README.md           # This file.
```

-   **`umbrella-chart/Chart.yaml`**: Describes the umbrella chart and lists `dv` and `prd` as dependencies using `file://./charts/dv` and `file://./charts/prd` repositories, indicating they are local subcharts.
-   **`umbrella-chart/values.yaml`**: Contains global values. These can be accessed by subcharts using `{{ .Values.global.someValue }}`.
-   **`umbrella-chart/charts/dv/`**: The `dv` subchart. Its `values.yaml` defines configurations specific to the development environment (e.g., lower replica count).
-   **`umbrella-chart/charts/prd/`**: The `prd` subchart. Its `values.yaml` defines configurations specific to the production environment (e.g., higher replica count).

## Configuration

Configuration is managed at multiple levels:

1.  **Global Values (`umbrella-chart/values.yaml`)**:
    These values are intended to be shared across all subcharts.
    Example from `umbrella-chart/values.yaml`:
    ```yaml
    global:
        namespace: default
        image:
            repository: nginx
            tag: "1.19"
        service:
            port: 80 # Default port for services in subcharts
    ```

2.  **Environment-Specific Values (e.g., `umbrella-chart/charts/dv/values.yaml`)**:
    Each subchart has its own `values.yaml` file for environment-specific settings. These values are accessed within the subchart's templates as `{{ .Values.someKey }}`.
    Example from `umbrella-chart/charts/dv/values.yaml`:
    ```yaml
    replicaCount: 1
    name: nginx-dv
    fullname: nginx-dv # Used for naming resources
    ```
    Example from `umbrella-chart/charts/prd/values.yaml`:
    ```yaml
    replicaCount: 3 # Higher replica count for production
    name: nginx-prd
    fullname: nginx-prd # Used for naming resources
    ```

## Usage

### 1. Preparation: Build Dependencies

Since the subcharts (`dv` and `prd`) are local file dependencies, you first need to build the dependency list. This command processes the local subcharts and prepares them for packaging, also creating/updating `Chart.lock`.

Navigate to the directory containing the `umbrella-chart` folder (e.g., `d:\WSL\repos\temp`):
```bash
helm dependency build ./umbrella-chart
```
You should see output like:
```
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "dv" chart repository
...Successfully got an update from the "prd" chart repository
Update Complete. ⎈Happy Helming!⎈
Saving 2 charts
Deleting outdated charts
```

### 3. Installation

Once the dependencies are built and the required Secret is created, install the umbrella chart. This will deploy the resources defined in both the `dv` and `prd` subcharts into the Kubernetes cluster.

```bash
helm install nginx-umbrella-release ./umbrella-chart --namespace default
```
-   `nginx-umbrella-release`: This is the name for your Helm release. You can choose any name.
-   `./umbrella-chart`: Path to your umbrella chart directory.
-   `--namespace default`: Specifies the Kubernetes namespace for deployment. This aligns with `global.namespace` in your `umbrella-chart/values.yaml`.

### 3. Verification

After installation, verify the deployment:

**a. List Helm Releases:**
```bash
helm list -n default
```
Expected output:
```
NAME                    NAMESPACE   REVISION    UPDATED                                 STATUS      CHART                   APP VERSION
nginx-umbrella-release  default     1           2025-05-12 10:00:00.000000000 +0000 UTC deployed    umbrella-chart-0.1.0    1.0
```

**b. Check Release Status:**
```bash
helm status nginx-umbrella-release -n default
```
This command provides detailed information about the deployed resources.

**c. Check the Required Secret:**
You can verify that the Secret exists and inspect its contents. For detailed instructions on how to check for the Secret and view its data, please refer to the [How to Check for a Kubernetes Secret](./docs/check-secret-existence.md) guide.

A quick check can be performed as follows:
To check if the Secret `my-app-credentials` exists in the `default` namespace:
```bash
kubectl get secret my-app-credentials -n default
```
To view the decoded data within the Secret (requires `jq` to be installed for easy viewing, or decode manually):
```bash
# Using jq
kubectl get secret my-app-credentials -n default -o jsonpath='{.data}' | jq 'map_values(@base64d)'

# Or, to get specific fields decoded:
echo "Username:"
kubectl get secret my-app-credentials -n default -o jsonpath='{.data.username}' | base64 --decode
echo ""
echo "Password:"
kubectl get secret my-app-credentials -n default -o jsonpath='{.data.password}' | base64 --decode
echo ""
```

**d. Check Kubernetes Deployments:**
Deployments from both `dv` and `prd` subcharts should be created.
```bash
kubectl get deployments -n default
```
Expected output (replica counts depend on subchart `values.yaml`):
```
NAME                   READY   UP-TO-DATE   AVAILABLE   AGE
nginx-dv-deployment    1/1     1            1           2m
nginx-prd-deployment   3/3     3            3           2m
```

**e. Check Kubernetes Pods:**
```bash
kubectl get pods -n default -l "app=nginx"
```
Expected output (number of pods matches replica counts):
```
NAME                                    READY   STATUS    RESTARTS   AGE
nginx-dv-deployment-xxxxxxxxxx-xxxxx    1/1     Running   0          2m
nginx-prd-deployment-yyyyyyyyyy-yyyyy   1/1     Running   0          2m
nginx-prd-deployment-yyyyyyyyyy-zzzzz   1/1     Running   0          2m
nginx-prd-deployment-yyyyyyyyyy-aaaaa   1/1     Running   0          2m
```
*(Pod name suffixes `xxxxxxxxxx-xxxxx` will be auto-generated.)*

**f. Check Kubernetes Services:**
Services defined in subcharts should be created.
```bash
kubectl get services -n default
```
Expected output (service names depend on `fullname` in subchart `values.yaml`):
```
NAME                TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
nginx-dv-service    ClusterIP   10.100.10.1     <none>        80/TCP    2m
nginx-prd-service   ClusterIP   10.100.20.2     <none>        80/TCP    2m
kubernetes          ClusterIP   10.96.0.1       <none>        443/TCP   ...
```
*(The port `80/TCP` should correspond to `{{ .Values.global.service.port }}` from `umbrella-chart/values.yaml` and `targetPort: 80` in service templates.)*

### 4. Upgrading the Release

If you modify the chart (e.g., update `values.yaml` files or templates):

1.  Rebuild dependencies if subchart structures or `Chart.yaml` files changed:
    ```bash
    helm dependency build ./umbrella-chart
    ```
2.  Upgrade the release:
    ```bash
    helm upgrade nginx-umbrella-release ./umbrella-chart --namespace default
    ```

### 5. Uninstalling the Release

To remove all Kubernetes resources deployed by this chart:
```bash
helm uninstall nginx-umbrella-release -n default
```

## Uninstalling the Chart and Cleaning Up

To remove the deployed Helm release and any manually created resources like the required Secret, please refer to the [Cleanup Guide](./docs/cleanup-guide.md).

## Other Useful Helm Commands

-   **Dry Run Installation (template rendering):**
    View the Kubernetes manifests that Helm would generate, without actually deploying them. This is useful for debugging.
    ```bash
    helm template nginx-umbrella-release ./umbrella-chart --namespace default --debug
    ```
    *(Ensure dependencies are built first: `helm dependency build ./umbrella-chart`)*

-   **Get Values:**
    Inspect the computed values for a deployed release:
    ```bash
    helm get values nginx-umbrella-release -n default
    ```

-   **Lint Chart:**
    Check the chart for possible issues:
    ```bash
    helm lint ./umbrella-chart
    ```

## Conclusion

By leveraging umbrella charts, you can effectively manage complex applications across multiple environments. This pattern promotes modularity, reusability, and consistency in your Kubernetes deployments. The "umbrella-chart" provides a clear, high-level way to orchestrate various components (represented by subcharts), each tailored to its specific environment, while still allowing for global configuration and control.

# Guide to Testing Umbrella Chart on Minikube

This document will guide you on how to test the created `my-umbrella-chart` in a Minikube environment.

## Prerequisites

Before you begin, ensure you have the following software installed on your system:

1.  **Minikube**: A tool for running a single-node Kubernetes cluster locally. You can find installation instructions in the [Minikube official documentation](https://minikube.sigs.k8s.io/docs/start/).
2.  **Helm**: The package manager for Kubernetes. You can find installation instructions in the [Helm official documentation](https://helm.sh/docs/intro/install/).
3.  **kubectl**: The Kubernetes command-line tool. It is usually installed with Minikube, or you can install it separately.

## Testing Steps

### 1. Start Minikube

If your Minikube is not already running, start it:

```bash
minikube start
```

This may take a few minutes depending on your system configuration.

### 2. Navigate to the Chart Directory

Open a terminal and navigate to the directory containing `my-umbrella-chart`:

```bash
cd /path/to/your/my-umbrella-chart
# For example, if the chart is in /ubuntu/my-umbrella-chart
# cd /ubuntu/my-umbrella-chart
```

### 3. Update Chart Dependencies (Optional)

Since our subcharts are local dependencies (specified via `file://` paths), explicitly running `helm dependency update` is often not necessary. Helm automatically handles local dependencies during packaging or installation. However, this step is required if dependencies are fetched from remote repositories.

To ensure dependencies are up-to-date (especially if the subchart's `Chart.yaml` version is modified in the future), you can run:

```bash
helm dependency build ./my-umbrella-chart
# Or, when in the my-umbrella-chart directory
# helm dependency build .
```

Alternatively, and more commonly, run in the parent chart directory:

```bash
cd /path/to/your/my-umbrella-chart
helm dependency update
```

This will check the dependencies defined in `Chart.yaml` and download them to the `charts/` directory (if they are remote) or verify local paths.

### 4. Lint the Chart (Check for Syntax Errors)

Before installation, it's good practice to lint the chart to catch any YAML formatting or template errors:

```bash
helm lint ./my-umbrella-chart
# Or, when in the my-umbrella-chart directory
# helm lint .
```

If everything is correct, you should see output similar to:

```
[INFO] Chart.yaml: icon is recommended

1 chart(s) linted, 0 chart(s) failed
```

### 5. Install the Umbrella Chart

Now, you can use the `helm install` command to install the umbrella chart into your Minikube cluster. We will specify a name for the release, for example, `my-app`.

```bash
helm install my-app ./my-umbrella-chart --namespace default
# Or, when in the my-umbrella-chart directory
# helm install my-app . --namespace default
```

The `--namespace default` is optional; replace `default` if you want to install into a specific namespace.

Upon successful installation, Helm will output information about the release, including the deployed resources.

### 6. Check Deployment Status

You can use `kubectl` to check the status of deployed Pods, Services, etc.:

View all Pods:
```bash
kubectl get pods -n default
```
You should see Pods for the frontend, backend, and database running or being created.

View all Services:
```bash
kubectl get services -n default
```
You should see Services created for the frontend, backend, and database.

View logs for a specific deployment (e.g., backend Pod):
```bash
# First, get the name of the backend pod
kubectl get pods -l app=backend -n default
# Then, view the logs, replacing <backend-pod-name>
kubectl logs <backend-pod-name> -n default
```

### 7. Access the Application

The method for accessing the application will vary depending on the type configured for the frontend service in your `values.yaml`.

*   **If the frontend service type is `ClusterIP` (as in the default configuration):**
    You need to use port forwarding to access it from your local machine:

    ```bash
    # Get the exact name of the frontend service (e.g., my-app-frontend-service)
    kubectl get svc -l app=frontend -n default
    # Assuming the service name is my-app-frontend-service and the port is 80
    kubectl port-forward svc/my-app-frontend-service 8080:80 -n default
    ```
    Then, you can access the frontend in your browser at `http://localhost:8080`.

*   **If the frontend service type is `LoadBalancer` or `NodePort`:**
    Minikube provides an easier way to access these types of services:

    ```bash
    minikube service my-app-frontend-service -n default
    ```
    This command usually opens the service URL in your browser automatically.

    **Note**: Backend and database services are typically configured as `ClusterIP` because they are primarily accessed by other services within the cluster (like the frontend or backend) rather than directly from outside.

### 8. Uninstall the Chart

Once testing is complete, you can uninstall the application using the `helm uninstall` command:

```bash
helm uninstall my-app -n default
```

This will delete all Kubernetes resources deployed by this Helm chart.

## Troubleshooting

*   **Pod status is `ImagePullBackOff` or `ErrImagePull`**:
    *   Check if the image name and tag specified in `values.yaml` are correct.
    *   Ensure Minikube can access the image repository. For locally built images, you might need to load the image into Minikube's Docker daemon (e.g., using `minikube image load my-image:tag`) or configure Minikube to use your local Docker daemon (`eval $(minikube -p minikube docker-env)`).
    *   In our example, the backend image `my-backend-app` is a placeholder. You need to replace it with an actual available image or build a simple backend application and push its image to an accessible repository or load it into Minikube.
*   **Helm installation fails**:
    *   Carefully read Helm's error output.
    *   Use `helm lint .` and `helm template . --debug` to debug template rendering issues.
*   **Service is inaccessible**:
    *   Confirm that the service and Pods are running correctly (`kubectl get pods,svc`).
    *   Check if port forwarding or the `minikube service` command is correct.
    *   View the logs of relevant Pods for more clues.

By following these steps, you should be able to successfully test your Helm umbrella chart on Minikube.