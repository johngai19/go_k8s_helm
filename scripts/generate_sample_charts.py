import os
import yaml
import json
import copy # For deep copying configurations
import argparse # For CLI arguments
import random

# Get the directory of the current script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Define BASE_DIR relative to the script's directory and then make it absolute
BASE_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "data", "charts"))
ALL_VARIABLES_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "data", "config", "all_variables.json"))

# --- Helper Functions for Variable Handling ---
def load_all_variables(path):
    print(f"Attempting to load variables from: {path}")
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            print("Successfully loaded all_variables.json")
            return data
    except FileNotFoundError:
        print(f"Error: {path} not found. Proceeding with empty variables.")
        return {}
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {path}. Proceeding with empty variables.")
        return {}

def get_nested_val(data_dict, key_path, default=None):
    if not key_path: # Handle cases where key_path might be None or empty
        return default
    keys = key_path.split('.')
    val = data_dict
    try:
        for key in keys:
            val = val[key]
        return val
    except (KeyError, TypeError, AttributeError):
        return default

def set_nested_val(data_dict, key_path, value):
    keys = key_path.split('.')
    d = data_dict
    for i, key in enumerate(keys[:-1]):
        if isinstance(d, dict):
            d = d.setdefault(key, {})
        elif isinstance(d, list) and key.isdigit() and int(key) < len(d): # Basic list support
            d = d[int(key)]
            if not isinstance(d, dict) and i < len(keys) - 2:
                 print(f"Warning: Trying to set a key on a non-dict element in a list for path {key_path}")
                 return
        else:
            print(f"Warning: Cannot set nested value for path {key_path} at segment '{key}'. Structure issue.")
            return
    if isinstance(d, dict):
        d[keys[-1]] = value
    else:
        print(f"Warning: Cannot set final key '{keys[-1]}' for path {key_path}. Penultimate element not a dict.")

def process_value_for_version(value, all_vars_data, use_placeholders):
    """
    Processes a value. If it's a 'VAR:' string, resolves it or creates a placeholder.
    Handles nested dicts/lists by recursively processing their string values.
    """
    if isinstance(value, dict):
        return {k: process_value_for_version(v, all_vars_data, use_placeholders) for k, v in value.items()}
    elif isinstance(value, list):
        return [process_value_for_version(item, all_vars_data, use_placeholders) for item in value]
    elif isinstance(value, str) and value.startswith("VAR:"):
        var_path = value[4:]
        if use_placeholders:
            # Extract only the last part of the variable path for the placeholder name
            simple_var_name = var_path.split('.')[-1]
            return f"@{{{simple_var_name}}}" # Generates @{LAST_PART_OF_VARIABLE}
        else:
            # Resolve the variable from all_vars_data
            resolved_value = get_nested_val(all_vars_data, var_path)

            # Special handling for main.REGISTRY in working charts
            if var_path == "main.REGISTRY":
                if resolved_value is None or resolved_value == "hub.fano.ai":
                    print(f"    INFO: main.REGISTRY is '{resolved_value}'. Defaulting to empty registry (Docker Hub) for working chart.")
                    return "" # Default to empty string, implying Docker Hub for common images
                return resolved_value

            if resolved_value is None: # Check if key path truly didn't resolve for other variables
                return f"MISSING_VAR_VALUE_FOR_{var_path}"
            return resolved_value # Could be empty string, number, bool, etc.
    return value


ALL_VARIABLES = load_all_variables(ALL_VARIABLES_PATH)

# --- Chart Configuration ---
CHARTS_CONFIG = [
    {
        "name": "appstack-alpha",
        "description": "Alpha application stack with web frontend and caching.",
        "subcharts": [
            {
                "name": "frontend-nginx",
                "image_repository": "VAR:main.REGISTRY", # Will use "" (Docker Hub) or actual from all_variables
                "image_tag": "1.25",
                "port": 80,
                "service_type": "LoadBalancer",
                "check": "curl http://<LoadBalancer-IP>",
                "values_from_all_vars": {
                    "config.timezone": "main.TIMEZONE", # Assuming TIMEZONE is in all_variables.json
                    "resources.requests.cpu": "main.NGINX_CPU_REQUEST",
                }
            },
            {
                "name": "cache-redis-alpha",
                "image_repository": "redis",
                "image_tag": "VAR:main.REDIS_IMAGE_TAG", # Assuming REDIS_IMAGE_TAG is in all_variables.json
                "port": 6379,
                "service_type": "ClusterIP",
                "check": "kubectl exec <pod-name> -- redis-cli ping",
                "values_from_all_vars": {
                    "config.host": "main.REDIS_HOST", # Assuming REDIS_HOST is in all_variables.json
                    "config.password": "main.REDIS_PASSWORD"
                }
            },
        ],
        "umbrella_values_overrides": {
            "frontend-nginx": {
                "replicaCount": 2,
                "image_tag": "latest",
                "config": {"timezone": "VAR:main.TIMEZONE"} 
            },
            "cache-redis-alpha": {
                "resources": {"limits": {"memory": "512Mi"}}
            }
        },
        "tags_values": {
            "global": {"environment_tag": "alpha-tagged", "cloud_provider": "VAR:main.DEFAULT_WORKSPACE"},
            "frontend-nginx": {
                "image_tag": "VAR:main.DEFAULT_WORKSPACE"
            }
        }
    },
    {
        "name": "appstack-beta",
        "description": "Beta application stack with API and worker.",
        "subcharts": [
            {
                "name": "api-service-beta",
                "image_repository": "httpd",
                "image_tag": "2.4",
                "port": 8080,
                "service_type": "ClusterIP",
                "check": "curl http://<api-service-beta-cluster-ip>:8080/api/health",
                "values_from_all_vars": {
                    "config.apiBasePath": "main.API_BASE_PATH",
                    "config.sftpHost": "main.SFTP_HOST",
                    "config.elasticHost": "main.ELASTICSEARCH_HOST" # Using a var from all_variables.json
                }
            },
            {
                "name": "worker-beta",
                "image_repository": "busybox",
                "image_tag": "latest",
                "port": None, "service_type": None,
                "check": "kubectl logs -l app=worker-beta",
                 "values_from_all_vars": {
                    "config.inputPath": "main.INPUT_ROOT_PATH",
                    "config.outputPath": "main.OUTPUT_ROOT_PATH",
                    "config.azureSpeechKey": "main.AZURE_TTS_SPEECH_KEY" # Using a var
                }
            },
        ],
        "umbrella_values_overrides": {
            "api-service-beta": {"replicaCount": 3, "config": {"apiBasePath": "/beta/v1"}},
            "worker-beta": {"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}}}
        }
    },
    {
        "name": "appstack-gamma-db",
        "description": "Gamma application stack with a database dependency.",
        "subcharts": [
            {
                "name": "app-gamma",
                "image_repository": "alpine/git",
                "image_tag": "latest",
                "port": 8888,
                "service_type": "ClusterIP",
                "check": "kubectl exec <pod-name> -- git --version",
                "values_from_all_vars": {
                    "config.dbClient": "database_configs.mysql.RDBMS_DB_CLIENT",
                    "config.dbHost": "database_configs.mysql.RDBMS_SERVER_URL",
                    "config.dbName": "database_configs.mysql.RDBMS_DATABASE_NAME",
                    "config.registry": "main.REGISTRY"
                }
            },
        ],
        "umbrella_values_overrides": {
            "app-gamma": {
                "replicaCount": 1,
                "config": {
                    "dbHost": "VAR:database_configs.postgres.RDBMS_SERVER_URL",
                    "dbClient": "VAR:database_configs.postgres.RDBMS_DB_CLIENT",
                    "dbName": "VAR:database_configs.postgres.RDBMS_DATABASE_NAME"
                }
            }
        },
        "tags_values": {
            "global": {"environment_tag": "gamma-db-tagged", "data_center": "VAR:main.DATA_CENTER_GAMMA"},
            "app-gamma": {
                "config": {"dbName": "VAR:database_configs.postgres.RDBMS_DATABASE_NAME_TAGGEDE"}
            }
        }
    },
]

# --- Fix any missing VAR: placeholders in CHARTS_CONFIG ---
valid_var_paths = []
def _flatten_paths(d, prefix=""):
    for k, v in d.items():
        p = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _flatten_paths(v, p)
        else:
            valid_var_paths.append(p)

_flatten_paths(ALL_VARIABLES)  # build list of real variable paths

def _fix_placeholders(obj):
    if isinstance(obj, dict):
        return {k: _fix_placeholders(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fix_placeholders(i) for i in obj]
    if isinstance(obj, str) and obj.startswith("VAR:"):
        var_path = obj[4:]
        if get_nested_val(ALL_VARIABLES, var_path) is None:
            new_var = random.choice(valid_var_paths)
            print(f"WARNING: placeholder '{var_path}' not found; replacing with '{new_var}'")
            return f"VAR:{new_var}"
        return obj
    return obj

# apply the fixer to every umbrella chart definition
CHARTS_CONFIG = [_fix_placeholders(uc) for uc in CHARTS_CONFIG]

# --- File Generation Functions ---
def create_dir(path):
    abs_path = os.path.abspath(path)
    os.makedirs(abs_path, exist_ok=True)
    print(f"Ensured directory exists: {abs_path}")

def write_file(path, content):
    abs_path = os.path.abspath(path)
    print(f"Writing file to: {abs_path}")
    with open(abs_path, 'w') as f:
        f.write(content)

def create_chart_yaml(chart_name, chart_version, app_version, description, dependencies, path, chart_type="application"):
    chart_data = {
        "apiVersion": "v2", "name": chart_name, "description": description,
        "type": chart_type, "version": chart_version, "appVersion": app_version,
    }
    if dependencies: chart_data["dependencies"] = dependencies
    write_file(os.path.join(path, "Chart.yaml"), yaml.dump(chart_data, sort_keys=False))

def create_subchart_values_yaml(subchart_def, all_vars_data, path, use_placeholders):
    values_data = {
        "replicaCount": 1,
        "image": {
            "repository": process_value_for_version(subchart_def.get("image_repository"), all_vars_data, use_placeholders),
            "tag": process_value_for_version(subchart_def.get("image_tag"), all_vars_data, use_placeholders),
            "pullPolicy": "IfNotPresent"
        },
        "resources": { # Define valid defaults for all resource fields
            "limits": {"cpu": "500m", "memory": "256Mi"},
            "requests": {"cpu": "100m", "memory": "128Mi"}
        },
        "config": {}
    }
    if subchart_def.get("port") is not None:
        values_data["service"] = {
            "port": subchart_def["port"],
            "type": subchart_def["service_type"]
        }

    if "values_from_all_vars" in subchart_def:
        for target_key_path, source_var_path in subchart_def["values_from_all_vars"].items():
            if source_var_path: # If source_var_path is None, it's a pre-defined value not from all_vars
                # Standard processing to get placeholder or resolved/missing value string
                value_for_processing = f"VAR:{source_var_path}"
                processed_value = process_value_for_version(value_for_processing, all_vars_data, use_placeholders)

                # Special handling for resource quantities in 'working' charts
                if not use_placeholders and target_key_path.startswith("resources."):
                    # Check the original variable in all_vars_data, not the "MISSING_VAR..." string
                    actual_var_value = get_nested_val(all_vars_data, source_var_path)
                    if actual_var_value is None or actual_var_value == "":
                        # If the variable is truly missing or empty in all_variables.json,
                        # skip setting this specific resource value.
                        # This allows the hardcoded defaults in `values_data` (e.g., "100m") to be used.
                        print(f"    INFO: Variable '{source_var_path}' for resource path '{target_key_path}' is missing or empty in all_variables.json. Using default value for subchart '{subchart_def['name']}'.")
                        continue # Skip set_nested_val for this resource key
                    else:
                        # Variable exists and is not empty, use its processed value (which should be the actual value)
                        set_nested_val(values_data, target_key_path, processed_value)
                else:
                    # For non-resource paths or for placeholder charts, set the processed value as usual
                    set_nested_val(values_data, target_key_path, processed_value)

    if not values_data.get("config"): del values_data["config"] # Remove empty config
    write_file(os.path.join(path, "values.yaml"), yaml.dump(values_data, sort_keys=False, indent=2))
    return values_data

def create_umbrella_values_yaml(umbrella_def, all_vars_data, path, use_placeholders):
    values_data = process_value_for_version(copy.deepcopy(umbrella_def.get("umbrella_values_overrides", {})), all_vars_data, use_placeholders)
    values_data["global"] = process_value_for_version(
        {"environment": "development", "umbrellaName": umbrella_def["name"], "default_registry": "VAR:main.REGISTRY"}, # This will also use the updated logic
        all_vars_data, use_placeholders
    )
    write_file(os.path.join(path, "values.yaml"), yaml.dump(values_data, sort_keys=False, indent=2))

def create_values_tags_yaml(umbrella_def, all_vars_data, path, use_placeholders):
    tags_data_template = umbrella_def.get("tags_values", {})
    if not tags_data_template: return

    tags_data = process_value_for_version(copy.deepcopy(tags_data_template), all_vars_data, use_placeholders)
    write_file(os.path.join(path, "values-tags.yaml"), yaml.dump(tags_data, sort_keys=False, indent=2))

def create_deployment_yaml(path):
    deployment = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{{{ .Chart.Name }}}}-{{{{ .Release.Name }}}}
  labels:
    app.kubernetes.io/name: {{{{ .Chart.Name }}}}
    app.kubernetes.io/instance: {{{{ .Release.Name }}}}
spec:
  replicas: {{{{ .Values.replicaCount }}}}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{{{ .Chart.Name }}}}
      app.kubernetes.io/instance: {{{{ .Release.Name }}}}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: {{{{ .Chart.Name }}}}
        app.kubernetes.io/instance: {{{{ .Release.Name }}}}
    spec:
      containers:
      - name: {{{{ .Chart.Name }}}}
        image: "{{{{ .Values.image.repository }}}}:{{{{ .Values.image.tag }}}}"
        imagePullPolicy: {{{{ .Values.image.pullPolicy }}}}
{{{{- if .Values.service }}}}
{{{{- if .Values.service.port }}}}
        ports:
        - name: http
          containerPort: {{{{ .Values.service.port }}}}
          protocol: TCP
{{{{- end }}}}
{{{{- end }}}}
        env:
{{{{- range $key, $value := .Values.config }}}}
        - name: APP_{{{{ $key | upper | replace "." "_" }}}}
          value: "{{{{ $value | toString }}}}"
{{{{- end }}}}
        resources: {{{{ toYaml .Values.resources | nindent 10 }}}}
"""
    write_file(os.path.join(path, "deployment.yaml"), deployment)

def create_service_yaml(path):
    service = f"""{{{{- if .Values.service -}}}}
{{{{- if .Values.service.port -}}}}
apiVersion: v1
kind: Service
metadata:
  name: {{{{ .Chart.Name }}}}-{{{{ .Release.Name }}}}
  labels:
    app.kubernetes.io/name: {{{{ .Chart.Name }}}}
    app.kubernetes.io/instance: {{{{ .Release.Name }}}}
spec:
  type: {{{{ .Values.service.type }}}}
  ports:
    - port: {{{{ .Values.service.port }}}}
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app.kubernetes.io/name: {{{{ .Chart.Name }}}}
    app.kubernetes.io/instance: {{{{ .Release.Name }}}}
{{{{- end -}}}}
{{{{- end -}}}}
"""
    write_file(os.path.join(path, "service.yaml"), service)

def create_readme(chart_name, description, subchart_defs, path, is_umbrella=False, use_placeholders=False):
    readme_content = f"# {chart_name}\n\n{description}\n\n"
    if is_umbrella:
        readme_content += "This is an umbrella chart.\nSubcharts (located in the `./charts/` directory):\n"
        for sub in subchart_defs: readme_content += f"- {sub['name']}\n"
    else:
        readme_content += "This is a subchart.\n"
    if use_placeholders:
        readme_content += "\nThis chart version uses `@{variable.path}` placeholders for values sourced from external configuration.\n"
    readme_content += "\nSee `values.yaml` (and `values-tags.yaml` if present for umbrella charts) for configuration options.\n"
    write_file(os.path.join(path, "README.md"), readme_content)

# --- Main Generation Logic ---
def _generate_charts_for_type(output_base_dir, all_vars_data, use_placeholders):
    version_name = "Placeholder Version (@{var} format)" if use_placeholders else "Working Values Version"
    print(f"\n--- Generating: {version_name} in {output_base_dir} ---")
    create_dir(output_base_dir)

    for umbrella_config in CHARTS_CONFIG:
        umbrella_name = umbrella_config["name"]
        print(f"\n  Generating Umbrella Chart: {umbrella_name}")
        umbrella_path = os.path.join(output_base_dir, umbrella_name)
        create_dir(umbrella_path)
        umbrella_subcharts_dir = os.path.join(umbrella_path, "charts")
        create_dir(umbrella_subcharts_dir)
        # Umbrella charts usually have minimal or no templates of their own
        create_dir(os.path.join(umbrella_path, "templates"))

        dependencies = []
        for sub_def_template in umbrella_config["subcharts"]:
            sub_name = sub_def_template["name"]
            print(f"    Generating Subchart Instance: {sub_name} for {umbrella_name}")
            # For local subcharts, repository is not needed, or use file://
            dependencies.append({"name": sub_name, "version": "0.1.0", "repository": f"file://./charts/{sub_name}"})

            sub_instance_path = os.path.join(umbrella_subcharts_dir, sub_name)
            create_dir(sub_instance_path)
            sub_templates_path = os.path.join(sub_instance_path, "templates")
            create_dir(sub_templates_path)

            create_chart_yaml(sub_name, "0.1.0", "1.0.0", f"Subchart {sub_name}", [], sub_instance_path)
            create_subchart_values_yaml(sub_def_template, all_vars_data, sub_instance_path, use_placeholders)
            create_deployment_yaml(sub_templates_path)
            if sub_def_template.get("port") is not None and sub_def_template.get("service_type") is not None:
                create_service_yaml(sub_templates_path)
            create_readme(sub_name, f"Subchart {sub_name} for {umbrella_name}", [sub_def_template], sub_instance_path, is_umbrella=False, use_placeholders=use_placeholders)

        create_chart_yaml(umbrella_name, "0.1.0", "1.0.0", umbrella_config["description"], dependencies, umbrella_path)
        create_umbrella_values_yaml(umbrella_config, all_vars_data, umbrella_path, use_placeholders)
        if "tags_values" in umbrella_config: # Check if tags_values are defined for this umbrella
            create_values_tags_yaml(umbrella_config, all_vars_data, umbrella_path, use_placeholders)
        create_readme(umbrella_name, umbrella_config["description"], umbrella_config["subcharts"], umbrella_path, is_umbrella=True, use_placeholders=use_placeholders)


def main():
    parser = argparse.ArgumentParser(description="Generate Helm chart examples.")
    parser.add_argument(
        "--version-type",
        choices=["working", "placeholder"],
        default="working",
        help="Type of chart version to generate: 'working' (with resolved values) or 'placeholder' (with @{var} placeholders)."
    )
    args = parser.parse_args()

    print(f"--- Starting Helm Chart Generation ---")
    print(f"Global ALL_VARIABLES loaded. Using base output directory: {BASE_DIR}")

    use_placeholders_flag = args.version_type == "placeholder"
    output_directory_name = "placeholder_charts" if use_placeholders_flag else "working_charts"
    target_output_dir = os.path.join(BASE_DIR, output_directory_name)

    _generate_charts_for_type(target_output_dir, ALL_VARIABLES, use_placeholders=use_placeholders_flag)

    print(f"\n--- Helm charts generation process finished. ---")
    print(f"Generated charts ({args.version_type} version) are in: '{target_output_dir}'")

    if not use_placeholders_flag:
        print("\nTo use a generated working umbrella chart (e.g., appstack-alpha):")
        print(f"  1. cd {os.path.join(target_output_dir, CHARTS_CONFIG[0]['name'])}")
        print(f"  2. helm dependency build  # This will create/update Chart.lock and download subcharts into ./charts/ if they were remote")
        print(f"  3. helm install my-{CHARTS_CONFIG[0]['name']} . -n <your-namespace> --dry-run --debug # To test")
        print(f"  4. helm install my-{CHARTS_CONFIG[0]['name']} . -n <your-namespace> # To deploy")
    else:
        print("\nFor placeholder charts, you would need a separate process to replace @{...} variables before deployment.")

if __name__ == "__main__":
    main()