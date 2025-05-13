# Cleaning Up Resources

This guide explains how to remove the Kubernetes resources created by the `umbrella-chart`, including the Helm release itself and any manually created Secrets.

## 1. Uninstall the Helm Release

To remove the deployed Helm release (which will delete all Kubernetes resources managed by that release, such as Deployments, Services, etc.), use the `helm uninstall` command.

You need to specify the release name and the namespace it was installed into. If you followed the `README.md` examples, the release name was `nginx-umbrella-release` and the namespace was `default`.

```bash
helm uninstall <release-name> -n <namespace>
```

**Example:**

```bash
helm uninstall nginx-umbrella-release -n default
```

After running this command, Helm will remove all resources associated with this release. You can verify by listing releases again:

```bash
helm list -n default
```
The `nginx-umbrella-release` should no longer be listed.

## 2. Delete the Kubernetes Secret

If you manually created the `my-app-credentials` Secret (or any other Secret for this chart), Helm will not automatically delete it because it was not created as part of the Helm release lifecycle (unless it was defined within the chart's templates and not as a prerequisite).

To delete a Secret, use the `kubectl delete secret` command.

```bash
kubectl delete secret <secret-name> -n <namespace>
```

**Example (deleting the `my-app-credentials` Secret from the `default` namespace):**

```bash
kubectl delete secret my-app-credentials -n default
```

**Verification:**

You can verify that the Secret has been deleted by trying to get it:

```bash
kubectl get secret my-app-credentials -n default
```

If the Secret has been successfully deleted, you will see an error message like:
```
Error from server (NotFound): secrets "my-app-credentials" not found
```

By following these steps, you can clean up the resources deployed by the `umbrella-chart` and its prerequisites.