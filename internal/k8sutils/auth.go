package k8sutils

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	// v1 "k8s.io/api/core/v1" // Not directly used in the provided snippet, but often useful
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// K8sAuthChecker defines the interface for Kubernetes authentication and permission checks.
type K8sAuthChecker interface {
	GetKubeConfig() (*rest.Config, error)
	GetClientset() (kubernetes.Interface, error)
	IsRunningInCluster() bool
	GetCurrentNamespace() (string, error)
	CheckNamespacePermissions(ctx context.Context, namespace string, resource schema.GroupVersionResource, verbs []string) (map[string]bool, error)
	CanPerformClusterAction(ctx context.Context, resource schema.GroupVersionResource, verb string) (bool, error)
}

// AuthUtil implements K8sAuthChecker.
type AuthUtil struct {
	clientset kubernetes.Interface
	config    *rest.Config
	inCluster bool
}

// NewAuthUtil creates a new AuthUtil instance.
// It automatically tries to load in-cluster config first, then falls back to kubeconfig.
func NewAuthUtil() (*AuthUtil, error) {
	util := &AuthUtil{}
	config, err := rest.InClusterConfig()
	if err == nil {
		util.inCluster = true
		util.config = config
	} else {
		// Not in cluster, try to load from kubeconfig
		util.inCluster = false
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			home, err_home := os.UserHomeDir()
			if err_home != nil {
				return nil, fmt.Errorf("failed to get user home directory: %w", err_home)
			}
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig from %s: %w", kubeconfigPath, err)
		}
		util.config = config
	}

	clientset, err := kubernetes.NewForConfig(util.config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}
	util.clientset = clientset
	return util, nil
}

// GetKubeConfig returns the Kubernetes REST config.
func (u *AuthUtil) GetKubeConfig() (*rest.Config, error) {
	if u.config == nil {
		return nil, fmt.Errorf("config not initialized")
	}
	return u.config, nil
}

// GetClientset returns the Kubernetes clientset.
func (u *AuthUtil) GetClientset() (kubernetes.Interface, error) {
	if u.clientset == nil {
		return nil, fmt.Errorf("clientset not initialized")
	}
	return u.clientset, nil
}

// IsRunningInCluster returns true if the program is likely running inside a Kubernetes cluster.
func (u *AuthUtil) IsRunningInCluster() bool {
	return u.inCluster
}

// GetCurrentNamespace returns the namespace the pod is running in (if in-cluster).
// Falls back to the namespace in the current kubeconfig context if not in-cluster, or "default" if not determinable.
func (u *AuthUtil) GetCurrentNamespace() (string, error) {
	if !u.IsRunningInCluster() {
		// For out-of-cluster, get it from kubeconfig context.
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})
		namespace, _, err := kubeConfig.Namespace()
		if err != nil {
			// Fallback to default if not determinable from kubeconfig
			return "default", fmt.Errorf("could not determine namespace from kubeconfig: %w, defaulting to 'default'", err)
		}
		if namespace == "" {
			return "default", nil
		}
		return namespace, nil
	}

	nsBytes, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("failed to read namespace file %s: %w", inClusterNamespacePath, err)
	}
	return strings.TrimSpace(string(nsBytes)), nil
}

// CheckNamespacePermissions checks if the current identity has the specified verbs (permissions)
// on a given resource within a specific namespace.
// Example resource: {Group: "apps", Version: "v1", Resource: "deployments"}
// Example verbs: ["get", "list", "create", "update", "delete", "patch", "watch"]
func (u *AuthUtil) CheckNamespacePermissions(ctx context.Context, namespace string, resourceGV schema.GroupVersionResource, verbs []string) (map[string]bool, error) {
	results := make(map[string]bool)
	if u.clientset == nil {
		return results, fmt.Errorf("clientset not initialized")
	}

	for _, verb := range verbs {
		sar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Verb:      verb,
					Group:     resourceGV.Group,
					Version:   resourceGV.Version,
					Resource:  resourceGV.Resource,
				},
			},
		}

		response, err := u.clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
		if err != nil {
			// Store false for this verb and continue, or return immediately?
			// For now, let's assume we want to know about the error and stop.
			return results, fmt.Errorf("failed to perform SelfSubjectAccessReview for verb '%s' on resource '%s' in namespace '%s': %w", verb, resourceGV.Resource, namespace, err)
		}
		results[verb] = response.Status.Allowed
	}
	return results, nil
}

// CanPerformClusterAction checks if the current identity can perform a specific cluster-level action (non-namespaced).
// Example: Check if it can create namespaces: resource={Group: "", Version: "v1", Resource: "namespaces"}, verb="create"
func (u *AuthUtil) CanPerformClusterAction(ctx context.Context, resourceGV schema.GroupVersionResource, verb string) (bool, error) {
	if u.clientset == nil {
		return false, fmt.Errorf("clientset not initialized")
	}

	sar := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Verb:     verb,
				Group:    resourceGV.Group,
				Version:  resourceGV.Version,
				Resource: resourceGV.Resource,
				// Namespace is empty for cluster-scoped resources
			},
		},
	}

	response, err := u.clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to perform SelfSubjectAccessReview for verb '%s' on cluster resource '%s': %w", verb, resourceGV.Resource, err)
	}
	return response.Status.Allowed, nil
}

// Common Kubernetes GVRs (GroupVersionResource) for convenience.
var (
	ResourcePods         = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	ResourceServices     = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}
	ResourceConfigMaps   = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	ResourceSecrets      = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	ResourceNamespaces   = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}
	ResourceDeployments  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	ResourceStatefulSets = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
	ResourceDaemonSets   = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}
)

// DefaultCRUDVerbs lists common CRUD operations.
var DefaultCRUDVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete"}
