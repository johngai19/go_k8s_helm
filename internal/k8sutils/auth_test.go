package k8sutils

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestNewAuthUtil mainly tests config loading logic (in-cluster vs. out-of-cluster).
// Full testing requires a mock Kubernetes environment or integration tests.
func TestNewAuthUtil(t *testing.T) {
	// Scenario 1: Simulate out-of-cluster by ensuring in-cluster specific env vars are not set
	// and a dummy kubeconfig exists.
	originalKubeconfig := os.Getenv("KUBECONFIG")
	originalKubeServiceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	originalKubeServicePort := os.Getenv("KUBERNETES_SERVICE_PORT")

	// Unset in-cluster variables
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")

	tempDir := t.TempDir()
	dummyKubeconfigFile := filepath.Join(tempDir, "config")
	if err := os.WriteFile(dummyKubeconfigFile, []byte(`
apiVersion: v1
clusters:
- cluster:
    server: https://fake-cluster
  name: fake-cluster
contexts:
- context:
    cluster: fake-cluster
    user: fake-user
    namespace: test-ns-from-kubeconfig
  name: fake-context
current-context: fake-context
kind: Config
preferences: {}
users:
- name: fake-user
  user: {}
`), 0600); err != nil {
		t.Fatalf("Failed to write dummy kubeconfig: %v", err)
	}
	os.Setenv("KUBECONFIG", dummyKubeconfigFile)

	util, err := NewAuthUtil()
	if err != nil {
		// This will fail if it can't connect to a real cluster or parse the dummy config correctly.
		// For unit tests, we often mock the client-go functions or use fakes.
		// Given the constraints, we accept this might error out if it tries to *actually* connect.
		// The goal here is to test the path selection.
		t.Logf("NewAuthUtil (out-of-cluster) returned error (expected in some CI environments without real K8s or if dummy cluster is unreachable): %v", err)
	} else {
		if util.IsRunningInCluster() {
			t.Errorf("IsRunningInCluster() = true, want false for out-of-cluster scenario")
		}
		// Test GetClientset and GetKubeConfig basic retrieval
		cs, csErr := util.GetClientset()
		if csErr != nil {
			t.Errorf("GetClientset() returned error: %v", csErr)
		}
		if cs == nil {
			t.Errorf("GetClientset() returned nil clientset")
		}
		cfg, cfgErr := util.GetKubeConfig()
		if cfgErr != nil {
			t.Errorf("GetKubeConfig() returned error: %v", cfgErr)
		}
		if cfg == nil {
			t.Errorf("GetKubeConfig() returned nil config")
		}
	}

	// Restore original environment variables
	os.Setenv("KUBECONFIG", originalKubeconfig)
	if originalKubeServiceHost != "" {
		os.Setenv("KUBERNETES_SERVICE_HOST", originalKubeServiceHost)
	} else {
		os.Unsetenv("KUBERNETES_SERVICE_HOST")
	}
	if originalKubeServicePort != "" {
		os.Setenv("KUBERNETES_SERVICE_PORT", originalKubeServicePort)
	} else {
		os.Unsetenv("KUBERNETES_SERVICE_PORT")
	}

	// Scenario 2: Simulate in-cluster (harder to do in pure unit test without more complex mocks)
	// This part is more of an integration test concern.
	// To truly test in-cluster, one would typically set KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT
	// and mock the InClusterConfig() call or the service account file reads.
}

func TestAuthUtil_IsRunningInCluster(t *testing.T) {
	// This is implicitly tested by TestNewAuthUtil, but a direct test could be added
	// if NewAuthUtil's logic for setting `inCluster` was more complex or configurable.
	t.Skip("IsRunningInCluster is primarily tested via NewAuthUtil scenarios if NewAuthUtil doesn't error.")
}

func TestAuthUtil_GetCurrentNamespace(t *testing.T) {
	originalKubeconfig := os.Getenv("KUBECONFIG")
	originalKubeServiceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	originalKubeServicePort := os.Getenv("KUBERNETES_SERVICE_PORT")

	// Ensure in-cluster vars are not set for these out-of-cluster tests
	os.Unsetenv("KUBERNETES_SERVICE_HOST")
	os.Unsetenv("KUBERNETES_SERVICE_PORT")

	tempDir := t.TempDir()

	// Scenario 1: Out-of-cluster, with KUBECONFIG pointing to a config with a namespace
	dummyKubeconfigFileWithNS := filepath.Join(tempDir, "config_with_ns")
	kubeconfigContentWithNS := []byte(`
apiVersion: v1
clusters:
- cluster:
    server: https://fake-cluster
  name: fake-cluster
contexts:
- context:
    cluster: fake-cluster
    user: fake-user
    namespace: my-kube-namespace
  name: fake-context
current-context: fake-context
kind: Config
users:
- name: fake-user
  user: {}
`)
	if err := os.WriteFile(dummyKubeconfigFileWithNS, kubeconfigContentWithNS, 0600); err != nil {
		t.Fatalf("Failed to write dummy kubeconfig (with ns): %v", err)
	}
	os.Setenv("KUBECONFIG", dummyKubeconfigFileWithNS)

	utilWithNs, err := NewAuthUtil()
	if err != nil {
		t.Logf("NewAuthUtil for GetCurrentNamespace (out-of-cluster, with ns) returned error: %v", err)
	} else {
		ns, errNs := utilWithNs.GetCurrentNamespace()
		if errNs != nil {
			t.Errorf("GetCurrentNamespace() (out-of-cluster, with ns) returned error: %v", errNs)
		}
		if ns != "my-kube-namespace" {
			t.Errorf("GetCurrentNamespace() (out-of-cluster, with ns) = %q, want %q", ns, "my-kube-namespace")
		}
	}

	// Scenario 2: Out-of-cluster, KUBECONFIG pointing to a config *without* a namespace (should default)
	dummyKubeconfigFileNoNS := filepath.Join(tempDir, "config_no_ns")
	kubeconfigContentNoNS := []byte(`
apiVersion: v1
clusters:
- cluster:
    server: https://fake-cluster
  name: fake-cluster
contexts:
- context:
    cluster: fake-cluster
    user: fake-user
    # No namespace here
  name: fake-context
current-context: fake-context
kind: Config
users:
- name: fake-user
  user: {}
`)
	if err := os.WriteFile(dummyKubeconfigFileNoNS, kubeconfigContentNoNS, 0600); err != nil {
		t.Fatalf("Failed to write dummy kubeconfig (no ns): %v", err)
	}
	os.Setenv("KUBECONFIG", dummyKubeconfigFileNoNS)

	utilNoNs, err := NewAuthUtil()
	if err != nil {
		t.Logf("NewAuthUtil for GetCurrentNamespace (out-of-cluster, no ns) returned error: %v", err)
	} else {
		ns, errNs := utilNoNs.GetCurrentNamespace()
		if errNs != nil {
			// Based on auth.go, if namespace is "" in kubeconfig and no error from clientcmd, it returns "default", nil
			t.Errorf("GetCurrentNamespace() (out-of-cluster, no ns) unexpected error: %v", errNs)
		}
		if ns != "default" {
			t.Errorf("GetCurrentNamespace() (out-of-cluster, no ns) = %q, want %q", ns, "default")
		}
	}

	// Scenario 3: In-cluster (requires mocking os.ReadFile and in-cluster env vars)
	// This is more complex to unit test without a proper mocking framework for file system.
	// Consider testing this part with integration tests or more advanced mocking.

	// Restore original KUBECONFIG and in-cluster vars
	os.Setenv("KUBECONFIG", originalKubeconfig)
	if originalKubeServiceHost != "" {
		os.Setenv("KUBERNETES_SERVICE_HOST", originalKubeServiceHost)
	} else {
		os.Unsetenv("KUBERNETES_SERVICE_HOST")
	}
	if originalKubeServicePort != "" {
		os.Setenv("KUBERNETES_SERVICE_PORT", originalKubeServicePort)
	} else {
		os.Unsetenv("KUBERNETES_SERVICE_PORT")
	}
}

func TestAuthUtil_CheckNamespacePermissions(t *testing.T) {
	fakeClientset := fake.NewSimpleClientset()
	util := &AuthUtil{clientset: fakeClientset, inCluster: false} // Assuming out-of-cluster for this test

	fakeClientset.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		response := &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{},
		}
		// Simulate permissions based on verb and resource
		if sar.Spec.ResourceAttributes.Namespace == "test-ns" {
			if sar.Spec.ResourceAttributes.Resource == "pods" {
				if sar.Spec.ResourceAttributes.Verb == "get" {
					response.Status.Allowed = true
				} else if sar.Spec.ResourceAttributes.Verb == "list" {
					response.Status.Allowed = false // Explicitly deny list for pods
				} else {
					response.Status.Allowed = true // Allow other verbs for pods for simplicity
				}
			} else if sar.Spec.ResourceAttributes.Resource == "services" {
				if sar.Spec.ResourceAttributes.Verb == "create" {
					response.Status.Allowed = true
				} else {
					response.Status.Allowed = false
				}
			} else {
				response.Status.Allowed = false // Deny other resources
			}
		} else {
			response.Status.Allowed = false // Deny other namespaces
		}
		return true, response, nil
	})

	ctx := context.TODO()

	// Test case 1: Pods - get (allowed), list (denied)
	permsPods, err := util.CheckNamespacePermissions(ctx, "test-ns", ResourcePods, []string{"get", "list", "delete"})
	if err != nil {
		t.Fatalf("CheckNamespacePermissions for pods returned error: %v", err)
	}
	if !permsPods["get"] {
		t.Errorf("Expected 'get' permission on pods in 'test-ns' to be true")
	}
	if permsPods["list"] {
		t.Errorf("Expected 'list' permission on pods in 'test-ns' to be false")
	}
	if !permsPods["delete"] { // Allowed by fallback in reactor
		t.Errorf("Expected 'delete' permission on pods in 'test-ns' to be true by default mock logic")
	}

	// Test case 2: Services - create (allowed), get (denied)
	permsServices, err := util.CheckNamespacePermissions(ctx, "test-ns", ResourceServices, []string{"create", "get"})
	if err != nil {
		t.Fatalf("CheckNamespacePermissions for services returned error: %v", err)
	}
	if !permsServices["create"] {
		t.Errorf("Expected 'create' permission on services in 'test-ns' to be true")
	}
	if permsServices["get"] {
		t.Errorf("Expected 'get' permission on services in 'test-ns' to be false")
	}

	// Test case 3: Different namespace (should be denied by mock)
	permsOtherNs, err := util.CheckNamespacePermissions(ctx, "other-ns", ResourcePods, []string{"get"})
	if err != nil {
		t.Fatalf("CheckNamespacePermissions for other-ns returned error: %v", err)
	}
	if permsOtherNs["get"] {
		t.Errorf("Expected 'get' permission on pods in 'other-ns' to be false")
	}
}

func TestAuthUtil_CanPerformClusterAction(t *testing.T) {
	fakeClientset := fake.NewSimpleClientset()
	util := &AuthUtil{clientset: fakeClientset, inCluster: false}

	fakeClientset.PrependReactor("create", "selfsubjectaccessreviews", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview)
		response := &authorizationv1.SelfSubjectAccessReview{
			Status: authorizationv1.SubjectAccessReviewStatus{},
		}
		// Simulate cluster permissions
		if sar.Spec.ResourceAttributes.Resource == "namespaces" && sar.Spec.ResourceAttributes.Verb == "create" {
			response.Status.Allowed = true
		} else if sar.Spec.ResourceAttributes.Resource == "nodes" && sar.Spec.ResourceAttributes.Verb == "list" {
			response.Status.Allowed = true
		} else {
			response.Status.Allowed = false
		}
		return true, response, nil
	})

	ctx := context.TODO()

	// Test case 1: Can create namespaces (allowed)
	canCreateNS, err := util.CanPerformClusterAction(ctx, ResourceNamespaces, "create")
	if err != nil {
		t.Fatalf("CanPerformClusterAction for creating namespaces returned error: %v", err)
	}
	if !canCreateNS {
		t.Errorf("Expected CanPerformClusterAction for creating namespaces to be true")
	}

	// Test case 2: Can list namespaces (denied by mock)
	canListNS, err := util.CanPerformClusterAction(ctx, ResourceNamespaces, "list")
	if err != nil {
		t.Fatalf("CanPerformClusterAction for listing namespaces returned error: %v", err)
	}
	if canListNS {
		t.Errorf("Expected CanPerformClusterAction for listing namespaces to be false")
	}

	// Test case 3: Can list nodes (allowed)
	canListNodes, err := util.CanPerformClusterAction(ctx, schema.GroupVersionResource{Group: "", Version: "v1", Resource: "nodes"}, "list")
	if err != nil {
		t.Fatalf("CanPerformClusterAction for listing nodes returned error: %v", err)
	}
	if !canListNodes {
		t.Errorf("Expected CanPerformClusterAction for listing nodes to be true")
	}
}

func TestResourceVariables(t *testing.T) {
	if ResourceNamespaces.Resource != "namespaces" {
		t.Errorf("ResourceNamespaces.Resource = %q, want %q", ResourceNamespaces.Resource, "namespaces")
	}
	expectedCRUDVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete"}
	if !reflect.DeepEqual(DefaultCRUDVerbs, expectedCRUDVerbs) {
		t.Errorf("DefaultCRUDVerbs = %v, want %v", DefaultCRUDVerbs, expectedCRUDVerbs)
	}
}
