package helmutils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go_k8s_helm/internal/k8sutils"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/release"
	"helm.sh/helm/v3/pkg/repo"
	"helm.sh/helm/v3/pkg/storage/driver"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// HelmClient defines the interface for Helm operations.
type HelmClient interface {
	ListReleases(namespace string, stateMask action.ListStates) ([]*ReleaseInfo, error)
	InstallChart(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, createNamespace bool, wait bool, timeout time.Duration) (*ReleaseInfo, error)
	UninstallRelease(namespace, releaseName string, keepHistory bool, timeout time.Duration) (string, error)
	UpgradeRelease(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, wait bool, timeout time.Duration, installIfMissing bool, force bool) (*ReleaseInfo, error)
	GetReleaseDetails(namespace, releaseName string) (*ReleaseInfo, error)
	GetReleaseHistory(namespace, releaseName string) ([]*ReleaseInfo, error)
	AddRepository(name, url, username, password string, passCredentials bool) error
	UpdateRepositories() error
	EnsureChart(chartName, version string) (string, error)
}

// Client implements HelmClient.
type Client struct {
	settings       *cli.EnvSettings
	authChecker    k8sutils.K8sAuthChecker
	baseKubeConfig *rest.Config
	Log            func(format string, v ...interface{})
}

// ReleaseInfo holds summarized information about a Helm release.
type ReleaseInfo struct {
	Name         string                 `json:"name"`
	Namespace    string                 `json:"namespace"`
	Revision     int                    `json:"revision"`
	Updated      time.Time              `json:"updated"`
	Status       release.Status         `json:"status"`
	ChartName    string                 `json:"chartName"`
	ChartVersion string                 `json:"chartVersion"`
	AppVersion   string                 `json:"appVersion"`
	Description  string                 `json:"description,omitempty"`
	Notes        string                 `json:"notes,omitempty"`
	Config       map[string]interface{} `json:"config,omitempty"`   // Default chart values
	Manifest     string                 `json:"manifest,omitempty"` // Rendered manifest
	Values       map[string]interface{} `json:"values,omitempty"`   // User-supplied values
}

// NewClient creates a new Helm client instance.
// It uses K8sAuthChecker to obtain Kubernetes configuration.
// defaultNamespace is used for cli.EnvSettings and as the primary context for action.Configuration.
func NewClient(authChecker k8sutils.K8sAuthChecker, defaultNamespace string, logger func(format string, v ...interface{})) (*Client, error) {
	c := &Client{
		authChecker: authChecker,
	}
	if logger == nil {
		c.Log = log.Printf // Default logger
	} else {
		c.Log = logger
	}

	c.settings = cli.New()
	if defaultNamespace != "" {
		c.settings.SetNamespace(defaultNamespace)
	} else {
		currentNs, err := authChecker.GetCurrentNamespace()
		if err != nil {
			c.Log("Warning: could not determine current namespace via authChecker, using settings default: %v", err)
			// cli.New() will set a default namespace (e.g. "default" or from KUBECONFIG context)
		} else {
			c.settings.SetNamespace(currentNs)
		}
	}

	kubeConfig, err := authChecker.GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig from authChecker: %w", err)
	}
	c.baseKubeConfig = kubeConfig

	return c, nil
}

// getActionConfig creates a new action.Configuration for the specified namespace.
func (c *Client) getActionConfig(namespace string) (*action.Configuration, error) {
	if namespace == "" {
		namespace = c.settings.Namespace()
		if namespace == "" {
			return nil, fmt.Errorf("getActionConfig: target namespace is empty and client's default namespace is also empty")
		}
	}

	clientGetter := newConfigGetter(c.baseKubeConfig, namespace)
	actionConfig := new(action.Configuration)

	if err := actionConfig.Init(clientGetter, namespace, os.Getenv("HELM_DRIVER"), c.Log); err != nil {
		return nil, fmt.Errorf("failed to initialize Helm action configuration for namespace '%s': %w", namespace, err)
	}
	return actionConfig, nil
}

// configGetter implements clientcmd.RESTClientGetter for a given rest.Config
type configGetter struct {
	config    *rest.Config
	namespace string // The default namespace for this getter's context
}

func newConfigGetter(config *rest.Config, namespace string) genericclioptions.RESTClientGetter {
	return &configGetter{config: config, namespace: namespace}
}

func (cg *configGetter) ToRESTConfig() (*rest.Config, error) {
	if cg.config == nil {
		return nil, fmt.Errorf("kubeconfig not provided to configGetter")
	}
	configCopy := rest.CopyConfig(cg.config)
	return configCopy, nil
}

func (cg *configGetter) ToDiscoveryClient() (discovery.CachedDiscoveryInterface, error) {
	rc, err := cg.ToRESTConfig()
	if err != nil {
		return nil, err
	}
	d, err := discovery.NewDiscoveryClientForConfig(rc)
	if err != nil {
		return nil, err
	}
	return memory.NewMemCacheClient(d), nil
}

func (cg *configGetter) ToRESTMapper() (meta.RESTMapper, error) {
	dc, err := cg.ToDiscoveryClient()
	if err != nil {
		return nil, err
	}
	return restmapper.NewDeferredDiscoveryRESTMapper(dc), nil
}

func (cg *configGetter) ToRawKubeConfigLoader() clientcmd.ClientConfig {
	cfg := clientcmdapi.NewConfig()
	contextName := "helm-synthesized-context"
	clusterName := "helm-synthesized-cluster"

	cfg.Clusters[clusterName] = &clientcmdapi.Cluster{
		Server:                   cg.config.Host,
		CertificateAuthorityData: cg.config.CAData,
		InsecureSkipTLSVerify:    cg.config.Insecure,
	}
	cfg.AuthInfos["helm-synthesized-user"] = &clientcmdapi.AuthInfo{
		ClientCertificateData: cg.config.CertData,
		ClientKeyData:         cg.config.KeyData,
		Token:                 cg.config.BearerToken,
		Username:              cg.config.Username,
		Password:              cg.config.Password,
		Impersonate:           cg.config.Impersonate.UserName,
		ImpersonateGroups:     cg.config.Impersonate.Groups,
	}
	cfg.Contexts[contextName] = &clientcmdapi.Context{
		Cluster:   clusterName,
		AuthInfo:  "helm-synthesized-user",
		Namespace: cg.namespace,
	}
	cfg.CurrentContext = contextName

	return clientcmd.NewDefaultClientConfig(*cfg, &clientcmd.ConfigOverrides{})
}

func (c *Client) ListReleases(namespace string, stateMask action.ListStates) ([]*ReleaseInfo, error) {
	var actionConf *action.Configuration
	var err error

	if namespace == "" {
		actionConf, err = c.getActionConfig(c.settings.Namespace())
	} else {
		actionConf, err = c.getActionConfig(namespace)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get action configuration for ListReleases: %w", err)
	}

	listClient := action.NewList(actionConf)
	listClient.StateMask = stateMask

	if namespace == "" {
		listClient.AllNamespaces = true
	} else {
		listClient.AllNamespaces = false
	}

	results, err := listClient.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to list releases: %w", err)
	}

	var releases []*ReleaseInfo
	for _, rel := range results {
		releases = append(releases, convertReleaseToInfo(rel))
	}
	return releases, nil
}

func (c *Client) InstallChart(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, createNamespace bool, wait bool, timeout time.Duration) (*ReleaseInfo, error) {
	actionConf, err := c.getActionConfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get action configuration for InstallChart: %w", err)
	}
	installClient := action.NewInstall(actionConf)
	installClient.ReleaseName = releaseName
	installClient.Namespace = namespace
	installClient.CreateNamespace = createNamespace
	installClient.ChartPathOptions.Version = chartVersion
	installClient.Wait = wait
	installClient.Timeout = timeout
	installClient.Devel = true

	cp, err := installClient.ChartPathOptions.LocateChart(chartName, c.settings)
	if err != nil {
		return nil, fmt.Errorf("failed to locate chart %s version %s: %w", chartName, chartVersion, err)
	}
	c.Log("Located chart for %s at %s", chartName, cp)

	chartRequested, err := loader.Load(cp)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart from path %s: %w", cp, err)
	}

	if chartRequested.Metadata.Type != "" && chartRequested.Metadata.Type != "application" {
		return nil, fmt.Errorf("chart %s is of type %s, expected 'application'", chartName, chartRequested.Metadata.Type)
	}

	rel, err := installClient.Run(chartRequested, vals)
	if err != nil {
		return nil, fmt.Errorf("failed to install chart %s as release %s: %w", chartName, releaseName, err)
	}
	return convertReleaseToInfo(rel), nil
}

func (c *Client) UninstallRelease(namespace, releaseName string, keepHistory bool, timeout time.Duration) (string, error) {
	actionConf, err := c.getActionConfig(namespace)
	if err != nil {
		return "", fmt.Errorf("failed to get action configuration for UninstallRelease: %w", err)
	}
	uninstallClient := action.NewUninstall(actionConf)
	uninstallClient.KeepHistory = keepHistory
	uninstallClient.Timeout = timeout

	resp, err := uninstallClient.Run(releaseName)
	if err != nil {
		return "", fmt.Errorf("failed to uninstall release %s from namespace %s: %w", releaseName, namespace, err)
	}
	if resp != nil && resp.Info != "" {
		return resp.Info, nil
	}
	return fmt.Sprintf("release %s uninstalled from namespace %s", releaseName, namespace), nil
}

func (c *Client) UpgradeRelease(namespace, releaseName, chartName string, chartVersion string, vals map[string]interface{}, wait bool, timeout time.Duration, installIfMissing bool, force bool) (*ReleaseInfo, error) {
	actionConf, err := c.getActionConfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get action configuration for UpgradeRelease: %w", err)
	}
	upgradeClient := action.NewUpgrade(actionConf)
	upgradeClient.Namespace = namespace
	upgradeClient.Install = installIfMissing
	upgradeClient.Version = chartVersion
	upgradeClient.Wait = wait
	upgradeClient.Timeout = timeout
	upgradeClient.Force = force
	upgradeClient.Devel = true

	cp, err := upgradeClient.ChartPathOptions.LocateChart(chartName, c.settings)
	if err != nil {
		return nil, fmt.Errorf("failed to locate chart %s version %s for upgrade: %w", chartName, chartVersion, err)
	}
	c.Log("Located chart for upgrade %s at %s", chartName, cp)

	chartRequested, err := loader.Load(cp)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart from path %s for upgrade: %w", cp, err)
	}

	if !installIfMissing {
		_, errGet := c.GetReleaseDetails(namespace, releaseName)
		if errGet != nil {
			if errGet == driver.ErrReleaseNotFound || strings.Contains(strings.ToLower(errGet.Error()), "release: not found") {
				return nil, fmt.Errorf("release %s not found in namespace %s and install-if-missing is false: %w", releaseName, namespace, errGet)
			}
			return nil, fmt.Errorf("failed to check existence of release %s in namespace %s before upgrade: %w", releaseName, namespace, errGet)
		}
	}

	rel, err := upgradeClient.Run(releaseName, chartRequested, vals)
	if err != nil {
		return nil, fmt.Errorf("failed to upgrade release %s with chart %s: %w", releaseName, chartName, err)
	}
	return convertReleaseToInfo(rel), nil
}

func (c *Client) GetReleaseDetails(namespace, releaseName string) (*ReleaseInfo, error) {
	actionConf, err := c.getActionConfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get action configuration for GetReleaseDetails: %w", err)
	}
	getClient := action.NewGet(actionConf)
	rel, err := getClient.Run(releaseName)
	if err != nil {
		if err == driver.ErrReleaseNotFound || strings.Contains(strings.ToLower(err.Error()), "release: not found") {
			return nil, fmt.Errorf("release %s not found in namespace %s: %w", releaseName, namespace, driver.ErrReleaseNotFound)
		}
		return nil, fmt.Errorf("failed to get release %s details from namespace %s: %w", releaseName, namespace, err)
	}
	return convertReleaseToInfo(rel), nil
}

func (c *Client) GetReleaseHistory(namespace, releaseName string) ([]*ReleaseInfo, error) {
	actionConf, err := c.getActionConfig(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get action configuration for GetReleaseHistory: %w", err)
	}
	historyClient := action.NewHistory(actionConf)
	historyClient.Max = 256

	history, err := historyClient.Run(releaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for release %s in namespace %s: %w", releaseName, namespace, err)
	}

	var releaseHistory []*ReleaseInfo
	for _, rel := range history {
		releaseHistory = append(releaseHistory, convertReleaseToInfo(rel))
	}
	return releaseHistory, nil
}

func convertReleaseToInfo(rel *release.Release) *ReleaseInfo {
	if rel == nil {
		return nil
	}
	info := &ReleaseInfo{
		Name:      rel.Name,
		Namespace: rel.Namespace,
		Revision:  rel.Version,
		Values:    rel.Config,
		Manifest:  rel.Manifest,
	}
	if rel.Info != nil {
		info.Status = rel.Info.Status
		info.Description = rel.Info.Description
		info.Notes = rel.Info.Notes
		if !rel.Info.LastDeployed.IsZero() {
			info.Updated = rel.Info.LastDeployed.Time
		}
	}
	if rel.Chart != nil {
		info.Config = rel.Chart.Values
		if rel.Chart.Metadata != nil {
			info.ChartName = rel.Chart.Metadata.Name
			info.ChartVersion = rel.Chart.Metadata.Version
			info.AppVersion = rel.Chart.Metadata.AppVersion
		}
	}
	return info
}

func (c *Client) AddRepository(name, url, username, password string, passCredentials bool) error {
	repoFile := c.settings.RepositoryConfig

	r, err := repo.LoadFile(repoFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load repository file (%s): %w", repoFile, err)
	}
	if r == nil {
		r = repo.NewFile()
	}

	entry := &repo.Entry{
		Name:               name,
		URL:                url,
		Username:           username,
		Password:           password,
		PassCredentialsAll: passCredentials,
	}

	if r.Has(name) {
		c.Log("Repository name (%s) already exists.", name)
		return fmt.Errorf("repository name (%s) already exists", name)
	}

	chartRepo, err := repo.NewChartRepository(entry, getter.All(c.settings))
	if err != nil {
		return fmt.Errorf("failed to create chart repository for %s from URL %s: %w", name, url, err)
	}

	if _, err := chartRepo.DownloadIndexFile(); err != nil {
		return fmt.Errorf("looks like %q is not a valid chart repository or cannot be reached: %w", url, err)
	}

	r.Add(entry)

	if err := os.MkdirAll(filepath.Dir(repoFile), 0755); err != nil {
		return fmt.Errorf("failed to create directory for repository file %s: %w", repoFile, err)
	}

	if err := r.WriteFile(repoFile, 0644); err != nil {
		return fmt.Errorf("failed to write repository file %s: %w", repoFile, err)
	}
	c.Log("%s has been added to your repositories", name)
	return nil
}

func (c *Client) UpdateRepositories() error {
	repoFile := c.settings.RepositoryConfig
	f, err := repo.LoadFile(repoFile)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to load repository file (%s): %w", repoFile, err)
	}
	if f == nil || len(f.Repositories) == 0 {
		c.Log("No repositories found. Nothing to update.")
		return nil
	}

	var reposToUpdate []*repo.ChartRepository
	for _, cfg := range f.Repositories {
		cr, err := repo.NewChartRepository(cfg, getter.All(c.settings))
		if err != nil {
			c.Log("Warning: failed to create chart repository for %s (%s), skipping update: %v", cfg.Name, cfg.URL, err)
			continue
		}
		reposToUpdate = append(reposToUpdate, cr)
	}

	if len(reposToUpdate) == 0 {
		c.Log("No valid repositories to update.")
		return nil
	}

	c.Log("Hang tight while we grab the latest from your chart repositories...")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var updateErrors []string

	for _, cr := range reposToUpdate {
		repoCfg := cr.Config
		chartRepoInstance := cr

		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Log("Updating %s (%s)...", repoCfg.Name, repoCfg.URL)
			if _, err := chartRepoInstance.DownloadIndexFile(); err != nil {
				errMsg := fmt.Sprintf("unable to get an update from the %q chart repository (%s): %s", repoCfg.Name, repoCfg.URL, err.Error())
				c.Log(errMsg)
				mu.Lock()
				updateErrors = append(updateErrors, errMsg)
				mu.Unlock()
			} else {
				c.Log("...Successfully got an update from the %q chart repository", repoCfg.Name)
			}
		}()
	}

	wg.Wait()

	if len(updateErrors) > 0 {
		var combinedError strings.Builder
		for _, s := range updateErrors {
			combinedError.WriteString(fmt.Sprintf("- %s\n", s))
		}
		return errors.New(combinedError.String())
	}

	c.Log("Update Complete. Happy Helming!")
	return nil
}

func (c *Client) EnsureChart(chartName, version string) (string, error) {
	chartPathOpts := action.ChartPathOptions{Version: version}

	chartPath, err := chartPathOpts.LocateChart(chartName, c.settings)
	if err != nil {
		c.Log("Chart %s version %s not found locally. Attempting to update repositories and re-locate.", chartName, version)
		if updateErr := c.UpdateRepositories(); updateErr != nil {
			c.Log("Warning: Failed to update all repositories during EnsureChart: %v. Proceeding with chart location attempt.", updateErr)
		}
		chartPath, err = chartPathOpts.LocateChart(chartName, c.settings)
		if err != nil {
			return "", fmt.Errorf("failed to locate chart %s version %s even after repository update attempt: %w", chartName, version, err)
		}
	}
	c.Log("Successfully located chart %s version %s at %s", chartName, version, chartPath)
	return chartPath, nil
}
