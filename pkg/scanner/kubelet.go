package scanner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// kubeletConfigFlagPaths maps the kubelet CLI flag names used in STIG
// finding YAML files (e.g. "anonymous-auth") to the JSON path inside
// the `/configz` response (e.g. "authentication.anonymous.enabled").
//
// The STIG YAMLs reference CLI flags because that's how the DISA
// benchmark is written, but the actual running kubelet now reads most
// config from /var/lib/kubelet/config.yaml. /configz exposes the merged
// effective config, so it's the right source of truth regardless of
// whether a setting came from a flag or the config file.
var kubeletConfigFlagPaths = map[string]string{
	"read-only-port":     "readOnlyPort",
	"anonymous-auth":     "authentication.anonymous.enabled",
	"authorization-mode": "authorization.mode",
	"static-pod-path":    "staticPodPath",
	"hostname-override":  "hostnameOverride",
	"client-ca-file":     "authentication.x509.clientCAFile",
}

// kubeletConfigs maps node name → effective kubelet config (parsed JSON)
// fetched via the API server's node proxy.
type kubeletConfigs map[string]map[string]interface{}

// fetchKubeletConfigs retrieves /configz from every node.
//
// Primary transport is the apiserver proxy: /api/v1/nodes/<node>/proxy/configz.
// That path is RBAC-gated and uses the client cert from the kubeconfig.
//
// If insecureKubelet is true, we bypass the apiserver and connect to
// kubelet:10250 directly with the client cert from restConfig, skipping
// kubelet's serving-cert TLS verification. This is useful for clusters
// whose kubelet cert has no IP SANs (the kubeadm default) and therefore
// can't be proxied through the apiserver.
//
// Nodes that can't be reached end up with a nil map so callers can
// produce a helpful "couldn't read kubelet config on X" error rather
// than a silent failure.
func fetchKubeletConfigs(ctx context.Context, client *kubernetes.Clientset, restConfig *rest.Config, insecureKubelet bool) (kubeletConfigs, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}

	var directClient *http.Client
	if insecureKubelet {
		directClient, err = buildDirectKubeletClient(restConfig)
		if err != nil {
			return nil, fmt.Errorf("building direct kubelet client: %w", err)
		}
	}

	out := make(kubeletConfigs, len(nodes.Items))
	for _, n := range nodes.Items {
		var cfg map[string]interface{}
		if insecureKubelet {
			cfg, err = fetchConfigzDirect(ctx, directClient, &n)
		} else {
			cfg, err = fetchConfigzViaAPIProxy(ctx, client, n.Name)
		}
		if err != nil {
			out[n.Name] = nil
			continue
		}
		out[n.Name] = cfg
	}
	return out, nil
}

// fetchConfigzViaAPIProxy is the secure default path, the apiserver
// proxies, handles auth, and verifies the kubelet's serving cert.
func fetchConfigzViaAPIProxy(ctx context.Context, client *kubernetes.Clientset, nodeName string) (map[string]interface{}, error) {
	raw, err := client.CoreV1().
		RESTClient().
		Get().
		Resource("nodes").
		Name(nodeName).
		SubResource("proxy").
		Suffix("configz").
		DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("proxy to %s/configz: %w", nodeName, err)
	}
	return decodeConfigz(raw, nodeName)
}

// fetchConfigzDirect talks straight to kubelet:10250 using the client
// cert from the kubeconfig. Used only when --insecure-kubelet is set.
func fetchConfigzDirect(ctx context.Context, c *http.Client, node *corev1.Node) (map[string]interface{}, error) {
	ip := internalNodeIP(node)
	if ip == "" {
		return nil, fmt.Errorf("node %s has no InternalIP", node.Name)
	}

	url := fmt.Sprintf("https://%s:10250/configz", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("direct kubelet %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("direct kubelet %s: HTTP %d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return decodeConfigz(raw, node.Name)
}

func decodeConfigz(raw []byte, nodeName string) (map[string]interface{}, error) {
	var wrapper struct {
		KubeletConfig map[string]interface{} `json:"kubeletconfig"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return nil, fmt.Errorf("decoding configz for %s: %w", nodeName, err)
	}
	if wrapper.KubeletConfig == nil {
		return nil, fmt.Errorf("configz on %s has no kubeletconfig key", nodeName)
	}
	return wrapper.KubeletConfig, nil
}

// buildDirectKubeletClient constructs an HTTP client that auths with
// the same client cert the kubeconfig uses, but skips verification of
// the kubelet's serving cert.
func buildDirectKubeletClient(cfg *rest.Config) (*http.Client, error) {
	// Pull TLS material out of the rest.Config. For kubeconfigs that
	// store the cert inline (the kubeadm default), these are PEM bytes.
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if len(cfg.CertData) > 0 && len(cfg.KeyData) > 0 {
		cert, err := tls.X509KeyPair(cfg.CertData, cfg.KeyData)
		if err != nil {
			return nil, fmt.Errorf("loading client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else if cfg.BearerToken != "" || cfg.BearerTokenFile != "" {
		// Bearer-token kubeconfigs don't work with kubelet:10250 directly
		//, kubelet needs the x509 client cert. Let the call proceed and
		// fail with 401 so the error surface is clear.
	}

	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// internalNodeIP returns the node's InternalIP (what kubelet binds to
// for :10250). Falls back to the first Address of any type.
func internalNodeIP(n *corev1.Node) string {
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	if len(n.Status.Addresses) > 0 {
		return n.Status.Addresses[0].Address
	}
	return ""
}

// walkPath navigates a dot-separated JSON path into a decoded config
// map and returns the terminal value. Missing keys return (nil, false).
func walkPath(cfg map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var cur interface{} = cfg
	for _, p := range parts {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// formatValue renders a decoded JSON scalar the way a STIG evidence
// line expects, "false" not "FALSE", "0" not "0.0" for ints-as-floats.
func formatValue(v interface{}) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		// JSON numbers decode as float64. Most kubelet config numerics
		// are ints (port numbers, TTLs), so render without decimals
		// when the value is whole.
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%v", x)
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}
