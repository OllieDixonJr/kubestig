package scanner

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/kubestig/kubestig/pkg/stig"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Scanner checks a Kubernetes cluster against STIG findings.
type Scanner struct {
	client          *kubernetes.Clientset
	restConfig      *rest.Config
	InsecureKubelet bool
	WithNodeAgent   bool
	AgentImage      string
}

// New creates a scanner connected to the cluster.
//
// Kubeconfig resolution mirrors kubectl: explicit --kubeconfig flag wins,
// otherwise the KUBECONFIG env var, otherwise ~/.kube/config.
func New(kubeconfigPath string) (*Scanner, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}

	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	).ClientConfig()
	if err != nil {
		src := kubeconfigPath
		if src == "" {
			src = loadingRules.GetDefaultFilename()
		}
		return nil, fmt.Errorf("cannot load kubeconfig from %s: %w", src, err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("cannot create kubernetes client: %w", err)
	}

	return &Scanner{client: client, restConfig: config}, nil
}

// Scan runs all STIG checks and returns results.
func (s *Scanner) Scan(findings []stig.Finding) ([]stig.Result, error) {
	var results []stig.Result

	// Pre-fetch data we'll need for multiple checks
	ctx := context.Background()
	pods, err := s.client.CoreV1().Pods("kube-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("cannot list kube-system pods: %w", err)
	}

	// Fetch kubelet /configz from every node. Primary path is the API
	// server's /api/v1/nodes/<node>/proxy/configz (clean, RBAC-gated).
	// If the user passed --insecure-kubelet we connect to kubelet:10250
	// directly with client cert auth, bypassing the apiserver's
	// kubelet-serving-cert TLS verification. This is useful for
	// clusters that haven't enabled serverTLSBootstrap yet, kubeadm
	// defaults leave the kubelet with a self-signed cert lacking
	// IP SANs, which the apiserver proxy refuses to talk to.
	kubelets, err := fetchKubeletConfigs(ctx, s.client, s.restConfig, s.InsecureKubelet)
	if err != nil {
		// Non-fatal, individual kubelet-backed findings will fall
		// back to StatusErr with per-node context. Warn once here
		// so the user understands why those errors appear.
		fmt.Fprintf(os.Stderr, "warning: kubelet /configz fetch failed: %v\n", err)
	}

	// Optionally deploy the node-agent DaemonSet to answer findings
	// that need filesystem / process-state visibility on the nodes.
	// Ephemeral, the DaemonSet is deleted before Scan() returns.
	var agentReports NodeReports
	if s.WithNodeAgent {
		// If the kubelet proxy is broken for /configz (insecure mode),
		// it's broken for /containerLogs too. Reuse the direct kubelet
		// client so we can read pod logs.
		var directLogClient *http.Client
		if s.InsecureKubelet {
			c, clientErr := buildDirectKubeletClient(s.restConfig)
			if clientErr != nil {
				// Fall back to apiserver-proxied log reads, which
				// will probably fail the same TLS check that drove
				// the user to --insecure-kubelet in the first place,
				// but reporting the failure is better than hiding it.
				fmt.Fprintf(os.Stderr, "warning: direct kubelet client unavailable: %v\n", clientErr)
			}
			directLogClient = c
		}
		reports, agentErr := RunNodeAgent(ctx, s.client, s.AgentImage, directLogClient)
		if agentErr != nil {
			fmt.Fprintf(os.Stderr, "node agent failed: %v\n", agentErr)
		}
		if len(reports) == 0 && agentErr == nil {
			fmt.Fprintln(os.Stderr, "node agent ran but produced no reports (pods may have been cleaned up before logs could be read)")
		}
		agentReports = reports
	}

	// Extract control plane pod specs for flag checking
	componentArgs := make(map[string]map[string]string)
	for _, pod := range pods.Items {
		name := pod.Name
		var component string
		switch {
		case strings.HasPrefix(name, "kube-apiserver"):
			component = "apiserver"
		case strings.HasPrefix(name, "kube-controller-manager"):
			component = "controller-manager"
		case strings.HasPrefix(name, "kube-scheduler"):
			component = "scheduler"
		case strings.HasPrefix(name, "etcd"):
			component = "etcd"
		default:
			continue
		}

		args := make(map[string]string)
		for _, container := range pod.Spec.Containers {
			for _, arg := range container.Command {
				parseArg(arg, args)
			}
			for _, arg := range container.Args {
				parseArg(arg, args)
			}
		}
		componentArgs[component] = args
	}

	for _, f := range findings {
		result := s.checkFinding(ctx, f, componentArgs, kubelets, agentReports)
		results = append(results, result)
	}

	return results, nil
}

func parseArg(arg string, args map[string]string) {
	arg = strings.TrimPrefix(arg, "--")
	if idx := strings.Index(arg, "="); idx > 0 {
		args[arg[:idx]] = arg[idx+1:]
	}
}

func (s *Scanner) checkFinding(ctx context.Context, f stig.Finding, componentArgs map[string]map[string]string, kubelets kubeletConfigs, agentReports NodeReports) stig.Result {
	switch f.CheckType {
	case stig.CheckClusterAPI:
		return s.checkClusterAPI(ctx, f, componentArgs)
	case stig.CheckWorkload:
		return s.checkWorkload(ctx, f)
	case stig.CheckNodeConfig:
		// Kubelet flag checks are answerable via the /configz proxy.
		if strings.HasPrefix(f.CheckField, "kubelet.") {
			return s.checkKubeletConfig(f, kubelets)
		}
		// Everything else in node_config needs the filesystem/process
		// agent, look it up by check_field.
		return checkAgentReport(f, agentReports)
	case stig.CheckManual:
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusNA,
			Evidence: f.Description,
		}
	default:
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: "Unknown check type"}
	}
}

// checkAgentReport evaluates an agent-backed node_config finding
// against the reports collected from every node. All nodes must pass
// for the cluster-wide result to pass.
func checkAgentReport(f stig.Finding, reports NodeReports) stig.Result {
	if len(reports) == 0 {
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusErr,
			Evidence: "Agent reports unavailable, re-run with --with-node-agent",
		}
	}

	switch f.CheckField {
	case "worker-sshd-running":
		return aggregateNodeBool(f, reports, func(r NodeReport) bool { return r.SshdRunning },
			false, "sshd must not be running on worker nodes")

	case "worker-sshd-enabled":
		return aggregateNodeBool(f, reports, func(r NodeReport) bool { return r.SshdEnabled },
			false, "sshd must not be enabled on worker nodes")

	case "kubelet-config-ownership":
		return aggregateFileOwnership(f, reports, func(r NodeReport) []FileStat {
			return []FileStat{r.KubeletConfig}
		}, 0, 0, "kubelet config file")

	case "manifest-ownership":
		return aggregateFileOwnership(f, reports, func(r NodeReport) []FileStat {
			return r.Manifests
		}, 0, 0, "kubernetes manifest")

	case "kubelet-config-permissions":
		return aggregateFilePerms(f, reports, func(r NodeReport) []FileStat {
			return []FileStat{r.KubeletConfig}
		}, 0o644, "kubelet config file")

	case "manifest-permissions":
		return aggregateFilePerms(f, reports, func(r NodeReport) []FileStat {
			return r.Manifests
		}, 0o644, "kubernetes manifest")

	default:
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusErr,
			Evidence: fmt.Sprintf("no agent handler for check_field %q", f.CheckField),
		}
	}
}

// aggregateNodeBool passes only if every node's boolean observation
// equals the expected value. Note: this applies the check to every
// node; for "worker-*" findings, control plane nodes are technically
// out of scope. We still include them, a control plane running sshd
// is also a finding worth flagging.
func aggregateNodeBool(f stig.Finding, reports NodeReports, getter func(NodeReport) bool, expected bool, label string) stig.Result {
	var offenders []string
	for node, r := range reports {
		if getter(r) != expected {
			offenders = append(offenders, node)
		}
	}
	if len(offenders) == 0 {
		return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: fmt.Sprintf("%s as expected on all %d node(s)", label, len(reports))}
	}
	return stig.Result{
		Finding:  f,
		Status:   stig.StatusFail,
		Evidence: fmt.Sprintf("%s, violating nodes: %s", label, strings.Join(offenders, ", ")),
	}
}

// aggregateFileOwnership verifies that every file reported by the
// getter on every node has the expected uid/gid. Missing files are
// skipped (not all nodes have control-plane manifests).
func aggregateFileOwnership(f stig.Finding, reports NodeReports, getter func(NodeReport) []FileStat, expectUID, expectGID int, label string) stig.Result {
	var issues []string
	checked := 0
	for node, r := range reports {
		for _, fs := range getter(r) {
			if !fs.Exists {
				continue
			}
			checked++
			if fs.UID != expectUID || fs.GID != expectGID {
				issues = append(issues, fmt.Sprintf("%s:%s uid=%d gid=%d", node, fs.Path, fs.UID, fs.GID))
			}
		}
	}
	if checked == 0 {
		return stig.Result{Finding: f, Status: stig.StatusNA, Evidence: fmt.Sprintf("no %s files present on any node", label)}
	}
	if len(issues) == 0 {
		return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: fmt.Sprintf("all %d %s file(s) owned by root:root", checked, label)}
	}
	return stig.Result{
		Finding:  f,
		Status:   stig.StatusFail,
		Evidence: fmt.Sprintf("%s ownership, offenders: %s", label, strings.Join(issues, "; ")),
	}
}

// aggregateFilePerms verifies every reported file's mode is <= maxMode.
// maxMode is given as an octal literal (0o644). The agent reports mode
// as a string of octal digits which we decode here.
func aggregateFilePerms(f stig.Finding, reports NodeReports, getter func(NodeReport) []FileStat, maxMode int, label string) stig.Result {
	var issues []string
	checked := 0
	for node, r := range reports {
		for _, fs := range getter(r) {
			if !fs.Exists {
				continue
			}
			checked++
			mode := fs.ModeOctal()
			if mode > maxMode {
				issues = append(issues, fmt.Sprintf("%s:%s mode=%04o (>%04o)", node, fs.Path, mode, maxMode))
			}
		}
	}
	if checked == 0 {
		return stig.Result{Finding: f, Status: stig.StatusNA, Evidence: fmt.Sprintf("no %s files present on any node", label)}
	}
	if len(issues) == 0 {
		return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: fmt.Sprintf("all %d %s file(s) mode <= %04o", checked, label, maxMode)}
	}
	return stig.Result{
		Finding:  f,
		Status:   stig.StatusFail,
		Evidence: fmt.Sprintf("%s permissions, offenders: %s", label, strings.Join(issues, "; ")),
	}
}

// checkKubeletConfig evaluates a kubelet-flag finding against the
// effective kubelet config fetched from every node's /configz endpoint.
//
// The check passes only if every node reports the expected value;
// disagreement between nodes is a FAIL with evidence naming the
// divergent node(s).
func (s *Scanner) checkKubeletConfig(f stig.Finding, kubelets kubeletConfigs) stig.Result {
	flag := strings.TrimPrefix(f.CheckField, "kubelet.")
	path, known := kubeletConfigFlagPaths[flag]
	if !known {
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusErr,
			Evidence: fmt.Sprintf("No /configz path mapping for kubelet flag %q", flag),
		}
	}

	if len(kubelets) == 0 {
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusErr,
			Evidence: "No nodes reachable for kubelet /configz (check RBAC on nodes/proxy)",
		}
	}

	// Aggregate per-node observations. We want a single cluster-wide
	// verdict, but if nodes disagree we must say so.
	type nodeObs struct {
		node   string
		value  string
		exists bool
	}
	var obs []nodeObs
	for node, cfg := range kubelets {
		if cfg == nil {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusErr,
				Evidence: fmt.Sprintf("kubelet /configz unreachable on node %s", node),
			}
		}
		v, present := walkPath(cfg, path)
		obs = append(obs, nodeObs{node: node, value: formatValue(v), exists: present})
	}

	// All-nodes-agree check: if any two nodes differ, flag it.
	for i := 1; i < len(obs); i++ {
		if obs[i].value != obs[0].value || obs[i].exists != obs[0].exists {
			return stig.Result{
				Finding: f,
				Status:  stig.StatusFail,
				Evidence: fmt.Sprintf(
					"kubelet config inconsistent across nodes: %s=%q vs %s=%q",
					obs[0].node, obs[0].value, obs[i].node, obs[i].value,
				),
			}
		}
	}

	// All nodes agree, compare the unified value against expected.
	actual := obs[0].value
	exists := obs[0].exists

	switch f.ExpectedVal {
	case "not-set":
		if exists && actual != "" {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Actual:   actual,
				Evidence: fmt.Sprintf("kubelet %s is set to %q but should not be set", flag, actual),
			}
		}
		return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: fmt.Sprintf("kubelet %s is not set", flag)}

	case "set":
		if !exists || actual == "" {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Evidence: fmt.Sprintf("kubelet %s is not set but is required", flag),
			}
		}
		return stig.Result{Finding: f, Status: stig.StatusPass, Actual: actual, Evidence: fmt.Sprintf("kubelet %s=%s", flag, actual)}

	default:
		if !exists {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Evidence: fmt.Sprintf("kubelet %s is not set, expected %q", flag, f.ExpectedVal),
			}
		}
		if actual == f.ExpectedVal {
			return stig.Result{Finding: f, Status: stig.StatusPass, Actual: actual, Evidence: fmt.Sprintf("kubelet %s=%s", flag, actual)}
		}
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusFail,
			Actual:   actual,
			Evidence: fmt.Sprintf("kubelet %s=%s, expected %q", flag, actual, f.ExpectedVal),
		}
	}
}

func (s *Scanner) checkClusterAPI(ctx context.Context, f stig.Finding, componentArgs map[string]map[string]string) stig.Result {
	parts := strings.SplitN(f.CheckField, ".", 2)
	if len(parts) != 2 {
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: "Invalid check_field format"}
	}
	component, flag := parts[0], parts[1]

	args, ok := componentArgs[component]
	if !ok {
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusErr,
			Evidence: fmt.Sprintf("Component %s not found in kube-system pods", component),
		}
	}

	actual, flagSet := args[flag]

	switch f.ExpectedVal {
	case "not-set":
		if flagSet {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Actual:   actual,
				Evidence: fmt.Sprintf("--%s is set to %q but should not be set", flag, actual),
			}
		}
		return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: fmt.Sprintf("--%s is not set", flag)}

	case "set":
		if !flagSet || actual == "" {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Evidence: fmt.Sprintf("--%s is not set but is required", flag),
			}
		}
		return stig.Result{Finding: f, Status: stig.StatusPass, Actual: actual, Evidence: fmt.Sprintf("--%s=%s", flag, actual)}

	case "not-zero":
		if flagSet && actual == "0" {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Actual:   actual,
				Evidence: fmt.Sprintf("--%s is set to 0 but must be non-zero", flag),
			}
		}
		return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: fmt.Sprintf("--%s=%s", flag, actual)}

	default:
		// Direct value comparison
		if !flagSet {
			// Check if the expected value should be the default
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Evidence: fmt.Sprintf("--%s is not set, expected %q", flag, f.ExpectedVal),
			}
		}
		// Handle comma-separated values (e.g., Node,RBAC)
		if strings.Contains(f.ExpectedVal, ",") {
			expected := strings.Split(f.ExpectedVal, ",")
			for _, e := range expected {
				if !strings.Contains(actual, strings.TrimSpace(e)) {
					return stig.Result{
						Finding:  f,
						Status:   stig.StatusFail,
						Actual:   actual,
						Evidence: fmt.Sprintf("--%s=%s, expected to contain %q", flag, actual, f.ExpectedVal),
					}
				}
			}
			return stig.Result{Finding: f, Status: stig.StatusPass, Actual: actual}
		}
		if actual != f.ExpectedVal {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Actual:   actual,
				Evidence: fmt.Sprintf("--%s=%s, expected %q", flag, actual, f.ExpectedVal),
			}
		}
		return stig.Result{Finding: f, Status: stig.StatusPass, Actual: actual}
	}
}

func (s *Scanner) checkWorkload(ctx context.Context, f stig.Finding) stig.Result {
	switch f.CheckField {
	case "workloads-in-default-namespace":
		return s.checkDefaultNamespaceWorkloads(ctx, f)
	case "secrets-as-env-vars":
		return s.checkSecretsAsEnvVars(ctx, f)
	case "dashboard-deployed":
		return s.checkDashboard(ctx, f)
	case "privileged-host-ports":
		return s.checkPrivilegedPorts(ctx, f)
	default:
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: "Workload check not implemented: " + f.CheckField}
	}
}

func (s *Scanner) checkDefaultNamespaceWorkloads(ctx context.Context, f stig.Finding) stig.Result {
	pods, err := s.client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{})
	if err != nil {
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: err.Error()}
	}
	if len(pods.Items) > 0 {
		names := make([]string, 0)
		for _, p := range pods.Items {
			names = append(names, p.Name)
		}
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusFail,
			Evidence: fmt.Sprintf("%d pod(s) in default namespace: %s", len(pods.Items), strings.Join(names, ", ")),
		}
	}
	return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: "No workloads in default namespace"}
}

func (s *Scanner) checkSecretsAsEnvVars(ctx context.Context, f stig.Finding) stig.Result {
	namespaces, err := s.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: err.Error()}
	}

	var violations []string
	for _, ns := range namespaces.Items {
		// Skip system namespaces
		if strings.HasPrefix(ns.Name, "kube-") {
			continue
		}
		pods, err := s.client.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, pod := range pods.Items {
			for _, c := range pod.Spec.Containers {
				for _, env := range c.Env {
					if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
						violations = append(violations, fmt.Sprintf("%s/%s (container: %s, env: %s)", ns.Name, pod.Name, c.Name, env.Name))
					}
				}
				for _, envFrom := range c.EnvFrom {
					if envFrom.SecretRef != nil {
						violations = append(violations, fmt.Sprintf("%s/%s (container: %s, envFrom: %s)", ns.Name, pod.Name, c.Name, envFrom.SecretRef.Name))
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		evidence := fmt.Sprintf("%d pod(s) use secrets as env vars", len(violations))
		if len(violations) <= 5 {
			evidence += ": " + strings.Join(violations, "; ")
		}
		return stig.Result{Finding: f, Status: stig.StatusFail, Evidence: evidence}
	}
	return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: "No secrets used as environment variables"}
}

func (s *Scanner) checkDashboard(ctx context.Context, f stig.Finding) stig.Result {
	_, err := s.client.CoreV1().Namespaces().Get(ctx, "kubernetes-dashboard", metav1.GetOptions{})
	if err == nil {
		return stig.Result{Finding: f, Status: stig.StatusFail, Evidence: "kubernetes-dashboard namespace exists"}
	}

	// Also check for dashboard deployments in other namespaces
	deployments, err := s.client.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: err.Error()}
	}
	for _, d := range deployments.Items {
		if strings.Contains(d.Name, "dashboard") {
			return stig.Result{
				Finding:  f,
				Status:   stig.StatusFail,
				Evidence: fmt.Sprintf("Dashboard deployment found: %s/%s", d.Namespace, d.Name),
			}
		}
	}

	return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: "No Kubernetes dashboard found"}
}

func (s *Scanner) checkPrivilegedPorts(ctx context.Context, f stig.Finding) stig.Result {
	namespaces, err := s.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return stig.Result{Finding: f, Status: stig.StatusErr, Evidence: err.Error()}
	}

	var violations []string
	for _, ns := range namespaces.Items {
		if strings.HasPrefix(ns.Name, "kube-") {
			continue
		}
		pods, err := s.client.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}
		for _, pod := range pods.Items {
			for _, c := range pod.Spec.Containers {
				for _, p := range c.Ports {
					if p.HostPort > 0 && p.HostPort < 1024 {
						violations = append(violations, fmt.Sprintf("%s/%s (container: %s, hostPort: %d)", ns.Name, pod.Name, c.Name, p.HostPort))
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		return stig.Result{
			Finding:  f,
			Status:   stig.StatusFail,
			Evidence: fmt.Sprintf("%d container(s) use privileged host ports: %s", len(violations), strings.Join(violations, "; ")),
		}
	}
	return stig.Result{Finding: f, Status: stig.StatusPass, Evidence: "No user pods use privileged host ports"}
}
