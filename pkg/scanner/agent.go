package scanner

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

//go:embed agent_script.sh
var agentScript string

const (
	agentNamespace      = "kube-system"
	agentConfigMapName  = "kubestig-node-agent"
	agentDaemonSetName  = "kubestig-node-agent"
	agentLabelKey       = "app"
	agentLabelValue     = "kubestig-node-agent"
	agentReportBegin    = "---BEGIN-KUBESTIG-REPORT---"
	agentReportEnd      = "---END-KUBESTIG-REPORT---"
	defaultAgentImage   = "docker.io/library/busybox:stable"
	agentWaitTimeoutSec = 90
)

// FileStat is the per-file report emitted by the node agent script.
//
// Mode arrives as a JSON string of octal digits (e.g. "644"), the
// shell's `stat -c '%a'` output. ModeOctal decodes it for comparisons.
type FileStat struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
	Mode   string `json:"mode"`
}

// ModeOctal parses the Mode string as octal. Returns 0 on parse
// failure, callers should treat 0 as "unknown / could not determine".
func (f FileStat) ModeOctal() int {
	if f.Mode == "" {
		return 0
	}
	n, err := strconv.ParseInt(f.Mode, 8, 32)
	if err != nil {
		return 0
	}
	return int(n)
}

// NodeReport is the parsed JSON emitted by the agent on a single node.
type NodeReport struct {
	KubeletConfig FileStat   `json:"kubelet_config"`
	Manifests     []FileStat `json:"manifests"`
	SshdRunning   bool       `json:"sshd_running"`
	SshdEnabled   bool       `json:"sshd_enabled"`
}

// NodeReports maps node name → agent report.
type NodeReports map[string]NodeReport

// RunNodeAgent deploys a DaemonSet that runs the agent script on every
// node, collects the JSON reports from the pods' stdout, and cleans up.
//
// If directLogClient is non-nil, logs are pulled directly from
// kubelet:10250/containerLogs/... instead of through the apiserver.
// This mirrors the /configz path: clusters whose kubelet serving cert
// lacks IP SANs need this escape hatch because `kubectl logs` also
// fails the same TLS check.
//
// The scanner calls this at most once per Scan() when node-agent mode
// is enabled via Scanner.WithNodeAgent.
func RunNodeAgent(ctx context.Context, client *kubernetes.Clientset, image string, directLogClient *http.Client) (NodeReports, error) {
	if image == "" {
		image = defaultAgentImage
	}

	// Create ConfigMap + DaemonSet. Always try to clean both up.
	if err := applyAgentConfigMap(ctx, client); err != nil {
		return nil, fmt.Errorf("apply agent configmap: %w", err)
	}
	defer deleteAgentConfigMap(context.Background(), client)

	if err := applyAgentDaemonSet(ctx, client, image); err != nil {
		return nil, fmt.Errorf("apply agent daemonset: %w", err)
	}
	defer deleteAgentDaemonSet(context.Background(), client)

	// Wait for pods to be running.
	pods, err := waitForAgentPods(ctx, client, agentWaitTimeoutSec*time.Second)
	if err != nil {
		return nil, fmt.Errorf("waiting for agent pods: %w", err)
	}

	// The agent script prints its report and then sleeps. Give the
	// script a moment to finish writing before we read logs, Pod's
	// "Running" phase transition happens the moment the container
	// process starts, which is before `sh` has exec'd the script.
	time.Sleep(4 * time.Second)

	// Pull logs, parse reports. Nodes whose logs we can't read (or
	// whose reports don't parse) are simply absent from the result
	// map, check code reports ERROR per-finding rather than failing
	// the whole scan.
	reports := make(NodeReports, len(pods))
	var lastErr error
	for _, p := range pods {
		nodeIP := podNodeIP(ctx, client, &p)
		report, err := readAgentReport(ctx, client, &p, nodeIP, directLogClient)
		if err != nil {
			lastErr = err
			continue
		}
		reports[p.Spec.NodeName] = report
	}

	if len(reports) == 0 && lastErr != nil {
		return reports, fmt.Errorf("no agent reports readable: %w", lastErr)
	}
	return reports, nil
}

// podNodeIP returns the InternalIP of the node a pod is running on,
// or empty string if we can't determine it.
func podNodeIP(ctx context.Context, client *kubernetes.Clientset, p *corev1.Pod) string {
	if p.Spec.NodeName == "" {
		return ""
	}
	n, err := client.CoreV1().Nodes().Get(ctx, p.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return internalNodeIP(n)
}

func applyAgentConfigMap(ctx context.Context, client *kubernetes.Clientset) error {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentConfigMapName,
			Namespace: agentNamespace,
			Labels:    map[string]string{agentLabelKey: agentLabelValue},
		},
		Data: map[string]string{"scan.sh": agentScript},
	}
	// Try create; if it already exists (from a previous aborted scan), update.
	_, err := client.CoreV1().ConfigMaps(agentNamespace).Create(ctx, cm, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		_, err = client.CoreV1().ConfigMaps(agentNamespace).Update(ctx, cm, metav1.UpdateOptions{})
	}
	return err
}

func deleteAgentConfigMap(ctx context.Context, client *kubernetes.Clientset) {
	_ = client.CoreV1().ConfigMaps(agentNamespace).Delete(ctx, agentConfigMapName, metav1.DeleteOptions{})
}

func applyAgentDaemonSet(ctx context.Context, client *kubernetes.Clientset, image string) error {
	trueVal := true
	falseVal := false
	hostPathDir := corev1.HostPathDirectory
	hostPathDirOrCreate := corev1.HostPathDirectoryOrCreate
	rootUser := int64(0)

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentDaemonSetName,
			Namespace: agentNamespace,
			Labels:    map[string]string{agentLabelKey: agentLabelValue},
			Annotations: map[string]string{
				// Flag ourselves as an ephemeral compliance tool so operators
				// inspecting the cluster can tell this isn't a permanent workload.
				"kubestig.io/ephemeral": "true",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{agentLabelKey: agentLabelValue},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{agentLabelKey: agentLabelValue},
				},
				Spec: corev1.PodSpec{
					// Tolerate control-plane taints so we land on every node.
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
					HostPID: true, // so /host/proc shows host processes for sshd_running
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &rootUser,
					},
					Containers: []corev1.Container{{
						Name:    "agent",
						Image:   image,
						Command: []string{"sh", "/agent/scan.sh"},
						SecurityContext: &corev1.SecurityContext{
							RunAsUser:                &rootUser,
							AllowPrivilegeEscalation: &falseVal,
							ReadOnlyRootFilesystem:   &trueVal,
							Capabilities: &corev1.Capabilities{
								// We only need to read files as root; no network, no exec.
								Drop: []corev1.Capability{"ALL"},
							},
						},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "script", MountPath: "/agent", ReadOnly: true},
							{Name: "etc-kubernetes", MountPath: "/host/etc-kubernetes", ReadOnly: true},
							{Name: "var-lib-kubelet", MountPath: "/host/var-lib-kubelet", ReadOnly: true},
							{Name: "proc", MountPath: "/host/proc", ReadOnly: true},
							{Name: "etc-systemd-system", MountPath: "/host/etc-systemd-system", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{
							Name: "script",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: agentConfigMapName},
									DefaultMode:          int32Ptr(0o555),
								},
							},
						},
						hostVol("etc-kubernetes", "/etc/kubernetes", hostPathDir),
						hostVol("var-lib-kubelet", "/var/lib/kubelet", hostPathDir),
						hostVol("proc", "/proc", hostPathDir),
						hostVol("etc-systemd-system", "/etc/systemd/system", hostPathDirOrCreate),
					},
				},
			},
		},
	}

	_, err := client.AppsV1().DaemonSets(agentNamespace).Create(ctx, ds, metav1.CreateOptions{})
	if err == nil {
		return nil
	}
	if apierrors.IsAlreadyExists(err) {
		_, err = client.AppsV1().DaemonSets(agentNamespace).Update(ctx, ds, metav1.UpdateOptions{})
	}
	return err
}

func deleteAgentDaemonSet(ctx context.Context, client *kubernetes.Clientset) {
	policy := metav1.DeletePropagationForeground
	_ = client.AppsV1().DaemonSets(agentNamespace).Delete(ctx, agentDaemonSetName, metav1.DeleteOptions{
		PropagationPolicy: &policy,
	})
}

func hostVol(name, path string, kind corev1.HostPathType) corev1.Volume {
	return corev1.Volume{
		Name: name,
		VolumeSource: corev1.VolumeSource{
			HostPath: &corev1.HostPathVolumeSource{Path: path, Type: &kind},
		},
	}
}

func int32Ptr(v int32) *int32 { return &v }

// waitForAgentPods polls until every DaemonSet pod has reached the
// Running phase, or the timeout elapses. Returns whatever pods the
// DaemonSet produced at end of the wait so partial results still work.
func waitForAgentPods(ctx context.Context, client *kubernetes.Clientset, timeout time.Duration) ([]corev1.Pod, error) {
	deadline := time.Now().Add(timeout)
	selector := fmt.Sprintf("%s=%s", agentLabelKey, agentLabelValue)

	for {
		pods, err := client.CoreV1().Pods(agentNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			return nil, err
		}

		running := 0
		for _, p := range pods.Items {
			if p.Status.Phase == corev1.PodRunning {
				running++
			}
		}

		if running > 0 && running == len(pods.Items) {
			return pods.Items, nil
		}
		if time.Now().After(deadline) {
			return pods.Items, fmt.Errorf("timed out waiting for %d agent pods (got %d running)", len(pods.Items), running)
		}
		time.Sleep(2 * time.Second)
	}
}

// readAgentReport fetches a pod's stdout logs and extracts the JSON
// payload between the BEGIN/END markers.
//
// If directLogClient is non-nil and nodeIP is set, logs are pulled
// directly from kubelet:10250/containerLogs/... instead of via the
// apiserver proxy. Needed for clusters whose kubelet serving cert
// fails the apiserver's TLS verification.
func readAgentReport(ctx context.Context, client *kubernetes.Clientset, pod *corev1.Pod, nodeIP string, directLogClient *http.Client) (NodeReport, error) {
	var out NodeReport
	var body []byte

	if directLogClient != nil && nodeIP != "" {
		url := fmt.Sprintf("https://%s:10250/containerLogs/%s/%s/agent",
			nodeIP, agentNamespace, pod.Name)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return out, err
		}
		resp, err := directLogClient.Do(req)
		if err != nil {
			return out, fmt.Errorf("direct kubelet logs %s: %w", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return out, fmt.Errorf("direct kubelet logs %s: HTTP %d", url, resp.StatusCode)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return out, err
		}
	} else {
		req := client.CoreV1().Pods(agentNamespace).GetLogs(pod.Name, &corev1.PodLogOptions{})
		stream, err := req.Stream(ctx)
		if err != nil {
			return out, fmt.Errorf("opening logs for %s: %w", pod.Name, err)
		}
		defer stream.Close()
		body, err = io.ReadAll(stream)
		if err != nil {
			return out, fmt.Errorf("reading logs for %s: %w", pod.Name, err)
		}
	}

	// Carve out the JSON payload between the markers.
	lines := bufio.NewScanner(strings.NewReader(string(body)))
	lines.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var inReport bool
	var jsonText strings.Builder
	for lines.Scan() {
		line := lines.Text()
		switch {
		case line == agentReportBegin:
			inReport = true
		case line == agentReportEnd:
			inReport = false
		case inReport:
			jsonText.WriteString(line)
			jsonText.WriteByte('\n')
		}
	}

	if jsonText.Len() == 0 {
		return out, fmt.Errorf("no kubestig report markers in logs for %s", pod.Name)
	}

	if err := json.Unmarshal([]byte(jsonText.String()), &out); err != nil {
		return out, fmt.Errorf("parsing agent JSON from %s: %w", pod.Name, err)
	}
	return out, nil
}
