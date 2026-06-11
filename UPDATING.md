# Updating KubeSTIG When a New STIG Version Drops

DISA releases new Kubernetes STIG versions 2-3 times per year. This guide covers exactly how to update KubeSTIG when that happens.

---

## Step 1: Find Out What Changed

```bash
# Go to STIG Viewer and look at the latest Kubernetes STIG
# https://www.stigviewer.com/stigs/kubernetes
#
# Compare the new version (e.g., v2r6) with the current version (v2r5)
# Look for:
#   - New findings (new V-IDs you haven't seen before)
#   - Modified findings (same V-ID but changed description, severity, or check)
#   - Removed findings (V-IDs that no longer exist)
```

You can also check the Tenable audit page for a formatted list:
```
https://www.tenable.com/audits/DISA_STIG_Kubernetes_v2rX
```
Replace `v2rX` with the new version number.

---

## Step 2: See What KubeSTIG Currently Has

```bash
# List all current findings
ls KubeSTIG/pkg/stig/findings/

# Count them
ls KubeSTIG/pkg/stig/findings/ | wc -l

# View a specific finding
cat KubeSTIG/pkg/stig/findings/V-242390.yaml
```

---

## Step 3: Add a New Finding

When DISA adds a new finding (new V-ID that doesn't exist yet):

```bash
# Create a new YAML file named after the V-ID
cat > KubeSTIG/pkg/stig/findings/V-242500.yaml << 'EOF'
vid: V-242500
cntr_id: CNTR-K8-001500
title: "Paste the finding title from STIG Viewer"
severity: "CAT II"
category: "ACCESS CONTROL"
nist_controls: "AC-6"
check_type: cluster_api
check_field: "apiserver.some-flag"
expected_value: "true"
description: "What this finding checks for"
remediation: "How to fix it if it fails"
EOF
```

### How to fill in each field

**vid**, The V-ID from STIG Viewer (e.g., V-242500). This is the unique identifier.

**cntr_id**, The CNTR-K8 ID (e.g., CNTR-K8-001500). Found in the STIG finding details.

**title**, Copy the finding title exactly as it appears in STIG Viewer.

**severity**, One of:
- `CAT I`: Critical. Must fix. Highest priority.
- `CAT II`: High. Should fix. Most findings are this.
- `CAT III`: Medium/Low. Fix when possible.

**category**, The STIG category. Common values:
- `ACCESS CONTROL`
- `CONFIGURATION MANAGEMENT`
- `SYSTEM AND COMMUNICATIONS PROTECTION`
- `AUDIT AND ACCOUNTABILITY`
- `IDENTIFICATION AND AUTHENTICATION`

**nist_controls**, The NIST 800-53 control IDs listed in the finding (e.g., AC-6, SC-8, AU-3).

**check_type**, How KubeSTIG verifies this finding. One of:

| Value | What it does | When to use |
|---|---|---|
| `cluster_api` | Reads flags from control plane pod specs via the Kubernetes API | API server, controller manager, scheduler, etcd flags |
| `node_config` | Checks node-level settings (file permissions, kubelet config) | Kubelet settings, file ownership, SSH. Currently returns ERROR (needs DaemonSet) |
| `workload` | Checks deployed workloads (pods, secrets, namespaces) | Secrets as env vars, privileged ports, default namespace, dashboard |
| `manual` | Cannot be automated, requires human review | Returns N/A |

**check_field**, Tells the scanner what to check. Format depends on check_type:

For `cluster_api`: use `component.flag-name`:
```yaml
# Checks --anonymous-auth flag on kube-apiserver
check_field: "apiserver.anonymous-auth"

# Checks --profiling flag on kube-controller-manager
check_field: "controller-manager.profiling"

# Checks --tls-min-version flag on kube-scheduler
check_field: "scheduler.tls-min-version"

# Checks --auto-tls flag on etcd
check_field: "etcd.auto-tls"
```

Valid components: `apiserver`, `controller-manager`, `scheduler`, `etcd`

For `workload`: use one of the existing check names:
```yaml
check_field: "workloads-in-default-namespace"   # Checks for pods in default ns
check_field: "secrets-as-env-vars"              # Checks for secrets used as env vars
check_field: "dashboard-deployed"               # Checks if K8s dashboard exists
check_field: "privileged-host-ports"            # Checks for pods using host ports < 1024
```

For `node_config`: describe what to check (scanner will return ERROR until node scanning is implemented):
```yaml
check_field: "kubelet.read-only-port"
check_field: "manifest-ownership"
check_field: "kubelet-config-permissions"
```

**expected_value**, What the scanner expects to find:
```yaml
expected_value: "true"      # Flag must be set to exactly "true"
expected_value: "false"     # Flag must be set to exactly "false"
expected_value: "set"       # Flag must exist (any value)
expected_value: "not-set"   # Flag must NOT exist
expected_value: "not-zero"  # Flag must not be "0"
expected_value: "Node,RBAC" # Flag must contain these comma-separated values
expected_value: "n/a"       # Used with check_type: manual
```

**description**, One sentence explaining what the check does. Keep it short.

**remediation**, How to fix it. Copy from STIG Viewer or write your own.

---

## Step 4: Modify an Existing Finding

When DISA changes an existing finding (same V-ID, different content):

```bash
# Edit the existing file
vi KubeSTIG/pkg/stig/findings/V-242390.yaml

# Common changes:
#   - severity changed (e.g., CAT II → CAT I)
#   - description updated
#   - remediation steps changed
#   - NIST controls updated
```

---

## Step 5: Remove a Finding

When DISA removes a finding from the STIG:

```bash
# Simply delete the file
rm KubeSTIG/pkg/stig/findings/V-242437.yaml
```

---

## Step 6: Rebuild KubeSTIG

After making any changes to the findings:

```bash
cd KubeSTIG

# Rebuild the binary (the findings are embedded at compile time)
go build -o kubestig ./cmd/

# Verify it picks up your changes
./kubestig scan --kubeconfig ~/.kube/config
```

The Go compiler embeds all YAML files from `pkg/stig/findings/` into the binary at build time. No external files needed at runtime, the binary is self-contained.

---

## Step 7: Test Your Changes

```bash
# Run a scan and check the total count matches expectations
./kubestig scan --kubeconfig ~/.kube/config

# Check that new findings appear
./kubestig scan --kubeconfig ~/.kube/config --output json | grep "V-242500"

# The CKL output contains the Fix Text (DISA-standard remediation guidance)
# that auditors read in STIG Viewer. KubeSTIG does not apply remediations , 
# use ansible-lockdown or your provisioning pipeline for that.
./kubestig scan --kubeconfig ~/.kube/config --output ckl > results.ckl
```

---

## Step 8: Commit and Push

```bash
git add KubeSTIG/pkg/stig/findings/
git commit -m "Update STIG definitions to v2r6: added V-242500, modified V-242390, removed V-242437"
git push origin main
```

---

## Adding a New Type of Check (Rare)

If a new STIG finding requires a check that doesn't fit the existing patterns, you'll need to add Go code. This is rare, most findings check API server flags or workload configurations, which are already supported.

### Adding a new workload check

1. Open `KubeSTIG/pkg/scanner/scanner.go`
2. Find the `checkWorkload` function
3. Add a new case:

```go
case "your-new-check-name":
    return s.yourNewCheckFunction(ctx, f)
```

4. Write the check function:

```go
func (s *Scanner) yourNewCheckFunction(ctx context.Context, f stig.Finding) stig.Result {
    // Your check logic here
    // Use s.client to talk to the Kubernetes API
    // Return stig.Result with StatusPass, StatusFail, or StatusErr
}
```

5. Reference it in your finding YAML:

```yaml
check_type: workload
check_field: "your-new-check-name"
```

### Adding a new component to cluster_api checks

The scanner already supports `apiserver`, `controller-manager`, `scheduler`, and `etcd`. If a new STIG finding checks a different component (unlikely), you'd need to add it to the pod detection logic in `scanner.go`:

```go
case strings.HasPrefix(name, "your-new-component"):
    component = "your-new-component"
```

---

## Quick Reference: File Structure

```
KubeSTIG/
├── cmd/
│   ├── main.go              # CLI entry point
│   ├── scan.go              # kubestig scan command
│   └── report.go            # kubestig report command (stub)
├── pkg/
│   ├── scanner/
│   │   └── scanner.go       # Core scanning logic (only touch for new check types)
│   └── stig/
│       ├── definitions.go   # Loads all YAML files from findings/ (don't touch)
│       ├── output.go        # Terminal and JSON output formatting (don't touch)
│       ├── types.go         # Data types (don't touch)
│       └── findings/        # ← THIS IS WHERE YOU WORK
│           ├── V-242376.yaml
│           ├── V-242377.yaml
│           ├── ...
│           └── V-242437.yaml
├── Makefile
├── go.mod
└── go.sum
```

**For 95% of STIG updates, you only touch files in `pkg/stig/findings/`.** No Go code changes needed.

---

## Maintenance Schedule

| When | What | Time |
|---|---|---|
| DISA drops a new STIG version (2-3x/year) | Diff findings, add/modify/remove YAML files, rebuild | 30-60 minutes |
| New Kubernetes version (3x/year) | Test existing scans still work, check for deprecated flags | 15-30 minutes |
| Someone reports a false positive | Edit the finding YAML to fix the check, rebuild | 10 minutes |
