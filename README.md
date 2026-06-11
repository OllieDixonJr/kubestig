# KubeSTIG

**Automated DISA Kubernetes STIG scanning that produces CKL output.**

A read-only compliance scanner that evaluates a Kubernetes cluster against the DISA Kubernetes STIG and emits results in `.ckl` format, the same format STIG Viewer and eMASS consume. Current implementation targets a subset of the STIG; see `pkg/stig/findings/` for the exact list of supported V-IDs. Full coverage against the current manual revision is in progress.

---

## The gap this fills

The compliance tooling landscape for Kubernetes is well-populated for CIS but conspicuously empty for DISA STIG. KubeSTIG fills the specific overlap none of the existing tools cover:

| Tool | Coverage | Output | Reads or writes? |
|---|---|---|---|
| **Kube-Bench** (Aqua Security) | CIS Kubernetes Benchmark | text/JSON | reads |
| **OpenSCAP** | RHEL/Rocky STIG, some CIS | XCCDF, ARF | reads |
| **eSTIG** | Host-level STIGs (Linux, Windows) | CKL | reads |
| **ansible-lockdown** | DISA STIG remediation (Linux) | n/a | **writes** |
| **Manual STIG Viewer** | Anything you click through | CKL | reads |
| **KubeSTIG** | **DISA Kubernetes STIG v2r5** | **CKL**, JSON, table | **reads only** |

### What none of the others do

- **Kube-Bench** is the obvious comparison, but CIS ≠ DISA STIG. CIS is a community benchmark; DISA STIG is an authoritative DoD compliance baseline. They overlap in spirit, diverge in specifics, and consume different evidence formats. If you're filing eMASS packages, Kube-Bench output is not what gets uploaded.
- **OpenSCAP** has SCAP content for many Linux STIGs but no DISA Kubernetes STIG content. The DISA Kubernetes STIG ships only as a checklist, not as machine-readable XCCDF.
- **eSTIG** evaluates host-level STIGs against an OS. It doesn't speak Kubernetes, it can't read a kubelet `/configz`, list API server flags, or know what a `staticPodPath` is.
- **ansible-lockdown** is the remediation half of the equation. It changes things. KubeSTIG is the assessment half, it reports what's wrong and lets you decide what to fix and how. The two are complementary, not redundant.
- **Manual STIG Viewer** review is what most teams do today. Open the checklist, walk through every finding, click through `kubectl` and `journalctl` checks for each. Hours of work per cluster, error-prone, and the answers go stale the moment a kubeadm upgrade lands.

KubeSTIG automates what manual STIG Viewer review does, in the format STIG Viewer expects, against the live cluster.

---

## What it does

- Scans against 38 findings from the **DISA Kubernetes STIG v2r5** (a curated subset, 7 CAT I, 31 CAT II; see `pkg/stig/findings/` for the exact V-IDs, with full coverage in progress)
- Reads cluster state via:
  - The Kubernetes API server (deployments, configmaps, RBAC, pod specs)
  - Kubelet `/configz` on each node (effective merged kubelet config)
  - An optional ephemeral DaemonSet for host-side checks (file modes/owners under `/etc/kubernetes`, kubelet config file on disk, sshd state), deployed and torn down per scan
- Outputs results in three formats:
  - `table`: human-readable terminal output (default)
  - `json`: machine-readable for pipelines
  - `ckl`: DISA Checklist format, opens directly in STIG Viewer 2.x
- Filters by severity: `CAT_I`, `CAT_II`, `CAT_III`

---

## What it explicitly does not do

These are deliberate non-goals:

- **No remediation.** KubeSTIG never modifies your workloads or cluster configuration. (The optional `--with-node-agent` mode creates and then deletes an ephemeral, self-cleaning DaemonSet + ConfigMap for host-side checks, nothing else.) Use [ansible-lockdown](https://github.com/ansible-lockdown) or your own change management to fix findings.
- **No CIS Benchmark.** Use [Kube-Bench](https://github.com/aquasecurity/kube-bench) for CIS. The two tools sit side-by-side, scoped to different standards.
- **No host OS scanning.** The Linux STIG belongs to OpenSCAP or eSTIG. KubeSTIG only evaluates the Kubernetes layer.
- **No continuous monitoring.** It's a point-in-time scan invoked from CI, on-demand, or before a cluster crosses an enclave boundary.

---

## Quick start

```bash
# Build (Go 1.25+)
make linux

# Or download a prebuilt binary from the GitHub Releases page

# Scan the cluster pointed at by ~/.kube/config
./kubestig scan

# Scan with host-level checks (deploys + cleans up an ephemeral DaemonSet)
./kubestig scan --with-node-agent

# Output a CKL file for STIG Viewer / eMASS upload
./kubestig scan --with-node-agent \
  --output ckl \
  --hostname my-cluster \
  --host-ip 10.0.1.10 \
  > my-cluster.ckl

# Filter to Category I findings only
./kubestig scan --severity CAT_I

# JSON for pipelines
./kubestig scan --output json | jq '.[] | select(.status == "fail")'
```

For clusters whose kubelet serving certificate lacks IP SANs (the kubeadm default without `serverTLSBootstrap`), pass `--insecure-kubelet` to read `/configz` directly from the kubelet socket. The tool reports which findings were evaluated in this mode so reviewers know not to trust the scan path blindly.

---

## Output: the CKL file

The `.ckl` (DISA Checklist) format is what STIG Viewer, eMASS, and most DoD compliance pipelines consume. KubeSTIG produces a fully-populated CKL: each evaluated V-ID has its status (`NotAFinding`, `Open`, `NotApplicable`, `Not_Reviewed`), the actual evidence the scanner gathered, and the unmodified Fix Text from DISA so whoever reads the report knows how to remediate.

Open the resulting CKL in STIG Viewer 2.x and it looks identical to what an analyst would have produced manually, except automated, reproducible, and tied to a specific cluster state.

---

## Status

**Pre-1.0, internal use.** The tool works against kubeadm-provisioned clusters running Kubernetes 1.28+ on Rocky/RHEL 8. STIG content is current as of v2r5 (released 2024). See `UPDATING.md` for the procedure when DISA publishes a new revision.

Build instructions, CI integration, and the GitLab Runner setup that produces release binaries: see `run-compile.md`.

---

## License

Apache 2.0. See `LICENSE`.
