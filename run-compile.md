# Running a GitLab Runner & Compiling KubeSTIG

This document covers two related tasks:

1. **Setting up a GitLab Runner** so the project's CI pipeline (SAST, future jobs) actually executes.
2. **Compiling KubeSTIG** locally and via CI.

---

## Part 1: Setting Up a GitLab Runner

### What a runner is, briefly

GitLab parses `.gitlab-ci.yml` and queues jobs, but it does not execute them. A **GitLab Runner** is a small daemon that polls GitLab over HTTP, claims pending jobs, executes them in a configured environment (shell, Docker, Kubernetes), and uploads results back. Without at least one runner attached to a project, every pipeline sits in `pending` forever.

### Prerequisites

- A host that can reach the GitLab instance over HTTP/HTTPS (outbound only, the runner never accepts inbound connections).
- A container runtime if using the docker executor, Docker or Podman installed and running.
- `sudo` on the host (the runner installs as a systemd service).
- A GitLab account with at least Maintainer on the target project.

### Step 1: Install the runner

For Rocky Linux 8 / RHEL 8:

```bash
curl -LfsSo /tmp/gitlab-runner.rpm \
  "https://packages.gitlab.com/runner/gitlab-runner/packages/el/8/gitlab-runner-17.5.0-1.x86_64.rpm/download.rpm"
sudo rpm -i /tmp/gitlab-runner.rpm
gitlab-runner --version
```

For Debian/Ubuntu, swap the URL to the `.deb` and use `dpkg -i`. For other platforms, see <https://docs.gitlab.com/runner/install/>.

The RPM creates:
- `/usr/bin/gitlab-runner`: the binary
- `/etc/gitlab-runner/config.toml`: the config (created on first registration)
- A `gitlab-runner` system user
- A systemd unit at `/etc/systemd/system/gitlab-runner.service`

### Step 2: Grant the runner user access to Docker

Skip if using the shell executor. For docker executor:

```bash
sudo usermod -aG docker gitlab-runner
```

### Step 3: Generate a runner authentication token

Two ways. UI:

1. GitLab → project → Settings → CI/CD → Runners → "New project runner"
2. Choose tags, expiration, untagged-jobs preference
3. Copy the `glrt-...` token it displays, it is shown **once**

API (requires a Personal Access Token with `api` scope):

```bash
curl -X POST \
  -H "PRIVATE-TOKEN: <YOUR_PAT>" \
  "http://<GITLAB_HOST>/api/v4/user/runners" \
  -d 'runner_type=project_type' \
  -d 'project_id=<PROJECT_ID>' \
  -d 'description=<DESCRIPTION>' \
  -d 'tag_list=docker,local' \
  -d 'run_untagged=true'
```

The response includes `"token": "glrt-..."`. Save it.

### Step 4: Register the runner

```bash
sudo gitlab-runner register \
  --non-interactive \
  --url "http://<GITLAB_HOST>" \
  --token "<glrt-token-from-step-3>" \
  --executor "docker" \
  --docker-image "alpine:latest" \
  --description "<DESCRIPTION>"
```

This writes the config to `/etc/gitlab-runner/config.toml`. The auth token lives in that file, `chmod 600`, treat it like a secret.

### Step 5: Fix the systemd HOME issue (Rocky/RHEL only)

On some RHEL-family distros, `gitlab-runner` 17.x fails on first start with `FATAL: failed to get user home dir: $HOME is not defined`. Fix with a systemd drop-in:

```bash
sudo mkdir -p /etc/systemd/system/gitlab-runner.service.d
sudo tee /etc/systemd/system/gitlab-runner.service.d/override.conf <<EOF
[Service]
Environment="HOME=/home/gitlab-runner"
EOF
sudo systemctl daemon-reload
```

### Step 6: Start the runner

```bash
sudo systemctl enable --now gitlab-runner
systemctl status gitlab-runner
sudo gitlab-runner verify
```

`verify` should report `is valid` for each registered runner.

### Step 7: Confirm it appears in GitLab

GitLab → project → Settings → CI/CD → Runners. The runner shows up with a green status indicator. Push any change that triggers `.gitlab-ci.yml` and confirm the job moves from `pending` → `running` → `success`.

### Useful day-to-day commands

```bash
sudo gitlab-runner list                    # registered runners
sudo gitlab-runner verify                  # confirm reachability
sudo gitlab-runner unregister --name <n>   # remove a runner
sudo journalctl -u gitlab-runner -f        # tail logs
cat /etc/gitlab-runner/config.toml         # view config (contains tokens)
```

---

## Part 2: Compiling KubeSTIG

### Prerequisites

- Go 1.25 or later (`go version` to check)
- `make`
- For cross-compiling to Windows: nothing extra, Go's stdlib handles it

### Local builds

The `Makefile` at the root of the KubeSTIG directory provides the targets you need.

```bash
cd KubeSTIG/

# Build for the host platform
make build

# Build the Linux x86_64 release binary (committed as KubeSTIG/kubestig)
make linux

# Build the Windows x86_64 release binary (committed as KubeSTIG/kubestig.exe)
make windows

# Build both at once
make release

# Run unit tests
make test

# Remove build artifacts
make clean
```

`make release` prints the file sizes of both binaries on completion.

### What the build does

The `Makefile` invokes:

```bash
go build -ldflags "-X main.version=0.1.0" -o kubestig ./cmd/
```

Cross-compilation is handled by setting `GOOS` and `GOARCH`:

```bash
GOOS=linux   GOARCH=amd64 go build -o kubestig     ./cmd/
GOOS=windows GOARCH=amd64 go build -o kubestig.exe ./cmd/
```

### Building via CI

The repo's `.gitlab-ci.yml` runs the SAST scan automatically on every push to `main`. To add a build job, append to `.gitlab-ci.yml`:

```yaml
build-kubestig:
  stage: test
  image: golang:1.25
  script:
    - cd KubeSTIG
    - go build -o kubestig ./cmd/
  artifacts:
    paths:
      - KubeSTIG/kubestig
    expire_in: 1 week
```

The runner installed in Part 1 will pick up this job and produce `kubestig` as a downloadable artifact under the job page.

### Verifying the binary

After build:

```bash
./kubestig --version           # confirms version string from -ldflags
./kubestig --help              # lists subcommands
sha256sum kubestig             # for hash-based integrity verification
```

---

## Putting it together

The end-to-end flow this document enables:

1. **Set up a runner** (Part 1) on any host that can reach your GitLab instance.
2. **Push to the project**, GitLab queues pipeline jobs.
3. **Runner picks up the job** and executes inside its configured executor.
4. **For KubeSTIG**, the build job (Part 2) produces the `kubestig` binary as a CI artifact.
5. **The SAST job** (already in `.gitlab-ci.yml`) produces `gl-sast-report.json` for cyber review.

Both artifacts are downloadable from the pipeline page in the GitLab UI, or via the API:

```bash
curl -H "PRIVATE-TOKEN: <PAT>" \
  -o artifacts.zip \
  "http://<GITLAB_HOST>/api/v4/projects/<PROJECT_ID>/jobs/<JOB_ID>/artifacts"
```
