# Building KubeSTIG

KubeSTIG is distributed as source. Clone the repo, build the binary, and scan. The
binary is fully self-contained — the STIG finding definitions and the node-agent
script are embedded at compile time, so you can copy the built `kubestig` anywhere
(a bastion, an air-gapped enclave) without dragging the repo along.

There are two ways to build: with a local Go toolchain, or inside a container if
you don't have (or can't install) Go.

---

## Option 1: Local Go toolchain

### Prerequisites

- Go 1.25 or later (`go version` to check)
- `make`
- For cross-compiling to Windows: nothing extra, Go's stdlib handles it

### Build

```bash
git clone https://github.com/OllieDixonJr/kubestig.git
cd kubestig
make build
```

The `Makefile` provides these targets:

```bash
make build     # Build for the host platform
make linux     # Cross-compile the Linux x86_64 binary
make windows   # Cross-compile the Windows x86_64 binary (kubestig.exe)
make release   # Build both and print their sizes
make test      # Run unit tests
make clean     # Remove build artifacts
```

Built binaries stay in the working tree and are gitignored — never commit them.

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

---

## Option 2: Container build (no Go install)

Any host with Docker or Podman can build without installing Go:

```bash
git clone https://github.com/OllieDixonJr/kubestig.git
cd kubestig

# Podman (the :Z suffix relabels the mount for SELinux hosts like RHEL/Rocky)
podman run --rm -v "$PWD":/src:Z -w /src docker.io/library/golang:1.25 make build

# Docker
docker run --rm -v "$PWD":/src -w /src golang:1.25 make build
```

The binary lands at `./kubestig` on the host, owned by root if your runtime runs
as root — `sudo chown $USER kubestig` if that bothers you.

---

## Verifying the binary

```bash
./kubestig version             # confirms version string from -ldflags
./kubestig --help              # lists subcommands
sha256sum kubestig             # for hash-based integrity verification
```

Then point it at a cluster:

```bash
./kubestig scan                # read-only scan of the cluster in ~/.kube/config
```

See the [README](README.md) for scan options and output formats.
