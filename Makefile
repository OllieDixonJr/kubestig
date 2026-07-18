BINARY=kubestig
VERSION=0.1.0
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default: build for the host platform
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/kubestig

# Linux x86_64 binary (attach to a GitHub Release; do NOT commit to the repo)
linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY) ./cmd/kubestig

# Windows x86_64 binary (attach to a GitHub Release; do NOT commit to the repo)
windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY).exe ./cmd/kubestig

# Build both release binaries, run this before publishing a GitHub Release
release: linux windows
	@echo ""
	@echo "Release binaries built:"
	@ls -lh $(BINARY) $(BINARY).exe

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux

test:
	go test ./...

.PHONY: build linux windows release clean test
