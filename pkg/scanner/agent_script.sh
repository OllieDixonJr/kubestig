#!/bin/sh
# KubeSTIG node agent, runs inside a privileged pod on every node.
# Gathers the facts needed to answer node_config findings that aren't
# available via the Kubernetes API, and prints a JSON report between
# well-known markers so the scanner can parse them out of pod logs.
#
# Mounts expected from the DaemonSet:
#   /host/etc-kubernetes       → host /etc/kubernetes       (read-only)
#   /host/var-lib-kubelet      → host /var/lib/kubelet      (read-only)
#   /host/proc                 → host /proc                 (read-only)
#   /host/etc-systemd-system   → host /etc/systemd/system   (read-only)

set -u

HOST_MANIFESTS=/host/etc-kubernetes/manifests
HOST_KUBELET_CFG=/host/var-lib-kubelet/config.yaml
HOST_PROC=/host/proc
HOST_SYSTEMD=/host/etc-systemd-system

# Emit a JSON object describing a file's existence, ownership, and mode.
# Mode is emitted as a string of octal digits (e.g. "644") to avoid
# JSON int-decoding ambiguity, the scanner parses it as octal.
# If missing, emits {"path":..., "exists":false}.
stat_file() {
    path=$1
    if [ -e "$path" ]; then
        stat -c '{"path":"%n","exists":true,"uid":%u,"gid":%g,"mode":"%a"}' "$path" 2>/dev/null \
            || printf '{"path":"%s","exists":true,"uid":-1,"gid":-1,"mode":"000"}' "$path"
    else
        printf '{"path":"%s","exists":false,"uid":-1,"gid":-1,"mode":"000"}' "$path"
    fi
}

# Walk /host/proc and return 0 (true) if any process's comm is "sshd".
sshd_running() {
    for comm in "$HOST_PROC"/[0-9]*/comm; do
        [ -r "$comm" ] || continue
        c=$(cat "$comm" 2>/dev/null)
        [ "$c" = "sshd" ] && return 0
    done
    return 1
}

# Detect whether sshd.service is enabled by looking for its symlink
# under multi-user.target.wants, the systemd enablement convention.
sshd_enabled() {
    [ -e "$HOST_SYSTEMD/multi-user.target.wants/sshd.service" ] && return 0
    return 1
}

# ---- begin report ----
echo '---BEGIN-KUBESTIG-REPORT---'

# Build the report one key at a time so the output is a single JSON blob.
printf '{"kubelet_config":'
stat_file "$HOST_KUBELET_CFG"

printf ',"manifests":['
first=1
if [ -d "$HOST_MANIFESTS" ]; then
    for f in "$HOST_MANIFESTS"/*.yaml "$HOST_MANIFESTS"/*.yml; do
        [ -f "$f" ] || continue
        [ "$first" -eq 1 ] || printf ','
        stat_file "$f"
        first=0
    done
fi
printf ']'

if sshd_running; then running=true; else running=false; fi
if sshd_enabled; then enabled=true; else enabled=false; fi
printf ',"sshd_running":%s,"sshd_enabled":%s}\n' "$running" "$enabled"

echo '---END-KUBESTIG-REPORT---'

# Keep the pod alive so the scanner can read logs on its own schedule.
# The scanner deletes the DaemonSet when it's done, which terminates us.
exec sleep 3600
