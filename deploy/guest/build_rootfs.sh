#!/bin/bash
#
# Build the Claude Code guest rootfs from scratch  (M1)
# =====================================================
# Clean, reproducible build of an Alpine 3.22 root filesystem for the microVM.
# Alpine 3.22 ships Node.js 22 natively (Claude Code requires >=22), so there is
# no patched-in runtime — everything comes from apk/npm.
#
# Produces: deploy/images/claude-rootfs.ext4  (ext4, init=/init)
# Kernel is separate: the prebuilt Cloud Hypervisor vmlinux (virtio built-in).
#
# Contents:
#   * python3            — runs the PTY<->vsock bridge
#   * nodejs 22 + npm    — runtime for Claude Code
#   * @anthropic-ai/claude-code (global)  — the real, unmodified agent
#   * git, ripgrep, bash, curl, coreutils — a realistic agent workspace
#   * unprivileged `agent` user (uid/gid 1000)
#   * static network 192.168.100.2 behind the host bridge/NAT
#   * /opt/bridge/{pty_vsock_bridge.py,smoke_cmd.sh} + /init
#
set -euo pipefail

ALPINE_VER="3.22"
ALPINE_REL="3.22.5"
ARCH="x86_64"
MIRROR="https://dl-cdn.alpinelinux.org/alpine"
IMG_SIZE_MB=2048

DEPLOY="$(cd "$(dirname "$0")/.." && pwd)"
GUEST="${DEPLOY}/guest"
IMG="${DEPLOY}/images/claude-rootfs.ext4"
BUILD="${DEPLOY}/images/_build_rootfs"

if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi
for c in wget tar mkfs.ext4 mount chroot; do
    command -v "$c" >/dev/null || { echo "missing tool: $c"; exit 1; }
done

echo "[build] === Alpine ${ALPINE_REL} Claude Code guest rootfs ==="
rm -rf "$BUILD"; mkdir -p "$BUILD/rootfs"
ROOT="$BUILD/rootfs"

# ---- 1. fetch + extract minirootfs ----
TARBALL="$BUILD/minirootfs.tar.gz"
URL="${MIRROR}/v${ALPINE_VER}/releases/${ARCH}/alpine-minirootfs-${ALPINE_REL}-${ARCH}.tar.gz"
echo "[build] downloading ${URL##*/}"
wget -q -O "$TARBALL" "$URL"
tar -xzf "$TARBALL" -C "$ROOT"

# ---- 2. chroot prep: DNS + bind mounts + repos ----
echo "nameserver 8.8.8.8" > "$ROOT/etc/resolv.conf"
cat > "$ROOT/etc/apk/repositories" <<EOF
${MIRROR}/v${ALPINE_VER}/main
${MIRROR}/v${ALPINE_VER}/community
EOF
mount --bind /proc "$ROOT/proc"
mount --bind /sys  "$ROOT/sys"
mount --bind /dev  "$ROOT/dev"

# Network channel (M3): install the mitmproxy CA so the guest trusts the
# transparent proxy's MITM certificates. Copied in before the chroot runs
# update-ca-certificates (below), which folds it into the system CA bundle that
# SSL_CERT_FILE / NODE_EXTRA_CA_CERTS point at.
MITM_CA="${MITM_CA:-/root/.mitmproxy/mitmproxy-ca-cert.pem}"
if [ -f "$MITM_CA" ]; then
    mkdir -p "$ROOT/usr/local/share/ca-certificates"
    cp "$MITM_CA" "$ROOT/usr/local/share/ca-certificates/mitmproxy.crt"
    echo "[build] mitmproxy CA staged for guest trust store"
else
    echo "[build] WARN: mitmproxy CA not found ($MITM_CA); run mitmdump once to generate it"
fi

cleanup() {
    umount "$ROOT/proc" 2>/dev/null || true
    umount "$ROOT/sys"  2>/dev/null || true
    umount "$ROOT/dev"  2>/dev/null || true
}
trap cleanup EXIT

# ---- 3. packages + Claude Code + agent user (inside chroot) ----
echo "[build] installing packages + Claude Code..."
chroot "$ROOT" /bin/sh <<'CHROOT'
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
apk update
apk add --no-cache \
    alpine-base busybox-openrc \
    ca-certificates \
    python3 \
    nodejs npm \
    bash git ripgrep curl \
    coreutils util-linux findutils grep sed shadow \
    iproute2
update-ca-certificates 2>/dev/null || true

# Claude Code (global -> /usr/bin/claude), running on Alpine's Node 22
npm install -g @anthropic-ai/claude-code
echo "INSTALLED node=$(node --version) npm=$(npm --version) claude=$(claude --version 2>&1 | head -1)"

# unprivileged agent user (uid/gid 1000 to match the bridge)
addgroup -g 1000 agent
adduser -D -u 1000 -G agent -h /home/agent -s /bin/bash agent
mkdir -p /home/agent/.claude /home/agent/work
chown -R agent:agent /home/agent
CHROOT

# ---- 4. runtime config: hostname, network, DNS, TLS env ----
echo "[build] writing runtime config..."
echo "agent-sandbox" > "$ROOT/etc/hostname"
cat > "$ROOT/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   agent-sandbox
EOF

# static IP behind the host bridge (used if /etc/network/interfaces is honored;
# the bridge is also brought up explicitly by /init)
cat > "$ROOT/etc/network/interfaces" <<EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.100.2
    netmask 255.255.255.0
    gateway 192.168.100.1
EOF

# guest DNS -> host resolver on the bridge
echo "nameserver 192.168.100.1" > "$ROOT/etc/resolv.conf"

# system-wide CA + Node CA env (proxy CA slots in here from M4)
cat >> "$ROOT/etc/profile" <<'EOF'
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
EOF

# ---- 5. guest agent files ----
echo "[build] installing bridge + init + smoke payload..."
mkdir -p "$ROOT/opt/bridge"
install -m 0755 "$GUEST/pty_vsock_bridge.py" "$ROOT/opt/bridge/pty_vsock_bridge.py"
install -m 0755 "$GUEST/smoke_cmd.sh"        "$ROOT/opt/bridge/smoke_cmd.sh"
install -m 0755 "$GUEST/serial_smoke.sh"     "$ROOT/opt/bridge/serial_smoke.sh"
install -m 0755 "$GUEST/init"                "$ROOT/init"

# Default interactive command WITH flags (init reads this file; see init step 2).
# --dangerously-skip-permissions: KAIROS is the sole external gate (plan 1.2), so
#   Claude Code must not also prompt for permission on every tool call.
# You can still change the model live at runtime with the /model slash command;
# add --model <id> here if you want a fixed default instead.
mkdir -p "$ROOT/etc/kairos"
BRIDGE_CMD_DEFAULT="${BRIDGE_CMD_DEFAULT:-claude --dangerously-skip-permissions}"
printf '%s\n' "$BRIDGE_CMD_DEFAULT" > "$ROOT/etc/kairos/bridge_cmd"
echo "[build] default bridge command: $BRIDGE_CMD_DEFAULT"

cleanup
trap - EXIT

# ---- 6. pack into an ext4 image ----
echo "[build] creating ext4 image (${IMG_SIZE_MB}MB)..."
dd if=/dev/zero of="$IMG" bs=1M count="$IMG_SIZE_MB" status=none
mkfs.ext4 -q -F -L claude-rootfs "$IMG"
MP="$(mktemp -d)"
mount -o loop "$IMG" "$MP"
cp -a "$ROOT"/. "$MP"/
sync
df -h "$MP" | tail -1
umount "$MP"; rmdir "$MP"

rm -rf "$BUILD"
echo "[build] done. Image: $IMG"
