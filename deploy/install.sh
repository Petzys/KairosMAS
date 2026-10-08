#!/bin/bash
#
# Kairos deploy — installer (monitoring stack, no kairos judge)
# ============================================================
# Installs everything needed to run the observe/enforce monitoring system on a
# fresh Linux host and builds the guest image. Idempotent: skips what's present.
#
#   sudo deploy/install.sh
#
# Installs: python3 + fusepy + mitmproxy, dnsmasq, iproute2/iptables, fuse3,
# cloud-hypervisor + virtiofsd, the microVM kernel, the mitmproxy CA, and builds
# deploy/images/claude-rootfs.ext4 (Alpine 3.22 + Node 22 + Claude Code).
#
# Requires: x86_64, hardware virtualization (/dev/kvm), outbound internet.
#
set -uo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"
IMAGES="$DEPLOY/images"
CH_VERSION="v49.0.0"
KERNEL_URL="https://github.com/cloud-hypervisor/linux/releases/download/ch-release-v6.2-20240908/vmlinux"
CH_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static"

say(){ echo -e "\033[1;36m[install]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[install] WARN:\033[0m $*"; }
die(){ echo -e "\033[1;31m[install] ERROR:\033[0m $*"; exit 1; }

[ "$EUID" -eq 0 ] || die "run as root (sudo)"
[ "$(uname -m)" = "x86_64" ] || die "x86_64 required (got $(uname -m))"
mkdir -p "$IMAGES"

# ---- 1. base packages via the system package manager ----
if command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v apt-get >/dev/null 2>&1; then PM=apt-get
else PM=""; warn "no dnf/apt found — install base deps manually"; fi

say "installing base packages ($PM)..."
if [ "$PM" = dnf ]; then
    dnf install -y python3 python3-pip dnsmasq iproute iptables fuse3 wget tar xz \
        e2fsprogs util-linux virtiofsd 2>/dev/null || warn "some dnf packages missing (continuing)"
elif [ "$PM" = apt-get ]; then
    apt-get update -y
    apt-get install -y python3 python3-pip dnsmasq iproute2 iptables fuse3 wget tar xz-utils \
        e2fsprogs util-linux virtiofsd 2>/dev/null || warn "some apt packages missing (continuing)"
fi

# ---- 2. python libs (host side): fusepy + mitmproxy ----
say "installing python deps (fusepy, mitmproxy)..."
python3 -c "import fuse" 2>/dev/null || pip3 install --quiet fusepy || warn "fusepy install failed"
command -v mitmdump >/dev/null 2>&1 || pip3 install --quiet mitmproxy || warn "mitmproxy install failed"

# ---- 3. cloud-hypervisor ----
if command -v cloud-hypervisor >/dev/null 2>&1; then
    say "cloud-hypervisor present: $(command -v cloud-hypervisor)"
else
    say "downloading cloud-hypervisor ${CH_VERSION}..."
    if wget -q -O /usr/local/bin/cloud-hypervisor "$CH_URL"; then
        chmod +x /usr/local/bin/cloud-hypervisor
    else
        warn "download failed — get cloud-hypervisor manually from github.com/cloud-hypervisor/cloud-hypervisor/releases"
    fi
fi

# ---- 4. virtiofsd ----
if command -v virtiofsd >/dev/null 2>&1 || [ -x /usr/local/bin/virtiofsd ]; then
    say "virtiofsd present"
else
    warn "virtiofsd not found. Install via your package manager (dnf/apt install virtiofsd)"
    warn "or download the rust virtiofsd from gitlab.com/virtio-fs/virtiofsd/-/releases to /usr/local/bin/"
fi

# ---- 5. microVM kernel ----
if [ -f "$IMAGES/vmlinux-6.2.0" ]; then
    say "kernel present: images/vmlinux-6.2.0"
else
    say "downloading microVM kernel..."
    wget -q -O "$IMAGES/vmlinux-6.2.0" "$KERNEL_URL" || warn "kernel download failed ($KERNEL_URL)"
fi

# ---- 6. mitmproxy CA (needed before building the rootfs trust store) ----
if [ ! -f /root/.mitmproxy/mitmproxy-ca-cert.pem ]; then
    say "generating mitmproxy CA..."
    timeout 8 mitmdump -p 18080 >/dev/null 2>&1 || true
fi
[ -f /root/.mitmproxy/mitmproxy-ca-cert.pem ] && say "mitmproxy CA ready" || warn "mitmproxy CA not generated"

# ---- 7. build the guest rootfs ----
if [ -f "$IMAGES/claude-rootfs.ext4" ]; then
    say "guest rootfs present: images/claude-rootfs.ext4 (delete it to rebuild)"
else
    say "building guest rootfs (Alpine 3.22 + Node 22 + Claude Code)..."
    bash "$DEPLOY/guest/build_rootfs.sh" || die "rootfs build failed"
fi

# ---- 8. sanity checks ----
say "checks:"
[ -e /dev/kvm ] && echo "  /dev/kvm            OK" || warn "  /dev/kvm MISSING — enable hardware/nested virtualization"
grep -qE 'vmx|svm' /proc/cpuinfo && echo "  virtualization ext  OK" || warn "  no VT-x/AMD-V flags"
for b in cloud-hypervisor virtiofsd mitmdump python3 dnsmasq; do
    command -v "$b" >/dev/null 2>&1 && echo "  $b OK" || warn "  $b missing"
done
python3 -c "import fuse" 2>/dev/null && echo "  fusepy             OK" || warn "  fusepy missing"
[ -f "$IMAGES/vmlinux-6.2.0" ] && echo "  kernel image        OK" || warn "  kernel image missing"
[ -f "$IMAGES/claude-rootfs.ext4" ] && echo "  guest rootfs        OK" || warn "  guest rootfs missing"

say "done. Next:  sudo KAIROS_FS_SEED=/path/to/project deploy/run.sh   (then open http://localhost:8090)"
say "See deploy/docs/USAGE.md for usage and deploy/docs/INTERNAL.md for internals."
