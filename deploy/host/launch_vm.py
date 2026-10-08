#!/usr/bin/env python3
"""
Host-side VM launcher  (M1)
===========================

Boots the Claude Code guest under Cloud Hypervisor with:
  * the prebuilt CH kernel (virtio built-in, no initramfs),
  * the claude-rootfs ext4 disk as /dev/vda (rw, init=/init),
  * a virtio-vsock device (guest CID 3) whose host UNIX socket is
    /tmp/kairos_vsock.sock  -> guest-initiated port N lands on `<sock>_N`,
  * a tap NIC on the host bridge for NAT egress.

Serial console is streamed to a log file so the boot/init trace is inspectable
without stealing the terminal (the terminal is for the vsock PTY session).

This is the M1 wrapper only — no monitor/FUSE/proxy yet (those are M2–M4).
"""

import os
import sys
import time
import shutil
import signal
import argparse
import subprocess

DEPLOY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KERNEL = os.path.join(DEPLOY, "images", "vmlinux-6.2.0")
ROOTFS = os.path.join(DEPLOY, "images", "claude-rootfs.ext4")
VSOCK_SOCK = "/tmp/kairos_vsock.sock"
SERIAL_LOG = "/tmp/kairos_vm_serial.log"


def cleanup_sockets():
    # Only the main vsock socket is owned by Cloud Hypervisor. The per-port
    # backend socket (<sock>_<port>) is created and listened on by the host
    # attach client — never unlink it here or we destroy its listener and the
    # guest's connection is reset (ECONNRESET).
    try:
        os.unlink(VSOCK_SOCK)
    except FileNotFoundError:
        pass


def find_ch():
    # sudo's secure_path usually drops /usr/local/bin where CH is installed, so
    # resolve an absolute path rather than relying on PATH.
    ch = shutil.which("cloud-hypervisor")
    if ch:
        return ch
    for cand in ("/usr/local/bin/cloud-hypervisor", "/usr/bin/cloud-hypervisor"):
        if os.access(cand, os.X_OK):
            return cand
    print("[vm] cloud-hypervisor not found (checked PATH, /usr/local/bin, /usr/bin)",
          file=sys.stderr)
    sys.exit(1)


def build_cmd(memory, cpus, extra_bridge_cmd, fs_mounts, gpu_pci):
    cmdline = "console=ttyS0 root=/dev/vda rw init=/init"
    if extra_bridge_cmd:
        # BRIDGE_CMD is read by init from the kernel cmdline environment via /proc
        cmdline += f" kairos.bridge_cmd={extra_bridge_cmd}"

    # virtio-fs (monitored filesystem channels) attach only when their socket is
    # present, so the VM still boots standalone. virtio-fs (and VFIO) need shared
    # guest memory.
    active = [(tag, sock) for tag, sock in fs_mounts if sock and os.path.exists(sock)]
    shared = active or gpu_pci
    mem = f"size={memory}" + (",shared=on" if shared else "")

    cmd = [
        find_ch(),
        "--kernel", KERNEL,
        "--disk", f"path={ROOTFS}",
        "--cmdline", cmdline,
        "--cpus", f"boot={cpus}",
        "--memory", mem,
        "--vsock", f"cid=3,socket={VSOCK_SOCK}",
        "--net", "tap=tap0,mac=12:34:56:78:9a:bc",
        "--serial", "tty",
        "--console", "off",
    ]
    # Cloud Hypervisor takes MULTIPLE devices as values after a SINGLE flag
    # (e.g. --fs A B), not a repeated flag.
    if active:
        cmd.append("--fs")
        cmd += [f"tag={tag},socket={sock}" for tag, sock in active]
        for tag, sock in active:
            print(f"[vm] virtio-fs attached (tag={tag}, socket={sock})", flush=True)
    # GPU / PCI passthrough (VFIO). Each device must already be bound to vfio-pci
    # on the host and the host must have IOMMU enabled. See deploy/docs/USAGE.md.
    if gpu_pci:
        cmd.append("--device")
        cmd += [f"path=/sys/bus/pci/devices/{pci}" for pci in gpu_pci]
        for pci in gpu_pci:
            print(f"[vm] VFIO passthrough: {pci}", flush=True)
    return cmd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--memory", default="1024M")
    ap.add_argument("--cpus", default="2")
    ap.add_argument("--serial-log", default=SERIAL_LOG)
    ap.add_argument("--foreground", action="store_true",
                    help="stream serial to stdout instead of a log file")
    ap.add_argument("--bridge-cmd", default="",
                    help="override the guest bridge command (default: claude)")
    ap.add_argument("--virtiofs-sock", default="/tmp/kairos_virtiofs.sock",
                    help="virtiofsd socket for /data; --fs added only if it exists")
    ap.add_argument("--fs-tag", default="kairosfs")
    ap.add_argument("--virtiofs-tmp-sock", default="/tmp/kairos_virtiofs_tmp.sock",
                    help="virtiofsd socket for the monitored /tmp channel (optional)")
    ap.add_argument("--gpu-pci", default=os.environ.get("KAIROS_GPU_PCI", ""),
                    help="comma-separated PCI addresses to pass through (VFIO), e.g. 0000:65:00.0")
    args = ap.parse_args()

    for path, what in ((KERNEL, "kernel"), (ROOTFS, "rootfs")):
        if not os.path.exists(path):
            print(f"[vm] missing {what}: {path}", file=sys.stderr)
            return 1

    cleanup_sockets()
    fs_mounts = [(args.fs_tag, args.virtiofs_sock), ("kairostmp", args.virtiofs_tmp_sock)]
    gpu_pci = [p.strip() for p in args.gpu_pci.split(",") if p.strip()]
    cmd = build_cmd(args.memory, args.cpus, args.bridge_cmd, fs_mounts, gpu_pci)
    print("[vm] launching:", " ".join(cmd), flush=True)

    if args.foreground:
        proc = subprocess.Popen(cmd)
    else:
        logf = open(args.serial_log, "wb")
        proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
        print(f"[vm] pid {proc.pid}, serial -> {args.serial_log}", flush=True)

    def _term(*_):
        if proc.poll() is None:
            proc.terminate()
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    try:
        proc.wait()
    finally:
        if proc.poll() is None:
            proc.terminate()
        cleanup_sockets()
    return proc.returncode or 0


if __name__ == "__main__":
    sys.exit(main())
