#!/usr/bin/env python3
"""
Guest-side PTY <-> vsock bridge  (M1)
=====================================

Runs inside the microVM. Connects OUT to the host reference monitor over
virtio-vsock, spawns an interactive command (default: `claude`) on a
pseudo-terminal, and pumps bytes bidirectionally so the operator's terminal on
the host drives the process running inside the guest.

Why a PTY: the whole point of the real system (REAL_SYSTEM_PLAN.md 1.2) is that
the guest runs a *real, unmodified* agent. Claude Code is a full-screen TUI that
needs a controlling terminal, so we give it one and tunnel it over vsock rather
than modifying the agent.

Connection model (matches the prototype): the guest dials the host CID
(VMADDR_CID_HOST = 2) on BRIDGE_PORT. Cloud Hypervisor forwards that to a host
UNIX socket listener at `<vsock-socket>_<port>`. The stream is raw (no vsock
hybrid handshake for guest-initiated connections).

App-level handshake: the host sends one line `WINSZ <cols> <rows>\n` first so we
can size the PTY correctly for the TUI. Everything after that first newline is
raw terminal traffic.
"""

import os
import sys
import pty
import time
import fcntl
import struct
import select
import socket
import termios

HOST_CID = getattr(socket, "VMADDR_CID_HOST", 2)          # host is always CID 2
PORT = int(os.environ.get("BRIDGE_PORT", "5005"))
CMD = os.environ.get("BRIDGE_CMD", "claude")               # what to run on the PTY
# Default: run as root inside the guest. This is a throwaway sandbox VM — in-guest
# privilege is irrelevant to the security model (KAIROS mediates at the VM
# boundary, not via guest uids), and root avoids the virtio-fs/overlay ownership
# mismatch that blocks a non-root user from editing files under /data. Set
# BRIDGE_UID=1000 to drop to the `agent` user instead.
RUN_AS_UID = int(os.environ.get("BRIDGE_UID", "0"))
RUN_AS_GID = int(os.environ.get("BRIDGE_GID", "0"))
HOME = os.environ.get("BRIDGE_HOME", "/home/agent")        # reuse the Claude login state


def log(msg):
    sys.stderr.write(f"[bridge] {msg}\n")
    sys.stderr.flush()


def connect():
    """Dial the host over vsock, retrying while the host attach client comes up."""
    for attempt in range(120):
        try:
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            s.connect((HOST_CID, PORT))
            log(f"connected to host CID {HOST_CID} port {PORT}")
            return s
        except OSError as e:
            if attempt == 0:
                log(f"waiting for host listener ({e}) ...")
            time.sleep(0.5)
    raise SystemExit("bridge: could not reach host vsock after 60s")


def read_handshake(sock):
    """Read the leading 'WINSZ <cols> <rows>\\n' line the host sends first."""
    buf = b""
    sock.settimeout(10)
    try:
        while b"\n" not in buf and len(buf) < 256:
            c = sock.recv(1)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    sock.settimeout(None)
    cols, rows = 160, 50
    line = buf.decode(errors="ignore").strip()
    if line.startswith("WINSZ"):
        try:
            _, c, r = line.split()
            cols, rows = int(c), int(r)
        except ValueError:
            pass
    return cols, rows


def main():
    sock = connect()
    cols, rows = read_handshake(sock)

    pid, master = pty.fork()
    if pid == 0:
        # ---- child: (optionally drop privileges and) exec the command on the PTY ----
        if RUN_AS_UID != 0:
            try:
                os.initgroups("agent", RUN_AS_GID)
            except (KeyError, PermissionError, OSError):
                pass
            try:
                os.setgid(RUN_AS_GID)
                os.setuid(RUN_AS_UID)
            except (PermissionError, OSError):
                pass
            user = "agent"
        else:
            user = "root"
        os.environ["HOME"] = HOME
        os.environ["USER"] = user
        os.environ["LOGNAME"] = user
        # This guest IS a sandbox VM, so allow `--dangerously-skip-permissions`
        # to run even as root (Claude Code honors IS_SANDBOX for exactly this).
        os.environ["IS_SANDBOX"] = "1"
        os.environ.setdefault("TERM", "xterm-256color")
        os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        os.environ["SSL_CERT_FILE"] = "/etc/ssl/certs/ca-certificates.crt"
        os.environ["NODE_EXTRA_CA_CERTS"] = "/etc/ssl/certs/ca-certificates.crt"
        # Work in the monitored /data (virtio-fs) when it is mounted, so the
        # agent's project edits flow through the FS channel; otherwise HOME.
        workdir = "/data" if os.path.ismount("/data") else HOME
        try:
            os.chdir(workdir)
        except OSError:
            os.chdir("/")
        # login shell so profile/env is set up; -c runs the target command
        os.execvp("/bin/sh", ["/bin/sh", "-lc", CMD])
        os._exit(127)

    # ---- parent: size the PTY, then pump PTY <-> vsock ----
    ws = struct.pack("HHHH", rows, cols, 0, 0)
    try:
        fcntl.ioctl(master, termios.TIOCSWINSZ, ws)
    except OSError:
        pass

    fds = [master, sock]
    try:
        while True:
            r, _, _ = select.select(fds, [], [])
            if master in r:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                sock.sendall(data)
            if sock in r:
                try:
                    data = sock.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    break
                os.write(master, data)
    finally:
        try:
            sock.close()
        except OSError:
            pass
        try:
            os.close(master)
        except OSError:
            pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        log("session ended")


if __name__ == "__main__":
    main()
