#!/usr/bin/env python3
"""
Host-side terminal attach  (M1)
===============================

Listens on the host UNIX socket that Cloud Hypervisor uses for guest-initiated
vsock connections (`<vsock-socket>_<port>`), accepts the guest PTY bridge, and
connects it to this terminal.

Two modes:
  (default)  interactive  -- put the local terminal in raw mode and tunnel it to
                             Claude Code inside the VM. Detach with Ctrl-] .
                             Requires a real TTY on stdin.
  --smoke    read-only     -- send a default window size, then print everything
                             the guest emits until it closes (or --timeout).
                             Used for headless validation of the bridge.

Run this *after* (or concurrently with) launching the VM; the guest bridge
retries the connection for ~60s.
"""

import os
import sys
import time
import select
import socket
import argparse

DEFAULT_SOCK = "/tmp/kairos_vsock.sock_5005"


def make_listener(sockpath):
    if os.path.exists(sockpath):
        os.unlink(sockpath)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sockpath)
    os.chmod(sockpath, 0o666)
    srv.listen(1)
    return srv


def accept_guest(srv, wait_s):
    srv.settimeout(wait_s)
    try:
        conn, _ = srv.accept()
        return conn
    except socket.timeout:
        return None


def run_smoke(conn, timeout):
    conn.sendall(b"WINSZ 120 40\n")
    conn.settimeout(timeout)
    out = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = conn.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        out.extend(data)
        if b"===SMOKE_DONE===" in out:
            break
    sys.stdout.write(out.decode(errors="replace"))
    sys.stdout.flush()
    return b"===SMOKE_DONE===" in out


def run_interactive(conn):
    import tty
    import termios

    cols, rows = 120, 40
    try:
        sz = os.get_terminal_size()
        cols, rows = sz.columns, sz.lines
    except OSError:
        pass
    conn.sendall(b"WINSZ %d %d\n" % (cols, rows))

    sys.stdout.write("\r\n[attach] connected to guest — Ctrl-] to detach\r\n")
    sys.stdout.flush()

    stdin_fd = sys.stdin.fileno()
    old = termios.tcgetattr(stdin_fd)
    tty.setraw(stdin_fd)
    try:
        fds = [stdin_fd, conn]
        while True:
            r, _, _ = select.select(fds, [], [])
            if stdin_fd in r:
                data = os.read(stdin_fd, 65536)
                if not data or b"\x1d" in data:   # Ctrl-] detaches
                    break
                conn.sendall(data)
            if conn in r:
                data = conn.recv(65536)
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
    finally:
        termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old)
        sys.stdout.write("\r\n[attach] detached\r\n")
        sys.stdout.flush()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", default=DEFAULT_SOCK)
    ap.add_argument("--smoke", action="store_true", help="headless read-only validation")
    ap.add_argument("--wait", type=float, default=90.0, help="seconds to wait for the guest")
    ap.add_argument("--timeout", type=float, default=40.0, help="smoke read timeout")
    args = ap.parse_args()

    srv = make_listener(args.sock)
    print(f"[attach] listening on {args.sock} (waiting up to {args.wait:.0f}s for guest)...",
          flush=True)
    conn = accept_guest(srv, args.wait)
    if conn is None:
        print("[attach] timed out waiting for guest bridge", file=sys.stderr)
        return 2
    print("[attach] guest bridge connected", flush=True)

    try:
        if args.smoke:
            ok = run_smoke(conn, args.timeout)
            return 0 if ok else 3
        run_interactive(conn)
        return 0
    finally:
        conn.close()
        srv.close()
        if os.path.exists(args.sock):
            os.unlink(args.sock)


if __name__ == "__main__":
    sys.exit(main())
