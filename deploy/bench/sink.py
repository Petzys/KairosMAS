#!/usr/bin/env python3
"""Minimal HTTP sink: binds to the host side of the guest bridge, answers 200 to every
request and records each one as a JSON line. It is the local endpoint of the proxy latency
benchmark (latency.py net) and, being independent of the monitor, a record of what actually
arrived at a destination.

    sudo python3 deploy/bench/sink.py --out /tmp/sink.jsonl

Env:
    KAIROS_SINK_ADDR   bind address (default 192.168.100.1)
    KAIROS_SINK_PORT   bind port    (default 80)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 1 << 20  # 1 MiB is far above anything this scenario sends


class _Sink(BaseHTTPRequestHandler):
    server_version = "kairos-sink/1.0"
    out = None
    lock = threading.Lock()

    def _record(self) -> None:
        try:
            n = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        except ValueError:
            n = 0
        body = self.rfile.read(n) if n else b""
        try:
            text, binary = body.decode("utf-8"), False
        except UnicodeDecodeError:
            text, binary = body[:64].hex(), True
        rec = {
            "ts": round(time.time(), 6),
            "method": self.command,
            # Host header, not the bind address: all three names share one socket,
            # so this is the only thing that says WHICH destination was addressed.
            "host": self.headers.get("Host", ""),
            "path": self.path,
            "client": self.client_address[0],
            "headers": dict(self.headers),
            "body_len": len(body),
            "body": text,
            "body_binary": binary,
        }
        with _Sink.lock:
            _Sink.out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            _Sink.out.flush()
        sys.stderr.write(f"[sink] {self.command} {rec['host']}{self.path} "
                         f"({len(body)} bytes)\n")
        sys.stderr.flush()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _record

    def log_message(self, *_args) -> None:
        pass                                   # stderr line above is the log


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--addr", default=os.environ.get("KAIROS_SINK_ADDR", "192.168.100.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("KAIROS_SINK_PORT", "80")))
    ap.add_argument("--out", required=True, help="JSONL file to append arrivals to")
    a = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(a.out)) or ".", exist_ok=True)
    _Sink.out = open(a.out, "a", buffering=1)
    srv = ThreadingHTTPServer((a.addr, a.port), _Sink)
    sys.stderr.write(f"[sink] listening on {a.addr}:{a.port} -> {a.out}\n")
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _Sink.out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
