"""The KAIROS MAS run viewer: replay a benchmark run graphically.

  python -m kairos.mas.viewer serve evaluation/logs [--port 8765]
      browse every result under a log directory (http://127.0.0.1:8765)

  python -m kairos.mas.viewer export RESULT.json [-o run.html]
      one self-contained HTML file for one run (open it in any browser, share it)

A result recorded with the flight recorder (the default since its introduction)
replays exactly; an older result, or one run with --no-trace, is reconstructed
from its report and transcripts and marked as approximate.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from kairos.mas.viewer.legacy import load_trace

STATIC = Path(__file__).parent / "static" / "index.html"
# The page's slot for an embedded trace (an exported page carries its run in here).
_PLACEHOLDER = '<script id="trace-data" type="application/json">null</script>'


def render_html(trace: dict[str, Any] | None) -> str:
    """The viewer page, with `trace` embedded (None: the page loads runs from the server)."""
    html = STATIC.read_text(encoding="utf-8")
    if trace is None:
        return html
    # "</" inside the JSON would close the <script> element early (a trace holds
    # arbitrary agent text); "<\/" means the same to JSON.
    data = json.dumps(trace, ensure_ascii=False).replace("</", "<\\/")
    assert html.count(_PLACEHOLDER) == 1
    return html.replace(_PLACEHOLDER, f'<script id="trace-data" type="application/json">{data}</script>')


def export(result: str, out: str | None) -> Path:
    """Write one run as a self-contained HTML page (next to the result by default)."""
    trace = load_trace(result)
    path = Path(out) if out else Path(result).with_suffix(".html")
    path.write_text(render_html(trace), encoding="utf-8")
    return path


# --- serve -------------------------------------------------------------------------
class RunIndex:
    """The results under a log directory, summarized (cached by modification time)."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._cache: dict[Path, tuple[float, dict[str, Any] | None]] = {}

    def runs(self) -> list[dict[str, Any]]:
        """One summary per result file (summary.json files and other JSON are skipped)."""
        summaries = []
        for path in sorted(self.root.rglob("*.json")):
            if path.name == "summary.json":
                continue
            mtime = path.stat().st_mtime
            hit = self._cache.get(path)
            if hit is None or hit[0] != mtime:
                hit = (mtime, self._summarize(path))
                self._cache[path] = hit
            if hit[1] is not None:
                summaries.append(hit[1])
        return summaries

    def _summarize(self, p: Path) -> dict[str, Any] | None:
        """What the run list shows of one result; None if the file is not a result."""
        try:
            result = json.loads(p.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(result, dict) or "user_task" not in result or not ("report" in result or "events" in result):
            return None
        relative = p.relative_to(self.root)
        # results are stored as <config tag>/<suite>/<user task>/<file>: group by config and suite
        group = str(relative.parent.parent) if len(relative.parts) > 2 else str(relative.parent)
        return {"path": str(relative), "group": group,
                "suite": result.get("suite"), "user_task": result.get("user_task"),
                "injection_task": result.get("injection_task"), "utility": result.get("utility"),
                "attack_success": result.get("attack_success"),
                "traced": bool(result.get("trace") or result.get("events"))}

    def resolve(self, rel: str) -> Path:
        """The file a page asks for, which must be a JSON file under the log directory
        (a request like `../../etc/passwd` is refused)."""
        path = (self.root / rel).resolve()
        if self.root not in path.parents or path.suffix != ".json":
            raise PermissionError(rel)
        return path


def make_handler(index: RunIndex):
    """The HTTP handler: `/` the page, `/api/runs` the run list, `/api/trace?path=...`
    one run's trace."""
    page = render_html(None).encode()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:          # noqa: N802 - http.server's naming
            url = urlparse(self.path)
            try:
                if url.path in ("/", "/index.html"):
                    self._send(HTTPStatus.OK, page, "text/html; charset=utf-8")
                elif url.path == "/api/runs":
                    self._send(HTTPStatus.OK, json.dumps(index.runs()).encode(), "application/json")
                elif url.path == "/api/trace":
                    relative = parse_qs(url.query).get("path", [""])[0]
                    trace = load_trace(str(index.resolve(relative)))
                    self._send(HTTPStatus.OK, json.dumps(trace, ensure_ascii=False).encode(), "application/json")
                else:
                    self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            except PermissionError:
                self._send(HTTPStatus.FORBIDDEN, b"outside the log directory", "text/plain")
            except Exception as e:          # noqa: BLE001 - report to the page
                self._send(HTTPStatus.INTERNAL_SERVER_ERROR, f"{type(e).__name__}: {e}".encode(), "text/plain")

        def log_message(self, *_: Any) -> None:
            pass

    return Handler


def serve(logdir: str, host: str, port: int) -> None:
    index = RunIndex(Path(logdir))
    server = ThreadingHTTPServer((host, port), make_handler(index))
    print(f"KAIROS MAS viewer: {len(index.runs())} runs under {index.root}\n  http://{host}:{port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kairos.mas.viewer", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="cmd", required=True)
    serve_parser = commands.add_parser("serve", help="browse the results under a log directory")
    serve_parser.add_argument("logdir", nargs="?", default="evaluation/logs")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=int(os.environ.get("KAIROS_VIEWER_PORT", 8765)))
    export_parser = commands.add_parser("export", help="write one run as a self-contained HTML file")
    export_parser.add_argument("result")
    export_parser.add_argument("-o", "--out", default=None)
    args = parser.parse_args(argv)
    if args.cmd == "serve":
        if not Path(args.logdir).is_dir():
            print(f"ERROR: {args.logdir} is not a directory", file=sys.stderr)
            return 2
        serve(args.logdir, args.host, args.port)
    else:
        print(export(args.result, args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
