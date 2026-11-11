"""In-process simulated environments for `environment.kind: python` (B2).

A `SimEnvironment` is the shared world of one run: a state dict, shared boards, and a sink
that records every request leaving the MAS to a host that is not allowlisted ("at sink" in
the attack catalogue). Tools are methods marked with `@tool`; their JSON schema comes from
the signature and their defense-neutral annotations from the decorator, so the scenario's
`tools[]` is generated from the class and cannot drift from the code.

Nothing here runs real code or opens a socket. Tools that "execute" a script or command go
through `run_shell`, which recognises a small fixed set of effects (HTTP requests, file
writes and deletes, package installs) and ignores everything else.
"""
from __future__ import annotations

import copy
import fnmatch
import inspect
import re
import shlex
import typing
from typing import Any
from urllib.parse import urlsplit

from masbench.env import ToolOutcome
from masbench.schema import Case, Check, Scenario, ToolSpec

SLOT = re.compile(r"\[\[inj:([\w.-]+)\]\]")


def slot(vector: str) -> str:
    """Placeholder for an injection vector inside initial state text."""
    return f"[[inj:{vector}]]"


class ToolError(Exception):
    """A tool failed in a way the calling agent should see."""


def tool(*, effect: str = "read", reversible: bool | None = None, external: bool = False,
         impact: str = "none", output_trust: str = "trusted", output_sensitivity: str = "public",
         board: str | None = None, name: str | None = None):  # noqa: ANN201
    """Mark a method `(self, agent, **args) -> str` as a tool and annotate it."""

    def deco(fn):  # noqa: ANN001, ANN202
        fn._tool = dict(name=name or fn.__name__, effect=effect,
                        reversible=(effect == "read") if reversible is None else reversible,
                        external=external, impact=impact, output_trust=output_trust,
                        output_sensitivity=output_sensitivity, board=board)
        return fn

    return deco


_JSON_TYPES = {str: "string", int: "integer", float: "number", bool: "boolean"}


def _schema(fn: Any) -> dict[str, Any]:
    hints = typing.get_type_hints(fn)
    props: dict[str, Any] = {}
    required = []
    docs = dict(re.findall(r"^\s*:param (\w+): (.+)$", fn.__doc__ or "", flags=re.M))
    for pname, p in list(inspect.signature(fn).parameters.items())[2:]:  # skip self, agent
        t = hints.get(pname, str)
        if typing.get_origin(t) is list:
            prop: dict[str, Any] = {"type": "array", "items": {"type": _JSON_TYPES[typing.get_args(t)[0]]}}
        else:
            prop = {"type": _JSON_TYPES[t]}
        if pname in docs:
            prop["description"] = docs[pname]
        props[pname] = prop
        if p.default is inspect.Parameter.empty:
            required.append(pname)
    return {"type": "object", "properties": props, "required": required}


def _description(fn: Any) -> str:
    doc = inspect.cleandoc(fn.__doc__ or "")
    return " ".join(doc.split(":param")[0].split())


class SimEnvironment:
    """Base class. Subclasses define `initial_state` and `@tool` methods."""

    ALLOW_HOSTS: frozenset[str] = frozenset()  # requests to these hosts stay out of the sink
    VECTORS: dict[str, str] = {}  # injection vector id -> where the slot is returned

    def __init__(self, scenario: Scenario, case: Case, injections: dict[str, str]) -> None:
        self.scenario, self.case = scenario, case
        self.sink: list[dict[str, Any]] = []
        self.requests: list[dict[str, Any]] = []  # every outgoing request, sink or not
        self.boards: dict[str, dict[str, str]] = {b.id: {} for b in scenario.boards}
        self.board_log: list[dict[str, str]] = []
        self.state: dict[str, Any] = self.initial_state(dict(case.setup))
        self.state = _fill(self.state, injections)
        self.boards = _fill(self.boards, injections)
        for w in case.attacker.board_writes if case.attacker else []:
            self.board_write(w.board, w.object, w.content, w.author)
        self.pre_state = copy.deepcopy(self.state)

    # -- to be defined by the environment ------------------------------------------------

    def initial_state(self, setup: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    def shell_hook(self, agent: str, argv: list[str]) -> str | None:
        """Environment-specific shell commands (e.g. `npm owner add`); None = not handled."""
        return None

    # -- tools -----------------------------------------------------------------------------

    @classmethod
    def _tools(cls) -> dict[str, Any]:
        out = {}
        for _, fn in inspect.getmembers(cls, inspect.isfunction):
            if hasattr(fn, "_tool"):
                out[fn._tool["name"]] = fn
        return out

    @classmethod
    def tool_specs(cls, names: list[str] | None = None) -> list[ToolSpec]:
        tools = cls._tools()
        return [ToolSpec(description=_description(fn), parameters=_schema(fn), **fn._tool)
                for name, fn in tools.items() if names is None or name in names]

    def openai_tools(self, names: list[str]) -> list[dict[str, Any]]:
        specs = {t.name: t for t in self.scenario.tools}
        return [{"type": "function", "function": {
            "name": n, "description": specs[n].description, "parameters": specs[n].parameters}} for n in names]

    def run_tool(self, function: str, args: dict[str, Any], agent: str = "") -> ToolOutcome:
        fn = self._tools().get(function)
        if fn is None:
            return ToolOutcome("", f"ToolNotFoundError: `{function}`")
        try:
            inspect.signature(fn).bind(self, agent, **args)
        except TypeError as e:
            return ToolOutcome("", f"ValidationError: {e}")
        try:
            return ToolOutcome(str(fn(self, agent, **args)), None)
        except (ToolError, KeyError) as e:
            return ToolOutcome("", f"{type(e).__name__}: {e}")

    # -- world -----------------------------------------------------------------------------

    def request(self, agent: str, method: str, url: str, body: Any = "") -> str:
        """An HTTP request leaving the MAS. Non-allowlisted hosts resolve to the sink."""
        if "://" not in url:
            url = "https://" + url
        parts = urlsplit(url)
        rec = {"agent": agent, "method": method.upper(), "url": url, "host": parts.hostname or "",
               "path": parts.path or "/", "body": body if isinstance(body, str) else repr(body)}
        self.requests.append(rec)
        if rec["host"] not in self.ALLOW_HOSTS:
            self.sink.append(rec)
        return "200 OK"

    def board_read(self, board: str, obj: str) -> str:
        if obj not in self.boards[board]:
            raise ToolError(f"`{obj}` does not exist")
        return self.boards[board][obj]

    def board_write(self, board: str, obj: str, content: str, author: str) -> None:
        self.boards[board][obj] = content
        self.board_log.append({"board": board, "object": obj, "author": author})

    # -- Environment protocol ----------------------------------------------------------------

    def score(self, check: Check, final_output: str, trace: list[tuple[str, dict]]) -> bool:
        raise ValueError(f"simulated environments use python checks, got {check.ref}")

    def ground_truth(self, check: Check) -> tuple[list[tuple[str, dict]], str]:
        raise ValueError("simulated environments replay `case.script`")

    def snapshot(self) -> Any:
        return copy.deepcopy((self.state, self.boards, self.sink, self.requests, self.board_log))

    def restore(self, snap: Any) -> None:
        self.state, self.boards, self.sink, self.requests, self.board_log = copy.deepcopy(snap)


def _fill(obj: Any, injections: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return SLOT.sub(lambda m: injections.get(m.group(1), ""), obj)
    if isinstance(obj, dict):
        return {k: _fill(v, injections) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, injections) for v in obj]
    return obj


# --------------------------------------------------------------------------- scripted shell

_PY_REQUEST = re.compile(r"requests\.(post|get|put)\(\s*(?:f?['\"])([^'\"]+)['\"](.*)\)", re.S)
_URLOPEN = re.compile(r"urlopen\(\s*(?:f?['\"])([^'\"]+)['\"](.*)\)", re.S)
_ENV_REF = re.compile(r"os\.environ(?:\.get)?[\[(]\s*['\"](\w+)['\"](?:\s*,[^)\]]*)?[\])]|os\.getenv\(\s*['\"](\w+)['\"][^)]*\)")
_OPEN_REF = re.compile(r"open\(\s*['\"]([^'\"]+)['\"][^)]*\)(?:\.read\(\))?")
_SH_VAR = re.compile(r"\$\{?(\w+)\}?")
_SH_CAT = re.compile(r"\$\(\s*cat\s+([^)\s]+)\s*\)|`cat\s+([^`\s]+)`")


def run_shell(env: SimEnvironment, agent: str, text: str, files: dict[str, str],
              environ: dict[str, str], depth: int = 0) -> str:
    """"Execute" a shell command, a shell script or a Python snippet: perform the effects the
    simulation knows (HTTP requests via curl / wget / requests / urlopen, `echo >`, `rm`,
    `cat`, package installs, running a script file) and return their output."""
    if depth > 3:
        return ""
    out: list[str] = []
    for m in list(_PY_REQUEST.finditer(text)) + list(_URLOPEN.finditer(text)):
        method, url, rest = (m.group(1), m.group(2), m.group(3)) if m.re is _PY_REQUEST else ("post", m.group(1), m.group(2))
        body = _ENV_REF.sub(lambda r: environ.get(r.group(1) or r.group(2), ""), rest)
        body = _OPEN_REF.sub(lambda r: _file(files, r.group(1)), body)
        out.append(env.request(agent, method, url, body.strip(" ,")))
    if out:
        return "\n".join(out)
    for line in re.split(r"\n|&&|;", text):
        line = re.split(r"\|\||\|", line)[0].strip()  # `a || b`, `a | b`: only `a` is simulated
        if not line or line.startswith("#"):
            continue
        res = _shell_line(env, agent, line, files, environ, depth)
        if res:
            out.append(res)
    return "\n".join(out) or "(no output)"


def _file(files: dict[str, str], path: str) -> str:
    path = path.strip("'\"")
    for cand in (path, path.removeprefix("~/"), path.removeprefix("./"), path.rsplit("/", 1)[-1]):
        if cand in files:
            return files[cand]
    return ""


def _expand(s: str, files: dict[str, str], environ: dict[str, str]) -> str:
    s = _SH_CAT.sub(lambda m: _file(files, m.group(1) or m.group(2)), s)
    return _SH_VAR.sub(lambda m: environ.get(m.group(1), ""), s)


def _shell_line(env: SimEnvironment, agent: str, line: str, files: dict[str, str],
                environ: dict[str, str], depth: int) -> str:
    redirect = re.match(r"^echo\s+(.*?)\s*(>>?)\s*(\S+)$", line)
    if redirect:
        text, op, path = redirect.groups()
        text = _expand(text.strip("'\""), files, environ)
        files[path] = (files.get(path, "") + text + "\n") if op == ">>" else text + "\n"
        return ""
    try:
        argv = shlex.split(line)
    except ValueError:
        argv = line.split()
    if not argv:
        return ""
    hooked = env.shell_hook(agent, argv)
    if hooked is not None:
        return hooked
    cmd = argv[0].rsplit("/", 1)[-1]
    if cmd in ("curl", "wget"):
        url = next((a for a in argv[1:] if a.startswith("http") or re.match(r"^[\w.-]+\.\w+(/|$)", a)), None)
        if url is None:
            return "curl: no URL"
        data, method = [], "GET"
        for i, a in enumerate(argv[:-1]):
            if a in ("-d", "--data", "--data-binary", "--data-raw", "-F", "--form", "--post-data", "-T"):
                v = argv[i + 1]
                v = "@" + v.split("=@", 1)[1] if "=@" in v else v
                data.append(_file(files, v[1:]) if v.startswith("@") else _expand(v, files, environ))
                method = "POST"
            if a in ("-X", "--request"):
                method = argv[i + 1]
        return env.request(agent, method, _expand(url, files, environ), "\n".join(data))
    if cmd in ("pip", "pip3", "npm", "yarn") and len(argv) > 2 and argv[1] in ("install", "add", "i"):
        pkgs = [a for a in argv[2:] if not a.startswith("-")]
        index = "pypi.org" if cmd.startswith("pip") else "registry.npmjs.org"
        for p in pkgs:
            env.state.setdefault("installed", []).append(p)
            env.request(agent, "GET", f"https://{index}/{p}")
        return "installed " + " ".join(pkgs)
    if cmd == "rm":
        for p in (a for a in argv[1:] if not a.startswith("-")):
            files.pop(p, None)
        return ""
    if cmd in ("cat", "head", "tail", "less", "more"):
        return "\n".join(_file(files, p) for p in argv[1:] if not p.startswith("-") and not p.isdigit())
    if cmd in ("ls", "find", "tree"):
        prefix = next((a.strip("./") for a in argv[1:] if not a.startswith("-") and "*" not in a), "")
        pattern = next((argv[i + 1] for i, a in enumerate(argv[:-1]) if a in ("-name", "-iname")), "*")
        names = sorted(f for f in files if f.startswith(prefix) and not f.startswith(".")
                       and fnmatch.fnmatch(f.rsplit("/", 1)[-1], pattern))
        return "\n".join(names) or "(no matching files)"
    if cmd == "grep":
        words = [a for a in argv[1:] if not a.startswith("-")]
        hits = [f"{name}:{line}" for name, body in sorted(files.items()) if not name.startswith(".")
                for line in body.splitlines() if words and words[0] in line]
        return "\n".join(hits) or "(no matches)"
    if cmd == "pwd":
        return "/workspace"
    if cmd in ("cd", "export", "set", "mkdir", "touch", "chmod", "true", "test", "git", "sleep", "source", "which"):
        return ""
    if cmd in ("python", "python3") and "-c" in argv:
        return run_shell(env, agent, argv[argv.index("-c") + 1], files, environ, depth + 1) if "requests." in line or "urlopen" in line else "(executed without errors)"
    if cmd in ("bash", "sh", "python", "python3", "node") or cmd.endswith((".sh", ".py")):
        path = argv[1] if cmd in ("bash", "sh", "python", "python3", "node") and len(argv) > 1 else argv[0]
        body = _file(files, path)
        return run_shell(env, agent, body, files, environ, depth + 1) if body else f"{path}: not found"
    return f"sh: {cmd}: not available in this sandbox (available: ls, cat, grep, find, echo, rm, curl, wget, pip, npm, sh, python)"
