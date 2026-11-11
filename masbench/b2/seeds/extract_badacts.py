"""Copy prompts from a checkout of the BAD-ACTS repository, verbatim (strings are read with
`ast`; nothing from the checkout is run):

* `badacts_agents.json`: the original system prompts and descriptions of the agents, used
  by `masbench/b2/envs/teams.py` for the benign scenarios;
* `badacts_adversarial.json`: the source's prompt templates for an adversarial agent, for
  whoever writes the seed files of B2-01..06 (see README.md). Not used by any code.

    python -I masbench/b2/seeds/extract_badacts.py <path to JNoether/BAD-ACTS at 5ddfcfa>
"""
import ast
import json
import sys
from pathlib import Path

repo = Path(sys.argv[1])
out: dict = {"commit": "5ddfcfa9619d4d0c5b0e2c42fa8ecdce33c3f4f9", "adversarial": {}, "agents": {}}
for node in ast.walk(ast.parse((repo / "agents/adversarial_agent.py").read_text())):
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(v, ast.Constant) and isinstance(v.value, str) and "{goal}" in v.value:
                out["adversarial"][k.value] = v.value


def fold(node: ast.AST) -> str:
    """The string value of a constant expression (literals joined by + or implicit concatenation)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return fold(node.left) + fold(node.right)
    if isinstance(node, ast.JoinedStr):
        return "".join(fold(v) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return fold(node.value)
    if isinstance(node, ast.IfExp):  # `... if safe else ...`: the source's default is safe=False
        return fold(node.orelse)
    return "<<not a constant: " + ast.unparse(node) + ">>"


for path in sorted((repo / "environments").glob("*.py")):
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "AssistantAgent" and node.args:
            kw = {k.arg: fold(k.value) for k in node.keywords if k.arg in ("description", "system_message")}
            out["agents"][f"{path.stem}/{fold(node.args[0])}"] = kw
here = Path(__file__).parent
agents = {"commit": out["commit"], "agents": {k: v for k, v in out["agents"].items() if "Debate" not in k}}
(here / "badacts_agents.json").write_text(json.dumps(agents, indent=1, ensure_ascii=False) + "\n")
(here / "badacts_adversarial.json").write_text(
    json.dumps({"commit": out["commit"], "templates": out["adversarial"]}, indent=1, ensure_ascii=False) + "\n")
print(sorted(agents["agents"]), sorted(out["adversarial"]))
