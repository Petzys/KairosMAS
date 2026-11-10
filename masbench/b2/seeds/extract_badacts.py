"""Copy the prompts of the six BAD-ACTS core cases from a checkout of the seed repository
into `badacts.json` (verbatim strings, read with `ast`; nothing from the checkout is run).

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
Path(__file__).with_name("badacts.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
print({k: sorted(v) if isinstance(v, dict) else v for k, v in out.items()})
