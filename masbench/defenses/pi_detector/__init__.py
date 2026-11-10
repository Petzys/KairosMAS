"""PI detector (lifted single-agent defense), run R05. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class PiDetector(NotPorted):
    name = "pi-detector"
    run_id = "R05"
    hooks = ('after_tool', 'on_receive', 'ctx.llm')


DEFENSE = PiDetector
