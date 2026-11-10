"""SafeFlow, ported (MAS defense), run R25. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class SafeFlow(NotPorted):
    name = "safeflow"
    run_id = "R25"
    hooks = ('after_tool', 'on_receive', 'Message.meta', 'before_tool', 'ctx.llm')


DEFENSE = SafeFlow
