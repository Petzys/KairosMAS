"""BlindGuard, retrained (MAS defense), run R26. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class BlindGuard(NotPorted):
    name = "blindguard"
    run_id = "R26"
    hooks = ('on_message', 'ctx.messages', 'ctx.isolate')


DEFENSE = BlindGuard
