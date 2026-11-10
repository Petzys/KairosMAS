"""multi-CaMeL (MAS defense), run R24. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class MultiCaMeL(NotPorted):
    name = "multi-camel"
    run_id = "R24"
    hooks = ('make_brain', 'AgentHandle', 'Message.meta', 'supports')


DEFENSE = MultiCaMeL
