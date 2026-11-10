"""CaMeL per agent (lifted single-agent defense), run R09. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class CaMeL(NotPorted):
    name = "camel"
    run_id = "R09"
    hooks = ('make_brain', 'AgentHandle')


DEFENSE = CaMeL
