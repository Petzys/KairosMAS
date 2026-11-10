"""Spotlighting (lifted single-agent defense), run R06. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class Spotlighting(NotPorted):
    name = "spotlighting"
    run_id = "R06"
    hooks = ('system_prompt', 'after_tool', 'on_receive')


DEFENSE = Spotlighting
