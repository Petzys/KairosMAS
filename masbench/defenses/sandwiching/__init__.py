"""Sandwiching (lifted single-agent defense), run R07. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class Sandwiching(NotPorted):
    name = "sandwiching"
    run_id = "R07"
    hooks = ('before_llm',)


DEFENSE = Sandwiching
