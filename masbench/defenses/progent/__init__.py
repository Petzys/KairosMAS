"""Progent (lifted single-agent defense), run R08. Not ported yet; see README.md."""
from masbench.defenses._stub import NotPorted


class Progent(NotPorted):
    name = "progent"
    run_id = "R08"
    hooks = ('before_tool', 'before_llm', 'ctx.llm')


DEFENSE = Progent
