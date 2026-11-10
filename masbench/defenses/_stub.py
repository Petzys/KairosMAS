"""Base for adapters that are laid out but not ported yet."""
from __future__ import annotations

from typing import Any

from masbench.runner.defense import Defense


class NotPorted(Defense):
    """Declares which hooks the adapter will use; refuses to run."""

    run_id = ""
    hooks: tuple[str, ...] = ()

    def __init__(self, **options: Any) -> None:
        raise NotImplementedError(
            f"the `{self.name}` adapter ({self.run_id}) is not ported yet; see its README.md "
            f"for the hooks it uses ({', '.join(self.hooks)})")
