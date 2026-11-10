"""Defense adapters, one directory per defense. `--defense <name>` loads `<name>/` (`-` reads
as `_`) and instantiates its `DEFENSE` class with the `--defense-options`.

The masbench core (everything outside this directory) imports nothing from here; an adapter
imports the core's `masbench.runner.defense` and whatever its defense needs.
"""
