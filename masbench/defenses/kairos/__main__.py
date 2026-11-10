"""Regenerate the KAIROS MAS layouts and policies for every masbench scenario with a KAIROS suite policy."""
from masbench.defenses.kairos.policies import write_all

if __name__ == "__main__":
    print(f"{len(write_all())} files written to masbench/defenses/kairos/data/")
