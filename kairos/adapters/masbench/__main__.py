"""Regenerate the KAIROS MAS layouts and policies for every masbench scenario with a KAIROS suite policy."""
from kairos.adapters.masbench.policies import write_all

if __name__ == "__main__":
    print(f"{len(write_all())} files written to kairos/adapters/masbench/data/")
