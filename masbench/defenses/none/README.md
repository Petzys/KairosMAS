# none (R01, undefended MAS)

The runner's default hooks: nothing is checked, changed or blocked. This is the reference for
utility (Ub) and for the attack success rate without a defense, and the run every B2 case is
validated on before it is frozen.

    python -m masbench.cli run -s 'b2.*' --defense none --repeat 3
