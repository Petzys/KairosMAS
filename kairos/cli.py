"""KAIROS CLI. Phase 0: `kairos validate <policy.yaml>`."""
from __future__ import annotations

import argparse
import sys

from kairos.policy.parser import PolicyError, load_policy

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="biforst")
    sub = parser.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="parse and validate a policy file")
    v.add_argument("policy", help="path to a YAML policy")

    args = parser.parse_args(argv)
    if args.cmd == "validate":
        try:
            policy = load_policy(args.policy)
        except (PolicyError, NotImplementedError) as exc:
            print(f"invalid: {exc}", file=sys.stderr)
            return 1
        print(f"ok: {policy.context.name} (version {policy.version})")
        return 0
    return 2

if __name__ == "__main__":
    raise SystemExit(main())