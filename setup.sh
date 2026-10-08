#!/usr/bin/env bash
#
# One-time setup: benchmarks at their pinned commits, then the two Python environments with
# the exact package versions of the runs (env/). Needs git, uv and Python 3.12.
#
#   .venv        everything except CaMeL
#   .venv-camel  CaMeL (it pins dependency versions that conflict with the main environment)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
bash benchmarks/setup_benchmarks.sh

# env/requirements-*.txt are complete freezes of the environments the runs used, so they are
# installed exactly as recorded (--no-deps) rather than re-resolved: the main environment holds
# a package whose declared requirements its recorded neighbours do not satisfy, which a resolver
# rejects although the environment ran every reported experiment.
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python --no-deps -r env/requirements-main.txt
uv pip install --python .venv/bin/python --no-deps -e benchmark/agentdojo -e .

uv venv .venv-camel --python 3.12 --seed
uv pip install --python .venv-camel/bin/python --no-deps -r env/requirements-camel.txt
uv pip install --python .venv-camel/bin/python --no-deps -e benchmark/autodojo/agentdojo

[ -f .env ] || cp .env.example .env
echo "setup done; put your API keys into .env, then: set -a; . ./.env; set +a"
