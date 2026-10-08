#!/usr/bin/env bash
#
# Fetch the three benchmarks at the exact upstream commits the evaluation used and apply our
# changes to them. Everything lands in benchmark/ (not part of this repository).
#
#   benchmark/agentdojo   AgentDojo  (GPT-4.1 runs: Kairos, undefended agent, strict monitor)
#   benchmark/autodojo    AutoDojo   (its AgentDojo fork runs the comparison defenses, the open-model
#                                     and Qwen3.5 runs, and the AutoDojo attack)
#   benchmark/agentdyn    AgentDyn   (AgentDyn suites, unmodified)
#
# Idempotent: an existing checkout is moved to the pinned commit and the patch is applied once.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p benchmark

fetch() {   # fetch <url> <commit> <dir> [patch]
    local url="$1" sha="$2" dir="$3" patch="${4:-}"
    [ -d "$dir/.git" ] || git clone -q "$url" "$dir"
    git -C "$dir" fetch -q origin "$sha" 2>/dev/null || true
    git -C "$dir" checkout -q "$sha"
    if [ -n "$patch" ]; then
        if git -C "$dir" apply --check "$ROOT/$patch" 2>/dev/null; then
            git -C "$dir" apply "$ROOT/$patch"
            echo "[bench] $dir @ ${sha:0:8} + $patch"
        elif git -C "$dir" apply --reverse --check "$ROOT/$patch" 2>/dev/null; then
            echo "[bench] $dir @ ${sha:0:8} (patch already applied)"
        else
            echo "[bench] ERROR: $patch does not apply to $dir" >&2; exit 1
        fi
    else
        echo "[bench] $dir @ ${sha:0:8}"
    fi
}

fetch https://github.com/ethz-spylab/agentdojo 089ed468cf3ed0322acc66b0211f26d9d90dbf60 \
      benchmark/agentdojo benchmarks/patches/agentdojo.patch
fetch https://github.com/xhOwenMa/AutoDojo   abbcbd8d59ea19115dc874eeb2cf294169ac5e0d \
      benchmark/autodojo benchmarks/patches/autodojo.patch
fetch https://github.com/SaFo-Lab/AgentDyn   5353cf7615b135cace8d07c8f12dac53a16b6db3 \
      benchmark/agentdyn

# AutoDojo replays cached injections from its variant_generation directory: put the injections
# that were optimized against Kairos (autodojo_runs/variants_v2) where the replay looks for them.
VG=benchmark/autodojo/agentdojo/variant_generation
mkdir -p "$VG/variants_v2"
cp -rn autodojo_runs/variants_v2/. "$VG/variants_v2/"
echo "[bench] optimized injections -> $VG/variants_v2"
