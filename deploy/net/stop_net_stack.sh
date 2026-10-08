#!/bin/bash
#
# Tear down the network channel  (M3)
# ===================================
# Stops mitmproxy and removes the redirect rules. The event log is kept for
# net_report.py.
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN="/run/kairos"

if [ -f "$RUN/mitmproxy.pid" ]; then
    kill "$(cat "$RUN/mitmproxy.pid")" 2>/dev/null || true
    rm -f "$RUN/mitmproxy.pid"
fi
pkill -f "net_monitor_addon.py" 2>/dev/null || true

bash "$HERE/setup_proxy_rules.sh" down
echo "[net] channel down (event log kept for net_report.py)"
