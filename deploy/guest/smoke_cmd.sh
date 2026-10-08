#!/bin/sh
# Non-interactive smoke payload for the PTY<->vsock bridge (M1 validation).
# Proves, from inside the guest and over the vsock terminal, that:
#   1. the bridge exec path works (this output reaches the host),
#   2. Claude Code is installed and runnable on the guest's Node 22,
#   3. the guest has outbound IPv4 internet to Anthropic (NAT path) via BOTH
#      curl and Node's HTTPS stack (the path Claude Code actually uses).
echo "===BRIDGE_UP==="
echo "whoami=$(whoami) home=$HOME"
echo "node=$(node --version 2>&1)"
echo "claude=$(claude --version 2>&1 | head -1)"

# resolver should now hand back IPv4 only (dnsmasq --filter-AAAA)
echo "dns=$(getent ahostsv4 api.anthropic.com 2>&1 | head -1 || echo FAILED)"

# curl over IPv4
echo "curl_v4_anthropic=$(curl -4 -s -m 15 -o /dev/null -w '%{http_code}' https://api.anthropic.com/ 2>&1)"

# Node HTTPS — mirrors what Claude Code does for API + login
node -e '
const https=require("https");
const req=https.get("https://api.anthropic.com/",{timeout:15000},res=>{
  console.log("node_https_anthropic="+res.statusCode); process.exit(0);
});
req.on("timeout",()=>{console.log("node_https_anthropic=TIMEOUT");req.destroy();process.exit(0);});
req.on("error",e=>{console.log("node_https_anthropic=ERR:"+e.code);process.exit(0);});
' 2>&1
echo "===SMOKE_DONE==="
