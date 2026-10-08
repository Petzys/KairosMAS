#!/bin/sh
# Autonomous serial smoke (used as init= for a self-terminating boot).
# Brings up the guest network, exercises the IPv4 egress path to Anthropic via
# curl AND Node's HTTPS stack, prints results to the serial console (captured on
# the host), then powers off. No vsock needed — this validates the network fix
# deterministically. The vsock PTY bridge is validated separately.
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

ip link set lo up
ip addr add 192.168.100.2/24 dev eth0 2>/dev/null
ip link set eth0 up
ip route add default via 192.168.100.1 2>/dev/null

echo "=====SERIAL_SMOKE_BEGIN====="
echo "node=$(node --version 2>&1)"
echo "claude=$(claude --version 2>&1 | head -1)"
echo "route=$(ip route | tr '\n' ';')"
echo "dns_v4=$(getent ahostsv4 api.anthropic.com 2>&1 | head -1 || echo FAILED)"
echo "curl_v4=$(curl -4 -s -m 15 -o /dev/null -w '%{http_code}' https://api.anthropic.com/ 2>&1)"
node -e '
const https=require("https");
const r=https.get("https://api.anthropic.com/",{timeout:15000},res=>{console.log("node_https="+res.statusCode);process.exit(0);});
r.on("timeout",()=>{console.log("node_https=TIMEOUT");r.destroy();process.exit(0);});
r.on("error",e=>{console.log("node_https=ERR:"+e.code);process.exit(0);});
' 2>&1
echo "=====SERIAL_SMOKE_END====="
sync
poweroff -f
