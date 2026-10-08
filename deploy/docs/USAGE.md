# Kairos deployed stack: usage

The stack runs an unmodified coding agent (Claude Code, installed into the guest image)
inside a microVM and mediates everything it does to the **filesystem** and the **network**.
Every effect is recorded, and in an enforcing mode the reference monitor releases, refuses or
defers it. The decisions come from the Kairos policy engine and oracle (`kairos/`), the same
code that is evaluated on the benchmarks.

## 1. Requirements

- Linux, x86_64, with hardware virtualization (`/dev/kvm`; on a cloud VM, nested
  virtualization must be enabled).
- root (the stack manages a bridge, iptables rules, mounts and a VM).
- Outbound internet (the agent talks to its model provider; the install pulls packages).
- About 3 GB of disk for the guest image, plus room for the session records.

`install.sh` installs `cloud-hypervisor`, `virtiofsd`, `mitmproxy`, Python 3 with `fusepy`,
`dnsmasq`, `iproute2`/`iptables` and `fuse3`.

## 2. Install

```bash
sudo deploy/install.sh
```

This installs the dependencies, downloads the microVM kernel, generates the mitmproxy
certificate authority, and builds the guest image `deploy/images/claude-rootfs.ext4`
(Alpine, Node, Claude Code, the proxy's certificate authority). Re-running skips what is
already present; delete the `.ext4` to rebuild the image.

## 3. Run

```bash
sudo KAIROS_FS_SEED=/path/to/project KAIROS_MODE=judge-auto deploy/run.sh
```

Your terminal becomes the agent's terminal inside the VM (the `ctrl` channel), working in
`/data`, which is the mediated working directory. On the first run the agent asks you to log
in to its provider. Detach with **Ctrl-]**; the session is then finalized (section 5).
Without `KAIROS_FS_SEED`, `/data` starts empty.

## 4. Modes

The control plane (`deploy/frontend/serve.py`, port 8090 on the host) is the decision point
the proxy and the file channel consult. The mode is set at start with `KAIROS_MODE` or while
running with `POST /api/mode {"mode": ...}`.

| Mode | Behavior |
|---|---|
| `observe` (default) | Nothing is held; everything is recorded. |
| `judge-auto` | The monitor decides every state-changing request: the policy releases what it can verify, and the oracle decides what the policy defers. This is the configuration of the paper. |
| `human` | Requests the policy does not release are held until a person decides: `GET /api/net/pending` lists them, `POST /api/net/resolve {"id": ..., "action": "commit"\|"abort"}` decides one. The oracle's verdict is attached to each. |
| `judge-recommend` | As `human`, with the oracle's verdict as a recommendation. |

The oracle is an LLM (`OPENAI_API_KEY`; model `KAIROS_JUDGE_MODEL`, default `gpt-4o-mini`;
the deployment uses the intent-first prompt of `kairos/judge/prod_oracle.py`). Without a key
the policy decides alone and defers nothing to a model. Read requests (`GET`) and the model
provider's traffic are recorded but never held. Staged file changes are resolved per file
with `POST /api/fs/resolve` or all at once with `POST /api/fs/finalize`.

## 4a. Strict network boundary (`KAIROS_NET_STRICT=1`)

By default the guest's TCP is redirected into the proxy, while its DNS queries are forwarded
upstream, other UDP is forwarded, and the host's services are reachable from the guest. With
`KAIROS_NET_STRICT=1` every packet the guest sends either passes the monitor or is dropped:

| Path | Default | Strict |
|---|---|---|
| TCP to any address | redirected to the proxy | redirected to the proxy; non-HTTP flows are refused |
| DNS | forwarded upstream by `dnsmasq` | answered locally: every name resolves to the bridge address, no query leaves the host, names are logged |
| other UDP, ICMP, IPv6 | forwarded (NAT) | dropped |
| host services from the guest | reachable | dropped; only the proxy (:8080) and the resolver (:53) accept |

Because every name resolves to the bridge address, the proxy chooses the upstream itself
(`deploy/net/sinkhole_policy.py`): from the TLS SNI or the HTTP Host header, resolved with the
host's resolver, and only if every address is globally routable. Names pinned with
`KAIROS_DNS_HOSTS` go to `KAIROS_DNS_TARGET` on `KAIROS_NET_PINNED_PORTS`. A refused
connection gets `403 Refused by the Kairos strict boundary: <reason>` and a
`sinkhole_refused` event in `net_events.jsonl`. HTTPS to a bare IP address (no SNI) and
non-HTTP protocols do not work in strict mode by design.

## 5. The session record

Each run writes an audit directory, write-protected when the session ends:

```
/var/lib/kairos/sessions/<timestamp>/
  session.json            run metadata (start, end, mode, seed)
  net_events.jsonl        every network request and response
  fs_events.jsonl         every filesystem operation
  bodies/<sha256>         full request and response bodies
  decisions.jsonl         every release, refusal and deferral, and who decided
  judge_prompts.jsonl     the exact view each oracle call received, and its answer
  wal_journal.jsonl       per change: which turn or held request made it, and its fate
  fs_report.txt/.json     end-of-session snapshot of the working directory's changes
  net_report.txt          end-of-session network summary
```

**Where file changes land.** The seed directory is the overlay's read-only lower layer, used
in place; the agent's changes accumulate in the upper layer, and the write-ahead log keeps a
pre-image of each change so that the changes of one turn or one held request can be undone
while the session runs. At exit, `KAIROS_FS_ON_EXIT` decides: `commit` (default) merges the
changes into the seed directory, or into `KAIROS_FS_OUT` if set; `keep` leaves them staged;
`abort` discards them.

The guest's `/tmp` is recorded as well, through a separate observe-only channel, and never
written back (`KAIROS_NO_TMP=1` disables it). Content capture is capped at 100 MB per file
or body (`KAIROS_MAX_LOG_BYTES`); beyond that only metadata is recorded.

## 6. Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `KAIROS_FS_SEED` | none | project directory used as the agent's `/data` |
| `KAIROS_FS_ON_EXIT` | `commit` | `commit`, `keep` or `abort` |
| `KAIROS_FS_OUT` | seed directory | where `commit` writes the result |
| `KAIROS_FS_RESET` | `0` | `1` wipes staged changes at start |
| `KAIROS_FS_WAL` | `1` | write-ahead log for per-turn resolution while the session runs |
| `KAIROS_MODE` | `observe` | initial mode (section 4) |
| `OPENAI_API_KEY` | none | enables the LLM oracle |
| `KAIROS_JUDGE_MODEL` | `gpt-4o-mini` | oracle model |
| `KAIROS_JUDGE_BASE_URL`, `KAIROS_JUDGE_API_KEY` | none | an OpenAI-compatible endpoint for the oracle |
| `KAIROS_LLM_JUDGE` | `1` | `0` disables the oracle even when a key is set |
| `KAIROS_CLEARED_HOSTS` | none | additional destinations cleared for sensitive data |
| `KAIROS_KNOWN_HOSTS` | none | additional known destinations (benign traffic passes, sensitive data is deferred) |
| `KAIROS_NET_STRICT` | `0` | strict network boundary (section 4a) |
| `KAIROS_DNS_HOSTS`, `KAIROS_DNS_TARGET` | none, `192.168.100.1` | names pinned to an address on the host side |
| `KAIROS_NET_PINNED_PORTS` | `80,443` | ports a pinned name may use under the strict boundary |
| `KAIROS_MITM_PASSTHROUGH` | none | host pattern not to decrypt (not combinable with the strict boundary) |
| `KAIROS_BRIDGE_CMD` | image default | the command started in the guest |
| `KAIROS_UI_PORT` | `8090` | control plane port |
| `KAIROS_MAX_LOG_BYTES` | `104857600` | capture cap per file or body |
| `KAIROS_NO_TMP`, `KAIROS_NO_FS`, `KAIROS_NO_NET` | none | disable the `/tmp` channel, the file channel or the network channel |

## 7. Troubleshooting

- **The guest cannot reach the internet**: check that `dnsmasq` runs and the NAT rules are in
  place; `deploy/net/setup_net_nat.sh` is re-run by `run.sh`. The guest is IPv4-only.
- **The agent's provider connection fails under TLS interception**: start with
  `KAIROS_MITM_PASSTHROUGH='anthropic\.com'` to pass that channel through undecrypted.
- **No events recorded**: check that the VM booted, `tail /tmp/kairos_vm_serial.log`.
