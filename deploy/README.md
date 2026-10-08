# Deployed stack

The isolation boundary of the paper (Implementation): an unmodified coding agent runs in a
Cloud Hypervisor microVM, and every effect it has on the working directory or the network
crosses the reference monitor first.

| Path | Component |
|---|---|
| `host/` | microVM launch (`launch_vm.py`) and the `ctrl` channel, the agent's terminal over vsock (`attach_terminal.py`) |
| `guest/` | guest image build (`build_rootfs.sh`) and its init and vsock terminal bridge |
| `fs/` | `file` channel: OverlayFS staging, FUSE passthrough monitor, write-ahead log, resolution |
| `net/` | `net` channel: transparent TLS-terminating mitmproxy, firewall redirect, DNS, strict boundary |
| `frontend/serve.py` | control plane: the decision point the proxy and the file channel consult, running the Kairos policy engine and oracle, and writing the session record |
| `bench/` | latency microbenchmarks of the two channels (paper: Cost) |
| `run.sh`, `install.sh` | one-time setup and the run entry point |

Usage, modes and the session record: [docs/USAGE.md](docs/USAGE.md).
