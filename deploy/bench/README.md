# Latency microbenchmarks

The two overhead figures of the paper's Cost section, measured on a running stack
(`deploy/run.sh`). The raw results of the reported runs are in `production_runs/latency/`;
`python3 evaluation/cost_and_decisions.py latency` summarizes them.

```bash
# file channel: 200 cycles of create, write, fsync, read, unlink on 4 KB files, through the
# FUSE monitor against the same overlay without it (repeated three times)
sudo python3 deploy/bench/latency.py --json rq2_fs_1.json fs --root /var/lib/kairos/fs

# network channel: 50 allowed requests from the host, through the proxy against direct, to a
# local HTTP endpoint (repeated three times). sink.py is that endpoint; the URL's host name
# must resolve to the sink's address on the host.
sudo python3 deploy/bench/sink.py --out /tmp/sink.jsonl &
python3 deploy/bench/latency.py --json rq2_net_1.json net --url http://status.internal.local/notify -n 50
```

The figures are single-host and indicative; they measure the mechanism, not the oracle (a
held request's latency is dominated by the oracle's model call and is not part of them).
