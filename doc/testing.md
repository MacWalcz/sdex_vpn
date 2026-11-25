# Testing SDEx VPN

How the VPN is exercised, what counts as a pass, and what the current runs
produced. Test data lives here, not in the design document.

Companion documents:

* `doc/doc.md` — architecture and the SDEx algorithm.
* `doc/infrastructure.md` — the three VMs, addressing, SSH, kernel prerequisites.
* `test/sdex_vpn_test.py` (+ `test/sdex_vpn_test.sh` wrapper) — the smoke test.
* `test/sdex_bench.py` (+ `test/sdex_bench.sh` wrapper) — the throughput
  benchmark; raw data and aggregates in `bench/`.

---

## 1. The smoke test

`test/sdex_vpn_test.sh` drives three VMs over SSH (client `192.168.67.2`,
server `192.168.67.3`, HTTP target `192.168.76.4`) and asserts that the client
can reach the target **only** through the tunnel.

The eight steps, in order:

1. TCP/22 reachability and a real login on all three hosts.
2. Locate the `client` and `server` binaries on their VMs.
3. Baseline isolation: the client must **not** reach the HTTP host yet.
4. Start `python3 -m http.server 80` on the target and confirm it listens.
5. Start the VPN server, then set forwarding / `rp_filter` / NAT prerequisites.
6. Start the VPN client with a split route (`--route 192.168.76.0/24`).
7. Print the client's `tun0` and routing table, and warn if the server died.
8. `ping` the target from the client, then fetch it over HTTP.

Teardown kills processes by binary path. It does **not** undo `ip_forward` or
the `ip nat` table — see section 4.

### Preconditions

| Requirement | Value / location |
|-------------|------------------|
| SSH user + password | `dupa`, password in `~/.hermes/vm_pass` (mode 600) on the WSL host |
| paramiko | `/home/admin/.hermes/cache/scratch/sshtools/bin/python` (venv) |
| Binaries | `~/test/sdex_vpn/target/release/{client,server}` on the VMs |
| Server default route | `sdex-lab-default-route.service` (enabled, section 3 of `infrastructure.md`) |

### Running it

```bash
cd /home/admin/projects/algo
./test/sdex_vpn_test.sh               # run + cleanup
./test/sdex_vpn_test.sh --no-cleanup  # leave the tunnel up to inspect
```

Useful overrides: `--client`, `--server`, `--http`, `--route`, `--port`,
`--threads`, `--password-file`, `--ping-count`. `--help` lists them.

A pass looks like:

```
[8/8] ping 192.168.76.4 from 192.168.67.2 through the tunnel ...
4 packets transmitted, 4 received, 0% packet loss
SUCCESS: 192.168.67.2 -> 192.168.76.4 works over the SDEx tunnel
         http check: HTTP 200 in 0.003155s
```

Exit status is 0 on success, 1 on any failure.

---

## 2. Current result (2026-11-22)

**It works** on the current lab, provided the server has a default route. The
route is supplied by `sdex-lab-default-route.service` (installed and enabled);
with it active the harness passes with no manual steps.

### Variants measured

All runs used the deployed binaries, no source changes.

| Server route                    | Client mode                | rc | Result |
|---------------------------------|----------------------------|----|--------|
| none                            | `--route 192.168.76.0/24`  | 1  | FAIL — server exits `Error: "Couldnt find default route"`, 0/4 pings |
| `default via 192.168.76.1 eth2` | `--route 192.168.76.0/24`  | 0  | PASS — 4/4 pings, 0.78–0.88 ms avg (three runs), HTTP 200 |
| `default via 192.168.67.1 eth1` | `--route 192.168.76.0/24`  | 0  | PASS, 4/4, 1.04 ms, HTTP 200 — qualified: only because the harness adds its own `oifname eth2` masquerade; the binary's rule names `eth1` and does nothing |
| `default via 192.168.76.1 eth2` | full tunnel (no `--route`)  | 0  | PASS — `default dev tun0`, 4/4, 0.92 ms, HTTP 200; SSH session survived |

Notes on interpreting this table:

* The startup failure depends only on the **existence** of a default route, not
  on where it points. The NAT interface does depend on where it points.
* A green run does not prove the server's NAT is correct: the harness adds a
  masquerade rule for the target's interface itself (`test/sdex_vpn_test.py`,
  step 5). Inspect `sudo nft list table ip nat` when that matters.
* RTTs are sub-millisecond because all guests share one Hyper-V host. They are
  a connectivity signal, not a performance measurement.
* The baseline isolation check (step 3) must pass; if the client can already
  reach the target, the switches are bridged and a PASS means nothing.

---

## 3. Performance benchmarking (SDEx vs OpenVPN vs WireGuard)

Only SDEx has been measured. The harness is generic, so OpenVPN and WireGuard
plug into the same procedure: same VMs, same offers, same statistics.

### 3.1 Harness

`./test/sdex_bench.sh run` (`test/sdex_bench.py`) drives the three VMs over
paramiko, exactly like the smoke test, and appends every measurement to a JSONL
file as it completes, so a killed run never loses finished iterations.

Five phases:

1. **Reset** — kill leftovers, delete `tun0` routes, `ip nat` table,
   `ip_forward`, and the daemon logs.
2. **Baseline A** — `client -> server` on segment A, no tunnel.
3. **Baseline B** — `server -> target` on segment B, no tunnel.
4. **Tunnel** — start server + client, `ping -c 100`, then the throughput
   scenarios.
5. **Teardown** — kill by anchored path, reset kernel state.

The two baselines exist because the client cannot reach the target without the
tunnel (that is the point of the lab), so there is no single "raw path" to
compare against. The tunnel rides on segment A and NATs onto segment B, so both
legs are measured and the slower one is the honest reference.

| scenario | iperf3 client args | offer |
|---|---|---|
| `tcp1` | `-t N` | as fast as TCP can go |
| `tcp4` | `-t N -P 4` | as fast as TCP can go |
| `tcp1_mss` | `-t N -M 1360` | TCP with a clamped MSS (1400-byte inner packets) |
| `udp64` | `-u -b 100M -l 64 -t N` | 100 Mbps → 136 kpps |
| `udp512` | `-u -b 500M -l 512 -t N` | 500 Mbps → 116 kpps |
| `udp1200` | `-u -b 1G -l 1200 -t N` | 1 Gbps → 102 kpps |
| `udp1472` | `-u -b 1G -l 1472 -t N` | 1 Gbps → 83 kpps |

The UDP offers were chosen so the *packet rate* stays inside what a 2-vCPU VM
can generate; 64 B at 1 Gbps would be ~2 Mpps, which `iperf3` itself cannot
produce, and the result would describe the tool instead of the tunnel. Baselines
use the same offers, so the only variable between them and the tunnel numbers is
the tunnel.

**CPU** comes from `/proc/<pid>/stat` (utime+stime of the daemon, sampled before
and after each run) and `/proc/stat` (whole VM), normalised with `getconf
CLK_TCK`. `pidstat` is not installed on these images and `sysctl` is missing —
see `infrastructure.md` section 5.

**Statistics** (`./test/sdex_bench.sh report`): mean, median, standard
deviation, min, max and a 95% CI per series; the first 3 iterations of each
series are dropped as warm-up; tunnel vs baseline is compared with the
two-sided Mann-Whitney U test (normal approximation, tie-corrected), because
throughput samples are not normally distributed. Raw data: `bench/full.jsonl`,
aggregate `bench/full.md` and `bench/full.csv`.

### 3.2 Results — 2026-11-22

30 tunnel iterations and 10 baseline iterations per scenario, 5 s each, 3
warm-up discarded (n = 27 and n = 7). `tun0` MTU 1500, 4 threads, logging
redirected to `/dev/null` (see 3.5).

**Baselines, no tunnel**

| config | scenario | n | mean Mbps | stdev | min | max |
|---|---|---|---|---|---|---|
| A: client→server (seg A) | tcp1 | 7 | 15142.09 | 968.95 | 14018.73 | 16444.39 |
| A | tcp4 | 7 | 21024.00 | 4020.28 | 12147.76 | 23840.86 |
| A | udp64 | 7 | 99.85 | 0.09 | 99.72 | 99.95 |
| A | udp512 | 7 | 499.72 | 0.17 | 499.47 | 499.92 |
| A | udp1200 | 7 | 999.46 | 0.36 | 998.79 | 999.81 |
| A | udp1472 | 7 | 999.11 | 0.45 | 998.18 | 999.45 |
| B: server→target (seg B) | tcp1 | 7 | 31657.25 | 5670.39 | 21237.82 | 37560.99 |
| B | tcp4 | 7 | 32596.77 | 5928.93 | 20272.62 | 39211.70 |
| B | udp64 | 7 | 99.85 | 0.14 | 99.55 | 99.96 |
| B | udp512 | 7 | 499.73 | 0.24 | 499.24 | 499.94 |
| B | udp1200 | 7 | 999.37 | 0.21 | 998.99 | 999.69 |
| B | udp1472 | 7 | 999.45 | 0.42 | 998.59 | 999.77 |

Every UDP baseline delivers its full offer with ≤ 0.1% loss, i.e. the raw path
is not the limit at any of the offered rates. TCP over the same virtual switches
runs at 15–33 Gbps.

**Through the SDEx tunnel**

| scenario | n | mean Mbps | median | stdev | 95% CI | client CPU % | server CPU % | loss % |
|---|---|---|---|---|---|---|---|---|
| tcp1 | 27 | 206.20 | 203.82 | 8.64 | 202.93–209.46 | 91.5 | 94.7 | — |
| tcp1_mss | 27 | 212.04 | 210.41 | 5.68 | 209.90–214.18 | 92.8 | 98.1 | — |
| tcp4 | 27 | 206.09 | 205.86 | 5.68 | 203.95–208.23 | 95.4 | 97.6 | — |
| udp64 | 27 | 50.28 | 49.14 | 5.65 | 48.14–52.41 | 98.2 | 97.9 | 49.6 |
| udp512 | 27 | 160.15 | 153.09 | 15.70 | 154.23–166.08 | 98.8 | 98.7 | 67.7 |
| udp1200 | 27 | 205.09 | 202.08 | 11.26 | 200.84–209.34 | 98.4 | 98.1 | 79.0 |
| udp1472 | 27 | 216.49 | 210.43 | 12.88 | 211.63–221.35 | 98.6 | 98.2 | 77.8 |

Latency, idle tunnel, 100 packets: `rtt min/avg/max/mdev =
0.434/0.842/2.445/0.280 ms`, 0% loss. Under load, UDP jitter rises to
0.06–0.09 ms.

Mann-Whitney against baseline A: every tunnel scenario gives U = 0,
p = 0.0001 — the difference is not a fluctuation.

**Worker threads** (3 kept iterations each, tcp1 / tcp4 means):

| threads | tcp1 Mbps | tcp4 Mbps | client CPU % |
|---|---|---|---|
| 1 | 216.6 | 214.0 | 93 |
| 2 | 205.7 | 203.0 | 91 |
| 4 | 202.6 | 205.9 | 92 |

**Logging cost** (4 iterations, logging to tmpfs instead of `/dev/null`):
tcp1 206–213 Mbps, udp1200 198–211 Mbps — indistinguishable from the
logging-off numbers above.

### 3.3 What the numbers say

1. **The ceiling is ~206 Mbps TCP single-stream, and it is one core.** The
   client process burns 91–99% of a single core while the VM has two, the second
   core stays idle, and the tunnel delivers ~1.4% of what the same path carries
   without it.
2. **Threads do not help; one thread is slightly faster.** 1 thread ≈ 216 Mbps,
   4 threads ≈ 203–206 Mbps. Process CPU stays at ~93% of one core regardless of
   `--threads`, so the work is serialised on one stage (one flow hashes to one
   TUN queue / one crypto context) and oversubscribing 4 workers on 2 vCPUs
   costs ~5%.
3. **Multiple TCP streams do not add throughput** (tcp4 ≈ tcp1) but do add
   retransmits (~759 vs ~154 per run), i.e. congestion control reacts to losses
   that are not congestion.
4. **Small UDP packets are the expensive case**: 50 Mbps at 64 B (68 kpps), 160
   at 512 B, 205 at 1200 B, 216 at 1472 B. Throughput grows with payload size
   because there is both a per-packet and a per-byte cost; a constant-packet-rate
   limit would show a flat kpps column, which it is not (68 → 18 kpps).
5. **Loss is saturation, not breakage**: the offers are 2–7× the achievable rate,
   so UDP loss of 50–79% is the expected consequence of offering 100 Mbps–1 Gbps
   to a path that moves ~200 Mbps.
6. **The MTU problem is soft, not fatal.** 1472-byte UDP payloads (1500-byte
   inner packets, 1528 bytes on the wire) still get through at 216 Mbps — they
   fragment. TCP without an MSS clamp loses throughput to retransmits (206.20 vs
   212.04 with `-M 1360`), the classic PMTU symptom, but it does not stall.

### 3.4 Reproducing

```bash
# pilot (2 minutes)
./test/sdex_bench.sh run --iterations 3 --warmup 1 --duration 5 --tag pilot \
    --baseline none --scenarios tcp1,udp512

# the run behind 3.2 (about 40 minutes)
./test/sdex_bench.sh run --iterations 30 --warmup 3 --duration 5 \
    --baseline-iterations 10 --tag full
./test/sdex_bench.sh report --results bench/full.jsonl --warmup 3
```

`--scenarios`, `--baseline a|b|none`, `--threads`, `--route`, `--daemon-logs
null|file`, `--extra-args` and the host/port options mirror the smoke test.
One run at a time: the harness takes a lock in `bench/.lock`, because two
overlapping runs share the VMs and the loser's teardown kills the winner's
daemons.

### 3.5 Lab quirks that cost time

* **`iperf3` must be installed offline.** The VMs have no internet (no default
  route by design). Install from `.deb` files fetched on the host:
  `apt-get download iperf3 libiperf0 libsctp1` on the WSL host, `sftp` them to
  each guest, `sudo dpkg -i /tmp/*.deb`. `libsctp1` is the undocumented
  dependency — without it `iperf3` fails to load its shared library.
* **`/tmp` is a 243 MB tmpfs and the daemons log every packet.** A benchmark
  fills it in seconds; a full `/tmp` stops the next run from starting at all
  (the daemon cannot create its log). The harness deletes `/tmp/*.log` as
  **root** and redirects daemon output to `/dev/null` by default.
* **`fs.protected_regular=1`** (Debian default): a root daemon cannot append to
  a log file created by the unprivileged user in sticky `/tmp`. Symptom: the
  process never appears, log empty, no error anywhere. Truncate as root.
* **The client exits when the server is not listening** (`udp.recv: Connection
  refused`). A missed server start therefore shows up as "the client never
  installed the route". The harness verifies both daemons with `pgrep` (anchored
  to the binary path) and retries.
* **SSH starves at saturation.** With both vCPUs pinned, paramiko channel reads
  time out mid-measurement; the harness reconnects and repeats that iteration.
* **`iperf3` occasionally segfaults** on the client VM (several `segfault at 10
  ... in libc.so.6` entries in `dmesg`). Runs whose JSON parsed are kept; a
  crashed run records an `error` field rather than a silent zero.


---

## 4. Between runs

The harness leaves kernel state behind, and leftover state can make a broken
tunnel look green. Reset before trusting a result:

```bash
# server
sudo nft delete table ip nat 2>/dev/null
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
pgrep -af '^/home/dupa/test/sdex_vpn/target/release' || true

# client (the /32 host route to the server is not removed by the daemons)
sudo ip route del 192.168.67.3/32 2>/dev/null
pgrep -af '^/home/dupa/test/sdex_vpn/target/release' || true
```

Do not remove the server's default route unless you also stop
`sdex-lab-default-route.service`; otherwise the service and the route disagree
until the next start.
