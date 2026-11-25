# Methodology and Results of SDEx VPN Performance Tests

Technical version (procedure, raw data, error codes) lives in `doc/testing.md`
section 3; this file describes the methodology and presents the results in a form
suitable for a thesis chapter.

---

## 1. Goal and scope

The goal is to measure throughput, latency and CPU load of the SDEx tunnel under
laboratory conditions, and to compare the result with the throughput of the same
path without a VPN (baseline). The methodology is written so that OpenVPN and
WireGuard can be dropped into the same place in later steps — with no changes to
the measurement procedure.

## 2. Test environment

Three Hyper-V virtual machines (Debian 13, kernel 6.12, 2 vCPU, ~400 MB RAM,
5.4 GB disk), attached to private virtual switches:

| Machine | Addresses | Role |
|---|---|---|
| `sdex-client` | 192.168.67.2 | VPN client (tun0: 10.0.0.2) |
| `sdex-server` | 192.168.67.3 / 192.168.76.2 | VPN server (UDP/51820, tun0: 10.0.0.1), routing + NAT |
| `sdex-http` | 192.168.76.4 | test target, `iperf3 -s` |

The segments `192.168.67.0/24` and `192.168.76.0/24` are separated: the client has
**no** route to the target without the tunnel, and the server is the only machine
with a leg in both segments. Every packet that reaches the target therefore had to
travel through `tun0` — the throughput result describes the tunnel, not an
accidental bypass path.

All VMs run on one host, so latencies are on the order of 1 ms and do not reflect
a real network; the "through the tunnel / without the tunnel" comparisons remain
valid, however, because both configurations are measured on the same hardware.

## 3. Measurement tools

* **`iperf3` 3.18** — TCP and UDP throughput, output in JSON format (`-J`).
* **`ping`** — latency (RTT) and variability (mdev), 100 packets.
* **`/proc/<pid>/stat`** and **`/proc/stat`** — CPU usage of the VPN processes and
  of the whole machine. `pidstat` is not installed on these images, and reading
  `/proc` provides the same information without extra packages.
* **`ip route`, `nft list table ip nat`, `ss -lunp`** — verification that traffic
  actually traverses the tunnel and is NATed.

`iperf3` was installed **without internet access** (the VMs do not have it): the
`iperf3`, `libiperf0` and `libsctp1` packages were downloaded on the WSL host,
uploaded over SFTP, and installed with `dpkg -i`. A missing `libsctp1` causes a
failure to load the shared library `libsctp.so.1`.

## 4. Procedure

One measurement iteration consists of five phases executed automatically by
`test/sdex_bench.py`:

1. **State reset** — kill leftover VPN processes, remove the `tun0` routes, the
   `ip nat` table, zero `ip_forward`, clear the logs.
2. **Baseline A** — `client → server` in segment A, without a tunnel.
3. **Baseline B** — `server → target` in segment B, without a tunnel.
4. **Tunnel** — start the server and the client, `ping -c 100`, then the
   throughput scenarios.
5. **Cleanup** — kill the daemons by binary path, reset the kernel state.

Two baselines are needed because the client cannot reach the target without the
tunnel: there is no single "native path" to compare against. The tunnel uses
segment A and NATs traffic into segment B, so both legs are measured, and the
slower of the two is the fair reference point.

## 5. Scenarios

| Scenario | Command | Offered load |
|---|---|---|
| TCP, 1 stream | `iperf3 -c <target> -t N` | maximum |
| TCP, 4 streams | `iperf3 -c <target> -t N -P 4` | maximum |
| TCP with MSS clamp | `iperf3 -c <target> -t N -M 1360` | maximum |
| UDP 64 B | `-u -b 100M -l 64` | 136k pkt/s |
| UDP 512 B | `-u -b 500M -l 512` | 116k pkt/s |
| UDP 1200 B | `-u -b 1G -l 1200` | 102k pkt/s |
| UDP 1472 B | `-u -b 1G -l 1472` | 83k pkt/s |

The offered loads were chosen so that the packet stream stays within what a
2-vCPU VM can generate; 64 B at 1 Gb/s is roughly 2 million pkt/s, which `iperf3`
cannot produce by itself, so the result would describe the tool rather than the
tunnel. The baseline uses identical offers, so the tunnel is the only variable.

Two supplementary tests were also run: the effect of the number of worker threads
(1, 2, 4) and the effect of logging every packet to standard output.

## 6. Statistical analysis

* 30 independent iterations per tunnel scenario, 10 for the baselines.
* The first 3 iterations are discarded as warm-up (n = 27 for the tunnel, n = 7
  for the baselines).
* For each series: mean, median, standard deviation, minimum, maximum and the 95%
  confidence interval.
* Significance of the difference between the tunnel and the baseline: two-sided
  Mann-Whitney U test with a normal approximation and a tie correction
  (throughput distributions are not normal).

## 7. Results

### 7.1 Baseline (no VPN)

| Configuration | Scenario | n | Mean [Mb/s] | Std dev | Min | Max |
|---|---|---|---|---|---|---|
| A: client→server | TCP 1 | 7 | 15142.09 | 968.95 | 14018.73 | 16444.39 |
| A | TCP 4 | 7 | 21024.00 | 4020.28 | 12147.76 | 23840.86 |
| A | UDP 64 B | 7 | 99.85 | 0.09 | 99.72 | 99.95 |
| A | UDP 512 B | 7 | 499.72 | 0.17 | 499.47 | 499.92 |
| A | UDP 1200 B | 7 | 999.46 | 0.36 | 998.79 | 999.81 |
| A | UDP 1472 B | 7 | 999.11 | 0.45 | 998.18 | 999.45 |
| B: server→target | TCP 1 | 7 | 31657.25 | 5670.39 | 21237.82 | 37560.99 |
| B | TCP 4 | 7 | 32596.77 | 5928.93 | 20272.62 | 39211.70 |
| B | UDP 64 B | 7 | 99.85 | 0.14 | 99.55 | 99.96 |
| B | UDP 512 B | 7 | 499.73 | 0.24 | 499.24 | 499.94 |
| B | UDP 1200 B | 7 | 999.37 | 0.21 | 998.99 | 999.69 |
| B | UDP 1472 B | 7 | 999.45 | 0.42 | 998.59 | 999.77 |

Every UDP measurement delivers the full offered load at a loss of ≤ 0.1%, so none
of the offers comes close to the limit of the raw path. TCP over the same virtual
switches reaches 15–33 Gb/s.

### 7.2 Through the SDEx tunnel

| Scenario | n | Mean [Mb/s] | Median | Std dev | 95% CI | Client CPU [%] | Server CPU [%] | Loss [%] |
|---|---|---|---|---|---|---|---|---|
| TCP 1 | 27 | 206.20 | 203.82 | 8.64 | 202.93–209.46 | 91.5 | 94.7 | — |
| TCP 1 (MSS 1360) | 27 | 212.04 | 210.41 | 5.68 | 209.90–214.18 | 92.8 | 98.1 | — |
| TCP 4 | 27 | 206.09 | 205.86 | 5.68 | 203.95–208.23 | 95.4 | 97.6 | — |
| UDP 64 B | 27 | 50.28 | 49.14 | 5.65 | 48.14–52.41 | 98.2 | 97.9 | 49.6 |
| UDP 512 B | 27 | 160.15 | 153.09 | 15.70 | 154.23–166.08 | 98.8 | 98.7 | 67.7 |
| UDP 1200 B | 27 | 205.09 | 202.08 | 11.26 | 200.84–209.34 | 98.4 | 98.1 | 79.0 |
| UDP 1472 B | 27 | 216.49 | 210.43 | 12.88 | 211.63–221.35 | 98.6 | 98.2 | 77.8 |

Idle latency (100 packets): `min/avg/max/mdev =
0.434/0.842/2.445/0.280 ms`, 0% loss. Under load, UDP jitter rises to
0.06–0.09 ms.

Mann-Whitney U test (tunnel vs baseline A) for every scenario: U = 0,
p = 0.0001 — the difference is not fluctuation.

### 7.3 Effect of the number of worker threads

| Threads | TCP 1 [Mb/s] | TCP 4 [Mb/s] | Client CPU [%] |
|---|---|---|---|
| 1 | 216.6 | 214.0 | 93 |
| 2 | 205.7 | 203.0 | 91 |
| 4 | 202.6 | 205.9 | 92 |

### 7.4 Effect of packet logging

Logging every packet to standard output (into tmpfs) instead of `/dev/null`:
TCP 1 = 206–213 Mb/s, UDP 1200 B = 198–211 Mb/s — the difference is
indistinguishable from measurement noise.

## 8. Interpretation

1. **The throughput ceiling is about 206 Mb/s for a single TCP stream, and it is
   limited by one core.** The client process uses 91–99% of one core out of two
   available; the second core stays idle.
2. **Threads do not increase throughput; one thread is slightly faster**
   (216 Mb/s vs ~203–206 Mb/s with four). The process's CPU usage stays at ~93%
   of one core regardless of `--threads`, which points to a bottleneck in a
   single serial processing stage (one stream lands in one TUN queue / one
   encryption context), and oversubscribing four threads on two vCPUs costs about
   5%.
3. **Multiple TCP streams do not add up in throughput** (TCP 4 ≈ TCP 1), but they
   do increase the number of retransmissions (~759 vs ~154 per run).
4. **Small UDP packets are the most expensive**: 50 Mb/s at 64 B (68k pkt/s),
   160 Mb/s at 512 B, 205 Mb/s at 1200 B, 216 Mb/s at 1472 B. The per-unit cost
   has both a "per packet" and a "per byte" component.
5. **UDP packet loss comes from congestion, not from a fault**: the offers are
   2–7× higher than the achievable throughput, so a 50–79% loss is the expected
   consequence of offering 100 Mb/s–1 Gb/s to a path that carries ~200 Mb/s.
6. **The MTU problem is mild, not critical.** UDP 1472 B packets (1500 B inner
   packet, 1528 B on the wire) get through and reach 216 Mb/s, i.e. they are
   fragmented. TCP without the MSS clamp loses to retransmissions (206.20 vs
   212.04 Mb/s with `-M 1360`), but does not stall.

## 9. Limitations

* All VMs on one host: the latency and throughput of the raw path (15–33 Gb/s)
  are unrealistically high; the absolute values for the tunnel (~200 Mb/s) are
  nevertheless limited by guest CPU, so they remain meaningful.
* Only 2 vCPU and ~400 MB RAM per VM — the result is a lower bound on SDEx
  performance, not its hardware maximum.
* Only SDEx was measured; OpenVPN and WireGuard require being started on the same
  VMs with the same procedure (the harness is prepared for that).
* The CPU sampling resolution is 10 ms (`CLK_TCK=100`), which over 5 s series
  gives an error on the order of 1%.

## 10. Reproducing the measurement

```bash
cd /home/admin/projects/algo

# the series described in chapter 7 (about 40 minutes)
./test/sdex_bench.sh run --iterations 30 --warmup 3 --duration 5 \
    --baseline-iterations 10 --tag full
./test/sdex_bench.sh report --results bench/full.jsonl --warmup 3

# quick control run (2 minutes)
./test/sdex_bench.sh run --iterations 3 --warmup 1 --duration 5 --tag pilot \
    --baseline none --scenarios tcp1,udp512
```

Raw data: `bench/full.jsonl` (one JSON line per iteration), aggregates:
`bench/full.md` and `bench/full.csv`.
