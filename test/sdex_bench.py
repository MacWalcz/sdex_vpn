#!/usr/bin/env python3
"""SDEx VPN throughput benchmark (TCP/UDP, multiple payload sizes).

Reuses the SSH plumbing from sdex_vpn_test.py so there is one place that knows
how to talk to the lab.

Usage
    ./test/sdex_bench.sh run  --iterations 5 --warmup 1 --duration 5 --tag pilot
    ./test/sdex_bench.sh run  --iterations 30 --warmup 3 --duration 10 --tag full
    ./test/sdex_bench.sh report --results bench/pilot.jsonl

Phases
    1. clean leftover kernel state on client + server
    2. baseline (no tunnel): client->server (segment A), server->target (segment B)
    3. bring the tunnel up, verify with ping (100 packets, latency + jitter)
    4. tunnel scenarios: TCP 1/4 streams, TCP with -M 1360, UDP 64/512/1200/1472
    5. teardown, leave the lab in its idle state

Every iteration is appended to the JSONL file immediately, so a timeout or a
killed run never loses completed measurements. `report` then aggregates.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shlex
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sdex_vpn_test import Host, RemoteError, read_password, resolve_binary  # noqa: E402

RESULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bench")

# name -> iperf3 client arguments (target and duration filled in at run time).
#
# UDP offers are chosen so the *packet rate* stays within what a 2-vCPU VM can
# generate: 64 B at 1G would be ~2 Mpps, which iperf3 itself cannot produce, and
# the measurement would describe the tool rather than the tunnel. The TCP
# baselines are what establish the raw path ceiling.
SCENARIOS = {
    "tcp1":       ["-t", "{d}"],
    "tcp4":       ["-t", "{d}", "-P", "4"],
    "tcp1_mss":   ["-t", "{d}", "-M", "1360"],
    "udp64":      ["-u", "-b", "100M", "-l", "64", "-t", "{d}"],
    "udp512":     ["-u", "-b", "500M", "-l", "512", "-t", "{d}"],
    "udp1200":    ["-u", "-b", "1G", "-l", "1200", "-t", "{d}"],
    "udp1472":    ["-u", "-b", "1G", "-l", "1472", "-t", "{d}"],
}

# baselines use the same scenarios (same offer, same tool) - the only variable
# is the tunnel
BASELINE_SCENARIOS = SCENARIOS


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def parse_iperf_json(text: str) -> dict | None:
    """iperf3 -J prints one JSON object; warnings can precede it."""
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def extract_metrics(doc: dict | None) -> dict:
    """Pull the numbers we report out of an iperf3 JSON document.

    iperf3 3.18 emits sum_received for UDP as well, so the protocol has to be
    read from start.test_start.protocol, not inferred from the end keys.
    """
    if not doc:
        return {}
    end = doc.get("end", {})
    proto = (doc.get("start", {}).get("test_start", {}) or {}).get("protocol", "TCP")
    udp = str(proto).upper() == "UDP"
    out: dict = {}

    s = end.get("sum_received") or end.get("sum") or {}
    out["mbps"] = (s.get("bits_per_second") or 0) / 1e6
    out["bytes"] = s.get("bytes")
    out["seconds"] = s.get("seconds")

    if udp:
        u = end.get("sum") or {}
        out["jitter_ms"] = u.get("jitter_ms", s.get("jitter_ms"))
        out["lost_packets"] = u.get("lost_packets", s.get("lost_packets"))
        out["lost_percent"] = u.get("lost_percent", s.get("lost_percent"))
        out["packets"] = u.get("packets", s.get("packets"))
    else:
        out["retransmits"] = (end.get("sum_sent") or {}).get("retransmits")

    cpu = end.get("cpu_utilization_percent") or {}
    if cpu:
        # remote = target VM, local = client VM (iperf3's own naming)
        out["cpu_local"] = cpu.get("host_total")
        out["cpu_remote"] = cpu.get("remote_total")
    return out


# --------------------------------------------------------------------------
# CPU sampling (no pidstat on these images)
# --------------------------------------------------------------------------
def proc_ticks(host: Host, pattern: str) -> int | None:
    """utime+stime of the first PID whose cmdline is anchored to `pattern`."""
    cmd = (f"for p in $(pgrep -f {shlex.quote('^' + pattern)}); do "
           f"awk '{{print $14+$15; exit}}' /proc/$p/stat; break; done")
    try:
        rc, out = host.run(cmd, timeout=20)
        return int(out.split()[0])
    except Exception:                                   # noqa: BLE001
        return None


def system_ticks(host: Host) -> tuple[int, int] | None:
    """(busy, total) jiffies from /proc/stat."""
    try:
        rc, out = host.run("grep '^cpu ' /proc/stat", timeout=20)
        f = [int(x) for x in out.split()[1:]]
    except Exception:                                   # noqa: BLE001
        return None
    total = sum(f[:8])
    idle = f[3] + (f[4] if len(f) > 4 else 0)
    return total - idle, total


def run_with_retry(host: Host, cmd: str, timeout: float, attempts: int = 3) -> tuple[int, str]:
    """A saturated VPN pins both vCPUs and can starve the SSH channel.

    When that happens the channel read times out and the session is unusable;
    reconnect and repeat the measurement instead of losing the series.
    """
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            return host.run(cmd, timeout=timeout)
        except Exception as exc:                        # noqa: BLE001
            last = exc
            try:
                assert host.client is not None
                host.client.close()
            except Exception:                           # noqa: BLE001
                pass
            host.client = None
            time.sleep(3 + attempt * 3)
            try:
                host.connect()
            except RemoteError:
                time.sleep(5)
    raise RemoteError(f"{host.name}: command failed after {attempts} attempts: {last}")


def cpu_delta(t0: int | None, t1: int | None, elapsed: float, hz: int) -> float | None:
    if t0 is None or t1 is None or elapsed <= 0:
        return None
    return (t1 - t0) / hz / elapsed * 100.0      # percent of one core


# --------------------------------------------------------------------------
# lab control
# --------------------------------------------------------------------------
def clean_state(hosts: dict[str, Host], args) -> None:
    client, server = hosts["client"], hosts["server"]
    for h, path, extra in (
        (client, args.client_bin, f"ip route del {args.route} 2>/dev/null; "
                                  f"ip route del {args.server}/32 2>/dev/null; "
                                  f"ip link del tun0 2>/dev/null"),
        (server, args.server_bin, "nft delete table ip nat 2>/dev/null; "
                                  "sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'"),
    ):
        h.run(f"pkill -f {shlex.quote('^' + path)} 2>/dev/null; true", sudo=True, timeout=15)
        h.run(extra + "; true", sudo=True, timeout=15)
    hosts["target"].run("pkill -f '^iperf3 -s' 2>/dev/null; true", sudo=True, timeout=15)
    server.run(f"pkill -f {shlex.quote('^iperf3 -s')} 2>/dev/null; true", sudo=True, timeout=15)
    # /tmp is a 243 MB tmpfs on these VMs and the daemons log every packet;
    # a leftover 200 MB log stops the next run from even starting. rm/redirect
    # must run as root: /tmp has the sticky bit, so the unprivileged user cannot
    # delete root-owned logs, and fs.protected_regular=1 makes the root daemon
    # unable to append to a log the unprivileged user created.
    for h in (client, server, hosts["target"]):
        h.run("sh -c 'rm -f /tmp/*.log'", sudo=True, timeout=15)


def diagnostics(log_path: str, host: Host, lines: int = 20) -> str:
    """Log tail, or a clear note when logging is redirected to /dev/null."""
    if log_path == "/dev/null":
        return "(daemon stdout is /dev/null in this run; use --daemon-logs file to capture it)"
    return host.log_tail(log_path, lines)


def ensure_server_default_route(server: Host) -> str:
    rc, out = server.run("ip -4 route show default")
    if out.strip():
        return out.strip().splitlines()[0]
    server.run("ip route add default via 192.168.76.1 dev eth2", sudo=True, timeout=15)
    return "default via 192.168.76.1 dev eth2 (added by bench harness)"


def start_daemon_verified(host: Host, argv: list[str], log_path: str,
                          attempts: int = 3) -> None:
    """Start a daemon from an uploaded launcher script and confirm it is alive.

    The command is never quoted into `sh -c`: with a file there is nothing for
    the remote shell to mangle, and sudo stays in the foreground so it can read
    the password from stdin. (A nested `sh -c 'exec ... >>file'` intermittently
    produced no process and an empty log - a failed exec is invisible because
    the wrapper backgrounds itself.)
    """
    script = "/tmp/sdex_launch.sh"
    body = ("#!/bin/sh\n"
            "exec " + " ".join(shlex.quote(a) for a in argv) +
            f" >>{shlex.quote(log_path)} 2>&1 </dev/null\n")
    assert host.client is not None
    sftp = host.client.open_sftp()
    try:
        with sftp.file(script, "w") as fh:
            fh.write(body)
        sftp.chmod(script, 0o755)
    finally:
        sftp.close()

    for attempt in range(attempts):
        host.run(f"sh -c {shlex.quote('setsid sh ' + script + ' &')}",
                 sudo=True, timeout=20)
        time.sleep(1.5 + attempt)
        if host.pid_of(argv[0]):
            return
        if log_path != "/dev/null":
            print(f"      retry {attempt + 1}: {argv[0].rsplit('/', 1)[-1]} did not stay up "
                  f"({host.log_tail(log_path, 3)})")
    raise RemoteError(f"{host.name}: {argv[0]} failed to start after {attempts} attempts:\n"
                      + diagnostics(log_path, host))


def bring_up(target_ip: str, args, hosts: dict[str, Host],
             client_log: str, server_log: str) -> None:
    server, client = hosts["server"], hosts["client"]

    start_daemon_verified(server, [args.server_bin, "--listen", f"0.0.0.0:{args.port}",
                                   "--tun-ip", args.tun_server,
                                   "--threads", str(args.threads)], server_log)
    time.sleep(1.5)

    server.run(
        "echo 1 > /proc/sys/net/ipv4/ip_forward; "
        "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; "
        "echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter; "
        "echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter 2>/dev/null; "
        "nft add chain ip nat prerouting 2>/dev/null; true",
        sudo=True)
    prefix = target_ip.rsplit(".", 1)[0]
    rc, out = server.run("ip -o -4 addr show | awk '{print $2, $4}' | "
                         f"grep -F '{prefix}' | head -n1", sudo=True)
    if out.strip():
        iface = out.split()[0]
        server.run(f"nft add rule ip nat postrouting ip saddr 10.0.0.0/24 "
                   f"oifname {shlex.quote(iface)} masquerade 2>/dev/null || true", sudo=True)

    start_daemon_verified(client, [args.client_bin, "--server", f"{args.server}:{args.port}",
                                   "--tun-ip", args.tun_client, "--threads", str(args.threads),
                                   "--route", args.route], client_log)

    # Wait for the route, not for the clock: the client needs a moment to
    # create tun0 and install --route, and a fixed sleep races it.
    deadline = time.time() + 25
    ready = False
    while time.time() < deadline:
        rc, out = client.run(f"ip -4 route show | grep -F {shlex.quote(args.route)} || true")
        if args.route.split("/")[0] in out:
            ready = True
            break
        time.sleep(1.0)
    if not ready:
        raise RemoteError(
            "client never installed the route " + args.route + "\n"
            "client routes:\n" + client.run("ip -4 route")[1] + "\n"
            "client log:\n" + diagnostics(client_log, client))
    if not client.pid_of(args.client_bin):
        # the client exits on ECONNREFUSED when the server is not listening
        raise RemoteError("client did not stay up:\n" + diagnostics(client_log, client, 20))

    client.run("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; "
               "echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter 2>/dev/null; true", sudo=True)


def start_iperf_server(host: Host) -> None:
    host.start_daemon(["iperf3", "-s", "-p", "5201"], "/tmp/iperf3s.log", sudo=True)
    time.sleep(1.0)


def stop_iperf_server(host: Host) -> None:
    host.run("pkill -f '^iperf3 -s' 2>/dev/null; sleep 0.5; true", sudo=True, timeout=15)


# --------------------------------------------------------------------------
# one measurement
# --------------------------------------------------------------------------
def measure(client: Host, target_ip: str, scenario: str, argv_template: list[str],
            duration: int, result_path: str, label: str, args,
            cpu_pairs: list[tuple[str, Host, str]] | None = None) -> dict:
    argv = [a.format(d=duration) for a in argv_template]
    cmd = "iperf3 -c %s -p 5201 -J %s" % (shlex.quote(target_ip), " ".join(argv))

    _, hz_out = client.run("getconf CLK_TCK")
    hz = int(hz_out.strip() or 100)

    sys0 = system_ticks(client)
    samples0 = [(name, proc_ticks(h, pat)) for name, h, pat in (cpu_pairs or [])]
    t0 = time.time()

    rc, out = run_with_retry(client, cmd, timeout=duration + 120)

    elapsed = time.time() - t0
    sys1 = system_ticks(client)
    samples1 = [(name, proc_ticks(h, pat)) for name, h, pat in (cpu_pairs or [])]

    doc = parse_iperf_json(out)
    m = extract_metrics(doc)
    m.update({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "label": label,
        "scenario": scenario,
        "duration": duration,
        "rc": rc,
        "wall_s": round(elapsed, 2),
        "system_cpu_pct": (round(cpu_delta(sys0[0], sys1[0], elapsed, hz) or 0, 1)
                           if sys0 and sys1 else None),
    })
    for (name, t0v), (_, t1v) in zip(samples0, samples1):
        pct = cpu_delta(t0v, t1v, elapsed, hz)
        m[f"{name}_cpu_pct"] = round(pct, 1) if pct is not None else None
    if rc != 0 and not m.get("mbps"):
        m.setdefault("error", out.strip()[:300])
    with open(result_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(m) + "\n")
    return m


def fmt(m: dict) -> str:
    if not m.get("mbps"):
        return f"FAILED  {m.get('error', 'no data')[:70]}"
    extra = ""
    if m.get("lost_percent") is not None:
        extra = f"  jitter={float(m.get('jitter_ms') or 0):.3f}ms loss={float(m['lost_percent']):.2f}%"
    if m.get("retransmits") is not None:
        extra += f"  retr={m['retransmits']}"
    if m.get("client_cpu_pct") is not None:
        extra += f"  cpu={m['client_cpu_pct']}%"
    return f"{m['mbps']:9.2f} Mbps{extra}"


# --------------------------------------------------------------------------
# statistics
# --------------------------------------------------------------------------
def mannwhitneyu(x: list[float], y: list[float]) -> tuple[float, float]:
    """Two-sided Mann-Whitney U with normal approximation and tie correction."""
    n1, n2 = len(x), len(y)
    if n1 < 3 or n2 < 3:
        return float("nan"), float("nan")
    combined = [(v, 0) for v in x] + [(v, 1) for v in y]
    combined.sort()
    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    r1 = sum(ranks[k] for k in range(len(combined)) if combined[k][1] == 0)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    mu = n1 * n2 / 2.0
    n = n1 + n2
    # tie correction
    tie_sum = 0
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1][0] == combined[i][0]:
            j += 1
        t = j - i + 1
        tie_sum += t ** 3 - t
        i = j + 1
    sigma = math.sqrt(n1 * n2 / 12.0 * ((n + 1) - tie_sum / (n * (n - 1))))
    if sigma == 0:
        return u1, 1.0
    z = (u1 - mu) / sigma
    p = math.erfc(abs(z) / math.sqrt(2))
    return u1, p


def ci95(vals: list[float]) -> tuple[float, float]:
    if len(vals) < 2:
        return (float("nan"), float("nan"))
    m = statistics.mean(vals)
    se = statistics.stdev(vals) / math.sqrt(len(vals))
    half = 1.96 * se
    return (m - half, m + half)


def load_results(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def report(path: str, warmup: int, md_out: str) -> int:
    rows = load_results(path)
    if not rows:
        print(f"no results in {path}")
        return 1

    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        if r.get("scenario") == "ping":          # latency probe, not throughput
            continue
        groups.setdefault((r["label"], r["scenario"]), []).append(r)

    lines = ["# SDEx VPN — throughput benchmark", "",
             f"Source: `{os.path.relpath(path)}` — {len(rows)} iterations, "
             f"first {warmup} of each series discarded as warm-up.", ""]

    table = ["| config | scenario | n | mean Mbps | median | stdev | min | max | 95% CI | client CPU % | server CPU % | loss % |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    series: dict[tuple[str, str], list[float]] = {}
    for key in sorted(groups):
        label, scen = key
        vals = [r["mbps"] for r in groups[key] if r.get("mbps")]
        kept = vals[warmup:] if len(vals) > warmup else vals
        if not kept:
            table.append(f"| {label} | {scen} | 0 | — | — | — | — | — | — | — | — | — |")
            continue
        series[key] = kept
        lo, hi = ci95(kept)
        kept_rows = groups[key][warmup:] if len(groups[key]) > warmup else groups[key]

        def avg(field: str) -> str:
            xs: list[float] = [float(r[field]) for r in kept_rows if r.get(field) is not None]
            return f"{statistics.mean(xs):.1f}" if xs else "—"

        table.append(
            f"| {label} | {scen} | {len(kept)} | {statistics.mean(kept):.2f} | "
            f"{statistics.median(kept):.2f} | "
            f"{statistics.stdev(kept) if len(kept) > 1 else 0:.2f} | "
            f"{min(kept):.2f} | {max(kept):.2f} | "
            f"{lo:.2f}–{hi:.2f} | "
            f"{avg('client_cpu_pct')} | {avg('server_cpu_pct')} | {avg('lost_percent')} |"
        )
    lines += table

    # significance vs baseline where both exist
    lines += ["", "## Mann-Whitney U vs baseline (two-sided)", "",
              "| tunnel scenario | baseline | U | p | significant at 0.05 |",
              "|---|---|---|---|---|"]
    for (label, scen), vals in sorted(series.items()):
        if label != "tunnel":
            continue
        base = series.get(("baseline_a", scen)) or series.get(("baseline_b", scen))
        bname = "baseline_a" if ("baseline_a", scen) in series else "baseline_b"
        if not base:
            continue
        u, p = mannwhitneyu(vals, base)
        sig = "yes" if p == p and p < 0.05 else "no"
        lines.append(f"| {scen} | {bname} | {u:.1f} | {p:.4f} | {sig} |")

    text = "\n".join(lines) + "\n"
    with open(md_out, "w", encoding="utf-8") as fh:
        fh.write(text)

    # csv next to the jsonl
    csv_path = os.path.splitext(path)[0] + ".csv"
    with open(csv_path, "w", encoding="utf-8") as fh:
        keys = ["ts", "label", "scenario", "mbps", "jitter_ms", "lost_percent",
                "retransmits", "client_cpu_pct", "server_cpu_pct", "system_cpu_pct",
                "rc", "wall_s", "error"]
        fh.write(",".join(keys) + "\n")
        for r in rows:
            fh.write(",".join(str(r.get(k, "")) for k in keys) + "\n")

    print(text)
    print(f"written: {md_out}\nwritten: {csv_path}")
    return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="SDEx VPN throughput benchmark")
    ap.add_argument("mode", choices=["run", "report"])
    ap.add_argument("--results", default=None, help="JSONL path (default bench/<tag>.jsonl)")
    ap.add_argument("--tag", default="pilot", help="run label, used for filenames")
    ap.add_argument("--iterations", type=int, default=5)
    ap.add_argument("--baseline-iterations", type=int, default=0,
                    help="iterations for the no-tunnel baselines (0 = same as --iterations)")
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--duration", type=int, default=5)
    ap.add_argument("--scenarios", default=",".join(SCENARIOS),
                    help="comma-separated subset of: " + ",".join(SCENARIOS))
    ap.add_argument("--baseline", default="a,b", help="baselines to run: a,b or none")
    ap.add_argument("--ping-count", type=int, default=100, help="0 disables the latency probe")
    ap.add_argument("--md", default=None, help="markdown report path")

    ap.add_argument("--user", default="dupa")
    ap.add_argument("--password-file", default=os.path.expanduser("~/.hermes/vm_pass"))
    ap.add_argument("--client", default="192.168.67.2")
    ap.add_argument("--server", default="192.168.67.3")
    ap.add_argument("--target", default="192.168.76.4")
    ap.add_argument("--repo", default="$HOME/test/sdex_vpn")
    ap.add_argument("--port", type=int, default=51820)
    ap.add_argument("--tun-server", default="10.0.0.1")
    ap.add_argument("--tun-client", default="10.0.0.2")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--route", default="192.168.76.0/24")
    ap.add_argument("--no-cleanup", action="store_true")
    ap.add_argument("--daemon-logs", choices=["null", "file"], default="null",
                    help="where VPN daemons write stdout: 'null' measures the data path, "
                         "'file' keeps the per-packet logging (and its cost)")
    ap.add_argument("--extra-args", default="", help="extra iperf3 flags for every run")
    args = ap.parse_args()

    os.makedirs(RESULT_DIR, exist_ok=True)
    results = args.results or os.path.join(RESULT_DIR, f"{args.tag}.jsonl")
    md_out = args.md or os.path.join(RESULT_DIR, f"{args.tag}.md")

    if args.mode == "report":
        return report(results, args.warmup, md_out)

    # One run at a time: two overlapping runs share the same VMs, and the
    # loser's cleanup pkill kills the winner's daemons mid-series.
    lock_path = os.path.join(RESULT_DIR, ".lock")
    lock = open(lock_path, "w")
    try:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        sys.exit(f"another benchmark is running (lock {lock_path}); wait for it to finish")

    pw = read_password(args.password_file)
    hosts = {
        "client": Host("client", args.client, args.user, pw, None),
        "server": Host("server", args.server, args.user, pw, None),
        "target": Host("target", args.target, args.user, pw, None),
    }
    for h in hosts.values():
        h.connect()

    args.server_bin = resolve_binary(hosts["server"], args.repo, "server")
    args.client_bin = resolve_binary(hosts["client"], args.repo, "client")
    if not args.server_bin or not args.client_bin:
        sys.exit("client/server binaries not found under " + args.repo)

    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    baselines = [] if args.baseline == "none" else [b.strip() for b in args.baseline.split(",")]
    base_iters = args.baseline_iterations or args.iterations

    print(f"=== SDEx throughput benchmark [{args.tag}] ===")
    print(f"    tunnel iterations {args.iterations} (warm-up {args.warmup}), "
          f"{args.duration}s per run")
    print(f"    baseline iterations {base_iters if baselines else 'skipped'}")
    print(f"    scenarios  {', '.join(scenarios)}")
    print(f"    results    {results}")
    print()

    open(results, "w", encoding="utf-8").close()

    try:
        clean_state(hosts, args)
        print(f"server default route: {ensure_server_default_route(hosts['server'])}")

        # ---- baseline: no tunnel ------------------------------------------
        def baseline_argv(scen: str) -> list[str]:
            return list(BASELINE_SCENARIOS[scen]) + args.extra_args.split()

        if "a" in baselines:
            print(f"\n[baseline A] {args.client} -> {args.server} (segment A, no tunnel)")
            start_iperf_server(hosts["server"])
            for i in range(base_iters):
                for scen in scenarios:
                    if scen not in BASELINE_SCENARIOS:
                        continue
                    m = measure(hosts["client"], args.server, scen,
                                baseline_argv(scen), args.duration, results,
                                "baseline_a", args)
                    print(f"  {i:2d} {scen:9s} {fmt(m)}")
            stop_iperf_server(hosts["server"])
            clean_state(hosts, args)

        if "b" in baselines:
            print(f"\n[baseline B] {args.server} -> {args.target} (segment B, no tunnel)")
            start_iperf_server(hosts["target"])
            for i in range(base_iters):
                for scen in scenarios:
                    if scen not in BASELINE_SCENARIOS:
                        continue
                    m = measure(hosts["server"], args.target, scen,
                                baseline_argv(scen), args.duration, results,
                                "baseline_b", args)
                    print(f"  {i:2d} {scen:9s} {fmt(m)}")
            stop_iperf_server(hosts["target"])

        # ---- tunnel -------------------------------------------------------
        print("\n[tunnel] bringing SDEx up ...")
        start_iperf_server(hosts["target"])
        if args.daemon_logs == "null":
            client_log = server_log = "/dev/null"
            print("      daemon output -> /dev/null (per-packet println! otherwise "
                  "fills the 243 MB tmpfs and dominates the measurement)")
        else:
            client_log, server_log = "/tmp/sdex_client.log", "/tmp/sdex_server.log"
            # truncate as root: the daemon runs as root and fs.protected_regular
            # refuses to append to a file created by the unprivileged user
            for h, path in ((hosts["client"], client_log), (hosts["server"], server_log)):
                h.run(f"sh -c ': > {path}'", sudo=True)
            print("      daemon output -> /tmp (logging cost included in the numbers)")
        bring_up(args.target, args, hosts, client_log, server_log)

        rc, out = hosts["client"].run(f"ping -c 3 -W 2 {shlex.quote(args.target)}")
        print("      " + (out.splitlines()[-2] if len(out.splitlines()) > 1 else out))
        if rc != 0:
            print("      tunnel is NOT passing traffic; aborting tunnel phase")
            print("--- client routes\n" + hosts["client"].run("ip -4 route")[1])
            print("--- client procs\n" +
                  hosts["client"].run("pgrep -af 'sdex_vpn/target/release' || echo NONE")[1])
            print("--- client log\n" + diagnostics(client_log, hosts["client"], 15))
            print("--- server log\n" + diagnostics(server_log, hosts["server"], 15))
            print("--- disk\n" + hosts["client"].run("df -h /tmp | tail -1")[1])
            return 1

        if args.ping_count:
            print(f"\n[latency] ping -c {args.ping_count} {args.target} through the tunnel")
            rc, out = hosts["client"].run(
                f"ping -c {args.ping_count} -i 0.02 -W 2 {shlex.quote(args.target)}",
                timeout=args.ping_count * 0.5 + 30)
            tail = [l for l in out.splitlines() if "rtt" in l or "packet loss" in l]
            for l in tail:
                print("      " + l)
            with open(results, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"label": "tunnel", "scenario": "ping",
                                     "packets": args.ping_count,
                                     "ping_summary": tail, "rc": rc}) + "\n")

        print("\n[tunnel] throughput scenarios")
        cpu_pairs = [("client", hosts["client"], args.client_bin),
                     ("server", hosts["server"], args.server_bin)]
        for i in range(args.iterations):
            for scen in scenarios:
                m = measure(hosts["client"], args.target, scen,
                            SCENARIOS[scen] + args.extra_args.split(),
                            args.duration, results, "tunnel", args,
                            cpu_pairs=cpu_pairs)
                print(f"  {i:2d} {scen:9s} {fmt(m)}")
            if args.daemon_logs == "file":
                # keep tmpfs alive: the daemons write ~3 lines per packet
                for h, path in ((hosts["client"], client_log), (hosts["server"], server_log)):
                    rc, out = h.run(f"stat -c %s {path} 2>/dev/null || echo 0")
                    try:
                        if int(out.strip() or 0) > 32 * 1024 * 1024:
                            h.run(f"sh -c ': > {path}'", sudo=True)
                    except ValueError:
                        pass

    except RemoteError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if not args.no_cleanup:
            print("\n[cleanup] killing daemons and resetting kernel state ...")
            try:
                clean_state(hosts, args)
            except Exception as exc:                     # noqa: BLE001
                print(f"  cleanup warning: {exc}")
        for h in hosts.values():
            h.close()

    print(f"\nraw results: {results}")
    print(f"aggregate:   ./test/sdex_bench.sh report --results {results} --warmup {args.warmup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
