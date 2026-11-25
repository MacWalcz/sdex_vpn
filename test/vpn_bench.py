#!/usr/bin/env python3
"""Three-way tunnel benchmark: SDEx vs WireGuard vs OpenVPN on the same lab.

Same VM set, same iperf3 offers, same statistics as `sdex_bench.py` — only the
tunnel backend changes, so a difference in the numbers is attributable to the
tunnel and not to the procedure.

    ./test/vpn_bench.py run --vpn baseline   --iterations 10 --tag cmp
    ./test/vpn_bench.py run --vpn sdex       --iterations 30 --warmup 3 --tag cmp
    ./test/vpn_bench.py run --vpn wireguard  --iterations 30 --warmup 3 --tag cmp
    ./test/vpn_bench.py run --vpn openvpn    --iterations 30 --warmup 3 --tag cmp
    ./test/vpn_bench.py compare --tag cmp --warmup 3

Each `run` writes bench/<tag>_<vpn>.jsonl and appends every measurement as it
completes, so an interrupted run keeps its finished iterations.

Backends differ only in how eth0->tun forwarding is built:

    sdex       client/server binaries, tun0 10.0.0.2/10.0.0.1, UDP 51820
    wireguard  wg-quick interface `sdexbench`, 10.66.0.2/10.66.0.1, UDP 51821
    openvpn    TLS+AES-256-GCM, tun10, 10.67.0.2/10.67.0.1, UDP 1195

WireGuard runs in the kernel, so it has no userspace daemon to sample; its CPU
column is the client VM's whole-CPU figure (/proc/stat). That is reported as
"n/a" for the per-process columns rather than silently compared with SDEx's.
"""

from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import shlex
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sdex_vpn_test import Host, RemoteError, read_password, resolve_binary  # noqa: E402
from sdex_bench import (  # noqa: E402
    RESULT_DIR, SCENARIOS, bring_up as sdex_bring_up, ci95, fmt, load_results,
    mannwhitneyu, measure, ensure_server_default_route, start_iperf_server,
    stop_iperf_server, start_daemon_verified,
)

WG_IFACE = "sdexbench"          # < 15 chars, and not "tun0"
WG_SERVER_IP, WG_CLIENT_IP = "10.66.0.1", "10.66.0.2"
WG_PORT = 51821
OVPN_DEV = "tun10"              # never tun0: SDEx owns that name
OVPN_SERVER_IP, OVPN_CLIENT_IP = "10.67.0.1", "10.67.0.2"
OVPN_PORT = 1195

PROFILE = {
    "sdex": {"inner": "10.0.0.0/24", "dev": "tun0", "port": 51820,
             "cipher": "SDEx (BLAKE3-based)", "threads": "4 workers"},
    "wireguard": {"inner": "10.66.0.0/24", "dev": WG_IFACE, "port": WG_PORT,
                  "cipher": "ChaCha20-Poly1305", "threads": "kernel, multicore path"},
    "openvpn": {"inner": "10.67.0.0/24", "dev": OVPN_DEV, "port": OVPN_PORT,
                "cipher": "AES-256-GCM (TLS 1.3 control channel)",
                "threads": "single process"},
}


# --------------------------------------------------------------------------
# lab state
# --------------------------------------------------------------------------
def reset(hosts: dict[str, Host], args) -> None:
    """Kill every tunnel backend and reset kernel state on client + server."""
    client, server, target = hosts["client"], hosts["server"], hosts["target"]
    for h, pattern in ((client, args.client_bin), (server, args.server_bin)):
        if pattern:                       # never pkill with an empty anchor
            h.run(f"pkill -f {shlex.quote('^' + pattern)} 2>/dev/null; true",
                  sudo=True, timeout=15)
    per_host = f"""#!/bin/sh
pkill -f '^/usr/sbin/openvpn' 2>/dev/null
wg-quick down {WG_IFACE} 2>/dev/null
ip link del {WG_IFACE} 2>/dev/null
ip link del {OVPN_DEV} 2>/dev/null
ip link del tun0 2>/dev/null
exit 0
"""
    for h in (client, server):
        sudo_script(h, per_host, "vpnbench_reset.sh", timeout=40)
    sudo_script(server, """#!/bin/sh
nft delete table ip nat 2>/dev/null
echo 0 > /proc/sys/net/ipv4/ip_forward
exit 0
""", "vpnbench_reset2.sh", timeout=30)
    client.run("ip route del 192.168.76.0/24 2>/dev/null; "
               "ip route del 192.168.67.3/32 2>/dev/null; true", sudo=True, timeout=20)
    for h in (client, server, target):
        h.run("pkill -f '^iperf3 -s' 2>/dev/null; sh -c 'rm -f /tmp/*.log'; true",
              sudo=True, timeout=15)


def server_forwarding(hosts: dict[str, Host], inner: str, target_ip: str) -> str:
    """ip_forward + loose rp_filter + masquerade of the tunnel subnet out the
    segment that holds the target. Returns the egress interface it used."""
    server = hosts["server"]
    prefix = target_ip.rsplit(".", 1)[0]
    rc, out = server.run("ip -o -4 addr show | awk '{print $2, $4}' | "
                         f"grep -F '{prefix}' | head -n1")
    iface = out.split()[0] if out.strip() else "eth2"

    body = f"""#!/bin/sh
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
echo 0 > /proc/sys/net/ipv4/conf/{OVPN_DEV}/rp_filter 2>/dev/null
echo 0 > /proc/sys/net/ipv4/conf/{WG_IFACE}/rp_filter 2>/dev/null
echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter 2>/dev/null
nft add table ip nat 2>/dev/null
nft add chain ip nat prerouting 2>/dev/null
nft add chain ip nat postrouting '{{ type nat hook postrouting priority 100 ; }}' 2>/dev/null
nft add rule ip nat postrouting ip saddr {inner} oifname {iface} masquerade 2>/dev/null
exit 0
"""
    sudo_script(server, body, "vpnbench_fwd.sh", timeout=40)
    rc, out = server.run("nft list table ip nat 2>/dev/null", sudo=True)
    ok = "masquerade" in out and iface in out
    return iface if ok else f"{iface} (MASQUERADE MISSING)"


def wait_route(host: Host, cidr: str, deadline_s: float = 30) -> bool:
    deadline = time.time() + deadline_s
    net = cidr.rsplit(".", 1)[0]
    while time.time() < deadline:
        rc, out = host.run("ip -4 route")
        if net in out:
            return True
        time.sleep(1.0)
    return False


def write_remote(host: Host, path: str, text: str, mode: str = "600") -> None:
    assert host.client is not None
    sftp = host.client.open_sftp()
    tmp = "/tmp/.vpnbench.tmp"
    try:
        with sftp.file(tmp, "w") as fh:
            fh.write(text)
    finally:
        sftp.close()
    host.run(f"sh -c {shlex.quote('mv %s %s && chown root:root %s && chmod %s %s'
                                 % (tmp, path, path, mode, path))}", sudo=True, timeout=20)


def sudo_script(host: Host, body: str, name: str = "vpnbench.sh",
                timeout: float = 60) -> tuple[int, str]:
    """Upload a shell script and run it with ONE sudo.

    `sudo a; b` elevates only `a`, so a semicolon chain silently runs half its
    commands as the unprivileged user: sysctl writes fail and nft rules vanish
    while the caller sees rc=0. One `sudo sh <file>` keeps every line privileged.
    """
    path = f"/tmp/{name}"
    assert host.client is not None
    sftp = host.client.open_sftp()
    try:
        with sftp.file(path, "w") as fh:
            fh.write(body)
        sftp.chmod(path, 0o700)
    finally:
        sftp.close()
    return host.run(f"sh {path}", sudo=True, timeout=timeout)


# --------------------------------------------------------------------------
# backends
# --------------------------------------------------------------------------
def up_sdex(args, hosts, client_log: str, server_log: str) -> str:
    sdex_bring_up(args.target, args, hosts, client_log, server_log)
    return "tun0"


def up_wireguard(args, hosts, client_log: str, server_log: str) -> str:
    server, client = hosts["server"], hosts["client"]

    def pubkey(h: Host, key: str) -> str:
        rc, out = h.run(f"sh -c {shlex.quote('wg pubkey < ' + key)}", sudo=True)
        return out.strip().splitlines()[-1]

    srv_pub = pubkey(server, "/etc/wireguard/srv.key")
    cli_pub = pubkey(client, "/etc/wireguard/cli.key")

    srv_conf = (f"[Interface]\nAddress = {WG_SERVER_IP}/24\nListenPort = {WG_PORT}\n"
                "PrivateKey = __KEY__\n\n"
                f"[Peer]\nPublicKey = {cli_pub}\nAllowedIPs = {WG_CLIENT_IP}/32\n")
    cli_conf = (f"[Interface]\nAddress = {WG_CLIENT_IP}/24\nPrivateKey = __KEY__\n\n"
                f"[Peer]\nPublicKey = {srv_pub}\nEndpoint = {args.server}:{WG_PORT}\n"
                f"AllowedIPs = {WG_SERVER_IP}/32, {args.route}\n"
                "PersistentKeepalive = 25\n")

    for h, conf, keyfile in ((server, srv_conf, "/etc/wireguard/srv.key"),
                             (client, cli_conf, "/etc/wireguard/cli.key")):
        write_remote(h, f"/etc/wireguard/{WG_IFACE}.conf", conf, "600")
        h.run(f"sh -c {shlex.quote('KEY=$(cat %s); sed -i \"s|__KEY__|$KEY|\" '
                                   '/etc/wireguard/%s.conf' % (keyfile, WG_IFACE))}",
              sudo=True, timeout=20)

    rc, out = client.run(f"wg-quick up {WG_IFACE}", sudo=True, timeout=60)
    if rc != 0:
        raise RemoteError(f"client wg-quick up failed: {out}")
    rc, out = server.run(f"wg-quick up {WG_IFACE}", sudo=True, timeout=60)
    if rc != 0:
        raise RemoteError(f"server wg-quick up failed: {out}")

    egress = server_forwarding(hosts, PROFILE["wireguard"]["inner"], args.target)
    if not wait_route(client, args.route, 20):
        raise RemoteError("client has no route to " + args.route + " after wg-quick up")

    # The first packet triggers the handshake and can take seconds; nudge it
    # before the caller starts timing anything.
    deadline = time.time() + 20
    while time.time() < deadline:
        rc, out = client.run(f"wg show {WG_IFACE} latest-handshakes")
        if out.strip() and not out.strip().split()[-1].endswith("0"):
            break
        client.run(f"ping -c 1 -W 1 {WG_SERVER_IP}")
        time.sleep(1.0)
    return f"{WG_IFACE} (egress {egress})"


def up_openvpn(args, hosts, client_log: str, server_log: str) -> str:
    server, client = hosts["server"], hosts["client"]
    # PUSH_REPLY parses `route` as "network netmask", not CIDR: pushing
    # "route 192.168.76.0/24" makes the client log "must be a valid address"
    # and silently skip the route (tunnel comes up, nothing routes into it).
    net = ipaddress.IPv4Network(args.route, strict=False)
    srv_conf = f"""port {OVPN_PORT}
proto udp
dev {OVPN_DEV}
dev-type tun
topology subnet
server 10.67.0.0 255.255.255.0
push "route {net.network_address} {net.netmask}"
ca /etc/openvpn/keys/ca.crt
cert /etc/openvpn/keys/server.crt
key /etc/openvpn/keys/server.key
tls-crypt /etc/openvpn/keys/ta.key
dh none
ecdh-curve prime256v1
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
persist-key
persist-tun
verb 3
status /tmp/openvpn-status.log
"""
    cli_conf = f"""client
dev {OVPN_DEV}
dev-type tun
proto udp
remote {args.server} {OVPN_PORT}
nobind
topology subnet
ca /etc/openvpn/keys/ca.crt
cert /etc/openvpn/keys/client.crt
key /etc/openvpn/keys/client.key
tls-crypt /etc/openvpn/keys/ta.key
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
persist-key
persist-tun
verb 3
"""
    write_remote(server, "/etc/openvpn/server/sdex-bench.conf", srv_conf)
    write_remote(client, "/etc/openvpn/client/sdex-bench.conf", cli_conf)

    start_daemon_verified(server, ["/usr/sbin/openvpn", "--config",
                                   "/etc/openvpn/server/sdex-bench.conf"], server_log)
    deadline = time.time() + 25
    while time.time() < deadline:
        rc, out = server.run(f"ip -4 -br a show {OVPN_DEV} 2>/dev/null")
        if OVPN_SERVER_IP in out:
            break
        time.sleep(1.0)
    else:
        raise RemoteError("openvpn server never created " + OVPN_DEV)

    egress = server_forwarding(hosts, PROFILE["openvpn"]["inner"], args.target)

    start_daemon_verified(client, ["/usr/sbin/openvpn", "--config",
                                   "/etc/openvpn/client/sdex-bench.conf"], client_log)
    if not wait_route(client, args.route, 30):
        raise RemoteError("openvpn client never installed the route " + args.route
                          + "\nroute:\n" + client.run("ip -4 route")[1])
    return f"{OVPN_DEV} (egress {egress})"


BACKENDS = {"sdex": up_sdex, "wireguard": up_wireguard, "openvpn": up_openvpn}


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------
def run(args) -> int:
    vpn = args.vpn
    results = os.path.join(RESULT_DIR, f"{args.tag}_{vpn}.jsonl")
    os.makedirs(RESULT_DIR, exist_ok=True)

    lock_path = os.path.join(RESULT_DIR, ".lock")
    lock = open(lock_path, "w")
    try:
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError):
        sys.exit(f"another benchmark is running (lock {lock_path})")

    pw = read_password(args.password_file)
    hosts = {
        "client": Host("client", args.client, args.user, pw, None),
        "server": Host("server", args.server, args.user, pw, None),
        "target": Host("target", args.target, args.user, pw, None),
    }
    for h in hosts.values():
        h.connect()

    args.server_bin = resolve_binary(hosts["server"], args.repo, "server") or args.server_bin
    args.client_bin = resolve_binary(hosts["client"], args.repo, "client") or args.client_bin
    scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip()]

    print(f"=== three-way tunnel benchmark [{args.tag}] vpn={vpn} ===")
    print(f"    iterations {args.iterations} (warm-up {args.warmup}), {args.duration}s each")
    print(f"    scenarios  {', '.join(scenarios)}")
    print(f"    results    {results}\n")
    open(results, "w", encoding="utf-8").close()

    try:
        reset(hosts, args)
        print(f"server default route: {ensure_server_default_route(hosts['server'])}")

        if vpn == "baseline":
            cases = [("baseline_a", hosts["client"], hosts["server"]),
                     ("baseline_b", hosts["server"], hosts["target"])]
            for label, src, dst in cases:
                print(f"\n[{label}] {src.addr} -> {dst.addr} (no tunnel)")
                start_iperf_server(dst)
                for i in range(args.iterations):
                    for scen in scenarios:
                        m = measure(src, dst.addr, scen, list(SCENARIOS[scen]),
                                    args.duration, results, label, args)
                        print(f"  {i:2d} {scen:9s} {fmt(m)}")
                stop_iperf_server(dst)
                reset(hosts, args)
            print(f"\nraw results: {results}")
            return 0

        print(f"\n[tunnel:{vpn}] bringing it up ...")
        start_iperf_server(hosts["target"])
        # daemon stdout -> /dev/null: SDEx logs every packet and would fill the
        # 243 MB tmpfs, which is how the documented run was measured too.
        client_log = server_log = "/dev/null"
        status = BACKENDS[vpn](args, hosts, client_log, server_log)
        print(f"      tunnel up: {status}")

        # First traffic can trigger the WireGuard handshake or the OpenVPN TLS
        # connect and take seconds; wait for the tunnel to actually pass
        # packets instead of failing on the first three probes.
        deadline = time.time() + 30
        while time.time() < deadline:
            rc, _ = hosts["client"].run(f"ping -c 2 -W 2 {shlex.quote(args.target)}")
            if rc == 0:
                break
            time.sleep(2)

        rc, out = hosts["client"].run(f"ping -c 3 -W 2 {shlex.quote(args.target)}")
        print("      " + (out.splitlines()[-2] if len(out.splitlines()) > 1 else out))
        if rc != 0:
            print("      tunnel is NOT passing traffic; aborting")
            print("--- client routes\n" + hosts["client"].run("ip -4 route")[1])
            print("--- server routes\n" + hosts["server"].run("ip -4 route")[1])
            print("--- nft\n" + hosts["server"].run("nft list table ip nat", sudo=True)[1])
            return 1

        mtus = {}
        for name in ("client", "server"):
            rc, out = hosts[name].run(
                f"ip link show {PROFILE[vpn]['dev']} 2>/dev/null | "
                "grep -o 'mtu [0-9]*' | head -1")
            mtus[name] = out.strip() or "n/a"
        print(f"      MTU: client {mtus['client']}, server {mtus['server']}")

        if args.ping_count:
            print(f"\n[latency] ping -c {args.ping_count}")
            rc, out = hosts["client"].run(
                f"ping -c {args.ping_count} -i 0.02 -W 2 {shlex.quote(args.target)}",
                timeout=args.ping_count * 0.5 + 30)
            tail = [l for l in out.splitlines() if "rtt" in l or "packet loss" in l]
            for l in tail:
                print("      " + l)
            with open(results, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"label": vpn, "scenario": "ping",
                                     "packets": args.ping_count, "ping_summary": tail,
                                     "rc": rc}) + "\n")

        if vpn == "sdex":
            cpu_pairs = [("client", hosts["client"], args.client_bin),
                         ("server", hosts["server"], args.server_bin)]
        elif vpn == "openvpn":
            cpu_pairs = [("client", hosts["client"], "/usr/sbin/openvpn"),
                         ("server", hosts["server"], "/usr/sbin/openvpn")]
        else:
            cpu_pairs = []      # in-kernel: no daemon to sample

        print(f"\n[tunnel:{vpn}] throughput scenarios")
        for i in range(args.iterations):
            for scen in scenarios:
                m = measure(hosts["client"], args.target, scen,
                            list(SCENARIOS[scen]), args.duration, results, vpn, args,
                            cpu_pairs=cpu_pairs)
                print(f"  {i:2d} {scen:9s} {fmt(m)}")

    except RemoteError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if not args.no_cleanup:
            print("\n[cleanup] ...")
            try:
                reset(hosts, args)
            except Exception as exc:                     # noqa: BLE001
                print(f"  cleanup warning: {exc}")
        for h in hosts.values():
            h.close()

    print(f"\nraw results: {results}")
    return 0


# --------------------------------------------------------------------------
# compare
# --------------------------------------------------------------------------
def series(rows: list[dict], label: str, warmup: int) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for r in rows:
        if r.get("label") != label or r.get("scenario") == "ping" or not r.get("mbps"):
            continue
        out.setdefault(r["scenario"], []).append(r)
    return {k: v[warmup:] if len(v) > warmup else v for k, v in out.items()}


def stats(rows: list[dict]) -> dict:
    vals = [r["mbps"] for r in rows]
    lo, hi = ci95(vals)
    def avg(*fields):
        xs = [float(r[f]) for r in rows for f in fields if r.get(f) is not None]
        return statistics.mean(xs) if xs else None
    return {"n": len(vals), "mean": statistics.mean(vals),
            "median": statistics.median(vals),
            "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "min": min(vals), "max": max(vals), "lo": lo, "hi": hi,
            "client_cpu": avg("client_cpu_pct"), "server_cpu": avg("server_cpu_pct"),
            "system_cpu": avg("system_cpu_pct"), "loss": avg("lost_percent"),
            "retr": avg("retransmits"), "jitter": avg("jitter_ms")}


def compare(args) -> int:
    files = {v: os.path.join(RESULT_DIR, f"{args.tag}_{v}.jsonl")
             for v in ("baseline", "sdex", "wireguard", "openvpn")}
    missing = [v for v, p in files.items() if not os.path.exists(p)]
    if missing:
        sys.exit("missing result files for: " + ", ".join(missing))

    raw = {v: load_results(p) for v, p in files.items()}

    base: dict[str, dict[str, list[dict]]] = {}
    for r in raw["baseline"]:
        if r.get("scenario") == "ping" or not r.get("mbps"):
            continue
        base.setdefault(r["label"], {}).setdefault(r["scenario"], []).append(r)
    for label in base:
        for scen, rows in base[label].items():
            base[label][scen] = rows[args.warmup:] if len(rows) > args.warmup else rows

    tun = {v: series(raw[v], v, args.warmup) for v in ("sdex", "wireguard", "openvpn")}

    scen_order = [s for s in SCENARIOS if any(s in tun[v] for v in ("sdex", "wireguard", "openvpn"))]
    lines = ["# SDEx vs WireGuard vs OpenVPN — same lab, same procedure", ""]
    lines += [f"Source: `bench/{args.tag}_{{baseline,sdex,wireguard,openvpn}}.jsonl`; "
              f"first {args.warmup} iterations of each series discarded as warm-up.", ""]

    lines += ["## Configurations compared", "",
              "| tunnel | inner subnet | device | transport | cipher | parallelism |",
              "|---|---|---|---|---|---|"]
    for v in ("sdex", "wireguard", "openvpn"):
        p = PROFILE[v]
        lines.append(f"| {v} | {p['inner']} | {p['dev']} | UDP/{p['port']} | "
                     f"{p['cipher']} | {p['threads']} |")

    lines += ["", "## Baseline (no tunnel)", "",
              "| path | scenario | n | mean Mbps | stdev | 95% CI |", "|---|---|---|---|---|---|"]
    for label in ("baseline_a", "baseline_b"):
        for s in scen_order:
            rows = base.get(label, {}).get(s)
            if not rows:
                continue
            st = stats(rows)
            lines.append(f"| {label} | {s} | {st['n']} | {st['mean']:.2f} | "
                         f"{st['stdev']:.2f} | {st['lo']:.2f}–{st['hi']:.2f} |")

    lines += ["", "## Through the tunnel (Mbps)", "",
              "| scenario | SDEx | WireGuard | OpenVPN | best |", "|---|---|---|---|---|"]
    for s in scen_order:
        cells, means = [], {}
        for v in ("sdex", "wireguard", "openvpn"):
            rows = tun[v].get(s)
            if rows:
                means[v] = statistics.mean([r["mbps"] for r in rows])
                cells.append(f"{means[v]:.2f}")
            else:
                cells.append("—")
        best = max(means, key=means.get) if means else "—"
        lines.append(f"| {s} | {cells[0]} | {cells[1]} | {cells[2]} | {best} |")

    lines += ["", "## Full statistics per tunnel", "",
              "| tunnel | scenario | n | mean | median | stdev | min | max | 95% CI | "
              "client CPU % | server CPU % | loss % | retrans |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for v in ("sdex", "wireguard", "openvpn"):
        for s in scen_order:
            rows = tun[v].get(s)
            if not rows:
                continue
            st = stats(rows)
            cc = f"{st['client_cpu']:.1f}" if st["client_cpu"] is not None else "—"
            sc = f"{st['server_cpu']:.1f}" if st["server_cpu"] is not None else "—"
            sysc = f"{st['system_cpu']:.0f}" if st["system_cpu"] is not None else "—"
            if st["client_cpu"] is None:
                cc = f"({sysc} sys)" if st["system_cpu"] is not None else "—"
            loss = f"{st['loss']:.1f}" if st["loss"] is not None else "—"
            retr = f"{st['retr']:.0f}" if st["retr"] is not None else "—"
            lines.append(f"| {v} | {s} | {st['n']} | {st['mean']:.2f} | {st['median']:.2f} | "
                         f"{st['stdev']:.2f} | {st['min']:.2f} | {st['max']:.2f} | "
                         f"{st['lo']:.2f}–{st['hi']:.2f} | {cc} | {sc} | {loss} | {retr} |")

    lines += ["", "## Relative to the no-tunnel path", "",
              "| scenario | baseline | SDEx | WireGuard | OpenVPN |", "|---|---|---|---|---|"]
    for s in scen_order:
        brows = base.get("baseline_a", {}).get(s)
        if not brows:
            continue
        bmean = statistics.mean([r["mbps"] for r in brows])
        cells = []
        for v in ("sdex", "wireguard", "openvpn"):
            rows = tun[v].get(s)
            cells.append(f"{statistics.mean([r['mbps'] for r in rows]) / bmean * 100:.2f}%"
                         if rows else "—")
        lines.append(f"| {s} | {bmean:.2f} | {cells[0]} | {cells[1]} | {cells[2]} |")

    lines += ["", "## Pairwise Mann-Whitney U (two-sided)", "",
              "| scenario | pair | U | p | significant at 0.05 |", "|---|---|---|---|---|"]
    pairs = (("sdex", "wireguard"), ("sdex", "openvpn"), ("wireguard", "openvpn"))
    for s in scen_order:
        for a, b in pairs:
            ra, rb = tun[a].get(s), tun[b].get(s)
            if not ra or not rb:
                continue
            u, p = mannwhitneyu([r["mbps"] for r in ra], [r["mbps"] for r in rb])
            lines.append(f"| {s} | {a} vs {b} | {u:.1f} | {p:.4f} | "
                         f"{'yes' if p == p and p < 0.05 else 'no'} |")

    lines += ["", "## Latency (ping, idle tunnel)", "",
              "| tunnel | packets | summary |", "|---|---|---|"]
    for v in ("sdex", "wireguard", "openvpn"):
        for r in load_results(files[v]):
            if r.get("scenario") == "ping":
                lines.append(f"| {v} | {r.get('packets')} | "
                             + " / ".join(x.strip() for x in r.get("ping_summary", [])) + " |")

    # supplementary ceiling probe: offers above 1 Gbps for the stacks the
    # prescribed offers do not saturate (written by the extra probe run)
    ceiling = {}
    for v in ("sdex", "wireguard", "openvpn"):
        p = os.path.join(RESULT_DIR, f"{args.tag}_{v}_ceiling.jsonl")
        if os.path.exists(p):
            ceiling[v] = load_results(p)
    if ceiling:
        lines += ["", "## Supplementary UDP ceiling probe (offers above 1 Gbps)", "",
                  "| tunnel | scenario | n | mean Mbps | loss % |", "|---|---|---|---|---|"]
        for v, rows in ceiling.items():
            by: dict[str, list[dict]] = {}
            for r in rows:
                if r.get("mbps"):
                    by.setdefault(r["scenario"], []).append(r)
            for s in sorted(by):
                rs = by[s]
                mb = [r["mbps"] for r in rs]
                loss = [r["lost_percent"] for r in rs if r.get("lost_percent") is not None]
                lines.append(f"| {v} | {s} | {len(mb)} | {statistics.mean(mb):.1f} | "
                             f"{statistics.mean(loss) if loss else 0:.1f} |")

    text = "\n".join(lines) + "\n"
    md = os.path.join(RESULT_DIR, f"{args.tag}_comparison.md")
    with open(md, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)
    print(f"written: {md}")
    return 0


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="SDEx vs WireGuard vs OpenVPN benchmark")
    ap.add_argument("mode", choices=["run", "compare"])
    ap.add_argument("--vpn", choices=["baseline", "sdex", "wireguard", "openvpn"],
                    default="sdex")
    ap.add_argument("--tag", default="cmp")
    ap.add_argument("--iterations", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--duration", type=int, default=5)
    ap.add_argument("--scenarios", default=",".join(SCENARIOS))
    ap.add_argument("--ping-count", type=int, default=100)
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
    ap.add_argument("--server-bin", default="", help="override the SDEx server binary path")
    ap.add_argument("--client-bin", default="", help="override the SDEx client binary path")
    ap.add_argument("--no-cleanup", action="store_true")
    args = ap.parse_args()
    return compare(args) if args.mode == "compare" else run(args)


if __name__ == "__main__":
    sys.exit(main())
