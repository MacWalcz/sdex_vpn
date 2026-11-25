# SDEx VPN — Infrastructure and Test Lab

This document describes the machines the project is developed and measured on:
what they are, how they are wired, how to reach them, what their network state
is, and what currently breaks. It was produced from the live lab over SSH on
2026-11-22 in two passes:

* **pass 1** — baseline inventory (three VMs, the server still had its DHCP leg);
* **pass 2** — after the DHCP client and the `10.77.15.0/25` leg were removed
  from `sdex-server`. That removed the server's **default route**, which the
  binary requires, so the VPN stopped starting. Section 7 documents the failure,
  the end-to-end test matrix, and the fix applied here (a route added by a
  small systemd unit — no project code was changed).

Companion documents:

* `doc/doc.md` — code architecture, the SDEx algorithm, engineering decisions.
* `test/sdex_vpn_test.py` — the automated end-to-end smoke test that drives
  these three VMs over SSH.

---

## 1. Purpose and scope

The lab exists to answer one question: *does a packet sent from the client reach
a host that is only reachable through the VPN server, and what does that cost?*

It is deliberately small and deliberately **routed, not bridged**:

* the client and the HTTP target sit in two different `/24` segments and have
  **no route to each other**;
* the VPN server is the only machine with a leg in both segments;
* therefore any successful `client -> http` packet must have travelled through
  `tun0` on both ends.

That property is what makes the ping test meaningful. If the client could reach
the HTTP host natively, a "working VPN" result would prove nothing.

Scope: hypervisor/host wiring, per-VM addressing and routing, SSH access, kernel
prerequisites (forwarding, `rp_filter`, nftables NAT), the current failure, the
verified workaround, and the commands to re-inspect all of it. It does not cover
the SDEx algorithm or benchmark statistics — see `doc/doc.md`.

---

## 2. Topology

```
                       WSL host: DESKTOP-79NDBAC
        ┌──────────────────────┬─────────────────────────┐
        │ eth0 192.168.67.1/24 │ eth2 192.168.76.1/24    │
        │  (segment A)         │  (segment B)            │
        └──────────┬───────────┴───────────┬─────────────┘
                   │                       │
        ┌──────────┴─────────┐   ┌─────────┴──────────┐
        │ sdex-client        │   │ sdex-http          │
        │ eth1 192.168.67.2  │   │ eth1 192.168.76.4  │
        │ no default route   │   │ no default route   │
        └──────────┬─────────┘   └─────────┬──────────┘
                   │                       │
                   │      ┌────────────────┴──────────────┐
                   │      │ sdex-server                   │
                   └──────┤ eth1 192.168.67.3/24  (A)     │
                          │ eth2 192.168.76.2/24  (B)     │
                          │ eth0 DOWN, no address         │
                          │ no default route  <- blocker  │
                          └───────────────────────────────┘

        tunnel (once both binaries run):
        client tun0 10.0.0.2  ── UDP/51820 ──  server tun0 10.0.0.1
        split route used by the test: 192.168.76.0/24 -> tun0 on the client
```

All three VMs are Hyper-V guests (MAC prefix `00:15:5d`), Debian 13 (trixie),
kernel 6.12.x, 2 vCPU, 396 MiB RAM, 5.4 GB root filesystem. The two `192.168.x`
segments are separate virtual switches presented to WSL as `eth0` and `eth2`;
the host has one address in each and is *not* a router between them.

The `10.77.15.0/25` management network is gone from the server. It used to give
the VM a DHCP address (`10.77.15.66/25`) and, with it, a default route via
`10.77.15.1`. The host still has `10.77.15.68/25` on its own `eth1` for internet
access, but there is no longer a path between the server and that network.

### 2.1 Address plan

| Machine       | Interface | Address / prefix      | Role                                   |
|---------------|-----------|-----------------------|----------------------------------------|
| sdex-client   | eth1      | 192.168.67.2/24       | VPN client, segment A                  |
| sdex-client   | eth0      | — (NO-CARRIER)        | spare adapter, unused                  |
| sdex-server   | eth1      | 192.168.67.3/24       | VPN server UDP/51820, segment A        |
| sdex-server   | eth2      | 192.168.76.2/24       | external leg, segment B                |
| sdex-server   | eth0      | — (DOWN, no address)  | was DHCP 10.77.15.66/25 until 2026-11-22 |
| sdex-http     | eth1      | 192.168.76.4/24       | `python3 -m http.server 80`            |
| sdex-http     | eth0      | — (NO-CARRIER)        | spare adapter, unused                  |
| WSL host      | eth0      | 192.168.67.1/24       | segment A gateway/orchestrator         |
| WSL host      | eth2      | 192.168.76.1/24       | segment B gateway/orchestrator         |
| WSL host      | eth1      | 10.77.15.68/25        | internet only (not a path to the VMs)  |
| tunnel        | tun0      | 10.0.0.1 (server), 10.0.0.2 (client) | inner IPs, `/24`, no gateway |

---

## 3. Per-host state (`ip a`, `ip route`)

State below is with **no VPN process running** (pass 2).

### 3.1 sdex-client — 192.168.67.2

```
2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP>  mtu 1500 state UP
    inet 192.168.67.2/24 brd 192.168.67.255 scope global eth1

$ ip -4 route
192.168.67.0/24 dev eth1 proto kernel scope link src 192.168.67.2
192.168.67.3 dev eth1 proto static              <- residue, see 7.3
```

Two facts matter here:

1. **No default route.** The client can only talk to `192.168.67.0/24` until the
   VPN client installs routes.
2. `eth1` is the only live NIC; `eth0` is `NO-CARRIER` on client and HTTP host
   (leftover adapter from the VM template, harmless).

The `/32` route to `192.168.67.3` is left behind by a previous client run: the
client adds a host route to the server before touching the tunnel
(`add_host_route`) and never removes it. It disappears with a reboot (it is not
persistent) and is harmless — it just pins the server address to `eth1`.

Interface MTUs are all 1500 (`lo` is 65536). The Rust code does not call
`.mtu(...)` on the tun builder, so `tun0` also comes up at the kernel default of
1500. Encapsulation adds 28 bytes (IPv4 + UDP) on the wire, so a 1500-byte inner
packet cannot fit in a 1500-byte outer frame — see section 8.3.

### 3.2 sdex-server — 192.168.67.3 / 192.168.76.2

```
2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 state DOWN
    (no address)
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.67.3/24 brd 192.168.67.255 scope global eth1
4: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.76.2/24 brd 192.168.76.255 scope global eth2

$ ip -4 route
default via 192.168.76.1 dev eth2                          <- from the lab unit
192.168.67.0/24 dev eth1 proto kernel scope link src 192.168.67.3
192.168.76.0/24 dev eth2 proto kernel scope link src 192.168.76.2
```

The `default` line is not part of the VM's base configuration: it is added by
`sdex-lab-default-route.service`, a small unit installed on 2026-11-22 (section
7.2). Without it the table has only the two on-link routes and the server binary
aborts at startup (`Error: "Couldnt find default route"`) before it creates
`tun0` or any nftables state — that was the state right after the DHCP leg was
removed. Section 7.1 has the failure, 7.2 the fix.

`hostname -I` now prints `192.168.67.3 192.168.76.2`. Previously it also showed
the DHCP address first; do not use that order to infer which NIC faces which
segment.

The removed DHCP leg leaves a residue: right after the change, `ss -lunp` still
showed a `dhcpcd` socket bound to `10.77.15.66:68` although the address no longer
existed. It clears on reboot; until then, ignore it.

### 3.3 sdex-http — 192.168.76.4

```
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 192.168.76.4/24 brd 192.168.76.255 scope global eth1

$ ip -4 route
192.168.76.0/24 dev eth1 proto kernel scope link src 192.168.76.4
```

Same shape as the client: on-link only, no default route. This is what keeps
the two segments mutually unreachable without the VPN. The HTTP host has
`python3` and `nftables` but **no `curl`** installed.

No policy routing is configured on any VM: `ip -4 rule` shows only the standard
`local` / `main` / `default` tables on all three hosts.

---

## 4. Reachability matrix (observed, pass 2)

Two pings per pair (`ping -c 2 -W 1`), no VPN running.

| from \ to       | 192.168.67.2 | 192.168.67.3 | 192.168.76.2 | 192.168.76.4 |
|-----------------|--------------|--------------|--------------|--------------|
| sdex-client     | 0% (0.019ms) | 0% (0.236ms) | unreachable  | unreachable  |
| sdex-server     | 0% (0.389ms) | 0% (0.020ms) | 0% (0.018ms) | 0% (0.329ms) |
| sdex-http       | unreachable  | unreachable  | 0% (0.235ms) | 0% (0.024ms) |

"Unreachable" is *routing*, not firewalling: `ping` fails immediately with
"No route to host" because neither the client nor the HTTP host has a route into
the other `/24`. The server reaches both segments; it can no longer reach
`10.77.15.0/25` at all.

Latency figures are sub-millisecond because all three VMs are on one Hyper-V
host; they are a sanity check, not a performance result. Real comparisons belong
to the iperf3 methodology in `doc/doc.md` section 5, which needs `iperf3`
installed (currently missing on all three VMs — section 8.2).

---

## 5. SSH access

All three VMs run OpenSSH 10.0 (`openssh-server 1:10.0p1-7+deb13u4`) on port 22,
and all three remain reachable after the DHCP change, because SSH comes in over
`192.168.67.x` / `192.168.76.x`:

* user: `dupa` (uid 1000, member of `netdev`; **not** in the `sudo` group — root
  access is via `sudo` with a password)
* authentication: **password only**. No `~/.ssh` directory exists on any VM and
  the host's `id_ed25519` is rejected (`Permission denied
  (publickey,password)`).
* the password is stored in `~/.hermes/vm_pass` on the WSL host (mode 600,
  single line). It is never passed on a command line, never echoed, never
  committed. `test/sdex_vpn_test.py` reads it from that file (`--password-file`
  or `$PASS_FILE`).
* the host has no `sshpass` and no local root, so non-interactive automation
  goes through **paramiko**, not a shell loop.

Interactive use is plain `ssh` (it prompts for the VM password):

```bash
ssh dupa@192.168.67.2    # client
ssh dupa@192.168.67.3    # server
ssh dupa@192.168.76.4    # http
```

Non-interactive use needs the paramiko virtualenv the smoke-test wrapper
expects:

```bash
python3 -m venv /home/admin/.hermes/cache/scratch/sshtools
/home/admin/.hermes/cache/scratch/sshtools/bin/pip install paramiko   # 5.1.0 here
```

The harness uses `AutoAddPolicy`, i.e. host keys are accepted without being
pinned to `known_hosts`. Acceptable for throw-away guests; know it before
trusting a "login OK" line.

`sudo` on the VMs requires a TTY *or* `-S`; `sudo -n` fails and `sudo -l` from a
non-interactive session fails with "a terminal is required". Automation must do
`sudo -S -p '' <cmd>` and write the password to stdin. Two PATH traps:

* the remote **user's** `PATH` is `/usr/local/bin:/usr/bin:/bin:/usr/games` — no
  `sbin`, so `command -v nft` reports "missing" while `/usr/sbin/nft` exists;
* `sudo` resolves it (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`),
  but only for the command sudo itself runs. `sudo cmd1; cmd2` elevates only
  `cmd1` — `cmd2` runs in the user shell and can hit "nft: command not found".
  Use `sudo -S -p '' sh -c '...'` when several privileged commands must run.

Binaries live at `~/test/sdex_vpn` (a git checkout) and
`~/test/sdex_vpn/target/release/{client,server}` on every VM.

---

## 6. Traffic path

### 6.1 Before the VPN: nothing gets through

```
client 192.168.67.2 ──(no route to 192.168.76.0/24)── ✗
```

`ping -c 1 -W 1 192.168.76.4` from the client fails. The smoke test asserts this
first (`[3/8] baseline`) and only warns if it unexpectedly succeeds — a success
means the virtual switches are bridged somewhere and the test would be
meaningless.

### 6.2 After both binaries start

```
client app ──> tun0 (10.0.0.2)
            ──> SDEx encrypt ──> UDP 192.168.67.3:51820  (src 192.168.67.2)
server eth1 ──> UDP recv ──> SDEx decrypt
            ──> tun0 (10.0.0.1) ──> kernel forward
            ──> eth2 192.168.76.2 ──> [masquerade 10.0.0.0/24] ──> 192.168.76.4
return: 192.168.76.4 ──> 192.168.76.2 ──> server route 10.0.0.0/24 via tun0
            ──> client-map lookup (inner dst IP -> UDP source addr)
            ──> SDEx encrypt ──> UDP to 192.168.67.2:ephemeral
client ──> tun0 ──> application
```

The server keeps the `10.0.0.x -> public UDP source address` mapping in a
lock-free `papaya::HashMap` (`doc/doc.md` section 4). It replies to the UDP
source address of the last packet it saw, so the client needs no fixed source
port and the server needs no peer list.

The server's outbound interface for forwarded client packets is chosen by the
kernel: `192.168.76.4` is on-link on `eth2`, so it goes out `eth2` regardless of
the default route. The default route matters for *NAT* and for the startup check
(section 7), not for this forwarding decision.

### 6.3 Routing side effects on the client

`src/vpn/client.rs` acts in this order:

1. resolves the route to the server IP and installs a `/32` host route to it
   through the existing NIC (`add_host_route`) — this keeps the encrypted UDP
   stream out of the tunnel;
2. if `--route` was given **no** routes (full tunnel), replaces the default
   route with `default dev tun0` (`add_default_route`, `NLM_F_REPLACE`);
3. otherwise installs each `--route <cidr>` through `tun0` and leaves the
   default route untouched.

This split is critical for remote operation. A full tunnel on the client
replaces its default route, so the SSH session from `192.168.67.1` can die as
soon as the route change lands. The smoke test therefore always runs the client
with `--route 192.168.76.0/24`, never full tunnel. HEAD is literally "default
route bug v2 (will come back)"; treat full-tunnel mode as the risky path and
test it from the console, not over SSH.

Observed client table with the tunnel up (from the passing run):

```
10.0.0.0/24 dev tun0 proto kernel scope link src 10.0.0.2
192.168.67.0/24 dev eth1 proto kernel scope link src 192.168.67.2
192.168.67.3 dev eth1 proto static
192.168.76.0/24 dev tun0 proto static
```

`tun0` is `POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP`, MTU 1500, qlen 500.

---

## 7. Kernel prerequisites and NAT

`src/vpn/server.rs::setup_forwarding()` runs before the TUN device is created:

| Step | What the code does |
|------|--------------------|
| forwarding | writes `1` to `/proc/sys/net/ipv4/ip_forward` |
| nft table | `nft add table ip nat` if missing |
| postrouting chain | `type nat hook postrouting priority 100` |
| masquerade | `ip saddr 10.0.0.0/24 oifname <default-route iface> masquerade` |
| `rp_filter` | **not** set by the code — the test harness writes `0` |

Observed clean server state (no VPN process):

```
$ sudo nft list ruleset                       # empty
$ cat /proc/sys/net/ipv4/ip_forward           -> 0
$ cat /proc/sys/net/ipv4/conf/all/rp_filter   -> 0
$ cat /proc/sys/net/ipv4/conf/eth1/rp_filter  -> 2   (loose)
$ cat /proc/sys/net/ipv4/conf/eth2/rp_filter  -> 2   (loose)
```

The test harness explicitly writes `0` to `all`, `default` and `tun0` before
pinging, because strict reverse-path filtering drops the asymmetric ICMP return
path. It also creates an empty `ip nat prerouting` chain when the table exists:
without a `prerouting` chain, the kernel does not deliver NATed ICMP correctly
even though TCP/UDP may appear to work (`doc/doc.md` section 3.4).

Other traps that cost time:

* `/usr/sbin/nft` exists on all three VMs (nftables 1.1.3-1) and works under
  `sudo`; it is invisible to the unprivileged user because `/usr/sbin` is not in
  their PATH.
* `sysctl` is **not installed** on these images. Write `/proc/sys/...` directly;
  `sysctl -w` fails silently inside `|| true` chains.

### 7.1 The default-route dependency (verified failure)

`src/vpn/server.rs` does this **before** creating the TUN:

```rust
let (_, oif) = rt_setup.block_on(get_default_gateway())?;
let out_iface = iface_name_by_index(oif).unwrap_or_else(|| "eth0".to_string());
setup_forwarding(&subnet, &out_iface)?;
```

`get_default_gateway()` returns `Err("Couldnt find default route")` when the main
table has no `default` entry — exactly the state after the DHCP leg was removed.
The `?` propagates, `main` returns, and the process exits **before** `tun0` and
before any forwarding/NAT is configured. Verified against the deployed
`~/test/sdex_vpn/target/release/server`:

```
$ sudo ./target/release/server --listen 0.0.0.0:51820 --tun-ip 10.0.0.1 --threads 2
[server] listening on 0.0.0.0:51820
[server] threads = 2
[server] multi_queue = true
Error: "Couldnt find default route"        # exit 1, no tun0, no nft table
```

And through the project's own harness (`./test/sdex_vpn_test.sh`, rc=1):

```
[5/8] starting SDEx VPN server ...
      ip_forward=1, rp_filter=0, empty nat prerouting chain ensured
      masquerade for 10.0.0.0/24 out eth2 ensured
[7/8] tunnel state ...
      WARNING: the server process is not running; see log below
      Error: "Couldnt find default route"
[8/8] ping 192.168.76.4 from 192.168.67.2 through the tunnel ...
      4 packets transmitted, 0 received, 100% packet loss
FAIL: ping did not get through
```

Two lines in that output are misleading:

* "masquerade for 10.0.0.0/24 out eth2 ensured" is printed unconditionally after
  `nft add rule ... 2>/dev/null || true`. With no `ip nat` table the rule is not
  added; the message lies.
* "ip_forward=1, rp_filter=0 ... ensured" is true, but `ip_forward` is left at
  `1` by the test even when it fails. Reset it if you need a clean baseline.

### 7.2 Fix without touching code: give the server a default route

The server only needs *a* default route; in this topology the useful one points
at the host's segment-B address. It also makes the binary's own NAT rule correct
(`oifname eth2` instead of the old `eth0`).

Manual (one shot, lost on reboot):

```bash
ssh dupa@192.168.67.3
sudo ip route add default via 192.168.76.1 dev eth2
```

Persistent: **`sdex-lab-default-route.service` is installed and enabled** on
`sdex-server` (2026-11-22). It is a plain oneshot that adds exactly that route on
boot and removes it on stop; it does not touch the project or the ifupdown
configuration:

```ini
[Unit]
Description=Lab default route for the SDEx VPN server (eth2 -> WSL host)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/usr/bin/ip route add default via 192.168.76.1 dev eth2
ExecStop=-/usr/bin/ip route del default via 192.168.76.1 dev eth2

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now sdex-lab-default-route.service   # already done
systemctl is-enabled sdex-lab-default-route.service          # enabled
systemctl is-active  sdex-lab-default-route.service          # active
```

With the route present the server starts, sets forwarding, creates the table,
chain and a **single** correct masquerade rule, then creates the TUN:

```
[server] ip_forward = 1
[server] created nft table 'ip nat'
[server] created nft chain 'postrouting'
[server] added NAT: 10.0.0.0/24 → eth2
[server] TUN created
[server] 2 workers started
```

#### Variants measured

The full matrix (route, client mode, rc, pings, RTTs) is in
[`doc/testing.md`](testing.md) section 2. What it means for the infrastructure:

* the startup failure depends only on the *existence* of a default route, not on
  which interface it points at;
* the binary's NAT interface is wrong whenever that route does not point at the
  segment carrying the target. The harness hides this with its own
  `oifname <target-iface>` rule, so a passing test is **not** proof that NAT is
  correct — inspect `nft list table ip nat`;
* full tunnel on the client works here (it does not disconnect SSH, because the
  on-link segment route wins), but it remains the risky code path referenced by
  the HEAD commit.

Caveats of the route fix:

* `192.168.76.1` is the WSL host, which does **not** forward or NAT. The route
  is fine for on-link traffic (`192.168.76.4`) but gives the server no working
  internet path — same as having no default route in practice.
* it is a lab fix, not a design fix: the server still cannot start on a machine
  without a default route. A code-level alternative is to stop requiring one —
  e.g. accept an explicit `--out-iface`, derive the egress interface from the
  configured peers, or skip NAT when no default route exists and let the
  operator configure nftables. Not implemented as of 326c103.

### 7.3 Restoring a clean baseline

```bash
sudo systemctl stop sdex-lab-default-route.service   # removes the default route
sudo nft delete table ip nat 2>/dev/null
sudo sh -c 'echo 0 > /proc/sys/net/ipv4/ip_forward'
```

The client's leftover `192.168.67.3 dev eth1 proto static` route and the
server's stale `dhcpcd` socket for `10.77.15.66` both clear on reboot.

---

## 8. Deployment drift and limits

### 8.1 The three VMs are not in sync

State read 2026-11-22:

| Machine     | repo HEAD on VM                          | binary mtime   |
|-------------|------------------------------------------|----------------|
| sdex-client | 326c103 fix: default route bug v2        | Nov 15 18:44   |
| sdex-server | 679af42 fix: added NAT with nft to server| Oct 16 06:30   |
| sdex-http   | 6ff5f83 feat: forcing multi queue        | Oct  6 04:25   |

The server binary predates the November route fixes; the HTTP VM is only a
ping/HTTP target so its checkout is irrelevant. Before trusting a result,
rebuild and redeploy on client and server — the test resolves
`~/test/sdex_vpn/{client,server}` or `target/release/...` and silently uses
whichever exists.

### 8.2 Measurement tooling

`iperf3` **is installed** on all three VMs (3.18-2+deb13u2), but not from the
network: the guests have no internet, so the packages were fetched on the WSL
host (Debian 13, same arch) and pushed over SFTP:

```bash
apt-get download iperf3 libiperf0 libsctp1     # on the host
# sftp each .deb to /tmp on every VM, then:
sudo dpkg -i /tmp/libiperf0_*.deb /tmp/libsctp1_*.deb /tmp/iperf3_*.deb
```

`libsctp1` is easy to miss — `dpkg -i iperf3` succeeds without it and the binary
then dies with `error while loading shared libraries: libsctp.so.1`.
`curl` still exists on client and server but not on the target VM.

`pidstat` is **not** installed; `test/sdex_bench.py` samples `/proc/<pid>/stat`
and `/proc/stat` instead, which needs no package at all.

Two tmpfs/sticky-bit traps bite every benchmark run:

* `/tmp` is a **243 MB tmpfs** and both daemons `println!` every packet. A
  throughput test fills it in seconds; with `/tmp` full the daemon cannot create
  its log and exits before printing anything (or, for the client, fails to start
  at all). Delete `/tmp/*.log` **as root** — the sticky bit stops `dupa` from
  removing root-owned logs.
* `fs.protected_regular=1` (Debian default) makes a root process **unable to
  append** to a file in sticky `/tmp` that was created by the unprivileged user.
  A log truncated as `dupa` therefore silently prevents the daemon from starting.
  Truncate as root: `sudo sh -c ': > /tmp/sdex_server.log'`.

### 8.3 MTU

All links are 1500 and `tun0` is created without an explicit MTU, so it also
defaults to 1500 while the encrypted packet is 28 bytes larger. Measured
consequences (`doc/testing.md` 3.3):

* full-size inner packets either fragment (DF=0) or are dropped with
  `ICMP fragmentation needed` (DF=1). UDP fragments and still gets through:
  1472-byte payloads (1500-byte inner, 1528-byte outer) sustained 216 Mbps;
* TCP keeps working but pays retransmits: 206.20 Mbps unclamped vs 212.04 Mbps
  with `-M 1360` (1400-byte inner packets). Not a stall, a tax;
* if tuning is needed, call `.mtu(...)` on `DeviceBuilder` (e.g. 1400) or clamp
  MSS, and record the value with the results.

### 8.4 Anomalous tun0 packets

While testing the server standalone, `tun.recv` repeatedly logged 48-byte
packets whose parsed destination was not `10.0.0.x` (`10.92.126.121`,
`10.103.31.36`, `228.217.104.213`) with no client connected. They are correctly
dropped ("brak w mapie"), and the same 48-byte size also appears in the client's
log, but the origin was not identified. Worth understanding before production —
most likely the parser reading a non-IPv4 frame (bytes 16-19 of an IPv6 header)
rather than a real packet for the VPN subnet.

---

## 9. Inspection runbook

All read-only. Run from the WSL host; inside paramiko add `sudo -S -p ''` and
write the password to stdin.

```bash
# 1. who is reachable (TCP/22 is what matters)
for ip in 192.168.67.2 192.168.67.3 192.168.76.4; do
  ping -c1 -W1 "$ip" >/dev/null && echo "$ip up" || echo "$ip down"
done

# 2. per-host addressing, routes, listeners
for ip in 192.168.67.2 192.168.67.3 192.168.76.4; do
  echo "===== $ip"
  ssh dupa@$ip 'hostname; ip a; ip -4 route; ip -4 rule; ss -lntup'
done

# 3. segment isolation, from the client
ssh dupa@192.168.67.2 'ping -c2 -W1 192.168.76.4; ip route get 192.168.76.4'

# 4. server prerequisites and the current blocker
ssh dupa@192.168.67.3 "sudo -S -p '' sh -c '
  ip -4 route
  cat /proc/sys/net/ipv4/ip_forward
  cat /proc/sys/net/ipv4/conf/all/rp_filter
  nft list ruleset'"

# 5. tunnel device (absent when idle)
ssh dupa@192.168.67.2 'ip -br addr show tun0; ls -l /dev/net/tun'
```

End-to-end check (needs the paramiko venv and `~/.hermes/vm_pass`):

```bash
./test/sdex_vpn_test.sh --no-cleanup   # leave it up to poke at
./test/sdex_vpn_test.sh                # normal run + cleanup
```

While it runs:

```bash
ip -br addr show tun0
ip -4 route
ip -4 route get 192.168.76.4
ss -lunp | grep 51820
sudo nft list table ip nat
```

**The server's default route comes from `sdex-lab-default-route.service` (7.2).
Check `systemctl is-active sdex-lab-default-route.service` before testing;
without that route the server exits immediately and the test fails at step 7.**

---

## 10. How this document was produced

From `DESKTOP-79NDBAC` (WSL) over SSH/paramiko, twice on 2026-11-22 — before and
after the server's DHCP leg was removed:

* `hostname`, `/etc/os-release`, `uname -r/-m`
* `ip a` (full), `ip -br -4/-6 addr`, `ip -4 route`, `ip -4 rule`
* per-interface MTU from `/sys/class/net/*/mtu`, link flags
* `/proc/sys/net/ipv4/ip_forward`, `rp_filter` (`all`, per interface)
* `ss -lntup`, `nproc`, CPU model, `free -h`, `df -h /`
* `git log -1` + binary timestamps under `~/test/sdex_vpn`
* `dpkg -l` for `nftables`, `openssh-server`, `curl`, `iperf3`
* full 3x4 `ping -c 2 -W 1` matrix
* with `sudo` (password on stdin): resolved PATH, `nft list ruleset`,
  `nft list table ip nat`, forwarding/`rp_filter` values

Plus five controlled runs, each followed by a reset:

1. deployed server binary alone, no default route → exits with
   `Couldnt find default route`;
2. `./test/sdex_vpn_test.sh`, no default route → rc=1, 100% packet loss;
3. `./test/sdex_vpn_test.sh` after `ip route add default via 192.168.76.1` →
   rc=0, 4/4 pings, HTTP 200 (run twice, 0.84 and 0.78 ms average);
4. `./test/sdex_vpn_test.sh` with the default route via `eth1` → rc=0 as well,
   but only thanks to the harness's own masquerade rule; the binary's NAT rule
   was `oifname eth1`;
5. manual full-tunnel run (client without `--route`) → `default dev tun0`,
   4/4 pings, 0.92 ms, HTTP 200, SSH session intact.

Final state left behind: `sdex-lab-default-route.service` enabled and active
(route via `192.168.76.1` present), `ip_forward=0`, empty nft ruleset, no VPN
processes. No project source files were changed.

Re-run these checks before quoting numbers. The server's configuration changed
once already, the VMs are periodically rebuilt, and nothing here is persistent.

---

## 11. Troubleshooting quick reference

| Symptom | Likely cause | Check / fix |
|---------|--------------|-------------|
| Server exits with `Couldnt find default route` | no default route on the server (DHCP leg removed, lab unit stopped) | `ip -4 route`, `systemctl status sdex-lab-default-route`; start the unit or add `default via 192.168.76.1 dev eth2` (7.2) |
| Test fails at `[7/8]`, "server process is not running" | same as above | server log `/tmp/sdex_server.log` |
| `ping` from client to 192.168.76.4 fails before the VPN | expected: no route between segments | `ip route get 192.168.76.4` on client |
| `ping` works *without* the VPN | switches bridged / a VM got a default route | `ip -4 route` on client and http |
| SSH to a VM times out | VM down or wrong segment | host `ping <ip>`; port 22 probe |
| `ssh` says `Permission denied (publickey,password)` | key auth not configured, password required | use the password from `~/.hermes/vm_pass`; no `~/.ssh` on the VMs |
| `sudo: a terminal is required` | non-interactive sudo | `sudo -S -p ''`, password on stdin |
| `nft: command not found` as `dupa`, or in `sudo a; b` | `/usr/sbin` not in the user PATH | `sudo -S -p '' sh -c '...'` for the whole command list |
| NAT "applied" but no return traffic | masquerade bound to an interface that carries no traffic | `sudo nft list table ip nat`; rule must say `oifname "eth2"` |
| Tunnel up, TCP stalls on large packets | MTU 1500 + 28-byte encapsulation | `ip link show tun0`; reduce MTU or test with 1200-byte payloads |
| SSH session dies when the client starts | full tunnel replaced the default route | rerun with `--route 192.168.76.0/24` |
| Test "passes" but uses an old binary | VM checkout behind the host repo | compare `git log -1` and binary mtimes on the VM |
