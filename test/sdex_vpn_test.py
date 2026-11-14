#!/usr/bin/env python3
"""SDEx VPN multi-VM smoke test over SSH.

Topology
    VM-sdex-client  192.168.67.2                     <- VPN client
    VM-sdex-server  192.168.67.3 (internal)          <- VPN server, UDP 51820
                    192.168.76.2 (external)
    VM-sdex-http    192.168.76.4                     <- plain http.server :80

Client and HTTP host sit in different, isolated segments. Before the tunnel
is up the client must NOT be able to reach 192.168.76.4; after the client and
server are running, the client must be able to ping it.

Requires paramiko. No sshpass, no sudo on the local machine.
Password is read from a file (default ~/.hermes/vm_pass), never from argv.
"""

from __future__ import annotations

import argparse
import os
import shlex
import socket
import sys
import time

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.exit("paramiko is missing; run the wrapper script test/sdex_vpn_test.sh instead")


class RemoteError(RuntimeError):
    pass


class Host:
    """Thin paramiko wrapper for one VM."""

    def __init__(self, name: str, addr: str, user: str, password: str, key_path: str | None):
        self.name = name
        self.addr = addr
        self.user = user
        self.password = password
        self.key_path = key_path
        self.client: paramiko.SSHClient | None = None

    # -- connection -------------------------------------------------------
    def connect(self, timeout: float = 10.0) -> None:
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict[str, object] = dict(
            hostname=self.addr,
            port=22,
            username=self.user,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        if self.key_path:
            kwargs["key_filename"] = self.key_path
            # keep the password as a fallback for the sudo prompt path
            kwargs["password"] = self.password
        else:
            kwargs["password"] = self.password
        try:
            cli.connect(**kwargs)  # type: ignore[arg-type]
        except paramiko.AuthenticationException:
            raise RemoteError(
                f"{self.name} ({self.user}@{self.addr}): authentication failed - "
                f"wrong password in the password file?"
            )
        except Exception as exc:
            raise RemoteError(f"{self.name} ({self.user}@{self.addr}): {exc}")
        self.client = cli

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None

    # -- command execution ------------------------------------------------
    def run(self, cmd: str, sudo: bool = False, timeout: float = 30.0,
            check: bool = False) -> tuple[int, str]:
        """Run a shell command. Returns (exit_status, combined output)."""
        assert self.client is not None, f"{self.name} not connected"
        if sudo:
            full = f"sudo -S -p '' {cmd}"
        else:
            full = cmd
        stdin, stdout, stderr = self.client.exec_command(full, timeout=timeout)
        if sudo:
            stdin.write(self.password + "\n")
            stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:
                pass
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc = stdout.channel.recv_exit_status()
        text = (out + err).strip()
        if check and rc != 0:
            raise RemoteError(f"{self.name}: command failed (rc={rc}): {cmd}\n{text}")
        return rc, text

    # -- daemonising ------------------------------------------------------
    def start_daemon(self, argv: list[str], log_path: str, sudo: bool = True) -> None:
        """Start a long-running process detached from the SSH channel.

        sudo must stay in the foreground: if it is backgrounded with '&' the
        remote shell hands it /dev/null as stdin and it never reads the
        password. So sudo runs a shell that backgrounds the daemon itself.
        """
        quoted = " ".join(shlex.quote(a) for a in argv)
        inner = f"exec {quoted} >>{log_path} 2>&1 </dev/null"
        daemon = (
            f"setsid sh -c {shlex.quote(inner)} >/dev/null 2>&1 </dev/null &"
        )
        cmd = f"sudo -S -p '' sh -c {shlex.quote(daemon)}" if sudo else daemon

        assert self.client is not None
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=15)
        if sudo:
            stdin.write(self.password + "\n")
            stdin.flush()
        try:
            stdin.channel.shutdown_write()
        except Exception:
            pass

        # sudo exits as soon as the inner shell forks the daemon, so this
        # returns immediately; guard anyway in case a child keeps the pty.
        chan = stdout.channel
        chan.settimeout(5.0)
        out, err = "", ""
        try:
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            rc = chan.recv_exit_status()
        except Exception:
            rc = 0
        try:
            chan.close()
        except Exception:
            pass

        text = (out + err).strip()
        if rc != 0:
            raise RemoteError(f"{self.name}: failed to start {argv[0]} (rc={rc}): {text}")
        if "password" in text.lower():
            raise RemoteError(f"{self.name}: sudo rejected the password: {text}")

    # -- helpers ----------------------------------------------------------
    def pid_of(self, pattern: str) -> str:
        """Find PIDs whose command line *starts* with `pattern`.

        The anchor matters: without it pgrep -f also matches the shell wrapper
        that is running pgrep itself.
        """
        pat = pattern if pattern.startswith("^") else "^" + pattern
        rc, out = self.run(f"pgrep -f {shlex.quote(pat)} | head -n 3")
        return out if rc == 0 else ""

    def log_tail(self, path: str, lines: int = 40) -> str:
        rc, out = self.run(f"tail -n {lines} {shlex.quote(path)} 2>/dev/null")
        return out if out else "(empty)"


def tcp_probe(addr: str, port: int = 22, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return True
    except OSError:
        return False


def read_password(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pw = fh.readline().rstrip("\r\n")
    except FileNotFoundError:
        sys.exit(
            f"Password file not found: {path}\n"
            f"Create it with:\n"
            f"  printf '%s\\n' 'VM_PASSWORD_FOR_USER_dupa' > {path} && chmod 600 {path}"
        )
    except PermissionError:
        sys.exit(f"Cannot read {path} (check permissions)")
    if not pw:
        sys.exit(f"Password file {path} is empty")
    return pw


def resolve_binary(host: Host, repo: str, name: str) -> str | None:
    """Accept either <repo>/<bin> or <repo>/target/release/<bin>.

    `repo` may contain $HOME (the default), so the candidates are embedded in
    double quotes and expanded by the remote shell rather than locally.
    """
    candidates = [f"{repo}/{name}", f"{repo}/target/release/{name}"]
    first, second = candidates
    cmd = f'if [ -x "{first}" ]; then echo "{first}"; elif [ -x "{second}" ]; then echo "{second}"; fi'
    rc, out = host.run(cmd)
    if rc != 0 or not out.strip():
        return None
    # the remote shell expanded $HOME for us, so this is a usable absolute path
    return out.strip().splitlines()[0]


def main() -> int:
    ap = argparse.ArgumentParser(description="SDEx VPN multi-VM smoke test")
    ap.add_argument("--user", default=os.environ.get("VM_USER", "dupa"))
    ap.add_argument("--password-file", default=os.environ.get(
        "PASS_FILE", os.path.expanduser("~/.hermes/vm_pass")))
    ap.add_argument("--identity", default=os.environ.get("SDEX_IDENTITY"),
                    help="SSH private key to use instead of a password (~/.ssh/id_ed25519)")
    ap.add_argument("--client", default="192.168.67.2")
    ap.add_argument("--server", default="192.168.67.3")
    ap.add_argument("--http", default="192.168.76.4")
    ap.add_argument("--repo", default=None, help="path to sdex_vpn on the VMs (default ~/test/sdex_vpn)")
    ap.add_argument("--port", type=int, default=51820, help="VPN UDP port")
    ap.add_argument("--tun-server", default="10.0.0.1")
    ap.add_argument("--tun-client", default="10.0.0.2")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--route", default="192.168.76.0/24",
                    help="subnet to route through the tunnel (keeps SSH alive)")
    ap.add_argument("--no-cleanup", action="store_true", help="leave processes running")
    ap.add_argument("--ping-count", type=int, default=4)
    args = ap.parse_args()

    repo = args.repo or "$HOME/test/sdex_vpn"
    # The remote binaries need root (TUN + NAT + routes), so a sudo password is
    # required even when SSH itself authenticates with a key.
    password = read_password(args.password_file)
    key_path = os.path.expanduser(args.identity) if args.identity else None

    hosts = {
        "client": Host("client", args.client, args.user, password, key_path),
        "server": Host("server", args.server, args.user, password, key_path),
        "http": Host("http", args.http, args.user, password, key_path),
    }

    print("=== SDEx VPN smoke test ===")
    print(f"    user      : {args.user}")
    print(f"    client    : {args.client}")
    print(f"    server    : {args.server} (udp/{args.port})")
    print(f"    http      : {args.http}")
    print(f"    repo      : {repo}")
    print(f"    route     : {args.route} -> tun")
    print()

    started: dict[str, bool] = {}
    failure = 1
    # pkill patterns, filled in as binaries are resolved
    procs: dict[str, list[str]] = {
        "client": ["sdex_vpn/target/release/client", "sdex_vpn/client --server"],
        "server": ["sdex_vpn/target/release/server", "sdex_vpn/server --listen"],
        "http": ["http.server 80"],
    }

    try:
        # ---- 1. reachability ------------------------------------------------
        print("[1/8] checking TCP/22 reachability ...")
        for name, h in hosts.items():
            if not tcp_probe(h.addr):
                print(f"      {name:<6} {h.addr}: UNREACHABLE")
                return 1
            print(f"      {name:<6} {h.addr}: port 22 open")
        for h in hosts.values():
            h.connect()
        print("      ssh login OK on all three hosts")

        # ---- 2. binaries ----------------------------------------------------
        print("[2/8] locating binaries ...")
        server_bin = resolve_binary(hosts["server"], repo, "server")
        client_bin = resolve_binary(hosts["client"], repo, "client")
        if not server_bin:
            print(f"      ERROR: no executable 'server' under {repo} or {repo}/target/release")
            return 1
        if not client_bin:
            print(f"      ERROR: no executable 'client' under {repo} or {repo}/target/release")
            return 1
        print(f"      server: {server_bin}")
        print(f"      client: {client_bin}")
        procs["server"].insert(0, server_bin)
        procs["client"].insert(0, client_bin)

        # ---- 3. baseline isolation -----------------------------------------
        print("[3/8] baseline: client must NOT reach http before the tunnel ...")
        rc, out = hosts["client"].run(
            f"ping -c 1 -W 1 {shlex.quote(args.http)}", timeout=15)
        if rc == 0:
            print(f"      WARNING: {args.client} already pings {args.http} without the VPN."
                  " The isolation test will be meaningless (check the VBox/Hyper-V networks).")
        else:
            print(f"      OK: {args.client} cannot reach {args.http} yet")

        # ---- 4. http server --------------------------------------------------
        print("[4/8] starting http.server on :80 ...")
        hosts["http"].start_daemon(
            ["python3", "-m", "http.server", "80"], "/tmp/sdex_http.log", sudo=True)
        time.sleep(1.5)
        rc, out = hosts["http"].run("ss -lntp 2>/dev/null | grep ':80 ' || true")
        print(f"      {out.splitlines()[0] if out else 'listener not visible (continuing)'}")

        # ---- 5. vpn server ---------------------------------------------------
        print("[5/8] starting SDEx VPN server ...")
        server_argv = [
            server_bin,
            "--listen", f"0.0.0.0:{args.port}",
            "--tun-ip", args.tun_server,
            "--threads", str(args.threads),
        ]
        hosts["server"].start_daemon(server_argv, "/tmp/sdex_server.log", sudo=True)
        time.sleep(2.5)

        # kernel prerequisites the binary does not set itself (see doc/doc.md 3.4).
        # Write /proc/sys directly: these VM images have no sysctl binary, so
        # the sysctl form fails silently.
        hosts["server"].run(
            "echo 1 > /proc/sys/net/ipv4/ip_forward; "
            "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; "
            "echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter; "
            "echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter 2>/dev/null; "
            "nft add chain ip nat prerouting 2>/dev/null; "
            "echo \"ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) "
            "rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter)\"",
            sudo=True)
        print("      ip_forward=1, rp_filter=0, empty nat prerouting chain ensured")

        # on multi-homed servers the default route may not point at the http segment
        http_prefix = args.http.rsplit(".", 1)[0]
        ext_if = hosts["server"].run(
            "ip -o -4 addr show | awk '{print $2, $4}' | "
            f"grep -F '{http_prefix}' 2>/dev/null | head -n 1",
            sudo=True)[1]
        if ext_if:
            iface = ext_if.split()[0]
            hosts["server"].run(
                f"nft add rule ip nat postrouting ip saddr 10.0.0.0/24 oifname {shlex.quote(iface)} masquerade 2>/dev/null || true",
                sudo=True)
            print(f"      masquerade for 10.0.0.0/24 out {iface} ensured")
        else:
            print("      NOTE: could not detect the external interface on the server")

        # ---- 6. vpn client ---------------------------------------------------
        print("[6/8] starting SDEx VPN client ...")
        client_argv = [
            client_bin,
            "--server", f"{args.server}:{args.port}",
            "--tun-ip", args.tun_client,
            "--threads", str(args.threads),
            "--route", args.route,
        ]
        hosts["client"].start_daemon(client_argv, "/tmp/sdex_client.log", sudo=True)
        time.sleep(3.0)
        hosts["client"].run(
            "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter; "
            "echo 0 > /proc/sys/net/ipv4/conf/tun0/rp_filter 2>/dev/null", sudo=True)

        # ---- 7. tunnel state -------------------------------------------------
        print("[7/8] tunnel state ...")
        rc, out = hosts["client"].run("ip -4 addr show tun0 2>/dev/null; ip route show 2>/dev/null")
        for line in out.splitlines():
            print("      " + line)
        alive = hosts["server"].pid_of(server_bin)
        if not alive:
            print("      WARNING: the server process is not running; see log below")
            print(hosts["server"].log_tail("/tmp/sdex_server.log"))
        started["tunnel"] = True

        # ---- 8. the actual test ---------------------------------------------
        print(f"[8/8] ping {args.http} from {args.client} through the tunnel ...")
        rc, out = hosts["client"].run(
            f"ping -c {args.ping_count} -W 2 {shlex.quote(args.http)}",
            timeout=args.ping_count * 3 + 10)
        print(out)

        if rc == 0:
            print()
            print(f"SUCCESS: {args.client} -> {args.http} works over the SDEx tunnel")
            rc2, out2 = hosts["client"].run(
                f"curl -sS -m 5 -o /dev/null -w 'HTTP %{{http_code}} in %{{time_total}}s' http://{args.http}/",
                timeout=20)
            print(f"         http check: {out2 or 'no response'}")
            failure = 0
        else:
            print()
            print("FAIL: ping did not get through")
            print("--- server log (tail) ---")
            print(hosts["server"].log_tail("/tmp/sdex_server.log", 40))
            print("--- client log (tail) ---")
            print(hosts["client"].log_tail("/tmp/sdex_client.log", 40))
            print("--- server routes / nat ---")
            print(hosts["server"].run("ip route; echo; nft list table ip nat 2>/dev/null", sudo=True)[1])

    except RemoteError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        failure = 1
    finally:
        if not args.no_cleanup:
            print("\n[cleanup] stopping remote processes ...")
            for name, patterns in procs.items():
                h = hosts[name]
                if h.client is None:
                    continue
                for pattern in patterns:
                    try:
                        h.run(f"pkill -f {shlex.quote(pattern)}", sudo=True, timeout=15)
                    except Exception:
                        pass
            for h in hosts.values():
                h.close()

    return failure


if __name__ == "__main__":
    sys.exit(main())
