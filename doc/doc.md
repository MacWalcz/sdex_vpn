# Project Documentation: SDEx VPN

## 1. General Project Description
SDEx VPN is a custom VPN application operating at the L3 layer (TUN interface), written in **Rust**. The main goal of the project is the implementation and performance analysis of a proprietary encryption algorithm **SDEx**, based on the ultra-fast **BLAKE3** hash function. The application consists of two binaries: `client` and `server`, and its architecture is optimized for high throughput and low latency.

## 2. Code Architecture and Main Modules
The project uses `Cargo` and is divided into modules:
*   `src/sdex.rs`: Implementation of the SDEx encryption/decryption algorithm.
*   `src/vpn/client.rs`: VPN client logic (TUN creation, packet sending/receiving, routing).
*   `src/vpn/server.rs`: VPN server logic (multithreaded UDP listening, decryption, NAT, client mapping).
*   `src/vpn/routes.rs`: Asynchronous routing table manipulation using `rtnetlink`.
*   `src/bin/`: CLI entry files (`client` and `server`) using the `clap` library.

### 2.1. SDEx Cryptographic Algorithm
Instead of a classic block cipher (like AES), SDEx uses BLAKE3 for dynamic key stream generation.
*   Data is divided into small blocks (default 4-bytes) and processed in pairs.
*   Three base hashes are generated from the keys (`H1`, `H2`, and `H1+H2`).
*   Data blocks are XORed with hashes. After processing a pair, a new chained hash is generated (`hk+1 = hash(hk-1 ^ hk || M1 || M2)`).
*   Uses the `blake3` library.

## 3. Key Engineering Decisions and Solved Problems (Important!)

During development, several serious system-level problems were encountered and solved in the code. **The new agent must be aware of them:**

1.  **Multithreading (Multi-Queue) and Queue 0 Starvation:**
    *   The server and client spawn `N` threads (defaulting to the number of CPU cores). Each thread receives its own clone of the TUN interface (`try_clone()`), which creates a separate queue in the kernel.
    *   **Problem:** The main TUN interface (queue 0) was not assigned to any thread, causing packets that landed in it (based on flow hash) to be dropped.
    *   **Solution:** The main TUN handle (`main_tun`) is explicitly passed to thread #0 (Worker 0).

2.  **`tun-rs` Hanging due to Edge-Triggered Epoll:**
    *   **Problem:** Using the multithreaded Tokio runtime (`new_multi_thread()`) caused the asynchronous TUN receiver (`AsyncFd`) to drop packets or hang when there was more than one event in the queue (typical for Epoll in Edge-Triggered mode).
    *   **Solution:** Each worker thread creates its **own independent runtime** using `Builder::new_current_thread()`. The entire lifecycle of the `AsyncDevice` (including `try_clone()`) takes place in the context of this specific runtime (`rt.enter()`).

3.  **Virtual Environment Specifics (WSL2 / Hyper-V):**
    *   In some virtual environments, the `IFF_MULTI_QUEUE` flag in TUN is not supported by the kernel.
    *   **Solution:** An environment variable `SDEX_NO_MULTI_QUEUE=1` was introduced, which forces the application to run on a single queue.

4.  **Server-side Network Configuration:**
    *   The server automatically enables forwarding (`/proc/sys/net/ipv4/ip_forward` = 1).
    *   The server configures NAT using `nftables` (invoked via `std::process::Command`). It creates the `ip nat` table, the `postrouting` chain, and adds a `masquerade` rule for the VPN subnet.
    *   **Kernel requirement:** For ICMP NAT to work correctly, it is also required to create an empty `prerouting` chain in the `nat` table and disable `rp_filter` on the TUN interface (and globally).

## 4. Client Tracking on the Server
The server uses a `papaya::HashMap` (lock-free) to map the client's internal IP address (e.g., `10.0.0.2`) to its public UDP source address.
*   When the server receives a packet, it decrypts it, extracts the source IP from the IP header (bytes 12-15), and updates the map.
*   When a return packet exits the TUN, the server extracts the destination IP (bytes 16-19), looks up the client's UDP address in the map, and sends the encrypted packet there.

## 5. Performance Testing Methodology
To conduct comparative studies (SDEx vs OpenVPN vs WireGuard), the following methodology should be applied:
*   **Environment:** 3 virtual machines (Client, VPN Server, Target). Target is a machine in the same LAN running `iperf3 -s`.
*   **Tools:** `iperf3` (TCP/UDP throughput), `ping` (latency/jitter), `pidstat` (CPU usage).
*   **Scenarios:**
    *   Baseline (without VPN) - to determine the overhead.
    *   TCP: `iperf3 -c <target_ip> -t 10` (single-stream) and `-P 4` (multi-stream).
    *   UDP: `iperf3 -c <target_ip> -u -b 1G -l <size> -t 10` (tests for small packets e.g., 64B, medium 512B, and large 1200B).
*   **Statistics:** Minimum 30 iterations for each test. Rejection of the first 2-3 iterations (warm-up). Calculation of mean, median, and standard deviation. Application of the Mann-Whitney U test to verify the statistical significance of differences.

## 6. Running the Application
The applications require root privileges (to create TUN and modify routing/NAT).

```bash
# Server
sudo ./target/release/server --listen 0.0.0.0:51820 --tun-ip 10.0.0.1 --threads 4

# Client (requires providing the server IP)
sudo ./target/release/client --server <SERVER_IP>:51820 --tun-ip 10.0.0.2 --threads 4

# If testing in an environment without multi-queue support (e.g., WSL2):
sudo SDEX_NO_MULTI_QUEUE=1 ./target/release/client --server <SERVER_IP>:51820 --tun-ip 10.0.0.2