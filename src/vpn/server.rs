use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;

use ipnetwork::Ipv4Network;
use papaya::HashMap;
use tokio::sync::mpsc;
use tun_rs::DeviceBuilder;

use super::routes::get_default_gateway;
use super::{
    ipv4_flow_key, raise_socket_buffer_limits, tun_task, FlowKey, SOCKET_BUFFER_BYTES,
};
use crate::sdex;

pub fn run(
    listen: &str,
    tun_name: &str,
    tun_ip: &str,
    first_key: &[u8],
    second_key: &[u8],
    num_threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let num_threads = num_threads.max(1);

    println!("[server] listening on {}", listen);
    println!("[server] threads = {}", num_threads);

    let multi_queue = std::env::var("SDEX_NO_MULTI_QUEUE")
        .map(|v| !matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(true);
    println!("[server] multi_queue = {}", multi_queue);

    let rt_setup = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let tun_ip_addr: Ipv4Addr = tun_ip.parse()?;
    let network = Ipv4Network::new(tun_ip_addr, 24)?;
    let subnet = format!("{}/24", network.network());

    let (_, oif) = rt_setup.block_on(get_default_gateway())?;
    let out_iface = iface_name_by_index(oif).unwrap_or_else(|| "eth0".to_string());

    setup_forwarding(&subnet, &out_iface)?;

    let main_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let main_tun = {
        let _guard = main_rt.enter();
        DeviceBuilder::new()
            .name(tun_name)
            .ipv4(tun_ip, 24, None)
            .multi_queue(multi_queue)
            .build_async()?
    };
    println!("[server] TUN created");

    raise_socket_buffer_limits();

    let client_map: Arc<HashMap<FlowKey, SocketAddr>> = Arc::new(HashMap::new());

    let mut worker_txs = Vec::with_capacity(num_threads);
    let mut worker_rxs = Vec::with_capacity(num_threads);
    for _ in 0..num_threads {
        let (tx, rx) = mpsc::channel(4096);
        worker_txs.push(tx);
        worker_rxs.push(rx);
    }
    let (to_tun_tx, to_tun_rx) = mpsc::channel(4096);

    let mut handles = Vec::with_capacity(num_threads + 1);

    for (worker_id, rx) in worker_rxs.into_iter().enumerate() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let key1 = first_key.to_vec();
        let key2 = second_key.to_vec();
        let listen = listen.to_string();
        let client_map = Arc::clone(&client_map);
        let to_tun = to_tun_tx.clone();
        handles.push(thread::spawn(move || {
            rt.block_on(async move {
                run_worker(worker_id, rx, to_tun, &listen, key1, key2, client_map).await;
            });
        }));
    }
    drop(to_tun_tx);

    {
        let rt = main_rt;
        handles.push(thread::spawn(move || {
            rt.block_on(async move {
                tun_task(main_tun, worker_txs, to_tun_rx).await;
            });
        }));
    }

    println!("[server] {} workers started", num_threads);

    for (i, h) in handles.into_iter().enumerate() {
        if let Err(e) = h.join() {
            eprintln!("[server] worker {} panicked: {:?}", i, e);
        }
    }

    Ok(())
}

async fn run_worker(
    worker_id: usize,
    mut rx: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    listen: &str,
    key1: Vec<u8>,
    key2: Vec<u8>,
    client_map: Arc<HashMap<FlowKey, SocketAddr>>,
) {
    let socket = bind_reuseport(listen).expect("bind UDP");

    let mut udp_buf = vec![0u8; 65535];
    let mut enc_buf = vec![0u8; 65535];
    let mut dec_buf = vec![0u8; 65535];

    println!("[worker {}] started", worker_id);

    loop {
        tokio::select! {
            packet = rx.recv() => {
                match packet {
                    Some(packet) => {
                        tun_to_udp(&packet, &socket, &mut enc_buf, &key1, &key2, &client_map).await
                    }
                    None => return,
                }
            }
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src)) => {
                        udp_to_tun(&udp_buf[..n], src, &to_tun, &mut dec_buf, &key1, &key2, &client_map).await
                    }
                    Err(_) => return,
                }
            }
        }

        // One wakeup handles a burst; cap it so both directions still run.
        for _ in 0..super::DRAIN_BATCH {
            match rx.try_recv() {
                Ok(packet) => tun_to_udp(&packet, &socket, &mut enc_buf, &key1, &key2, &client_map).await,
                Err(_) => break,
            }
        }

        for _ in 0..super::DRAIN_BATCH {
            match socket.try_recv_from(&mut udp_buf) {
                Ok((n, src)) => {
                    udp_to_tun(&udp_buf[..n], src, &to_tun, &mut dec_buf, &key1, &key2, &client_map).await
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }
    }
}

async fn udp_to_tun(
    packet: &[u8],
    src: SocketAddr,
    to_tun: &mpsc::Sender<Vec<u8>>,
    dec_buf: &mut [u8],
    key1: &[u8],
    key2: &[u8],
    client_map: &HashMap<FlowKey, SocketAddr>,
) {
    let written = sdex::decrypt_into(packet, dec_buf, key1, key2);
    if written == 0 {
        return;
    }
    let plaintext = &dec_buf[..written];

    if let Some(flow) = ipv4_flow_key(plaintext) {
        let map = client_map.pin();
        map.insert(flow, src);
    }

    let _ = to_tun.send(plaintext.to_vec()).await;
}

async fn tun_to_udp(
    packet: &[u8],
    socket: &tokio::net::UdpSocket,
    enc_buf: &mut [u8],
    key1: &[u8],
    key2: &[u8],
    client_map: &HashMap<FlowKey, SocketAddr>,
) {
    let Some(flow) = ipv4_flow_key(packet) else {
        return;
    };
    let dst = {
        let map = client_map.pin();
        map.get(&flow).copied()
    };
    let Some(addr) = dst else {
        return;
    };

    let written = sdex::encrypt_into(packet, enc_buf, key1, key2);
    if written == 0 {
        return;
    }

    match socket.try_send_to(&enc_buf[..written], addr) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let _ = socket.send_to(&enc_buf[..written], addr).await;
        }
        Err(_) => {}
    }
}

fn bind_reuseport(addr: &str) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::ToSocketAddrs;

    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad addr"))?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(SOCKET_BUFFER_BYTES)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_BYTES)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

fn setup_forwarding(subnet: &str, out_iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    println!("[server] ip_forward = 1");

    let table_exists = std::process::Command::new("nft")
        .args(["list", "table", "ip", "nat"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if !table_exists {
        let s = std::process::Command::new("nft")
            .args(["add", "table", "ip", "nat"])
            .status()?;
        if !s.success() {
            return Err("nft add table failed".into());
        }
        println!("[server] created nft table 'ip nat'");

        let s = std::process::Command::new("nft")
            .args([
                "add",
                "chain",
                "ip",
                "nat",
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "}",
            ])
            .status()?;
        if !s.success() {
            return Err("nft add chain failed".into());
        }
        println!("[server] created nft chain 'postrouting'");
    }

    let ruleset = std::process::Command::new("nft")
        .args(["list", "chain", "ip", "nat", "postrouting"])
        .output()?;
    let ruleset_str = String::from_utf8_lossy(&ruleset.stdout);

    if ruleset_str.contains(subnet) && ruleset_str.contains("masquerade") {
        println!("[server] NAT already exists");
        return Ok(());
    }

    let s = std::process::Command::new("nft")
        .args([
            "add",
            "rule",
            "ip",
            "nat",
            "postrouting",
            "ip",
            "saddr",
            subnet,
            "oifname",
            out_iface,
            "masquerade",
        ])
        .status()?;
    if !s.success() {
        return Err("nft add rule MASQUERADE failed".into());
    }

    println!("[server] added NAT: {} → {}", subnet, out_iface);
    Ok(())
}

fn iface_name_by_index(idx: u32) -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let path = entry.path().join("ifindex");
        if let Ok(content) = std::fs::read_to_string(&path) {
            if content.trim().parse::<u32>().ok() == Some(idx) {
                return entry.file_name().to_str().map(|s| s.to_string());
            }
        }
    }
    None
}
