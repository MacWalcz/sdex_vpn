use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread;

use ipnetwork::Ipv4Network;
use papaya::HashMap;
use tun_rs::DeviceBuilder;

use super::routes::get_default_gateway;
use crate::sdex;

pub fn run(
    listen: &str,
    tun_name: &str,
    tun_ip: &str,
    first_key: &[u8],
    second_key: &[u8],
    num_threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let client_map: Arc<HashMap<Ipv4Addr, SocketAddr>> = Arc::new(HashMap::new());

    let mut extra_tuns = Vec::with_capacity(num_threads.saturating_sub(1));
    for _ in 1..num_threads {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let tun = {
            let _guard = rt.enter();
            main_tun.try_clone().expect("try_clone")
        };
        extra_tuns.push((tun, rt));
    }

    let mut handles = Vec::with_capacity(num_threads);

    {
        let key1 = first_key.to_vec();
        let key2 = second_key.to_vec();
        let listen = listen.to_string();
        let client_map = Arc::clone(&client_map);
        let tun = main_tun;
        let rt = main_rt;
        handles.push(thread::spawn(move || {
            rt.block_on(async move {
                run_worker(tun, &listen, key1, key2, 0, client_map).await;
            });
        }));
    }

    for (idx, (tun, rt)) in extra_tuns.into_iter().enumerate() {
        let worker_id = idx + 1;
        let key1 = first_key.to_vec();
        let key2 = second_key.to_vec();
        let listen = listen.to_string();
        let client_map = Arc::clone(&client_map);
        handles.push(thread::spawn(move || {
            rt.block_on(async move {
                run_worker(tun, &listen, key1, key2, worker_id, client_map).await;
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
    tun: tun_rs::AsyncDevice,
    listen: &str,
    key1: Vec<u8>,
    key2: Vec<u8>,
    worker_id: usize,
    client_map: Arc<HashMap<Ipv4Addr, SocketAddr>>,
) {
    let socket = bind_reuseport(listen).expect("bind UDP");

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    println!("[worker {}] started", worker_id);

    loop {
        tokio::select! {
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src)) => {
                        println!("[worker {}] udp.recv_from: {} bytes od {}", worker_id, n, src);

                        let decrypted = sdex::decrypt(&udp_buf[..n], &key1, &key2);

                        if decrypted.len() >= 20 {
                            let src_ip = Ipv4Addr::new(
                                decrypted[12], decrypted[13], decrypted[14], decrypted[15],
                            );

                            let is_new = {
                                let map = client_map.pin();
                                map.insert(src_ip, src).is_none()
                            };

                            if is_new {
                                println!("[worker {}] NOWY KLIENT: {} <-> {}", worker_id, src_ip, src);
                            }
                        }

                        match tun.send(&decrypted).await {
                            Ok(_) => println!("[worker {}] tun.send: {} bytes OK", worker_id, decrypted.len()),
                            Err(e) => eprintln!("[worker {}] tun.send ERR: {}", worker_id, e),
                        }
                    }
                    Err(e) => {
                        eprintln!("[worker {}] udp.recv_from ERR: {}", worker_id, e);
                        break;
                    }
                }
            }
            result = tun.recv(&mut tun_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        if n < 20 {
                            continue;
                        }

                        let dst_ip = Ipv4Addr::new(
                            tun_buf[16], tun_buf[17], tun_buf[18], tun_buf[19],
                        );

                        let dst = {
                            let map = client_map.pin();
                            map.get(&dst_ip).copied()
                        };

                        let encrypted = sdex::encrypt(&tun_buf[..n], &key1, &key2);

                        match dst {
                            Some(addr) => {
                                match socket.send_to(&encrypted, addr).await {
                                    Ok(sent) => println!(
                                        "[worker {}] tun.recv {} bytes (dst {}) -> udp.send_to {} do {}",
                                        worker_id, n, dst_ip, sent, addr
                                    ),
                                    Err(e) => eprintln!("[worker {}] udp.send_to ERR: {}", worker_id, e),
                                }
                            }
                            None => {
                                println!(
                                    "[worker {}] tun.recv {} bytes, dst {} – brak w mapie, drop",
                                    worker_id, n, dst_ip
                                );
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("[worker {}] tun.recv ERR: {}", worker_id, e);
                        break;
                    }
                }
            }
        }
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
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

fn setup_forwarding(
    subnet: &str,
    out_iface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
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
        println!("[server] utworzono tabelę nft 'ip nat'");

        let s = std::process::Command::new("nft")
            .args([
                "add", "chain", "ip", "nat", "postrouting",
                "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}",
            ])
            .status()?;
        if !s.success() {
            return Err("nft add chain failed".into());
        }
        println!("[server] utworzono łańcuch nft 'postrouting'");
    }

    let ruleset = std::process::Command::new("nft")
        .args(["list", "chain", "ip", "nat", "postrouting"])
        .output()?;
    let ruleset_str = String::from_utf8_lossy(&ruleset.stdout);

    if ruleset_str.contains(subnet) && ruleset_str.contains("masquerade") {
        println!("[server] NAT już istnieje");
        return Ok(());
    }

    let s = std::process::Command::new("nft")
        .args([
            "add", "rule", "ip", "nat", "postrouting",
            "ip", "saddr", subnet,
            "oifname", out_iface,
            "masquerade",
        ])
        .status()?;
    if !s.success() {
        return Err("nft add rule MASQUERADE failed".into());
    }

    println!("[server] dodano NAT: {} → {}", subnet, out_iface);
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