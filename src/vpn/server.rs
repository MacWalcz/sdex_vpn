use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
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

    rt_setup.block_on(setup_forwarding(tun_name, &subnet, &out_iface))?;

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

async fn setup_forwarding(
    tun_name: &str,
    subnet: &str,
    out_iface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    println!("[server] ip_forward = 1");

    let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{}/rp_filter", tun_name), "0");
    let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{}/accept_local", tun_name), "1");
    println!("[server] rp_filter = 0, accept_local = 1 dla {}", tun_name);

    let check = std::process::Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", out_iface, "-j", "MASQUERADE"])
        .status();

    if matches!(check, Ok(s) if s.success()) {
        println!("[server] NAT już istnieje");
    } else {
        let status = std::process::Command::new("iptables")
            .args(["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", out_iface, "-j", "MASQUERADE"])
            .status()?;
        if !status.success() {
            return Err("iptables MASQUERADE failed".into());
        }
        println!("[server] dodano NAT: {} → {}", subnet, out_iface);
    }

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