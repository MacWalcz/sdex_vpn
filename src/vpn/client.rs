use std::net::{SocketAddr, ToSocketAddrs};
use std::thread;

use tokio::sync::mpsc;
use tun_rs::DeviceBuilder;

use super::routes::{add_default_route, add_host_route, add_route, get_route_to_ip};
use crate::sdex;

pub fn run(
    server: &str,
    tun_name: &str,
    tun_ip: &str,
    first_key: &[u8],
    second_key: &[u8],
    routes: Vec<String>,
    num_threads: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let num_threads = num_threads.max(1);

    println!("[client] connecting to {}", server);
    println!("[client] TUN {} with IP {}", tun_name, tun_ip);
    println!("[client] threads = {}", num_threads);

    let multi_queue = std::env::var("SDEX_NO_MULTI_QUEUE")
        .map(|v| !matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(true);
    println!("[client] multi_queue = {}", multi_queue);

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
    println!("[client] TUN created");

    let full_tunnel = routes.is_empty();
    let server_ip: std::net::Ipv4Addr = server.split(':').next().unwrap().parse()?;
    println!("[client] setting up routes (full_tunnel = {})", full_tunnel);

    main_rt.block_on(async {
        let (gw, oif) = get_route_to_ip(server_ip).await?;
        add_host_route(server_ip, gw, oif).await?;
        if full_tunnel {
            add_default_route(tun_name).await?;
        }
        for r in &routes {
            add_route(tun_name, r).await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    println!("[client] routes set up");

    let server_addr: SocketAddr = server
        .to_socket_addrs()?
        .next()
        .ok_or("cannot resolve server")?;

    super::raise_socket_buffer_limits();

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
        let to_tun = to_tun_tx.clone();
        handles.push(thread::spawn(move || {
            rt.block_on(async move {
                run_worker(worker_id, rx, to_tun, server_addr, key1, key2).await;
            });
        }));
    }
    drop(to_tun_tx);

    {
        let rt = main_rt;
        handles.push(thread::spawn(move || {
            rt.block_on(async move {
                super::tun_task(main_tun, worker_txs, to_tun_rx).await;
            });
        }));
    }

    println!("[client] {} workers started", num_threads);

    for (i, h) in handles.into_iter().enumerate() {
        if let Err(e) = h.join() {
            eprintln!("[client] worker {} panicked: {:?}", i, e);
        }
    }

    Ok(())
}

async fn run_worker(
    worker_id: usize,
    mut rx: mpsc::Receiver<Vec<u8>>,
    to_tun: mpsc::Sender<Vec<u8>>,
    server_addr: SocketAddr,
    key1: Vec<u8>,
    key2: Vec<u8>,
) {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind UDP");
    {
        let socket = socket2::SockRef::from(&socket);
        let _ = socket.set_recv_buffer_size(super::SOCKET_BUFFER_BYTES);
        let _ = socket.set_send_buffer_size(super::SOCKET_BUFFER_BYTES);
    }
    socket.connect(server_addr).await.expect("connect UDP");

    let mut udp_buf = vec![0u8; 65535];
    let mut enc_buf = vec![0u8; 65535];
    let mut dec_buf = vec![0u8; 65535];

    println!("[worker {}] started", worker_id);

    loop {
        tokio::select! {
            packet = rx.recv() => {
                match packet {
                    Some(packet) => tun_to_udp(&packet, &socket, &mut enc_buf, &key1, &key2).await,
                    None => return,
                }
            }
            result = socket.recv(&mut udp_buf) => {
                match result {
                    Ok(n) => udp_to_tun(&udp_buf[..n], &to_tun, &mut dec_buf, &key1, &key2).await,
                    Err(_) => return,
                }
            }
        }

        // One wakeup handles a burst; cap it so both directions still run.
        for _ in 0..super::DRAIN_BATCH {
            match rx.try_recv() {
                Ok(packet) => tun_to_udp(&packet, &socket, &mut enc_buf, &key1, &key2).await,
                Err(_) => break,
            }
        }

        for _ in 0..super::DRAIN_BATCH {
            match socket.try_recv(&mut udp_buf) {
                Ok(n) => udp_to_tun(&udp_buf[..n], &to_tun, &mut dec_buf, &key1, &key2).await,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }
    }
}

async fn tun_to_udp(
    packet: &[u8],
    socket: &tokio::net::UdpSocket,
    enc_buf: &mut [u8],
    key1: &[u8],
    key2: &[u8],
) {
    let written = sdex::encrypt_into(packet, enc_buf, key1, key2);
    if written == 0 {
        return;
    }
    match socket.try_send(&enc_buf[..written]) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let _ = socket.send(&enc_buf[..written]).await;
        }
        Err(_) => {}
    }
}

async fn udp_to_tun(
    packet: &[u8],
    to_tun: &mpsc::Sender<Vec<u8>>,
    dec_buf: &mut [u8],
    key1: &[u8],
    key2: &[u8],
) {
    let written = sdex::decrypt_into(packet, dec_buf, key1, key2);
    if written == 0 {
        return;
    }
    let _ = to_tun.send(dec_buf[..written].to_vec()).await;
}
