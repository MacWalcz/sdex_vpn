use std::net::SocketAddr;
use std::net::ToSocketAddrs;

use tun_rs::DeviceBuilder;

use super::routes::{add_default_route, add_host_route, add_route, get_default_gateway};
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
    println!("[client] connecting to {}", server);
    println!("[client] TUN {} with IP {}", tun_name, tun_ip);
    println!("[client] threads = {}", num_threads);

    let multi_queue = std::env::var("SDEX_NO_MULTI_QUEUE")
        .map(|v| !matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(true);
    println!("[client] multi_queue = {}", multi_queue);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_threads)
        .enable_all()
        .build()?;

    let main_tun = {
        let _guard = rt.enter();
        DeviceBuilder::new()
            .name(tun_name)
            .ipv4(tun_ip, 24, None)
            .multi_queue(multi_queue)
            .build_async()?
    };
    println!("[client] TUN created");

    // 3. Routing – raz, w runtime
    let full_tunnel = routes.is_empty();
    let server_ip: std::net::Ipv4Addr = server.split(':').next().unwrap().parse()?;
    println!("[client] setting up routes (full_tunnel = {})", full_tunnel);

    rt.block_on(async {
        let (gw, oif) = get_default_gateway().await?;
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

    // 4. Adres serwera
    let server_addr: SocketAddr = server
        .to_socket_addrs()?
        .next()
        .ok_or("cannot resolve server")?;

    // 5. Spawn N tasków na TYM SAMYM runtime
    rt.block_on(async move {
        let mut tasks = Vec::with_capacity(num_threads);

        for worker_id in 0..num_threads {
            let tun = main_tun.try_clone()?;   // nowa kolejka
            let key1 = first_key.to_vec();
            let key2 = second_key.to_vec();

            let task = tokio::spawn(async move {
                run_worker(tun, server_addr, key1, key2, worker_id).await;
            });
            tasks.push(task);
        }

        println!("[client] {} workers started", num_threads);

        // Czekaj na wszystkie taski
        for (i, t) in tasks.into_iter().enumerate() {
            if let Err(e) = t.await {
                eprintln!("[client] worker {} panicked: {:?}", i, e);
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

async fn run_worker(
    tun: tun_rs::AsyncDevice,
    server_addr: SocketAddr,
    key1: Vec<u8>,
    key2: Vec<u8>,
    worker_id: usize,
) {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
        .await
        .expect("bind UDP");
    socket.connect(server_addr).await.expect("connect UDP");

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    println!("[worker {}] started", worker_id);

    loop {
        tokio::select! {
            // TUN -> szyfruj -> UDP
            result = tun.recv(&mut tun_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        let encrypted = sdex::encrypt(&tun_buf[..n], &key1, &key2);
                        if let Err(e) = socket.send(&encrypted).await {
                            eprintln!("[worker {}] udp send: {}", worker_id, e);
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("[worker {}] tun.recv: {}", worker_id, e);
                        break;
                    }
                }
            }
            // UDP -> deszyfruj -> TUN
            result = socket.recv(&mut udp_buf) => {
                match result {
                    Ok(n) => {
                        let decrypted = sdex::decrypt(&udp_buf[..n], &key1, &key2);
                        if let Err(e) = tun.send(&decrypted).await {
                            eprintln!("[worker {}] tun.send: {}", worker_id, e);
                        }
                    }
                    Err(e) => {
                        eprintln!("[worker {}] udp.recv: {}", worker_id, e);
                        break;
                    }
                }
            }
        }
    }
}