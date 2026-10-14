use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::thread;

use papaya::HashMap;
use tun_rs::DeviceBuilder;

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

    let main_tun = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _guard = rt.enter();
        Arc::new(
            DeviceBuilder::new()
                .name(tun_name)
                .ipv4(tun_ip, 24, None)
                .multi_queue(multi_queue)
                .build_async()?,
        )
    };
    println!("[server] TUN created");

    let client_map: Arc<HashMap<Ipv4Addr, SocketAddr>> = Arc::new(HashMap::new());

    let mut handles = Vec::with_capacity(num_threads);

    for worker_id in 0..num_threads {
        let main_tun = Arc::clone(&main_tun);
        let key1 = first_key.to_vec();
        let key2 = second_key.to_vec();
        let listen = listen.to_string();
        let client_map = Arc::clone(&client_map);

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");

            let tun = {
                let _guard = rt.enter();
                main_tun.try_clone().expect("try_clone")
            };

            rt.block_on(async move {
                run_worker(tun, &listen, key1, key2, worker_id, client_map).await;
            });
        });
        handles.push(handle);
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
