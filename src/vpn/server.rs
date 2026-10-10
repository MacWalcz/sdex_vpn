use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::thread;

use tokio::sync::Mutex;
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

    let client_addrs: Arc<Mutex<Vec<Option<SocketAddr>>>> =
        Arc::new(Mutex::new(vec![None; num_threads]));

    let mut handles = Vec::with_capacity(num_threads);

    for worker_id in 0..num_threads {
        let main_tun = Arc::clone(&main_tun);
        let key1 = first_key.to_vec();
        let key2 = second_key.to_vec();
        let listen = listen.to_string();
        let client_addrs = Arc::clone(&client_addrs);

        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");

            // 👇 try_clone POZA block_on, w kontekście runtime
            let tun = {
                let _guard = rt.enter();
                main_tun.try_clone().expect("try_clone")
            };

            // 👇 block_on dostaje gotowy tun, nie pożycza rt do async move
            rt.block_on(async move {
                run_worker(tun, &listen, key1, key2, worker_id, client_addrs).await;
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
    client_addrs: Arc<Mutex<Vec<Option<SocketAddr>>>>,
) {
    let socket = bind_reuseport(listen).await.expect("bind UDP");

    let mut tun_buf = vec![0u8; 65535];
    let mut udp_buf = vec![0u8; 65535];

    println!("[worker {}] started", worker_id);

    loop {
        tokio::select! {
            result = socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src)) => {
                        {
                            let mut addrs = client_addrs.lock().await;
                            addrs[worker_id] = Some(src);
                        }
                        let decrypted = sdex::decrypt(&udp_buf[..n], &key1, &key2);
                        if let Err(e) = tun.send(&decrypted).await {
                            eprintln!("[worker {}] tun.send: {}", worker_id, e);
                        }
                    }
                    Err(e) => {
                        eprintln!("[worker {}] udp.recv_from: {}", worker_id, e);
                        break;
                    }
                }
            }
            result = tun.recv(&mut tun_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        let encrypted = sdex::encrypt(&tun_buf[..n], &key1, &key2);
                        let addr = {
                            let addrs = client_addrs.lock().await;
                            addrs[worker_id]
                        };
                        if let Some(dst) = addr {
                            if let Err(e) = socket.send_to(&encrypted, dst).await {
                                eprintln!("[worker {}] udp.send_to: {}", worker_id, e);
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        eprintln!("[worker {}] tun.recv: {}", worker_id, e);
                        break;
                    }
                }
            }
        }
    }
}

async fn bind_reuseport(addr: &str) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr: SocketAddr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad addr"))?;
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}