use std::net::{Ipv4Addr, UdpSocket};
use std::thread;

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
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[client] connecting to {}", server);
    println!("[client] TUN {} with IP {}", tun_name, tun_ip);

    let tun = DeviceBuilder::new()
        .name(tun_name)
        .ipv4(tun_ip, 24, None)
        .multi_queue(true)
        .build_sync()?;
    println!("[client] TUN created");

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;
    println!("[client] UDP socket connected to {}", server);

    let tun_read = tun.try_clone()?;
    let socket_read = socket.try_clone()?;
    println!("[client] descriptors cloned, starting threads");

    let key1 = first_key.to_vec();
    let key2 = second_key.to_vec();

    // Thread 1: UDP -> decrypt -> TUN
    let key1_rx = key1.clone();
    let key2_rx = key2.clone();
    thread::spawn(move || {
        let tun = tun_read;
        let mut buf = [0u8; 65535];
        println!("[client][rx] UDP receive thread started");
        loop {
            match socket_read.recv(&mut buf) {
                Ok(amt) => {
                    println!("[client][rx] {} bytes UDP from server", amt);
                    let decrypted = sdex::decrypt(&buf[..amt], &key1_rx, &key2_rx);
                    println!("[client][rx] decrypted to {} bytes", decrypted.len());

                    match tun.send(&decrypted) {
                        Ok(_) => println!("[client][rx] written to TUN"),
                        Err(e) => eprintln!("[client][rx] tun.send: {}", e),
                    }
                }
                Err(e) => eprintln!("[client][rx] recv: {}", e),
            }
        }
    });

    // Routing setup
    let rt = tokio::runtime::Runtime::new()?;
    let full_tunnel = routes.is_empty();
    let server_ip: Ipv4Addr = server.split(':').next().unwrap().parse()?;

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

    // Main thread: TUN -> encrypt -> UDP
    let tun = tun;
    let mut buf = [0u8; 65535];
    println!("[client][tx] main thread started, waiting for packets from TUN");
    loop {
        let n = tun.recv(&mut buf)?;
        if n == 0 {
            println!("[client][tx] TUN returned 0 bytes");
            continue;
        }
        println!("[client][tx] {} bytes from TUN", n);

        let encrypted = sdex::encrypt(&buf[..n], &key1, &key2);
        println!("[client][tx] encrypted to {} bytes", encrypted.len());

        if let Err(e) = socket.send(&encrypted) {
            eprintln!("[client][tx] send: {}", e);
        } else {
            println!("[client][tx] sent to server");
        }
    }
}