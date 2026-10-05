use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;

use tun_rs::DeviceBuilder;

use crate::sdex;

pub fn run(
    listen: &str,
    tun_name: &str,
    tun_ip: &str,
    first_key: &[u8],
    second_key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[server] listening on {}", listen);
    println!("[server] TUN {} with IP {}", tun_name, tun_ip);

    let multi_queue = std::env::var("SDEX_NO_MULTI_QUEUE").is_err();
    println!("[server] TUN multi_queue = {}", multi_queue);

    let tun = DeviceBuilder::new()
        .name(tun_name)
        .ipv4(tun_ip, 24, None)
        .multi_queue(multi_queue)
        .build_sync()?;

    println!("[server] TUN created");

    let socket = UdpSocket::bind(listen)?;
    println!("[server] UDP socket bound on {}", listen);

    let tun_read = tun.try_clone()?;
    let socket_read = socket.try_clone()?;
    println!("[server] descriptors cloned, starting threads");

    let key1 = first_key.to_vec();
    let key2 = second_key.to_vec();

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Thread 1: UDP -> decrypt -> TUN
    let client_addr_rx = Arc::clone(&client_addr);
    let key1_rx = key1.clone();
    let key2_rx = key2.clone();
    thread::spawn(move || {
        let tun = tun_read;
        let mut buf = [0u8; 65535];
        println!("[server][rx] UDP receive thread started");
        loop {
            match socket_read.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    println!("[server][rx] {} bytes UDP from {}", amt, src);
                    *client_addr_rx.lock().unwrap() = Some(src);

                    let decrypted = sdex::decrypt(&buf[..amt], &key1_rx, &key2_rx);
                    println!("[server][rx] decrypted to {} bytes", decrypted.len());

                    match tun.send(&decrypted) {
                        Ok(_) => println!("[server][rx] written to TUN"),
                        Err(e) => eprintln!("[server][rx] tun.send: {}", e),
                    }
                }
                Err(e) => eprintln!("[server][rx] recv_from: {}", e),
            }
        }
    });

    // Main thread: TUN -> encrypt -> UDP
    let tun = tun;
    let mut buf = [0u8; 65535];
    println!("[server][tx] main thread started, waiting for packets from TUN");
    loop {
        let n = tun.recv(&mut buf)?;
        if n == 0 {
            println!("[server][tx] TUN returned 0 bytes");
            continue;
        }
        println!("[server][tx] {} bytes from TUN", n);

        let encrypted = sdex::encrypt(&buf[..n], &key1, &key2);
        println!("[server][tx] encrypted to {} bytes", encrypted.len());

        let addr_opt = *client_addr.lock().unwrap();
        match addr_opt {
            Some(addr) => {
                println!("[server][tx] sending {} bytes to {}", encrypted.len(), addr);
                if let Err(e) = socket.send_to(&encrypted, addr) {
                    eprintln!("[server][tx] send_to: {}", e);
                }
            }
            None => {
                println!("[server][tx] no client_addr – don't know where to send");
            }
        }
    }
}