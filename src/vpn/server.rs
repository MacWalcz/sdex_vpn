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
    println!("[server] nasłuchuję na {}", listen);
    println!("[server] TUN {} z IP {}", tun_name, tun_ip);

    let multi_queue = std::env::var("SDEX_NO_MULTI_QUEUE").is_err();
    println!("[server] TUN multi {} ", multi_queue);

    let tun = DeviceBuilder::new()
        .name(tun_name)
        .ipv4(tun_ip, 24, None)

        
        .multi_queue(multi_queue)
        .build_sync()?;

    let socket = UdpSocket::bind(listen)?;

    let tun_read = tun.try_clone()?;
    let socket_read = socket.try_clone()?;

    let key1 = first_key.to_vec();
    let key2 = second_key.to_vec();

    let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // Wątek 1: UDP -> decrypt -> TUN
    let client_addr_rx = Arc::clone(&client_addr);
    let key1_rx = key1.clone();
    let key2_rx = key2.clone();
    thread::spawn(move || {
        let tun = tun_read;
        let mut buf = [0u8; 65535];
        loop {
            match socket_read.recv_from(&mut buf) {
                Ok((amt, src)) => {
                    *client_addr_rx.lock().unwrap() = Some(src);
                    let decrypted = sdex::decrypt(&buf[..amt], &key1_rx, &key2_rx);
                    if let Err(e) = tun.send(&decrypted) {
                        eprintln!("[server] tun.send: {}", e);
                    }
                }
                Err(e) => eprintln!("[server] recv_from: {}", e),
            }
        }
    });

    // Wątek główny: TUN -> encrypt -> UDP
    let tun = tun;
    let mut buf = [0u8; 65535];
    loop {
        let n = tun.recv(&mut buf)?;
        if n == 0 {
            continue;
        }
        let encrypted = sdex::encrypt(&buf[..n], &key1, &key2);
        if let Some(addr) = *client_addr.lock().unwrap() {
            if let Err(e) = socket.send_to(&encrypted, addr) {
                eprintln!("[server] send_to: {}", e);
            }
        }
    }
}
