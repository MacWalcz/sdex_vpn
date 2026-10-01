use std::net::{Ipv4Addr, UdpSocket};
use std::thread;

use tun_rs::DeviceBuilder;

use crate::sdex;
use super::routes::{
    add_default_route, add_host_route, add_route, get_default_gateway,
};
pub fn run(
    server: &str,
    tun_name: &str,
    tun_ip: &str,
    first_key: &[u8],
    second_key: &[u8],
    routes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("[client] łączę się z {}", server);
    println!("[client] TUN {} z IP {}", tun_name, tun_ip);


    let multi_queue = std::env::var("SDEX_NO_MULTI_QUEUE").is_err();
    let tun = DeviceBuilder::new()
        .name(tun_name)
        .ipv4(tun_ip, 24, None)
        .multi_queue(multi_queue)  
        .build_sync()?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(server)?;

    let tun_read = tun.try_clone()?;
    let socket_read = socket.try_clone()?;

    let key1 = first_key.to_vec();
    let key2 = second_key.to_vec();

    // Wątek 1: UDP -> decrypt -> TUN
    let key1_rx = key1.clone();
    let key2_rx = key2.clone();
    thread::spawn(move || {
        let tun = tun_read;
        let mut buf = [0u8; 65535];
        loop {
            match socket_read.recv(&mut buf) {
                Ok(amt) => {
                    let decrypted = sdex::decrypt(&buf[..amt], &key1_rx, &key2_rx);
                    // SyncDevice: "send" = wstrzyknięcie pakietu do TUN
                    if let Err(e) = tun.send(&decrypted) {
                        eprintln!("[client] tun.send: {}", e);
                    }
                }
                Err(e) => eprintln!("[client] recv: {}", e),
            }
        }
    });

    let rt = tokio::runtime::Runtime::new()?;
    let full_tunnel = routes.is_empty();
    let server_ip: Ipv4Addr = server.split(':').next().unwrap().parse()?;

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

    // Wątek główny: TUN -> encrypt -> UDP
    let tun = tun;
    let mut buf = [0u8; 65535];
    loop {
        // SyncDevice: "recv" = odbiór pakietu z TUN
        let n = tun.recv(&mut buf)?;
        if n == 0 {
            continue;
        }
        let encrypted = sdex::encrypt(&buf[..n], &key1, &key2);
        if let Err(e) = socket.send(&encrypted) {
            eprintln!("[client] send: {}", e);
        }
    }
}