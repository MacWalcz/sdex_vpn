pub mod client;
pub mod server;

pub mod routes;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

pub(crate) const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const DRAIN_BATCH: usize = 256;

/// Direction-independent IPv4 flow identity: swapping source and destination
/// yields the same key, so a flow and its replies hash to the same worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    low: (u32, u16),
    high: (u32, u16),
    proto: u8,
}

pub(crate) fn ipv4_flow_key(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }

    let proto = packet[9];
    let src_ip = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
    let dst_ip = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
    let (src_port, dst_port) = if (proto == 6 || proto == 17) && packet.len() >= ihl + 4 {
        (
            u16::from_be_bytes([packet[ihl], packet[ihl + 1]]),
            u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]),
        )
    } else {
        (0, 0)
    };

    let src = (src_ip, src_port);
    let dst = (dst_ip, dst_port);
    let (low, high) = if src <= dst { (src, dst) } else { (dst, src) };
    Some(FlowKey { low, high, proto })
}

pub(crate) fn flow_index(key: FlowKey, workers: usize) -> usize {
    debug_assert!(workers > 0);
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % workers
}

/// One task owns the TUN device: a reader stripes outgoing packets to
/// per-worker channels (a flow always hashes to the same worker) and a writer
/// writes packets decrypted by the workers back to the device. They run as two
/// independent futures so a full worker queue cannot stall the write path.
pub(crate) async fn tun_task(
    tun: AsyncDevice,
    txs: Vec<mpsc::Sender<Vec<u8>>>,
    to_tun: mpsc::Receiver<Vec<u8>>,
) {
    if txs.is_empty() {
        return;
    }

    tokio::select! {
        _ = tun_reader(&tun, &txs) => {}
        _ = tun_writer(&tun, to_tun) => {}
    }
}

async fn tun_reader(tun: &AsyncDevice, txs: &[mpsc::Sender<Vec<u8>>]) {
    let mut buf = vec![0u8; 65535];

    loop {
        match tun.recv(&mut buf).await {
            Ok(n) if n > 0 => {
                if !dispatch_packet(&buf[..n], txs).await {
                    return;
                }
            }
            Ok(_) => {}
            Err(_) => return,
        }

        // One wakeup handles a burst; cap it so the write side still runs.
        for _ in 0..DRAIN_BATCH {
            match tun.try_recv(&mut buf) {
                Ok(n) if n > 0 => {
                    if !dispatch_packet(&buf[..n], txs).await {
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => return,
            }
        }
    }
}

async fn tun_writer(tun: &AsyncDevice, mut to_tun: mpsc::Receiver<Vec<u8>>) {
    loop {
        match to_tun.recv().await {
            Some(packet) => write_to_tun(tun, &packet).await,
            None => return,
        }

        for _ in 0..DRAIN_BATCH {
            match to_tun.try_recv() {
                Ok(packet) => write_to_tun(tun, &packet).await,
                Err(_) => break,
            }
        }
    }
}

async fn write_to_tun(tun: &AsyncDevice, packet: &[u8]) {
    match tun.try_send(packet) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            let _ = tun.send(packet).await;
        }
        Err(_) => {}
    }
}

async fn dispatch_packet(packet: &[u8], txs: &[mpsc::Sender<Vec<u8>>]) -> bool {
    let Some(key) = ipv4_flow_key(packet) else {
        return true;
    };
    let idx = flow_index(key, txs.len());
    txs[idx].send(packet.to_vec()).await.is_ok()
}

pub(crate) fn raise_socket_buffer_limits() {
    for path in ["/proc/sys/net/core/rmem_max", "/proc/sys/net/core/wmem_max"] {
        let current = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok());
        if current.map_or(true, |value| value < SOCKET_BUFFER_BYTES) {
            let _ = std::fs::write(path, SOCKET_BUFFER_BYTES.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(proto: u8, src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[9] = proto;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let forward = packet(6, [10, 0, 0, 2], [192, 168, 1, 5], 40000, 5201);
        let reverse = packet(6, [192, 168, 1, 5], [10, 0, 0, 2], 5201, 40000);
        assert_eq!(ipv4_flow_key(&forward), ipv4_flow_key(&reverse));

        let other_flow = packet(6, [10, 0, 0, 2], [192, 168, 1, 5], 40001, 5201);
        assert_ne!(ipv4_flow_key(&forward), ipv4_flow_key(&other_flow));
    }

    #[test]
    fn flow_index_is_stable_and_in_range() {
        let key = ipv4_flow_key(&packet(17, [10, 0, 0, 2], [8, 8, 8, 8], 1234, 53)).unwrap();
        for workers in 1..=8 {
            let index = flow_index(key, workers);
            assert!(index < workers);
            assert_eq!(index, flow_index(key, workers));
        }
    }
}
