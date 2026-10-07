use std::net::Ipv4Addr;

use futures_util::stream::TryStreamExt;
use ipnetwork::Ipv4Network;
use rtnetlink::{
    new_connection, Handle, RouteMessageBuilder,
    packet_route::route::{RouteAddress, RouteAttribute},
};

pub async fn get_iface_index(handle: &Handle, name: &str) -> Result<u32, rtnetlink::Error> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    if let Some(link) = links.try_next().await? {
        Ok(link.header.index)
    } else {
        Err(rtnetlink::Error::RequestFailed)
    }
}

pub async fn get_default_gateway() -> Result<(Ipv4Addr, u32), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let route_msg = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut routes = handle.route().get(route_msg).execute();

    while let Some(route) = routes.try_next().await? {
        if route.header.destination_prefix_length != 0 {
            continue;
        }
        let mut gateway = None;
        let mut oif = None;
        for attr in &route.attributes {
            match attr {
                RouteAttribute::Gateway(gw) => {
                    if let RouteAddress::Inet(ip) = gw {
                        gateway = Some(*ip);
                    }
                }
                RouteAttribute::Oif(idx) => oif = Some(*idx),
                _ => {}
            }
        }
        if let (Some(gw), Some(idx)) = (gateway, oif) {
            return Ok((gw, idx));
        }
    }
    Err("Couldnt find default route".into())
}

pub async fn add_default_route(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    let idx = get_iface_index(&handle, iface).await?;

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(idx)
        .build();

    handle.route().add(route).execute().await?;
    println!("[routes] added default route {}", iface);
    Ok(())
}

pub async fn add_host_route(
    dest: Ipv4Addr,
    gateway: Ipv4Addr,
    oif: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dest, 32)
        .gateway(gateway)
        .output_interface(oif)
        .build();

    handle.route().add(route).execute().await?;
    println!("[routes] Host route {} -> {} (iface {})", dest, gateway, oif);
    Ok(())
}

pub async fn add_route(iface: &str, cidr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let network: Ipv4Network = cidr.parse()?;
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    let idx = get_iface_index(&handle, iface).await?;

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(network.network(), network.prefix())
        .output_interface(idx)
        .build();

    handle.route().add(route).execute().await?;
    println!("[routes] Added route {} trough {}", cidr, iface);
    Ok(())
}

