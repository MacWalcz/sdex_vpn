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


pub async fn get_route_to_ip(dest: Ipv4Addr) -> Result<(Ipv4Addr, u32), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let route_msg = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dest, 32)
        .build();

    let mut routes = handle.route().get(route_msg).execute();

    if let Some(route) = routes.try_next().await? {
        let mut gateway = Ipv4Addr::UNSPECIFIED; // 0.0.0.0 (brak bramy)
        let mut oif = None;

        for attr in &route.attributes {
            match attr {
                RouteAttribute::Gateway(gw) => {
                    if let RouteAddress::Inet(ip) = gw {
                        gateway = *ip;
                    }
                }
                RouteAttribute::Oif(idx) => oif = Some(*idx),
                _ => {}
            }
        }

        if let Some(idx) = oif {
            return Ok((gateway, idx));
        }
    }
    Err(format!("Could not find a route to {}", dest).into())
}

pub async fn add_default_route(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    let idx = get_iface_index(&handle, iface).await?;

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(idx)
        .build();

    // Use .replace() to overwrite an existing default route without an EEXIST (-17) error
    handle.route().add(route).replace().execute().await?;
    println!("[routes] replaced default route with {}", iface);
    Ok(())
}

pub async fn add_host_route(
    dest: Ipv4Addr,
    gateway: Ipv4Addr,
    oif: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(dest, 32)
        .output_interface(oif);

    if gateway != Ipv4Addr::UNSPECIFIED {
        builder = builder.gateway(gateway);
    }

    let route = builder.build();

    match handle.route().add(route).execute().await {
        Ok(()) => println!("[routes] Host route {} via {} (iface {})", dest, gateway, oif),
        Err(rtnetlink::Error::NetlinkError(msg)) if msg.raw_code() == (-17) => {
            println!("[routes] Host route {} already exists. Skipping.", dest);
        }
        Err(e) => return Err(e.into()),
    }
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

    match handle.route().add(route).execute().await {
        Ok(()) => println!("[routes] Added route {} through {}", cidr, iface),
        Err(rtnetlink::Error::NetlinkError(msg)) if msg.raw_code() == (-17) => {
            println!("[routes] Route {} already exists. Skipping.", cidr);
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}