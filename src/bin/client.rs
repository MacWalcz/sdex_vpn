use clap::Parser;
use sdex_vpn::vpn::client;

#[derive(Parser)]
#[command(name = "sdex-client", about = "Client VPN SDEx")]
struct Args {
    /// Server address (IP:port)
    #[arg(short, long)]
    server: String,

    /// TUN interface name
    #[arg(short, long, default_value = "tun0")]
    tun_name: String,

    /// TUN interface address
    #[arg(short, long, default_value = "10.0.0.2")]
    tun_ip: String,

    /// Partial route
    #[arg(long)]
    route: Vec<String>,

    /// First session key
    #[arg(long, default_value = "key1")]
    key1: String,

    /// Second session key
    #[arg(long, default_value = "key2")]
    key2: String,

    /// Number of threads
    #[arg(long, default_value_t = num_cpus::get())]
    threads: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    client::run(
        &args.server,
        &args.tun_name,
        &args.tun_ip,
        args.key1.as_bytes(),
        args.key2.as_bytes(),
        args.route,
        args.threads,
    )
}