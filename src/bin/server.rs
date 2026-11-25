use clap::Parser;
use sdex_vpn::vpn::server;

#[derive(Parser)]
#[command(name = "sdex-server", about = "SDEx VPN server")]
struct Args {
    /// UDP listen address and port
    #[arg(short, long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// TUN interface name
    #[arg(short, long, default_value = "tun0")]
    tun_name: String,

    /// IP address for the TUN interface (server)
    #[arg(short, long, default_value = "10.0.0.1")]
    tun_ip: String,

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
    server::run(
        &args.listen,
        &args.tun_name,
        &args.tun_ip,
        args.key1.as_bytes(),
        args.key2.as_bytes(),
        args.threads,
    )
}