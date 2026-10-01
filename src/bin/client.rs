use clap::Parser;
use sdex_vpn::vpn::client;

#[derive(Parser)]
#[command(name = "sdex-client", about = "Klient VPN SDEx")]
struct Args {
    /// Adres serwera (IP:port)
    #[arg(short, long)]
    server: String,

    /// Nazwa interfejsu TUN
    #[arg(short, long, default_value = "tun0")]
    tun_name: String,

    /// Adres IP dla interfejsu TUN (klient)
    #[arg(short, long, default_value = "10.0.0.2")]
    tun_ip: String,

    #[arg(long)]
    route: Vec<String>,
    /// Pierwszy klucz sesyjny

    #[arg(long, default_value = "key1")]
    key1: String,

    /// Drugi klucz sesyjny
    #[arg(long, default_value = "key2")]
    key2: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    client::run(
        &args.server,
        &args.tun_name,
        &args.tun_ip,
        args.key1.as_bytes(),
        args.key2.as_bytes(),
        args.route
    )
}