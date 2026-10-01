use clap::Parser;
use sdex_vpn::vpn::server;

#[derive(Parser)]
#[command(name = "sdex-server", about = "Serwer VPN SDEx")]
struct Args {
    /// Adres i port nasłuchu UDP
    #[arg(short, long, default_value = "0.0.0.0:51820")]
    listen: String,

    /// Nazwa interfejsu TUN
    #[arg(short, long, default_value = "tun0")]
    tun_name: String,

    /// Adres IP dla interfejsu TUN (serwer)
    #[arg(short, long, default_value = "10.0.0.1")]
    tun_ip: String,

    /// Pierwszy klucz sesyjny
    #[arg(long, default_value = "key1")]
    key1: String,

    /// Drugi klucz sesyjny
    #[arg(long, default_value = "key2")]
    key2: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    server::run(
        &args.listen,
        &args.tun_name,
        &args.tun_ip,
        args.key1.as_bytes(),
        args.key2.as_bytes(),
    )
}