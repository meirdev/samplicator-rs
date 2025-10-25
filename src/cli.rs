use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::{ArgAction, Parser};

#[derive(Parser, Debug)]
#[command(version)]
pub struct Cli {
    #[arg(short = 's', default_value = "0.0.0.0", help = "Address to listen on")]
    pub address: IpAddr,

    #[arg(short = 'p', default_value_t = 2000, help = "Port to listen on")]
    pub port: u16,

    #[arg(short = 'S', action = ArgAction::SetTrue, help = "Enable spoofing of source IP address and port")]
    pub spoof: bool,

    #[arg(
        short = 'n',
        action = ArgAction::SetTrue,
        help = "Disable checksum calculation (only works with spoofing enabled)",
    )]
    pub no_checksum: bool,

    #[arg(
        short = 'm',
        help = "Path to the file where the process ID will be stored"
    )]
    pub pidfile: Option<PathBuf>,

    #[arg(
        short = 'b',
        default_value_t = 65536,
        help = "Size of the receive buffer in bytes"
    )]
    pub buflen: usize,

    #[arg(
        short = 'u',
        default_value_t = 65536,
        help = "Size of the send buffer in bytes"
    )]
    pub pdulen: usize,

    #[arg(
        required = true,
        help = "Reveiver addresses to forward packets to. IPv4 example: 127.0.0.1:5000, IPv6 example: [::1]:5000"
    )]
    pub receiver: Vec<SocketAddr>,

    #[arg(
        short = 't',
        default_value_t = 64,
        help = "Time to live (TTL) for forwarded packets"
    )]
    pub ttl: u8,

    #[arg(
        short = 'f',
        action = ArgAction::SetTrue,
        help = "Fork the process into the background"
    )]
    pub fork: bool,
}
