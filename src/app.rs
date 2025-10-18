use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{io, process};

use anyhow::{Result, anyhow};
use log::{debug, error, info};
use nix::unistd::daemon;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{MutableIpv4Packet, checksum as ipv4_checksum};
use pnet_packet::ipv6::MutableIpv6Packet;
use pnet_packet::udp::{
    MutableUdpPacket, ipv4_checksum as udp_ipv4_checksum, ipv6_checksum as udp_ipv6_checksum,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::cli::Cli;

const IPV4_HEADER_SIZE: usize = 20;

const IPV6_HEADER_SIZE: usize = 40;

const UDP_HEADER_SIZE: usize = 8;

fn build_ipv4_udp_packet(
    buf: &mut [u8],
    src_addr: Ipv4Addr,
    src_port: u16,
    dst_addr: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
    no_checksum: bool,
) {
    buf[..].fill(0);

    {
        let mut udp_packet = MutableUdpPacket::new(&mut buf[IPV4_HEADER_SIZE..]).unwrap();

        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length((payload.len() + UDP_HEADER_SIZE) as u16);
        udp_packet.set_payload(&payload);

        if !no_checksum {
            let checksum = udp_ipv4_checksum(&udp_packet.to_immutable(), &src_addr, &dst_addr);
            udp_packet.set_checksum(checksum);
        }
    }

    let mut ip_packet = MutableIpv4Packet::new(&mut buf[..]).unwrap();

    ip_packet.set_version(4);
    ip_packet.set_header_length(IPV4_HEADER_SIZE as u8 / 4);
    ip_packet.set_total_length((payload.len() + IPV4_HEADER_SIZE + UDP_HEADER_SIZE) as u16);
    ip_packet.set_ttl(ttl);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(src_addr);
    ip_packet.set_destination(dst_addr);

    if !no_checksum {
        let ip_checksum = ipv4_checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(ip_checksum);
    }
}

fn build_ipv6_udp_packet(
    buf: &mut [u8],
    src_addr: Ipv6Addr,
    src_port: u16,
    dst_addr: Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
    no_checksum: bool,
) {
    buf[..].fill(0);

    {
        let mut udp_packet = MutableUdpPacket::new(&mut buf[IPV6_HEADER_SIZE..]).unwrap();

        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length((payload.len() + UDP_HEADER_SIZE) as u16);
        udp_packet.set_payload(&payload);

        if !no_checksum {
            let checksum = udp_ipv6_checksum(&udp_packet.to_immutable(), &src_addr, &dst_addr);
            udp_packet.set_checksum(checksum);
        }
    }

    let mut ip_packet = MutableIpv6Packet::new(&mut buf[..]).unwrap();

    ip_packet.set_version(6);
    ip_packet.set_payload_length((payload.len() + UDP_HEADER_SIZE) as u16);
    ip_packet.set_next_header(IpNextHeaderProtocols::Udp);
    ip_packet.set_hop_limit(ttl);
    ip_packet.set_source(src_addr);
    ip_packet.set_destination(dst_addr);
}

pub fn run(cli: Cli) -> Result<()> {
    cli.receiver
        .iter()
        .all(|i| match (cli.address, i.ip()) {
            (IpAddr::V4(_), IpAddr::V4(_)) => true,
            (IpAddr::V6(_), IpAddr::V6(_)) => true,
            _ => false,
        })
        .then_some(())
        .ok_or_else(|| {
            anyhow!("All receiver addresses must be of the same type as the listening address")
        })?;

    if let Some(pidfile) = &cli.pidfile {
        let pid = process::id();

        std::fs::write(pidfile, pid.to_string())?;

        info!("PID written to {:?}", pidfile);
    }

    if cli.fork {
        daemon(false, false)?;
    }

    let socket_addr: SocketAddr = format!("{}:{}", cli.address, cli.port).parse()?;

    info!("Listening on {}", socket_addr);

    let domain = Domain::for_address(socket_addr);

    let udp_sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    udp_sock.set_reuse_port(true)?;
    udp_sock.set_recv_buffer_size(cli.buflen)?;
    udp_sock.set_send_buffer_size(cli.pdulen)?;

    udp_sock.bind(&socket2::SockAddr::from(socket_addr))?;

    let raw_sock = Socket::new(domain, Type::RAW, Some(Protocol::UDP))?;

    raw_sock.set_recv_buffer_size(0)?; // we are not interested in reading from this socket.
    raw_sock.set_send_buffer_size(cli.pdulen)?;

    debug!("Config: {:#?}", cli);

    match domain {
        Domain::IPV4 => {
            udp_sock.set_ttl_v4(cli.ttl.into())?;
            raw_sock.set_header_included_v4(true)?;
        }
        Domain::IPV6 => {
            // NOTE: set libc::IPV6_HOPLIMIT is missing in socket2
            raw_sock.set_header_included_v6(true)?;
        }
        _ => panic!("Unsupported domain"),
    }

    let mut buf = vec![MaybeUninit::<u8>::uninit(); cli.buflen];

    let mut buf_new_packet = vec![0; cli.pdulen];

    loop {
        match udp_sock.recv_from(&mut buf) {
            Ok((size, src_sock_addr)) => {
                let src_addr = src_sock_addr.as_socket().unwrap();

                debug!("Received {} bytes from {:?}", size, src_addr);

                let payload = unsafe {
                    std::slice::from_raw_parts(buf[..size].as_mut_ptr() as *mut u8, size)
                };

                debug!("Payload: {:?}", payload);

                for dst_addr in cli.receiver.iter() {
                    let dst_sock_addr = SockAddr::from(*dst_addr);

                    let send_result: io::Result<usize>;

                    if cli.spoof {
                        match (src_addr.ip(), dst_addr.ip()) {
                            (IpAddr::V4(src_ipv4), IpAddr::V4(dst_ipv4)) => {
                                build_ipv4_udp_packet(
                                    &mut buf_new_packet
                                        [..size + IPV4_HEADER_SIZE + UDP_HEADER_SIZE],
                                    src_ipv4,
                                    src_addr.port(),
                                    dst_ipv4,
                                    dst_addr.port(),
                                    payload,
                                    cli.ttl,
                                    cli.no_checksum,
                                );

                                send_result = raw_sock.send_to(
                                    &buf_new_packet[..size + IPV4_HEADER_SIZE + UDP_HEADER_SIZE],
                                    &dst_sock_addr,
                                );
                            }
                            (IpAddr::V6(src_ipv6), IpAddr::V6(dst_ipv6)) => {
                                build_ipv6_udp_packet(
                                    &mut buf_new_packet
                                        [..size + IPV6_HEADER_SIZE + UDP_HEADER_SIZE],
                                    src_ipv6,
                                    src_addr.port(),
                                    dst_ipv6,
                                    dst_addr.port(),
                                    payload,
                                    cli.ttl,
                                    cli.no_checksum,
                                );

                                send_result = raw_sock.send_to(
                                    &buf_new_packet[..size + IPV6_HEADER_SIZE + UDP_HEADER_SIZE],
                                    &dst_sock_addr,
                                );
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        send_result = udp_sock.send_to(payload, &dst_sock_addr);
                    }

                    match send_result {
                        Ok(sent_size) => {
                            debug!("Sent {} bytes to {}", sent_size, dst_addr);
                        }
                        Err(e) => {
                            error!("Failed to send packet: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to receive packet: {}", e);
            }
        }
    }
}
