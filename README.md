# UDP Samplicator

A simple UDP packet samplicator written in Rust. Inspired by the original [samplicator](https://github.com/sleinen/samplicator).

## Usage

```
Usage: samplicator [OPTIONS] <RECEIVER>...

Arguments:
  <RECEIVER>...  Reveiver addresses to forward packets to. IPv4 example: 127.0.0.1:5000, IPv6 example: [::1]:5000

Options:
  -s <ADDRESS>      Address to listen on [default: 0.0.0.0]
  -p <PORT>         Port to listen on [default: 2000]
  -S                Enable spoofing of source IP address and port
  -n                Disable checksum calculation (only works with spoofing enabled)
  -m <PIDFILE>      Path to the file where the process ID will be stored
  -b <BUFLEN>       Size of the receive buffer in bytes [default: 65536]
  -u <PDULEN>       Size of the send buffer in bytes [default: 65536]
  -t <TTL>          Time to live (TTL) for forwarded packets [default: 64]
  -f                Fork the process into the background
  -h, --help        Print help
  -V, --version     Print version
```
