# rcroc

A Rust implementation of a croc-style file transfer tool (rcroc protocol).

## 1-minute quick start

Start a relay (server):

```bash
rcroc relay --listen 0.0.0.0:9009
```

Sender:

```bash
rcroc send /path/to/file --relay 107.174.204.124:9009
```

The sender will print output like this:

```text
Code is: fLuOQ4XY

On the other computer run

rcroc fLuOQ4XY --relay 107.174.204.124:9009
```

Receiver (shorthand):

```bash
rcroc fLuOQ4XY --relay 107.174.204.124:9009
```

Full form is also supported:

```bash
rcroc receive --secret fLuOQ4XY --relay 107.174.204.124:9009
```

## Default behavior (no need to type these)

- LAN discovery and LAN data-path upgrade are enabled by default (can automatically bypass remote relay for LAN transfer)
- Default `--transfers 4`
- Default `--hash-algorithm xxh3`
- Default `--relay-password pass`
- Default output directory `--out .`

In normal usage, you can omit these default arguments.

## Progress display

- Sender: each file shows a `Sending ...` progress bar, percentage, and throughput.
- Receiver: each file shows a `Receiving ...` progress bar, percentage, and throughput.

## Common scenarios

Send a directory:

```bash
rcroc send ./my-dir --relay 107.174.204.124:9009
```

Set receiver output directory:

```bash
rcroc fLuOQ4XY --relay 107.174.204.124:9009 --out /tmp/downloads
```

Disable LAN discovery (force relay-only path):

```bash
rcroc send ./file.bin --relay 107.174.204.124:9009 --no-lan-discovery
```

Custom relay password (must match on both sides):

```bash
rcroc send ./file.bin --relay 107.174.204.124:9009 --relay-password yourpass
rcroc fLuOQ4XY --relay 107.174.204.124:9009 --relay-password yourpass
```

## Development build

```bash
cargo build --release
```

## Core capabilities

- Relay mode (room matching + bidirectional pipe)
- End-to-end encrypted transfer (P-256 ECDH + PBKDF2 + AES-256-GCM)
- Multi-file and directory transfer (including empty directories)
- Resume support
- Multi-stream parallel transfer
- LAN discovery + LAN data-path upgrade
- Proxy support (SOCKS5, HTTP CONNECT)
- `.gitignore` filtering

## Known limitations

- Only rcroc protocol compatibility is guaranteed; compatibility with Go `croc` is not guaranteed
- Rate limit, QR, and SOCKS5/HTTP auth headers are not implemented yet
