# dns-tunnel-setup

**English** | [فارسی](README.fa.md)

Automated DNS tunnel setup with slipstream. One script for server and client.

## Quick Start

### Server (outside Iran)

```bash
curl -O https://raw.githubusercontent.com/nightowlnerd/dns-tunnel-setup/main/dns-tunnel.sh
chmod +x dns-tunnel.sh
./dns-tunnel.sh server
```

Follow the prompts to configure Cloudflare DNS.

### Client (inside Iran)

```bash
# If network is not blocked:
curl -O https://raw.githubusercontent.com/nightowlnerd/dns-tunnel-setup/main/dns-tunnel.sh
chmod +x dns-tunnel.sh
./dns-tunnel.sh client

# If network is blocked (offline mode):
./dns-tunnel.sh client --dnscan ./dnscan-linux-amd64.tar.gz --slipstream ./slipstream-client-linux-amd64
```

## Prerequisites

### Server

- VPS with root access
- Domain with Cloudflare DNS
- 3x-ui panel installed (or any V2ray panel)

### Client

- Linux machine with root access
- For offline:
  - [dnscan releases](https://github.com/nightowlnerd/dnscan/releases)
  - [slipstream releases](https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases)

## Commands

```bash
./dns-tunnel.sh server              # Setup server
./dns-tunnel.sh client              # Setup client
./dns-tunnel.sh status              # Show current status
./dns-tunnel.sh health              # Check DNS and switch if slow
./dns-tunnel.sh remove              # Remove everything
```

## Options

| Option         | Description                               |
| -------------- | ----------------------------------------- |
| `--domain`     | Tunnel domain (e.g., t.example.com)       |
| `--port`       | Server: target port / Client: listen port |
| `--dns-file`   | Custom DNS server list (skips subnet scan)|
| `--dnscan`     | Path to dnscan tarball (offline mode)     |
| `--slipstream` | Path to slipstream binary (offline mode)  |
| `--docker`     | Use Docker instead of binary              |

## How It Works

### Server Setup

1. Guides Cloudflare DNS configuration (A + NS records)
2. Verifies DNS with `dig`
3. Generates self-signed certificate
4. Downloads and installs slipstream-server binary
5. Creates and starts systemd service

### Client Setup

1. Downloads dnscan and slipstream binaries (cached for reuse)
2. Prompts for scan settings (country, mode, workers, timeout)
3. Scans and verifies DNS servers with actual tunnel connection
4. Picks fastest verified server and starts slipstream-client
5. Sets up hourly health check

### Health Check

- Runs every hour via systemd timer
- Tests current DNS server latency
- If latency > 1000ms, switches to better server
- Logs to `~/.tunnel/health.log`

## Files

```
~/.tunnel/
├── config          # Current configuration
├── servers.txt     # Working DNS servers from scan
├── health.log      # Health check history
└── dnscan/         # dnscan binary and data
```

## Troubleshooting

**Server: "DNS not configured"**

- Check Cloudflare DNS records
- Wait 5 minutes for DNS propagation
- Verify with: `dig NS t.example.com`

**Client: "No DNS servers passed verification"**

- Is the server running?
  - Binary: `systemctl status slipstream-server`
  - Docker: `docker ps | grep slipstream`
- Is port 53 open on server?
- Check server logs:
  - Binary: `journalctl -u slipstream-server -f`
  - Docker: `docker logs slipstream-server -f`

**Client: "Cannot download"**

- Network is blocked
- Use offline mode with `--dnscan` and `--slipstream` options
- Get binaries from:
  - https://github.com/nightowlnerd/dnscan/releases
  - https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases