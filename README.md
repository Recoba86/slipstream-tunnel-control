# slipstream-tunnel

**English** | [فارسی](README.fa.md)

Slipstream DNS tunnel setup with automatic DNS server scanning via dnscan.

## Quick Start

### Server (outside Iran)

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh) server
```

Follow the prompts to configure Cloudflare DNS.

### Client (inside Iran)

```bash
sudo bash <(curl -Ls https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh) client
```

After install, `slipstream-tunnel` command is available globally.

### Offline Mode

If network is blocked, download binaries first then provide paths:

```bash
slipstream-tunnel client --dnscan ./dnscan.tar.gz --slipstream ./slipstream-client
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
  - [slipstream releases](https://github.com/nightowlnerd/slipstream-rust/releases)

Uses a [fork of slipstream-rust](https://github.com/nightowlnerd/slipstream-rust) with fixes for CPU spin and connection stall bugs. The upstream repo is no longer actively maintained.

## Commands

```bash
slipstream-tunnel server    # Setup server
slipstream-tunnel client    # Setup client
slipstream-tunnel status    # Show current status
slipstream-tunnel logs      # View logs (add -f to follow)
slipstream-tunnel health    # Check DNS and switch if slow
slipstream-tunnel rescan    # Manual DNS rescan + switch best server
slipstream-tunnel dashboard # Small client dashboard
slipstream-tunnel servers   # Full verified DNS list (live ping + DNS latency)
slipstream-tunnel menu      # Interactive monitoring menu
sst                         # Short command for client menu
slipstream-tunnel remove    # Remove everything
```

Inside `menu`, you can also manually select a DNS server from the verified list and switch instantly.

## Options

| Option         | Description                               |
| -------------- | ----------------------------------------- |
| `--domain`     | Tunnel domain (e.g., t.example.com)       |
| `--port`       | Server: target port / Client: listen port |
| `--dns-file`   | Custom DNS server list (skips subnet scan)|
| `--dnscan`     | Path to dnscan tarball (offline mode)     |
| `--slipstream` | Path to slipstream binary (offline mode)  |
| `--manage-resolver` | Allow server setup to edit resolver config |

## How It Works

### Server Setup

1. Guides Cloudflare DNS configuration (A + NS records)
2. Verifies DNS with `dig`
3. Generates self-signed certificate
4. Downloads and installs slipstream-server binary
5. Creates and starts systemd service

### Client Setup

1. Downloads dnscan and slipstream binaries (cached for reuse)
2. Prompts for tunnel listen port (default: 7000)
3. Prompts for scan settings (country, mode, workers, timeout)
4. Scans and verifies DNS servers with actual tunnel connection
5. Picks fastest verified server and starts slipstream-client
6. Sets up hourly health check and opens interactive monitor menu

### Health Check

- Runs every hour via systemd timer
- Tests current DNS server latency
- If latency > 1000ms, switches to better server
- Logs to `~/.tunnel/health.log`
- You can trigger checks manually with `slipstream-tunnel health` or full rescan with `slipstream-tunnel rescan`
- Use `slipstream-tunnel dashboard` or `slipstream-tunnel menu` for manual monitoring

## Files

```
~/.tunnel/
├── config          # Current configuration
├── servers.txt     # Working DNS servers from scan
├── health.log      # Health check history
└── dnscan/         # dnscan binary and data
```

## x-ui Setup

After running the script on both server and client:

1. **Open x-ui panel** on your server (3x-ui, x-ui, etc.)

2. **Create inbound** listening on slipstream server port
   - Port: `2053` (or your `--port` value)
   - Protocol: VLESS/VMess/etc.

3. **Add external proxy** to the inbound
   - Host: IP address of your Iran client machine
   - Port: `7000` (or your client `--port` value)

4. **Export config** and use in your V2Ray app

## Troubleshooting

**Server: "DNS not configured"**

- Check Cloudflare DNS records
- Wait 5 minutes for DNS propagation
- Verify with: `dig NS t.example.com`

**Client: "No DNS servers passed verification"**

- Is the server running? `systemctl status slipstream-server`
- Is port 53 open on server?
- Check server logs: `journalctl -u slipstream-server -f`

**Client: "Cannot download"**

- Network is blocked
- Use offline mode with `--dnscan` and `--slipstream` options
- Get binaries from:
  - https://github.com/nightowlnerd/dnscan/releases
  - https://github.com/nightowlnerd/slipstream-rust/releases
