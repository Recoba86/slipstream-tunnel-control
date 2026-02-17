# slipstream-tunnel

**English** | [فارسی](README.fa.md)

Slipstream DNS tunnel setup with automatic DNS server scanning via dnscan.

The installer auto-installs missing runtime dependencies (for example `sshpass`, `openssh-client`, and DNS tools) when possible.

## Quick Start

### Server (outside Iran)

```bash
curl -fsSL https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh | sudo bash -s -- server
```

Follow the prompts to configure Cloudflare DNS.

### Client (inside Iran)

```bash
curl -fsSL https://raw.githubusercontent.com/Recoba86/slipstream-tunnel-control/main/install.sh | sudo bash -s -- client
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
- OpenSSH server installed (`sshd`) if using SSH auth overlay

### Client

- Linux machine with root access
- `ssh` + `sshpass` installed if using SSH auth client overlay
- For offline:
  - [dnscan releases](https://github.com/nightowlnerd/dnscan/releases)
  - [slipstream releases](https://github.com/nightowlnerd/slipstream-rust/releases)

Uses a [fork of slipstream-rust](https://github.com/nightowlnerd/slipstream-rust) with fixes for CPU spin and connection stall bugs. The upstream repo is no longer actively maintained.

You can also test an experimental core with `--core plus` (downloads from [Fox-Fig/slipstream-rust-plus-deploy](https://github.com/Fox-Fig/slipstream-rust-plus-deploy)). Default remains `nightowl`.

## Commands

```bash
slipstream-tunnel server    # Setup server
slipstream-tunnel client    # Setup client
slipstream-tunnel edit      # Edit saved settings (domain/port/...)
slipstream-tunnel start     # Start tunnel service (current mode)
slipstream-tunnel stop      # Stop tunnel service (current mode)
slipstream-tunnel restart   # Restart tunnel service (current mode)
slipstream-tunnel status    # Show current status
slipstream-tunnel logs      # View logs (add -f to follow)
slipstream-tunnel health    # Check DNS and switch if slow
slipstream-tunnel rescan    # Manual DNS rescan + switch best server
slipstream-tunnel dashboard # Small client dashboard
slipstream-tunnel servers   # Full verified DNS list (live ping + DNS latency)
slipstream-tunnel menu      # Interactive monitoring menu (client/server)
sst                         # Short command for monitor menu
slipstream-tunnel speed-profile [fast|secure|status] # Toggle/check profile
slipstream-tunnel core-switch [nightowl|plus] # Switch core in-place after install
slipstream-tunnel auth-setup # Enable/update SSH auth overlay (server mode)
slipstream-tunnel auth-disable # Disable SSH auth overlay (server mode)
slipstream-tunnel auth-client-enable # Enable SSH auth overlay (client mode)
slipstream-tunnel auth-client-disable # Disable SSH auth overlay (client mode)
slipstream-tunnel auth-add   # Create SSH tunnel user
slipstream-tunnel auth-passwd # Change SSH tunnel user password
slipstream-tunnel auth-del   # Delete SSH tunnel user
slipstream-tunnel auth-list  # List SSH tunnel users
slipstream-tunnel uninstall # Remove everything
slipstream-tunnel remove    # Remove everything
```

Inside `menu`, actions are grouped into compact submenus (monitoring, service, auth/profile) for both server and client.

## Options

| Option         | Description                               |
| -------------- | ----------------------------------------- |
| `--domain`     | Tunnel domain (e.g., t.example.com)       |
| `--port`       | Server: target port / Client: listen port |
| `--core`       | Core source: `nightowl` (default) or `plus` (experimental) |
| `--dns-file`   | Custom DNS server list (skips subnet scan)|
| `--dnscan`     | Path to dnscan tarball (offline mode)     |
| `--slipstream` | Path to slipstream binary (offline mode)  |
| `--manage-resolver` | Allow server setup to edit resolver config |
| `--ssh-auth`   | Server: enable SSH username/password auth overlay |
| `--ssh-backend-port` | Server: SSH daemon port behind slipstream when auth is enabled |
| `--ssh-auth-client` | Client: enable SSH username/password overlay |
| `--ssh-user`   | Client: SSH username for auth overlay |
| `--ssh-pass`   | Client: SSH password for auth overlay |

## How It Works

For A/B testing on a separate branch/environment:

```bash
slipstream-tunnel server --core plus --domain t.example.com
slipstream-tunnel client --core plus --domain t.example.com
```

### Server Setup

1. Guides Cloudflare DNS configuration (A + NS records)
2. Verifies DNS with `dig`
3. Auto-detects port 53 conflicts and attempts automatic safe remediation
4. Generates self-signed certificate
5. Downloads and installs slipstream-server binary
6. Creates and starts systemd service
7. Optional: enables SSH auth overlay and creates tunnel users

### Client Setup

1. Downloads dnscan and slipstream binaries (cached for reuse)
2. Prompts for tunnel listen port (default: 7000)
3. Prompts for scan settings (country, mode, workers, timeout)
4. Scans and verifies DNS servers with actual tunnel connection
5. Picks fastest verified server and starts slipstream-client
6. Optional: asks SSH username/password and enables client SSH auth overlay
7. Sets up hourly health check and opens interactive monitor menu

### Health Check

- Runs every hour via systemd timer
- Tests current DNS server latency
- If latency > 1000ms, switches to better server
- Logs to `~/.tunnel/health.log`
- You can trigger checks manually with `slipstream-tunnel health` or full rescan with `slipstream-tunnel rescan`
- Use `slipstream-tunnel dashboard` or `slipstream-tunnel menu` for manual monitoring

## SSH Auth Overlay

- During `server` setup, you can enable SSH username/password overlay.
- Script creates a dedicated SSH match-group (`slipstream-tunnel`) and tunnel users.
- Tunnel users are restricted to port-forwarding rules (no normal shell access expected).
- During `client` setup, you can enable SSH auth client mode and provide username/password.
- Manage server users later with: `auth-add`, `auth-passwd`, `auth-del`, `auth-list`.
- You can toggle overlays later with:
  - Server: `auth-setup` / `auth-disable`
  - Client: `auth-client-enable` / `auth-client-disable`

## Speed Profiles

- `slipstream-tunnel speed-profile secure`: SSH overlay ON (more secure, more overhead)
- `slipstream-tunnel speed-profile fast`: SSH overlay OFF (lower overhead, higher throughput)
- `slipstream-tunnel speed-profile status`: show current profile

In fast profile, use the Iran client public port directly (usually `7000`).

## TCP Tuning (BBR)

- Installer and edit flows attempt to enable `bbr` + `fq` automatically when kernel support exists.
- Verify with:
  - `sysctl net.ipv4.tcp_available_congestion_control`
  - `sysctl net.ipv4.tcp_congestion_control`
  - `sysctl net.core.default_qdisc`

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
  - https://github.com/Fox-Fig/slipstream-rust-plus-deploy/releases
