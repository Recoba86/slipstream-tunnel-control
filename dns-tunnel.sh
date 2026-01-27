#!/usr/bin/env bash
# DNS Tunnel Setup - Automated slipstream tunnel configuration
set -euo pipefail

# =============================================================================
# Slipstream source configuration
# Change these when upstream provides official releases or Docker images
# =============================================================================
# Binary releases (default mode)
# Switch to "Mygod/slipstream-rust" when they publish releases
SLIPSTREAM_REPO="AliRezaBeigy/slipstream-rust-deploy"
SLIPSTREAM_TAG="5fc4ecd"

# Docker image (--docker mode)
# Switch to official image when available
SLIPSTREAM_DOCKER_IMAGE="bashsiz/slipstream-rust:latest"
# =============================================================================

TUNNEL_DIR="$HOME/.tunnel"
DNSCAN_DIR="$TUNNEL_DIR/dnscan"
SERVERS_FILE="$TUNNEL_DIR/servers.txt"
CONFIG_FILE="$TUNNEL_DIR/config"
HEALTH_LOG="$TUNNEL_DIR/health.log"
CERT_DIR="/opt/slipstream/cert"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() {
  echo -e "${RED}[x]${NC} $1"
  exit 1
}

need_root() {
  [[ $EUID -eq 0 ]] || error "Run as root (sudo)"
}

usage() {
  cat <<EOF
Usage: $0 <command> [options]

Commands:
  server              Setup slipstream server
  client              Setup slipstream client
  health              Run health check (called by timer)
  status              Show current status
  remove              Remove all tunnel components

Options:
  --domain <domain>   Tunnel domain (e.g., t.example.com)
  --port <port>       Server: target port (default: 2053)
                      Client: listen port (default: 7000)
  --docker            Use Docker instead of binary (optional)
  --slipstream <path> Path to slipstream binary or Docker tarball (offline)
  --dnscan <path>     Path to dnscan tarball (client offline install)

Examples:
  $0 server --domain t.example.com
  $0 client --domain t.example.com
  $0 client --domain t.example.com --dnscan ./dnscan-linux-amd64.tar.gz --slipstream ./slipstream.tar.gz
EOF
  exit 0
}

detect_arch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
  x86_64) echo "amd64" ;;
  aarch64 | arm64) echo "arm64" ;;
  *) error "Unsupported architecture: $arch" ;;
  esac
}

detect_os() {
  local os
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  [[ "$os" == "linux" ]] || error "Unsupported OS: $os (Linux only)"
  echo "linux"
}

# ============================================
# SERVER MODE
# ============================================
cmd_server() {
  need_root
  local domain="" port="2053" use_docker=false slipstream_path=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
    --domain)
      domain="$2"
      shift 2
      ;;
    --port)
      port="$2"
      shift 2
      ;;
    --docker)
      use_docker=true
      shift
      ;;
    --slipstream)
      slipstream_path="$2"
      shift 2
      ;;
    *) shift ;;
    esac
  done

  log "=== Slipstream Server Setup ==="

  # Get server IP
  log "Detecting server IP..."
  local server_ip
  server_ip=$(curl -s --connect-timeout 5 ifconfig.me)
  [[ -z "$server_ip" ]] && server_ip=$(curl -s --connect-timeout 5 ip.me)
  [[ -z "$server_ip" ]] && server_ip=$(hostname -I | awk '{print $1}')

  if [[ -z "$server_ip" ]]; then
    read -p "Could not detect IP. Enter server IP: " server_ip
  fi

  echo ""
  echo -e "${YELLOW}=== Cloudflare DNS Setup ===${NC}"
  echo ""
  echo "Add these DNS records in Cloudflare for your domain:"
  echo ""
  echo "  1. A record:"
  echo "     Name: ns"
  echo "     Content: $server_ip"
  echo ""
  echo "  2. NS record:"
  echo "     Name: t"
  echo "     Content: ns.<your-domain>"
  echo ""
  echo "Example for 'example.com':"
  echo "  A  -> ns.example.com  -> $server_ip"
  echo "  NS -> t.example.com   -> ns.example.com"
  echo ""

  # Get domain if not provided
  if [[ -z "$domain" ]]; then
    read -p "Enter tunnel domain (e.g., t.example.com): " domain
  fi

  # Confirm DNS setup
  read -p "DNS configured? (y/n): " confirm
  [[ "$confirm" != "y" ]] && error "Please configure DNS first, then run again."

  # Try to verify (informational only)
  log "Checking DNS..."
  if command -v dig &>/dev/null; then
    local ns_host trace_output
    trace_output=$(timeout 30 dig -4 +trace +time=3 "$domain" 2>/dev/null || true)

    if [[ -n "$trace_output" ]]; then
      ns_host=$(echo "$trace_output" | grep -i "IN.*NS" | grep -i "$domain" | awk '{print $5}' | sed 's/\.$//' | head -1 || true)

      if [[ -n "$ns_host" ]]; then
        local ns_ip
        ns_ip=$(dig +short +time=3 A "$ns_host" @8.8.8.8 2>/dev/null || true)
        if [[ -n "$ns_ip" ]]; then
          log "NS delegation: $domain -> $ns_host -> $ns_ip"
          if [[ "$ns_ip" == "$server_ip" ]]; then
            log "DNS configured correctly"
          else
            warn "NS points to $ns_ip, but this server is $server_ip"
          fi
        else
          warn "Could not resolve $ns_host (DNS may still be propagating)"
        fi
      else
        warn "Could not find NS record (DNS may still be propagating)"
      fi
    else
      warn "DNS trace timed out"
    fi
  else
    warn "dig not installed, skipping DNS verification"
  fi
  log "Continuing with setup..."

  # Free port 53
  if systemctl is-active systemd-resolved &>/dev/null; then
    log "Stopping systemd-resolved to free port 53..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
  fi

  # Fix DNS resolution (handle symlink case)
  if [[ -L /etc/resolv.conf ]] || [[ ! -f /etc/resolv.conf ]]; then
    log "Fixing DNS configuration..."
    rm -f /etc/resolv.conf
    echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" >/etc/resolv.conf
  fi

  # Generate self-signed cert
  mkdir -p "$CERT_DIR"
  if [[ ! -f "$CERT_DIR/key.pem" ]]; then
    log "Generating self-signed certificate..."
    openssl genrsa -out "$CERT_DIR/key.pem" 2048
    openssl req -x509 -new -nodes \
      -key "$CERT_DIR/key.pem" \
      -out "$CERT_DIR/cert.pem" \
      -days 365 \
      -subj "/CN=$domain"
  fi

  local runtime="binary"

  if [[ "$use_docker" == true ]]; then
    # --- Docker mode ---
    runtime="docker"

    if ! command -v docker &>/dev/null; then
      log "Installing Docker..."
      curl -fsSL https://get.docker.com | sh
      systemctl enable docker
      systemctl start docker
    fi

    log "Pulling slipstream Docker image..."
    docker pull "$SLIPSTREAM_DOCKER_IMAGE" || warn "Pull failed, using cached image"

    docker rm -f slipstream-server 2>/dev/null || true

    log "Starting slipstream server (Docker)..."
    docker run -d --restart=unless-stopped \
      --name slipstream-server \
      --network host \
      -v "$CERT_DIR":/opt/cert:ro \
      "$SLIPSTREAM_DOCKER_IMAGE" \
      slipstream-server \
      --dns-listen-port 53 \
      --target-address "127.0.0.1:$port" \
      --domain "$domain" \
      --cert /opt/cert/cert.pem \
      --key /opt/cert/key.pem

    # Create client tarball for transfer
    log "Creating client tarball for transfer..."
    docker save "$SLIPSTREAM_DOCKER_IMAGE" | gzip >~/slipstream-client.tar.gz

  else
    # --- Binary mode (default) ---
    local arch bin_url bin_path="/usr/local/bin/slipstream-server"
    arch=$(detect_arch)

    # Stop existing service
    systemctl stop slipstream-server 2>/dev/null || true

    if [[ -n "$slipstream_path" ]]; then
      log "Installing slipstream-server from $slipstream_path..."
      cp "$slipstream_path" "$bin_path"
    else
      bin_url="https://github.com/${SLIPSTREAM_REPO}/releases/download/${SLIPSTREAM_TAG}/slipstream-server-linux-${arch}"
      log "Downloading slipstream-server..."
      curl -fsSL "$bin_url" -o "$bin_path" || error "Failed to download slipstream-server"
    fi
    chmod +x "$bin_path"

    # Create systemd service
    log "Creating systemd service..."
    cat >/etc/systemd/system/slipstream-server.service <<EOF
[Unit]
Description=Slipstream DNS Tunnel Server
After=network.target

[Service]
Type=simple
ExecStart=$bin_path \\
  --dns-listen-port 53 \\
  --target-address 127.0.0.1:$port \\
  --domain $domain \\
  --cert $CERT_DIR/cert.pem \\
  --key $CERT_DIR/key.pem
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slipstream-server
    systemctl start slipstream-server
    log "Started slipstream-server service"
  fi

  # Save config
  mkdir -p "$TUNNEL_DIR"
  cat >"$CONFIG_FILE" <<EOF
DOMAIN=$domain
MODE=server
RUNTIME=$runtime
PORT=$port
EOF

  echo ""
  echo -e "${GREEN}=== Server Ready ===${NC}"
  echo ""
  echo "Runtime: $runtime"
  echo ""
  echo "Next steps:"
  echo "  1. In 3x-ui panel: create inbound on port $port"
  echo "  2. Transfer slipstream binary/tarball to client"
  echo "  3. On client run: tunnel.sh client --domain $domain"
  echo ""
  if [[ "$runtime" == "docker" ]]; then
    echo "Logs: docker logs -f slipstream-server"
  else
    echo "Logs: journalctl -u slipstream-server -f"
  fi
}

# ============================================
# CLIENT MODE
# ============================================
cmd_client() {
  need_root
  local domain="" dnscan_path="" slipstream_path="" port="7000" use_docker=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
    --domain)
      domain="$2"
      shift 2
      ;;
    --dnscan)
      dnscan_path="$2"
      shift 2
      ;;
    --slipstream)
      slipstream_path="$2"
      shift 2
      ;;
    --port)
      port="$2"
      shift 2
      ;;
    --docker)
      use_docker=true
      shift
      ;;
    *) shift ;;
    esac
  done

  log "=== Slipstream Client Setup ==="

  mkdir -p "$TUNNEL_DIR" "$DNSCAN_DIR"

  # Get dnscan
  local arch os
  arch=$(detect_arch)
  os=$(detect_os)

  if [[ ! -x "$DNSCAN_DIR/dnscan" ]]; then
    if [[ -n "$dnscan_path" ]]; then
      log "Extracting dnscan from $dnscan_path..."
      tar xzf "$dnscan_path" -C "$DNSCAN_DIR"
    else
      log "Downloading dnscan..."
      local url="https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan-${os}-${arch}.tar.gz"
      if curl -fsSL --connect-timeout 15 "$url" -o /tmp/dnscan.tar.gz 2>/dev/null; then
        tar xzf /tmp/dnscan.tar.gz -C "$DNSCAN_DIR"
        rm -f /tmp/dnscan.tar.gz
      else
        echo ""
        warn "Cannot download dnscan (network blocked?)"
        echo ""
        echo "Transfer this file from a non-blocked network:"
        echo "  https://github.com/nightowlnerd/dnscan/releases/latest/download/dnscan-${os}-${arch}.tar.gz"
        echo ""
        read -p "Path to dnscan tarball: " dnscan_path
        tar xzf "$dnscan_path" -C "$DNSCAN_DIR"
      fi
    fi
    chmod +x "$DNSCAN_DIR/dnscan"
  fi

  # Get domain
  if [[ -z "$domain" ]]; then
    read -p "Enter tunnel domain (e.g., t.example.com): " domain
  fi

  # Get slipstream binary (required for --verify)
  local slipstream_bin="/tmp/slipstream-client"
  local bin_url="https://github.com/${SLIPSTREAM_REPO}/releases/download/${SLIPSTREAM_TAG}/slipstream-client-linux-${arch}"

  if [[ -n "$slipstream_path" ]]; then
    log "Copying slipstream-client from $slipstream_path..."
    if ! cp "$slipstream_path" "$slipstream_bin" 2>/dev/null; then
      error "Cannot copy from $slipstream_path"
    fi
  else
    log "Downloading slipstream-client..."
    if ! curl -fsSL "$bin_url" -o "$slipstream_bin" 2>/dev/null; then
      echo ""
      warn "Cannot download slipstream-client (network blocked?)"
      echo ""
      echo "Transfer binary from a non-blocked network:"
      echo "  $bin_url"
      echo ""
      read -p "Path to slipstream-client binary: " slipstream_path
      if [[ -z "$slipstream_path" ]]; then
        error "Binary required for verification. Cannot continue."
      fi
      if ! cp "$slipstream_path" "$slipstream_bin" 2>/dev/null; then
        error "Cannot copy from $slipstream_path"
      fi
    fi
  fi
  chmod +x "$slipstream_bin"

  # Scan settings
  echo ""
  echo -e "${YELLOW}=== DNS Scan Settings ===${NC}"
  echo ""
  echo "Modes:"
  echo "  list   - Known working DNS servers (fastest)"
  echo "  fast   - Sample common IPs per subnet (default)"
  echo "  medium - More IPs per subnet"
  echo "  all    - All IPs per subnet (slowest)"
  echo ""
  local scan_country="ir"
  local scan_mode="fast"
  local scan_workers="500"
  local scan_timeout="2s"
  read -p "Country code [ir]: " input_country
  [[ -n "$input_country" ]] && scan_country="$input_country"
  read -p "Scan mode [fast]: " input_mode
  [[ -n "$input_mode" ]] && scan_mode="$input_mode"
  read -p "Workers [500]: " input_workers
  [[ -n "$input_workers" ]] && scan_workers="$input_workers"
  read -p "Timeout [2s]: " input_timeout
  [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"

  # Run dnscan
  log "Scanning for working DNS servers..."
  local dnscan_args=(
    --country "$scan_country"
    --mode "$scan_mode"
    --domain "$domain"
    --data-dir "$DNSCAN_DIR/data"
    --output "$SERVERS_FILE"
    --workers "$scan_workers"
    --timeout "$scan_timeout"
  )
  # Add verify if binary available
  dnscan_args+=(--verify "$slipstream_bin")

  "$DNSCAN_DIR/dnscan" "${dnscan_args[@]}"

  # Check results (dnscan only outputs verified servers)
  if [[ ! -s "$SERVERS_FILE" ]]; then
    error "No DNS servers passed verification. Is your server running correctly?"
  fi

  local server_count
  server_count=$(wc -l <"$SERVERS_FILE")
  log "Found $server_count verified DNS servers"

  # Pick best server (first one)
  local best_server
  best_server=$(head -1 "$SERVERS_FILE")
  log "Using DNS server: $best_server"

  local runtime="binary"

  if [[ "$use_docker" == true ]]; then
    # --- Docker mode ---
    runtime="docker"

    if ! command -v docker &>/dev/null; then
      log "Installing Docker..."
      if curl -fsSL --connect-timeout 10 https://get.docker.com -o /tmp/get-docker.sh 2>/dev/null; then
        sh /tmp/get-docker.sh
        rm -f /tmp/get-docker.sh
        systemctl enable docker
        systemctl start docker
      else
        error "Cannot install Docker. Please install manually and retry."
      fi
    fi

    # Get slipstream Docker image
    if ! docker image inspect "$SLIPSTREAM_DOCKER_IMAGE" &>/dev/null; then
      if [[ -n "$slipstream_path" ]]; then
        log "Loading slipstream image from $slipstream_path..."
        docker load <"$slipstream_path"
      else
        log "Pulling slipstream Docker image..."
        if ! docker pull "$SLIPSTREAM_DOCKER_IMAGE" 2>/dev/null; then
          echo ""
          warn "Cannot pull Docker image (network blocked?)"
          echo ""
          echo "Transfer slipstream-client.tar.gz from your server"
          echo ""
          read -p "Path to slipstream tarball: " slipstream_path
          docker load <"$slipstream_path"
        fi
      fi
    fi

    docker rm -f slipstream-client 2>/dev/null || true

    log "Starting slipstream client (Docker)..."
    docker run -d --restart=unless-stopped \
      --name slipstream-client \
      --network host \
      "$SLIPSTREAM_DOCKER_IMAGE" \
      slipstream-client \
      --resolver "${best_server}:53" \
      --domain "$domain" \
      --tcp-listen-port "$port"

  else
    # --- Binary mode (default) ---
    local bin_path="/usr/local/bin/slipstream-client"

    # Stop existing service
    systemctl stop slipstream-client 2>/dev/null || true

    # Move pre-downloaded binary to final location
    log "Installing slipstream-client..."
    mv "$slipstream_bin" "$bin_path"
    chmod +x "$bin_path"

    # Create systemd service
    log "Creating systemd service..."
    cat >/etc/systemd/system/slipstream-client.service <<EOF
[Unit]
Description=Slipstream DNS Tunnel Client
After=network.target

[Service]
Type=simple
ExecStart=$bin_path \\
  --resolver ${best_server}:53 \\
  --domain $domain \\
  --tcp-listen-port $port
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable slipstream-client
    systemctl start slipstream-client
    log "Started slipstream-client service"
  fi

  # Save config
  cat >"$CONFIG_FILE" <<EOF
DOMAIN=$domain
MODE=client
RUNTIME=$runtime
CURRENT_SERVER=$best_server
PORT=$port
EOF

  # Setup health check timer
  setup_health_timer

  echo ""
  echo -e "${GREEN}=== Client Ready ===${NC}"
  echo ""
  echo "Runtime: $runtime"
  echo "Tunnel running on: 127.0.0.1:$port"
  echo "DNS server: $best_server"
  echo ""
  echo "Configure your V2ray/Nekobox client:"
  echo "  Address: 127.0.0.1"
  echo "  Port: $port"
  echo ""
  echo "Health check: runs hourly, switches DNS if needed"
  if [[ "$runtime" == "docker" ]]; then
    echo "Logs: docker logs -f slipstream-client"
  else
    echo "Logs: journalctl -u slipstream-client -f"
  fi
}

# ============================================
# HEALTH CHECK
# ============================================
cmd_health() {
  [[ ! -f "$CONFIG_FILE" ]] && exit 0
  [[ ! -f "$SERVERS_FILE" ]] && exit 0
  source "$CONFIG_FILE"

  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')

  # Test current server latency
  local latency
  latency=$(test_dns_latency "$CURRENT_SERVER" "$DOMAIN" || echo "9999")

  if [[ "$latency" -gt 1000 ]]; then
    echo "[$timestamp] Current server $CURRENT_SERVER slow (${latency}ms), checking alternatives..." >>"$HEALTH_LOG"

    # Find better server
    local best_server="" best_latency=9999
    while IFS= read -r server; do
      local lat
      lat=$(test_dns_latency "$server" "$DOMAIN" || echo "9999")
      if [[ "$lat" -lt "$best_latency" ]]; then
        best_latency="$lat"
        best_server="$server"
      fi
    done <"$SERVERS_FILE"

    if [[ -n "$best_server" && "$best_server" != "$CURRENT_SERVER" && "$best_latency" -lt 1000 ]]; then
      echo "[$timestamp] Switching to $best_server (${best_latency}ms)" >>"$HEALTH_LOG"

      # Update config
      sed -i "s/CURRENT_SERVER=.*/CURRENT_SERVER=$best_server/" "$CONFIG_FILE"

      # Restart client with new server
      if [[ "${RUNTIME:-docker}" == "docker" ]]; then
        # Docker mode
        docker rm -f slipstream-client 2>/dev/null || true
        if docker run -d --restart=unless-stopped \
          --name slipstream-client \
          --network host \
          "$SLIPSTREAM_DOCKER_IMAGE" \
          slipstream-client \
          --resolver "${best_server}:53" \
          --domain "$DOMAIN" \
          --tcp-listen-port "${PORT:-7000}"; then
          echo "[$timestamp] Switched to $best_server" >>"$HEALTH_LOG"
        else
          echo "[$timestamp] ERROR: container restart failed" >>"$HEALTH_LOG"
        fi
      else
        # Binary mode - update systemd service and restart
        local bin_path="/usr/local/bin/slipstream-client"
        cat >/etc/systemd/system/slipstream-client.service <<EOF
[Unit]
Description=Slipstream DNS Tunnel Client
After=network.target

[Service]
Type=simple
ExecStart=$bin_path \\
  --resolver ${best_server}:53 \\
  --domain $DOMAIN \\
  --tcp-listen-port ${PORT:-7000}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        if systemctl restart slipstream-client; then
          echo "[$timestamp] Switched to $best_server" >>"$HEALTH_LOG"
        else
          echo "[$timestamp] ERROR: service restart failed" >>"$HEALTH_LOG"
        fi
      fi
    else
      echo "[$timestamp] No better server found" >>"$HEALTH_LOG"
    fi
  else
    echo "[$timestamp] Server $CURRENT_SERVER OK (${latency}ms)" >>"$HEALTH_LOG"
  fi

  # Rotate log (keep last 1000 lines)
  if [[ $(wc -l <"$HEALTH_LOG") -gt 1000 ]]; then
    tail -500 "$HEALTH_LOG" >/tmp/health.log.tmp && mv /tmp/health.log.tmp "$HEALTH_LOG"
  fi
}

test_dns_latency() {
  local server="$1" domain="$2"
  local start end
  start=$(date +%s%N)
  if dig +short +time=2 +tries=1 "@$server" "$domain" TXT &>/dev/null; then
    end=$(date +%s%N)
    echo $(((end - start) / 1000000))
  else
    echo "9999"
  fi
}

setup_health_timer() {
  local script_path
  script_path=$(realpath "$0")

  # Create systemd service
  cat >/etc/systemd/system/tunnel-health.service <<EOF
[Unit]
Description=DNS Tunnel Health Check
After=network.target

[Service]
Type=oneshot
ExecStart=$script_path health
EOF

  # Create systemd timer (hourly)
  cat >/etc/systemd/system/tunnel-health.timer <<EOF
[Unit]
Description=DNS Tunnel Health Check Timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable tunnel-health.timer
  systemctl start tunnel-health.timer
  log "Health check timer installed (runs hourly)"
}

# ============================================
# STATUS
# ============================================
cmd_status() {
  echo "=== DNS Tunnel Status ==="
  echo ""

  if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
    echo "Mode: ${MODE:-unknown}"
    echo "Runtime: ${RUNTIME:-docker}"
    echo "Domain: $DOMAIN"
    echo "Port: ${PORT:-7000}"
    [[ -n "${CURRENT_SERVER:-}" ]] && echo "Current DNS: $CURRENT_SERVER"
  else
    echo "Not configured"
    return
  fi

  echo ""
  echo "Services:"
  if [[ "${RUNTIME:-docker}" == "docker" ]]; then
    docker ps --filter "name=slipstream" --format "  {{.Names}}: {{.Status}}" 2>/dev/null || echo "  None"
  else
    # Binary mode - check systemd services
    if [[ "${MODE:-}" == "server" ]]; then
      local status
      status=$(systemctl is-active slipstream-server 2>/dev/null || echo "not running")
      echo "  slipstream-server: $status"
    else
      local status
      status=$(systemctl is-active slipstream-client 2>/dev/null || echo "not running")
      echo "  slipstream-client: $status"
    fi
  fi

  # Health timer only relevant for client
  if [[ "${MODE:-}" == "client" ]]; then
    echo ""
    if systemctl list-unit-files tunnel-health.timer &>/dev/null; then
      echo "Health timer: $(systemctl is-active tunnel-health.timer 2>/dev/null)"
    else
      echo "Health timer: not installed"
    fi

    if [[ -f "$HEALTH_LOG" ]]; then
      echo ""
      echo "Recent health checks:"
      tail -5 "$HEALTH_LOG" | sed 's/^/  /'
    fi
  fi
}

# ============================================
# REMOVE
# ============================================
cmd_remove() {
  need_root
  log "=== Removing DNS Tunnel ==="

  # Stop and remove Docker containers (if any)
  if command -v docker &>/dev/null; then
    if docker ps -a --format '{{.Names}}' | grep -q slipstream; then
      log "Stopping slipstream Docker containers..."
      docker rm -f slipstream-server slipstream-client 2>/dev/null || true
    fi

    # Remove Docker image
    if docker images bashsiz/slipstream-rust -q 2>/dev/null | grep -q .; then
      log "Removing slipstream Docker image..."
      docker rmi bashsiz/slipstream-rust:latest 2>/dev/null || true
    fi
  fi

  # Stop and remove systemd services (binary mode)
  if [[ -f /etc/systemd/system/slipstream-server.service ]]; then
    log "Stopping slipstream-server service..."
    systemctl stop slipstream-server 2>/dev/null || true
    systemctl disable slipstream-server 2>/dev/null || true
    rm -f /etc/systemd/system/slipstream-server.service
  fi

  if [[ -f /etc/systemd/system/slipstream-client.service ]]; then
    log "Stopping slipstream-client service..."
    systemctl stop slipstream-client 2>/dev/null || true
    systemctl disable slipstream-client 2>/dev/null || true
    rm -f /etc/systemd/system/slipstream-client.service
  fi

  # Remove binaries
  if [[ -f /usr/local/bin/slipstream-server ]]; then
    log "Removing slipstream-server binary..."
    rm -f /usr/local/bin/slipstream-server
  fi

  if [[ -f /usr/local/bin/slipstream-client ]]; then
    log "Removing slipstream-client binary..."
    rm -f /usr/local/bin/slipstream-client
  fi

  # Remove health check timer
  if [[ -f /etc/systemd/system/tunnel-health.timer ]]; then
    log "Removing health check timer..."
    systemctl stop tunnel-health.timer 2>/dev/null || true
    systemctl disable tunnel-health.timer 2>/dev/null || true
    rm -f /etc/systemd/system/tunnel-health.timer
    rm -f /etc/systemd/system/tunnel-health.service
  fi

  systemctl daemon-reload

  # Remove tunnel directory
  if [[ -d "$TUNNEL_DIR" ]]; then
    log "Removing $TUNNEL_DIR..."
    rm -rf "$TUNNEL_DIR"
  fi

  # Remove certificates
  if [[ -d "$CERT_DIR" ]]; then
    log "Removing certificates..."
    rm -rf "$CERT_DIR"
  fi

  # Remove client tarball from home
  [[ -f ~/slipstream-client.tar.gz ]] && rm -f ~/slipstream-client.tar.gz

  # Ask about systemd-resolved
  if ! systemctl is-active systemd-resolved &>/dev/null; then
    read -p "Re-enable systemd-resolved? (y/n): " restore_resolved
    if [[ "$restore_resolved" == "y" ]]; then
      log "Re-enabling systemd-resolved..."
      systemctl enable systemd-resolved
      systemctl start systemd-resolved
      ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi
  fi

  log "Cleanup complete"
}

# ============================================
# MAIN
# ============================================
[[ $# -eq 0 ]] && usage

case "$1" in
server)
  shift
  cmd_server "$@"
  ;;
client)
  shift
  cmd_client "$@"
  ;;
health) cmd_health ;;
status) cmd_status ;;
remove) cmd_remove ;;
-h | --help | help) usage ;;
*) error "Unknown command: $1" ;;
esac
