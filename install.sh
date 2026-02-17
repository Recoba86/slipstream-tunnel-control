#!/usr/bin/env bash
# DNS Tunnel Setup - Automated slipstream tunnel configuration
set -euo pipefail

# =============================================================================
# Release source configuration (pinned versions)
# =============================================================================
SLIPSTREAM_REPO="nightowlnerd/slipstream-rust"
SLIPSTREAM_VERSION="${SLIPSTREAM_VERSION:-v0.1.1}"
DNSCAN_REPO="nightowlnerd/dnscan"
DNSCAN_VERSION="${DNSCAN_VERSION:-v1.4.0}"
SCRIPT_REPO="${SCRIPT_REPO:-Recoba86/slipstream-tunnel-control}"
SCRIPT_BRANCH="${SCRIPT_BRANCH:-main}"
# =============================================================================

TUNNEL_DIR="$HOME/.tunnel"
DNSCAN_DIR="$TUNNEL_DIR/dnscan"
SERVERS_FILE="$TUNNEL_DIR/servers.txt"
CONFIG_FILE="$TUNNEL_DIR/config"
HEALTH_LOG="$TUNNEL_DIR/health.log"
RESOLV_BACKUP="$TUNNEL_DIR/resolv.conf.backup"
CERT_DIR="/opt/slipstream/cert"
SERVICE_USER="slipstream"

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
Usage: slipstream-tunnel <command> [options]

Commands:
  server              Setup slipstream server
  client              Setup slipstream client
  health              Check DNS server and switch if slow
  rescan              Run manual DNS rescan and switch to best server
  dashboard           Show client tunnel dashboard
  servers             Show verified DNS IPs with live latency checks
  menu                Open interactive client monitor menu
  m                   Short alias for menu
  status              Show current status
  logs                View tunnel logs (-f to follow)
  remove              Remove all tunnel components

Options:
  --domain <domain>   Tunnel domain (e.g., t.example.com)
  --port <port>       Server: target port (default: 2053)
                      Client: listen port (default: 7000)
  --slipstream <path> Path to slipstream binary (offline)
  --dnscan <path>     Path to dnscan tarball (client offline install)
  --dns-file <path>   Custom DNS server list (skips subnet scan)
  --manage-resolver   Server: allow script to manage systemd-resolved/resolv.conf

Examples:
  slipstream-tunnel server --domain t.example.com
  slipstream-tunnel server --domain t.example.com --manage-resolver
  slipstream-tunnel client --domain t.example.com
  slipstream-tunnel client --dns-file /tmp/dns-servers.txt
  slipstream-tunnel rescan
  slipstream-tunnel servers
  slipstream-tunnel menu
  sst
EOF
  exit 0
}

detect_arch() {
  local arch
  arch=$(uname -m)
  case "$arch" in
  x86_64) echo "x86_64" ;;
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

check_dependencies() {
  local missing=()
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    error "Missing required commands: ${missing[*]}"
  fi
}

require_flag_value() {
  local flag="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || error "Missing value for $flag"
}

is_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o1 o2 o3 o4 octet
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$octet" =~ ^[0-9]+$ ]] || return 1
    ((octet >= 0 && octet <= 255)) || return 1
  done
  return 0
}

validate_ipv4_or_error() {
  is_valid_ipv4 "$1" || error "Invalid IPv4 address: $1"
}

validate_domain_or_error() {
  local domain="$1"
  local re='^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$'
  [[ "$domain" =~ $re ]] || error "Invalid domain: $domain"
}

validate_port_or_error() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || error "Port must be numeric: $port"
  ((port >= 1 && port <= 65535)) || error "Port out of range (1-65535): $port"
}

validate_dns_file_or_error() {
  local file="$1"
  [[ -f "$file" ]] || error "DNS file not found: $file"
  local server
  while IFS= read -r server; do
    [[ -z "$server" ]] && continue
    validate_ipv4_or_error "$server"
  done <"$file"
}

sha256_of_file() {
  local file="$1"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum &>/dev/null; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    error "No SHA256 tool found (need sha256sum or shasum)"
  fi
}

github_asset_digest() {
  local repo="$1" tag="$2" asset="$3"
  local api_url="https://api.github.com/repos/${repo}/releases/tags/${tag}"
  local release_json digest

  release_json=$(curl -fsSL --connect-timeout 15 "$api_url") || return 1
  digest=$(printf '%s\n' "$release_json" | awk -v asset="$asset" '
    $0 ~ "\"name\": \"" asset "\"" {found=1; next}
    found && /"digest": "sha256:/ {
      line=$0
      sub(/.*"digest": "sha256:/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  ')
  [[ -n "$digest" ]] || return 1
  echo "$digest"
}

download_release_asset_verified() {
  local repo="$1" tag="$2" asset="$3" output="$4"
  local url="https://github.com/${repo}/releases/download/${tag}/${asset}"
  local expected_sha actual_sha

  expected_sha=$(github_asset_digest "$repo" "$tag" "$asset") || return 1
  curl -fsSL --connect-timeout 20 "$url" -o "$output" || return 1

  actual_sha=$(sha256_of_file "$output")
  [[ "$actual_sha" == "$expected_sha" ]] || return 1
}

ensure_service_user() {
  if id -u "$SERVICE_USER" &>/dev/null; then
    return
  fi

  local nologin="/usr/sbin/nologin"
  [[ -x "$nologin" ]] || nologin="/sbin/nologin"
  if command -v useradd &>/dev/null; then
    useradd --system --home /nonexistent --shell "$nologin" "$SERVICE_USER" \
      || error "Failed to create service user: $SERVICE_USER"
  elif command -v adduser &>/dev/null; then
    adduser --system --no-create-home --shell "$nologin" "$SERVICE_USER" \
      || error "Failed to create service user: $SERVICE_USER"
  else
    error "No user creation command found (need useradd or adduser)"
  fi
}

port_53_in_use() {
  if command -v ss &>/dev/null; then
    ss -H -lntu | awk '$5 ~ /:53$/ {found=1} END {exit !found}'
  elif command -v netstat &>/dev/null; then
    netstat -lntu 2>/dev/null | awk '$4 ~ /:53$/ {found=1} END {exit !found}'
  else
    return 1
  fi
}

backup_resolver_if_needed() {
  mkdir -p "$TUNNEL_DIR"
  if [[ -f /etc/resolv.conf && ! -f "$RESOLV_BACKUP" ]]; then
    cp /etc/resolv.conf "$RESOLV_BACKUP"
    log "Backed up /etc/resolv.conf to $RESOLV_BACKUP"
  fi
}

restore_resolver_if_backed_up() {
  if [[ -f "$RESOLV_BACKUP" ]]; then
    cp "$RESOLV_BACKUP" /etc/resolv.conf
    log "Restored /etc/resolv.conf from backup"
  fi
}

set_config_value() {
  local key="$1" value="$2" file="$3"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >>"$file"
  fi
}

load_config_or_error() {
  [[ -f "$CONFIG_FILE" ]] || error "No tunnel configured"
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

install_self() {
  local install_path="/usr/local/bin/slipstream-tunnel"
  local shortcut_path="/usr/local/bin/sst"
  local current_script=""

  if [[ -f "$0" ]]; then
    current_script=$(realpath "$0")
    # Skip only if running FROM install location
    [[ "$current_script" == "$install_path" ]] && return
  fi

  log "Installing slipstream-tunnel command..."

  if [[ -n "$current_script" ]]; then
    cp "$current_script" "$install_path"
  else
    # Pipe/process substitution - download instead
    curl -fsSL "https://raw.githubusercontent.com/${SCRIPT_REPO}/${SCRIPT_BRANCH}/install.sh" -o "$install_path"
  fi

  chmod +x "$install_path"
  log "Installed: slipstream-tunnel"

  cat >"$shortcut_path" <<'EOF'
#!/usr/bin/env bash
exec /usr/local/bin/slipstream-tunnel menu "$@"
EOF
  chmod +x "$shortcut_path"
  log "Installed shortcut: sst"
}

# ============================================
# SERVER MODE
# ============================================
cmd_server() {
  need_root
  check_dependencies curl tar systemctl openssl awk sed grep head tr
  local domain="" port="2053" slipstream_path="" manage_resolver=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
    --domain)
      require_flag_value "$1" "${2:-}"
      domain="$2"
      shift 2
      ;;
    --port)
      require_flag_value "$1" "${2:-}"
      port="$2"
      shift 2
      ;;
    --slipstream)
      require_flag_value "$1" "${2:-}"
      slipstream_path="$2"
      shift 2
      ;;
    --manage-resolver)
      manage_resolver=true
      shift
      ;;
    -h | --help)
      usage
      ;;
    *)
      error "Unknown option for server: $1"
      ;;
    esac
  done

  validate_port_or_error "$port"
  [[ -n "$domain" ]] && validate_domain_or_error "$domain"

  log "=== Slipstream Server Setup ==="

  # Get server IP with failover and validation
  log "Detecting server IP..."
  local server_ip=""
  local ip_services=(
    "https://api.ipify.org"
    "https://ifconfig.me"
    "https://icanhazip.com"
    "https://ipecho.net/plain"
  )

  for service in "${ip_services[@]}"; do
    local fetched_ip
    fetched_ip=$(curl -s --max-time 5 "$service" | tr -d '[:space:]')
    if [[ "$fetched_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      server_ip="$fetched_ip"
      break
    fi
  done

  if [[ -z "$server_ip" ]]; then
    warn "Could not auto-detect IP (services blocked or unreachable)"
    read -p "Enter server IP: " server_ip
    validate_ipv4_or_error "$server_ip"
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
    validate_domain_or_error "$domain"
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

  if port_53_in_use; then
    if [[ "$manage_resolver" == true && $(systemctl is-active systemd-resolved 2>/dev/null || true) == "active" ]]; then
      backup_resolver_if_needed
      log "Stopping systemd-resolved to free port 53..."
      systemctl stop systemd-resolved
      systemctl disable systemd-resolved
    else
      error "Port 53 is busy. Free it manually, or re-run with --manage-resolver to auto-manage resolver settings."
    fi
  fi

  # Resolver changes are opt-in to avoid breaking host DNS unexpectedly.
  if [[ "$manage_resolver" == true ]]; then
    backup_resolver_if_needed
    if [[ -L /etc/resolv.conf ]] || [[ ! -f /etc/resolv.conf ]]; then
      log "Writing static resolver configuration..."
      rm -f /etc/resolv.conf
      echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" >/etc/resolv.conf
    fi
  fi

  # Generate self-signed cert
  ensure_service_user
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
  chown -R "$SERVICE_USER:$SERVICE_USER" "$CERT_DIR"
  chmod 700 "$CERT_DIR"
  chmod 600 "$CERT_DIR/key.pem"
  chmod 644 "$CERT_DIR/cert.pem"

  local arch bin_path="/usr/local/bin/slipstream-server"
  arch=$(detect_arch)

  # Stop existing service
  systemctl stop slipstream-server 2>/dev/null || true

  if [[ -n "$slipstream_path" ]]; then
    log "Installing slipstream-server from $slipstream_path..."
    cp "$slipstream_path" "$bin_path"
    warn "Local slipstream binary was not checksum-verified"
  else
    log "Downloading slipstream-server..."
    local slipstream_asset="slipstream-linux-${arch}.tar.gz"
    local tmp_tar tmp_dir
    tmp_tar=$(mktemp /tmp/slipstream.XXXXXX.tar.gz)
    tmp_dir=$(mktemp -d /tmp/slipstream.XXXXXX)
    if download_release_asset_verified "$SLIPSTREAM_REPO" "$SLIPSTREAM_VERSION" "$slipstream_asset" "$tmp_tar"; then
      tar xzf "$tmp_tar" -C "$tmp_dir" slipstream-server
      install -m 0755 "$tmp_dir/slipstream-server" "$bin_path"
    else
      warn "Automatic download failed for ${slipstream_asset}"
      echo "Provide local slipstream-server binary path (or Ctrl+C to abort):"
      read -e -r -p "Path: " slipstream_path
      [[ -n "$slipstream_path" ]] || error "No local binary path provided"
      cp "$slipstream_path" "$bin_path"
      chmod +x "$bin_path"
      warn "Local slipstream binary was not checksum-verified"
      rm -f "$tmp_tar"
      rm -rf "$tmp_dir"
      tmp_tar=""
      tmp_dir=""
    fi
    [[ -n "${tmp_tar:-}" ]] && rm -f "$tmp_tar"
    [[ -n "${tmp_dir:-}" ]] && rm -rf "$tmp_dir"
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
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$bin_path \\
  --dns-listen-port 53 \\
  --target-address 127.0.0.1:$port \\
  --domain $domain \\
  --cert $CERT_DIR/cert.pem \\
  --key $CERT_DIR/key.pem
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CERT_DIR
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable slipstream-server
  systemctl start slipstream-server
  log "Started slipstream-server service"

  # Save config
  mkdir -p "$TUNNEL_DIR"
  cat >"$CONFIG_FILE" <<EOF
DOMAIN=$domain
MODE=server
PORT=$port
MANAGE_RESOLVER=$manage_resolver
EOF

  # Install global command
  install_self

  echo ""
  echo -e "${GREEN}=== Server Ready ===${NC}"
  echo ""
  echo "Next steps:"
  echo "  1. In 3x-ui panel: create inbound on port $port"
  echo "  2. On client run the same install command"
  echo ""
  echo "Commands:"
  echo "  slipstream-tunnel status"
  echo "  journalctl -u slipstream-server -f"
}

write_client_service() {
  local resolver="$1" domain="$2" port="$3"
  local bin_path="/usr/local/bin/slipstream-client"

  cat >/etc/systemd/system/slipstream-client.service <<EOF
[Unit]
Description=Slipstream DNS Tunnel Client
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$bin_path \\
  --resolver ${resolver}:53 \\
  --domain $domain \\
  --tcp-listen-port $port
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ProtectHome=true
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

find_best_server() {
  local domain="$1" file="$2"
  local best_server="" best_latency=9999
  local server lat

  while IFS= read -r server; do
    [[ -z "$server" ]] && continue
    is_valid_ipv4 "$server" || continue
    lat=$(test_dns_latency "$server" "$domain" || echo "9999")
    if ((lat < best_latency)); then
      best_latency="$lat"
      best_server="$server"
    fi
  done <"$file"

  [[ -n "$best_server" ]] || return 1
  echo "$best_server $best_latency"
}

# ============================================
# CLIENT MODE
# ============================================
cmd_client() {
  need_root
  check_dependencies curl tar systemctl awk sed grep head wc dig
  local domain="" dnscan_path="" slipstream_path="" port="7000" dns_file=""
  local port_from_flag=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
    --domain)
      require_flag_value "$1" "${2:-}"
      domain="$2"
      shift 2
      ;;
    --dnscan)
      require_flag_value "$1" "${2:-}"
      dnscan_path="$2"
      shift 2
      ;;
    --slipstream)
      require_flag_value "$1" "${2:-}"
      slipstream_path="$2"
      shift 2
      ;;
    --port)
      require_flag_value "$1" "${2:-}"
      port="$2"
      port_from_flag=true
      shift 2
      ;;
    --dns-file)
      require_flag_value "$1" "${2:-}"
      dns_file="$2"
      shift 2
      ;;
    -h | --help)
      usage
      ;;
    *)
      error "Unknown option for client: $1"
      ;;
    esac
  done

  [[ -n "$domain" ]] && validate_domain_or_error "$domain"
  [[ -n "$dns_file" ]] && validate_dns_file_or_error "$dns_file"

  log "=== Slipstream Client Setup ==="

  ensure_service_user
  mkdir -p "$TUNNEL_DIR" "$DNSCAN_DIR"

  # Get dnscan
  local arch os dnscan_arch
  arch=$(detect_arch)
  os=$(detect_os)
  case "$arch" in
  x86_64) dnscan_arch="amd64" ;;
  arm64) dnscan_arch="arm64" ;;
  *) error "Unsupported dnscan architecture mapping: $arch" ;;
  esac

  if [[ ! -x "$DNSCAN_DIR/dnscan" ]]; then
    if [[ -n "$dnscan_path" ]]; then
      log "Extracting dnscan from $dnscan_path..."
      tar xzf "$dnscan_path" -C "$DNSCAN_DIR"
    else
      log "Downloading dnscan..."
      local dnscan_asset="dnscan-${os}-${dnscan_arch}.tar.gz"
      local tmp_dnscan
      tmp_dnscan=$(mktemp /tmp/dnscan.XXXXXX.tar.gz)
      if download_release_asset_verified "$DNSCAN_REPO" "$DNSCAN_VERSION" "$dnscan_asset" "$tmp_dnscan"; then
        tar xzf "$tmp_dnscan" -C "$DNSCAN_DIR"
        rm -f "$tmp_dnscan"
      else
        rm -f "$tmp_dnscan"
        echo ""
        warn "Cannot download dnscan (network blocked?)"
        echo ""
        echo "Transfer this file from a non-blocked network:"
        echo "  https://github.com/${DNSCAN_REPO}/releases/download/${DNSCAN_VERSION}/${dnscan_asset}"
        echo ""
        read -e -p "Path to dnscan tarball: " dnscan_path
        tar xzf "$dnscan_path" -C "$DNSCAN_DIR"
      fi
    fi
    chmod +x "$DNSCAN_DIR/dnscan"
  fi

  # Get domain
  if [[ -z "$domain" ]]; then
    read -p "Enter tunnel domain (e.g., t.example.com): " domain
    validate_domain_or_error "$domain"
  fi

  if [[ "$port_from_flag" == false ]]; then
    read -r -p "Client tunnel listen port [7000]: " input_port
    [[ -n "$input_port" ]] && port="$input_port"
  fi
  validate_port_or_error "$port"

  # Get slipstream binary (required for --verify)
  local slipstream_bin="$TUNNEL_DIR/slipstream-client"
  local installed_bin="/usr/local/bin/slipstream-client"
  local slipstream_asset="slipstream-linux-${arch}.tar.gz"

  if [[ -x "$slipstream_bin" ]]; then
    # Use cached binary
    log "Using cached slipstream-client"
  elif [[ -x "$installed_bin" ]]; then
    # Already installed, use existing
    slipstream_bin="$installed_bin"
  elif [[ -n "$slipstream_path" ]]; then
    log "Copying slipstream-client from $slipstream_path..."
    if ! cp "$slipstream_path" "$slipstream_bin" 2>/dev/null; then
      error "Cannot copy from $slipstream_path"
    fi
    chmod +x "$slipstream_bin"
    warn "Local slipstream binary was not checksum-verified"
  else
    log "Downloading slipstream-client..."
    local tmp_slipstream tmp_extract_dir
    tmp_slipstream=$(mktemp /tmp/slipstream.XXXXXX.tar.gz)
    tmp_extract_dir=$(mktemp -d /tmp/slipstream.XXXXXX)
    if download_release_asset_verified "$SLIPSTREAM_REPO" "$SLIPSTREAM_VERSION" "$slipstream_asset" "$tmp_slipstream"; then
      tar xzf "$tmp_slipstream" -C "$tmp_extract_dir" slipstream-client
      mv "$tmp_extract_dir/slipstream-client" "$slipstream_bin"
      rm -f "$tmp_slipstream"
      rm -rf "$tmp_extract_dir"
    else
      rm -f "$tmp_slipstream"
      rm -rf "$tmp_extract_dir"
      echo ""
      warn "Cannot download slipstream-client (network blocked?)"
      echo ""
      echo "Transfer tarball from a non-blocked network:"
      echo "  https://github.com/${SLIPSTREAM_REPO}/releases/download/${SLIPSTREAM_VERSION}/${slipstream_asset}"
      echo ""
      read -e -p "Path to slipstream-client binary: " slipstream_path
      if [[ -z "$slipstream_path" ]]; then
        error "Binary required for verification. Cannot continue."
      fi
      if ! cp "$slipstream_path" "$slipstream_bin" 2>/dev/null; then
        error "Cannot copy from $slipstream_path"
      fi
    fi
    chmod +x "$slipstream_bin"
  fi

  # Run dnscan
  log "Scanning for working DNS servers..."
  local dnscan_args=(
    --domain "$domain"
    --data-dir "$DNSCAN_DIR/data"
    --output "$SERVERS_FILE"
    --verify "$slipstream_bin"
  )
  local scan_source="generated"
  local scan_file=""
  local scan_country="ir"
  local scan_mode="fast"
  local scan_workers="500"
  local scan_timeout="2s"
  local scan_threshold="50"

  # Scan settings
  echo ""
  echo -e "${YELLOW}=== DNS Scan Settings ===${NC}"
  echo ""

  if [[ -n "$dns_file" ]]; then
    # Custom DNS file from CLI flag
    log "Using custom DNS file: $dns_file"
    scan_source="file"
    scan_file="$dns_file"
    dnscan_args+=(--file "$dns_file")
    read -p "Workers [500]: " input_workers
    [[ -n "$input_workers" ]] && scan_workers="$input_workers"
    read -p "Timeout [2s]: " input_timeout
    [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"
    read -p "Benchmark threshold % [50]: " input_threshold
    [[ -n "$input_threshold" ]] && scan_threshold="$input_threshold"
    dnscan_args+=(--workers "$scan_workers" --timeout "$scan_timeout" --threshold "$scan_threshold")
  else
    # Ask for custom file first
    read -e -p "Custom DNS file (Enter to scan): " input_dns_file
    if [[ -n "$input_dns_file" ]]; then
      validate_dns_file_or_error "$input_dns_file"
      log "Using custom DNS file: $input_dns_file"
      scan_source="file"
      scan_file="$input_dns_file"
      dnscan_args+=(--file "$input_dns_file")
      read -p "Workers [500]: " input_workers
      [[ -n "$input_workers" ]] && scan_workers="$input_workers"
      read -p "Timeout [2s]: " input_timeout
      [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"
      read -p "Benchmark threshold % [50]: " input_threshold
      [[ -n "$input_threshold" ]] && scan_threshold="$input_threshold"
      dnscan_args+=(--workers "$scan_workers" --timeout "$scan_timeout" --threshold "$scan_threshold")
    else
      # Show scan options
      echo ""
      echo "Modes:"
      echo "  list   - Known working DNS servers (fastest)"
      echo "  fast   - Sample common IPs per subnet (default)"
      echo "  medium - More IPs per subnet"
      echo "  all    - All IPs per subnet (slowest)"
      echo ""
      read -p "Country code [ir]: " input_country
      [[ -n "$input_country" ]] && scan_country="$input_country"
      read -p "Scan mode [fast]: " input_mode
      [[ -n "$input_mode" ]] && scan_mode="$input_mode"
      read -p "Workers [500]: " input_workers
      [[ -n "$input_workers" ]] && scan_workers="$input_workers"
      read -p "Timeout [2s]: " input_timeout
      [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"
      read -p "Benchmark threshold % [50]: " input_threshold
      [[ -n "$input_threshold" ]] && scan_threshold="$input_threshold"

      dnscan_args+=(
        --country "$scan_country"
        --mode "$scan_mode"
        --workers "$scan_workers"
        --threshold "$scan_threshold"
        --timeout "$scan_timeout"
      )
    fi
  fi

  "$DNSCAN_DIR/dnscan" "${dnscan_args[@]}"

  # Check results (dnscan only outputs verified servers)
  if [[ ! -s "$SERVERS_FILE" ]]; then
    error "No DNS servers passed verification. Is your server running correctly?"
  fi

  local server_count
  server_count=$(wc -l <"$SERVERS_FILE")
  log "Found $server_count verified DNS servers"

  # Pick best server by latency
  local best_server best_latency
  read -r best_server best_latency <<<"$(find_best_server "$domain" "$SERVERS_FILE")"
  [[ -n "$best_server" ]] || error "Could not choose a working DNS server from scan results"
  log "Using DNS server: $best_server (${best_latency}ms)"

  local bin_path="/usr/local/bin/slipstream-client"

  # Stop existing service
  systemctl stop slipstream-client 2>/dev/null || true

  # Install binary if not already in place
  if [[ "$slipstream_bin" != "$bin_path" ]]; then
    log "Installing slipstream-client..."
    mv "$slipstream_bin" "$bin_path"
    chmod +x "$bin_path"
  fi

  # Create systemd service
  log "Creating systemd service..."
  write_client_service "$best_server" "$domain" "$port"

  systemctl daemon-reload
  systemctl enable slipstream-client
  systemctl restart slipstream-client
  log "Started slipstream-client service"

  # Save config
  cat >"$CONFIG_FILE" <<EOF
DOMAIN=$domain
MODE=client
CURRENT_SERVER=$best_server
PORT=$port
SCAN_SOURCE=$scan_source
SCAN_DNS_FILE=$scan_file
SCAN_COUNTRY=$scan_country
SCAN_MODE=$scan_mode
SCAN_WORKERS=$scan_workers
SCAN_TIMEOUT=$scan_timeout
SCAN_THRESHOLD=$scan_threshold
EOF

  # Setup health check timer
  setup_health_timer

  # Install global command
  install_self

  echo ""
  echo -e "${GREEN}=== Client Ready ===${NC}"
  echo ""
  echo "Tunnel: 127.0.0.1:$port"
  echo "DNS server: $best_server"
  echo ""
  echo "Commands:"
  echo "  slipstream-tunnel status"
  echo "  slipstream-tunnel health"
  echo "  slipstream-tunnel rescan"
  echo "  slipstream-tunnel dashboard"
  echo "  slipstream-tunnel servers"
  echo "  slipstream-tunnel menu"
  echo "  sst"
  echo "  journalctl -u slipstream-client -f"
  echo ""
  echo "Verified servers saved to: $SERVERS_FILE"
  echo ""
  if [[ -t 0 ]]; then
    log "Opening client monitor menu..."
    cmd_menu
  else
    warn "Non-interactive session detected; skipping menu auto-open"
  fi
}

# ============================================
# HEALTH CHECK
# ============================================
cmd_health() {
  need_root
  check_dependencies dig systemctl wc tail date
  if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "No tunnel configured"
    exit 0
  fi
  if [[ ! -f "$SERVERS_FILE" ]]; then
    echo "No servers file found"
    exit 0
  fi
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Health check applies only to client mode"

  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')

  # Test current server latency
  echo "Testing DNS server: $CURRENT_SERVER"
  local latency
  latency=$(test_dns_latency "$CURRENT_SERVER" "$DOMAIN" || echo "9999")
  echo "Latency: ${latency}ms"

  if [[ "$latency" -gt 1000 ]]; then
    echo "Server slow, checking alternatives..."
    echo "[$timestamp] Current server $CURRENT_SERVER slow (${latency}ms), checking alternatives..." >>"$HEALTH_LOG"

    # Find better server
    local best_server best_latency
    read -r best_server best_latency <<<"$(find_best_server "$DOMAIN" "$SERVERS_FILE")"

    if [[ -n "$best_server" && "$best_server" != "$CURRENT_SERVER" && "$best_latency" -lt 1000 ]]; then
      echo "Switching to $best_server (${best_latency}ms)"
      echo "[$timestamp] Switching to $best_server (${best_latency}ms)" >>"$HEALTH_LOG"

      # Update config
      set_config_value "CURRENT_SERVER" "$best_server" "$CONFIG_FILE"

      # Restart client with new server
      write_client_service "$best_server" "$DOMAIN" "${PORT:-7000}"
      systemctl daemon-reload
      if systemctl restart slipstream-client; then
        echo "[$timestamp] Switched to $best_server" >>"$HEALTH_LOG"
      else
        echo "[$timestamp] ERROR: service restart failed" >>"$HEALTH_LOG"
      fi
    else
      echo "No better server found"
      echo "[$timestamp] No better server found" >>"$HEALTH_LOG"
    fi
  else
    echo "Server OK"
    echo "[$timestamp] Server $CURRENT_SERVER OK (${latency}ms)" >>"$HEALTH_LOG"
  fi

  # Rotate log (keep last 1000 lines)
  if [[ $(wc -l <"$HEALTH_LOG") -gt 1000 ]]; then
    local tmp_health
    tmp_health=$(mktemp /tmp/health.XXXXXX.log)
    tail -500 "$HEALTH_LOG" >"$tmp_health" && mv "$tmp_health" "$HEALTH_LOG"
  fi
}

cmd_rescan() {
  need_root
  check_dependencies dig systemctl wc head
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Manual rescan applies only to client mode"
  [[ -x "$DNSCAN_DIR/dnscan" ]] || error "dnscan binary not found: $DNSCAN_DIR/dnscan"
  [[ -x /usr/local/bin/slipstream-client ]] || error "slipstream-client not installed"

  local dnscan_args=(
    --domain "$DOMAIN"
    --data-dir "$DNSCAN_DIR/data"
    --output "$SERVERS_FILE"
    --verify "/usr/local/bin/slipstream-client"
  )

  local scan_source="${SCAN_SOURCE:-generated}"
  local scan_workers="${SCAN_WORKERS:-500}"
  local scan_timeout="${SCAN_TIMEOUT:-2s}"
  local scan_threshold="${SCAN_THRESHOLD:-50}"

  if [[ "$scan_source" == "file" ]]; then
    local scan_file="${SCAN_DNS_FILE:-}"
    [[ -n "$scan_file" ]] || error "SCAN_DNS_FILE missing in config"
    validate_dns_file_or_error "$scan_file"
    dnscan_args+=(--file "$scan_file")
  else
    dnscan_args+=(
      --country "${SCAN_COUNTRY:-ir}"
      --mode "${SCAN_MODE:-fast}"
    )
  fi
  dnscan_args+=(--workers "$scan_workers" --timeout "$scan_timeout" --threshold "$scan_threshold")

  log "Running manual DNS rescan..."
  "$DNSCAN_DIR/dnscan" "${dnscan_args[@]}"
  [[ -s "$SERVERS_FILE" ]] || error "Manual rescan found no verified DNS servers"

  local best_server best_latency
  read -r best_server best_latency <<<"$(find_best_server "$DOMAIN" "$SERVERS_FILE")"
  [[ -n "$best_server" ]] || error "No usable DNS server found after manual rescan"

  set_config_value "CURRENT_SERVER" "$best_server" "$CONFIG_FILE"
  write_client_service "$best_server" "$DOMAIN" "${PORT:-7000}"
  systemctl daemon-reload
  systemctl restart slipstream-client

  log "Switched to best DNS server: $best_server (${best_latency}ms)"
  cmd_servers
  cmd_dashboard
}

cmd_dashboard() {
  check_dependencies systemctl date
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Dashboard is available only in client mode"

  local service_status timer_status current_latency now
  service_status=$(systemctl is-active slipstream-client 2>/dev/null || echo "not running")
  timer_status=$(systemctl is-active tunnel-health.timer 2>/dev/null || echo "not installed")
  now=$(date '+%Y-%m-%d %H:%M:%S')

  echo "=== Client Dashboard ==="
  echo "Time: $now"
  echo "Service: $service_status"
  echo "Health timer: $timer_status"
  echo "Domain: ${DOMAIN:-unknown}"
  echo "Port: ${PORT:-7000}"
  echo "Current DNS: ${CURRENT_SERVER:-unknown}"

  if [[ -n "${CURRENT_SERVER:-}" ]] && command -v dig &>/dev/null; then
    current_latency=$(test_dns_latency "$CURRENT_SERVER" "$DOMAIN" || echo "9999")
    echo "Current latency: ${current_latency}ms"
  else
    echo "Current latency: unavailable (dig missing or server unknown)"
  fi

  if [[ -s "$SERVERS_FILE" && -n "${DOMAIN:-}" ]]; then
    echo ""
    echo "Top DNS candidates (live check):"
    local shown=0 server lat
    while IFS= read -r server; do
      [[ -z "$server" ]] && continue
      is_valid_ipv4 "$server" || continue
      lat=$(test_dns_latency "$server" "$DOMAIN" || echo "9999")
      printf "  %-15s %sms\n" "$server" "$lat"
      shown=$((shown + 1))
      [[ "$shown" -ge 5 ]] && break
    done <"$SERVERS_FILE"
  fi

  if [[ -f "$HEALTH_LOG" ]]; then
    echo ""
    echo "Recent health events:"
    tail -5 "$HEALTH_LOG" | sed 's/^/  /'
  fi
}

ping_rtt_ms() {
  local server="$1"
  command -v ping &>/dev/null || {
    echo "n/a"
    return
  }

  local out rtt
  if out=$(ping -n -c 1 -W 1 "$server" 2>/dev/null); then
    rtt=$(echo "$out" | awk -F'time=' '/time=/{print $2}' | awk '{print $1}' | head -1)
    [[ -n "$rtt" ]] && {
      echo "$rtt"
      return
    }
  fi
  echo "timeout"
}

cmd_servers() {
  check_dependencies dig
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Server list is available only in client mode"
  [[ -s "$SERVERS_FILE" ]] || error "No verified DNS server list found"

  echo "=== Verified DNS Servers (Live Check) ==="
  printf "%-16s %-12s %-12s %s\n" "IP" "Ping(ms)" "DNS(ms)" "Status"

  local server ping_ms dns_ms status
  while IFS= read -r server; do
    [[ -z "$server" ]] && continue
    is_valid_ipv4 "$server" || continue
    ping_ms=$(ping_rtt_ms "$server")
    dns_ms=$(test_dns_latency "$server" "$DOMAIN" || echo "9999")
    if [[ "$dns_ms" -lt 1000 ]]; then
      status="OK"
    else
      status="SLOW/FAIL"
    fi
    printf "%-16s %-12s %-12s %s\n" "$server" "$ping_ms" "$dns_ms" "$status"
  done <"$SERVERS_FILE"
}

cmd_select_server() {
  need_root
  check_dependencies systemctl dig
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Manual selection is available only in client mode"
  [[ -s "$SERVERS_FILE" ]] || error "No verified DNS server list found"

  local servers=()
  local server
  while IFS= read -r server; do
    [[ -z "$server" ]] && continue
    is_valid_ipv4 "$server" || continue
    servers+=("$server")
  done <"$SERVERS_FILE"

  [[ ${#servers[@]} -gt 0 ]] || error "No valid DNS IP entries found in $SERVERS_FILE"

  echo "=== Manual DNS Selection ==="
  local i=1 ping_ms dns_ms status
  for server in "${servers[@]}"; do
    ping_ms=$(ping_rtt_ms "$server")
    dns_ms=$(test_dns_latency "$server" "$DOMAIN" || echo "9999")
    if [[ "$dns_ms" -lt 1000 ]]; then
      status="OK"
    else
      status="SLOW/FAIL"
    fi
    printf "%2d) %-15s ping=%-10s dns=%-8s %s\n" "$i" "$server" "$ping_ms" "$dns_ms" "$status"
    i=$((i + 1))
  done

  echo " 0) Cancel"
  read -r -p "Choose DNS index: " choice
  [[ -n "$choice" ]] || {
    warn "No selection made"
    return 0
  }
  [[ "$choice" =~ ^[0-9]+$ ]] || error "Invalid selection: $choice"
  [[ "$choice" == "0" ]] && {
    echo "Canceled"
    return 0
  }
  ((choice >= 1 && choice <= ${#servers[@]})) || error "Selection out of range: $choice"

  local selected="${servers[$((choice - 1))]}"
  set_config_value "CURRENT_SERVER" "$selected" "$CONFIG_FILE"
  write_client_service "$selected" "$DOMAIN" "${PORT:-7000}"
  systemctl daemon-reload
  systemctl restart slipstream-client
  log "Manually switched to DNS server: $selected"
  cmd_dashboard
}

cmd_menu() {
  need_root
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Menu is available only in client mode"

  while true; do
    echo ""
    cmd_dashboard
    echo ""
    echo "=== Manual Monitor Menu ==="
    echo "1) Run health check now"
    echo "2) Run full DNS rescan now"
    echo "3) Show status"
    echo "4) Follow client logs"
    echo "5) Show verified DNS IP list (live ping + DNS latency)"
    echo "6) Select DNS manually from verified list"
    echo "0) Exit menu"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_health ;;
    2) cmd_rescan ;;
    3) cmd_status ;;
    4) cmd_logs -f ;;
    5) cmd_servers ;;
    6) cmd_select_server ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
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
  local script_path="/usr/local/bin/slipstream-tunnel"

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
# LOGS
# ============================================
cmd_logs() {
  check_dependencies journalctl
  load_config_or_error

  local follow=false
  [[ "${1:-}" == "-f" ]] && follow=true

  local service_name="slipstream-${MODE:-client}"

  if $follow; then
    journalctl -u "$service_name" -f
  else
    journalctl -u "$service_name" -n 100 --no-pager
  fi
}

# ============================================
# STATUS
# ============================================
cmd_status() {
  check_dependencies systemctl
  echo "=== DNS Tunnel Status ==="
  echo ""

  if [[ -f "$CONFIG_FILE" ]]; then
    load_config_or_error
    echo "Mode: ${MODE:-unknown}"
    echo "Domain: $DOMAIN"
    echo "Port: ${PORT:-7000}"
    [[ -n "${CURRENT_SERVER:-}" ]] && echo "Current DNS: $CURRENT_SERVER"
  else
    echo "Not configured"
    return
  fi

  echo ""
  echo "Services:"
  if [[ "${MODE:-}" == "server" ]]; then
    local status
    status=$(systemctl is-active slipstream-server 2>/dev/null || echo "not running")
    echo "  slipstream-server: $status"
  else
    local status
    status=$(systemctl is-active slipstream-client 2>/dev/null || echo "not running")
    echo "  slipstream-client: $status"
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
  check_dependencies systemctl
  log "=== Removing DNS Tunnel ==="

  # Stop and remove systemd services
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

  if [[ -f /usr/local/bin/slipstream-tunnel ]]; then
    log "Removing slipstream-tunnel command..."
    rm -f /usr/local/bin/slipstream-tunnel
  fi

  if [[ -f /usr/local/bin/sst ]]; then
    log "Removing sst shortcut..."
    rm -f /usr/local/bin/sst
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

  # Remove certificates
  if [[ -d "$CERT_DIR" ]]; then
    log "Removing certificates..."
    rm -rf "$CERT_DIR"
  fi

  # Restore resolver settings if script changed them.
  if [[ -f "$RESOLV_BACKUP" ]]; then
    read -p "Restore resolver config from backup? (y/n): " restore_resolver
    if [[ "$restore_resolver" == "y" ]]; then
      restore_resolver_if_backed_up
    fi
  fi

  if ! systemctl is-active systemd-resolved &>/dev/null; then
    read -p "Re-enable systemd-resolved service? (y/n): " restore_resolved
    if [[ "$restore_resolved" == "y" ]]; then
      log "Re-enabling systemd-resolved..."
      systemctl enable systemd-resolved
      systemctl start systemd-resolved
    fi
  fi

  # Remove tunnel directory
  if [[ -d "$TUNNEL_DIR" ]]; then
    log "Removing $TUNNEL_DIR..."
    rm -rf "$TUNNEL_DIR"
  fi

  log "Cleanup complete"
}

# ============================================
# MAIN
# ============================================
main() {
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
  rescan) cmd_rescan ;;
  dashboard) cmd_dashboard ;;
  servers) cmd_servers ;;
  menu | m) cmd_menu ;;
  status) cmd_status ;;
  logs)
    shift
    cmd_logs "$@"
    ;;
  remove) cmd_remove ;;
  -h | --help | help) usage ;;
  *) error "Unknown command: $1" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
