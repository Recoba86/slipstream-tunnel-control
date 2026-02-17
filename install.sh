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
SLIPSTREAM_SERVER_BIN="${SLIPSTREAM_SERVER_BIN:-/usr/local/bin/slipstream-server}"
SLIPSTREAM_CLIENT_BIN="${SLIPSTREAM_CLIENT_BIN:-/usr/local/bin/slipstream-client}"
TUNNEL_CMD_BIN="${TUNNEL_CMD_BIN:-/usr/local/bin/slipstream-tunnel}"
SST_BIN="${SST_BIN:-/usr/local/bin/sst}"
# =============================================================================

TUNNEL_DIR="$HOME/.tunnel"
DNSCAN_DIR="$TUNNEL_DIR/dnscan"
SERVERS_FILE="$TUNNEL_DIR/servers.txt"
CONFIG_FILE="$TUNNEL_DIR/config"
HEALTH_LOG="$TUNNEL_DIR/health.log"
RESOLV_BACKUP="$TUNNEL_DIR/resolv.conf.backup"
CERT_DIR="/opt/slipstream/cert"
SERVICE_USER="slipstream"
SSH_AUTH_GROUP="slipstream-tunnel"
SSH_AUTH_CONFIG_DIR="/etc/ssh/sshd_config.d"
SSH_AUTH_CONFIG_FILE="$SSH_AUTH_CONFIG_DIR/99-slipstream-tunnel.conf"
SSH_CLIENT_SERVICE="slipstream-ssh-client"
SSH_CLIENT_ENV_DIR="/etc/slipstream-tunnel"
SSH_CLIENT_ENV_FILE="$SSH_CLIENT_ENV_DIR/ssh-client.env"

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
  edit                Edit saved settings (domain/port/...)
  start               Start tunnel service (server/client mode)
  stop                Stop tunnel service (server/client mode)
  restart             Restart tunnel service (server/client mode)
  health              Check DNS server and switch if slow
  rescan              Run manual DNS rescan and switch to best server
  dashboard           Show client tunnel dashboard
  servers             Show verified DNS IPs with live latency checks
  menu                Open interactive monitor menu (server/client)
  m                   Short alias for menu
  auth-setup          Enable/update SSH auth overlay for server mode
  auth-add            Create SSH tunnel user (username/password)
  auth-passwd         Change SSH tunnel user password
  auth-del            Delete SSH tunnel user
  auth-list           List SSH tunnel users
  status              Show current status
  logs                View tunnel logs (-f to follow)
  uninstall           Remove all tunnel components
  remove              Remove all tunnel components

Options:
  --domain <domain>   Tunnel domain (e.g., t.example.com)
  --port <port>       Server: target port (default: 2053)
                      Client: listen port (default: 7000)
  --slipstream <path> Path to slipstream binary (offline)
  --dnscan <path>     Path to dnscan tarball (client offline install)
  --dns-file <path>   Custom DNS server list (skips subnet scan)
  --manage-resolver   Server: allow script to manage systemd-resolved/resolv.conf
  --ssh-auth          Server: enable SSH username/password auth overlay
  --ssh-backend-port <port>
                      Server: SSH daemon port behind slipstream when --ssh-auth is enabled (default: 22)
  --ssh-auth-client   Client: use SSH username/password overlay
  --ssh-user <name>   Client: SSH username (with --ssh-auth-client)
  --ssh-pass <pass>   Client: SSH password (with --ssh-auth-client)

Examples:
  slipstream-tunnel server --domain t.example.com
  slipstream-tunnel server --domain t.example.com --manage-resolver
  slipstream-tunnel client --domain t.example.com
  slipstream-tunnel client --dns-file /tmp/dns-servers.txt
  slipstream-tunnel edit
  slipstream-tunnel stop
  slipstream-tunnel start
  slipstream-tunnel rescan
  slipstream-tunnel servers
  slipstream-tunnel menu
  slipstream-tunnel auth-add
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

validate_unix_username_or_error() {
  local username="$1"
  [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || error "Invalid username: $username"
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

port_53_owners() {
  if command -v ss &>/dev/null; then
    {
      ss -H -ltnup 2>/dev/null
      ss -H -lnuap 2>/dev/null
    } | awk '$5 ~ /:53$/ {print}' | sort -u
  elif command -v netstat &>/dev/null; then
    netstat -lntup 2>/dev/null | awk '$4 ~ /:53$/ {print}'
  else
    return 1
  fi
}

unit_exists() {
  local unit="$1"
  systemctl cat "$unit" >/dev/null 2>&1
}

stop_disable_unit_if_active() {
  local unit="$1" short_name="${2:-$1}"
  if ! unit_exists "$unit"; then
    return 1
  fi

  local state
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  if [[ "$state" == "active" || "$state" == "activating" || "$state" == "reloading" ]]; then
    log "Stopping $short_name to free port 53..."
    systemctl stop "$unit" || true
    systemctl disable "$unit" || true
    return 0
  fi
  return 1
}

auto_fix_port_53_conflict() {
  local attempted=false
  local fixed_any=false
  local owners

  port_53_in_use || return 0
  attempted=true
  warn "Port 53 is busy. Attempting automatic conflict resolution..."
  owners=$(port_53_owners || true)
  if [[ -n "$owners" ]]; then
    echo "Current listeners on :53:"
    echo "$owners" | sed 's/^/  /'
  fi

  if stop_disable_unit_if_active "systemd-resolved.service" "systemd-resolved"; then
    backup_resolver_if_needed
    manage_resolver=true
    fixed_any=true
  fi

  local dns_units=(
    "dnsmasq.service"
    "named.service"
    "bind9.service"
    "unbound.service"
    "pdns-recursor.service"
    "knot-resolver.service"
  )
  local unit
  for unit in "${dns_units[@]}"; do
    if stop_disable_unit_if_active "$unit" "${unit%.service}"; then
      fixed_any=true
    fi
  done

  if port_53_in_use; then
    owners=$(port_53_owners || true)
    warn "Port 53 is still busy after automatic attempts."
    if [[ -n "$owners" ]]; then
      echo "Still listening on :53:"
      echo "$owners" | sed 's/^/  /'
    fi
    return 1
  fi

  if [[ "$attempted" == true ]]; then
    if [[ "$fixed_any" == true ]]; then
      log "Port 53 conflict resolved automatically."
    else
      log "Port 53 became available."
    fi
  fi
  return 0
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
    sed_in_place "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >>"$file"
  fi
}

sed_in_place() {
  local expr="$1" file="$2"
  if sed --version >/dev/null 2>&1; then
    sed -i "$expr" "$file"
  else
    sed -i '' "$expr" "$file"
  fi
}

load_config_or_error() {
  [[ -f "$CONFIG_FILE" ]] || error "No tunnel configured"
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
}

ensure_mode_server_or_error() {
  load_config_or_error
  [[ "${MODE:-}" == "server" ]] || error "This command is available only in server mode"
}

is_true() {
  [[ "${1:-}" == "true" ]]
}

client_ssh_auth_enabled() {
  [[ "${MODE:-}" == "client" ]] && is_true "${SSH_AUTH_ENABLED:-false}"
}

install_self() {
  local install_path="$TUNNEL_CMD_BIN"
  local shortcut_path="$SST_BIN"
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

  cat >"$shortcut_path" <<EOF
#!/usr/bin/env bash
exec "$install_path" menu "\$@"
EOF
  chmod +x "$shortcut_path"
  log "Installed shortcut: sst"
}

tunnel_nologin_shell() {
  local shell_path="/usr/sbin/nologin"
  [[ -x "$shell_path" ]] || shell_path="/sbin/nologin"
  [[ -x "$shell_path" ]] || shell_path="/usr/bin/false"
  [[ -x "$shell_path" ]] || shell_path="/bin/false"
  echo "$shell_path"
}

detect_ssh_service_name() {
  local svc
  for svc in ssh sshd; do
    if systemctl cat "${svc}.service" >/dev/null 2>&1; then
      echo "$svc"
      return 0
    fi
  done
  return 1
}

ssh_group_users() {
  getent group "$SSH_AUTH_GROUP" | awk -F: '{print $4}' | tr ',' '\n' | awk 'NF'
}

ensure_ssh_auth_group() {
  if getent group "$SSH_AUTH_GROUP" >/dev/null; then
    return 0
  fi
  check_dependencies groupadd
  groupadd --system "$SSH_AUTH_GROUP"
}

prompt_password_twice() {
  local label="${1:-Password}"
  local password confirm
  while true; do
    read -r -s -p "${label}: " password
    echo "" >&2
    [[ -n "$password" ]] || {
      echo -e "${YELLOW}[!]${NC} Password cannot be empty" >&2
      continue
    }
    read -r -s -p "Confirm ${label}: " confirm
    echo "" >&2
    [[ "$password" == "$confirm" ]] || {
      echo -e "${YELLOW}[!]${NC} Passwords do not match" >&2
      continue
    }
    printf "%s\n" "$password"
    return 0
  done
}

write_ssh_auth_config() {
  local tunnel_port="$1"
  validate_port_or_error "$tunnel_port"
  mkdir -p "$SSH_AUTH_CONFIG_DIR"
  cat >"$SSH_AUTH_CONFIG_FILE" <<EOF
# Managed by slipstream-tunnel
Match Group $SSH_AUTH_GROUP
    PasswordAuthentication yes
    KbdInteractiveAuthentication no
    AuthenticationMethods password
    AllowTcpForwarding yes
    AllowAgentForwarding no
    AllowStreamLocalForwarding no
    GatewayPorts no
    PermitTunnel no
    PermitTTY no
    X11Forwarding no
    PermitOpen 127.0.0.1:$tunnel_port
EOF
}

apply_ssh_auth_overlay() {
  local tunnel_port="$1"
  check_dependencies systemctl getent awk tr
  command -v sshd &>/dev/null || error "sshd not found. Install openssh-server first."

  local ssh_service
  ssh_service=$(detect_ssh_service_name || true)
  [[ -n "$ssh_service" ]] || error "Could not detect SSH service (ssh/sshd)."

  ensure_ssh_auth_group
  local backup_file=""
  if [[ -f "$SSH_AUTH_CONFIG_FILE" ]]; then
    backup_file=$(mktemp /tmp/sshd-slipstream-backup.XXXXXX)
    cp "$SSH_AUTH_CONFIG_FILE" "$backup_file"
  fi

  write_ssh_auth_config "$tunnel_port"
  if ! sshd -t; then
    if [[ -n "$backup_file" && -f "$backup_file" ]]; then
      cp "$backup_file" "$SSH_AUTH_CONFIG_FILE"
    else
      rm -f "$SSH_AUTH_CONFIG_FILE"
    fi
    [[ -n "$backup_file" ]] && rm -f "$backup_file"
    error "Generated SSH config is invalid. Changes rolled back."
  fi
  [[ -n "$backup_file" ]] && rm -f "$backup_file"

  systemctl restart "$ssh_service"
  log "SSH auth overlay ready (service: $ssh_service, group: $SSH_AUTH_GROUP, permit-open: 127.0.0.1:$tunnel_port)"
}

create_or_update_tunnel_user() {
  local username="$1" password="$2"
  validate_unix_username_or_error "$username"
  [[ -n "$password" ]] || error "Password cannot be empty"

  ensure_ssh_auth_group
  local shell_path
  shell_path=$(tunnel_nologin_shell)

  if id -u "$username" &>/dev/null; then
    usermod -a -G "$SSH_AUTH_GROUP" "$username"
  else
    if command -v useradd &>/dev/null; then
      useradd --create-home --shell "$shell_path" --groups "$SSH_AUTH_GROUP" "$username"
    elif command -v adduser &>/dev/null; then
      adduser --disabled-password --gecos "" --shell "$shell_path" "$username"
      usermod -a -G "$SSH_AUTH_GROUP" "$username"
    else
      error "No user creation command found (need useradd or adduser)"
    fi
  fi

  printf '%s:%s\n' "$username" "$password" | chpasswd
  log "SSH tunnel user ready: $username"
}

write_ssh_client_env() {
  local username="$1" password_b64="$2" transport_port="$3" local_port="$4" remote_app_port="$5"
  validate_unix_username_or_error "$username"
  validate_port_or_error "$transport_port"
  validate_port_or_error "$local_port"
  validate_port_or_error "$remote_app_port"
  [[ -n "$password_b64" ]] || error "Missing encoded SSH password"

  mkdir -p "$SSH_CLIENT_ENV_DIR"
  chmod 700 "$SSH_CLIENT_ENV_DIR"
  cat >"$SSH_CLIENT_ENV_FILE" <<EOF
SSH_TUNNEL_USER=$username
SSH_TUNNEL_PASS_B64=$password_b64
SSH_TRANSPORT_PORT=$transport_port
SSH_LOCAL_PORT=$local_port
SSH_REMOTE_APP_PORT=$remote_app_port
EOF
  chmod 600 "$SSH_CLIENT_ENV_FILE"
}

write_ssh_client_service() {
  cat >/etc/systemd/system/${SSH_CLIENT_SERVICE}.service <<EOF
[Unit]
Description=Slipstream SSH Auth Overlay Client
After=network.target slipstream-client.service
Requires=slipstream-client.service

[Service]
Type=simple
EnvironmentFile=$SSH_CLIENT_ENV_FILE
ExecStart=/bin/bash -lc 'pass="\$(printf "%s" "\$SSH_TUNNEL_PASS_B64" | base64 -d)"; SSHPASS="\$pass" exec sshpass -e ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -L 127.0.0.1:\${SSH_LOCAL_PORT}:127.0.0.1:\${SSH_REMOTE_APP_PORT} -p \${SSH_TRANSPORT_PORT} \${SSH_TUNNEL_USER}@127.0.0.1'
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

remove_ssh_client_service_if_present() {
  if [[ -f /etc/systemd/system/${SSH_CLIENT_SERVICE}.service ]]; then
    systemctl stop "${SSH_CLIENT_SERVICE}" 2>/dev/null || true
    systemctl disable "${SSH_CLIENT_SERVICE}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SSH_CLIENT_SERVICE}.service"
  fi
  if [[ -f "$SSH_CLIENT_ENV_FILE" ]]; then
    rm -f "$SSH_CLIENT_ENV_FILE"
  fi
}

restart_client_stack() {
  systemctl restart slipstream-client
  if client_ssh_auth_enabled && systemctl list-unit-files "${SSH_CLIENT_SERVICE}.service" &>/dev/null; then
    systemctl restart "${SSH_CLIENT_SERVICE}"
  fi
}

start_client_stack() {
  systemctl start slipstream-client
  if client_ssh_auth_enabled && systemctl list-unit-files "${SSH_CLIENT_SERVICE}.service" &>/dev/null; then
    systemctl start "${SSH_CLIENT_SERVICE}"
  fi
}

stop_client_stack() {
  if client_ssh_auth_enabled && systemctl list-unit-files "${SSH_CLIENT_SERVICE}.service" &>/dev/null; then
    systemctl stop "${SSH_CLIENT_SERVICE}" || true
  fi
  systemctl stop slipstream-client
}

ensure_server_cert() {
  local domain="$1"
  local force="${2:-false}"

  ensure_service_user
  mkdir -p "$CERT_DIR"
  if [[ "$force" == true || ! -f "$CERT_DIR/key.pem" || ! -f "$CERT_DIR/cert.pem" ]]; then
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
}

write_server_service() {
  local domain="$1" port="$2"
  local bin_path="$SLIPSTREAM_SERVER_BIN"

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
}

# ============================================
# SERVER MODE
# ============================================
cmd_server() {
  need_root
  check_dependencies curl tar systemctl openssl awk sed grep head tr sort
  local domain="" port="2053" slipstream_path="" manage_resolver=false
  local enable_ssh_auth=false ssh_backend_port="22"

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
    --ssh-auth)
      enable_ssh_auth=true
      shift
      ;;
    --ssh-backend-port)
      require_flag_value "$1" "${2:-}"
      ssh_backend_port="$2"
      enable_ssh_auth=true
      shift 2
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
  validate_port_or_error "$ssh_backend_port"
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
    auto_fix_port_53_conflict || error "Port 53 is still busy. Stop the remaining listener(s) shown above and run again."
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

  if [[ "$enable_ssh_auth" == false && -t 0 ]]; then
    read -r -p "Enable SSH username/password auth overlay? [Y/n]: " input_enable_auth
    [[ "${input_enable_auth:-y}" != "n" ]] && enable_ssh_auth=true
  fi

  if [[ "$enable_ssh_auth" == true && -t 0 ]]; then
    read -r -p "SSH daemon port on this server [22]: " input_ssh_backend_port
    [[ -n "$input_ssh_backend_port" ]] && ssh_backend_port="$input_ssh_backend_port"
    validate_port_or_error "$ssh_backend_port"
  fi

  ensure_server_cert "$domain" false

  local arch bin_path="$SLIPSTREAM_SERVER_BIN"
  arch=$(detect_arch)
  local slipstream_target_port="$port"
  if [[ "$enable_ssh_auth" == true ]]; then
    slipstream_target_port="$ssh_backend_port"
  fi

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

  log "Creating systemd service..."
  write_server_service "$domain" "$slipstream_target_port"

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
SSH_AUTH_ENABLED=$enable_ssh_auth
SSH_BACKEND_PORT=$ssh_backend_port
EOF

  if [[ "$enable_ssh_auth" == true ]]; then
    check_dependencies chpasswd usermod
    apply_ssh_auth_overlay "$port"
    set_config_value "SSH_AUTH_ENABLED" "true" "$CONFIG_FILE"
    set_config_value "SSH_BACKEND_PORT" "$ssh_backend_port" "$CONFIG_FILE"
    if [[ -t 0 ]]; then
      local initial_user initial_password
      while true; do
        read -r -p "Create first SSH tunnel username: " initial_user
        if [[ -z "$initial_user" ]]; then
          warn "Username cannot be empty"
          continue
        fi
        if [[ "$initial_user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
          break
        fi
        warn "Invalid username format. Use lowercase letters/numbers/_/-"
      done
      initial_password=$(prompt_password_twice "Password for ${initial_user}")
      create_or_update_tunnel_user "$initial_user" "$initial_password"
    else
      warn "Non-interactive session: SSH auth enabled, but no initial user created."
      warn "Create one with: slipstream-tunnel auth-add"
    fi
  else
    set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
    set_config_value "SSH_BACKEND_PORT" "" "$CONFIG_FILE"
  fi

  # Install global command
  install_self

  echo ""
  echo -e "${GREEN}=== Server Ready ===${NC}"
  echo ""
  echo "Next steps:"
  echo "  1. In 3x-ui panel: create inbound on port $port"
  echo "  2. On client run the same install command"
  if [[ "$enable_ssh_auth" == "true" ]]; then
    echo "  3. On client enable SSH auth overlay and use created username/password"
  fi
  echo ""
  echo "Commands:"
  echo "  slipstream-tunnel status"
  echo "  slipstream-tunnel edit"
  echo "  slipstream-tunnel stop"
  echo "  slipstream-tunnel start"
  echo "  slipstream-tunnel auth-add"
  echo "  slipstream-tunnel auth-list"
  echo "  slipstream-tunnel menu"
  echo "  sst"
  echo "  journalctl -u slipstream-server -f"
}

write_client_service() {
  local resolver="$1" domain="$2" port="$3"
  local bin_path="$SLIPSTREAM_CLIENT_BIN"

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

client_transport_port_from_config() {
  if client_ssh_auth_enabled; then
    local transport_port="${SSH_TRANSPORT_PORT:-17070}"
    validate_port_or_error "$transport_port"
    echo "$transport_port"
  else
    local listen_port="${PORT:-7000}"
    validate_port_or_error "$listen_port"
    echo "$listen_port"
  fi
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
  local ssh_auth_client=false ssh_user="" ssh_pass="" ssh_remote_port="2053" ssh_transport_port="17070"

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
    --ssh-auth-client)
      ssh_auth_client=true
      shift
      ;;
    --ssh-user)
      require_flag_value "$1" "${2:-}"
      ssh_user="$2"
      ssh_auth_client=true
      shift 2
      ;;
    --ssh-pass)
      require_flag_value "$1" "${2:-}"
      ssh_pass="$2"
      ssh_auth_client=true
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

  if [[ "$ssh_auth_client" == false && -t 0 ]]; then
    read -r -p "Use SSH username/password auth overlay? [y/N]: " input_ssh_auth_client
    [[ "${input_ssh_auth_client:-n}" == "y" ]] && ssh_auth_client=true
  fi

  if [[ "$ssh_auth_client" == true ]]; then
    check_dependencies ssh sshpass base64
    if [[ -z "$ssh_user" && -t 0 ]]; then
      read -r -p "SSH username: " ssh_user
    fi
    validate_unix_username_or_error "$ssh_user"
    if [[ -z "$ssh_pass" ]]; then
      if [[ -t 0 ]]; then
        ssh_pass=$(prompt_password_twice "SSH password for ${ssh_user}")
      else
        error "In non-interactive mode, --ssh-pass is required with --ssh-auth-client"
      fi
    fi
    if [[ -t 0 ]]; then
      read -r -p "Remote protected app port on server [2053]: " input_ssh_remote_port
      [[ -n "$input_ssh_remote_port" ]] && ssh_remote_port="$input_ssh_remote_port"
      read -r -p "Local internal slipstream port for SSH transport [17070]: " input_ssh_transport_port
      [[ -n "$input_ssh_transport_port" ]] && ssh_transport_port="$input_ssh_transport_port"
    fi
    validate_port_or_error "$ssh_remote_port"
    validate_port_or_error "$ssh_transport_port"
    [[ "$ssh_transport_port" != "$port" ]] || error "Internal SSH transport port must differ from client listen port"
  fi

  # Get slipstream binary (required for --verify)
  local slipstream_bin="$TUNNEL_DIR/slipstream-client"
  local installed_bin="$SLIPSTREAM_CLIENT_BIN"
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

  local bin_path="$SLIPSTREAM_CLIENT_BIN"
  local client_transport_port="$port"
  local ssh_pass_b64=""
  if [[ "$ssh_auth_client" == "true" ]]; then
    client_transport_port="$ssh_transport_port"
    ssh_pass_b64=$(printf '%s' "$ssh_pass" | base64 | tr -d '\n')
  fi

  # Stop existing service
  systemctl stop slipstream-client 2>/dev/null || true
  remove_ssh_client_service_if_present

  # Install binary if not already in place
  if [[ "$slipstream_bin" != "$bin_path" ]]; then
    log "Installing slipstream-client..."
    mv "$slipstream_bin" "$bin_path"
    chmod +x "$bin_path"
  fi

  # Create systemd service
  log "Creating systemd service..."
  write_client_service "$best_server" "$domain" "$client_transport_port"
  if [[ "$ssh_auth_client" == "true" ]]; then
    write_ssh_client_env "$ssh_user" "$ssh_pass_b64" "$ssh_transport_port" "$port" "$ssh_remote_port"
    write_ssh_client_service
  fi

  systemctl daemon-reload
  systemctl enable slipstream-client
  if [[ "$ssh_auth_client" == "true" ]]; then
    systemctl enable "${SSH_CLIENT_SERVICE}"
  fi
  systemctl restart slipstream-client
  if [[ "$ssh_auth_client" == "true" ]]; then
    systemctl restart "${SSH_CLIENT_SERVICE}"
  fi
  log "Started slipstream-client service"

  if [[ "$ssh_auth_client" != "true" ]]; then
    ssh_user=""
    ssh_pass_b64=""
    ssh_remote_port=""
    ssh_transport_port=""
  fi

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
SSH_AUTH_ENABLED=$ssh_auth_client
SSH_AUTH_USER=$ssh_user
SSH_PASS_B64=$ssh_pass_b64
SSH_REMOTE_APP_PORT=$ssh_remote_port
SSH_TRANSPORT_PORT=$ssh_transport_port
EOF

  # Setup health check timer
  setup_health_timer

  # Install global command
  install_self

  echo ""
  echo -e "${GREEN}=== Client Ready ===${NC}"
  echo ""
  echo "Tunnel: 127.0.0.1:$port"
  if [[ "$ssh_auth_client" == "true" ]]; then
    echo "Auth mode: SSH username/password overlay (user: $ssh_user)"
    echo "Internal slipstream transport port: $ssh_transport_port"
    echo "Remote protected app port: $ssh_remote_port"
  fi
  echo "DNS server: $best_server"
  echo ""
  echo "Commands:"
  echo "  slipstream-tunnel status"
  echo "  slipstream-tunnel edit"
  echo "  slipstream-tunnel stop"
  echo "  slipstream-tunnel start"
  echo "  slipstream-tunnel restart"
  echo "  slipstream-tunnel health"
  echo "  slipstream-tunnel rescan"
  echo "  slipstream-tunnel dashboard"
  echo "  slipstream-tunnel servers"
  echo "  slipstream-tunnel menu"
  echo "  sst"
  echo "  journalctl -u slipstream-client -f"
  if [[ "$ssh_auth_client" == "true" ]]; then
    echo "  journalctl -u ${SSH_CLIENT_SERVICE} -f"
  fi
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
      local transport_port
      transport_port=$(client_transport_port_from_config)
      write_client_service "$best_server" "$DOMAIN" "$transport_port"
      systemctl daemon-reload
      if restart_client_stack; then
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
  [[ -x "$SLIPSTREAM_CLIENT_BIN" ]] || error "slipstream-client not installed"

  local dnscan_args=(
    --domain "$DOMAIN"
    --data-dir "$DNSCAN_DIR/data"
    --output "$SERVERS_FILE"
    --verify "$SLIPSTREAM_CLIENT_BIN"
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
  local transport_port
  transport_port=$(client_transport_port_from_config)
  write_client_service "$best_server" "$DOMAIN" "$transport_port"
  systemctl daemon-reload
  restart_client_stack

  log "Switched to best DNS server: $best_server (${best_latency}ms)"
  cmd_servers
  cmd_dashboard
}

cmd_dashboard() {
  check_dependencies systemctl date
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Dashboard is available only in client mode"

  local service_status timer_status current_latency now ssh_status
  service_status=$(systemctl is-active slipstream-client 2>/dev/null || echo "not running")
  timer_status=$(systemctl is-active tunnel-health.timer 2>/dev/null || echo "not installed")
  ssh_status="disabled"
  if client_ssh_auth_enabled; then
    ssh_status=$(systemctl is-active "${SSH_CLIENT_SERVICE}" 2>/dev/null || echo "not running")
  fi
  now=$(date '+%Y-%m-%d %H:%M:%S')

  echo "=== Client Dashboard ==="
  echo "Time: $now"
  echo "Service: $service_status"
  echo "SSH overlay service: $ssh_status"
  echo "Health timer: $timer_status"
  echo "Domain: ${DOMAIN:-unknown}"
  echo "Port: ${PORT:-7000}"
  echo "Current DNS: ${CURRENT_SERVER:-unknown}"
  echo "SSH auth overlay: ${SSH_AUTH_ENABLED:-false}"

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
  local transport_port
  transport_port=$(client_transport_port_from_config)
  write_client_service "$selected" "$DOMAIN" "$transport_port"
  systemctl daemon-reload
  restart_client_stack
  log "Manually switched to DNS server: $selected"
  cmd_dashboard
}

service_name_for_mode() {
  case "${MODE:-}" in
  server) echo "slipstream-server" ;;
  client) echo "slipstream-client" ;;
  *) error "Unsupported mode in config: ${MODE:-unknown}" ;;
  esac
}

cmd_start() {
  need_root
  check_dependencies systemctl
  load_config_or_error

  local service_name
  service_name=$(service_name_for_mode)
  if [[ "${MODE:-}" == "client" ]]; then
    start_client_stack
  else
    systemctl start "$service_name"
  fi

  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-health.timer &>/dev/null; then
    systemctl start tunnel-health.timer || true
  fi
  log "Started: $service_name"
}

cmd_stop() {
  need_root
  check_dependencies systemctl
  load_config_or_error

  local service_name
  service_name=$(service_name_for_mode)
  if [[ "${MODE:-}" == "client" ]]; then
    stop_client_stack
  else
    systemctl stop "$service_name"
  fi

  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-health.timer &>/dev/null; then
    systemctl stop tunnel-health.timer || true
  fi
  log "Stopped: $service_name"
}

cmd_restart() {
  need_root
  check_dependencies systemctl
  load_config_or_error

  local service_name
  service_name=$(service_name_for_mode)
  if [[ "${MODE:-}" == "client" ]]; then
    restart_client_stack
  else
    systemctl restart "$service_name"
  fi

  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-health.timer &>/dev/null; then
    systemctl start tunnel-health.timer || true
  fi
  log "Restarted: $service_name"
}

cmd_uninstall() {
  cmd_remove
}

cmd_edit_client() {
  need_root
  check_dependencies systemctl
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Client edit is available only in client mode"

  local new_domain="${DOMAIN:-}"
  local new_port="${PORT:-7000}"
  local new_server="${CURRENT_SERVER:-}"
  local new_ssh_auth="${SSH_AUTH_ENABLED:-false}"
  local new_ssh_user="${SSH_AUTH_USER:-}"
  local new_ssh_pass_b64="${SSH_PASS_B64:-}"
  local new_ssh_remote_port="${SSH_REMOTE_APP_PORT:-2053}"
  local new_ssh_transport_port="${SSH_TRANSPORT_PORT:-17070}"
  local input

  echo "=== Edit Client Settings ==="
  read -r -p "Domain [$new_domain]: " input
  [[ -n "$input" ]] && new_domain="$input"
  read -r -p "Tunnel listen port [$new_port]: " input
  [[ -n "$input" ]] && new_port="$input"
  read -r -p "DNS resolver IP [$new_server]: " input
  [[ -n "$input" ]] && new_server="$input"
  read -r -p "Use SSH username/password auth overlay? [y/N] (current: ${new_ssh_auth}): " input
  if [[ -n "$input" ]]; then
    [[ "$input" == "y" ]] && new_ssh_auth=true || new_ssh_auth=false
  fi

  validate_domain_or_error "$new_domain"
  validate_port_or_error "$new_port"
  if [[ -n "$new_server" ]]; then
    validate_ipv4_or_error "$new_server"
  elif [[ -s "$SERVERS_FILE" ]]; then
    read -r new_server _ <<<"$(find_best_server "$new_domain" "$SERVERS_FILE")"
  fi
  [[ -n "$new_server" ]] || error "No DNS resolver available. Run 'slipstream-tunnel rescan' first."

  if [[ "$new_ssh_auth" == "true" ]]; then
    check_dependencies ssh sshpass base64
    read -r -p "SSH username [$new_ssh_user]: " input
    [[ -n "$input" ]] && new_ssh_user="$input"
    validate_unix_username_or_error "$new_ssh_user"
    read -r -p "Remote protected app port [$new_ssh_remote_port]: " input
    [[ -n "$input" ]] && new_ssh_remote_port="$input"
    read -r -p "Local internal slipstream port for SSH transport [$new_ssh_transport_port]: " input
    [[ -n "$input" ]] && new_ssh_transport_port="$input"
    validate_port_or_error "$new_ssh_remote_port"
    validate_port_or_error "$new_ssh_transport_port"
    [[ "$new_ssh_transport_port" != "$new_port" ]] || error "Internal SSH transport port must differ from client listen port"
    read -r -p "Change SSH password now? [y/N]: " input
    if [[ "$input" == "y" || -z "$new_ssh_pass_b64" ]]; then
      local plain_pass
      plain_pass=$(prompt_password_twice "SSH password for ${new_ssh_user}")
      new_ssh_pass_b64=$(printf '%s' "$plain_pass" | base64 | tr -d '\n')
    fi
  fi

  set_config_value "DOMAIN" "$new_domain" "$CONFIG_FILE"
  set_config_value "PORT" "$new_port" "$CONFIG_FILE"
  set_config_value "CURRENT_SERVER" "$new_server" "$CONFIG_FILE"
  if [[ "$new_ssh_auth" == "true" ]]; then
    set_config_value "SSH_AUTH_ENABLED" "true" "$CONFIG_FILE"
    set_config_value "SSH_AUTH_USER" "$new_ssh_user" "$CONFIG_FILE"
    set_config_value "SSH_PASS_B64" "$new_ssh_pass_b64" "$CONFIG_FILE"
    set_config_value "SSH_REMOTE_APP_PORT" "$new_ssh_remote_port" "$CONFIG_FILE"
    set_config_value "SSH_TRANSPORT_PORT" "$new_ssh_transport_port" "$CONFIG_FILE"
    write_client_service "$new_server" "$new_domain" "$new_ssh_transport_port"
    write_ssh_client_env "$new_ssh_user" "$new_ssh_pass_b64" "$new_ssh_transport_port" "$new_port" "$new_ssh_remote_port"
    write_ssh_client_service
    SSH_AUTH_ENABLED="true"
  else
    set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
    set_config_value "SSH_AUTH_USER" "" "$CONFIG_FILE"
    set_config_value "SSH_PASS_B64" "" "$CONFIG_FILE"
    set_config_value "SSH_REMOTE_APP_PORT" "" "$CONFIG_FILE"
    set_config_value "SSH_TRANSPORT_PORT" "" "$CONFIG_FILE"
    write_client_service "$new_server" "$new_domain" "$new_port"
    remove_ssh_client_service_if_present
    SSH_AUTH_ENABLED="false"
  fi
  systemctl daemon-reload
  restart_client_stack

  log "Client settings updated and service restarted"
  cmd_dashboard
}

cmd_edit_server() {
  need_root
  check_dependencies systemctl openssl
  load_config_or_error
  [[ "${MODE:-}" == "server" ]] || error "Server edit is available only in server mode"

  local new_domain="${DOMAIN:-}"
  local new_port="${PORT:-2053}"
  local ssh_backend_port="${SSH_BACKEND_PORT:-22}"
  local input regenerate_cert=false

  echo "=== Edit Server Settings ==="
  read -r -p "Domain [$new_domain]: " input
  [[ -n "$input" ]] && new_domain="$input"
  read -r -p "Protected app port [$new_port]: " input
  [[ -n "$input" ]] && new_port="$input"
  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]]; then
    read -r -p "SSH backend port for slipstream [$ssh_backend_port]: " input
    [[ -n "$input" ]] && ssh_backend_port="$input"
    validate_port_or_error "$ssh_backend_port"
  fi

  validate_domain_or_error "$new_domain"
  validate_port_or_error "$new_port"

  if [[ "$new_domain" != "${DOMAIN:-}" ]]; then
    read -r -p "Domain changed. Regenerate certificate? [Y/n]: " input
    [[ "${input:-y}" != "n" ]] && regenerate_cert=true
  fi

  ensure_server_cert "$new_domain" "$regenerate_cert"
  set_config_value "DOMAIN" "$new_domain" "$CONFIG_FILE"
  set_config_value "PORT" "$new_port" "$CONFIG_FILE"
  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]]; then
    set_config_value "SSH_BACKEND_PORT" "$ssh_backend_port" "$CONFIG_FILE"
    write_server_service "$new_domain" "$ssh_backend_port"
  else
    set_config_value "SSH_BACKEND_PORT" "" "$CONFIG_FILE"
    write_server_service "$new_domain" "$new_port"
  fi
  systemctl daemon-reload
  systemctl restart slipstream-server

  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]]; then
    apply_ssh_auth_overlay "$new_port"
  fi

  log "Server settings updated and service restarted"
  cmd_status
}

cmd_edit() {
  need_root
  load_config_or_error
  case "${MODE:-}" in
  client) cmd_edit_client ;;
  server) cmd_edit_server ;;
  *) error "Unsupported mode in config: ${MODE:-unknown}" ;;
  esac
}

cmd_auth_setup() {
  need_root
  check_dependencies systemctl getent awk tr
  ensure_mode_server_or_error

  local app_port="${PORT:-2053}"
  local ssh_backend_port="${SSH_BACKEND_PORT:-22}"
  read -r -p "Protected app port [$app_port]: " input_port
  [[ -n "$input_port" ]] && app_port="$input_port"
  validate_port_or_error "$app_port"

  read -r -p "SSH backend port for slipstream [$ssh_backend_port]: " input_port
  [[ -n "$input_port" ]] && ssh_backend_port="$input_port"
  validate_port_or_error "$ssh_backend_port"

  apply_ssh_auth_overlay "$app_port"
  set_config_value "PORT" "$app_port" "$CONFIG_FILE"
  set_config_value "SSH_BACKEND_PORT" "$ssh_backend_port" "$CONFIG_FILE"
  write_server_service "$DOMAIN" "$ssh_backend_port"
  systemctl daemon-reload
  systemctl restart slipstream-server
  set_config_value "SSH_AUTH_ENABLED" "true" "$CONFIG_FILE"
  log "SSH auth overlay enabled. Users authenticate via SSH before reaching 127.0.0.1:$app_port."
}

cmd_auth_add() {
  need_root
  check_dependencies getent awk tr chpasswd usermod
  ensure_mode_server_or_error

  if [[ "${SSH_AUTH_ENABLED:-false}" != "true" ]]; then
    warn "SSH auth overlay is disabled. Running setup first..."
    cmd_auth_setup
    load_config_or_error
  fi

  local username="${1:-}" password
  if [[ -z "$username" ]]; then
    read -r -p "New SSH tunnel username: " username
  fi
  validate_unix_username_or_error "$username"
  password=$(prompt_password_twice "Password for ${username}")
  create_or_update_tunnel_user "$username" "$password"
}

cmd_auth_passwd() {
  need_root
  check_dependencies chpasswd id
  ensure_mode_server_or_error

  local username="${1:-}" password
  if [[ -z "$username" ]]; then
    read -r -p "SSH tunnel username to update password: " username
  fi
  validate_unix_username_or_error "$username"
  id -u "$username" >/dev/null || error "User does not exist: $username"
  password=$(prompt_password_twice "New password for ${username}")
  printf '%s:%s\n' "$username" "$password" | chpasswd
  log "Password updated for: $username"
}

cmd_auth_del() {
  need_root
  check_dependencies userdel id tr grep
  ensure_mode_server_or_error

  local username="${1:-}"
  if [[ -z "$username" ]]; then
    read -r -p "SSH tunnel username to delete: " username
  fi
  validate_unix_username_or_error "$username"
  id -u "$username" >/dev/null || error "User does not exist: $username"

  if ! id -nG "$username" | tr ' ' '\n' | grep -qx "$SSH_AUTH_GROUP"; then
    error "User is not managed by tunnel auth group ($SSH_AUTH_GROUP): $username"
  fi

  read -r -p "Delete user '$username' and home directory? [y/N]: " confirm_delete
  [[ "${confirm_delete:-n}" == "y" ]] || {
    echo "Canceled"
    return 0
  }
  userdel -r "$username" 2>/dev/null || userdel "$username"
  log "Deleted SSH tunnel user: $username"
}

cmd_auth_list() {
  check_dependencies getent awk tr
  ensure_mode_server_or_error
  echo "=== SSH Tunnel Users ==="
  echo "Group: $SSH_AUTH_GROUP"
  if ! getent group "$SSH_AUTH_GROUP" >/dev/null; then
    echo "No auth group found."
    return 0
  fi

  local users
  users=$(ssh_group_users || true)
  if [[ -z "$users" ]]; then
    echo "No users in group."
    return 0
  fi
  while IFS= read -r user; do
    [[ -z "$user" ]] && continue
    echo "  - $user"
  done <<<"$users"
}

cmd_menu_client() {
  while true; do
    echo ""
    cmd_dashboard
    echo ""
    echo "=== Client Monitor Menu ==="
    echo "1) Run health check now"
    echo "2) Run full DNS rescan now"
    echo "3) Show status"
    echo "4) Follow client logs"
    echo "5) Show verified DNS IP list (live ping + DNS latency)"
    echo "6) Select DNS manually from verified list"
    echo "7) Start client tunnel service"
    echo "8) Stop client tunnel service"
    echo "9) Restart client tunnel service"
    echo "10) Edit client settings (domain/port/resolver/auth)"
    echo "11) Uninstall everything"
    echo "0) Exit menu"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_health ;;
    2) cmd_rescan ;;
    3) cmd_status ;;
    4) cmd_logs -f ;;
    5) cmd_servers ;;
    6) cmd_select_server ;;
    7) cmd_start ;;
    8) cmd_stop ;;
    9) cmd_restart ;;
    10) cmd_edit_client ;;
    11)
      read -r -p "Confirm uninstall (y/n): " confirm_uninstall
      [[ "$confirm_uninstall" == "y" ]] || continue
      cmd_uninstall
      break
      ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_server() {
  while true; do
    echo ""
    cmd_status
    echo ""
    echo "=== Server Monitor Menu ==="
    echo "1) Start server tunnel service"
    echo "2) Stop server tunnel service"
    echo "3) Restart server tunnel service"
    echo "4) Show status"
    echo "5) Follow server logs"
    echo "6) Edit server settings (domain/port)"
    echo "7) Add SSH tunnel user"
    echo "8) Change SSH tunnel user password"
    echo "9) Delete SSH tunnel user"
    echo "10) List SSH tunnel users"
    echo "11) Enable/update SSH auth overlay"
    echo "12) Uninstall everything"
    echo "0) Exit menu"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_start ;;
    2) cmd_stop ;;
    3) cmd_restart ;;
    4) cmd_status ;;
    5) cmd_logs -f ;;
    6) cmd_edit_server ;;
    7) cmd_auth_add ;;
    8) cmd_auth_passwd ;;
    9) cmd_auth_del ;;
    10) cmd_auth_list ;;
    11) cmd_auth_setup ;;
    12)
      read -r -p "Confirm uninstall (y/n): " confirm_uninstall
      [[ "$confirm_uninstall" == "y" ]] || continue
      cmd_uninstall
      break
      ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu() {
  need_root
  load_config_or_error
  if [[ "${MODE:-}" == "client" ]]; then
    cmd_menu_client
  elif [[ "${MODE:-}" == "server" ]]; then
    cmd_menu_server
  else
    error "Unsupported mode in config: ${MODE:-unknown}"
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
  local script_path="$TUNNEL_CMD_BIN"

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
    if [[ "${MODE:-}" == "server" ]]; then
      echo "SSH auth overlay: ${SSH_AUTH_ENABLED:-false}"
    else
      echo "SSH auth overlay: ${SSH_AUTH_ENABLED:-false}"
      [[ -n "${SSH_AUTH_USER:-}" ]] && echo "SSH user: $SSH_AUTH_USER"
    fi
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
    if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && command -v getent &>/dev/null; then
      local ssh_users
      ssh_users=$(ssh_group_users | tr '\n' ',' | sed 's/,$//')
      [[ -z "$ssh_users" ]] && ssh_users="none"
      echo "  ssh-auth users: $ssh_users"
    fi
  else
    local status
    status=$(systemctl is-active slipstream-client 2>/dev/null || echo "not running")
    echo "  slipstream-client: $status"
    if client_ssh_auth_enabled; then
      local ssh_status
      ssh_status=$(systemctl is-active "${SSH_CLIENT_SERVICE}" 2>/dev/null || echo "not running")
      echo "  ${SSH_CLIENT_SERVICE}: $ssh_status"
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

  if [[ -f /etc/systemd/system/${SSH_CLIENT_SERVICE}.service ]]; then
    log "Stopping ${SSH_CLIENT_SERVICE} service..."
    systemctl stop "${SSH_CLIENT_SERVICE}" 2>/dev/null || true
    systemctl disable "${SSH_CLIENT_SERVICE}" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SSH_CLIENT_SERVICE}.service"
  fi

  # Remove binaries
  if [[ -f "$SLIPSTREAM_SERVER_BIN" ]]; then
    log "Removing slipstream-server binary..."
    rm -f "$SLIPSTREAM_SERVER_BIN"
  fi

  if [[ -f "$SLIPSTREAM_CLIENT_BIN" ]]; then
    log "Removing slipstream-client binary..."
    rm -f "$SLIPSTREAM_CLIENT_BIN"
  fi

  if [[ -f "$TUNNEL_CMD_BIN" ]]; then
    log "Removing slipstream-tunnel command..."
    rm -f "$TUNNEL_CMD_BIN"
  fi

  if [[ -f "$SST_BIN" ]]; then
    log "Removing sst shortcut..."
    rm -f "$SST_BIN"
  fi

  if [[ -f "$SSH_CLIENT_ENV_FILE" ]]; then
    log "Removing SSH client auth env..."
    rm -f "$SSH_CLIENT_ENV_FILE"
  fi
  if [[ -d "$SSH_CLIENT_ENV_DIR" ]]; then
    rmdir "$SSH_CLIENT_ENV_DIR" 2>/dev/null || true
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

  # Remove SSH auth overlay and managed users
  if [[ -f "$SSH_AUTH_CONFIG_FILE" ]]; then
    read -r -p "Remove SSH auth overlay config? (y/n): " remove_ssh_overlay
    if [[ "$remove_ssh_overlay" == "y" ]]; then
      rm -f "$SSH_AUTH_CONFIG_FILE"
      if command -v sshd &>/dev/null && sshd -t; then
        local ssh_service
        ssh_service=$(detect_ssh_service_name || true)
        [[ -n "$ssh_service" ]] && systemctl restart "$ssh_service" || true
      fi
      log "Removed SSH auth overlay config"
    fi
  fi

  if command -v getent &>/dev/null && getent group "$SSH_AUTH_GROUP" >/dev/null 2>&1; then
    local auth_users
    auth_users=$(ssh_group_users | tr '\n' ' ')
    if [[ -n "$auth_users" ]]; then
      read -r -p "Delete SSH tunnel users ($auth_users)? (y/n): " remove_ssh_users
      if [[ "$remove_ssh_users" == "y" ]]; then
        local auth_user
        while IFS= read -r auth_user; do
          [[ -z "$auth_user" ]] && continue
          userdel -r "$auth_user" 2>/dev/null || userdel "$auth_user" 2>/dev/null || true
        done <<<"$(ssh_group_users)"
        log "Removed SSH tunnel users"
      fi
    fi
    read -r -p "Delete SSH auth group '$SSH_AUTH_GROUP'? (y/n): " remove_ssh_group
    if [[ "$remove_ssh_group" == "y" ]]; then
      groupdel "$SSH_AUTH_GROUP" 2>/dev/null || true
    fi
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
  edit) cmd_edit ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  health) cmd_health ;;
  rescan) cmd_rescan ;;
  dashboard) cmd_dashboard ;;
  servers) cmd_servers ;;
  menu | m) cmd_menu ;;
  auth-setup) cmd_auth_setup ;;
  auth-add)
    shift
    cmd_auth_add "${1:-}"
    ;;
  auth-passwd)
    shift
    cmd_auth_passwd "${1:-}"
    ;;
  auth-del)
    shift
    cmd_auth_del "${1:-}"
    ;;
  auth-list) cmd_auth_list ;;
  status) cmd_status ;;
  logs)
    shift
    cmd_logs "$@"
    ;;
  uninstall | remove) cmd_uninstall ;;
  -h | --help | help) usage ;;
  *) error "Unknown command: $1" ;;
  esac
}

if [[ "${BASH_SOURCE[0]-$0}" == "$0" ]]; then
  main "$@"
fi
