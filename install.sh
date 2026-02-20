#!/usr/bin/env bash
# DNS Tunnel Setup - Automated slipstream tunnel configuration
set -euo pipefail
# systemd units may run without HOME; keep script safe under `set -u`.
HOME="${HOME:-/root}"

# =============================================================================
# Release source configuration (pinned versions)
# =============================================================================
SLIPSTREAM_CORE="${SLIPSTREAM_CORE:-dnstm}"
SLIPSTREAM_REPO_OVERRIDE="${SLIPSTREAM_REPO:-}"
SLIPSTREAM_VERSION_OVERRIDE="${SLIPSTREAM_VERSION:-}"
SLIPSTREAM_ASSET_LAYOUT_OVERRIDE="${SLIPSTREAM_ASSET_LAYOUT:-}"
SLIPSTREAM_REPO=""
SLIPSTREAM_VERSION=""
SLIPSTREAM_ASSET_LAYOUT=""
DNSCAN_REPO="nightowlnerd/dnscan"
DNSCAN_VERSION="${DNSCAN_VERSION:-v1.4.0}"
DNSTM_REPO="${DNSTM_REPO:-net2share/dnstm}"
DNSTM_VERSION="${DNSTM_VERSION:-v0.6.5}"
DNSTT_CLIENT_REPO="${DNSTT_CLIENT_REPO:-net2share/dnstt}"
DNSTT_CLIENT_VERSION="${DNSTT_CLIENT_VERSION:-latest}"
SCRIPT_REPO="${SCRIPT_REPO:-Recoba86/slipstream-tunnel-control}"
SCRIPT_BRANCH="${SCRIPT_BRANCH:-main}"
SLIPSTREAM_SERVER_BIN="${SLIPSTREAM_SERVER_BIN:-/usr/local/bin/slipstream-server}"
SLIPSTREAM_CLIENT_BIN="${SLIPSTREAM_CLIENT_BIN:-/usr/local/bin/slipstream-client}"
DNSTT_CLIENT_BIN="${DNSTT_CLIENT_BIN:-/usr/local/bin/dnstt-client}"
DNSTM_BIN="${DNSTM_BIN:-/usr/local/bin/dnstm}"
TUNNEL_CMD_BIN="${TUNNEL_CMD_BIN:-/usr/local/bin/slipstream-tunnel}"
SST_BIN="${SST_BIN:-/usr/local/bin/sst}"
# =============================================================================

TUNNEL_DIR="$HOME/.tunnel"
INSTANCES_DIR="$TUNNEL_DIR/instances"
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
BBR_SYSCTL_FILE="/etc/sysctl.d/99-slipstream-tunnel-bbr.conf"
WATCHDOG_STATE_DIR="/run/slipstream-tunnel"
WATCHDOG_LAST_RESTART_FILE="$WATCHDOG_STATE_DIR/watchdog.last_restart"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
PKG_MANAGER_CACHE="${PKG_MANAGER_CACHE:-}"
PKG_INDEX_UPDATED="${PKG_INDEX_UPDATED:-0}"

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
  watchdog            Run immediate runtime watchdog check (client mode)
  rescan              Run manual DNS rescan and switch to best server
  dashboard           Show client tunnel dashboard
  servers             Show verified DNS IPs with live latency checks
  instance-add        Add/start an extra client instance (multi-instance)
  instance-list       List extra client instances
  instance-status     Show one extra client instance status
  instance-start      Start one extra client instance
  instance-stop       Stop one extra client instance
  instance-restart    Restart one extra client instance
  instance-logs       View logs for one extra client instance (-f to follow)
  instance-servers    Show DNS candidates for one extra client instance
  instance-select     Manually switch DNS resolver for one extra client instance
  instance-rescan     Run DNS rescan for one extra client instance
  instance-edit       Edit one extra client instance (domain/port/resolver)
  instance-del        Delete one extra client instance
  menu                Open interactive monitor menu (server/client)
  m                   Short alias for menu
  speed-profile       Set profile: fast (SSH off) / secure (SSH on)
  core-switch         Switch current mode to another core (dnstm/nightowl/plus)
  dnstm               Pass-through to native dnstm CLI (server core)
  auth-setup          Enable/update SSH auth overlay for server mode
  auth-disable        Disable SSH auth overlay for server mode
  auth-client-enable  Enable SSH auth overlay for client mode
  auth-client-disable Disable SSH auth overlay for client mode
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
  --core <name>       Slipstream core source: dnstm (default), nightowl, or plus
  --slipstream <path> Path to slipstream binary (offline)
  --dnscan <path>     Path to dnscan tarball (client offline install)
  --dns-file <path>   Custom DNS server list (skips subnet scan)
  --transport <type>  Client transport: slipstream (default) or dnstt (dnstm core)
  --dnstt-pubkey <hex64>
                      Client transport=dnstt: DNSTT server public key (64 hex chars)
  --dnstt-client <path>
                      Client transport=dnstt: path to local dnstt-client binary
  --slipstream-cert <path>
                      Client transport=slipstream: optional pinned server certificate path
  --manage-resolver   Server: allow script to manage systemd-resolved/resolv.conf
  --ssh-auth          Server: enable SSH username/password auth overlay
  --ssh-backend-port <port>
                      Server: SSH daemon port behind slipstream when --ssh-auth is enabled (default: 22)
  --dnstm-bin <path>  Server: path to local dnstm binary (offline install/migration)
  --dnstm-transport <slipstream|dnstt>
                      Server (dnstm core): initial tunnel transport (default: slipstream)
  --dnstm-backend <custom|socks|ssh|shadowsocks>
                      Server (dnstm core): initial backend type (default: custom)
  --dnstm-backend-tag <tag>
                      Server (dnstm core): backend tag (default: app-main, or built-in socks/ssh)
  --dnstm-tunnel-tag <tag>
                      Server (dnstm core): tunnel tag (default: main)
  --dnstm-mode <single|multi>
                      Server (dnstm core): router mode to initialize (default: single)
  --dnstm-ss-password <value>
                      Server (dnstm core): optional Shadowsocks password for initial backend
  --dnstm-ss-method <method>
                      Server (dnstm core): Shadowsocks method (default: aes-256-gcm)
  --dnstm-netmod-domain <domain>
                      Server (dnstm core): optional extra domain for NetMod DNSTT-over-SSH tunnel
  --dnstm-netmod-tag <tag>
                      Server (dnstm core): optional NetMod tunnel tag (default: netmod-ssh)
  --ssh-auth-client   Client: use SSH username/password overlay
  --ssh-user <name>   Client: SSH username (with --ssh-auth-client)
  --ssh-pass <pass>   Client: SSH password (with --ssh-auth-client)

Examples:
  slipstream-tunnel server --domain t.example.com
  slipstream-tunnel server --domain t.example.com --manage-resolver
  slipstream-tunnel client --domain t.example.com
  slipstream-tunnel client --domain t.example.com --transport dnstt --dnstt-pubkey <hex64>
  slipstream-tunnel client --dns-file /tmp/dns-servers.txt
  slipstream-tunnel edit
  slipstream-tunnel stop
  slipstream-tunnel start
  slipstream-tunnel watchdog
  slipstream-tunnel rescan
  slipstream-tunnel servers
  slipstream-tunnel instance-add dubai
  slipstream-tunnel instance-list
  slipstream-tunnel instance-status dubai
  slipstream-tunnel instance-select dubai
  slipstream-tunnel menu
  slipstream-tunnel speed-profile fast
  slipstream-tunnel core-switch dnstm
  slipstream-tunnel dnstm router status
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

set_slipstream_source() {
  local core="${1:-dnstm}"
  local default_repo default_version default_layout

  case "$core" in
  dnstm)
    default_repo="net2share/slipstream-rust-build"
    default_version="v2026.02.05"
    default_layout="binary"
    ;;
  nightowl)
    default_repo="nightowlnerd/slipstream-rust"
    default_version="v0.1.1"
    default_layout="tarball"
    ;;
  plus)
    default_repo="Fox-Fig/slipstream-rust-plus-deploy"
    default_version="a2db384"
    default_layout="binary"
    ;;
  *)
    error "Unknown core '$core'. Valid values: dnstm, nightowl, plus"
    ;;
  esac

  SLIPSTREAM_CORE="$core"
  SLIPSTREAM_REPO="${SLIPSTREAM_REPO_OVERRIDE:-$default_repo}"
  SLIPSTREAM_VERSION="${SLIPSTREAM_VERSION_OVERRIDE:-$default_version}"
  SLIPSTREAM_ASSET_LAYOUT="${SLIPSTREAM_ASSET_LAYOUT_OVERRIDE:-$default_layout}"
}

slipstream_arch_token() {
  local arch="$1"
  case "$SLIPSTREAM_ASSET_LAYOUT" in
  tarball)
    case "$arch" in
    x86_64 | arm64) echo "$arch" ;;
    *) error "Unsupported architecture for tarball layout: $arch" ;;
    esac
    ;;
  binary)
    case "$arch" in
    x86_64) echo "amd64" ;;
    arm64) echo "arm64" ;;
    *) error "Unsupported architecture for binary layout: $arch" ;;
    esac
    ;;
  *)
    error "Unknown SLIPSTREAM_ASSET_LAYOUT: $SLIPSTREAM_ASSET_LAYOUT"
    ;;
  esac
}

slipstream_asset_name() {
  local component="$1" arch="$2" token
  token=$(slipstream_arch_token "$arch")
  case "$SLIPSTREAM_ASSET_LAYOUT" in
  tarball)
    echo "slipstream-linux-${token}.tar.gz"
    ;;
  binary)
    case "$component" in
    server) echo "slipstream-server-linux-${token}" ;;
    client) echo "slipstream-client-linux-${token}" ;;
    *) error "Unknown slipstream component: $component" ;;
    esac
    ;;
  *)
    error "Unknown SLIPSTREAM_ASSET_LAYOUT: $SLIPSTREAM_ASSET_LAYOUT"
    ;;
  esac
}

dnstm_arch_token() {
  local arch="$1"
  case "$arch" in
  x86_64) echo "amd64" ;;
  arm64) echo "arm64" ;;
  *) error "Unsupported architecture for dnstm binary: $arch" ;;
  esac
}

dnstm_asset_name() {
  local arch="$1" token
  token=$(dnstm_arch_token "$arch")
  echo "dnstm-linux-${token}"
}

dnstt_client_asset_name() {
  local arch="$1" token
  token=$(dnstm_arch_token "$arch")
  echo "dnstt-client-linux-${token}"
}

validate_transport_or_error() {
  local transport="$1"
  case "$transport" in
  slipstream | dnstt) ;;
  *) error "Invalid transport: $transport (use slipstream or dnstt)" ;;
  esac
}

validate_dnstt_bind_host_or_error() {
  local bind_host="$1"
  case "$bind_host" in
  127.0.0.1 | 0.0.0.0) ;;
  *) error "Invalid DNSTT bind host: $bind_host (use 127.0.0.1 or 0.0.0.0)" ;;
  esac
}

validate_local_bind_addr_or_error() {
  local bind_addr="$1"
  case "$bind_addr" in
  127.0.0.1 | 0.0.0.0) ;;
  *) error "Invalid local bind address: $bind_addr (use 127.0.0.1 or 0.0.0.0)" ;;
  esac
}

prompt_dnstt_bind_host_or_error() {
  local current="${1:-127.0.0.1}" input
  validate_dnstt_bind_host_or_error "$current"
  while true; do
    read -r -p "DNSTT bind host [127.0.0.1/0.0.0.0] [$current]: " input
    [[ -z "$input" ]] && input="$current"
    case "$input" in
    127.0.0.1 | 0.0.0.0)
      echo "$input"
      return 0
      ;;
    *)
      warn "Invalid bind host: $input"
      ;;
    esac
  done
}

prompt_local_bind_addr_or_error() {
  local current="${1:-0.0.0.0}" input
  validate_local_bind_addr_or_error "$current"
  while true; do
    read -r -p "Local app bind address [127.0.0.1/0.0.0.0] [$current]: " input
    [[ -z "$input" ]] && input="$current"
    case "$input" in
    127.0.0.1 | 0.0.0.0)
      echo "$input"
      return 0
      ;;
    *)
      warn "Invalid bind address: $input"
      ;;
    esac
  done
}

prompt_core_choice() {
  local current="${1:-dnstm}" input
  while true; do
    printf '\n' >&2
    printf 'Select slipstream core:\n' >&2
    printf '  1) dnstm (default, net2share build)\n' >&2
    printf '  2) nightowl (stable legacy)\n' >&2
    printf '  3) plus (faster, experimental)\n' >&2
    case "$current" in
    nightowl)
      read -r -p "Choice [2]: " input
      input="${input:-2}"
      ;;
    plus)
      read -r -p "Choice [3]: " input
      input="${input:-3}"
      ;;
    *)
      read -r -p "Choice [1]: " input
      input="${input:-1}"
      ;;
    esac
    case "$input" in
    1 | dnstm) echo "dnstm"; return 0 ;;
    2 | nightowl) echo "nightowl"; return 0 ;;
    3 | plus) echo "plus"; return 0 ;;
    *) printf '[!] Invalid choice: %s\n' "$input" >&2 ;;
    esac
  done
}

core_supports_ssh_overlay() {
  [[ "${SLIPSTREAM_CORE:-}" != "dnstm" ]]
}

check_dependencies() {
  local missing=()
  local cmd
  for cmd in "$@"; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done

  if [[ ${#missing[@]} -gt 0 ]]; then
    auto_install_missing_commands "${missing[@]}"
    local still_missing=()
    for cmd in "$@"; do
      command -v "$cmd" &>/dev/null || still_missing+=("$cmd")
    done
    [[ ${#still_missing[@]} -eq 0 ]] || error "Missing required commands: ${still_missing[*]}"
  fi
}

detect_package_manager() {
  if [[ -n "$PKG_MANAGER_CACHE" ]]; then
    echo "$PKG_MANAGER_CACHE"
    return 0
  fi

  local managers=(apt-get dnf yum zypper pacman apk)
  local manager
  for manager in "${managers[@]}"; do
    if command -v "$manager" &>/dev/null; then
      PKG_MANAGER_CACHE="$manager"
      echo "$manager"
      return 0
    fi
  done
  return 1
}

package_for_command() {
  local manager="$1" cmd="$2"
  case "$cmd" in
  dig)
    case "$manager" in
    apt-get) echo "dnsutils" ;;
    dnf | yum) echo "bind-utils" ;;
    zypper) echo "bind-utils" ;;
    pacman) echo "bind" ;;
    apk) echo "bind-tools" ;;
    esac
    ;;
  ssh)
    case "$manager" in
    apt-get) echo "openssh-client" ;;
    dnf | yum) echo "openssh-clients" ;;
    zypper | pacman) echo "openssh" ;;
    apk) echo "openssh-client" ;;
    esac
    ;;
  sshd)
    case "$manager" in
    apt-get) echo "openssh-server" ;;
    dnf | yum) echo "openssh-server" ;;
    zypper | pacman) echo "openssh" ;;
    apk) echo "openssh-server" ;;
    esac
    ;;
  sshpass)
    echo "sshpass"
    ;;
  ss)
    case "$manager" in
    apt-get) echo "iproute2" ;;
    dnf | yum | zypper | pacman | apk) echo "iproute2" ;;
    esac
    ;;
  netstat)
    echo "net-tools"
    ;;
  *)
    return 1
    ;;
  esac
}

install_packages() {
  local manager="$1"
  shift
  local packages=("$@")
  [[ ${#packages[@]} -gt 0 ]] || return 0

  case "$manager" in
  apt-get)
    if [[ "$PKG_INDEX_UPDATED" != "1" ]]; then
      log "Updating package index (apt-get update)..."
      apt-get update
      PKG_INDEX_UPDATED="1"
    fi
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
    ;;
  dnf)
    dnf install -y "${packages[@]}"
    ;;
  yum)
    yum install -y "${packages[@]}"
    ;;
  zypper)
    zypper --non-interactive install --no-confirm "${packages[@]}"
    ;;
  pacman)
    pacman -Sy --noconfirm "${packages[@]}"
    ;;
  apk)
    apk add --no-cache "${packages[@]}"
    ;;
  *)
    error "Unsupported package manager: $manager"
    ;;
  esac
}

auto_install_missing_commands() {
  local missing=("$@")
  [[ ${#missing[@]} -gt 0 ]] || return 0

  [[ $EUID -eq 0 ]] || error "Missing required commands: ${missing[*]} (run as root for auto-install)"
  local manager
  manager=$(detect_package_manager) || error "Missing required commands: ${missing[*]} (no supported package manager found)"

  local packages=() unresolved=()
  local cmd package
  for cmd in "${missing[@]}"; do
    package=$(package_for_command "$manager" "$cmd" || true)
    if [[ -n "$package" ]]; then
      packages+=("$package")
    else
      unresolved+=("$cmd")
    fi
  done

  if [[ ${#unresolved[@]} -gt 0 ]]; then
    error "Missing required commands: ${unresolved[*]} (auto-install mapping not available)"
  fi

  local unique_packages=()
  local pkg
  declare -A seen_pkgs=()
  for pkg in "${packages[@]}"; do
    [[ -n "$pkg" ]] || continue
    if [[ -z "${seen_pkgs[$pkg]+x}" ]]; then
      seen_pkgs[$pkg]=1
      unique_packages+=("$pkg")
    fi
  done

  if [[ ${#unique_packages[@]} -gt 0 ]]; then
    log "Installing missing dependencies: ${unique_packages[*]}"
    install_packages "$manager" "${unique_packages[@]}" || error "Failed to install required dependencies"
  fi
}

require_flag_value() {
  local flag="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || error "Missing value for $flag"
}

prompt_read() {
  local out_var="$1" prompt="$2" input=""
  if [[ -t 0 ]]; then
    read -r -p "$prompt" input
  elif [[ -e /dev/tty ]] && : </dev/tty 2>/dev/null; then
    read -r -p "$prompt" input </dev/tty
  else
    error "Interactive input required but no TTY is available. Run: curl ... -o /tmp/slipstream-install.sh && bash /tmp/slipstream-install.sh ..."
  fi
  printf -v "$out_var" '%s' "$input"
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

validate_dnstt_pubkey_or_error() {
  local pubkey="$1"
  [[ "$pubkey" =~ ^[A-Fa-f0-9]{64}$ ]] || error "Invalid DNSTT public key (must be 64 hex chars)"
}

validate_instance_name_or_error() {
  local name="$1"
  [[ "$name" =~ ^[a-z][a-z0-9_-]{0,30}$ ]] || error "Invalid instance name: $name (use: a-z, 0-9, -, _)"
}

instance_dir() {
  local name="$1"
  echo "$INSTANCES_DIR/$name"
}

instance_config_file() {
  local name="$1"
  echo "$(instance_dir "$name")/config"
}

instance_servers_file() {
  local name="$1"
  echo "$(instance_dir "$name")/servers.txt"
}

instance_health_log() {
  local name="$1"
  echo "$(instance_dir "$name")/health.log"
}

instance_client_service() {
  local name="$1"
  echo "slipstream-client-$name"
}

instance_ssh_client_service() {
  local name="$1"
  echo "slipstream-ssh-client-$name"
}

instance_ssh_client_env_file() {
  local name="$1"
  echo "$SSH_CLIENT_ENV_DIR/ssh-client-$name.env"
}

instance_health_service() {
  local name="$1"
  echo "tunnel-health-$name"
}

instance_health_timer() {
  local name="$1"
  echo "tunnel-health-$name.timer"
}

instance_watchdog_service() {
  local name="$1"
  echo "tunnel-watchdog-$name"
}

instance_watchdog_timer() {
  local name="$1"
  echo "tunnel-watchdog-$name.timer"
}

instance_watchdog_last_restart_file() {
  local name="$1"
  echo "$WATCHDOG_STATE_DIR/watchdog-$name.last_restart"
}

collect_known_resolver_candidates() {
  local candidate cfg

  {
    if [[ -f "$CONFIG_FILE" ]]; then
      candidate=$(grep -E '^CURRENT_SERVER=' "$CONFIG_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)
      is_valid_ipv4 "$candidate" && echo "$candidate"
    fi

    if [[ -s "$SERVERS_FILE" ]]; then
      while IFS= read -r candidate; do
        [[ -n "$candidate" ]] || continue
        is_valid_ipv4 "$candidate" && echo "$candidate"
      done <"$SERVERS_FILE"
    fi

    if [[ -d "$INSTANCES_DIR" ]]; then
      for cfg in "$INSTANCES_DIR"/*/config; do
        [[ -f "$cfg" ]] || continue
        candidate=$(grep -E '^CURRENT_SERVER=' "$cfg" 2>/dev/null | tail -1 | cut -d= -f2- || true)
        is_valid_ipv4 "$candidate" && echo "$candidate"
      done
    fi

    if [[ -f /etc/resolv.conf ]]; then
      awk '/^[[:space:]]*nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null \
        | while IFS= read -r candidate; do
          [[ -n "$candidate" ]] || continue
          is_valid_ipv4 "$candidate" || continue
          [[ "$candidate" == 127.* ]] && continue
          echo "$candidate"
        done
    fi

    # Common public resolvers as fallback candidates.
    echo "9.9.9.9"
    echo "1.1.1.1"
    echo "8.8.8.8"
    echo "208.67.222.222"
    echo "208.67.220.220"
  } | awk '!seen[$0]++'
}

refresh_resolver_candidates_file() {
  local domain="$1" output_file="$2" seed_file="${3:-}" preferred="${4:-}"
  local tmp candidate

  [[ -n "$domain" ]] || error "Internal error: domain is required for resolver refresh"
  tmp=$(mktemp /tmp/resolvers.XXXXXX.txt)

  {
    [[ -n "$preferred" ]] && echo "$preferred"
    [[ -f "$output_file" ]] && cat "$output_file"
    if [[ -n "$seed_file" && -f "$seed_file" && "$seed_file" != "$output_file" ]]; then
      cat "$seed_file"
    fi
    collect_known_resolver_candidates
  } | while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    is_valid_ipv4 "$candidate" || continue
    resolver_answers_dns_queries "$candidate" || continue
    resolver_supports_tunnel_domain "$candidate" "$domain" || continue
    echo "$candidate"
  done | awk '!seen[$0]++' >"$tmp"

  if [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"
    return 1
  fi
  mv "$tmp" "$output_file"
}

prompt_instance_resolver_or_error() {
  local out_var="$1" domain="$2" choice="" candidate_resolver="" latency=""
  local transport="${3:-${DNSTM_TRANSPORT:-slipstream}}"
  local dnstt_pubkey="${4:-${DNSTM_DNSTT_PUBKEY:-}}"
  local slipstream_cert="${5:-${DNSTM_SLIPSTREAM_CERT:-}}"
  local dnstt_bind_host="${6:-${DNSTT_BIND_HOST:-127.0.0.1}}"
  local candidates=()

  [[ -n "$domain" ]] || error "Internal error: domain is required for resolver selection"
  validate_transport_or_error "$transport"

  while IFS= read -r candidate_resolver; do
    [[ -n "$candidate_resolver" ]] || continue
    candidates+=("$candidate_resolver")
  done < <(collect_known_resolver_candidates)

  echo "Resolver must be a reachable DNS IP from this client (not blocked foreign server IP)."

  if [[ ${#candidates[@]} -gt 0 ]]; then
    echo "Known successful DNS resolver IPs:"
    local i=1
    for candidate_resolver in "${candidates[@]}"; do
      if command -v dig &>/dev/null; then
        if resolver_answers_dns_queries "$candidate_resolver"; then
          latency=$(test_dns_latency "$candidate_resolver" "$domain" || echo "9999")
          if [[ "$latency" -lt 1000 ]]; then
            printf "  %d) %s (dns=reachable, tunnel=%sms)\n" "$i" "$candidate_resolver" "$latency"
          else
            printf "  %d) %s (dns=reachable, tunnel=no-answer)\n" "$i" "$candidate_resolver"
          fi
        else
          printf "  %d) %s (dns=unreachable)\n" "$i" "$candidate_resolver"
        fi
      else
        printf "  %d) %s\n" "$i" "$candidate_resolver"
      fi
      i=$((i + 1))
    done
    echo "  0) Enter manually"

    while true; do
      prompt_read choice "Choose DNS index [1]: "
      choice="${choice:-1}"
      [[ "$choice" =~ ^[0-9]+$ ]] || {
        warn "Invalid selection: $choice"
        continue
      }
      if [[ "$choice" == "0" ]]; then
        prompt_read candidate_resolver "DNS resolver IP (server IP): "
        validate_ipv4_or_error "$candidate_resolver"
      else
        ((choice >= 1 && choice <= ${#candidates[@]})) || {
          warn "Selection out of range: $choice"
          continue
        }
        candidate_resolver="${candidates[$((choice - 1))]}"
      fi

      if command -v dig &>/dev/null && ! resolver_supports_tunnel_domain "$candidate_resolver" "$domain"; then
        warn "Resolver $candidate_resolver did not answer for $domain (dns=fail). Choose another resolver."
        continue
      fi
      if ! probe_tunnel_data_path "$candidate_resolver" "$domain" "$transport" "$dnstt_pubkey" "$slipstream_cert" "$dnstt_bind_host"; then
        warn "Resolver $candidate_resolver failed transport data-path probe (${transport}). Choose another resolver."
        continue
      fi
      printf -v "$out_var" '%s' "$candidate_resolver"
      return 0
    done
  fi

  while true; do
    prompt_read candidate_resolver "DNS resolver IP (server IP): "
    validate_ipv4_or_error "$candidate_resolver"
    if command -v dig &>/dev/null && ! resolver_supports_tunnel_domain "$candidate_resolver" "$domain"; then
      warn "Resolver $candidate_resolver did not answer for $domain (dns=fail). Choose another resolver."
      continue
    fi
    if ! probe_tunnel_data_path "$candidate_resolver" "$domain" "$transport" "$dnstt_pubkey" "$slipstream_cert" "$dnstt_bind_host"; then
      warn "Resolver $candidate_resolver failed transport data-path probe (${transport}). Choose another resolver."
      continue
    fi
    printf -v "$out_var" '%s' "$candidate_resolver"
    return 0
  done
}

load_instance_config_or_error() {
  local name="$1"
  local cfg
  cfg=$(instance_config_file "$name")
  [[ -f "$cfg" ]] || error "No such instance: $name"
  # shellcheck disable=SC1090
  source "$cfg"
  if [[ -z "${SLIPSTREAM_CORE:-}" ]]; then
    SLIPSTREAM_CORE="nightowl"
  fi
  set_slipstream_source "${SLIPSTREAM_CORE:-dnstm}"
}

port_in_use() {
  local port="$1"
  if command -v ss &>/dev/null; then
    ss -H -lnt "sport = :$port" 2>/dev/null | awk 'NF {found=1} END {exit !found}'
  else
    return 1
  fi
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

dnstm_is_installed() {
  [[ -x "$DNSTM_BIN" ]]
}

run_dnstm() {
  dnstm_is_installed || error "dnstm binary is not installed: $DNSTM_BIN"
  "$DNSTM_BIN" "$@"
}

ensure_dnstm_binary() {
  local arch source_path="${1:-}" asset tmp_bin

  if dnstm_is_installed; then
    return 0
  fi

  if [[ -n "$source_path" ]]; then
    log "Installing dnstm binary from $source_path..."
    cp "$source_path" "$DNSTM_BIN"
    chmod +x "$DNSTM_BIN"
    warn "Local dnstm binary was not checksum-verified"
    return 0
  fi

  arch=$(detect_arch)
  asset=$(dnstm_asset_name "$arch")
  tmp_bin=$(mktemp /tmp/dnstm.XXXXXX.bin)

  if download_release_asset_verified "$DNSTM_REPO" "$DNSTM_VERSION" "$asset" "$tmp_bin"; then
    install -m 0755 "$tmp_bin" "$DNSTM_BIN"
    rm -f "$tmp_bin"
    log "Installed dnstm binary: ${DNSTM_REPO}@${DNSTM_VERSION}"
    return 0
  fi
  rm -f "$tmp_bin"

  warn "Automatic dnstm download failed for ${asset}"
  echo ""
  echo "Failed URL:"
  echo "  https://github.com/${DNSTM_REPO}/releases/download/${DNSTM_VERSION}/${asset}"
  echo ""
  prompt_read source_path "Provide local dnstm binary path (or Ctrl+C to abort): "
  [[ -n "$source_path" ]] || error "No local dnstm binary path provided"
  cp "$source_path" "$DNSTM_BIN"
  chmod +x "$DNSTM_BIN"
  warn "Local dnstm binary was not checksum-verified"
}

ensure_slipstream_client_binary() {
  if [[ -x "$SLIPSTREAM_CLIENT_BIN" ]]; then
    return 0
  fi
  local arch
  arch=$(detect_arch)
  download_slipstream_component "client" "$SLIPSTREAM_CLIENT_BIN" "$arch" \
    || error "Failed to download slipstream-client binary"
  chmod +x "$SLIPSTREAM_CLIENT_BIN"
}

ensure_dnstt_client_binary() {
  local source_path="${1:-}" arch asset url tmp_bin

  if [[ -x "$DNSTT_CLIENT_BIN" ]]; then
    return 0
  fi

  if [[ -n "$source_path" ]]; then
    log "Installing dnstt-client from $source_path..."
    cp "$source_path" "$DNSTT_CLIENT_BIN"
    chmod +x "$DNSTT_CLIENT_BIN"
    warn "Local dnstt-client binary was not checksum-verified"
    return 0
  fi

  arch=$(detect_arch)
  asset=$(dnstt_client_asset_name "$arch")
  url="https://github.com/${DNSTT_CLIENT_REPO}/releases/download/${DNSTT_CLIENT_VERSION}/${asset}"
  tmp_bin=$(mktemp /tmp/dnstt-client.XXXXXX.bin)
  if curl -fsSL --connect-timeout 20 "$url" -o "$tmp_bin"; then
    install -m 0755 "$tmp_bin" "$DNSTT_CLIENT_BIN"
    rm -f "$tmp_bin"
    log "Installed dnstt-client: ${DNSTT_CLIENT_REPO}@${DNSTT_CLIENT_VERSION}"
    warn "dnstt-client download was not checksum-verified"
    return 0
  fi
  rm -f "$tmp_bin"

  warn "Automatic dnstt-client download failed for ${asset}"
  echo ""
  echo "Failed URL:"
  echo "  $url"
  echo ""
  prompt_read source_path "Provide local dnstt-client binary path (or Ctrl+C to abort): "
  [[ -n "$source_path" ]] || error "No local dnstt-client binary path provided"
  cp "$source_path" "$DNSTT_CLIENT_BIN"
  chmod +x "$DNSTT_CLIENT_BIN"
  warn "Local dnstt-client binary was not checksum-verified"
}

dnstm_backend_address_for_type() {
  local backend_type="$1" app_port="$2"
  case "$backend_type" in
  custom) echo "127.0.0.1:${app_port}" ;;
  socks) echo "127.0.0.1:1080" ;;
  ssh) echo "127.0.0.1:22" ;;
  shadowsocks) echo "managed-by-dnstm" ;;
  *) echo "unknown" ;;
  esac
}

dnstm_validate_transport_or_error() {
  local transport="$1"
  case "$transport" in
  slipstream | dnstt) ;;
  *) error "Invalid dnstm transport: $transport (use slipstream or dnstt)" ;;
  esac
}

dnstm_validate_backend_type_or_error() {
  local backend_type="$1"
  case "$backend_type" in
  custom | socks | ssh | shadowsocks) ;;
  *) error "Invalid dnstm backend type: $backend_type (use custom, socks, ssh, or shadowsocks)" ;;
  esac
}

dnstm_warn_custom_backend_listener() {
  local app_port="$1"
  if ! command -v ss >/dev/null 2>&1; then
    return 0
  fi
  if ss -lntH "sport = :$app_port" 2>/dev/null | grep -q .; then
    return 0
  fi
  warn "DNSTM custom backend is set to 127.0.0.1:${app_port}, but no local TCP listener is detected on that port."
  warn "Tunnel traffic will fail with 'target connect failed / Connection refused' until your app listens on ${app_port}."
  warn "If Xray uses another port (example: 2052), run 'slipstream-tunnel edit' in server mode and set the correct protected app port."
}

dnstm_setup_server_stack() {
  local domain="$1"
  local app_port="$2"
  local transport="$3"
  local backend_type="$4"
  local backend_tag="$5"
  local tunnel_tag="$6"
  local router_mode="$7"
  local ss_password="${8:-}"
  local ss_method="${9:-aes-256-gcm}"

  dnstm_validate_transport_or_error "$transport"
  dnstm_validate_backend_type_or_error "$backend_type"
  validate_domain_or_error "$domain"
  validate_port_or_error "$app_port"
  [[ "$router_mode" == "single" || "$router_mode" == "multi" ]] || error "Invalid dnstm router mode: $router_mode"
  [[ -n "$backend_tag" ]] || error "DNSTM backend tag cannot be empty"
  [[ -n "$tunnel_tag" ]] || error "DNSTM tunnel tag cannot be empty"

  log "Preparing native dnstm stack..."
  run_dnstm install --force --mode "$router_mode"

  # Keep setup idempotent for reruns/migrations.
  run_dnstm tunnel remove -t "$tunnel_tag" --force >/dev/null 2>&1 || true
  run_dnstm backend remove -t "$backend_tag" --force >/dev/null 2>&1 || true

  case "$backend_type" in
  custom)
    run_dnstm backend add --type custom -t "$backend_tag" --address "127.0.0.1:${app_port}"
    ;;
  shadowsocks)
    if [[ -n "$ss_password" ]]; then
      run_dnstm backend add --type shadowsocks -t "$backend_tag" --password "$ss_password" --method "$ss_method"
    else
      run_dnstm backend add --type shadowsocks -t "$backend_tag" --method "$ss_method"
    fi
    ;;
  socks | ssh)
    # Built-in backends created by dnstm install.
    backend_tag="$backend_type"
    ;;
  esac

  run_dnstm tunnel add --transport "$transport" --backend "$backend_tag" --domain "$domain" -t "$tunnel_tag"
  if [[ "$router_mode" == "single" ]]; then
    run_dnstm router switch -t "$tunnel_tag" >/dev/null 2>&1 || true
  fi
  run_dnstm router start >/dev/null 2>&1 || true
  if [[ "$backend_type" == "custom" ]]; then
    dnstm_warn_custom_backend_listener "$app_port"
  fi
}

dnstm_add_netmod_tunnel() {
  local domain="$1"
  local tunnel_tag="$2"
  validate_domain_or_error "$domain"
  [[ -n "$tunnel_tag" ]] || error "DNSTM NetMod tunnel tag cannot be empty"

  # Keep reruns idempotent.
  run_dnstm tunnel remove -t "$tunnel_tag" --force >/dev/null 2>&1 || true
  run_dnstm tunnel add --transport dnstt --backend ssh --domain "$domain" -t "$tunnel_tag"
  run_dnstm router start >/dev/null 2>&1 || true
}

should_auto_fallback_to_plus_for_arm() {
  local arch="$1"
  [[ "$arch" == "arm64" ]] || return 1
  [[ "$SLIPSTREAM_CORE" == "nightowl" ]] || return 1
  [[ "$SLIPSTREAM_REPO" == "nightowlnerd/slipstream-rust" ]] || return 1
  [[ "$SLIPSTREAM_VERSION" == "v0.1.1" ]] || return 1
  [[ "$SLIPSTREAM_ASSET_LAYOUT" == "tarball" ]] || return 1
}

download_slipstream_component() {
  local component="$1" destination="$2" arch="$3" allow_fallback="${4:-true}"
  local previous_core previous_repo previous_version previous_layout
  local asset
  previous_core="$SLIPSTREAM_CORE"
  previous_repo="$SLIPSTREAM_REPO"
  previous_version="$SLIPSTREAM_VERSION"
  previous_layout="$SLIPSTREAM_ASSET_LAYOUT"
  asset=$(slipstream_asset_name "$component" "$arch")

  case "$SLIPSTREAM_ASSET_LAYOUT" in
  tarball)
    local tmp_tar tmp_dir binary_name
    tmp_tar=$(mktemp /tmp/slipstream.XXXXXX.tar.gz)
    tmp_dir=$(mktemp -d /tmp/slipstream.XXXXXX)
    binary_name="slipstream-${component}"
    if download_release_asset_verified "$SLIPSTREAM_REPO" "$SLIPSTREAM_VERSION" "$asset" "$tmp_tar"; then
      tar xzf "$tmp_tar" -C "$tmp_dir" "$binary_name" || {
        rm -f "$tmp_tar"
        rm -rf "$tmp_dir"
        return 1
      }
      install -m 0755 "$tmp_dir/$binary_name" "$destination" || {
        rm -f "$tmp_tar"
        rm -rf "$tmp_dir"
        return 1
      }
      rm -f "$tmp_tar"
      rm -rf "$tmp_dir"
      return 0
    fi
    rm -f "$tmp_tar"
    rm -rf "$tmp_dir"
    ;;
  binary)
    local tmp_bin
    tmp_bin=$(mktemp /tmp/slipstream.XXXXXX.bin)
    if download_release_asset_verified "$SLIPSTREAM_REPO" "$SLIPSTREAM_VERSION" "$asset" "$tmp_bin"; then
      install -m 0755 "$tmp_bin" "$destination" || {
        rm -f "$tmp_bin"
        return 1
      }
      rm -f "$tmp_bin"
      return 0
    fi
    rm -f "$tmp_bin"
    ;;
  *)
    error "Unknown SLIPSTREAM_ASSET_LAYOUT: $SLIPSTREAM_ASSET_LAYOUT"
    ;;
  esac

  if [[ "$allow_fallback" == true ]] && should_auto_fallback_to_plus_for_arm "$arch"; then
    warn "No Linux ARM64 asset found for core '$SLIPSTREAM_CORE' (${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION})."
    warn "Auto-switching to core 'plus' for ARM64 compatibility..."
    set_slipstream_source "plus"
    if download_slipstream_component "$component" "$destination" "$arch" false; then
      log "ARM64 download succeeded with fallback core: plus (${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION})"
      return 0
    fi

    SLIPSTREAM_CORE="$previous_core"
    SLIPSTREAM_REPO="$previous_repo"
    SLIPSTREAM_VERSION="$previous_version"
    SLIPSTREAM_ASSET_LAYOUT="$previous_layout"
  fi

  return 1
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
    if ss -H -lntu 'sport = :53' 2>/dev/null | awk 'NF {found=1} END {exit !found}'; then
      return 0
    fi
    ss -H -lntu 2>/dev/null | awk '$5 ~ /:53$/ {found=1} END {exit !found}'
  elif command -v netstat &>/dev/null; then
    netstat -lntu 2>/dev/null | awk '$4 ~ /:53$/ {found=1} END {exit !found}'
  else
    return 1
  fi
}

port_53_owners() {
  if command -v ss &>/dev/null; then
    {
      ss -H -ltnup 'sport = :53' 2>/dev/null
      ss -H -lnuap 'sport = :53' 2>/dev/null
    } | awk 'NF {print}' | sort -u
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
    while IFS= read -r line; do
      echo "  $line"
    done <<<"$owners"
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
      while IFS= read -r line; do
        echo "  $line"
      done <<<"$owners"
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

ensure_static_resolver_config() {
  local needs_write=false
  if [[ ! -f /etc/resolv.conf || -L /etc/resolv.conf ]]; then
    needs_write=true
  else
    local non_loopback_count
    non_loopback_count=$(awk '/^[[:space:]]*nameserver[[:space:]]+/ {if ($2 !~ /^127\./) c++} END {print c+0}' /etc/resolv.conf 2>/dev/null || echo "0")
    [[ "$non_loopback_count" -gt 0 ]] || needs_write=true
  fi

  if [[ "$needs_write" == true ]]; then
    log "Writing static resolver configuration..."
    rm -f /etc/resolv.conf
    printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' >/etc/resolv.conf
  fi
}

enable_bbr_if_possible() {
  if ! command -v sysctl &>/dev/null; then
    warn "sysctl not found; skipping BBR tuning"
    return 0
  fi

  if command -v modprobe &>/dev/null; then
    modprobe tcp_bbr 2>/dev/null || true
  fi

  local available_cc
  available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
  if [[ "$available_cc" != *"bbr"* ]]; then
    warn "Kernel does not expose BBR congestion control; skipping BBR tuning"
    return 0
  fi

  mkdir -p "$(dirname "$BBR_SYSCTL_FILE")"
  cat >"$BBR_SYSCTL_FILE" <<EOF
# Managed by slipstream-tunnel
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

  if ! sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1; then
    warn "Could not set net.core.default_qdisc=fq"
  fi
  if ! sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1; then
    warn "Could not set net.ipv4.tcp_congestion_control=bbr"
    return 0
  fi

  local current_cc current_qdisc
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
  log "TCP tuning active: congestion_control=${current_cc}, qdisc=${current_qdisc}"
}

set_config_value() {
  local key="$1" value="$2" file="$3"
  if grep -q "^${key}=" "$file" 2>/dev/null; then
    sed_in_place "s|^${key}=.*|${key}=${value}|" "$file"
  else
    echo "${key}=${value}" >>"$file"
  fi
}

config_value_from_file() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || return 1
  awk -F= -v key="$key" '$1==key {print substr($0, index($0, "=") + 1); exit}' "$file"
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

  # Backward compatibility: old configs may not include core fields.
  if ! grep -q '^SLIPSTREAM_CORE=' "$CONFIG_FILE" 2>/dev/null; then
    SLIPSTREAM_CORE="nightowl"
  fi
  set_slipstream_source "${SLIPSTREAM_CORE:-dnstm}"
}

ensure_mode_server_or_error() {
  load_config_or_error
  [[ "${MODE:-}" == "server" ]] || error "This command is available only in server mode"
}

ensure_mode_client_or_error() {
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "This command is available only in client mode"
}

is_true() {
  [[ "${1:-}" == "true" ]]
}

client_ssh_auth_enabled() {
  [[ "${MODE:-}" == "client" ]] && is_true "${SSH_AUTH_ENABLED:-false}"
}

service_state() {
  local unit="$1" state
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  [[ -n "$state" ]] || state="not running"
  echo "$state"
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

decode_base64_or_raw() {
  local raw="$1" cleaned decoded
  cleaned=$(printf "%s" "$raw" | tr -d " \t\r\n")
  decoded=$(printf "%s" "$cleaned" | base64 -d 2>/dev/null || true)
  if [[ -n "$decoded" ]]; then
    printf "%s" "$decoded"
  else
    printf "%s" "$raw"
  fi
}

test_client_ssh_auth_credentials() {
  local username="$1" password="$2" transport_port="$3" local_port="$4" remote_app_port="$5"
  validate_unix_username_or_error "$username"
  validate_port_or_error "$transport_port"
  validate_port_or_error "$local_port"
  validate_port_or_error "$remote_app_port"
  [[ -n "$password" ]] || error "SSH password cannot be empty"

  check_dependencies ssh sshpass
  mkdir -p "$SSH_CLIENT_ENV_DIR"
  chmod 700 "$SSH_CLIENT_ENV_DIR"
  touch "$SSH_CLIENT_ENV_DIR/known_hosts"
  chmod 600 "$SSH_CLIENT_ENV_DIR/known_hosts"

  log "Testing SSH credentials through tunnel transport..."
  local attempt max_attempts=10
  local probe_log probe_pid probe_rc=0 probe_tail=""

  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    probe_log=$(mktemp /tmp/slipstream-ssh-probe.XXXXXX.log)
    SSHPASS="$password" sshpass -e ssh -N \
      -o ExitOnForwardFailure=yes \
      -o ConnectTimeout=10 \
      -o ServerAliveInterval=10 \
      -o ServerAliveCountMax=1 \
      -o TCPKeepAlive=yes \
      -o NumberOfPasswordPrompts=1 \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=accept-new \
      -o UserKnownHostsFile="$SSH_CLIENT_ENV_DIR/known_hosts" \
      -L "127.0.0.1:${local_port}:127.0.0.1:${remote_app_port}" \
      -p "$transport_port" "${username}@127.0.0.1" >"$probe_log" 2>&1 &
    probe_pid=$!

    sleep 4
    if kill -0 "$probe_pid" 2>/dev/null; then
      kill "$probe_pid" 2>/dev/null || true
      wait "$probe_pid" 2>/dev/null || true
      rm -f "$probe_log"
      log "SSH credential test passed"
      return 0
    fi

    probe_rc=0
    wait "$probe_pid" 2>/dev/null || probe_rc=$?
    probe_tail=""
    if [[ -s "$probe_log" ]]; then
      probe_tail=$(tail -n 3 "$probe_log" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g')
    fi
    rm -f "$probe_log"

    if [[ "$attempt" -lt "$max_attempts" ]]; then
      if [[ "$probe_tail" == *"Permission denied"* || "$probe_tail" == *"Authentication failed"* ]]; then
        error "SSH credential test failed: authentication rejected for user '${username}'. Update password on server or use the correct one."
      fi
      if [[ "$probe_tail" == *"administratively prohibited"* || "$probe_tail" == *"open failed"* ]]; then
        error "SSH credential test failed: server denied TCP forward to 127.0.0.1:${remote_app_port}. Check SSH overlay/PermitOpen on server."
      fi
      if [[ "$probe_tail" == *"Connection refused"* || "$probe_tail" == *"Connection closed"* || "$probe_tail" == *"timed out"* ]]; then
        warn "SSH transport/auth path is not ready yet (attempt ${attempt}/${max_attempts}), retrying..."
        sleep 2
        continue
      fi
    fi

    if [[ "$probe_tail" == *"Connection refused"* || "$probe_tail" == *"Connection closed"* || "$probe_tail" == *"timed out"* ]]; then
      warn "SSH credential preflight could not be confirmed after ${max_attempts} attempts (last error: $probe_tail)"
      warn "Hint: this often means the foreign server tunnel target is not SSH. On foreign server, re-run: slipstream-tunnel auth-setup (app port: ${remote_app_port}, SSH backend: 22)."
      return 2
    fi

    if [[ -n "$probe_tail" ]]; then
      error "SSH credential test failed (user/password/transport/app-port). Details: $probe_tail"
    fi
    error "SSH credential test failed (user/password/transport/app-port). Exit code: ${probe_rc}"
  done

  warn "SSH credential preflight could not be confirmed after ${max_attempts} attempts (transport/auth path timeout)"
  warn "Hint: on foreign server verify 'slipstream-server' targets 127.0.0.1:22 when SSH auth overlay is enabled."
  return 2
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
    PubkeyAuthentication no
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
  check_dependencies systemctl getent awk tr sshd

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

  ensure_service_user
  mkdir -p "$SSH_CLIENT_ENV_DIR"
  chown "$SERVICE_USER:$SERVICE_USER" "$SSH_CLIENT_ENV_DIR"
  chmod 700 "$SSH_CLIENT_ENV_DIR"
  cat >"$SSH_CLIENT_ENV_FILE" <<EOF
SSH_TUNNEL_USER=$username
SSH_TUNNEL_PASS_B64=$password_b64
SSH_TRANSPORT_PORT=$transport_port
SSH_LOCAL_PORT=$local_port
SSH_REMOTE_APP_PORT=$remote_app_port
SSH_LOCAL_BIND_ADDR=0.0.0.0
EOF
  chown "$SERVICE_USER:$SERVICE_USER" "$SSH_CLIENT_ENV_FILE"
  chmod 600 "$SSH_CLIENT_ENV_FILE"
  touch "$SSH_CLIENT_ENV_DIR/known_hosts"
  chown "$SERVICE_USER:$SERVICE_USER" "$SSH_CLIENT_ENV_DIR/known_hosts"
  chmod 600 "$SSH_CLIENT_ENV_DIR/known_hosts"
}

write_ssh_client_service() {
  ensure_service_user
  cat >/etc/systemd/system/${SSH_CLIENT_SERVICE}.service <<EOF
[Unit]
Description=Slipstream SSH Auth Overlay Client
After=network.target slipstream-client.service
Requires=slipstream-client.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$SSH_CLIENT_ENV_FILE
ExecStart=/bin/bash -lc 'raw="\$SSH_TUNNEL_PASS_B64"; cleaned="\$(printf "%%s" "\$raw" | tr -d " \t\r\n")"; pass="\$(printf "%%s" "\$cleaned" | base64 -d 2>/dev/null || true)"; [[ -n "\$pass" ]] || pass="\$raw"; SSHPASS="\$pass" exec sshpass -e ssh -N -g -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SSH_CLIENT_ENV_DIR/known_hosts -L \${SSH_LOCAL_BIND_ADDR}:\${SSH_LOCAL_PORT}:127.0.0.1:\${SSH_REMOTE_APP_PORT} -p \${SSH_TRANSPORT_PORT} \${SSH_TUNNEL_USER}@127.0.0.1'
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SSH_CLIENT_ENV_DIR
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

write_instance_ssh_client_env() {
  local instance="$1" username="$2" password_b64="$3" transport_port="$4" local_port="$5" remote_app_port="$6" local_bind_addr="$7"
  validate_instance_name_or_error "$instance"
  validate_unix_username_or_error "$username"
  validate_port_or_error "$transport_port"
  validate_port_or_error "$local_port"
  validate_port_or_error "$remote_app_port"
  validate_local_bind_addr_or_error "$local_bind_addr"
  [[ -n "$password_b64" ]] || error "Missing encoded SSH password for instance '$instance'"

  ensure_service_user
  mkdir -p "$SSH_CLIENT_ENV_DIR"
  chown "$SERVICE_USER:$SERVICE_USER" "$SSH_CLIENT_ENV_DIR"
  chmod 700 "$SSH_CLIENT_ENV_DIR"

  local env_file
  env_file=$(instance_ssh_client_env_file "$instance")
  cat >"$env_file" <<EOF
SSH_TUNNEL_USER=$username
SSH_TUNNEL_PASS_B64=$password_b64
SSH_TRANSPORT_PORT=$transport_port
SSH_LOCAL_PORT=$local_port
SSH_REMOTE_APP_PORT=$remote_app_port
SSH_LOCAL_BIND_ADDR=$local_bind_addr
EOF
  chown "$SERVICE_USER:$SERVICE_USER" "$env_file"
  chmod 600 "$env_file"
  touch "$SSH_CLIENT_ENV_DIR/known_hosts"
  chown "$SERVICE_USER:$SERVICE_USER" "$SSH_CLIENT_ENV_DIR/known_hosts"
  chmod 600 "$SSH_CLIENT_ENV_DIR/known_hosts"
}

write_instance_ssh_client_service() {
  local instance="$1"
  validate_instance_name_or_error "$instance"
  ensure_service_user
  local ssh_service env_file base_service
  ssh_service=$(instance_ssh_client_service "$instance")
  env_file=$(instance_ssh_client_env_file "$instance")
  base_service=$(instance_client_service "$instance")

  cat >"/etc/systemd/system/${ssh_service}.service" <<EOF
[Unit]
Description=Slipstream SSH App Bridge Client (${instance})
After=network.target ${base_service}.service
Requires=${base_service}.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$env_file
ExecStart=/bin/bash -lc 'raw="\$SSH_TUNNEL_PASS_B64"; cleaned="\$(printf "%%s" "\$raw" | tr -d " \t\r\n")"; pass="\$(printf "%%s" "\$cleaned" | base64 -d 2>/dev/null || true)"; [[ -n "\$pass" ]] || pass="\$raw"; SSHPASS="\$pass" exec sshpass -e ssh -N -g -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SSH_CLIENT_ENV_DIR/known_hosts -L \${SSH_LOCAL_BIND_ADDR}:\${SSH_LOCAL_PORT}:127.0.0.1:\${SSH_REMOTE_APP_PORT} -p \${SSH_TRANSPORT_PORT} \${SSH_TUNNEL_USER}@127.0.0.1'
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SSH_CLIENT_ENV_DIR
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

remove_instance_ssh_client_service_if_present() {
  local instance="$1"
  validate_instance_name_or_error "$instance"
  local ssh_service env_file
  ssh_service=$(instance_ssh_client_service "$instance")
  env_file=$(instance_ssh_client_env_file "$instance")
  if [[ -f "/etc/systemd/system/${ssh_service}.service" ]]; then
    systemctl stop "$ssh_service" 2>/dev/null || true
    systemctl disable "$ssh_service" 2>/dev/null || true
    rm -f "/etc/systemd/system/${ssh_service}.service"
  fi
  rm -f "$env_file"
  systemctl reset-failed "$ssh_service" 2>/dev/null || true
}

instance_ssh_bridge_enabled_from_file() {
  local instance="$1"
  local cfg value
  cfg=$(instance_config_file "$instance")
  value=$(config_value_from_file "$cfg" "DNSTT_SSH_BRIDGE_ENABLED" || true)
  [[ "$value" == "true" ]]
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
  # Clear stale failed state so `systemctl status` does not show an old dead unit.
  systemctl reset-failed "${SSH_CLIENT_SERVICE}" 2>/dev/null || true
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

restart_named_client_stack() {
  local service_name="$1"
  systemctl restart "$service_name"
}

start_named_client_stack() {
  local service_name="$1"
  systemctl start "$service_name"
}

stop_named_client_stack() {
  local service_name="$1"
  systemctl stop "$service_name"
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
  local slipstream_core="$SLIPSTREAM_CORE"
  local core_from_flag=false
  local domain="" port="2053" slipstream_path="" manage_resolver=false
  local enable_ssh_auth=false ssh_backend_port="22"
  local dnstm_path=""
  local dnstm_transport="slipstream"
  local dnstm_backend="custom"
  local dnstm_backend_tag="app-main"
  local dnstm_tunnel_tag="main"
  local dnstm_router_mode="single"
  local dnstm_ss_password=""
  local dnstm_ss_method="aes-256-gcm"
  local dnstm_netmod_setup=false
  local dnstm_netmod_domain=""
  local dnstm_netmod_tag="netmod-ssh"

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
    --core)
      require_flag_value "$1" "${2:-}"
      slipstream_core="$2"
      core_from_flag=true
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
    --dnstm-bin)
      require_flag_value "$1" "${2:-}"
      dnstm_path="$2"
      shift 2
      ;;
    --dnstm-transport)
      require_flag_value "$1" "${2:-}"
      dnstm_transport="$2"
      shift 2
      ;;
    --dnstm-backend)
      require_flag_value "$1" "${2:-}"
      dnstm_backend="$2"
      shift 2
      ;;
    --dnstm-backend-tag)
      require_flag_value "$1" "${2:-}"
      dnstm_backend_tag="$2"
      shift 2
      ;;
    --dnstm-tunnel-tag)
      require_flag_value "$1" "${2:-}"
      dnstm_tunnel_tag="$2"
      shift 2
      ;;
    --dnstm-mode)
      require_flag_value "$1" "${2:-}"
      dnstm_router_mode="$2"
      shift 2
      ;;
    --dnstm-ss-password)
      require_flag_value "$1" "${2:-}"
      dnstm_ss_password="$2"
      shift 2
      ;;
    --dnstm-ss-method)
      require_flag_value "$1" "${2:-}"
      dnstm_ss_method="$2"
      shift 2
      ;;
    --dnstm-netmod-domain)
      require_flag_value "$1" "${2:-}"
      dnstm_netmod_domain="$2"
      dnstm_netmod_setup=true
      shift 2
      ;;
    --dnstm-netmod-tag)
      require_flag_value "$1" "${2:-}"
      dnstm_netmod_tag="$2"
      dnstm_netmod_setup=true
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

  if [[ "$core_from_flag" == false && -t 0 ]]; then
    slipstream_core=$(prompt_core_choice "dnstm")
  fi
  set_slipstream_source "$slipstream_core"
  if [[ "$enable_ssh_auth" == true ]] && ! core_supports_ssh_overlay; then
    warn "Core '${SLIPSTREAM_CORE}' manages auth natively. Disabling legacy SSH auth overlay flags."
    enable_ssh_auth=false
    ssh_backend_port=""
  fi
  validate_port_or_error "$port"
  [[ -n "$ssh_backend_port" ]] && validate_port_or_error "$ssh_backend_port"
  [[ -n "$domain" ]] && validate_domain_or_error "$domain"
  if [[ "$SLIPSTREAM_CORE" == "dnstm" ]]; then
    dnstm_validate_transport_or_error "$dnstm_transport"
    dnstm_validate_backend_type_or_error "$dnstm_backend"
    [[ "$dnstm_router_mode" == "single" || "$dnstm_router_mode" == "multi" ]] \
      || error "Invalid dnstm mode: $dnstm_router_mode (use single or multi)"
    if [[ "$dnstm_transport" == "dnstt" && "$dnstm_backend" == "shadowsocks" ]]; then
      error "DNSTT transport does not support shadowsocks backend"
    fi
  fi

  log "=== Slipstream Server Setup ==="
  log "Core source: ${SLIPSTREAM_CORE} (${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION}, layout=${SLIPSTREAM_ASSET_LAYOUT})"
  enable_bbr_if_possible

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
    prompt_read server_ip "Enter server IP: "
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
    prompt_read domain "Enter tunnel domain (e.g., t.example.com): "
    validate_domain_or_error "$domain"
  fi

  # Confirm DNS setup
  prompt_read confirm "DNS configured? (y/n): "
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

  # Upgrade path: existing slipstream-server may already be bound to :53.
  # Stop it before conflict checks so in-place upgrades do not fail.
  if systemctl list-unit-files slipstream-server.service &>/dev/null; then
    if systemctl is-active --quiet slipstream-server; then
      log "Stopping existing slipstream-server to free port 53 for upgrade..."
      systemctl stop slipstream-server 2>/dev/null || true
    fi
  fi

  if port_53_in_use; then
    auto_fix_port_53_conflict || error "Port 53 is still busy. Stop the remaining listener(s) shown above and run again."
  fi

  # Resolver changes are opt-in to avoid breaking host DNS unexpectedly.
  if [[ "$manage_resolver" == true ]]; then
    backup_resolver_if_needed
    ensure_static_resolver_config
  fi

  if [[ "$SLIPSTREAM_CORE" == "dnstm" ]]; then
    if [[ "$enable_ssh_auth" == true ]]; then
      warn "Ignoring --ssh-auth flags: native dnstm backend/auth management is used on core '${SLIPSTREAM_CORE}'."
    fi

    if [[ -t 0 ]]; then
      read -r -p "dnstm router mode [single/multi] [$dnstm_router_mode]: " input
      [[ -n "$input" ]] && dnstm_router_mode="$input"
      read -r -p "Initial tunnel transport [slipstream/dnstt] [$dnstm_transport]: " input
      [[ -n "$input" ]] && dnstm_transport="$input"
      read -r -p "Initial backend type [custom/socks/ssh/shadowsocks] [$dnstm_backend]: " input
      [[ -n "$input" ]] && dnstm_backend="$input"
      dnstm_validate_transport_or_error "$dnstm_transport"
      dnstm_validate_backend_type_or_error "$dnstm_backend"
      [[ "$dnstm_router_mode" == "single" || "$dnstm_router_mode" == "multi" ]] \
        || error "Invalid dnstm mode: $dnstm_router_mode (use single or multi)"
      if [[ "$dnstm_transport" == "dnstt" && "$dnstm_backend" == "shadowsocks" ]]; then
        error "DNSTT transport does not support shadowsocks backend"
      fi
      case "$dnstm_backend" in
      custom)
        read -r -p "Protected app port for custom backend [$port]: " input
        [[ -n "$input" ]] && port="$input"
        validate_port_or_error "$port"
        ;;
      shadowsocks)
        read -r -p "Shadowsocks method [$dnstm_ss_method]: " input
        [[ -n "$input" ]] && dnstm_ss_method="$input"
        read -r -p "Shadowsocks password (Enter to auto-generate): " input
        [[ -n "$input" ]] && dnstm_ss_password="$input"
        ;;
      esac
      read -r -p "Backend tag [$dnstm_backend_tag]: " input
      [[ -n "$input" ]] && dnstm_backend_tag="$input"
      read -r -p "Tunnel tag [$dnstm_tunnel_tag]: " input
      [[ -n "$input" ]] && dnstm_tunnel_tag="$input"
      read -r -p "Add NetMod DNSTT-over-SSH tunnel on extra domain? [y/N]: " input
      if [[ "${input:-n}" == "y" ]]; then
        dnstm_netmod_setup=true
        read -r -p "NetMod extra domain (e.g., nm.example.com): " input
        [[ -n "$input" ]] && dnstm_netmod_domain="$input"
        validate_domain_or_error "$dnstm_netmod_domain"
        [[ "$dnstm_netmod_domain" != "$domain" ]] || error "NetMod domain must differ from main tunnel domain"
        read -r -p "NetMod tunnel tag [$dnstm_netmod_tag]: " input
        [[ -n "$input" ]] && dnstm_netmod_tag="$input"
      fi
    fi

    case "$dnstm_backend" in
    socks) dnstm_backend_tag="socks" ;;
    ssh) dnstm_backend_tag="ssh" ;;
    esac

    ensure_dnstm_binary "$dnstm_path"
    dnstm_setup_server_stack "$domain" "$port" "$dnstm_transport" "$dnstm_backend" "$dnstm_backend_tag" "$dnstm_tunnel_tag" "$dnstm_router_mode" "$dnstm_ss_password" "$dnstm_ss_method"
    if [[ "$dnstm_netmod_setup" == "true" ]]; then
      [[ -n "$dnstm_netmod_domain" ]] || error "NetMod setup requested but no extra domain provided"
      validate_domain_or_error "$dnstm_netmod_domain"
      [[ "$dnstm_netmod_domain" != "$domain" ]] || error "NetMod domain must differ from main tunnel domain"
      dnstm_add_netmod_tunnel "$dnstm_netmod_domain" "$dnstm_netmod_tag"
    fi

    # Legacy service may exist from previous cores.
    systemctl stop slipstream-server 2>/dev/null || true
    systemctl disable slipstream-server 2>/dev/null || true

    mkdir -p "$TUNNEL_DIR"
    cat >"$CONFIG_FILE" <<EOF
DOMAIN=$domain
MODE=server
PORT=$port
MANAGE_RESOLVER=$manage_resolver
SLIPSTREAM_CORE=$SLIPSTREAM_CORE
SLIPSTREAM_REPO=$SLIPSTREAM_REPO
SLIPSTREAM_VERSION=$SLIPSTREAM_VERSION
SLIPSTREAM_ASSET_LAYOUT=$SLIPSTREAM_ASSET_LAYOUT
DNSTM_REPO=$DNSTM_REPO
DNSTM_VERSION=$DNSTM_VERSION
DNSTM_MODE=$dnstm_router_mode
DNSTM_TRANSPORT=$dnstm_transport
DNSTM_BACKEND_TYPE=$dnstm_backend
DNSTM_BACKEND_TAG=$dnstm_backend_tag
DNSTM_TUNNEL_TAG=$dnstm_tunnel_tag
DNSTM_BACKEND_ADDRESS=$(dnstm_backend_address_for_type "$dnstm_backend" "$port")
DNSTM_NETMOD_ENABLED=$dnstm_netmod_setup
DNSTM_NETMOD_DOMAIN=$dnstm_netmod_domain
DNSTM_NETMOD_TAG=$dnstm_netmod_tag
SSH_AUTH_ENABLED=false
SSH_BACKEND_PORT=
EOF

    install_self
    echo ""
    echo -e "${GREEN}=== Server Ready (dnstm native mode) ===${NC}"
    echo ""
    echo "Native manager:"
    echo "  dnstm router status"
    echo "  dnstm tunnel list"
    echo "  dnstm backend list"
    echo ""
    echo "Through this script:"
    echo "  slipstream-tunnel status"
    echo "  slipstream-tunnel dnstm router status"
    if [[ "$dnstm_netmod_setup" == "true" ]]; then
      local netmod_pubkey
      netmod_pubkey=$(run_dnstm tunnel status -t "$dnstm_netmod_tag" 2>/dev/null | awk '/Public Key:/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/,""); print; exit}')
      echo ""
      echo "NetMod DNSTT-over-SSH:"
      echo "  domain: $dnstm_netmod_domain"
      echo "  tag: $dnstm_netmod_tag"
      [[ -n "$netmod_pubkey" ]] && echo "  pubkey: $netmod_pubkey"
      echo "  ssh backend: 127.0.0.1:22"
    fi
    echo "  slipstream-tunnel menu"
    echo "  sst"
    return 0
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

  # Ensure service is stopped before replacing binary/service config.
  systemctl stop slipstream-server 2>/dev/null || true

  if [[ -n "$slipstream_path" ]]; then
    log "Installing slipstream-server from $slipstream_path..."
    cp "$slipstream_path" "$bin_path"
    warn "Local slipstream binary was not checksum-verified"
  else
    log "Downloading slipstream-server..."
    local slipstream_asset
    slipstream_asset=$(slipstream_asset_name "server" "$arch")
    if download_slipstream_component "server" "$bin_path" "$arch"; then
      :
    else
      warn "Automatic download failed for ${slipstream_asset}"
      echo ""
      echo "Failed URL:"
      echo "  https://github.com/${SLIPSTREAM_REPO}/releases/download/${SLIPSTREAM_VERSION}/${slipstream_asset}"
      echo ""
      echo "Provide local slipstream-server binary path (or Ctrl+C to abort):"
      read -e -r -p "Path: " slipstream_path
      [[ -n "$slipstream_path" ]] || error "No local binary path provided"
      cp "$slipstream_path" "$bin_path"
      chmod +x "$bin_path"
      warn "Local slipstream binary was not checksum-verified"
    fi
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
SLIPSTREAM_CORE=$SLIPSTREAM_CORE
SLIPSTREAM_REPO=$SLIPSTREAM_REPO
SLIPSTREAM_VERSION=$SLIPSTREAM_VERSION
SLIPSTREAM_ASSET_LAYOUT=$SLIPSTREAM_ASSET_LAYOUT
SSH_AUTH_ENABLED=$enable_ssh_auth
SSH_BACKEND_PORT=$ssh_backend_port
EOF

  # Install global command early so recovery commands remain available on partial setup failures.
  install_self

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
  echo "  slipstream-tunnel auth-disable"
  echo "  slipstream-tunnel speed-profile [fast|secure|status]"
  echo "  slipstream-tunnel core-switch [dnstm|nightowl|plus]"
  echo "  slipstream-tunnel auth-list"
  echo "  slipstream-tunnel menu"
  echo "  sst"
  echo "  journalctl -u slipstream-server -f"
}

write_client_service_named() {
  local service_name="$1" resolver="$2" domain="$3" port="$4"
  local transport="${5:-slipstream}" slipstream_cert="${6:-}" dnstt_pubkey="${7:-}"
  local dnstt_bind_host="${8:-${DNSTT_BIND_HOST:-127.0.0.1}}"
  local exec_start=""

  validate_transport_or_error "$transport"
  validate_ipv4_or_error "$resolver"
  validate_domain_or_error "$domain"
  validate_port_or_error "$port"

  if [[ "$transport" == "dnstt" ]]; then
    validate_dnstt_pubkey_or_error "$dnstt_pubkey"
    validate_dnstt_bind_host_or_error "$dnstt_bind_host"
    exec_start="$DNSTT_CLIENT_BIN -udp ${resolver}:53 -pubkey ${dnstt_pubkey} ${domain} ${dnstt_bind_host}:${port}"
  else
    exec_start="$SLIPSTREAM_CLIENT_BIN --resolver ${resolver}:53 --domain ${domain} --tcp-listen-port ${port}"
    if [[ -n "$slipstream_cert" ]]; then
      [[ -f "$slipstream_cert" ]] || error "Slipstream cert file not found: $slipstream_cert"
      exec_start="$exec_start --cert $slipstream_cert"
    fi
  fi

  cat >"/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=Slipstream DNS Tunnel Client (${service_name})
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
ExecStart=$exec_start
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ProtectHome=true
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

write_client_service() {
  local resolver="$1" domain="$2" port="$3" transport="${4:-${DNSTM_TRANSPORT:-slipstream}}"
  local slipstream_cert="${5:-${DNSTM_SLIPSTREAM_CERT:-}}"
  local dnstt_pubkey="${6:-${DNSTM_DNSTT_PUBKEY:-}}"
  local dnstt_bind_host="${7:-${DNSTT_BIND_HOST:-127.0.0.1}}"
  write_client_service_named "slipstream-client" "$resolver" "$domain" "$port" "$transport" "$slipstream_cert" "$dnstt_pubkey" "$dnstt_bind_host"
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

default_instance_ssh_bridge_port() {
  local transport_port="$1"
  validate_port_or_error "$transport_port"
  local candidate=$((transport_port + 10000))
  if ((candidate > 65535)); then
    candidate=$((transport_port + 1000))
  fi
  if ((candidate > 65535)); then
    candidate=$((transport_port + 100))
  fi
  ((candidate <= 65535)) || candidate="$transport_port"
  echo "$candidate"
}

find_best_server() {
  local domain="$1" file="$2"
  local transport="${3:-${DNSTM_TRANSPORT:-slipstream}}"
  local dnstt_pubkey="${4:-${DNSTM_DNSTT_PUBKEY:-}}"
  local slipstream_cert="${5:-${DNSTM_SLIPSTREAM_CERT:-}}"
  local dnstt_bind_host="${6:-${DNSTT_BIND_HOST:-127.0.0.1}}"
  local ranked_tmp sorted_tmp
  local server lat
  local best_server="" best_latency=9999
  local attempts=0
  local probe_attempted=0

  validate_transport_or_error "$transport"

  ranked_tmp=$(mktemp /tmp/slipstream-ranked.XXXXXX)
  sorted_tmp=$(mktemp /tmp/slipstream-ranked-sorted.XXXXXX)

  while IFS= read -r server; do
    [[ -z "$server" ]] && continue
    is_valid_ipv4 "$server" || continue
    lat=$(test_dns_latency "$server" "$domain" || echo "9999")
    printf "%s %s\n" "$lat" "$server" >>"$ranked_tmp"
  done <"$file"

  if [[ ! -s "$ranked_tmp" ]]; then
    rm -f "$ranked_tmp" "$sorted_tmp"
    return 1
  fi

  sort -n "$ranked_tmp" >"$sorted_tmp"
  read -r best_latency best_server <"$sorted_tmp"

  # Run real transport-path checks on top fast candidates only.
  while IFS= read -r lat server; do
    [[ -n "$server" ]] || continue
    [[ "$lat" =~ ^[0-9]+$ ]] || continue
    ((lat < 1000)) || continue

    attempts=$((attempts + 1))
    ((attempts <= 4)) || break
    probe_attempted=1

    if probe_tunnel_data_path "$server" "$domain" "$transport" "$dnstt_pubkey" "$slipstream_cert" "$dnstt_bind_host"; then
      rm -f "$ranked_tmp" "$sorted_tmp"
      echo "$server $lat"
      return 0
    fi
  done <"$sorted_tmp"

  rm -f "$ranked_tmp" "$sorted_tmp"
  [[ -n "$best_server" ]] || return 1
  if ((probe_attempted == 1)); then
    echo "$best_server 9999"
    return 0
  fi
  echo "$best_server $best_latency"
}

has_interactive_tty() {
  [[ -t 0 && -t 1 ]]
}

prompt_scan_settings_for_profile() {
  local config_file="$1" fallback_dns_file="$2"
  local scan_source="${SCAN_SOURCE:-generated}"
  local scan_file="${SCAN_DNS_FILE:-}"
  local scan_country="${SCAN_COUNTRY:-ir}"
  local scan_mode="${SCAN_MODE:-fast}"
  local scan_workers="${SCAN_WORKERS:-500}"
  local scan_timeout="${SCAN_TIMEOUT:-2s}"
  local scan_threshold="${SCAN_THRESHOLD:-50}"
  local input=""

  [[ "$scan_source" == "generated" || "$scan_source" == "file" ]] || scan_source="generated"
  [[ -n "$scan_file" ]] || scan_file="$fallback_dns_file"

  if has_interactive_tty; then
    echo ""
    echo "=== DNS Scan Settings ==="
    echo "Press Enter to keep current values."
    echo ""
    while true; do
      prompt_read input "Scan source [generated/file] [$scan_source]: "
      [[ -z "$input" ]] && break
      case "$input" in
      generated | file)
        scan_source="$input"
        break
        ;;
      *)
        warn "Invalid scan source: $input"
        ;;
      esac
    done

    if [[ "$scan_source" == "file" ]]; then
      prompt_read input "DNS file path [$scan_file]: "
      [[ -n "$input" ]] && scan_file="$input"
      [[ -n "$scan_file" ]] || error "DNS file path is required when scan source is 'file'"
    else
      echo "Modes: list | fast | medium | all"
      prompt_read input "Country code [$scan_country]: "
      [[ -n "$input" ]] && scan_country="$input"
      prompt_read input "Scan mode [$scan_mode]: "
      [[ -n "$input" ]] && scan_mode="$input"
    fi

    prompt_read input "Workers [$scan_workers]: "
    [[ -n "$input" ]] && scan_workers="$input"
    prompt_read input "Timeout [$scan_timeout]: "
    [[ -n "$input" ]] && scan_timeout="$input"
    prompt_read input "Benchmark threshold % [$scan_threshold]: "
    [[ -n "$input" ]] && scan_threshold="$input"
  fi

  if [[ "$scan_source" == "file" ]]; then
    validate_dns_file_or_error "$scan_file"
  fi

  set_config_value "SCAN_SOURCE" "$scan_source" "$config_file"
  set_config_value "SCAN_DNS_FILE" "$scan_file" "$config_file"
  set_config_value "SCAN_COUNTRY" "$scan_country" "$config_file"
  set_config_value "SCAN_MODE" "$scan_mode" "$config_file"
  set_config_value "SCAN_WORKERS" "$scan_workers" "$config_file"
  set_config_value "SCAN_TIMEOUT" "$scan_timeout" "$config_file"
  set_config_value "SCAN_THRESHOLD" "$scan_threshold" "$config_file"
}

# ============================================
# CLIENT MODE
# ============================================
cmd_client() {
  need_root
  check_dependencies curl tar systemctl awk sed grep head wc dig
  local slipstream_core="$SLIPSTREAM_CORE"
  local core_from_flag=false
  local domain="" dnscan_path="" slipstream_path="" port="7000" dns_file=""
  local client_transport="slipstream" dnstt_pubkey="" dnstt_client_path="" slipstream_cert="" dnstt_bind_host="127.0.0.1"
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
    --core)
      require_flag_value "$1" "${2:-}"
      slipstream_core="$2"
      core_from_flag=true
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
    --transport)
      require_flag_value "$1" "${2:-}"
      client_transport="$2"
      shift 2
      ;;
    --dnstt-pubkey)
      require_flag_value "$1" "${2:-}"
      dnstt_pubkey="$2"
      shift 2
      ;;
    --dnstt-client)
      require_flag_value "$1" "${2:-}"
      dnstt_client_path="$2"
      shift 2
      ;;
    --slipstream-cert)
      require_flag_value "$1" "${2:-}"
      slipstream_cert="$2"
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

  if [[ "$core_from_flag" == false && -t 0 ]]; then
    slipstream_core=$(prompt_core_choice "dnstm")
  fi
  set_slipstream_source "$slipstream_core"
  if [[ "$ssh_auth_client" == "true" ]] && ! core_supports_ssh_overlay; then
    warn "Core '${SLIPSTREAM_CORE}' manages auth natively. Disabling legacy SSH auth client overlay flags."
    ssh_auth_client=false
    ssh_user=""
    ssh_pass=""
    ssh_remote_port=""
    ssh_transport_port=""
  fi
  validate_transport_or_error "$client_transport"
  if [[ "$client_transport" == "dnstt" && "${SLIPSTREAM_CORE}" != "dnstm" ]]; then
    error "Transport 'dnstt' is supported only with core 'dnstm'"
  fi
  if [[ -t 0 ]]; then
    local input_transport=""
    if [[ "${SLIPSTREAM_CORE}" == "dnstm" ]]; then
      read -r -p "Client transport [slipstream/dnstt] [${client_transport}]: " input_transport
      [[ -n "$input_transport" ]] && client_transport="$input_transport"
      validate_transport_or_error "$client_transport"
    else
      client_transport="slipstream"
    fi
  fi
  if [[ "$client_transport" == "dnstt" ]]; then
    if [[ -z "$dnstt_pubkey" && -t 0 ]]; then
      read -r -p "DNSTT public key (64 hex chars): " dnstt_pubkey
    fi
    validate_dnstt_pubkey_or_error "$dnstt_pubkey"
    if [[ -t 0 ]]; then
      dnstt_bind_host=$(prompt_dnstt_bind_host_or_error "$dnstt_bind_host")
    fi
    validate_dnstt_bind_host_or_error "$dnstt_bind_host"
    slipstream_cert=""
  else
    if [[ -z "$slipstream_cert" && -t 0 ]]; then
      read -r -p "Pinned slipstream cert path (Enter to skip): " slipstream_cert
    fi
    [[ -z "$slipstream_cert" || -f "$slipstream_cert" ]] || error "Slipstream cert file not found: $slipstream_cert"
    dnstt_pubkey=""
    dnstt_bind_host=""
  fi
  [[ -n "$domain" ]] && validate_domain_or_error "$domain"
  [[ -n "$dns_file" ]] && validate_dns_file_or_error "$dns_file"

  log "=== Slipstream Client Setup ==="
  log "Core source: ${SLIPSTREAM_CORE} (${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION}, layout=${SLIPSTREAM_ASSET_LAYOUT})"
  enable_bbr_if_possible

  ensure_service_user
  mkdir -p "$TUNNEL_DIR" "$DNSCAN_DIR"

  local arch os dnscan_arch
  arch=$(detect_arch)
  os=$(detect_os)
  case "$arch" in
  x86_64) dnscan_arch="amd64" ;;
  arm64) dnscan_arch="arm64" ;;
  *) error "Unsupported dnscan architecture mapping: $arch" ;;
  esac

  if [[ "$client_transport" != "dnstt" ]]; then
    # Get dnscan for slipstream verification scans.
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
          read -r -e -p "Path to dnscan tarball: " dnscan_path
          tar xzf "$dnscan_path" -C "$DNSCAN_DIR"
        fi
      fi
      chmod +x "$DNSCAN_DIR/dnscan"
    fi
  fi

  # Get domain
  if [[ -z "$domain" ]]; then
    read -r -p "Enter tunnel domain (e.g., t.example.com): " domain
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

  local scan_source="generated"
  local scan_file=""
  local scan_country="ir"
  local scan_mode="fast"
  local scan_workers="500"
  local scan_timeout="2s"
  local scan_threshold="50"
  local best_server best_latency
  local slipstream_bin="" installed_bin="$SLIPSTREAM_CLIENT_BIN" slipstream_asset=""
  if [[ "$client_transport" == "dnstt" ]]; then
    ensure_dnstt_client_binary "$dnstt_client_path"

    if [[ -n "$dns_file" ]]; then
      scan_source="file"
      scan_file="$dns_file"
    elif [[ -t 0 ]]; then
      read -r -e -p "Custom DNS file for resolver candidates (Enter to auto-build): " input_dns_file
      if [[ -n "$input_dns_file" ]]; then
        scan_source="file"
        scan_file="$input_dns_file"
      fi
    fi

    if [[ "$scan_source" == "file" ]]; then
      validate_dns_file_or_error "$scan_file"
      refresh_resolver_candidates_file "$domain" "$SERVERS_FILE" "$scan_file" "" \
        || error "No reachable DNS resolvers from '$scan_file'"
    else
      refresh_resolver_candidates_file "$domain" "$SERVERS_FILE" "" "" \
        || error "No reachable DNS resolvers found. Re-run with --dns-file"
    fi
  else
    # Get slipstream binary (required for --verify)
    slipstream_bin="$TUNNEL_DIR/slipstream-client"
    slipstream_asset=$(slipstream_asset_name "client" "$arch")

    if [[ -x "$slipstream_bin" ]]; then
      log "Using cached slipstream-client"
    elif [[ -x "$installed_bin" ]]; then
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
      if download_slipstream_component "client" "$slipstream_bin" "$arch"; then
        :
      else
        echo ""
        warn "Cannot download slipstream-client (network blocked?)"
        echo ""
        echo "Transfer this asset from a non-blocked network:"
        echo "  https://github.com/${SLIPSTREAM_REPO}/releases/download/${SLIPSTREAM_VERSION}/${slipstream_asset}"
        echo ""
        read -r -e -p "Path to slipstream-client binary: " slipstream_path
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

    echo ""
    echo -e "${YELLOW}=== DNS Scan Settings ===${NC}"
    echo ""

    if [[ -n "$dns_file" ]]; then
      log "Using custom DNS file: $dns_file"
      scan_source="file"
      scan_file="$dns_file"
      dnscan_args+=(--file "$dns_file")
      read -r -p "Workers [500]: " input_workers
      [[ -n "$input_workers" ]] && scan_workers="$input_workers"
      read -r -p "Timeout [2s]: " input_timeout
      [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"
      read -r -p "Benchmark threshold % [50]: " input_threshold
      [[ -n "$input_threshold" ]] && scan_threshold="$input_threshold"
      dnscan_args+=(--workers "$scan_workers" --timeout "$scan_timeout" --threshold "$scan_threshold")
    else
      read -r -e -p "Custom DNS file (Enter to scan): " input_dns_file
      if [[ -n "$input_dns_file" ]]; then
        validate_dns_file_or_error "$input_dns_file"
        log "Using custom DNS file: $input_dns_file"
        scan_source="file"
        scan_file="$input_dns_file"
        dnscan_args+=(--file "$input_dns_file")
        read -r -p "Workers [500]: " input_workers
        [[ -n "$input_workers" ]] && scan_workers="$input_workers"
        read -r -p "Timeout [2s]: " input_timeout
        [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"
        read -r -p "Benchmark threshold % [50]: " input_threshold
        [[ -n "$input_threshold" ]] && scan_threshold="$input_threshold"
        dnscan_args+=(--workers "$scan_workers" --timeout "$scan_timeout" --threshold "$scan_threshold")
      else
        echo ""
        echo "Modes:"
        echo "  list   - Known working DNS servers (fastest)"
        echo "  fast   - Sample common IPs per subnet (default)"
        echo "  medium - More IPs per subnet"
        echo "  all    - All IPs per subnet (slowest)"
        echo ""
        read -r -p "Country code [ir]: " input_country
        [[ -n "$input_country" ]] && scan_country="$input_country"
        read -r -p "Scan mode [fast]: " input_mode
        [[ -n "$input_mode" ]] && scan_mode="$input_mode"
        read -r -p "Workers [500]: " input_workers
        [[ -n "$input_workers" ]] && scan_workers="$input_workers"
        read -r -p "Timeout [2s]: " input_timeout
        [[ -n "$input_timeout" ]] && scan_timeout="$input_timeout"
        read -r -p "Benchmark threshold % [50]: " input_threshold
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

    if [[ ! -s "$SERVERS_FILE" ]]; then
      error "No DNS servers passed verification. Is your server running correctly?"
    fi
  fi

  local server_count
  server_count=$(wc -l <"$SERVERS_FILE")
  log "Found $server_count resolver candidates"

  read -r best_server best_latency <<<"$(find_best_server "$domain" "$SERVERS_FILE" "$client_transport" "$dnstt_pubkey" "$slipstream_cert" "$dnstt_bind_host")"
  [[ -n "$best_server" ]] || error "Could not choose a working DNS server"
  [[ "$best_latency" =~ ^[0-9]+$ ]] || best_latency=9999
  if [[ "$best_latency" -ge 1000 ]]; then
    error "No resolver passed transport data-path validation for ${domain}. Update resolver candidates and retry."
  fi
  log "Using DNS server: $best_server (${best_latency}ms)"

  local client_transport_port="$port"
  local ssh_pass_b64=""
  if [[ "$ssh_auth_client" == "true" ]]; then
    client_transport_port="$ssh_transport_port"
    ssh_pass_b64=$(printf '%s' "$ssh_pass" | base64 | tr -d '\n')
  fi

  # Stop existing service
  systemctl stop slipstream-client 2>/dev/null || true
  remove_ssh_client_service_if_present

  # Install binary if not already in place.
  if [[ "$client_transport" == "slipstream" && -n "$slipstream_bin" && "$slipstream_bin" != "$SLIPSTREAM_CLIENT_BIN" ]]; then
    log "Installing slipstream-client..."
    mv "$slipstream_bin" "$SLIPSTREAM_CLIENT_BIN"
    chmod +x "$SLIPSTREAM_CLIENT_BIN"
  fi

  # Create systemd service
  log "Creating systemd service..."
  write_client_service "$best_server" "$domain" "$client_transport_port" "$client_transport" "$slipstream_cert" "$dnstt_pubkey" "$dnstt_bind_host"

  systemctl daemon-reload
  systemctl enable slipstream-client
  systemctl restart slipstream-client

  if [[ "$ssh_auth_client" == "true" ]]; then
    local preflight_rc=0
    if test_client_ssh_auth_credentials "$ssh_user" "$ssh_pass" "$ssh_transport_port" "$port" "$ssh_remote_port"; then
      preflight_rc=0
    else
      preflight_rc=$?
    fi
    if [[ "$preflight_rc" -ne 0 ]]; then
      if [[ "$preflight_rc" -eq 2 ]]; then
        warn "Proceeding despite inconclusive SSH preflight. Verify with: slipstream-tunnel status && slipstream-tunnel logs -f"
      else
        error "SSH credential test failed. Aborting client setup."
      fi
    fi
    write_ssh_client_env "$ssh_user" "$ssh_pass_b64" "$ssh_transport_port" "$port" "$ssh_remote_port"
    write_ssh_client_service
    systemctl daemon-reload
    systemctl enable "${SSH_CLIENT_SERVICE}"
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
SLIPSTREAM_CORE=$SLIPSTREAM_CORE
SLIPSTREAM_REPO=$SLIPSTREAM_REPO
SLIPSTREAM_VERSION=$SLIPSTREAM_VERSION
SLIPSTREAM_ASSET_LAYOUT=$SLIPSTREAM_ASSET_LAYOUT
SCAN_SOURCE=$scan_source
SCAN_DNS_FILE=$scan_file
SCAN_COUNTRY=$scan_country
SCAN_MODE=$scan_mode
SCAN_WORKERS=$scan_workers
SCAN_TIMEOUT=$scan_timeout
SCAN_THRESHOLD=$scan_threshold
DNSTM_TRANSPORT=$client_transport
DNSTM_DNSTT_PUBKEY=$dnstt_pubkey
DNSTT_BIND_HOST=$dnstt_bind_host
DNSTM_SLIPSTREAM_CERT=$slipstream_cert
SSH_AUTH_ENABLED=$ssh_auth_client
SSH_AUTH_USER=$ssh_user
SSH_PASS_B64=$ssh_pass_b64
SSH_REMOTE_APP_PORT=$ssh_remote_port
SSH_TRANSPORT_PORT=$ssh_transport_port
EOF

  # Setup recovery timers
  setup_health_timer
  setup_watchdog_timer

  # Install global command
  install_self

  echo ""
  echo -e "${GREEN}=== Client Ready ===${NC}"
  echo ""
  echo "Tunnel: 127.0.0.1:$port"
  echo "Transport: $client_transport"
  if [[ "$client_transport" == "dnstt" ]]; then
    echo "DNSTT pubkey: ${dnstt_pubkey:0:12}... (configured)"
    echo "DNSTT bind host: ${dnstt_bind_host:-127.0.0.1}"
  elif [[ -n "$slipstream_cert" ]]; then
    echo "Pinned cert: $slipstream_cert"
  fi
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
  echo "  slipstream-tunnel watchdog"
  echo "  slipstream-tunnel rescan"
  echo "  slipstream-tunnel dashboard"
  echo "  slipstream-tunnel servers"
  echo "  slipstream-tunnel auth-client-disable"
  echo "  slipstream-tunnel auth-client-enable"
  echo "  slipstream-tunnel speed-profile [fast|secure|status]"
  echo "  slipstream-tunnel core-switch [dnstm|nightowl|plus]"
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
client_recover_reason() {
  local lookback="${1:-6 minutes ago}"
  local listen_port="${2:-${PORT:-7000}}"
  local service_name="${3:-slipstream-client}"
  local bridge_service_name="${4:-}"
  local bridge_listen_port="${5:-}"
  local expected_resolver="${6:-${CURRENT_SERVER:-}}"
  local recent_log="" closed_pipe_hits=0

  if ! systemctl is-active --quiet "$service_name"; then
    echo "$service_name service not active"
    return 0
  fi
  if ! ss -lntH "sport = :$listen_port" 2>/dev/null | grep -q .; then
    echo "client listen port $listen_port is not open"
    return 0
  fi
  if [[ -n "$bridge_service_name" ]]; then
    if ! systemctl is-active --quiet "$bridge_service_name"; then
      echo "$bridge_service_name service not active"
      return 0
    fi
  fi
  if [[ -n "$bridge_listen_port" ]]; then
    if ! ss -lntH "sport = :$bridge_listen_port" 2>/dev/null | grep -q .; then
      echo "bridge listen port $bridge_listen_port is not open"
      return 0
    fi
  fi
  if [[ -n "$expected_resolver" ]]; then
    if ! systemctl cat "$service_name" 2>/dev/null | awk '/^ExecStart=/{print; exit}' | grep -Eq -- "(-udp|--resolver) ${expected_resolver}:53([[:space:]]|$)"; then
      echo "service resolver does not match CURRENT_SERVER ($expected_resolver)"
      return 0
    fi
  fi

  recent_log=$(journalctl -u "$service_name" --since "$lookback" --no-pager -l 2>/dev/null || true)
  if printf '%s\n' "$recent_log" | grep -Eq 'WATCHDOG: main loop stalled|ERROR connection flow blocked'; then
    echo "recent watchdog/flow-blocked runtime errors detected"
    return 0
  fi
  closed_pipe_hits=$(printf '%s\n' "$recent_log" | grep -c 'io: read/write on closed pipe' || true)
  if [[ "$closed_pipe_hits" =~ ^[0-9]+$ ]] && ((closed_pipe_hits >= 3)); then
    echo "recent DNSTT stream-open failures detected (closed pipe)"
    return 0
  fi
  return 1
}

cmd_watchdog() {
  need_root
  check_dependencies systemctl ss journalctl grep date mkdir

  if [[ ! -f "$CONFIG_FILE" ]]; then
    exit 0
  fi
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || exit 0

  local reason=""
  if ! reason=$(client_recover_reason "90 seconds ago" "${PORT:-7000}"); then
    exit 0
  fi

  local now last=0
  now=$(date +%s)
  mkdir -p "$WATCHDOG_STATE_DIR"
  if [[ -f "$WATCHDOG_LAST_RESTART_FILE" ]]; then
    last=$(cat "$WATCHDOG_LAST_RESTART_FILE" 2>/dev/null || echo 0)
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
  fi
  if ((now - last < 45)); then
    exit 0
  fi
  echo "$now" >"$WATCHDOG_LAST_RESTART_FILE"

  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] Watchdog restart triggered: $reason" >>"$HEALTH_LOG"
  if [[ -n "${CURRENT_SERVER:-}" && -n "${DOMAIN:-}" ]]; then
    local transport_port
    transport_port=$(client_transport_port_from_config)
    write_client_service "$CURRENT_SERVER" "$DOMAIN" "$transport_port" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
    systemctl daemon-reload
  fi
  if restart_client_stack; then
    echo "[$timestamp] Watchdog restart completed" >>"$HEALTH_LOG"
  else
    echo "[$timestamp] ERROR: watchdog restart failed" >>"$HEALTH_LOG"
  fi
}

cmd_health() {
  need_root
  check_dependencies dig systemctl ss journalctl grep wc tail date
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

  # Fast self-heal path for common client failure states.
  local recover_reason=""
  if recover_reason=$(client_recover_reason "6 minutes ago" "$PORT"); then
    echo "Self-heal: $recover_reason"
    echo "[$timestamp] Self-heal triggered: $recover_reason" >>"$HEALTH_LOG"
    if [[ -n "${CURRENT_SERVER:-}" && -n "${DOMAIN:-}" ]]; then
      local transport_port
      transport_port=$(client_transport_port_from_config)
      write_client_service "$CURRENT_SERVER" "$DOMAIN" "$transport_port" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
      systemctl daemon-reload
    fi
    if restart_client_stack; then
      echo "[$timestamp] Self-heal restart completed" >>"$HEALTH_LOG"
      sleep 2
    else
      echo "[$timestamp] ERROR: self-heal restart failed" >>"$HEALTH_LOG"
    fi
  fi

  # Test current server latency
  local current_server="${CURRENT_SERVER:-}"
  local current_domain="${DOMAIN:-}"
  [[ -n "$current_server" ]] || error "No CURRENT_SERVER set in config"
  [[ -n "$current_domain" ]] || error "No DOMAIN set in config"
  echo "Testing DNS server: $current_server"
  local latency
  latency=$(test_dns_latency "$current_server" "$current_domain" || echo "9999")
  echo "Latency: ${latency}ms"

  if [[ "$latency" -gt 1000 ]]; then
    echo "Server slow, checking alternatives..."
    echo "[$timestamp] Current server $current_server slow (${latency}ms), checking alternatives..." >>"$HEALTH_LOG"

    # Find better server
    local best_server best_latency
    read -r best_server best_latency <<<"$(find_best_server "$current_domain" "$SERVERS_FILE")"

    if [[ -n "$best_server" && "$best_server" != "$current_server" && "$best_latency" -lt 1000 ]]; then
      echo "Switching to $best_server (${best_latency}ms)"
      echo "[$timestamp] Switching to $best_server (${best_latency}ms)" >>"$HEALTH_LOG"

      # Update config
      set_config_value "CURRENT_SERVER" "$best_server" "$CONFIG_FILE"

      # Restart client with new server
      local transport_port
      transport_port=$(client_transport_port_from_config)
      write_client_service "$best_server" "$current_domain" "$transport_port"
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
    echo "[$timestamp] Server $current_server OK (${latency}ms)" >>"$HEALTH_LOG"
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

  prompt_scan_settings_for_profile "$CONFIG_FILE" "$SERVERS_FILE"
  load_config_or_error

  local transport="${DNSTM_TRANSPORT:-slipstream}"
  validate_transport_or_error "$transport"
  local scan_source="${SCAN_SOURCE:-generated}"
  local scan_file="${SCAN_DNS_FILE:-$SERVERS_FILE}"
  local scan_workers="${SCAN_WORKERS:-500}"
  local scan_timeout="${SCAN_TIMEOUT:-2s}"
  local scan_threshold="${SCAN_THRESHOLD:-50}"

  if [[ "$transport" == "dnstt" ]]; then
    if [[ "$scan_source" == "file" ]]; then
      validate_dns_file_or_error "$scan_file"
      refresh_resolver_candidates_file "$DOMAIN" "$SERVERS_FILE" "$scan_file" "${CURRENT_SERVER:-}" \
        || error "Manual rescan found no reachable DNS resolvers"
    else
      refresh_resolver_candidates_file "$DOMAIN" "$SERVERS_FILE" "" "${CURRENT_SERVER:-}" \
        || error "Manual rescan found no reachable DNS resolvers"
    fi
  else
    [[ -x "$DNSCAN_DIR/dnscan" ]] || error "dnscan binary not found: $DNSCAN_DIR/dnscan"
    [[ -x "$SLIPSTREAM_CLIENT_BIN" ]] || error "slipstream-client not installed"
    local dnscan_args=(
      --domain "$DOMAIN"
      --data-dir "$DNSCAN_DIR/data"
      --output "$SERVERS_FILE"
      --verify "$SLIPSTREAM_CLIENT_BIN"
    )

    if [[ "$scan_source" == "file" ]]; then
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
  fi

  local best_server best_latency
  read -r best_server best_latency <<<"$(find_best_server "$DOMAIN" "$SERVERS_FILE")"
  [[ -n "$best_server" ]] || error "No usable DNS server found after manual rescan"
  [[ "$best_latency" =~ ^[0-9]+$ ]] || best_latency=9999
  [[ "$best_latency" -lt 1000 ]] || error "No resolver passed transport data-path validation after manual rescan"

  set_config_value "CURRENT_SERVER" "$best_server" "$CONFIG_FILE"
  local transport_port
  transport_port=$(client_transport_port_from_config)
  write_client_service "$best_server" "$DOMAIN" "$transport_port" "$transport"
  systemctl daemon-reload
  restart_client_stack

  log "Switched to best DNS server: $best_server (${best_latency}ms)"
  cmd_servers
  cmd_dashboard
}

cmd_dashboard() {
  check_dependencies systemctl date
  ensure_mode_client_or_error

  local now
  now=$(date '+%Y-%m-%d %H:%M:%S')
  echo "=== Client Dashboard ==="
  echo "Time: $now"
  echo ""
  printf "%-12s %-8s %-10s %-10s %-10s %-6s %-11s %-15s %-8s %s\n" \
    "Name" "Type" "Service" "Health" "Watchdog" "Port" "Transport" "Resolver" "DNSms" "Domain"

  local target cfg type service health_timer watchdog_timer domain port resolver transport state health_state watchdog_state latency
  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    cfg=$(tunnel_config_file_for_target "$target")
    [[ -f "$cfg" ]] || continue
    service=$(tunnel_service_name_for_target "$target")
    if [[ "$target" == "default" ]]; then
      type="main"
      health_timer="tunnel-health.timer"
      watchdog_timer="tunnel-watchdog.timer"
    else
      type="extra"
      health_timer=$(instance_health_timer "$target")
      watchdog_timer=$(instance_watchdog_timer "$target")
    fi

    state=$(service_state "$service")
    health_state=$(service_state "$health_timer")
    watchdog_state=$(service_state "$watchdog_timer")
    domain=$(config_value_from_file "$cfg" "DOMAIN" || echo "-")
    port=$(config_value_from_file "$cfg" "PORT" || echo "-")
    transport=$(config_value_from_file "$cfg" "DNSTM_TRANSPORT" || true)
    [[ -n "$transport" ]] || transport="slipstream"
    resolver=$(config_value_from_file "$cfg" "CURRENT_SERVER" || true)
    [[ -n "$resolver" ]] || resolver="-"
    latency="-"
    if [[ "$resolver" != "-" && -n "$domain" ]] && command -v dig &>/dev/null; then
      latency=$(test_dns_latency "$resolver" "$domain" || echo "9999")
    fi

    printf "%-12s %-8s %-10s %-10s %-10s %-6s %-11s %-15s %-8s %s\n" \
      "$target" "$type" "$state" "$health_state" "$watchdog_state" "$port" "$transport" "$resolver" "$latency" "$domain"
  done < <(collect_client_tunnel_targets)

  if [[ -f "$HEALTH_LOG" ]]; then
    echo ""
    echo "Main tunnel recent health events:"
    tail -5 "$HEALTH_LOG" | sed 's/^/  /'
  fi

  if [[ -d "$INSTANCES_DIR" ]]; then
    local hcfg instance hlog
    for hcfg in "$INSTANCES_DIR"/*/config; do
      [[ -f "$hcfg" ]] || continue
      instance=$(basename "$(dirname "$hcfg")")
      hlog=$(instance_health_log "$instance")
      if [[ -f "$hlog" ]]; then
        echo ""
        echo "Instance '$instance' recent health events:"
        tail -3 "$hlog" | sed 's/^/  /'
      fi
    done
  fi
}

ensure_instance_client_binary() {
  local transport="${1:-slipstream}" dnstt_path="${2:-}"
  validate_transport_or_error "$transport"
  if [[ "$transport" == "dnstt" ]]; then
    ensure_dnstt_client_binary "$dnstt_path"
  else
    ensure_slipstream_client_binary
  fi
}

write_instance_client_service() {
  local instance="$1" resolver="$2" domain="$3" port="$4" transport="${5:-${DNSTM_TRANSPORT:-slipstream}}"
  local slipstream_cert="${6:-${DNSTM_SLIPSTREAM_CERT:-}}"
  local dnstt_pubkey="${7:-${DNSTM_DNSTT_PUBKEY:-}}"
  local dnstt_bind_host="${8:-${DNSTT_BIND_HOST:-127.0.0.1}}"
  local service_name
  service_name=$(instance_client_service "$instance")
  write_client_service_named "$service_name" "$resolver" "$domain" "$port" "$transport" "$slipstream_cert" "$dnstt_pubkey" "$dnstt_bind_host"
}

setup_instance_timers() {
  local instance="$1"
  local health_service health_timer watchdog_service watchdog_timer
  health_service=$(instance_health_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_service=$(instance_watchdog_service "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  setup_health_timer_named "$health_service" "$health_timer" "$TUNNEL_CMD_BIN instance-health $instance"
  setup_watchdog_timer_named "$watchdog_service" "$watchdog_timer" "$TUNNEL_CMD_BIN instance-watchdog $instance"
}

start_instance_stack() {
  local instance="$1"
  local service_name health_timer watchdog_timer ssh_service
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  systemctl enable "$service_name"
  start_named_client_stack "$service_name"
  if instance_ssh_bridge_enabled_from_file "$instance"; then
    ssh_service=$(instance_ssh_client_service "$instance")
    if systemctl cat "${ssh_service}.service" >/dev/null 2>&1; then
      systemctl enable "$ssh_service" >/dev/null 2>&1 || true
      systemctl start "$ssh_service" || true
    fi
  fi
  systemctl start "$health_timer" || true
  systemctl start "$watchdog_timer" || true
}

stop_instance_stack() {
  local instance="$1"
  local service_name health_timer watchdog_timer ssh_service
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  systemctl stop "$watchdog_timer" 2>/dev/null || true
  systemctl stop "$health_timer" 2>/dev/null || true
  ssh_service=$(instance_ssh_client_service "$instance")
  systemctl stop "$ssh_service" 2>/dev/null || true
  stop_named_client_stack "$service_name" 2>/dev/null || true
}

restart_instance_stack() {
  local instance="$1"
  local service_name health_timer watchdog_timer ssh_service
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  restart_named_client_stack "$service_name"
  if instance_ssh_bridge_enabled_from_file "$instance"; then
    ssh_service=$(instance_ssh_client_service "$instance")
    if systemctl cat "${ssh_service}.service" >/dev/null 2>&1; then
      systemctl restart "$ssh_service" || true
    fi
  fi
  systemctl start "$health_timer" || true
  systemctl start "$watchdog_timer" || true
}

cmd_instance_add() {
  need_root
  check_dependencies systemctl ss
  install_self
  enable_bbr_if_possible
  load_config_or_error
  [[ "${MODE:-}" == "client" ]] || error "Instance add is available only in client mode"

  local instance="${1:-}" domain="" port="7001" resolver="" input
  local transport="slipstream" dnstt_pubkey="" slipstream_cert="" dnstt_client_path="" dnstt_bind_host="127.0.0.1"
  local dnstt_ssh_bridge_enabled="false" dnstt_ssh_user="" dnstt_ssh_pass="" dnstt_ssh_pass_b64=""
  local dnstt_ssh_remote_app_port="2053" dnstt_ssh_local_app_port="" dnstt_ssh_local_bind_addr="0.0.0.0"
  if [[ -z "$instance" ]]; then
    read -r -p "Instance name (e.g., dubai): " instance
  fi
  validate_instance_name_or_error "$instance"
  [[ "$instance" != "default" ]] || error "Instance name 'default' is reserved for the main client profile"

  local cfg instance_path servers_file health_log service_name
  instance_path=$(instance_dir "$instance")
  cfg=$(instance_config_file "$instance")
  servers_file=$(instance_servers_file "$instance")
  health_log=$(instance_health_log "$instance")
  service_name=$(instance_client_service "$instance")
  [[ ! -f "$cfg" ]] || error "Instance already exists: $instance"

  ensure_service_user

  echo "=== Add Client Instance: $instance ==="
  read -r -p "Domain (e.g., f.example.com): " domain
  validate_domain_or_error "$domain"
  if [[ "${SLIPSTREAM_CORE:-dnstm}" == "dnstm" ]]; then
    read -r -p "Transport [slipstream/dnstt] [slipstream]: " input
    [[ -n "$input" ]] && transport="$input"
  fi
  validate_transport_or_error "$transport"
  if [[ "$transport" == "dnstt" ]]; then
    read -r -p "DNSTT public key (64 hex chars): " dnstt_pubkey
    validate_dnstt_pubkey_or_error "$dnstt_pubkey"
    read -r -p "Local dnstt-client binary path (Enter to auto-download): " dnstt_client_path
    dnstt_bind_host=$(prompt_dnstt_bind_host_or_error "$dnstt_bind_host")
  else
    read -r -p "Pinned slipstream cert path (Enter to skip): " slipstream_cert
    [[ -z "$slipstream_cert" || -f "$slipstream_cert" ]] || error "Slipstream cert file not found: $slipstream_cert"
  fi
  ensure_instance_client_binary "$transport" "$dnstt_client_path"

  read -r -p "Local listen port [7001]: " input
  [[ -n "$input" ]] && port="$input"
  validate_port_or_error "$port"
  if port_in_use "$port"; then
    error "Port $port is already in use on this host"
  fi
  if [[ "$transport" == "dnstt" ]]; then
    read -r -p "Enable SSH app bridge over DNSTT for VLESS links? [y/N]: " input
    if [[ "${input:-n}" == "y" ]]; then
      dnstt_ssh_bridge_enabled="true"
      check_dependencies ssh sshpass base64
      read -r -p "SSH username: " dnstt_ssh_user
      validate_unix_username_or_error "$dnstt_ssh_user"
      dnstt_ssh_pass=$(prompt_password_twice "SSH password for ${dnstt_ssh_user}")
      read -r -p "Remote protected app port [2053]: " input
      [[ -n "$input" ]] && dnstt_ssh_remote_app_port="$input"
      validate_port_or_error "$dnstt_ssh_remote_app_port"
      dnstt_ssh_local_app_port=$(default_instance_ssh_bridge_port "$port")
      read -r -p "Local VLESS app port [${dnstt_ssh_local_app_port}]: " input
      [[ -n "$input" ]] && dnstt_ssh_local_app_port="$input"
      validate_port_or_error "$dnstt_ssh_local_app_port"
      [[ "$dnstt_ssh_local_app_port" != "$port" ]] || error "Local VLESS app port must differ from DNSTT transport port"
      if port_in_use "$dnstt_ssh_local_app_port"; then
        error "Local VLESS app port $dnstt_ssh_local_app_port is already in use on this host"
      fi
      dnstt_ssh_local_bind_addr=$(prompt_local_bind_addr_or_error "$dnstt_ssh_local_bind_addr")
      dnstt_ssh_pass_b64=$(printf '%s' "$dnstt_ssh_pass" | base64 | tr -d '\n')
    fi
  fi
  prompt_instance_resolver_or_error resolver "$domain" "$transport" "$dnstt_pubkey" "$slipstream_cert" "$dnstt_bind_host"

  mkdir -p "$instance_path"
  printf '%s\n' "$resolver" >"$servers_file"
  refresh_resolver_candidates_file "$domain" "$servers_file" "" "$resolver" || true
  : >"$health_log"
  cat >"$cfg" <<EOF
INSTANCE_NAME=$instance
MODE=client
DOMAIN=$domain
CURRENT_SERVER=$resolver
PORT=$port
DNSTM_TRANSPORT=$transport
DNSTM_DNSTT_PUBKEY=$dnstt_pubkey
DNSTT_BIND_HOST=$dnstt_bind_host
DNSTT_SSH_BRIDGE_ENABLED=$dnstt_ssh_bridge_enabled
DNSTT_SSH_USER=$dnstt_ssh_user
DNSTT_SSH_PASS_B64=$dnstt_ssh_pass_b64
DNSTT_SSH_REMOTE_APP_PORT=$dnstt_ssh_remote_app_port
DNSTT_SSH_LOCAL_APP_PORT=$dnstt_ssh_local_app_port
DNSTT_SSH_LOCAL_BIND_ADDR=$dnstt_ssh_local_bind_addr
DNSTM_SLIPSTREAM_CERT=$slipstream_cert
SLIPSTREAM_CORE=$SLIPSTREAM_CORE
SLIPSTREAM_REPO=$SLIPSTREAM_REPO
SLIPSTREAM_VERSION=$SLIPSTREAM_VERSION
SLIPSTREAM_ASSET_LAYOUT=$SLIPSTREAM_ASSET_LAYOUT
SCAN_SOURCE=file
SCAN_DNS_FILE=$servers_file
SCAN_COUNTRY=ir
SCAN_MODE=fast
SCAN_WORKERS=500
SCAN_TIMEOUT=2s
SCAN_THRESHOLD=50
SSH_AUTH_ENABLED=false
SSH_AUTH_USER=
SSH_PASS_B64=
SSH_REMOTE_APP_PORT=
SSH_TRANSPORT_PORT=
EOF
  warn "Instance '$instance' uses transport '$transport' (SSH auth overlay disabled)."
  if [[ "$dnstt_ssh_bridge_enabled" == "true" ]]; then
    log "DNSTT SSH app bridge enabled: ${dnstt_ssh_local_bind_addr}:${dnstt_ssh_local_app_port} -> 127.0.0.1:${dnstt_ssh_remote_app_port} (user: ${dnstt_ssh_user})"
  fi

  write_instance_client_service "$instance" "$resolver" "$domain" "$port" "$transport" "$slipstream_cert" "$dnstt_pubkey" "$dnstt_bind_host"
  if [[ "$dnstt_ssh_bridge_enabled" == "true" ]]; then
    write_instance_ssh_client_env "$instance" "$dnstt_ssh_user" "$dnstt_ssh_pass_b64" "$port" "$dnstt_ssh_local_app_port" "$dnstt_ssh_remote_app_port" "$dnstt_ssh_local_bind_addr"
    write_instance_ssh_client_service "$instance"
  else
    remove_instance_ssh_client_service_if_present "$instance"
  fi
  setup_instance_timers "$instance"
  systemctl daemon-reload
  start_instance_stack "$instance"

  log "Client instance '$instance' is ready on port $port"
  cmd_instance_status "$instance"
}

cmd_instance_list() {
  check_dependencies systemctl
  if [[ ! -d "$INSTANCES_DIR" ]]; then
    echo "No extra client instances configured."
    return 0
  fi

  local any=false
  local cfg instance status port resolver transport app_port
  echo "=== Client Instances ==="
  for cfg in "$INSTANCES_DIR"/*/config; do
    [[ -f "$cfg" ]] || continue
    any=true
    instance=$(basename "$(dirname "$cfg")")
    # shellcheck disable=SC1090
    source "$cfg"
    status=$(service_state "$(instance_client_service "$instance")")
    port="${PORT:-unknown}"
    resolver="${CURRENT_SERVER:-unknown}"
    transport="${DNSTM_TRANSPORT:-slipstream}"
    app_port="${DNSTT_SSH_LOCAL_APP_PORT:-}"
    if [[ "${DNSTT_SSH_BRIDGE_ENABLED:-false}" == "true" && -n "$app_port" ]]; then
      printf "  %-16s service=%-10s port=%-6s app=%-6s resolver=%-15s transport=%s\n" "$instance" "$status" "$port" "$app_port" "$resolver" "$transport"
    else
      printf "  %-16s service=%-10s port=%-6s resolver=%-15s transport=%s\n" "$instance" "$status" "$port" "$resolver" "$transport"
    fi
  done
  if [[ "$any" == false ]]; then
    echo "No extra client instances configured."
  fi
}

cmd_instance_status() {
  check_dependencies systemctl
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-status <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"

  local service_name health_timer watchdog_timer health_log
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  health_log=$(instance_health_log "$instance")

  echo "=== Client Instance Status: $instance ==="
  echo "Domain: ${DOMAIN:-unknown}"
  echo "Port: ${PORT:-unknown}"
  echo "Current DNS: ${CURRENT_SERVER:-unknown}"
  echo "Transport: ${DNSTM_TRANSPORT:-slipstream}"
  if [[ "${DNSTM_TRANSPORT:-slipstream}" == "dnstt" ]]; then
    [[ -n "${DNSTM_DNSTT_PUBKEY:-}" ]] && echo "DNSTT pubkey: ${DNSTM_DNSTT_PUBKEY:0:12}..."
    echo "DNSTT bind host: ${DNSTT_BIND_HOST:-127.0.0.1}"
  elif [[ -n "${DNSTM_SLIPSTREAM_CERT:-}" ]]; then
    echo "Pinned cert: ${DNSTM_SLIPSTREAM_CERT}"
  fi
  echo "Core: ${SLIPSTREAM_CORE:-dnstm}"
  echo "Service: $(service_state "$service_name")"
  echo "Health timer: $(service_state "$health_timer")"
  echo "Runtime watchdog: $(service_state "$watchdog_timer")"
  if [[ "${DNSTT_SSH_BRIDGE_ENABLED:-false}" == "true" ]]; then
    local ssh_service
    ssh_service=$(instance_ssh_client_service "$instance")
    echo "SSH app bridge: enabled"
    echo "  Bridge service: $(service_state "$ssh_service")"
    echo "  Local app endpoint: ${DNSTT_SSH_LOCAL_BIND_ADDR:-0.0.0.0}:${DNSTT_SSH_LOCAL_APP_PORT:-unknown}"
    echo "  Remote app via SSH: 127.0.0.1:${DNSTT_SSH_REMOTE_APP_PORT:-2053}"
    [[ -n "${DNSTT_SSH_USER:-}" ]] && echo "  SSH user: ${DNSTT_SSH_USER}"
  fi
  if [[ -f "$health_log" ]]; then
    echo ""
    echo "Recent health events:"
    tail -5 "$health_log" | sed 's/^/  /'
  fi
}

cmd_instance_start() {
  need_root
  check_dependencies systemctl
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-start <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"
  setup_instance_timers "$instance"
  systemctl daemon-reload
  start_instance_stack "$instance"
  log "Started instance: $instance"
}

cmd_instance_stop() {
  need_root
  check_dependencies systemctl
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-stop <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"
  stop_instance_stack "$instance"
  log "Stopped instance: $instance"
}

cmd_instance_restart() {
  need_root
  check_dependencies systemctl
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-restart <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"
  setup_instance_timers "$instance"
  systemctl daemon-reload
  restart_instance_stack "$instance"
  log "Restarted instance: $instance"
}

cmd_instance_logs() {
  check_dependencies journalctl
  local instance="${1:-}" follow="${2:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-logs <name> [-f]"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"
  local service_name
  service_name=$(instance_client_service "$instance")
  if [[ "$follow" == "-f" ]]; then
    journalctl -u "$service_name" -f
  else
    journalctl -u "$service_name" -n 100 --no-pager
  fi
}

cmd_instance_servers() {
  check_dependencies dig
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-servers <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"

  local servers_file
  servers_file=$(instance_servers_file "$instance")
  [[ -s "$servers_file" ]] || error "No verified DNS server list found for instance: $instance"

  echo "=== Verified DNS Servers (Instance: $instance) ==="
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
  done <"$servers_file"
}

cmd_instance_select_server() {
  need_root
  check_dependencies systemctl dig
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-select <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"

  local cfg servers_file
  cfg=$(instance_config_file "$instance")
  servers_file=$(instance_servers_file "$instance")
  [[ -s "$servers_file" ]] || error "No verified DNS server list found for instance: $instance"

  local servers=()
  local server
  while IFS= read -r server; do
    [[ -z "$server" ]] && continue
    is_valid_ipv4 "$server" || continue
    servers+=("$server")
  done <"$servers_file"
  [[ ${#servers[@]} -gt 0 ]] || error "No valid DNS IP entries found in $servers_file"

  echo "=== Manual DNS Selection (Instance: $instance) ==="
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
  [[ -n "${choice:-}" ]] || {
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
  if ! probe_tunnel_data_path "$selected" "$DOMAIN" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"; then
    error "Selected resolver $selected failed transport data-path validation. Pick another resolver."
  fi
  set_config_value "CURRENT_SERVER" "$selected" "$cfg"
  write_instance_client_service "$instance" "$selected" "$DOMAIN" "$PORT" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
  systemctl daemon-reload
  restart_instance_stack "$instance"
  log "Instance '$instance' switched to DNS server: $selected"
  cmd_instance_status "$instance"
}

cmd_instance_rescan() {
  need_root
  check_dependencies dig systemctl wc head
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-rescan <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"
  [[ "${MODE:-}" == "client" ]] || error "Instance '$instance' is not in client mode"

  local cfg servers_file
  cfg=$(instance_config_file "$instance")
  servers_file=$(instance_servers_file "$instance")

  prompt_scan_settings_for_profile "$cfg" "$servers_file"
  load_instance_config_or_error "$instance"

  local transport="${DNSTM_TRANSPORT:-slipstream}"
  validate_transport_or_error "$transport"
  local scan_source="${SCAN_SOURCE:-file}"
  local scan_file="${SCAN_DNS_FILE:-$servers_file}"
  local scan_workers="${SCAN_WORKERS:-500}"
  local scan_timeout="${SCAN_TIMEOUT:-2s}"
  local scan_threshold="${SCAN_THRESHOLD:-50}"

  if [[ "$transport" == "dnstt" ]]; then
    if [[ "$scan_source" == "file" ]]; then
      validate_dns_file_or_error "$scan_file"
      refresh_resolver_candidates_file "$DOMAIN" "$servers_file" "$scan_file" "${CURRENT_SERVER:-}" \
        || error "Manual rescan found no reachable DNS resolvers for instance '$instance'"
    else
      refresh_resolver_candidates_file "$DOMAIN" "$servers_file" "" "${CURRENT_SERVER:-}" \
        || error "Manual rescan found no reachable DNS resolvers for instance '$instance'"
    fi
  else
    [[ -x "$DNSCAN_DIR/dnscan" ]] || error "dnscan binary not found: $DNSCAN_DIR/dnscan"
    [[ -x "$SLIPSTREAM_CLIENT_BIN" ]] || error "slipstream-client not installed"
    local dnscan_args=(
      --domain "$DOMAIN"
      --data-dir "$DNSCAN_DIR/data"
      --output "$servers_file"
      --verify "$SLIPSTREAM_CLIENT_BIN"
    )

    if [[ "$scan_source" == "file" ]]; then
      validate_dns_file_or_error "$scan_file"
      dnscan_args+=(--file "$scan_file")
    else
      dnscan_args+=(
        --country "${SCAN_COUNTRY:-ir}"
        --mode "${SCAN_MODE:-fast}"
      )
    fi
    dnscan_args+=(--workers "$scan_workers" --timeout "$scan_timeout" --threshold "$scan_threshold")

    log "Running manual DNS rescan for instance '$instance'..."
    "$DNSCAN_DIR/dnscan" "${dnscan_args[@]}"
    [[ -s "$servers_file" ]] || error "Manual rescan found no verified DNS servers for instance '$instance'"
  fi

  local best_server best_latency
  read -r best_server best_latency <<<"$(find_best_server "$DOMAIN" "$servers_file")"
  [[ -n "$best_server" ]] || error "No usable DNS server found after manual rescan for '$instance'"
  [[ "$best_latency" =~ ^[0-9]+$ ]] || best_latency=9999
  [[ "$best_latency" -lt 1000 ]] || error "No resolver passed transport data-path validation for instance '$instance'"

  set_config_value "CURRENT_SERVER" "$best_server" "$cfg"
  write_instance_client_service "$instance" "$best_server" "$DOMAIN" "$PORT" "$transport" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
  systemctl daemon-reload
  restart_instance_stack "$instance"
  log "Instance '$instance' switched to best DNS server: $best_server (${best_latency}ms)"
  cmd_instance_servers "$instance"
}

cmd_instance_edit() {
  need_root
  check_dependencies systemctl ss
  local instance="${1:-}" input
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-edit <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"
  [[ "${MODE:-}" == "client" ]] || error "Instance '$instance' is not in client mode"

  local cfg servers_file old_port new_domain new_port new_server
  local new_transport new_dnstt_pubkey new_slipstream_cert new_dnstt_bind_host
  local new_bridge_enabled new_bridge_user new_bridge_pass_b64 new_bridge_remote_app_port new_bridge_local_app_port new_bridge_local_bind_addr
  cfg=$(instance_config_file "$instance")
  servers_file=$(instance_servers_file "$instance")
  old_port="${PORT:-7001}"
  new_domain="${DOMAIN:-}"
  new_port="${PORT:-7001}"
  new_server="${CURRENT_SERVER:-}"
  new_transport="${DNSTM_TRANSPORT:-slipstream}"
  new_dnstt_pubkey="${DNSTM_DNSTT_PUBKEY:-}"
  new_dnstt_bind_host="${DNSTT_BIND_HOST:-127.0.0.1}"
  new_bridge_enabled="${DNSTT_SSH_BRIDGE_ENABLED:-false}"
  new_bridge_user="${DNSTT_SSH_USER:-}"
  new_bridge_pass_b64="${DNSTT_SSH_PASS_B64:-}"
  new_bridge_remote_app_port="${DNSTT_SSH_REMOTE_APP_PORT:-2053}"
  new_bridge_local_app_port="${DNSTT_SSH_LOCAL_APP_PORT:-}"
  new_bridge_local_bind_addr="${DNSTT_SSH_LOCAL_BIND_ADDR:-0.0.0.0}"
  new_slipstream_cert="${DNSTM_SLIPSTREAM_CERT:-}"

  echo "=== Edit Client Instance: $instance ==="
  read -r -p "Domain [$new_domain]: " input
  [[ -n "$input" ]] && new_domain="$input"
  if [[ "${SLIPSTREAM_CORE:-dnstm}" == "dnstm" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Transport [slipstream/dnstt] [$new_transport]: " input
      [[ -n "$input" ]] && new_transport="$input"
    fi
  else
    new_transport="slipstream"
  fi
  read -r -p "Local listen port [$new_port]: " input
  [[ -n "$input" ]] && new_port="$input"
  read -r -p "DNS resolver IP [$new_server]: " input
  [[ -n "$input" ]] && new_server="$input"

  validate_domain_or_error "$new_domain"
  validate_transport_or_error "$new_transport"
  validate_port_or_error "$new_port"
  if [[ "$new_port" != "$old_port" ]] && port_in_use "$new_port"; then
    error "Port $new_port is already in use on this host"
  fi
  if [[ -z "$new_server" ]]; then
    prompt_instance_resolver_or_error new_server "$new_domain" "$new_transport" "$new_dnstt_pubkey" "$new_slipstream_cert" "$new_dnstt_bind_host"
  else
    validate_ipv4_or_error "$new_server"
  fi
  if [[ "$new_transport" == "dnstt" ]]; then
    read -r -p "DNSTT public key (64 hex chars) [$new_dnstt_pubkey]: " input
    [[ -n "$input" ]] && new_dnstt_pubkey="$input"
    validate_dnstt_pubkey_or_error "$new_dnstt_pubkey"
    new_dnstt_bind_host=$(prompt_dnstt_bind_host_or_error "$new_dnstt_bind_host")
    read -r -p "Enable SSH app bridge over DNSTT? [y/N] (current: ${new_bridge_enabled}): " input
    if [[ -n "$input" ]]; then
      [[ "$input" == "y" ]] && new_bridge_enabled="true" || new_bridge_enabled="false"
    fi
    if [[ "$new_bridge_enabled" == "true" ]]; then
      check_dependencies ssh sshpass base64
      read -r -p "SSH username [$new_bridge_user]: " input
      [[ -n "$input" ]] && new_bridge_user="$input"
      validate_unix_username_or_error "$new_bridge_user"
      read -r -p "Remote protected app port [$new_bridge_remote_app_port]: " input
      [[ -n "$input" ]] && new_bridge_remote_app_port="$input"
      validate_port_or_error "$new_bridge_remote_app_port"
      [[ -n "$new_bridge_local_app_port" ]] || new_bridge_local_app_port=$(default_instance_ssh_bridge_port "$new_port")
      read -r -p "Local VLESS app port [$new_bridge_local_app_port]: " input
      [[ -n "$input" ]] && new_bridge_local_app_port="$input"
      validate_port_or_error "$new_bridge_local_app_port"
      [[ "$new_bridge_local_app_port" != "$new_port" ]] || error "Local VLESS app port must differ from DNSTT transport port"
      if [[ "$new_bridge_local_app_port" != "${DNSTT_SSH_LOCAL_APP_PORT:-}" && "$new_bridge_local_app_port" != "$old_port" ]] && port_in_use "$new_bridge_local_app_port"; then
        error "Local VLESS app port $new_bridge_local_app_port is already in use on this host"
      fi
      new_bridge_local_bind_addr=$(prompt_local_bind_addr_or_error "$new_bridge_local_bind_addr")
      read -r -p "Change SSH password now? [y/N]: " input
      if [[ "$input" == "y" || -z "$new_bridge_pass_b64" ]]; then
        local plain_pass
        plain_pass=$(prompt_password_twice "SSH password for ${new_bridge_user}")
        new_bridge_pass_b64=$(printf '%s' "$plain_pass" | base64 | tr -d '\n')
      fi
      [[ -n "$new_bridge_pass_b64" ]] || error "SSH password is required when SSH app bridge is enabled"
    else
      new_bridge_user=""
      new_bridge_pass_b64=""
      new_bridge_remote_app_port="2053"
      new_bridge_local_app_port=""
      new_bridge_local_bind_addr="0.0.0.0"
    fi
    new_slipstream_cert=""
    ensure_instance_client_binary "$new_transport"
  else
    read -r -p "Pinned slipstream cert path [$new_slipstream_cert] (Enter to keep/empty): " input
    if [[ -n "$input" ]]; then
      new_slipstream_cert="$input"
    fi
    [[ -z "$new_slipstream_cert" || -f "$new_slipstream_cert" ]] || error "Slipstream cert file not found: $new_slipstream_cert"
    new_dnstt_pubkey=""
    new_dnstt_bind_host=""
    new_bridge_enabled="false"
    new_bridge_user=""
    new_bridge_pass_b64=""
    new_bridge_remote_app_port="2053"
    new_bridge_local_app_port=""
    new_bridge_local_bind_addr="0.0.0.0"
    ensure_instance_client_binary "$new_transport"
  fi

  mkdir -p "$(dirname "$servers_file")"
  printf '%s\n' "$new_server" >"$servers_file"
  refresh_resolver_candidates_file "$new_domain" "$servers_file" "" "$new_server" || true

  set_config_value "DOMAIN" "$new_domain" "$cfg"
  set_config_value "PORT" "$new_port" "$cfg"
  set_config_value "CURRENT_SERVER" "$new_server" "$cfg"
  set_config_value "DNSTM_TRANSPORT" "$new_transport" "$cfg"
  set_config_value "DNSTM_DNSTT_PUBKEY" "$new_dnstt_pubkey" "$cfg"
  set_config_value "DNSTT_BIND_HOST" "$new_dnstt_bind_host" "$cfg"
  set_config_value "DNSTT_SSH_BRIDGE_ENABLED" "$new_bridge_enabled" "$cfg"
  set_config_value "DNSTT_SSH_USER" "$new_bridge_user" "$cfg"
  set_config_value "DNSTT_SSH_PASS_B64" "$new_bridge_pass_b64" "$cfg"
  set_config_value "DNSTT_SSH_REMOTE_APP_PORT" "$new_bridge_remote_app_port" "$cfg"
  set_config_value "DNSTT_SSH_LOCAL_APP_PORT" "$new_bridge_local_app_port" "$cfg"
  set_config_value "DNSTT_SSH_LOCAL_BIND_ADDR" "$new_bridge_local_bind_addr" "$cfg"
  set_config_value "DNSTM_SLIPSTREAM_CERT" "$new_slipstream_cert" "$cfg"
  if [[ "${SCAN_SOURCE:-file}" == "file" ]]; then
    set_config_value "SCAN_DNS_FILE" "$servers_file" "$cfg"
  fi

  write_instance_client_service "$instance" "$new_server" "$new_domain" "$new_port" "$new_transport" "$new_slipstream_cert" "$new_dnstt_pubkey" "$new_dnstt_bind_host"
  if [[ "$new_bridge_enabled" == "true" ]]; then
    write_instance_ssh_client_env "$instance" "$new_bridge_user" "$new_bridge_pass_b64" "$new_port" "$new_bridge_local_app_port" "$new_bridge_remote_app_port" "$new_bridge_local_bind_addr"
    write_instance_ssh_client_service "$instance"
  else
    remove_instance_ssh_client_service_if_present "$instance"
  fi
  setup_instance_timers "$instance"
  systemctl daemon-reload
  restart_instance_stack "$instance"
  log "Instance '$instance' updated"
  cmd_instance_status "$instance"
}

cmd_instance_del() {
  need_root
  check_dependencies systemctl rm
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-del <name>"
  validate_instance_name_or_error "$instance"
  [[ "$instance" != "default" ]] || error "Cannot delete reserved instance name: default"
  load_instance_config_or_error "$instance"

  local service_name health_service health_timer watchdog_service watchdog_timer instance_path
  local ssh_service ssh_env_file
  service_name=$(instance_client_service "$instance")
  ssh_service=$(instance_ssh_client_service "$instance")
  ssh_env_file=$(instance_ssh_client_env_file "$instance")
  health_service=$(instance_health_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_service=$(instance_watchdog_service "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  instance_path=$(instance_dir "$instance")

  stop_instance_stack "$instance"
  systemctl disable "$service_name" 2>/dev/null || true
  systemctl disable "$ssh_service" 2>/dev/null || true
  systemctl disable "$health_timer" 2>/dev/null || true
  systemctl disable "$watchdog_timer" 2>/dev/null || true
  rm -f "/etc/systemd/system/${service_name}.service"
  rm -f "/etc/systemd/system/${ssh_service}.service"
  rm -f "$ssh_env_file"
  rm -f "/etc/systemd/system/${health_service}.service"
  rm -f "/etc/systemd/system/${health_timer}"
  rm -f "/etc/systemd/system/${watchdog_service}.service"
  rm -f "/etc/systemd/system/${watchdog_timer}"
  rm -rf "$instance_path"
  systemctl daemon-reload
  log "Deleted instance: $instance"
}

cmd_instance_health() {
  need_root
  check_dependencies systemctl ss journalctl grep dig wc tail date
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-health <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"

  local cfg servers_file health_log service_name bridge_service bridge_port
  cfg=$(instance_config_file "$instance")
  servers_file=$(instance_servers_file "$instance")
  health_log=$(instance_health_log "$instance")
  service_name=$(instance_client_service "$instance")
  bridge_service=""
  bridge_port=""
  if [[ "${DNSTT_SSH_BRIDGE_ENABLED:-false}" == "true" ]]; then
    bridge_service=$(instance_ssh_client_service "$instance")
    bridge_port="${DNSTT_SSH_LOCAL_APP_PORT:-}"
  fi
  [[ "${MODE:-}" == "client" ]] || error "Instance '$instance' is not in client mode"

  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  local current_server="${CURRENT_SERVER:-}"
  local current_domain="${DOMAIN:-}"
  local current_port="${PORT:-7000}"
  [[ -n "$current_server" ]] || error "Instance '$instance' has no CURRENT_SERVER in config"
  [[ -n "$current_domain" ]] || error "Instance '$instance' has no DOMAIN in config"

  local recover_reason=""
  if recover_reason=$(client_recover_reason "6 minutes ago" "$current_port" "$service_name" "$bridge_service" "$bridge_port"); then
    echo "[$timestamp] Self-heal triggered: $recover_reason" >>"$health_log"
    write_instance_client_service "$instance" "$current_server" "$current_domain" "$current_port" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
    systemctl daemon-reload
    if restart_instance_stack "$instance"; then
      echo "[$timestamp] Self-heal restart completed" >>"$health_log"
      sleep 2
    else
      echo "[$timestamp] ERROR: service restart failed" >>"$health_log"
    fi
  fi

  local latency
  latency=$(test_dns_latency "$current_server" "$current_domain" || echo "9999")
  if [[ "$latency" -gt 1000 ]]; then
    echo "[$timestamp] Current server $current_server slow (${latency}ms), checking alternatives..." >>"$health_log"
    if [[ -f "$servers_file" ]]; then
      local best_server best_latency
      read -r best_server best_latency <<<"$(find_best_server "$current_domain" "$servers_file" || true)"
      if [[ -n "$best_server" && "$best_server" != "$current_server" && "$best_latency" -lt 1000 ]]; then
        set_config_value "CURRENT_SERVER" "$best_server" "$cfg"
        write_instance_client_service "$instance" "$best_server" "$current_domain" "$current_port" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
        systemctl daemon-reload
        if restart_instance_stack "$instance"; then
          echo "[$timestamp] Switched to $best_server (${best_latency}ms)" >>"$health_log"
        else
          echo "[$timestamp] ERROR: switch restart failed" >>"$health_log"
        fi
      else
        echo "[$timestamp] No better server found" >>"$health_log"
      fi
    fi
  else
    echo "[$timestamp] Server $current_server OK (${latency}ms)" >>"$health_log"
  fi

  if [[ $(wc -l <"$health_log") -gt 1000 ]]; then
    local tmp_health
    tmp_health=$(mktemp /tmp/health.XXXXXX.log)
    tail -500 "$health_log" >"$tmp_health" && mv "$tmp_health" "$health_log"
  fi
}

cmd_instance_watchdog() {
  need_root
  check_dependencies systemctl ss journalctl grep date mkdir
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-watchdog <name>"
  validate_instance_name_or_error "$instance"
  load_instance_config_or_error "$instance"

  local service_name bridge_service bridge_port reason="" now last=0 state_file health_log
  service_name=$(instance_client_service "$instance")
  bridge_service=""
  bridge_port=""
  if [[ "${DNSTT_SSH_BRIDGE_ENABLED:-false}" == "true" ]]; then
    bridge_service=$(instance_ssh_client_service "$instance")
    bridge_port="${DNSTT_SSH_LOCAL_APP_PORT:-}"
  fi
  health_log=$(instance_health_log "$instance")
  if ! reason=$(client_recover_reason "90 seconds ago" "${PORT:-7000}" "$service_name" "$bridge_service" "$bridge_port" "${CURRENT_SERVER:-}"); then
    exit 0
  fi

  state_file=$(instance_watchdog_last_restart_file "$instance")
  now=$(date +%s)
  mkdir -p "$WATCHDOG_STATE_DIR"
  if [[ -f "$state_file" ]]; then
    last=$(cat "$state_file" 2>/dev/null || echo 0)
    [[ "$last" =~ ^[0-9]+$ ]] || last=0
  fi
  if ((now - last < 45)); then
    exit 0
  fi
  echo "$now" >"$state_file"

  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] Watchdog restart triggered: $reason" >>"$health_log"
  write_instance_client_service "$instance" "${CURRENT_SERVER:-}" "${DOMAIN:-}" "${PORT:-7000}" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"
  systemctl daemon-reload
  if restart_instance_stack "$instance"; then
    echo "[$timestamp] Watchdog restart completed" >>"$health_log"
  else
    echo "[$timestamp] ERROR: watchdog restart failed" >>"$health_log"
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
  if ! probe_tunnel_data_path "$selected" "$DOMAIN" "${DNSTM_TRANSPORT:-slipstream}" "${DNSTM_DNSTT_PUBKEY:-}" "${DNSTM_SLIPSTREAM_CERT:-}" "${DNSTT_BIND_HOST:-127.0.0.1}"; then
    error "Selected resolver $selected failed transport data-path validation. Pick another resolver."
  fi
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
  server)
    if [[ "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
      echo "dnstm-router"
    else
      echo "slipstream-server"
    fi
    ;;
  client) echo "slipstream-client" ;;
  *) error "Unsupported mode in config: ${MODE:-unknown}" ;;
  esac
}

cmd_start() {
  need_root
  check_dependencies systemctl
  load_config_or_error

  if [[ "${MODE:-}" == "client" ]]; then
    if ! systemctl list-unit-files tunnel-health.timer &>/dev/null || ! systemctl list-unit-files tunnel-watchdog.timer &>/dev/null; then
      setup_health_timer
      setup_watchdog_timer
    fi
  fi

  local service_name
  service_name=$(service_name_for_mode)
  if [[ "${MODE:-}" == "client" ]]; then
    start_client_stack
  elif [[ "${MODE:-}" == "server" && "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
    run_dnstm router start
  else
    systemctl start "$service_name"
  fi

  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-health.timer &>/dev/null; then
    systemctl start tunnel-health.timer || true
  fi
  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-watchdog.timer &>/dev/null; then
    systemctl start tunnel-watchdog.timer || true
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
  elif [[ "${MODE:-}" == "server" && "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
    run_dnstm router stop
  else
    systemctl stop "$service_name"
  fi

  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-health.timer &>/dev/null; then
    systemctl stop tunnel-health.timer || true
  fi
  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-watchdog.timer &>/dev/null; then
    systemctl stop tunnel-watchdog.timer || true
  fi
  log "Stopped: $service_name"
}

cmd_restart() {
  need_root
  check_dependencies systemctl
  load_config_or_error

  if [[ "${MODE:-}" == "client" ]]; then
    if ! systemctl list-unit-files tunnel-health.timer &>/dev/null || ! systemctl list-unit-files tunnel-watchdog.timer &>/dev/null; then
      setup_health_timer
      setup_watchdog_timer
    fi
  fi

  local service_name
  service_name=$(service_name_for_mode)
  if [[ "${MODE:-}" == "client" ]]; then
    restart_client_stack
  elif [[ "${MODE:-}" == "server" && "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
    run_dnstm router restart
  else
    systemctl restart "$service_name"
  fi

  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-health.timer &>/dev/null; then
    systemctl start tunnel-health.timer || true
  fi
  if [[ "${MODE:-}" == "client" ]] && systemctl list-unit-files tunnel-watchdog.timer &>/dev/null; then
    systemctl start tunnel-watchdog.timer || true
  fi
  log "Restarted: $service_name"
}

cmd_uninstall() {
  cmd_remove
}

cmd_edit_client() {
  need_root
  check_dependencies systemctl
  install_self
  enable_bbr_if_possible
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
  local new_transport="${DNSTM_TRANSPORT:-slipstream}"
  local new_dnstt_pubkey="${DNSTM_DNSTT_PUBKEY:-}"
  local new_dnstt_bind_host="${DNSTT_BIND_HOST:-127.0.0.1}"
  local new_slipstream_cert="${DNSTM_SLIPSTREAM_CERT:-}"
  local new_ssh_pass_plain=""
  local input=""

  echo "=== Edit Client Settings ==="
  read -r -p "Domain [$new_domain]: " input
  [[ -n "$input" ]] && new_domain="$input"
  if [[ "${SLIPSTREAM_CORE:-dnstm}" == "dnstm" ]]; then
    read -r -p "Transport [slipstream/dnstt] [$new_transport]: " input
    [[ -n "$input" ]] && new_transport="$input"
  else
    new_transport="slipstream"
  fi
  read -r -p "Tunnel listen port [$new_port]: " input
  [[ -n "$input" ]] && new_port="$input"
  read -r -p "DNS resolver IP [$new_server]: " input
  [[ -n "$input" ]] && new_server="$input"
  if core_supports_ssh_overlay; then
    read -r -p "Use SSH username/password auth overlay? [y/N] (current: ${new_ssh_auth}): " input
    if [[ -n "$input" ]]; then
      [[ "$input" == "y" ]] && new_ssh_auth=true || new_ssh_auth=false
    fi
  else
    if [[ "$new_ssh_auth" == "true" ]]; then
      warn "Core '${SLIPSTREAM_CORE}' does not use legacy SSH auth overlay. It will be disabled."
    fi
    new_ssh_auth=false
  fi

  validate_domain_or_error "$new_domain"
  validate_transport_or_error "$new_transport"
  validate_port_or_error "$new_port"
  if [[ -n "$new_server" ]]; then
    validate_ipv4_or_error "$new_server"
  elif [[ -s "$SERVERS_FILE" ]]; then
    local auto_latency
    read -r new_server auto_latency <<<"$(find_best_server "$new_domain" "$SERVERS_FILE" "$new_transport" "$new_dnstt_pubkey" "$new_slipstream_cert" "$new_dnstt_bind_host")"
    [[ "$auto_latency" =~ ^[0-9]+$ ]] || auto_latency=9999
    [[ "$auto_latency" -lt 1000 ]] || error "No resolver passed transport data-path validation for ${new_domain}. Run rescan with better candidates."
  fi
  [[ -n "$new_server" ]] || error "No DNS resolver available. Run 'slipstream-tunnel rescan' first."
  if [[ "$new_transport" == "dnstt" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "DNSTT public key (64 hex chars) [$new_dnstt_pubkey]: " input
      [[ -n "$input" ]] && new_dnstt_pubkey="$input"
    fi
    validate_dnstt_pubkey_or_error "$new_dnstt_pubkey"
    if [[ -t 0 ]]; then
      new_dnstt_bind_host=$(prompt_dnstt_bind_host_or_error "$new_dnstt_bind_host")
    fi
    validate_dnstt_bind_host_or_error "$new_dnstt_bind_host"
    new_slipstream_cert=""
    ensure_dnstt_client_binary
  else
    if [[ -t 0 ]]; then
      read -r -p "Pinned slipstream cert path [$new_slipstream_cert] (Enter to keep/empty): " input
      if [[ -n "$input" ]]; then
        new_slipstream_cert="$input"
      fi
    fi
    [[ -z "$new_slipstream_cert" || -f "$new_slipstream_cert" ]] || error "Slipstream cert file not found: $new_slipstream_cert"
    new_dnstt_pubkey=""
    new_dnstt_bind_host=""
    ensure_slipstream_client_binary
  fi

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
    new_ssh_pass_plain=$(decode_base64_or_raw "$new_ssh_pass_b64")
    [[ -n "$new_ssh_pass_plain" ]] || error "SSH password is empty after decode"
  fi

  if [[ "$new_ssh_auth" == "true" ]]; then
    write_client_service "$new_server" "$new_domain" "$new_ssh_transport_port" "$new_transport" "$new_slipstream_cert" "$new_dnstt_pubkey" "$new_dnstt_bind_host"
    systemctl daemon-reload
    systemctl restart slipstream-client
    systemctl stop "${SSH_CLIENT_SERVICE}" 2>/dev/null || true
    local preflight_rc=0
    if test_client_ssh_auth_credentials "$new_ssh_user" "$new_ssh_pass_plain" "$new_ssh_transport_port" "$new_port" "$new_ssh_remote_port"; then
      preflight_rc=0
    else
      preflight_rc=$?
    fi
    if [[ "$preflight_rc" -ne 0 ]]; then
      if [[ "$preflight_rc" -eq 2 ]]; then
        warn "Proceeding despite inconclusive SSH preflight. Verify with: slipstream-tunnel status && slipstream-tunnel logs -f"
      else
        error "SSH credential test failed. Aborting client edit."
      fi
    fi

    set_config_value "DOMAIN" "$new_domain" "$CONFIG_FILE"
    set_config_value "PORT" "$new_port" "$CONFIG_FILE"
    set_config_value "CURRENT_SERVER" "$new_server" "$CONFIG_FILE"
    set_config_value "DNSTM_TRANSPORT" "$new_transport" "$CONFIG_FILE"
    set_config_value "DNSTM_DNSTT_PUBKEY" "$new_dnstt_pubkey" "$CONFIG_FILE"
    set_config_value "DNSTT_BIND_HOST" "$new_dnstt_bind_host" "$CONFIG_FILE"
    set_config_value "DNSTM_SLIPSTREAM_CERT" "$new_slipstream_cert" "$CONFIG_FILE"
    set_config_value "SSH_AUTH_ENABLED" "true" "$CONFIG_FILE"
    set_config_value "SSH_AUTH_USER" "$new_ssh_user" "$CONFIG_FILE"
    set_config_value "SSH_PASS_B64" "$new_ssh_pass_b64" "$CONFIG_FILE"
    set_config_value "SSH_REMOTE_APP_PORT" "$new_ssh_remote_port" "$CONFIG_FILE"
    set_config_value "SSH_TRANSPORT_PORT" "$new_ssh_transport_port" "$CONFIG_FILE"
    write_ssh_client_env "$new_ssh_user" "$new_ssh_pass_b64" "$new_ssh_transport_port" "$new_port" "$new_ssh_remote_port"
    write_ssh_client_service
    SSH_AUTH_ENABLED="true"
  else
    set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
    set_config_value "SSH_AUTH_USER" "" "$CONFIG_FILE"
    set_config_value "SSH_PASS_B64" "" "$CONFIG_FILE"
    set_config_value "SSH_REMOTE_APP_PORT" "" "$CONFIG_FILE"
    set_config_value "SSH_TRANSPORT_PORT" "" "$CONFIG_FILE"
    set_config_value "DOMAIN" "$new_domain" "$CONFIG_FILE"
    set_config_value "PORT" "$new_port" "$CONFIG_FILE"
    set_config_value "CURRENT_SERVER" "$new_server" "$CONFIG_FILE"
    set_config_value "DNSTM_TRANSPORT" "$new_transport" "$CONFIG_FILE"
    set_config_value "DNSTM_DNSTT_PUBKEY" "$new_dnstt_pubkey" "$CONFIG_FILE"
    set_config_value "DNSTT_BIND_HOST" "$new_dnstt_bind_host" "$CONFIG_FILE"
    set_config_value "DNSTM_SLIPSTREAM_CERT" "$new_slipstream_cert" "$CONFIG_FILE"
    write_client_service "$new_server" "$new_domain" "$new_port" "$new_transport" "$new_slipstream_cert" "$new_dnstt_pubkey" "$new_dnstt_bind_host"
    remove_ssh_client_service_if_present
    SSH_AUTH_ENABLED="false"
  fi
  systemctl daemon-reload
  # Keep recovery units synced with latest script logic after edits/upgrades.
  setup_health_timer
  setup_watchdog_timer
  restart_client_stack

  log "Client settings updated and service restarted"
  cmd_dashboard
}

cmd_edit_server() {
  need_root
  check_dependencies systemctl openssl
  install_self
  enable_bbr_if_possible
  load_config_or_error
  [[ "${MODE:-}" == "server" ]] || error "Server edit is available only in server mode"

  if [[ "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
    local new_domain="${DOMAIN:-}"
    local new_port="${PORT:-2053}"
    local new_transport="${DNSTM_TRANSPORT:-slipstream}"
    local new_backend_type="${DNSTM_BACKEND_TYPE:-custom}"
    local new_backend_tag="${DNSTM_BACKEND_TAG:-app-main}"
    local new_tunnel_tag="${DNSTM_TUNNEL_TAG:-main}"
    local new_router_mode="${DNSTM_MODE:-single}"
    local new_ss_password=""
    local new_ss_method="aes-256-gcm"
    local input=""

    echo "=== Edit Server Settings (dnstm native) ==="
    read -r -p "Domain [$new_domain]: " input
    [[ -n "$input" ]] && new_domain="$input"
    read -r -p "dnstm router mode [single/multi] [$new_router_mode]: " input
    [[ -n "$input" ]] && new_router_mode="$input"
    read -r -p "Tunnel transport [slipstream/dnstt] [$new_transport]: " input
    [[ -n "$input" ]] && new_transport="$input"
    read -r -p "Backend type [custom/socks/ssh/shadowsocks] [$new_backend_type]: " input
    [[ -n "$input" ]] && new_backend_type="$input"

    case "$new_backend_type" in
    custom)
      read -r -p "Protected app port for custom backend [$new_port]: " input
      [[ -n "$input" ]] && new_port="$input"
      ;;
    shadowsocks)
      read -r -p "Shadowsocks method [$new_ss_method]: " input
      [[ -n "$input" ]] && new_ss_method="$input"
      read -r -p "Shadowsocks password (Enter to auto-generate): " input
      [[ -n "$input" ]] && new_ss_password="$input"
      ;;
    esac

    read -r -p "Backend tag [$new_backend_tag]: " input
    [[ -n "$input" ]] && new_backend_tag="$input"
    read -r -p "Tunnel tag [$new_tunnel_tag]: " input
    [[ -n "$input" ]] && new_tunnel_tag="$input"

    validate_domain_or_error "$new_domain"
    validate_port_or_error "$new_port"
    dnstm_validate_transport_or_error "$new_transport"
    dnstm_validate_backend_type_or_error "$new_backend_type"
    [[ "$new_router_mode" == "single" || "$new_router_mode" == "multi" ]] \
      || error "Invalid dnstm mode: $new_router_mode (use single or multi)"
    if [[ "$new_transport" == "dnstt" && "$new_backend_type" == "shadowsocks" ]]; then
      error "DNSTT transport does not support shadowsocks backend"
    fi
    case "$new_backend_type" in
    socks) new_backend_tag="socks" ;;
    ssh) new_backend_tag="ssh" ;;
    esac

    ensure_dnstm_binary
    dnstm_setup_server_stack "$new_domain" "$new_port" "$new_transport" "$new_backend_type" "$new_backend_tag" "$new_tunnel_tag" "$new_router_mode" "$new_ss_password" "$new_ss_method"

    set_config_value "DOMAIN" "$new_domain" "$CONFIG_FILE"
    set_config_value "PORT" "$new_port" "$CONFIG_FILE"
    set_config_value "DNSTM_MODE" "$new_router_mode" "$CONFIG_FILE"
    set_config_value "DNSTM_TRANSPORT" "$new_transport" "$CONFIG_FILE"
    set_config_value "DNSTM_BACKEND_TYPE" "$new_backend_type" "$CONFIG_FILE"
    set_config_value "DNSTM_BACKEND_TAG" "$new_backend_tag" "$CONFIG_FILE"
    set_config_value "DNSTM_TUNNEL_TAG" "$new_tunnel_tag" "$CONFIG_FILE"
    set_config_value "DNSTM_BACKEND_ADDRESS" "$(dnstm_backend_address_for_type "$new_backend_type" "$new_port")" "$CONFIG_FILE"
    set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
    set_config_value "SSH_BACKEND_PORT" "" "$CONFIG_FILE"

    log "dnstm native server settings updated."
    cmd_status
    return 0
  fi

  local new_domain="${DOMAIN:-}"
  local new_port="${PORT:-2053}"
  local ssh_backend_port="${SSH_BACKEND_PORT:-22}"
  local input regenerate_cert=false

  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && ! core_supports_ssh_overlay; then
    warn "Core '${SLIPSTREAM_CORE}' does not use legacy SSH auth overlay. Existing overlay settings will be cleared."
    SSH_AUTH_ENABLED="false"
    SSH_BACKEND_PORT=""
  fi

  echo "=== Edit Server Settings ==="
  read -r -p "Domain [$new_domain]: " input
  [[ -n "$input" ]] && new_domain="$input"
  read -r -p "Protected app port [$new_port]: " input
  [[ -n "$input" ]] && new_port="$input"
  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && core_supports_ssh_overlay; then
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
  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && core_supports_ssh_overlay; then
    set_config_value "SSH_BACKEND_PORT" "$ssh_backend_port" "$CONFIG_FILE"
    write_server_service "$new_domain" "$ssh_backend_port"
  else
    set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
    set_config_value "SSH_BACKEND_PORT" "" "$CONFIG_FILE"
    write_server_service "$new_domain" "$new_port"
  fi
  systemctl daemon-reload
  systemctl restart slipstream-server

  if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && core_supports_ssh_overlay; then
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

server_enable_auth_overlay_with_ports() {
  local app_port="$1" ssh_backend_port="$2"
  validate_port_or_error "$app_port"
  validate_port_or_error "$ssh_backend_port"

  apply_ssh_auth_overlay "$app_port"
  set_config_value "PORT" "$app_port" "$CONFIG_FILE"
  set_config_value "SSH_BACKEND_PORT" "$ssh_backend_port" "$CONFIG_FILE"
  write_server_service "$DOMAIN" "$ssh_backend_port"
  systemctl daemon-reload
  systemctl restart slipstream-server
  set_config_value "SSH_AUTH_ENABLED" "true" "$CONFIG_FILE"
  SSH_AUTH_ENABLED="true"
  PORT="$app_port"
  SSH_BACKEND_PORT="$ssh_backend_port"
  log "SSH auth overlay enabled. Users authenticate via SSH before reaching 127.0.0.1:$app_port."
}

server_disable_auth_overlay() {
  local app_port="${PORT:-2053}"
  local backup_file=""
  if [[ -f "$SSH_AUTH_CONFIG_FILE" ]]; then
    backup_file=$(mktemp /tmp/sshd-slipstream-disable.XXXXXX)
    cp "$SSH_AUTH_CONFIG_FILE" "$backup_file"
    rm -f "$SSH_AUTH_CONFIG_FILE"
  fi

  if command -v sshd &>/dev/null; then
    if ! sshd -t; then
      if [[ -n "$backup_file" && -f "$backup_file" ]]; then
        cp "$backup_file" "$SSH_AUTH_CONFIG_FILE"
      fi
      [[ -n "$backup_file" ]] && rm -f "$backup_file"
      error "SSH config became invalid after disabling overlay. Changes rolled back."
    fi
    local ssh_service
    ssh_service=$(detect_ssh_service_name || true)
    if [[ -n "$ssh_service" ]]; then
      systemctl restart "$ssh_service"
    else
      warn "Could not detect SSH service to restart"
    fi
  fi
  [[ -n "$backup_file" ]] && rm -f "$backup_file"

  write_server_service "$DOMAIN" "$app_port"
  systemctl daemon-reload
  systemctl restart slipstream-server
  set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
  set_config_value "SSH_BACKEND_PORT" "" "$CONFIG_FILE"
  SSH_AUTH_ENABLED="false"
  SSH_BACKEND_PORT=""
  log "SSH auth overlay disabled. Slipstream now forwards directly to 127.0.0.1:$app_port."
}

cmd_auth_setup() {
  need_root
  check_dependencies systemctl getent awk tr
  ensure_mode_server_or_error
  core_supports_ssh_overlay || error "Core '${SLIPSTREAM_CORE}' does not use legacy SSH auth overlay. Use native auth/backend features."

  local app_port="${PORT:-2053}"
  local ssh_backend_port="${SSH_BACKEND_PORT:-22}"
  read -r -p "Protected app port [$app_port]: " input_port
  [[ -n "$input_port" ]] && app_port="$input_port"
  read -r -p "SSH backend port for slipstream [$ssh_backend_port]: " input_port
  [[ -n "$input_port" ]] && ssh_backend_port="$input_port"
  server_enable_auth_overlay_with_ports "$app_port" "$ssh_backend_port"
}

cmd_auth_disable() {
  need_root
  check_dependencies systemctl
  ensure_mode_server_or_error

  if ! core_supports_ssh_overlay; then
    warn "Core '${SLIPSTREAM_CORE}' does not use legacy SSH auth overlay."
    return 0
  fi

  if [[ "${SSH_AUTH_ENABLED:-false}" != "true" ]]; then
    warn "SSH auth overlay is already disabled."
    return 0
  fi
  server_disable_auth_overlay
}

cmd_client_auth_enable() {
  need_root
  check_dependencies systemctl ssh sshpass base64
  ensure_mode_client_or_error
  core_supports_ssh_overlay || error "Core '${SLIPSTREAM_CORE}' does not use legacy SSH auth client overlay."

  if client_ssh_auth_enabled; then
    log "Client SSH auth overlay is already enabled."
    return 0
  fi

  local ssh_user="${SSH_AUTH_USER:-}"
  local ssh_pass_b64="${SSH_PASS_B64:-}"
  local ssh_remote_port="${SSH_REMOTE_APP_PORT:-2053}"
  local ssh_transport_port="${SSH_TRANSPORT_PORT:-17070}"
  local client_port="${PORT:-7000}"
  local current_server="${CURRENT_SERVER:-}"
  [[ -n "$current_server" ]] || error "No DNS resolver set in config"
  [[ -n "$ssh_user" ]] || error "No saved SSH username. Run 'slipstream-tunnel edit' first."
  [[ -n "$ssh_pass_b64" ]] || error "No saved SSH password. Run 'slipstream-tunnel edit' first."

  validate_unix_username_or_error "$ssh_user"
  validate_port_or_error "$ssh_remote_port"
  validate_port_or_error "$ssh_transport_port"
  validate_port_or_error "$client_port"
  [[ "$ssh_transport_port" != "$client_port" ]] || error "Internal SSH transport port must differ from client listen port"

  local plain_pass
  plain_pass=$(decode_base64_or_raw "$ssh_pass_b64")
  [[ -n "$plain_pass" ]] || error "Saved SSH password is empty after decode"

  write_client_service "$current_server" "$DOMAIN" "$ssh_transport_port"
  systemctl daemon-reload
  systemctl restart slipstream-client
  systemctl stop "${SSH_CLIENT_SERVICE}" 2>/dev/null || true

  local preflight_rc=0
  if test_client_ssh_auth_credentials "$ssh_user" "$plain_pass" "$ssh_transport_port" "$client_port" "$ssh_remote_port"; then
    preflight_rc=0
  else
    preflight_rc=$?
  fi
  if [[ "$preflight_rc" -ne 0 ]]; then
    if [[ "$preflight_rc" -eq 2 ]]; then
      warn "Proceeding despite inconclusive SSH preflight. Verify with: slipstream-tunnel status && slipstream-tunnel logs -f"
    else
      error "SSH credential test failed. Aborting client auth enable."
    fi
  fi

  write_ssh_client_env "$ssh_user" "$ssh_pass_b64" "$ssh_transport_port" "$client_port" "$ssh_remote_port"
  write_ssh_client_service
  set_config_value "SSH_AUTH_ENABLED" "true" "$CONFIG_FILE"
  SSH_AUTH_ENABLED="true"

  systemctl daemon-reload
  systemctl enable "${SSH_CLIENT_SERVICE}"
  systemctl restart "${SSH_CLIENT_SERVICE}"
  log "Client SSH auth overlay enabled."
}

cmd_client_auth_disable() {
  need_root
  check_dependencies systemctl
  ensure_mode_client_or_error

  if ! core_supports_ssh_overlay; then
    warn "Core '${SLIPSTREAM_CORE}' does not use legacy SSH auth client overlay."
    return 0
  fi

  if [[ "${SSH_AUTH_ENABLED:-false}" != "true" ]]; then
    warn "Client SSH auth overlay is already disabled."
    return 0
  fi

  local current_server="${CURRENT_SERVER:-}"
  local client_port="${PORT:-7000}"
  [[ -n "$current_server" ]] || error "No DNS resolver set in config"
  validate_port_or_error "$client_port"

  write_client_service "$current_server" "$DOMAIN" "$client_port"
  remove_ssh_client_service_if_present
  set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
  SSH_AUTH_ENABLED="false"

  systemctl daemon-reload
  systemctl restart slipstream-client
  log "Client SSH auth overlay disabled. Tunnel now runs without SSH auth wrapper."
}

cmd_speed_profile() {
  need_root
  load_config_or_error

  if ! core_supports_ssh_overlay; then
    case "${1:-status}" in
    status)
      echo "Speed profile: native (legacy SSH overlay not used on core '${SLIPSTREAM_CORE}')"
      return 0
      ;;
    fast | secure)
      warn "Speed profiles map to legacy SSH overlay and are not used on core '${SLIPSTREAM_CORE}'."
      return 0
      ;;
    esac
  fi

  local profile="${1:-status}"
  case "$profile" in
  status)
    if [[ "${MODE:-}" == "server" ]]; then
      if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]]; then
        echo "Speed profile: secure (SSH overlay enabled)"
      else
        echo "Speed profile: fast (SSH overlay disabled)"
      fi
    elif [[ "${MODE:-}" == "client" ]]; then
      if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]]; then
        echo "Speed profile: secure (SSH overlay enabled)"
      else
        echo "Speed profile: fast (SSH overlay disabled)"
      fi
    else
      error "Unsupported mode in config: ${MODE:-unknown}"
    fi
    ;;
  fast)
    if [[ "${MODE:-}" == "server" ]]; then
      cmd_auth_disable
    elif [[ "${MODE:-}" == "client" ]]; then
      cmd_client_auth_disable
    else
      error "Unsupported mode in config: ${MODE:-unknown}"
    fi
    ;;
  secure)
    if [[ "${MODE:-}" == "server" ]]; then
      server_enable_auth_overlay_with_ports "${PORT:-2053}" "${SSH_BACKEND_PORT:-22}"
    elif [[ "${MODE:-}" == "client" ]]; then
      cmd_client_auth_enable
    else
      error "Unsupported mode in config: ${MODE:-unknown}"
    fi
    ;;
  *)
    error "Unknown speed profile: $profile (use: fast, secure, status)"
    ;;
  esac
}

cmd_core_switch() {
  need_root
  check_dependencies curl tar systemctl
  load_config_or_error

  local current_core="${SLIPSTREAM_CORE:-dnstm}"
  local target_core="${1:-}"
  if [[ -z "$target_core" && -t 0 ]]; then
    target_core=$(prompt_core_choice "$current_core")
  fi
  [[ -n "$target_core" ]] || error "Usage: slipstream-tunnel core-switch <dnstm|nightowl|plus>"

  if [[ "${current_core}" == "${target_core}" ]]; then
    log "Core is already '${target_core}'."
    return 0
  fi

  if [[ "$target_core" == "dnstm" && "${SSH_AUTH_ENABLED:-false}" == "true" ]]; then
    warn "Switching to core 'dnstm': disabling legacy SSH auth overlay first."
    if [[ "${MODE:-}" == "server" ]]; then
      server_disable_auth_overlay
    elif [[ "${MODE:-}" == "client" ]]; then
      cmd_client_auth_disable
    fi
    load_config_or_error
  fi
  set_slipstream_source "$target_core"

  local arch
  arch=$(detect_arch)
  log "Switching core: ${current_core} -> ${target_core}"
  log "Source: ${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION} (${SLIPSTREAM_ASSET_LAYOUT})"

  if [[ "${MODE:-}" == "server" ]]; then
    if [[ "$target_core" == "dnstm" ]]; then
      local dnstm_transport dnstm_backend dnstm_backend_tag dnstm_tunnel_tag dnstm_mode dnstm_ss_password dnstm_ss_method
      dnstm_transport="${DNSTM_TRANSPORT:-slipstream}"
      dnstm_backend="${DNSTM_BACKEND_TYPE:-custom}"
      dnstm_backend_tag="${DNSTM_BACKEND_TAG:-app-main}"
      dnstm_tunnel_tag="${DNSTM_TUNNEL_TAG:-main}"
      dnstm_mode="${DNSTM_MODE:-single}"
      dnstm_ss_password=""
      dnstm_ss_method="aes-256-gcm"
      case "$dnstm_backend" in
      socks) dnstm_backend_tag="socks" ;;
      ssh) dnstm_backend_tag="ssh" ;;
      esac

      ensure_dnstm_binary
      dnstm_setup_server_stack "$DOMAIN" "${PORT:-2053}" "$dnstm_transport" "$dnstm_backend" "$dnstm_backend_tag" "$dnstm_tunnel_tag" "$dnstm_mode" "$dnstm_ss_password" "$dnstm_ss_method"
      set_config_value "DNSTM_REPO" "$DNSTM_REPO" "$CONFIG_FILE"
      set_config_value "DNSTM_VERSION" "$DNSTM_VERSION" "$CONFIG_FILE"
      set_config_value "DNSTM_MODE" "$dnstm_mode" "$CONFIG_FILE"
      set_config_value "DNSTM_TRANSPORT" "$dnstm_transport" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TYPE" "$dnstm_backend" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TAG" "$dnstm_backend_tag" "$CONFIG_FILE"
      set_config_value "DNSTM_TUNNEL_TAG" "$dnstm_tunnel_tag" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_ADDRESS" "$(dnstm_backend_address_for_type "$dnstm_backend" "${PORT:-2053}")" "$CONFIG_FILE"
      set_config_value "SSH_AUTH_ENABLED" "false" "$CONFIG_FILE"
      set_config_value "SSH_BACKEND_PORT" "" "$CONFIG_FILE"
    else
      if [[ "$current_core" == "dnstm" ]] && dnstm_is_installed; then
        run_dnstm router stop >/dev/null 2>&1 || true
      fi
      systemctl stop slipstream-server 2>/dev/null || true
      download_slipstream_component "server" "$SLIPSTREAM_SERVER_BIN" "$arch" \
        || error "Failed to download server binary for core '${target_core}'"
      chmod +x "$SLIPSTREAM_SERVER_BIN"
      systemctl daemon-reload
      systemctl restart slipstream-server
    fi
  elif [[ "${MODE:-}" == "client" ]]; then
    local client_transport="${DNSTM_TRANSPORT:-slipstream}"
    local client_pubkey="${DNSTM_DNSTT_PUBKEY:-}"
    local client_cert="${DNSTM_SLIPSTREAM_CERT:-}"
    local resolver="${CURRENT_SERVER:-}"
    local domain="${DOMAIN:-}"
    local listen_port
    listen_port=$(client_transport_port_from_config)

    if [[ "$target_core" != "dnstm" ]]; then
      client_transport="slipstream"
      client_pubkey=""
    fi
    validate_transport_or_error "$client_transport"
    if [[ "$client_transport" == "dnstt" && -z "$client_pubkey" ]]; then
      warn "DNSTT transport selected but no DNSTT public key is saved. Falling back to slipstream."
      client_transport="slipstream"
    fi

    download_slipstream_component "client" "$SLIPSTREAM_CLIENT_BIN" "$arch" \
      || error "Failed to download client binary for core '${target_core}'"
    chmod +x "$SLIPSTREAM_CLIENT_BIN"
    # Keep verifier binary in sync.
    cp "$SLIPSTREAM_CLIENT_BIN" "$TUNNEL_DIR/slipstream-client" 2>/dev/null || true
    chmod +x "$TUNNEL_DIR/slipstream-client" 2>/dev/null || true
    if [[ "$client_transport" == "dnstt" ]]; then
      ensure_dnstt_client_binary
    fi
    if [[ -n "$resolver" && -n "$domain" ]]; then
      write_client_service "$resolver" "$domain" "$listen_port" "$client_transport" "$client_cert" "$client_pubkey"
      systemctl daemon-reload
    fi
    set_config_value "DNSTM_TRANSPORT" "$client_transport" "$CONFIG_FILE"
    set_config_value "DNSTM_DNSTT_PUBKEY" "$client_pubkey" "$CONFIG_FILE"
    set_config_value "DNSTM_SLIPSTREAM_CERT" "$client_cert" "$CONFIG_FILE"
    restart_client_stack
  else
    error "Unsupported mode in config: ${MODE:-unknown}"
  fi

  set_config_value "SLIPSTREAM_CORE" "$SLIPSTREAM_CORE" "$CONFIG_FILE"
  set_config_value "SLIPSTREAM_REPO" "$SLIPSTREAM_REPO" "$CONFIG_FILE"
  set_config_value "SLIPSTREAM_VERSION" "$SLIPSTREAM_VERSION" "$CONFIG_FILE"
  set_config_value "SLIPSTREAM_ASSET_LAYOUT" "$SLIPSTREAM_ASSET_LAYOUT" "$CONFIG_FILE"
  if [[ "${MODE:-}" == "server" ]]; then
    if [[ "$target_core" == "dnstm" ]]; then
      set_config_value "DNSTM_REPO" "$DNSTM_REPO" "$CONFIG_FILE"
      set_config_value "DNSTM_VERSION" "$DNSTM_VERSION" "$CONFIG_FILE"
    else
      set_config_value "DNSTM_MODE" "" "$CONFIG_FILE"
      set_config_value "DNSTM_TRANSPORT" "" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TYPE" "" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TAG" "" "$CONFIG_FILE"
      set_config_value "DNSTM_TUNNEL_TAG" "" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_ADDRESS" "" "$CONFIG_FILE"
    fi
  fi

  if [[ "${MODE:-}" == "client" && -d "$INSTANCES_DIR" ]]; then
    local icfg instance_name instance_domain instance_resolver instance_port instance_transport instance_pubkey instance_cert
    local -a instances_to_restart=()
    for icfg in "$INSTANCES_DIR"/*/config; do
      [[ -f "$icfg" ]] || continue
      instance_name=$(basename "$(dirname "$icfg")")
      set_config_value "SLIPSTREAM_CORE" "$SLIPSTREAM_CORE" "$icfg"
      set_config_value "SLIPSTREAM_REPO" "$SLIPSTREAM_REPO" "$icfg"
      set_config_value "SLIPSTREAM_VERSION" "$SLIPSTREAM_VERSION" "$icfg"
      set_config_value "SLIPSTREAM_ASSET_LAYOUT" "$SLIPSTREAM_ASSET_LAYOUT" "$icfg"

      instance_domain=$(config_value_from_file "$icfg" "DOMAIN" || true)
      instance_resolver=$(config_value_from_file "$icfg" "CURRENT_SERVER" || true)
      instance_port=$(config_value_from_file "$icfg" "PORT" || true)
      instance_transport=$(config_value_from_file "$icfg" "DNSTM_TRANSPORT" || true)
      instance_pubkey=$(config_value_from_file "$icfg" "DNSTM_DNSTT_PUBKEY" || true)
      instance_cert=$(config_value_from_file "$icfg" "DNSTM_SLIPSTREAM_CERT" || true)
      [[ -n "$instance_transport" ]] || instance_transport="slipstream"

      if [[ "$target_core" != "dnstm" ]]; then
        instance_transport="slipstream"
        instance_pubkey=""
      elif [[ "$instance_transport" == "dnstt" && -z "$instance_pubkey" ]]; then
        warn "Instance '$instance_name' has DNSTT transport without pubkey. Falling back to slipstream."
        instance_transport="slipstream"
      fi
      set_config_value "DNSTM_TRANSPORT" "$instance_transport" "$icfg"
      set_config_value "DNSTM_DNSTT_PUBKEY" "$instance_pubkey" "$icfg"
      set_config_value "DNSTM_SLIPSTREAM_CERT" "$instance_cert" "$icfg"

      if [[ -n "$instance_domain" && -n "$instance_resolver" && -n "$instance_port" ]]; then
        write_instance_client_service "$instance_name" "$instance_resolver" "$instance_domain" "$instance_port" "$instance_transport" "$instance_cert" "$instance_pubkey"
        setup_instance_timers "$instance_name"
        instances_to_restart+=("$instance_name")
      fi
    done
    systemctl daemon-reload
    local restart_instance
    for restart_instance in "${instances_to_restart[@]}"; do
      restart_instance_stack "$restart_instance"
    done
  fi

  log "Core switch completed."
  cmd_status
}

cmd_auth_add() {
  need_root
  check_dependencies getent awk tr chpasswd usermod
  ensure_mode_server_or_error

  if ! core_supports_ssh_overlay; then
    local native_username="${1:-}" native_password
    if [[ -z "$native_username" ]]; then
      read -r -p "New SSH username (native dnstm mode): " native_username
    fi
    validate_unix_username_or_error "$native_username"
    native_password=$(prompt_password_twice "Password for ${native_username}")
    create_or_update_tunnel_user "$native_username" "$native_password"
    warn "Native dnstm mode: created SSH user '${native_username}'."
    warn "Use this user in DNSTT SSH app bridge prompts on clients."
    return 0
  fi

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

ensure_mode_server_dnstm_or_error() {
  ensure_mode_server_or_error
  [[ "${SLIPSTREAM_CORE:-}" == "dnstm" ]] || error "This action is available only when server core is 'dnstm'"
  dnstm_is_installed || error "dnstm binary is missing: $DNSTM_BIN"
}

cmd_dnstm_passthrough() {
  need_root
  ensure_mode_server_dnstm_or_error
  if [[ $# -eq 0 ]]; then
    "$DNSTM_BIN"
  else
    "$DNSTM_BIN" "$@"
  fi
}

prompt_instance_name_from_menu() {
  local instance=""
  read -r -p "Instance name: " instance
  if [[ -z "$instance" ]]; then
    warn "Instance name is required"
    return 1
  fi
  echo "$instance"
}

collect_client_tunnel_targets() {
  echo "default"
  if [[ -d "$INSTANCES_DIR" ]]; then
    local cfg
    for cfg in "$INSTANCES_DIR"/*/config; do
      [[ -f "$cfg" ]] || continue
      basename "$(dirname "$cfg")"
    done
  fi
}

tunnel_config_file_for_target() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    echo "$CONFIG_FILE"
  else
    instance_config_file "$target"
  fi
}

tunnel_service_name_for_target() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    echo "slipstream-client"
  else
    instance_client_service "$target"
  fi
}

cmd_tunnels_overview() {
  check_dependencies systemctl
  ensure_mode_client_or_error

  echo "=== Tunnel Overview ==="
  printf "%-12s %-8s %-10s %-6s %-11s %-15s %s\n" "Name" "Type" "Service" "Port" "Transport" "Resolver" "Domain"

  local target cfg service type state domain port resolver transport
  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    cfg=$(tunnel_config_file_for_target "$target")
    [[ -f "$cfg" ]] || continue
    service=$(tunnel_service_name_for_target "$target")
    state=$(service_state "$service")
    domain=$(config_value_from_file "$cfg" "DOMAIN" || echo "unknown")
    port=$(config_value_from_file "$cfg" "PORT" || echo "unknown")
    transport=$(config_value_from_file "$cfg" "DNSTM_TRANSPORT" || true)
    [[ -n "$transport" ]] || transport="slipstream"
    resolver=$(config_value_from_file "$cfg" "CURRENT_SERVER" || true)
    [[ -n "$resolver" ]] || resolver="-"
    if [[ "$target" == "default" ]]; then
      type="main"
    else
      type="extra"
    fi
    printf "%-12s %-8s %-10s %-6s %-11s %-15s %s\n" "$target" "$type" "$state" "$port" "$transport" "$resolver" "$domain"
  done < <(collect_client_tunnel_targets)
}

prompt_tunnel_target_from_menu() {
  local include_default="${1:-true}"
  local targets=() target cfg service state port resolver transport

  while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    if [[ "$include_default" != "true" && "$target" == "default" ]]; then
      continue
    fi
    targets+=("$target")
  done < <(collect_client_tunnel_targets)

  if [[ ${#targets[@]} -eq 0 ]]; then
    warn "No tunnel targets available" >&2
    return 1
  fi

  echo "Select tunnel target:" >&2
  local i=1
  for target in "${targets[@]}"; do
    cfg=$(tunnel_config_file_for_target "$target")
    service=$(tunnel_service_name_for_target "$target")
    state=$(service_state "$service")
    port=$(config_value_from_file "$cfg" "PORT" || echo "unknown")
    transport=$(config_value_from_file "$cfg" "DNSTM_TRANSPORT" || true)
    [[ -n "$transport" ]] || transport="slipstream"
    resolver=$(config_value_from_file "$cfg" "CURRENT_SERVER" || true)
    [[ -n "$resolver" ]] || resolver="-"
    printf " %2d) %-12s service=%-10s port=%-6s transport=%-10s resolver=%s\n" "$i" "$target" "$state" "$port" "$transport" "$resolver" >&2
    i=$((i + 1))
  done
  echo "  0) Cancel" >&2

  local choice=""
  while true; do
    read -r -p "Select tunnel [1]: " choice
    choice="${choice:-1}"
    [[ "$choice" =~ ^[0-9]+$ ]] || {
      warn "Invalid selection: $choice" >&2
      continue
    }
    [[ "$choice" == "0" ]] && return 1
    ((choice >= 1 && choice <= ${#targets[@]})) || {
      warn "Selection out of range: $choice" >&2
      continue
    }
    echo "${targets[$((choice - 1))]}"
    return 0
  done
}

cmd_tunnel_status() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_status
  else
    cmd_instance_status "$target"
  fi
}

cmd_tunnel_start() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_start
  else
    cmd_instance_start "$target"
  fi
}

cmd_tunnel_stop() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_stop
  else
    cmd_instance_stop "$target"
  fi
}

cmd_tunnel_restart() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_restart
  else
    cmd_instance_restart "$target"
  fi
}

cmd_tunnel_logs_follow() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_logs -f
  else
    cmd_instance_logs "$target" -f
  fi
}

cmd_tunnel_health() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_health
  else
    cmd_instance_health "$target"
  fi
}

cmd_tunnel_watchdog() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_watchdog
  else
    cmd_instance_watchdog "$target"
  fi
}

cmd_tunnel_servers() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_servers
  else
    cmd_instance_servers "$target"
  fi
}

cmd_tunnel_select_dns() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_select_server
  else
    cmd_instance_select_server "$target"
  fi
}

cmd_tunnel_rescan() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_rescan
  else
    cmd_instance_rescan "$target"
  fi
}

cmd_tunnel_edit() {
  local target="$1"
  if [[ "$target" == "default" ]]; then
    cmd_edit_client
  else
    cmd_instance_edit "$target"
  fi
}

cmd_menu_manage_single_tunnel() {
  local target="$1"
  while true; do
    echo ""
    echo "=== Tunnel Actions: $target ==="
    echo "1) Show tunnel status"
    echo "2) Start tunnel service"
    echo "3) Stop tunnel service"
    echo "4) Restart tunnel service"
    echo "5) Follow tunnel logs"
    echo "6) Run health check now"
    echo "7) Run runtime watchdog now"
    echo "8) Show DNS candidates"
    echo "9) Switch DNS resolver"
    echo "10) Run DNS rescan and switch best"
    echo "11) Edit tunnel settings"
    if [[ "$target" != "default" ]]; then
      echo "12) Delete this tunnel instance"
    fi
    echo "0) Back"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_tunnel_status "$target" ;;
    2) cmd_tunnel_start "$target" ;;
    3) cmd_tunnel_stop "$target" ;;
    4) cmd_tunnel_restart "$target" ;;
    5) cmd_tunnel_logs_follow "$target" ;;
    6) cmd_tunnel_health "$target" ;;
    7) cmd_tunnel_watchdog "$target" ;;
    8) cmd_tunnel_servers "$target" ;;
    9) cmd_tunnel_select_dns "$target" ;;
    10) cmd_tunnel_rescan "$target" ;;
    11) cmd_tunnel_edit "$target" ;;
    12)
      if [[ "$target" == "default" ]]; then
        warn "Default tunnel cannot be deleted"
        continue
      fi
      read -r -p "Delete instance '$target'? (y/n): " confirm_delete
      [[ "$confirm_delete" == "y" ]] || continue
      cmd_instance_del "$target"
      break
      ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client() {
  while true; do
    echo ""
    echo "=== Client Main Menu ==="
    echo "1) Show dashboard"
    echo "2) Monitoring submenu"
    echo "3) Tunnel service submenu"
    echo "4) Auth/profile submenu"
    echo "5) Manage tunnels (multi-instance)"
    echo "6) Uninstall everything"
    echo "0) Exit menu"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_dashboard ;;
    2) cmd_menu_client_monitor ;;
    3) cmd_menu_client_service ;;
    4) cmd_menu_client_auth ;;
    5) cmd_menu_client_instances ;;
    6)
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

cmd_menu_client_instances() {
  while true; do
    echo ""
    echo "=== Manage Tunnels Submenu ==="
    echo "1) Show all tunnels overview"
    echo "2) Manage one tunnel (main + instances)"
    echo "3) Add new tunnel instance"
    echo "4) List extra tunnel instances"
    echo "5) Delete one extra tunnel instance"
    echo "0) Back"
    read -r -p "Select: " choice

    local instance="" target=""
    case "$choice" in
    1) cmd_tunnels_overview ;;
    2)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_menu_manage_single_tunnel "$target"
      fi
      ;;
    3)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_add "$instance"
      fi
      ;;
    4) cmd_instance_list ;;
    5)
      if instance=$(prompt_instance_name_from_menu); then
        read -r -p "Delete instance '$instance'? (y/n): " confirm_delete
        [[ "$confirm_delete" == "y" ]] || continue
        cmd_instance_del "$instance"
      fi
      ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client_monitor() {
  while true; do
    echo ""
    echo "=== Client Monitoring Submenu ==="
    echo "1) Run health check now (choose tunnel)"
    echo "2) Run full DNS rescan now (choose tunnel)"
    echo "3) Show verified DNS IP list (choose tunnel)"
    echo "4) Select DNS manually from verified list (choose tunnel)"
    echo "5) Show status (choose tunnel)"
    echo "6) Show all tunnels overview"
    echo "0) Back"
    read -r -p "Select: " choice

    local target=""
    case "$choice" in
    1)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_health "$target"
      fi
      ;;
    2)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_rescan "$target"
      fi
      ;;
    3)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_servers "$target"
      fi
      ;;
    4)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_select_dns "$target"
      fi
      ;;
    5)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_status "$target"
      fi
      ;;
    6) cmd_tunnels_overview ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client_service() {
  while true; do
    echo ""
    echo "=== Client Service Submenu ==="
    echo "1) Start tunnel service (choose tunnel)"
    echo "2) Stop tunnel service (choose tunnel)"
    echo "3) Restart tunnel service (choose tunnel)"
    echo "4) Follow tunnel logs (choose tunnel)"
    echo "5) Show status (choose tunnel)"
    echo "6) Show all tunnels overview"
    echo "0) Back"
    read -r -p "Select: " choice

    local target=""
    case "$choice" in
    1)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_start "$target"
      fi
      ;;
    2)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_stop "$target"
      fi
      ;;
    3)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_restart "$target"
      fi
      ;;
    4)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_logs_follow "$target"
      fi
      ;;
    5)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_status "$target"
      fi
      ;;
    6) cmd_tunnels_overview ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client_dnstm() {
  while true; do
    echo ""
    echo "=== Client DNSTM Submenu ==="
    echo "1) Show all tunnels overview (with transport)"
    echo "2) Edit one tunnel transport/profile"
    echo "3) Run DNS rescan for one tunnel"
    echo "4) Show one tunnel status"
    echo "0) Back"
    read -r -p "Select: " choice

    local target=""
    case "$choice" in
    1) cmd_tunnels_overview ;;
    2)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_edit "$target"
      fi
      ;;
    3)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_rescan "$target"
      fi
      ;;
    4)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_status "$target"
      fi
      ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client_auth() {
  while true; do
    echo ""
    echo "=== Client Auth/Profile Submenu ==="
    echo "1) Enable client SSH auth overlay (main tunnel)"
    echo "2) Disable client SSH auth overlay (main tunnel)"
    echo "3) Set speed profile secure (main tunnel)"
    echo "4) Set speed profile fast (main tunnel)"
    echo "5) Show speed profile status (main tunnel)"
    echo "6) Switch core (dnstm/nightowl/plus, shared client binary)"
    echo "7) Edit one tunnel settings (main + instances)"
    echo "8) DNSTM transport/profile submenu (all tunnels)"
    echo "0) Back"
    read -r -p "Select: " choice

    local target=""
    case "$choice" in
    1) cmd_client_auth_enable ;;
    2) cmd_client_auth_disable ;;
    3) cmd_speed_profile secure ;;
    4) cmd_speed_profile fast ;;
    5) cmd_speed_profile status ;;
    6) cmd_core_switch ;;
    7)
      if target=$(prompt_tunnel_target_from_menu true); then
        cmd_tunnel_edit "$target"
      fi
      ;;
    8) cmd_menu_client_dnstm ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_server_dnstm() {
  ensure_mode_server_dnstm_or_error
  while true; do
    echo ""
    echo "=== Server Native DNSTM Submenu ==="
    echo "1) Router status"
    echo "2) Router start/restart"
    echo "3) Router stop"
    echo "4) Router logs (last 120 lines)"
    echo "5) Switch router mode (single/multi)"
    echo "6) Switch active tunnel (single mode)"
    echo "7) List tunnels"
    echo "8) Add tunnel"
    echo "9) Tunnel status"
    echo "10) Tunnel logs"
    echo "11) Tunnel start"
    echo "12) Tunnel stop"
    echo "13) Tunnel restart"
    echo "14) Tunnel remove"
    echo "15) List backends"
    echo "16) Available backend types"
    echo "17) Add custom backend"
    echo "18) Add shadowsocks backend"
    echo "19) Backend status"
    echo "20) Backend remove"
    echo "21) SSH users manager"
    echo "22) Run dnstm update --force"
    echo "0) Back"
    read -r -p "Select: " choice

    local tag="" mode="" transport="" backend="" domain="" port="" mtu="" address="" password="" method=""
    case "$choice" in
    1) run_dnstm router status ;;
    2) run_dnstm router start ;;
    3) run_dnstm router stop ;;
    4) run_dnstm router logs -n 120 ;;
    5)
      read -r -p "Router mode [single/multi]: " mode
      [[ "$mode" == "single" || "$mode" == "multi" ]] || {
        warn "Invalid mode: $mode"
        continue
      }
      run_dnstm router mode "$mode"
      set_config_value "DNSTM_MODE" "$mode" "$CONFIG_FILE"
      ;;
    6)
      read -r -p "Tunnel tag: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      run_dnstm router switch -t "$tag"
      set_config_value "DNSTM_TUNNEL_TAG" "$tag" "$CONFIG_FILE"
      ;;
    7) run_dnstm tunnel list ;;
    8)
      read -r -p "Transport [slipstream/dnstt]: " transport
      [[ "$transport" == "slipstream" || "$transport" == "dnstt" ]] || {
        warn "Invalid transport: $transport"
        continue
      }
      read -r -p "Backend tag: " backend
      [[ -n "$backend" ]] || {
        warn "Backend tag is required"
        continue
      }
      read -r -p "Domain: " domain
      [[ -n "$domain" ]] || {
        warn "Domain is required"
        continue
      }
      validate_domain_or_error "$domain"
      read -r -p "Tunnel tag (Enter for auto): " tag
      read -r -p "Internal tunnel port (Enter for auto): " port
      read -r -p "MTU (dnstt only, Enter for default): " mtu
      local add_args=(tunnel add --transport "$transport" --backend "$backend" --domain "$domain")
      [[ -n "$tag" ]] && add_args+=(-t "$tag")
      [[ -n "$port" ]] && add_args+=(-p "$port")
      [[ -n "$mtu" ]] && add_args+=(--mtu "$mtu")
      run_dnstm "${add_args[@]}"
      [[ -n "$tag" ]] && set_config_value "DNSTM_TUNNEL_TAG" "$tag" "$CONFIG_FILE"
      set_config_value "DNSTM_TRANSPORT" "$transport" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TAG" "$backend" "$CONFIG_FILE"
      ;;
    9)
      read -r -p "Tunnel tag: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      run_dnstm tunnel status -t "$tag"
      ;;
    10)
      read -r -p "Tunnel tag: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      run_dnstm tunnel logs -t "$tag" -n 120
      ;;
    11)
      read -r -p "Tunnel tag: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      run_dnstm tunnel start -t "$tag"
      ;;
    12)
      read -r -p "Tunnel tag: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      run_dnstm tunnel stop -t "$tag"
      ;;
    13)
      read -r -p "Tunnel tag: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      run_dnstm tunnel restart -t "$tag"
      ;;
    14)
      read -r -p "Tunnel tag to remove: " tag
      [[ -n "$tag" ]] || {
        warn "Tunnel tag is required"
        continue
      }
      read -r -p "Confirm remove tunnel '$tag' (y/n): " confirm_remove
      [[ "$confirm_remove" == "y" ]] || continue
      run_dnstm tunnel remove -t "$tag" --force
      ;;
    15) run_dnstm backend list ;;
    16) run_dnstm backend available ;;
    17)
      read -r -p "Backend tag: " tag
      [[ -n "$tag" ]] || {
        warn "Backend tag is required"
        continue
      }
      read -r -p "Custom target address (host:port): " address
      [[ -n "$address" ]] || {
        warn "Address is required"
        continue
      }
      run_dnstm backend add --type custom -t "$tag" --address "$address"
      set_config_value "DNSTM_BACKEND_TAG" "$tag" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TYPE" "custom" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_ADDRESS" "$address" "$CONFIG_FILE"
      ;;
    18)
      read -r -p "Backend tag: " tag
      [[ -n "$tag" ]] || {
        warn "Backend tag is required"
        continue
      }
      read -r -p "Method [aes-256-gcm]: " method
      method="${method:-aes-256-gcm}"
      read -r -p "Password (Enter to auto-generate): " password
      if [[ -n "$password" ]]; then
        run_dnstm backend add --type shadowsocks -t "$tag" --method "$method" --password "$password"
      else
        run_dnstm backend add --type shadowsocks -t "$tag" --method "$method"
      fi
      set_config_value "DNSTM_BACKEND_TAG" "$tag" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_TYPE" "shadowsocks" "$CONFIG_FILE"
      set_config_value "DNSTM_BACKEND_ADDRESS" "managed-by-dnstm" "$CONFIG_FILE"
      ;;
    19)
      read -r -p "Backend tag: " tag
      [[ -n "$tag" ]] || {
        warn "Backend tag is required"
        continue
      }
      run_dnstm backend status -t "$tag"
      ;;
    20)
      read -r -p "Backend tag to remove: " tag
      [[ -n "$tag" ]] || {
        warn "Backend tag is required"
        continue
      }
      read -r -p "Confirm remove backend '$tag' (y/n): " confirm_remove
      [[ "$confirm_remove" == "y" ]] || continue
      run_dnstm backend remove -t "$tag" --force
      ;;
    21) run_dnstm ssh-users ;;
    22) run_dnstm update --force ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_server() {
  while true; do
    echo ""
    echo "=== Server Main Menu ==="
    echo "1) Show status"
    echo "2) Tunnel service submenu"
    echo "3) SSH/auth submenu"
    echo "4) Native dnstm manager"
    echo "5) Uninstall everything"
    echo "0) Exit menu"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_status ;;
    2) cmd_menu_server_service ;;
    3) cmd_menu_server_auth ;;
    4)
      if [[ "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
        cmd_menu_server_dnstm
      else
        warn "Native dnstm manager is available only when core is 'dnstm'."
      fi
      ;;
    5)
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

cmd_menu_server_service() {
  while true; do
    echo ""
    echo "=== Server Service Submenu ==="
    echo "1) Start server tunnel service"
    echo "2) Stop server tunnel service"
    echo "3) Restart server tunnel service"
    echo "4) Follow server logs"
    echo "5) Edit server settings (domain/port)"
    echo "6) Show status"
    echo "0) Back"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_start ;;
    2) cmd_stop ;;
    3) cmd_restart ;;
    4) cmd_logs -f ;;
    5) cmd_edit_server ;;
    6) cmd_status ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_server_auth() {
  while true; do
    echo ""
    if [[ "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
      ensure_mode_server_dnstm_or_error
      echo "=== Server Auth Submenu (dnstm native) ==="
      echo "1) Open dnstm SSH users manager"
      echo "2) Open native dnstm manager submenu"
      echo "3) Switch core (dnstm/nightowl/plus)"
      echo "0) Back"
      read -r -p "Select: " choice

      case "$choice" in
      1) run_dnstm ssh-users ;;
      2) cmd_menu_server_dnstm ;;
      3) cmd_core_switch ;;
      0) break ;;
      *) warn "Invalid option: $choice" ;;
      esac
    else
      echo "=== Server SSH/Auth Submenu ==="
      echo "1) Add SSH tunnel user"
      echo "2) Change SSH tunnel user password"
      echo "3) Delete SSH tunnel user"
      echo "4) List SSH tunnel users"
      echo "5) Enable/update SSH auth overlay"
      echo "6) Disable SSH auth overlay"
      echo "7) Set speed profile secure"
      echo "8) Set speed profile fast"
      echo "9) Show speed profile status"
      echo "10) Switch core (dnstm/nightowl/plus)"
      echo "0) Back"
      read -r -p "Select: " choice

      case "$choice" in
      1) cmd_auth_add ;;
      2) cmd_auth_passwd ;;
      3) cmd_auth_del ;;
      4) cmd_auth_list ;;
      5) cmd_auth_setup ;;
      6) cmd_auth_disable ;;
      7) cmd_speed_profile secure ;;
      8) cmd_speed_profile fast ;;
      9) cmd_speed_profile status ;;
      10) cmd_core_switch ;;
      0) break ;;
      *) warn "Invalid option: $choice" ;;
      esac
    fi
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

resolver_answers_dns_queries() {
  local server="$1"
  command -v dig &>/dev/null || return 0
  dig +short +time=2 +tries=1 "@$server" . NS &>/dev/null
}

resolver_supports_tunnel_domain() {
  local server="$1" domain="$2"
  local out status
  command -v dig &>/dev/null || return 0
  out=$(dig +time=2 +tries=1 "@$server" "$domain" TXT 2>&1 || true)
  if printf '%s\n' "$out" | grep -Eq 'no servers could be reached|communications error|connection timed out|network is unreachable'; then
    return 1
  fi
  if printf '%s\n' "$out" | grep -q 'EDE: 22 (No Reachable Authority)'; then
    return 1
  fi
  status=$(printf '%s\n' "$out" | awk -F'status: ' '/status: /{split($2,a,","); print a[1]; exit}')
  case "$status" in
  NOERROR | NXDOMAIN) return 0 ;;
  *) return 1 ;;
  esac
}

pick_probe_port() {
  local attempt port
  for attempt in {1..40}; do
    port=$((20000 + (RANDOM % 25000)))
    if command -v ss &>/dev/null; then
      if ! ss -lntH "sport = :$port" 2>/dev/null | grep -q .; then
        echo "$port"
        return 0
      fi
    else
      echo "$port"
      return 0
    fi
  done
  return 1
}

probe_tunnel_data_path() {
  local server="$1" domain="$2"
  local transport="${3:-${DNSTM_TRANSPORT:-slipstream}}"
  local dnstt_pubkey="${4:-${DNSTM_DNSTT_PUBKEY:-}}"
  local slipstream_cert="${5:-${DNSTM_SLIPSTREAM_CERT:-}}"
  local dnstt_bind_host="${6:-${DNSTT_BIND_HOST:-127.0.0.1}}"
  local probe_port probe_log probe_pid=0 listening=0
  local -a cmd=()

  validate_transport_or_error "$transport"

  probe_port=$(pick_probe_port) || return 1
  probe_log=$(mktemp /tmp/slipstream-path-probe.XXXXXX.log)

  if [[ "$transport" == "dnstt" ]]; then
    [[ -x "$DNSTT_CLIENT_BIN" ]] || {
      rm -f "$probe_log"
      return 1
    }
    [[ -n "$dnstt_pubkey" ]] || {
      rm -f "$probe_log"
      return 1
    }
    cmd=("$DNSTT_CLIENT_BIN" -udp "${server}:53" -pubkey "$dnstt_pubkey" "$domain" "127.0.0.1:${probe_port}")
  else
    [[ -x "$SLIPSTREAM_CLIENT_BIN" ]] || {
      rm -f "$probe_log"
      return 1
    }
    cmd=("$SLIPSTREAM_CLIENT_BIN" --resolver "${server}:53" --domain "$domain" --tcp-listen-port "$probe_port")
    [[ -n "$slipstream_cert" ]] && cmd+=(--cert "$slipstream_cert")
  fi

  "${cmd[@]}" >"$probe_log" 2>&1 &
  probe_pid=$!

  for _ in {1..40}; do
    if ! kill -0 "$probe_pid" 2>/dev/null; then
      break
    fi
    if ss -lntH "sport = :$probe_port" 2>/dev/null | grep -q .; then
      listening=1
      break
    fi
    sleep 0.2
  done

  if ((listening == 1)); then
    for _ in {1..2}; do
      if command -v timeout &>/dev/null; then
        timeout 2 bash -lc "exec 3<>/dev/tcp/127.0.0.1/${probe_port}; printf 'probe' >&3; sleep 0.2; exec 3<&-; exec 3>&-" >/dev/null 2>&1 || true
      else
        bash -lc "exec 3<>/dev/tcp/127.0.0.1/${probe_port}; printf 'probe' >&3; sleep 0.2; exec 3<&-; exec 3>&-" >/dev/null 2>&1 || true
      fi
      sleep 0.2
    done
  fi
  sleep 1

  local ok=1
  if ((listening == 0)); then
    ok=0
  elif [[ "$transport" == "dnstt" ]]; then
    grep -q 'begin session' "$probe_log" || ok=0
    grep -Eq 'begin stream|end stream' "$probe_log" || ok=0
    grep -q 'io: read/write on closed pipe' "$probe_log" && ok=0
  else
    grep -q 'Connection ready' "$probe_log" || ok=0
    if grep -Eq 'Path for resolver .* became unavailable|Connection closed; reconnecting|ERROR connection flow blocked|WATCHDOG: main loop stalled' "$probe_log"; then
      ok=0
    fi
  fi

  if ((probe_pid > 0)) && kill -0 "$probe_pid" 2>/dev/null; then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
  fi
  rm -f "$probe_log"

  ((ok == 1))
}

test_dns_latency() {
  local server="$1" domain="$2"
  local start end
  start=$(date +%s%N)
  if resolver_supports_tunnel_domain "$server" "$domain"; then
    end=$(date +%s%N)
    echo $(((end - start) / 1000000))
  else
    echo "9999"
  fi
}

setup_health_timer_named() {
  local service_name="$1" timer_name="$2" exec_command="$3"
  local unit_dir="/etc/systemd/system"

  if [[ ! -d "$unit_dir" || ! -w "$unit_dir" ]]; then
    warn "Skipping health timer unit setup: $unit_dir is not writable"
    return 0
  fi

  cat >"${unit_dir}/${service_name}.service" <<EOF
[Unit]
Description=DNS Tunnel Health Check (${service_name})
After=network.target

[Service]
Type=oneshot
ExecStart=$exec_command
EOF

  cat >"${unit_dir}/${timer_name}" <<EOF
[Unit]
Description=DNS Tunnel Health Check Timer (${timer_name})

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable "$timer_name"
  systemctl start "$timer_name"
}

setup_health_timer() {
  setup_health_timer_named "tunnel-health" "tunnel-health.timer" "$TUNNEL_CMD_BIN health"
  log "Health check timer installed (runs every 5 minutes)"
}

setup_watchdog_timer_named() {
  local service_name="$1" timer_name="$2" exec_command="$3"
  local unit_dir="/etc/systemd/system"

  if [[ ! -d "$unit_dir" || ! -w "$unit_dir" ]]; then
    warn "Skipping runtime watchdog unit setup: $unit_dir is not writable"
    return 0
  fi

  cat >"${unit_dir}/${service_name}.service" <<EOF
[Unit]
Description=DNS Tunnel Runtime Watchdog (${service_name})
After=network.target

[Service]
Type=oneshot
ExecStart=$exec_command
EOF

  cat >"${unit_dir}/${timer_name}" <<EOF
[Unit]
Description=DNS Tunnel Runtime Watchdog Timer (${timer_name})

[Timer]
OnBootSec=90s
OnUnitActiveSec=30s
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable "$timer_name"
  systemctl start "$timer_name"
}

setup_watchdog_timer() {
  setup_watchdog_timer_named "tunnel-watchdog" "tunnel-watchdog.timer" "$TUNNEL_CMD_BIN watchdog"
  log "Runtime watchdog timer installed (runs every 30 seconds)"
}

# ============================================
# LOGS
# ============================================
cmd_logs() {
  check_dependencies journalctl
  load_config_or_error

  local follow=false
  [[ "${1:-}" == "-f" ]] && follow=true

  if [[ "${MODE:-}" == "client" ]] && client_ssh_auth_enabled; then
    if $follow; then
      journalctl -u slipstream-client -u "${SSH_CLIENT_SERVICE}" -f
    else
      journalctl -u slipstream-client -u "${SSH_CLIENT_SERVICE}" -n 100 --no-pager
    fi
    return
  fi

  if [[ "${MODE:-}" == "server" && "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
    if $follow; then
      journalctl -u dnstm-dnsrouter -f
    else
      run_dnstm router logs -n 100 || journalctl -u dnstm-dnsrouter -n 100 --no-pager
    fi
    return
  fi

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
    [[ -n "${SLIPSTREAM_CORE:-}" ]] && echo "Core: ${SLIPSTREAM_CORE}"
    if [[ -n "${SLIPSTREAM_REPO:-}" && -n "${SLIPSTREAM_VERSION:-}" ]]; then
      echo "Core source: ${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION}"
    fi
    if [[ "${MODE:-}" == "server" && "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
      echo "Native manager: dnstm (${DNSTM_REPO:-$DNSTM_REPO}@${DNSTM_VERSION:-$DNSTM_VERSION})"
      [[ -n "${DNSTM_MODE:-}" ]] && echo "DNSTM mode: ${DNSTM_MODE}"
      [[ -n "${DNSTM_TRANSPORT:-}" ]] && echo "DNSTM transport: ${DNSTM_TRANSPORT}"
      [[ -n "${DNSTM_BACKEND_TAG:-}" ]] && echo "DNSTM backend: ${DNSTM_BACKEND_TAG} (${DNSTM_BACKEND_TYPE:-unknown})"
      [[ -n "${DNSTM_TUNNEL_TAG:-}" ]] && echo "DNSTM tunnel tag: ${DNSTM_TUNNEL_TAG}"
    elif [[ "${MODE:-}" == "client" ]]; then
    echo "Client transport: ${DNSTM_TRANSPORT:-slipstream}"
    if [[ "${DNSTM_TRANSPORT:-slipstream}" == "dnstt" ]]; then
      [[ -n "${DNSTM_DNSTT_PUBKEY:-}" ]] && echo "DNSTT pubkey: ${DNSTM_DNSTT_PUBKEY:0:12}..."
      echo "DNSTT bind host: ${DNSTT_BIND_HOST:-127.0.0.1}"
    elif [[ -n "${DNSTM_SLIPSTREAM_CERT:-}" ]]; then
        echo "Pinned cert: ${DNSTM_SLIPSTREAM_CERT}"
      fi
    fi
    [[ -n "${CURRENT_SERVER:-}" ]] && echo "Current DNS: $CURRENT_SERVER"
    if core_supports_ssh_overlay; then
      if [[ "${MODE:-}" == "server" ]]; then
        echo "SSH auth overlay: ${SSH_AUTH_ENABLED:-false}"
      else
        echo "SSH auth overlay: ${SSH_AUTH_ENABLED:-false}"
        [[ -n "${SSH_AUTH_USER:-}" ]] && echo "SSH user: $SSH_AUTH_USER"
      fi
    else
      echo "SSH auth overlay: n/a on core ${SLIPSTREAM_CORE}"
    fi
  else
    echo "Not configured"
    return
  fi

  echo ""
  echo "Services:"
  if [[ "${MODE:-}" == "server" ]]; then
    if [[ "${SLIPSTREAM_CORE:-}" == "dnstm" ]]; then
      echo "  dnstm manager: $(if dnstm_is_installed; then echo "installed"; else echo "missing"; fi)"
      if dnstm_is_installed; then
        local router_mode backend_tag tunnel_tag transport
        router_mode="${DNSTM_MODE:-unknown}"
        backend_tag="${DNSTM_BACKEND_TAG:-unknown}"
        tunnel_tag="${DNSTM_TUNNEL_TAG:-unknown}"
        transport="${DNSTM_TRANSPORT:-unknown}"
        echo "  dnstm mode: $router_mode"
        echo "  native tunnel: $tunnel_tag (transport=$transport, backend=$backend_tag)"
        echo ""
        echo "Native router snapshot:"
        run_dnstm router status | sed 's/^/  /' || warn "Could not query dnstm router status"
      fi
    else
      local status
      status=$(service_state "slipstream-server")
      echo "  slipstream-server: $status"
    fi
    if core_supports_ssh_overlay && [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && command -v getent &>/dev/null; then
      local ssh_users
      ssh_users=$(ssh_group_users | tr '\n' ',' | sed 's/,$//')
      [[ -z "$ssh_users" ]] && ssh_users="none"
      echo "  ssh-auth users: $ssh_users"
    fi
  else
    local status
    status=$(service_state "slipstream-client")
    echo "  slipstream-client: $status"
    if core_supports_ssh_overlay && client_ssh_auth_enabled; then
      local ssh_status
      ssh_status=$(service_state "${SSH_CLIENT_SERVICE}")
      echo "  ${SSH_CLIENT_SERVICE}: $ssh_status"
    fi
  fi

  # Health timer only relevant for client
  if [[ "${MODE:-}" == "client" ]]; then
    echo ""
    if systemctl list-unit-files tunnel-health.timer &>/dev/null; then
      echo "Health timer: $(service_state "tunnel-health.timer")"
    else
      echo "Health timer: not installed"
    fi
    if systemctl list-unit-files tunnel-watchdog.timer &>/dev/null; then
      echo "Runtime watchdog: $(service_state "tunnel-watchdog.timer")"
    else
      echo "Runtime watchdog: not installed"
    fi

    if [[ -f "$HEALTH_LOG" ]]; then
      echo ""
      echo "Recent health checks:"
      tail -5 "$HEALTH_LOG" | sed 's/^/  /'
    fi

    if [[ -d "$INSTANCES_DIR" ]]; then
      local cfg instance extra_count
      extra_count=0
      for cfg in "$INSTANCES_DIR"/*/config; do
        [[ -f "$cfg" ]] || continue
        extra_count=$((extra_count + 1))
      done
      if ((extra_count > 0)); then
        echo ""
        echo "Extra client instances:"
        local extra_transport
        for cfg in "$INSTANCES_DIR"/*/config; do
          [[ -f "$cfg" ]] || continue
          instance=$(basename "$(dirname "$cfg")")
          extra_transport=$(config_value_from_file "$cfg" "DNSTM_TRANSPORT" || true)
          [[ -n "$extra_transport" ]] || extra_transport="slipstream"
          echo "  $instance: $(service_state "$(instance_client_service "$instance")"), transport=$extra_transport"
        done
      fi
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

  local configured_mode="" configured_core=""
  configured_mode=$(config_value_from_file "$CONFIG_FILE" "MODE" || true)
  configured_core=$(config_value_from_file "$CONFIG_FILE" "SLIPSTREAM_CORE" || true)
  if [[ "$configured_mode" == "server" && "$configured_core" == "dnstm" && -x "$DNSTM_BIN" ]]; then
    log "Uninstalling native dnstm components..."
    "$DNSTM_BIN" uninstall --force >/dev/null 2>&1 || warn "dnstm uninstall reported an error; continuing with cleanup"
  fi

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

  if [[ -f "$DNSTM_BIN" ]]; then
    log "Removing dnstm binary..."
    rm -f "$DNSTM_BIN"
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
  if [[ -f /etc/systemd/system/tunnel-watchdog.timer ]]; then
    log "Removing runtime watchdog timer..."
    systemctl stop tunnel-watchdog.timer 2>/dev/null || true
    systemctl disable tunnel-watchdog.timer 2>/dev/null || true
    rm -f /etc/systemd/system/tunnel-watchdog.timer
    rm -f /etc/systemd/system/tunnel-watchdog.service
  fi

  local unit
  for unit in /etc/systemd/system/slipstream-client-*.service; do
    [[ -f "$unit" ]] || continue
    local svc
    svc=$(basename "$unit" .service)
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "$unit"
  done
  for unit in /etc/systemd/system/tunnel-health-*.service /etc/systemd/system/tunnel-watchdog-*.service; do
    [[ -f "$unit" ]] || continue
    rm -f "$unit"
  done
  for unit in /etc/systemd/system/tunnel-health-*.timer /etc/systemd/system/tunnel-watchdog-*.timer; do
    [[ -f "$unit" ]] || continue
    local timer_name
    timer_name=$(basename "$unit")
    systemctl stop "$timer_name" 2>/dev/null || true
    systemctl disable "$timer_name" 2>/dev/null || true
    rm -f "$unit"
  done

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
    read -r -p "Restore resolver config from backup? (y/n): " restore_resolver
    if [[ "$restore_resolver" == "y" ]]; then
      restore_resolver_if_backed_up
    fi
  fi

  if ! systemctl is-active systemd-resolved &>/dev/null; then
    read -r -p "Re-enable systemd-resolved service? (y/n): " restore_resolved
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
  if [[ -d "$WATCHDOG_STATE_DIR" ]]; then
    rm -rf "$WATCHDOG_STATE_DIR"
  fi

  log "Cleanup complete"
}

# ============================================
# MAIN
# ============================================
main() {
  [[ $# -eq 0 ]] && usage
  set_slipstream_source "$SLIPSTREAM_CORE"

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
  watchdog) cmd_watchdog ;;
  instance-add)
    shift
    cmd_instance_add "${1:-}"
    ;;
  instance-list) cmd_instance_list ;;
  instance-status)
    shift
    cmd_instance_status "${1:-}"
    ;;
  instance-start)
    shift
    cmd_instance_start "${1:-}"
    ;;
  instance-stop)
    shift
    cmd_instance_stop "${1:-}"
    ;;
  instance-restart)
    shift
    cmd_instance_restart "${1:-}"
    ;;
  instance-logs)
    shift
    cmd_instance_logs "${1:-}" "${2:-}"
    ;;
  instance-servers)
    shift
    cmd_instance_servers "${1:-}"
    ;;
  instance-select | instance-select-server)
    shift
    cmd_instance_select_server "${1:-}"
    ;;
  instance-rescan)
    shift
    cmd_instance_rescan "${1:-}"
    ;;
  instance-edit)
    shift
    cmd_instance_edit "${1:-}"
    ;;
  instance-del)
    shift
    cmd_instance_del "${1:-}"
    ;;
  instance-health)
    shift
    cmd_instance_health "${1:-}"
    ;;
  instance-watchdog)
    shift
    cmd_instance_watchdog "${1:-}"
    ;;
  rescan) cmd_rescan ;;
  dashboard) cmd_dashboard ;;
  servers) cmd_servers ;;
  menu | m) cmd_menu ;;
  speed-profile)
    shift
    cmd_speed_profile "${1:-status}"
    ;;
  core-switch)
    shift
    cmd_core_switch "${1:-}"
    ;;
  dnstm)
    shift
    cmd_dnstm_passthrough "$@"
    ;;
  auth-setup) cmd_auth_setup ;;
  auth-disable) cmd_auth_disable ;;
  auth-client-enable) cmd_client_auth_enable ;;
  auth-client-disable) cmd_client_auth_disable ;;
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
