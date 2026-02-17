#!/usr/bin/env bash
# DNS Tunnel Setup - Automated slipstream tunnel configuration
set -euo pipefail
# systemd units may run without HOME; keep script safe under `set -u`.
HOME="${HOME:-/root}"

# =============================================================================
# Release source configuration (pinned versions)
# =============================================================================
SLIPSTREAM_CORE="${SLIPSTREAM_CORE:-nightowl}"
SLIPSTREAM_REPO_OVERRIDE="${SLIPSTREAM_REPO:-}"
SLIPSTREAM_VERSION_OVERRIDE="${SLIPSTREAM_VERSION:-}"
SLIPSTREAM_ASSET_LAYOUT_OVERRIDE="${SLIPSTREAM_ASSET_LAYOUT:-}"
SLIPSTREAM_REPO=""
SLIPSTREAM_VERSION=""
SLIPSTREAM_ASSET_LAYOUT=""
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
  instance-del        Delete one extra client instance
  menu                Open interactive monitor menu (server/client)
  m                   Short alias for menu
  speed-profile       Set profile: fast (SSH off) / secure (SSH on)
  core-switch         Switch current mode to another core (nightowl/plus)
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
  --core <name>       Slipstream core source: nightowl (default) or plus
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
  slipstream-tunnel watchdog
  slipstream-tunnel rescan
  slipstream-tunnel servers
  slipstream-tunnel instance-add dubai
  slipstream-tunnel instance-list
  slipstream-tunnel instance-status dubai
  slipstream-tunnel menu
  slipstream-tunnel speed-profile fast
  slipstream-tunnel core-switch plus
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
  local core="${1:-nightowl}"
  local default_repo default_version default_layout

  case "$core" in
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
    error "Unknown core '$core'. Valid values: nightowl, plus"
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

prompt_core_choice() {
  local current="${1:-nightowl}" input
  while true; do
    printf '\n' >&2
    printf 'Select slipstream core:\n' >&2
    printf '  1) nightowl (stable)\n' >&2
    printf '  2) plus (faster, experimental)\n' >&2
    if [[ "$current" == "plus" ]]; then
      read -r -p "Choice [2]: " input
      input="${input:-2}"
    else
      read -r -p "Choice [1]: " input
      input="${input:-1}"
    fi
    case "$input" in
    1 | nightowl) echo "nightowl"; return 0 ;;
    2 | plus) echo "plus"; return 0 ;;
    *) printf '[!] Invalid choice: %s\n' "$input" >&2 ;;
    esac
  done
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
  elif [[ -r /dev/tty ]]; then
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

load_instance_config_or_error() {
  local name="$1"
  local cfg
  cfg=$(instance_config_file "$name")
  [[ -f "$cfg" ]] || error "No such instance: $name"
  # shellcheck disable=SC1090
  source "$cfg"
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
ExecStart=/bin/bash -lc 'raw="\$SSH_TUNNEL_PASS_B64"; cleaned="\$(printf "%%s" "\$raw" | tr -d " \t\r\n")"; pass="\$(printf "%%s" "\$cleaned" | base64 -d 2>/dev/null || true)"; [[ -n "\$pass" ]] || pass="\$raw"; SSHPASS="\$pass" exec sshpass -e ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -o ServerAliveCountMax=3 -o TCPKeepAlive=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$SSH_CLIENT_ENV_DIR/known_hosts -L \${SSH_LOCAL_BIND_ADDR}:\${SSH_LOCAL_PORT}:127.0.0.1:\${SSH_REMOTE_APP_PORT} -p \${SSH_TRANSPORT_PORT} \${SSH_TUNNEL_USER}@127.0.0.1'
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
    -h | --help)
      usage
      ;;
    *)
      error "Unknown option for server: $1"
      ;;
    esac
  done

  if [[ "$core_from_flag" == false && -t 0 ]]; then
    slipstream_core=$(prompt_core_choice "nightowl")
  fi
  set_slipstream_source "$slipstream_core"
  validate_port_or_error "$port"
  validate_port_or_error "$ssh_backend_port"
  [[ -n "$domain" ]] && validate_domain_or_error "$domain"

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
  echo "  slipstream-tunnel core-switch [nightowl|plus]"
  echo "  slipstream-tunnel auth-list"
  echo "  slipstream-tunnel menu"
  echo "  sst"
  echo "  journalctl -u slipstream-server -f"
}

write_client_service_named() {
  local service_name="$1" resolver="$2" domain="$3" port="$4"
  local bin_path="$SLIPSTREAM_CLIENT_BIN"

  cat >"/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=Slipstream DNS Tunnel Client (${service_name})
After=network.target
StartLimitIntervalSec=0

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
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
}

write_client_service() {
  local resolver="$1" domain="$2" port="$3"
  write_client_service_named "slipstream-client" "$resolver" "$domain" "$port"
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
  local slipstream_core="$SLIPSTREAM_CORE"
  local core_from_flag=false
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
    slipstream_core=$(prompt_core_choice "nightowl")
  fi
  set_slipstream_source "$slipstream_core"
  [[ -n "$domain" ]] && validate_domain_or_error "$domain"
  [[ -n "$dns_file" ]] && validate_dns_file_or_error "$dns_file"

  log "=== Slipstream Client Setup ==="
  log "Core source: ${SLIPSTREAM_CORE} (${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION}, layout=${SLIPSTREAM_ASSET_LAYOUT})"
  enable_bbr_if_possible

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
  local slipstream_asset
  slipstream_asset=$(slipstream_asset_name "client" "$arch")

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
    if download_slipstream_component "client" "$slipstream_bin" "$arch"; then
      :
    else
      echo ""
      warn "Cannot download slipstream-client (network blocked?)"
      echo ""
      echo "Transfer this asset from a non-blocked network:"
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
  echo "  slipstream-tunnel core-switch [nightowl|plus]"
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

  if ! systemctl is-active --quiet "$service_name"; then
    echo "$service_name service not active"
    return 0
  fi
  if ! ss -lntH "sport = :$listen_port" 2>/dev/null | grep -q .; then
    echo "client listen port $listen_port is not open"
    return 0
  fi
  if journalctl -u "$service_name" --since "$lookback" --no-pager -l | grep -Eq \
    'WATCHDOG: main loop stalled|ERROR connection flow blocked'; then
    echo "recent watchdog/flow-blocked runtime errors detected"
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
    if restart_client_stack; then
      echo "[$timestamp] Self-heal restart completed" >>"$HEALTH_LOG"
      sleep 2
    else
      echo "[$timestamp] ERROR: self-heal restart failed" >>"$HEALTH_LOG"
    fi
  fi

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
  service_status=$(service_state "slipstream-client")
  timer_status=$(service_state "tunnel-health.timer")
  ssh_status="disabled"
  if client_ssh_auth_enabled; then
    ssh_status=$(service_state "${SSH_CLIENT_SERVICE}")
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

ensure_instance_client_binary() {
  if [[ -x "$SLIPSTREAM_CLIENT_BIN" ]]; then
    return 0
  fi
  local arch
  arch=$(detect_arch)
  log "slipstream-client binary not found; installing ${SLIPSTREAM_CORE} core..."
  download_slipstream_component "client" "$SLIPSTREAM_CLIENT_BIN" "$arch" \
    || error "Failed to download slipstream-client binary"
  chmod +x "$SLIPSTREAM_CLIENT_BIN"
}

write_instance_client_service() {
  local instance="$1" resolver="$2" domain="$3" port="$4"
  local service_name
  service_name=$(instance_client_service "$instance")
  write_client_service_named "$service_name" "$resolver" "$domain" "$port"
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
  local service_name health_timer watchdog_timer
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  systemctl enable "$service_name"
  start_named_client_stack "$service_name"
  systemctl start "$health_timer" || true
  systemctl start "$watchdog_timer" || true
}

stop_instance_stack() {
  local instance="$1"
  local service_name health_timer watchdog_timer
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  systemctl stop "$watchdog_timer" 2>/dev/null || true
  systemctl stop "$health_timer" 2>/dev/null || true
  stop_named_client_stack "$service_name" 2>/dev/null || true
}

restart_instance_stack() {
  local instance="$1"
  local service_name health_timer watchdog_timer
  service_name=$(instance_client_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  restart_named_client_stack "$service_name"
  systemctl start "$health_timer" || true
  systemctl start "$watchdog_timer" || true
}

cmd_instance_add() {
  need_root
  check_dependencies systemctl ss
  install_self
  enable_bbr_if_possible

  local instance="${1:-}" domain="" port="7001" resolver="" input
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
  ensure_instance_client_binary

  echo "=== Add Client Instance: $instance ==="
  read -r -p "Domain (e.g., f.example.com): " domain
  validate_domain_or_error "$domain"
  read -r -p "Local listen port [7001]: " input
  [[ -n "$input" ]] && port="$input"
  validate_port_or_error "$port"
  if port_in_use "$port"; then
    error "Port $port is already in use on this host"
  fi
  read -r -p "DNS resolver IP (server IP): " resolver
  validate_ipv4_or_error "$resolver"

  mkdir -p "$instance_path"
  printf '%s\n' "$resolver" >"$servers_file"
  : >"$health_log"
  cat >"$cfg" <<EOF
INSTANCE_NAME=$instance
MODE=client
DOMAIN=$domain
CURRENT_SERVER=$resolver
PORT=$port
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
  warn "Instance '$instance' uses direct slipstream mode (SSH auth overlay disabled)."

  write_instance_client_service "$instance" "$resolver" "$domain" "$port"
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
  local cfg instance status port resolver
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
    printf "  %-16s service=%-10s port=%-6s resolver=%s\n" "$instance" "$status" "$port" "$resolver"
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
  echo "Core: ${SLIPSTREAM_CORE:-nightowl}"
  echo "Service: $(service_state "$service_name")"
  echo "Health timer: $(service_state "$health_timer")"
  echo "Runtime watchdog: $(service_state "$watchdog_timer")"
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

cmd_instance_del() {
  need_root
  check_dependencies systemctl rm
  local instance="${1:-}"
  [[ -n "$instance" ]] || error "Usage: slipstream-tunnel instance-del <name>"
  validate_instance_name_or_error "$instance"
  [[ "$instance" != "default" ]] || error "Cannot delete reserved instance name: default"
  load_instance_config_or_error "$instance"

  local service_name health_service health_timer watchdog_service watchdog_timer instance_path
  service_name=$(instance_client_service "$instance")
  health_service=$(instance_health_service "$instance")
  health_timer=$(instance_health_timer "$instance")
  watchdog_service=$(instance_watchdog_service "$instance")
  watchdog_timer=$(instance_watchdog_timer "$instance")
  instance_path=$(instance_dir "$instance")

  stop_instance_stack "$instance"
  systemctl disable "$service_name" 2>/dev/null || true
  systemctl disable "$health_timer" 2>/dev/null || true
  systemctl disable "$watchdog_timer" 2>/dev/null || true
  rm -f "/etc/systemd/system/${service_name}.service"
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

  local cfg servers_file health_log service_name
  cfg=$(instance_config_file "$instance")
  servers_file=$(instance_servers_file "$instance")
  health_log=$(instance_health_log "$instance")
  service_name=$(instance_client_service "$instance")
  [[ "${MODE:-}" == "client" ]] || error "Instance '$instance' is not in client mode"

  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')

  local recover_reason=""
  if recover_reason=$(client_recover_reason "6 minutes ago" "${PORT:-7000}" "$service_name"); then
    echo "[$timestamp] Self-heal triggered: $recover_reason" >>"$health_log"
    if restart_named_client_stack "$service_name"; then
      echo "[$timestamp] Self-heal restart completed" >>"$health_log"
      sleep 2
    else
      echo "[$timestamp] ERROR: service restart failed" >>"$health_log"
    fi
  fi

  local latency
  latency=$(test_dns_latency "$CURRENT_SERVER" "$DOMAIN" || echo "9999")
  if [[ "$latency" -gt 1000 ]]; then
    echo "[$timestamp] Current server $CURRENT_SERVER slow (${latency}ms), checking alternatives..." >>"$health_log"
    if [[ -f "$servers_file" ]]; then
      local best_server best_latency
      read -r best_server best_latency <<<"$(find_best_server "$DOMAIN" "$servers_file" || true)"
      if [[ -n "$best_server" && "$best_server" != "$CURRENT_SERVER" && "$best_latency" -lt 1000 ]]; then
        set_config_value "CURRENT_SERVER" "$best_server" "$cfg"
        write_instance_client_service "$instance" "$best_server" "$DOMAIN" "$PORT"
        systemctl daemon-reload
        if restart_named_client_stack "$service_name"; then
          echo "[$timestamp] Switched to $best_server (${best_latency}ms)" >>"$health_log"
        else
          echo "[$timestamp] ERROR: switch restart failed" >>"$health_log"
        fi
      else
        echo "[$timestamp] No better server found" >>"$health_log"
      fi
    fi
  else
    echo "[$timestamp] Server $CURRENT_SERVER OK (${latency}ms)" >>"$health_log"
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

  local service_name reason="" now last=0 state_file health_log
  service_name=$(instance_client_service "$instance")
  health_log=$(instance_health_log "$instance")
  if ! reason=$(client_recover_reason "90 seconds ago" "${PORT:-7000}" "$service_name"); then
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
  if restart_named_client_stack "$service_name"; then
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
  local new_ssh_pass_plain=""
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
    new_ssh_pass_plain=$(decode_base64_or_raw "$new_ssh_pass_b64")
    [[ -n "$new_ssh_pass_plain" ]] || error "SSH password is empty after decode"
  fi

  if [[ "$new_ssh_auth" == "true" ]]; then
    write_client_service "$new_server" "$new_domain" "$new_ssh_transport_port"
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
    write_client_service "$new_server" "$new_domain" "$new_port"
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

  local current_core="${SLIPSTREAM_CORE:-nightowl}"
  local target_core="${1:-}"
  if [[ -z "$target_core" && -t 0 ]]; then
    target_core=$(prompt_core_choice "$current_core")
  fi
  [[ -n "$target_core" ]] || error "Usage: slipstream-tunnel core-switch <nightowl|plus>"

  if [[ "${current_core}" == "${target_core}" ]]; then
    log "Core is already '${target_core}'."
    return 0
  fi
  set_slipstream_source "$target_core"

  local arch
  arch=$(detect_arch)
  log "Switching core: ${current_core} -> ${target_core}"
  log "Source: ${SLIPSTREAM_REPO}@${SLIPSTREAM_VERSION} (${SLIPSTREAM_ASSET_LAYOUT})"

  if [[ "${MODE:-}" == "server" ]]; then
    systemctl stop slipstream-server 2>/dev/null || true
    download_slipstream_component "server" "$SLIPSTREAM_SERVER_BIN" "$arch" \
      || error "Failed to download server binary for core '${target_core}'"
    chmod +x "$SLIPSTREAM_SERVER_BIN"
    systemctl daemon-reload
    systemctl restart slipstream-server
  elif [[ "${MODE:-}" == "client" ]]; then
    download_slipstream_component "client" "$SLIPSTREAM_CLIENT_BIN" "$arch" \
      || error "Failed to download client binary for core '${target_core}'"
    chmod +x "$SLIPSTREAM_CLIENT_BIN"
    # Keep verifier binary in sync.
    cp "$SLIPSTREAM_CLIENT_BIN" "$TUNNEL_DIR/slipstream-client" 2>/dev/null || true
    chmod +x "$TUNNEL_DIR/slipstream-client" 2>/dev/null || true
    restart_client_stack
  else
    error "Unsupported mode in config: ${MODE:-unknown}"
  fi

  set_config_value "SLIPSTREAM_CORE" "$SLIPSTREAM_CORE" "$CONFIG_FILE"
  set_config_value "SLIPSTREAM_REPO" "$SLIPSTREAM_REPO" "$CONFIG_FILE"
  set_config_value "SLIPSTREAM_VERSION" "$SLIPSTREAM_VERSION" "$CONFIG_FILE"
  set_config_value "SLIPSTREAM_ASSET_LAYOUT" "$SLIPSTREAM_ASSET_LAYOUT" "$CONFIG_FILE"
  log "Core switch completed."
  cmd_status
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

prompt_instance_name_from_menu() {
  local instance=""
  read -r -p "Instance name: " instance
  if [[ -z "$instance" ]]; then
    warn "Instance name is required"
    return 1
  fi
  echo "$instance"
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
    echo "1) Add new tunnel instance"
    echo "2) List tunnel instances"
    echo "3) Show one instance status"
    echo "4) Start one instance"
    echo "5) Stop one instance"
    echo "6) Restart one instance"
    echo "7) Follow one instance logs"
    echo "8) Delete one instance"
    echo "0) Back"
    read -r -p "Select: " choice

    local instance=""
    case "$choice" in
    1)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_add "$instance"
      fi
      ;;
    2) cmd_instance_list ;;
    3)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_status "$instance"
      fi
      ;;
    4)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_start "$instance"
      fi
      ;;
    5)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_stop "$instance"
      fi
      ;;
    6)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_restart "$instance"
      fi
      ;;
    7)
      if instance=$(prompt_instance_name_from_menu); then
        cmd_instance_logs "$instance" -f
      fi
      ;;
    8)
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
    echo "1) Run health check now"
    echo "2) Run full DNS rescan now"
    echo "3) Show verified DNS IP list (live ping + DNS latency)"
    echo "4) Select DNS manually from verified list"
    echo "5) Show status"
    echo "0) Back"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_health ;;
    2) cmd_rescan ;;
    3) cmd_servers ;;
    4) cmd_select_server ;;
    5) cmd_status ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client_service() {
  while true; do
    echo ""
    echo "=== Client Service Submenu ==="
    echo "1) Start client tunnel service"
    echo "2) Stop client tunnel service"
    echo "3) Restart client tunnel service"
    echo "4) Follow client logs"
    echo "5) Show status"
    echo "0) Back"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_start ;;
    2) cmd_stop ;;
    3) cmd_restart ;;
    4) cmd_logs -f ;;
    5) cmd_status ;;
    0) break ;;
    *) warn "Invalid option: $choice" ;;
    esac
  done
}

cmd_menu_client_auth() {
  while true; do
    echo ""
    echo "=== Client Auth/Profile Submenu ==="
    echo "1) Enable client SSH auth overlay"
    echo "2) Disable client SSH auth overlay"
    echo "3) Set speed profile secure"
    echo "4) Set speed profile fast"
    echo "5) Show speed profile status"
    echo "6) Switch core (nightowl/plus)"
    echo "7) Edit client settings (domain/port/resolver/auth)"
    echo "0) Back"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_client_auth_enable ;;
    2) cmd_client_auth_disable ;;
    3) cmd_speed_profile secure ;;
    4) cmd_speed_profile fast ;;
    5) cmd_speed_profile status ;;
    6) cmd_core_switch ;;
    7) cmd_edit_client ;;
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
    echo "4) Uninstall everything"
    echo "0) Exit menu"
    read -r -p "Select: " choice

    case "$choice" in
    1) cmd_status ;;
    2) cmd_menu_server_service ;;
    3) cmd_menu_server_auth ;;
    4)
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
    echo "10) Switch core (nightowl/plus)"
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

setup_health_timer_named() {
  local service_name="$1" timer_name="$2" exec_command="$3"

  cat >"/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=DNS Tunnel Health Check (${service_name})
After=network.target

[Service]
Type=oneshot
ExecStart=$exec_command
EOF

  cat >"/etc/systemd/system/${timer_name}" <<EOF
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

  cat >"/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=DNS Tunnel Runtime Watchdog (${service_name})
After=network.target

[Service]
Type=oneshot
ExecStart=$exec_command
EOF

  cat >"/etc/systemd/system/${timer_name}" <<EOF
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
    status=$(service_state "slipstream-server")
    echo "  slipstream-server: $status"
    if [[ "${SSH_AUTH_ENABLED:-false}" == "true" ]] && command -v getent &>/dev/null; then
      local ssh_users
      ssh_users=$(ssh_group_users | tr '\n' ',' | sed 's/,$//')
      [[ -z "$ssh_users" ]] && ssh_users="none"
      echo "  ssh-auth users: $ssh_users"
    fi
  else
    local status
    status=$(service_state "slipstream-client")
    echo "  slipstream-client: $status"
    if client_ssh_auth_enabled; then
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
        for cfg in "$INSTANCES_DIR"/*/config; do
          [[ -f "$cfg" ]] || continue
          instance=$(basename "$(dirname "$cfg")")
          echo "  $instance: $(service_state "$(instance_client_service "$instance")")"
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
