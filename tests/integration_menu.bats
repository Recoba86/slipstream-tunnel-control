#!/usr/bin/env bats

setup() {
  export SCRIPT="${BATS_TEST_DIRNAME}/../install.sh"
  TEST_ROOT="${BATS_TEST_TMPDIR}/integration"
  export HOME="${TEST_ROOT}/home"
  export MOCK_BIN="${TEST_ROOT}/mockbin"
  export TEST_BIN="${TEST_ROOT}/bin"
  export MOCK_LOG="${TEST_ROOT}/mock.log"
  export SLIPSTREAM_CLIENT_BIN="${TEST_BIN}/slipstream-client"
  export TUNNEL_CMD_BIN="${TEST_BIN}/slipstream-tunnel"
  export SST_BIN="${TEST_BIN}/sst"
  export PATH="${MOCK_BIN}:$PATH"

  mkdir -p "${HOME}/.tunnel/dnscan" "$MOCK_BIN" "$TEST_BIN"
  : >"$MOCK_LOG"

  cat >"${MOCK_BIN}/systemctl" <<'EOF'
#!/usr/bin/env bash
echo "systemctl $*" >>"$MOCK_LOG"
if [[ "$1" == "is-active" ]]; then
  echo "active"
fi
exit 0
EOF
  chmod +x "${MOCK_BIN}/systemctl"

  cat >"${MOCK_BIN}/dig" <<'EOF'
#!/usr/bin/env bash
server=""
for arg in "$@"; do
  if [[ "$arg" == @* ]]; then
    server="${arg#@}"
  fi
done

case "$server" in
1.1.1.1)
  sleep 0.01
  echo "\"ok\""
  exit 0
  ;;
8.8.8.8)
  sleep 0.06
  echo "\"ok\""
  exit 0
  ;;
9.9.9.9)
  sleep 0.01
  exit 1
  ;;
*)
  echo "\"ok\""
  exit 0
  ;;
esac
EOF
  chmod +x "${MOCK_BIN}/dig"

  cat >"${MOCK_BIN}/ping" <<'EOF'
#!/usr/bin/env bash
server="${@: -1}"
case "$server" in
1.1.1.1) ms="11.1" ;;
8.8.8.8) ms="42.0" ;;
9.9.9.9) exit 1 ;;
*) ms="20.0" ;;
esac
echo "64 bytes from $server: icmp_seq=1 ttl=57 time=${ms} ms"
exit 0
EOF
  chmod +x "${MOCK_BIN}/ping"

  cat >"${HOME}/.tunnel/dnscan/dnscan" <<'EOF'
#!/usr/bin/env bash
echo "dnscan $*" >>"$MOCK_LOG"
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
  --output)
    out="$2"
    shift 2
    ;;
  *)
    shift
    ;;
  esac
done
[[ -n "$out" ]] || exit 1
cat >"$out" <<'EOL'
8.8.8.8
1.1.1.1
9.9.9.9
EOL
exit 0
EOF
  chmod +x "${HOME}/.tunnel/dnscan/dnscan"

  cat >"$SLIPSTREAM_CLIENT_BIN" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod +x "$SLIPSTREAM_CLIENT_BIN"

  cat >"${HOME}/.tunnel/config" <<'EOF'
DOMAIN=t.example.com
MODE=client
CURRENT_SERVER=8.8.8.8
PORT=7000
SCAN_SOURCE=generated
SCAN_COUNTRY=ir
SCAN_MODE=fast
SCAN_WORKERS=100
SCAN_TIMEOUT=2s
SCAN_THRESHOLD=50
EOF

  cat >"${HOME}/.tunnel/servers.txt" <<'EOF'
8.8.8.8
1.1.1.1
9.9.9.9
EOF
}

@test "servers command prints verified DNS list with latency columns" {
  cat >"${BATS_TEST_TMPDIR}/run_servers.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
cmd_servers
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_servers.sh"
  run bash "${BATS_TEST_TMPDIR}/run_servers.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Verified DNS Servers"* ]]
  [[ "$output" == *"8.8.8.8"* ]]
  [[ "$output" == *"1.1.1.1"* ]]
  [[ "$output" == *"Ping(ms)"* ]]
  [[ "$output" == *"DNS(ms)"* ]]
}

@test "manual selection switches to chosen DNS and restarts client service" {
  cat >"${BATS_TEST_TMPDIR}/run_manual_select.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
write_client_service() { echo "$1|$2|$3" >"$HOME/.tunnel/service.args"; }
cmd_select_server <<<"2"
grep '^CURRENT_SERVER=1.1.1.1$' "$HOME/.tunnel/config"
cat "$HOME/.tunnel/service.args"
grep 'systemctl restart slipstream-client' "$MOCK_LOG"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_manual_select.sh"
  run bash "${BATS_TEST_TMPDIR}/run_manual_select.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"CURRENT_SERVER=1.1.1.1"* ]]
  [[ "$output" == *"1.1.1.1|t.example.com|7000"* ]]
  [[ "$output" == *"systemctl restart slipstream-client"* ]]
}

@test "rescan refreshes servers and chooses the best DNS by latency" {
  cat >"${BATS_TEST_TMPDIR}/run_rescan.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
write_client_service() { echo "$1|$2|$3" >"$HOME/.tunnel/service.args"; }
cmd_rescan
grep '^CURRENT_SERVER=1.1.1.1$' "$HOME/.tunnel/config"
cat "$HOME/.tunnel/service.args"
grep '^dnscan ' "$MOCK_LOG"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_rescan.sh"
  run bash "${BATS_TEST_TMPDIR}/run_rescan.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Switched to best DNS server: 1.1.1.1"* ]]
  [[ "$output" == *"CURRENT_SERVER=1.1.1.1"* ]]
  [[ "$output" == *"1.1.1.1|t.example.com|7000"* ]]
  [[ "$output" == *"dnscan --domain t.example.com"* ]]
}

@test "dnstt transport rescan skips dnscan and refreshes resolver candidates" {
  cat >"${HOME}/.tunnel/config" <<'EOF'
DOMAIN=t.example.com
MODE=client
CURRENT_SERVER=8.8.8.8
PORT=7000
DNSTM_TRANSPORT=dnstt
DNSTM_DNSTT_PUBKEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
SCAN_SOURCE=generated
SCAN_COUNTRY=ir
SCAN_MODE=fast
SCAN_WORKERS=100
SCAN_TIMEOUT=2s
SCAN_THRESHOLD=50
EOF

  cat >"${BATS_TEST_TMPDIR}/run_rescan_dnstt.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
write_client_service() { echo "$1|$2|$3|$4" >"$HOME/.tunnel/service.args"; }
cmd_rescan
grep '^CURRENT_SERVER=' "$HOME/.tunnel/config"
cat "$HOME/.tunnel/service.args"
! grep -q '^dnscan ' "$MOCK_LOG"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_rescan_dnstt.sh"
  run bash "${BATS_TEST_TMPDIR}/run_rescan_dnstt.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"CURRENT_SERVER="* ]]
  [[ "$output" == *"|t.example.com|7000|dnstt"* ]]
}

@test "edit client settings updates domain and port without reinstall" {
  cat >"${BATS_TEST_TMPDIR}/run_edit_client.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
write_client_service() { echo "$1|$2|$3" >"$HOME/.tunnel/service.args"; }
cmd_dashboard() { :; }
cmd_edit_client <<< $'new.example.com\n7100\n1.1.1.1\n'
grep '^DOMAIN=new.example.com$' "$HOME/.tunnel/config"
grep '^PORT=7100$' "$HOME/.tunnel/config"
grep '^CURRENT_SERVER=1.1.1.1$' "$HOME/.tunnel/config"
cat "$HOME/.tunnel/service.args"
grep 'systemctl restart slipstream-client' "$MOCK_LOG"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_edit_client.sh"
  run bash "${BATS_TEST_TMPDIR}/run_edit_client.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"DOMAIN=new.example.com"* ]]
  [[ "$output" == *"PORT=7100"* ]]
  [[ "$output" == *"CURRENT_SERVER=1.1.1.1"* ]]
  [[ "$output" == *"1.1.1.1|new.example.com|7100"* ]]
}

@test "edit client keeps going when ssh preflight is inconclusive" {
  cat >"${HOME}/.tunnel/config" <<'EOF'
DOMAIN=t.example.com
MODE=client
CURRENT_SERVER=8.8.8.8
PORT=7000
SSH_AUTH_ENABLED=true
SSH_AUTH_USER=amin
SSH_PASS_B64=c2VjcmV0
SSH_REMOTE_APP_PORT=2053
SSH_TRANSPORT_PORT=17070
EOF

  cat >"${BATS_TEST_TMPDIR}/run_edit_client_inconclusive.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
check_dependencies() { :; }
write_client_service() { echo "$1|$2|$3" >"$HOME/.tunnel/service.args"; }
write_ssh_client_env() { echo "$1|$2|$3|$4|$5" >"$HOME/.tunnel/ssh_env.args"; }
write_ssh_client_service() { echo "ok" >"$HOME/.tunnel/ssh_service.args"; }
cmd_dashboard() { :; }
test_client_ssh_auth_credentials() { return 2; }
cmd_edit_client <<< $'\n\n\n\n\n\n\n\n'
grep '^SSH_AUTH_ENABLED=true$' "$HOME/.tunnel/config"
cat "$HOME/.tunnel/service.args"
cat "$HOME/.tunnel/ssh_env.args"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_edit_client_inconclusive.sh"
  run bash "${BATS_TEST_TMPDIR}/run_edit_client_inconclusive.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Proceeding despite inconclusive SSH preflight"* ]]
  [[ "$output" == *"SSH_AUTH_ENABLED=true"* ]]
  [[ "$output" == *"8.8.8.8|t.example.com|17070"* ]]
  [[ "$output" == *"amin|c2VjcmV0|17070|7000|2053"* ]]
}

@test "client auth disable rewires service to direct port and keeps saved creds" {
  cat >"${HOME}/.tunnel/config" <<'EOF'
DOMAIN=t.example.com
MODE=client
CURRENT_SERVER=8.8.8.8
PORT=7000
SSH_AUTH_ENABLED=true
SSH_AUTH_USER=amin
SSH_PASS_B64=c2VjcmV0
SSH_REMOTE_APP_PORT=2053
SSH_TRANSPORT_PORT=17070
EOF

  cat >"${BATS_TEST_TMPDIR}/run_client_auth_disable.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
check_dependencies() { :; }
write_client_service() { echo "$1|$2|$3" >"$HOME/.tunnel/service.args"; }
remove_ssh_client_service_if_present() { echo "removed" >"$HOME/.tunnel/removed.flag"; }
cmd_client_auth_disable
cat "$HOME/.tunnel/service.args"
grep '^SSH_AUTH_ENABLED=false$' "$HOME/.tunnel/config"
grep '^SSH_AUTH_USER=amin$' "$HOME/.tunnel/config"
grep '^SSH_PASS_B64=c2VjcmV0$' "$HOME/.tunnel/config"
test -f "$HOME/.tunnel/removed.flag"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_client_auth_disable.sh"
  run bash "${BATS_TEST_TMPDIR}/run_client_auth_disable.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"8.8.8.8|t.example.com|7000"* ]]
  [[ "$output" == *"SSH_AUTH_ENABLED=false"* ]]
}

@test "auth list prints SSH tunnel users in server mode" {
  cat >"${BATS_TEST_TMPDIR}/run_auth_list.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
check_dependencies() { :; }
load_config_or_error() {
  MODE=server
  SSH_AUTH_ENABLED=true
  PORT=2053
}
ssh_group_users() {
  printf "alice\nbob\n"
}
getent() {
  [[ "$1" == "group" && "$2" == "$SSH_AUTH_GROUP" ]] && return 0
  return 2
}
cmd_auth_list
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_auth_list.sh"
  run bash "${BATS_TEST_TMPDIR}/run_auth_list.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"SSH Tunnel Users"* ]]
  [[ "$output" == *"alice"* ]]
  [[ "$output" == *"bob"* ]]
}

@test "auth setup rewires server service to ssh backend and updates config" {
  cat >"${HOME}/.tunnel/config" <<'EOF'
DOMAIN=t.example.com
MODE=server
PORT=2053
SSH_AUTH_ENABLED=false
SSH_BACKEND_PORT=22
EOF

  cat >"${BATS_TEST_TMPDIR}/run_auth_setup.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
check_dependencies() { :; }
apply_ssh_auth_overlay() { echo "overlay:$1" >"$HOME/.tunnel/overlay.arg"; }
write_server_service() { echo "$1|$2" >"$HOME/.tunnel/server_service.args"; }
cmd_auth_setup <<< $'2100\n2222\n'
cat "$HOME/.tunnel/overlay.arg"
cat "$HOME/.tunnel/server_service.args"
grep '^PORT=2100$' "$HOME/.tunnel/config"
grep '^SSH_BACKEND_PORT=2222$' "$HOME/.tunnel/config"
grep '^SSH_AUTH_ENABLED=true$' "$HOME/.tunnel/config"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_auth_setup.sh"
  run bash "${BATS_TEST_TMPDIR}/run_auth_setup.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"overlay:2100"* ]]
  [[ "$output" == *"t.example.com|2222"* ]]
  [[ "$output" == *"PORT=2100"* ]]
  [[ "$output" == *"SSH_BACKEND_PORT=2222"* ]]
  [[ "$output" == *"SSH_AUTH_ENABLED=true"* ]]
}

@test "auth disable rewires server service to app port and updates config" {
  cat >"${HOME}/.tunnel/config" <<'EOF'
DOMAIN=t.example.com
MODE=server
PORT=2053
SSH_AUTH_ENABLED=true
SSH_BACKEND_PORT=22
EOF

  cat >"${BATS_TEST_TMPDIR}/run_auth_disable.sh" <<'EOF'
#!/usr/bin/env bash
set -e
source "$SCRIPT"
need_root() { :; }
check_dependencies() { :; }
detect_ssh_service_name() { echo ssh; }
sshd() { [[ "$1" == "-t" ]] && return 0; return 0; }
systemctl() { echo "systemctl $*" >>"$MOCK_LOG"; return 0; }
write_server_service() { echo "$1|$2" >"$HOME/.tunnel/server_service.args"; }
SSH_AUTH_CONFIG_FILE="$HOME/.tunnel/99-slipstream-tunnel.conf"
mkdir -p "$(dirname "$SSH_AUTH_CONFIG_FILE")"
echo "# test" >"$SSH_AUTH_CONFIG_FILE"
cmd_auth_disable
cat "$HOME/.tunnel/server_service.args"
grep '^SSH_AUTH_ENABLED=false$' "$HOME/.tunnel/config"
grep '^SSH_BACKEND_PORT=$' "$HOME/.tunnel/config"
EOF
  chmod +x "${BATS_TEST_TMPDIR}/run_auth_disable.sh"
  run bash "${BATS_TEST_TMPDIR}/run_auth_disable.sh"
  [ "$status" -eq 0 ]
  [[ "$output" == *"t.example.com|2053"* ]]
  [[ "$output" == *"SSH_AUTH_ENABLED=false"* ]]
}
