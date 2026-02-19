#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../install.sh"
}

@test "install.sh has valid bash syntax" {
  run bash -n "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "stdin execution mode works with bash -s" {
  run bash -lc "cat '$SCRIPT' | bash -s -- --help"
  [ "$status" -eq 0 ]
  [[ "$output" == *"Usage: slipstream-tunnel"* ]]
}

@test "help output includes manual monitoring commands" {
  run bash "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"edit                Edit saved settings"* ]]
  [[ "$output" == *"start               Start tunnel service"* ]]
  [[ "$output" == *"stop                Stop tunnel service"* ]]
  [[ "$output" == *"restart             Restart tunnel service"* ]]
  [[ "$output" == *"rescan"* ]]
  [[ "$output" == *"watchdog            Run immediate runtime watchdog check"* ]]
  [[ "$output" == *"dashboard"* ]]
  [[ "$output" == *"servers"* ]]
  [[ "$output" == *"instance-add"* ]]
  [[ "$output" == *"instance-list"* ]]
  [[ "$output" == *"instance-status"* ]]
  [[ "$output" == *"instance-start"* ]]
  [[ "$output" == *"instance-stop"* ]]
  [[ "$output" == *"instance-restart"* ]]
  [[ "$output" == *"instance-logs"* ]]
  [[ "$output" == *"instance-del"* ]]
  [[ "$output" == *"menu"* ]]
  [[ "$output" == *"speed-profile"* ]]
  [[ "$output" == *"core-switch"* ]]
  [[ "$output" == *"dnstm               Pass-through to native dnstm CLI"* ]]
  [[ "$output" == *"auth-setup"* ]]
  [[ "$output" == *"auth-disable"* ]]
  [[ "$output" == *"auth-client-enable"* ]]
  [[ "$output" == *"auth-client-disable"* ]]
  [[ "$output" == *"auth-add"* ]]
  [[ "$output" == *"auth-passwd"* ]]
  [[ "$output" == *"auth-del"* ]]
  [[ "$output" == *"auth-list"* ]]
  [[ "$output" == *"uninstall           Remove all tunnel components"* ]]
  [[ "$output" == *"m                   Short alias for menu"* ]]
  [[ "$output" == *"sst"* ]]
}

@test "IPv4 helper accepts valid address and rejects invalid address" {
  run bash -lc "source '$SCRIPT'; is_valid_ipv4 '8.8.8.8'"
  [ "$status" -eq 0 ]

  run bash -lc "source '$SCRIPT'; is_valid_ipv4 '999.8.8.8'"
  [ "$status" -ne 0 ]
}

@test "username helper accepts safe unix usernames and rejects bad names" {
  run bash -lc "source '$SCRIPT'; validate_unix_username_or_error 'client_01'"
  [ "$status" -eq 0 ]

  run bash -lc "source '$SCRIPT'; validate_unix_username_or_error 'Bad.Name'"
  [ "$status" -ne 0 ]
}

@test "instance name helper accepts safe names and rejects bad names" {
  run bash -lc "source '$SCRIPT'; validate_instance_name_or_error 'dubai_2'"
  [ "$status" -eq 0 ]

  run bash -lc "source '$SCRIPT'; validate_instance_name_or_error 'Bad.Name'"
  [ "$status" -ne 0 ]
}

@test "client transport port helper uses ssh transport when auth is enabled" {
  run bash -lc "source '$SCRIPT'; MODE=client; PORT=7000; SSH_AUTH_ENABLED=true; SSH_TRANSPORT_PORT=17070; client_transport_port_from_config"
  [ "$status" -eq 0 ]
  [ "$output" = "17070" ]
}

@test "help output includes ssh auth client/server flags" {
  run bash "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"--core <name>"* ]]
  [[ "$output" == *"--ssh-auth"* ]]
  [[ "$output" == *"--ssh-backend-port"* ]]
  [[ "$output" == *"--dnstm-transport <slipstream|dnstt>"* ]]
  [[ "$output" == *"--dnstm-backend <custom|socks|ssh|shadowsocks>"* ]]
  [[ "$output" == *"--ssh-auth-client"* ]]
  [[ "$output" == *"--ssh-user"* ]]
  [[ "$output" == *"--ssh-pass"* ]]
}

@test "auto port 53 fix enables resolver management when systemd-resolved is handled" {
  run bash -lc "source '$SCRIPT'; manage_resolver=false; c=0; port_53_in_use(){ c=\$((c+1)); [[ \$c -eq 1 ]]; }; port_53_owners(){ echo 'udp UNCONN 0 0 127.0.0.53:53'; }; stop_disable_unit_if_active(){ [[ \"\$1\" == 'systemd-resolved.service' ]]; }; backup_resolver_if_needed(){ :; }; auto_fix_port_53_conflict >/dev/null; echo \"\$manage_resolver\""
  [ "$status" -eq 0 ]
  [ "$output" = "true" ]
}

@test "password prompt helper returns clean single-line value for command substitution" {
  run bash -lc "source '$SCRIPT'; out=\$(prompt_password_twice 'Test password' <<< \$'secret123\nsecret123\n'); [[ \"\$out\" == 'secret123' ]]"
  [ "$status" -eq 0 ]
}

@test "package mapping covers ssh auth dependencies for apt-get" {
  run bash -lc "source '$SCRIPT'; [[ \"\$(package_for_command apt-get sshpass)\" == 'sshpass' ]] && [[ \"\$(package_for_command apt-get ssh)\" == 'openssh-client' ]] && [[ \"\$(package_for_command apt-get sshd)\" == 'openssh-server' ]] && [[ \"\$(package_for_command apt-get dig)\" == 'dnsutils' ]]"
  [ "$status" -eq 0 ]
}

@test "package mapping uses openssh meta package for pacman" {
  run bash -lc "source '$SCRIPT'; [[ \"\$(package_for_command pacman ssh)\" == 'openssh' ]] && [[ \"\$(package_for_command pacman sshd)\" == 'openssh' ]]"
  [ "$status" -eq 0 ]
}

@test "resolver helper rewrites loopback-only resolv.conf" {
  run bash -lc "source '$SCRIPT'; tmp=\$(mktemp -d); mkdir -p \"\$tmp/etc\"; printf 'nameserver 127.0.0.53\n' >\"\$tmp/etc/resolv.conf\"; rm(){ command rm \"\$@\"; }; cp(){ command cp \"\$@\"; }; RESOLV_BACKUP=\"\$tmp/backup\"; TUNNEL_DIR=\"\$tmp\"; sed(){ command sed \"\$@\"; }; awk(){ command awk \"\$@\"; }; ensure_static_resolver_config(){ local needs_write=false; if [[ ! -f \"\$tmp/etc/resolv.conf\" || -L \"\$tmp/etc/resolv.conf\" ]]; then needs_write=true; else local non_loopback_count; non_loopback_count=\$(awk '/^[[:space:]]*nameserver[[:space:]]+/ {if (\$2 !~ /^127\\./) c++} END {print c+0}' \"\$tmp/etc/resolv.conf\" 2>/dev/null || echo \"0\"); [[ \"\$non_loopback_count\" -gt 0 ]] || needs_write=true; fi; if [[ \"\$needs_write\" == true ]]; then printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' >\"\$tmp/etc/resolv.conf\"; fi; }; ensure_static_resolver_config; grep -q '^nameserver 8.8.8.8$' \"\$tmp/etc/resolv.conf\""
  [ "$status" -eq 0 ]
}

@test "service_state returns literal is-active output without duplicate fallback text" {
  run bash -lc "source '$SCRIPT'; systemctl(){ [[ \"\$1\" == 'is-active' ]] && { echo activating; return 3; }; }; out=\$(service_state slipstream-ssh-client); [[ \"\$out\" == 'activating' ]]"
  [ "$status" -eq 0 ]
}

@test "core prompt command substitution returns clean token on Enter default" {
  run bash -lc "source '$SCRIPT'; out=\$(prompt_core_choice dnstm <<< \$'\\n'); [[ \"\$out\" == 'dnstm' ]]"
  [ "$status" -eq 0 ]
}

@test "dnstm core source maps to net2share pinned binary release" {
  run bash -lc "source '$SCRIPT'; set_slipstream_source dnstm; [[ \"\$SLIPSTREAM_REPO\" == 'net2share/slipstream-rust-build' ]] && [[ \"\$SLIPSTREAM_VERSION\" == 'v2026.02.05' ]] && [[ \"\$SLIPSTREAM_ASSET_LAYOUT\" == 'binary' ]]"
  [ "$status" -eq 0 ]
}

@test "dnstm asset helper maps architecture to release filename" {
  run bash -lc "source '$SCRIPT'; [[ \"\$(dnstm_asset_name x86_64)\" == 'dnstm-linux-amd64' ]] && [[ \"\$(dnstm_asset_name arm64)\" == 'dnstm-linux-arm64' ]]"
  [ "$status" -eq 0 ]
}

@test "dnstt client asset helper maps architecture to release filename" {
  run bash -lc "source '$SCRIPT'; [[ \"\$(dnstt_client_asset_name x86_64)\" == 'dnstt-client-linux-amd64' ]] && [[ \"\$(dnstt_client_asset_name arm64)\" == 'dnstt-client-linux-arm64' ]]"
  [ "$status" -eq 0 ]
}

@test "dnstt pubkey validator enforces 64-hex format" {
  run bash -lc "source '$SCRIPT'; validate_dnstt_pubkey_or_error '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'"
  [ "$status" -eq 0 ]

  run bash -lc "source '$SCRIPT'; validate_dnstt_pubkey_or_error 'badpubkey'"
  [ "$status" -ne 0 ]
}

@test "service name helper returns native router name for dnstm server mode" {
  run bash -lc "source '$SCRIPT'; MODE=server; SLIPSTREAM_CORE=dnstm; out=\$(service_name_for_mode); [[ \"\$out\" == 'dnstm-router' ]]"
  [ "$status" -eq 0 ]
}

@test "dnstm passthrough forwards subcommands in server dnstm mode" {
  run bash -lc "source '$SCRIPT'; need_root(){ :; }; tmp=\$(mktemp -d); DNSTM_BIN=\"\$tmp/dnstm\"; printf '%s\n' '#!/usr/bin/env bash' 'echo \"dnstm-called:\$*\"' >\"\$DNSTM_BIN\"; chmod +x \"\$DNSTM_BIN\"; CONFIG_FILE=\"\$tmp/config\"; printf '%s\n' 'MODE=server' 'DOMAIN=t.example.com' 'SLIPSTREAM_CORE=dnstm' 'SLIPSTREAM_REPO=net2share/slipstream-rust-build' 'SLIPSTREAM_VERSION=v2026.02.05' 'SLIPSTREAM_ASSET_LAYOUT=binary' >\"\$CONFIG_FILE\"; cmd_dnstm_passthrough router status"
  [ "$status" -eq 0 ]
  [[ "$output" == *"dnstm-called:router status"* ]]
}

@test "ssh overlay helper is disabled on dnstm core" {
  run bash -lc "source '$SCRIPT'; set_slipstream_source dnstm; ! core_supports_ssh_overlay"
  [ "$status" -eq 0 ]
}

@test "arm64 nightowl auto-falls back to plus core when asset is unavailable" {
  run bash -lc "source '$SCRIPT'; set_slipstream_source nightowl; dest=\$(mktemp /tmp/ss-client.XXXXXX); rm -f \"\$dest\"; download_release_asset_verified(){ local repo=\"\$1\" output=\"\$4\"; if [[ \"\$repo\" == 'Fox-Fig/slipstream-rust-plus-deploy' ]]; then printf '#!/bin/sh\necho ok\n' >\"\$output\"; return 0; fi; return 1; }; download_slipstream_component client \"\$dest\" arm64; [[ \"\$SLIPSTREAM_CORE\" == 'plus' ]] && [[ -x \"\$dest\" ]]" 
  [ "$status" -eq 0 ]
}

@test "x86_64 nightowl does not auto-fallback to plus" {
  run bash -lc "source '$SCRIPT'; set_slipstream_source nightowl; download_release_asset_verified(){ return 1; }; ! download_slipstream_component client /tmp/ss-nope x86_64; [[ \"\$SLIPSTREAM_CORE\" == 'nightowl' ]]"
  [ "$status" -eq 0 ]
}

@test "instance resolver candidates include scanned and configured servers uniquely" {
  run bash -lc "source '$SCRIPT'; tmp=\$(mktemp -d); TUNNEL_DIR=\"\$tmp\"; CONFIG_FILE=\"\$tmp/config\"; SERVERS_FILE=\"\$tmp/servers.txt\"; INSTANCES_DIR=\"\$tmp/instances\"; mkdir -p \"\$INSTANCES_DIR/a\" \"\$INSTANCES_DIR/b\"; printf '%s\n' 'CURRENT_SERVER=2.2.2.2' >\"\$CONFIG_FILE\"; printf '%s\n' '1.1.1.1' '2.2.2.2' 'bad.ip' >\"\$SERVERS_FILE\"; printf '%s\n' 'CURRENT_SERVER=3.3.3.3' >\"\$INSTANCES_DIR/a/config\"; printf '%s\n' 'CURRENT_SERVER=1.1.1.1' >\"\$INSTANCES_DIR/b/config\"; out=\$(collect_known_resolver_candidates | tr '\n' ' '); [[ \"\$out\" == *'2.2.2.2 '* ]] && [[ \"\$out\" == *'1.1.1.1 '* ]] && [[ \"\$out\" == *'3.3.3.3 '* ]] && [[ \"\$out\" == *'9.9.9.9 '* ]]"
  [ "$status" -eq 0 ]
}

@test "resolver reachability check accepts reachable DNS and rejects unreachable DNS" {
  run bash -lc "source '$SCRIPT'; dig(){ [[ \"\$*\" == *'@1.1.1.1'* ]] && return 0 || return 1; }; resolver_answers_dns_queries '1.1.1.1'; ! resolver_answers_dns_queries '2.2.2.2'"
  [ "$status" -eq 0 ]
}

@test "rescan settings helper persists current defaults in non-interactive mode" {
  run bash -lc "source '$SCRIPT'; has_interactive_tty(){ return 1; }; cfg=\$(mktemp); SCAN_SOURCE=generated; SCAN_DNS_FILE=/tmp/custom-dns.txt; SCAN_COUNTRY=ir; SCAN_MODE=fast; SCAN_WORKERS=500; SCAN_TIMEOUT=2s; SCAN_THRESHOLD=50; prompt_scan_settings_for_profile \"\$cfg\" /tmp/fallback.txt; grep -q '^SCAN_SOURCE=generated$' \"\$cfg\" && grep -q '^SCAN_COUNTRY=ir$' \"\$cfg\" && grep -q '^SCAN_MODE=fast$' \"\$cfg\" && grep -q '^SCAN_WORKERS=500$' \"\$cfg\" && grep -q '^SCAN_TIMEOUT=2s$' \"\$cfg\" && grep -q '^SCAN_THRESHOLD=50$' \"\$cfg\""
  [ "$status" -eq 0 ]
}
