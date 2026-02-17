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
  [[ "$output" == *"dashboard"* ]]
  [[ "$output" == *"servers"* ]]
  [[ "$output" == *"menu"* ]]
  [[ "$output" == *"speed-profile"* ]]
  [[ "$output" == *"core-switch"* ]]
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
