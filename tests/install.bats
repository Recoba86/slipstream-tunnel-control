#!/usr/bin/env bats

setup() {
  SCRIPT="${BATS_TEST_DIRNAME}/../install.sh"
}

@test "install.sh has valid bash syntax" {
  run bash -n "$SCRIPT"
  [ "$status" -eq 0 ]
}

@test "help output includes manual monitoring commands" {
  run bash "$SCRIPT" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"rescan"* ]]
  [[ "$output" == *"dashboard"* ]]
  [[ "$output" == *"servers"* ]]
  [[ "$output" == *"menu"* ]]
  [[ "$output" == *"m                   Short alias for menu"* ]]
  [[ "$output" == *"sst"* ]]
}

@test "IPv4 helper accepts valid address and rejects invalid address" {
  run bash -lc "source '$SCRIPT'; is_valid_ipv4 '8.8.8.8'"
  [ "$status" -eq 0 ]

  run bash -lc "source '$SCRIPT'; is_valid_ipv4 '999.8.8.8'"
  [ "$status" -ne 0 ]
}
