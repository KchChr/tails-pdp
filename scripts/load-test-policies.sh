#!/usr/bin/env bash

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  exec sudo --preserve-env=ADM_TOOL,TEST_POLICY_DIR "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ADM_TOOL="${ADM_TOOL:-$ROOT_DIR/target/release/tails-pdp-admintool}"
TEST_POLICY_DIR="${TEST_POLICY_DIR:-/tmp/tails-pdp-test-policies}"

if [[ ! -x "$ADM_TOOL" ]]; then
  echo "Admin-Tool nicht gefunden oder nicht ausfuehrbar: $ADM_TOOL" >&2
  echo "Bitte zuerst cargo build --bin tails-pdp-admintool --release ausfuehren." >&2
  exit 1
fi

mkdir -p "$TEST_POLICY_DIR"

for i in $(seq 0 15); do
  printf 'test-policy-%02d\n' "$i" >"$TEST_POLICY_DIR/file-$i.txt"
done

for i in $(seq 0 15); do
  file_path="$TEST_POLICY_DIR/file-$i.txt"

  if (( i % 2 == 0 )); then
    static_entitlement="deny"
    stream_entitlement="permit"
    command="cat"
    transport="tcp"
    bind_ip="0.0.0.0"
    stream_ip="127.0.0.1"
    operator="less-than"
    value=5
  else
    static_entitlement="permit"
    stream_entitlement="deny"
    command="tail"
    transport="udp"
    bind_ip="127.0.0.1"
    stream_ip="0.0.0.0"
    operator="greater-than-or-equal"
    value=5
  fi

  subject=$((1000 + (i % 2)))
  static_port=$((41000 + i))
  stream_port=$((42000 + i))

  "$ADM_TOOL" set "$i" \
    --entitlement "$static_entitlement" \
    --action file-open \
    --subject "$subject" \
    --command "$command" \
    --resource "$file_path"

  "$ADM_TOOL" set-stream "$i" \
    --entitlement "$stream_entitlement" \
    --action file-open \
    --subject "$subject" \
    --resource "$file_path" \
    --operator "$operator" \
    --modulo 10 \
    --value "$value"

  "$ADM_TOOL" set "$i" \
    --entitlement "$static_entitlement" \
    --action socket-bind \
    --subject "$subject" \
    --family inet \
    --transport "$transport" \
    --resource "$bind_ip" \
    --port "$static_port"

  "$ADM_TOOL" set-stream "$i" \
    --entitlement "$stream_entitlement" \
    --action socket-bind \
    --subject "$subject" \
    --attribute time \
    --family inet \
    --transport "$transport" \
    --resource "$stream_ip" \
    --port "$stream_port" \
    --operator "$operator" \
    --modulo 10 \
    --value "$value"
done

echo "16 Test-Policies pro Map geschrieben."
echo "Testdateien liegen unter: $TEST_POLICY_DIR"
