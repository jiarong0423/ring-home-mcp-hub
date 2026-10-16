#!/usr/bin/env bash
# Live test of the family relay's Ring webhook path (POST /ring/webhook), for example from AWS CloudShell.
#
# What it proves: a webhook body shaped like Ring's documented examples (meta{version,time,request_id,account_id},
# data{id,type,attributes{source,source_type,timestamp,sub_type}}), signed with X-Signature: sha256=<hex HMAC-SHA256
# of the raw body>, is accepted by the deployed relay; a repeated meta.request_id is acknowledged as a duplicate and
# not queued again. With HOME_MCP_RING_WEBHOOKS=on the home hub then pulls the events over its signed channel
# (button_press / a person -> door request, device_offline -> guardian camera state).
#
# What it does not prove: real Ring deliveries. Those need Ring partner credentials with account linking; here the
# events are signed with a TEST key that you also configured as the relay's webhook key.
#
# Usage:
#   RELAY_BASE=https://<your-function-url-host> RING_WEBHOOK_KEY_FILE=~/ring_webhook_test.key \
#     bash scripts/live_webhook_test_cloudshell.sh
#   bash scripts/live_webhook_test_cloudshell.sh <relay-base-url> <hmac-key-file>
#
# The key is read from the file and never printed. It is handed to openssl as an argument, so run this on a
# single-user machine (CloudShell, your own laptop). Run it after the hub has done its first (baseline) pull,
# because the hub's first pull only records the position.
set -euo pipefail

RELAY_BASE=${1:-${RELAY_BASE:-}}
KEY_FILE=${2:-${RING_WEBHOOK_KEY_FILE:-}}
if [ -z "$RELAY_BASE" ] || [ -z "$KEY_FILE" ]; then
  echo "ERROR usage: $0 <relay-base-url> <hmac-key-file>   (or set RELAY_BASE and RING_WEBHOOK_KEY_FILE)" >&2
  exit 2
fi
if [ ! -r "$KEY_FILE" ]; then echo "ERROR key file not readable: $KEY_FILE" >&2; exit 2; fi
KEY=$(cat "$KEY_FILE")
if [ "${#KEY}" -lt 16 ]; then echo "ERROR key must be at least 16 characters (the relay refuses shorter keys)" >&2; exit 2; fi
URL="${RELAY_BASE%/}/ring/webhook"
FAILED=0

# send <label> <body>: POST one signed delivery and print the HTTP status and the relay's answer
send() {
  local label=$1 body=$2 sig code
  sig=$(printf %s "$body" | openssl dgst -sha256 -hmac "$KEY" -hex | sed 's/^.*= //')
  printf '%-22s ' "$label"
  code=$(curl -sS -o "$RESP" -w '%{http_code}' -X POST -H 'content-type: application/json' \
    -H "x-signature: sha256=$sig" --data-binary "$body" "$URL") || code=000
  printf 'HTTP %s %s\n' "$code" "$(head -c 200 "$RESP" 2>/dev/null)"
  [ "$code" = 200 ] || FAILED=1
}

# event <type> [sub_type]: a body shaped like Ring's documented webhook examples
event() {
  local type=$1 sub=${2:-} ts rid
  ts=$(($(date +%s) * 1000)); rid="live-test-$(openssl rand -hex 8)"
  printf '{"meta":{"version":"1.1","time":"%s","request_id":"%s","account_id":"live-test"},"data":{"id":"live-test-device_%s_%s","type":"%s","attributes":{"source":"live-test-device","source_type":"devices","timestamp":%s%s}}}' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" "$rid" "${sub:-$type}" "$ts" "$type" "$ts" "${sub:+,\"sub_type\":\"$sub\"}"
}

RESP=$(mktemp); trap 'rm -f "$RESP"' EXIT

PRESS=$(event button_press)
send button_press "$PRESS"
# Ring retries with the same request_id: the relay must answer 200 with "duplicate":true and not queue it again
send "button_press (repeat)" "$PRESS"
grep -q '"duplicate":true' "$RESP" || { echo "ERROR the repeated delivery was not reported as a duplicate" >&2; FAILED=1; }
sleep 1
send "motion_detected human" "$(event motion_detected human)"
sleep 1
send device_offline "$(event device_offline)"

if [ "$FAILED" = 0 ]; then echo "OK all deliveries answered 200"; else echo "ERROR at least one delivery did not answer 200" >&2; exit 1; fi
