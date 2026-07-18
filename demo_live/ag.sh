#!/usr/bin/env bash
# actiongate hands-on helper. Run from the repo root in Git Bash:
#
#   ./demo_live/ag.sh allow            # an allowed action  -> exit 0 + grant
#   ./demo_live/ag.sh deny             # a denied action    -> exit 2 + rule
#   ./demo_live/ag.sh gate             # a gated action     -> BLOCKS for approval
#   ./demo_live/ag.sh approve          # approve newest pending (run in a 2nd shell)
#   ./demo_live/ag.sh check TOOL JSON  # your own call, e.g. check bash '{"command":"pwd"}'
#   ./demo_live/ag.sh verify           # prove the audit log is intact
#   ./demo_live/ag.sh log              # show recent governed actions + states
#
set -euo pipefail

# ---- config (matches the running demo stack) --------------------------------
DB="postgres://ag:ag@localhost:5432/actiongate?sslmode=disable"
TENANT="2f871fa3-8397-413f-a1e1-a4ed8f123190"
EPOCH_PUB="vPFT7Qr4zOdAA4lJ9tjK0WYRH+tQcdI1OYDwBa8N+ig="
GW="./bin/gateway.exe"
VERIFY="./bin/verify.exe"

uuid() { powershell -NoProfile -Command "[guid]::NewGuid().ToString()"; }

check() { # tool  json-params
  local sid; sid=$(uuid)
  echo ">> check tool=$1 params=$2"
  set +e
  "$GW" check -agent me -session "$sid" -request-id "cli-$(date +%s)" \
    -tool "$1" -params "$2" -wait 10m
  local code=$?
  set -e
  echo "   exit=$code  (0=allowed  2=denied  3=approval-timeout)"
}

case "${1:-}" in
  allow)  check bash      '{"command":"ls"}' ;;
  deny)   check read_file '{"path":"/app/.env"}' ;;
  gate)   echo "This BLOCKS. In another Git Bash shell run: ./demo_live/ag.sh approve"
          check bash      '{"command":"rm -rf /tmp/demo-x"}' ;;
  check)  check "$2" "$3" ;;

  approve)
    tok=$(docker exec actiongate-db psql -U ag -d actiongate -tAc \
      "select args->>'callback_token' from river_job where kind='deliver_approval' order by id desc limit 1")
    [ -z "$tok" ] && { echo "no pending approval found"; exit 1; }
    echo ">> approving newest pending action (token ${tok:0:12}...)"
    curl -s -X POST http://localhost:8091/approval/callback \
      -H "Content-Type: application/json" \
      -d "{\"token\":\"$tok\",\"decision\":\"approved\",\"approver_id\":\"$(whoami)\",\"reason\":\"manual approve\"}"
    echo ;;

  deny-approval)
    tok=$(docker exec actiongate-db psql -U ag -d actiongate -tAc \
      "select args->>'callback_token' from river_job where kind='deliver_approval' order by id desc limit 1")
    [ -z "$tok" ] && { echo "no pending approval found"; exit 1; }
    echo ">> DENYING newest pending action"
    curl -s -X POST http://localhost:8091/approval/callback \
      -H "Content-Type: application/json" \
      -d "{\"token\":\"$tok\",\"decision\":\"denied\",\"approver_id\":\"$(whoami)\",\"reason\":\"manual deny\"}"
    echo ;;

  verify)
    "$VERIFY" -database-url "$DB" -tenant "$TENANT" -key "epoch-1=$EPOCH_PUB" ;;

  log)
    docker exec actiongate-db psql -U ag -d actiongate -c \
      "select tool_name, created_at::time(0) as at from action_requests order by created_at desc limit 10" ;;

  *)
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -12 ;;
esac
