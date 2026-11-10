#!/usr/bin/env bash
# Local Docker verification for WEB-01.
# Usage: ./tests/run-local-docker-tests.sh [image-tag]
set -euo pipefail

IMAGE="${1:-web-01-forgotten-backup:test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEAM_A='AXUM{team_a_test_flag}'
TEAM_B='AXUM{team_b_test_flag}'
NAME_A="web01-test-a-$$"
NAME_B="web01-test-b-$$"
WORK="$(mktemp -d)"
FAILURES=0

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f "$NAME_A" "$NAME_B" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

host_port() {
  docker port "$1" 3000/tcp | head -n1 | sed 's/.*://'
}

wait_healthy() {
  local name=$1
  for _ in $(seq 1 60); do
    if [ "$(docker inspect --format '{{.State.Health.Status}}' "$name" 2>/dev/null)" = "healthy" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

wait_ready() {
  local port=$1
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

expect_status() {
  local url=$1 expected=$2 actual
  actual=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  if [ "$actual" = "$expected" ]; then
    pass "$url -> $actual"
  else
    fail "$url -> $actual (expected $expected)"
  fi
}

info "Building $IMAGE"
docker build -q -t "$IMAGE" "$ROOT/source" >/dev/null
pass "image builds"

info "Starting one container per simulated team"
docker run -d --name "$NAME_A" -e "GZCTF_FLAG=$TEAM_A" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
docker run -d --name "$NAME_B" -e "GZCTF_FLAG=$TEAM_B" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
PORT_A=$(host_port "$NAME_A")
PORT_B=$(host_port "$NAME_B")
wait_ready "$PORT_A" || fail "team A did not become ready"
wait_ready "$PORT_B" || fail "team B did not become ready"
pass "containers listen on mapped ports ($PORT_A, $PORT_B)"

info "Application endpoints"
expect_status "http://127.0.0.1:${PORT_A}/" 200
expect_status "http://127.0.0.1:${PORT_A}/robots.txt" 200
expect_status "http://127.0.0.1:${PORT_A}/healthz" 200
expect_status "http://127.0.0.1:${PORT_A}/backups/" 200

if curl -s "http://127.0.0.1:${PORT_A}/robots.txt" | grep -q 'Disallow: /backups/'; then
  pass "robots.txt points at the backup directory"
else
  fail "robots.txt is missing the /backups/ clue"
fi

if curl -s "http://127.0.0.1:${PORT_A}/backups/" | grep -q 'northstar-site-backup.zip'; then
  pass "directory listing exposes the archive"
else
  fail "directory listing does not expose the archive"
fi

info "Archive download and extraction"
for team in A B; do
  port_var="PORT_${team}"
  port=${!port_var}
  code=$(curl -s -o "$WORK/team${team}.zip" -w '%{http_code}' \
    "http://127.0.0.1:${port}/backups/northstar-site-backup.zip")
  [ "$code" = "200" ] && pass "team ${team}: archive downloads" \
    || fail "team ${team}: archive download returned $code"

  if unzip -tqq "$WORK/team${team}.zip" >/dev/null 2>&1; then
    pass "team ${team}: archive extracts cleanly"
  else
    fail "team ${team}: archive is corrupt"
  fi
done

FLAG_A=$(unzip -p "$WORK/teamA.zip" config/production.env | sed -n 's/^CTF_FLAG=//p')
FLAG_B=$(unzip -p "$WORK/teamB.zip" config/production.env | sed -n 's/^CTF_FLAG=//p')

[ "$FLAG_A" = "$TEAM_A" ] && pass "team A archive contains team A's flag" \
  || fail "team A archive contains '$FLAG_A'"
[ "$FLAG_B" = "$TEAM_B" ] && pass "team B archive contains team B's flag" \
  || fail "team B archive contains '$FLAG_B'"

if ! unzip -p "$WORK/teamA.zip" config/production.env | grep -q "$TEAM_B"; then
  pass "team A archive does not contain team B's flag"
else
  fail "team A archive leaks team B's flag"
fi

if ! unzip -p "$WORK/teamB.zip" config/production.env | grep -q "$TEAM_A"; then
  pass "team B archive does not contain team A's flag"
else
  fail "team B archive leaks team A's flag"
fi

info "Flag leakage outside the archive"
LEAK=0
for path in / /style.css /app.js /favicon.svg /healthz /robots.txt /backups/ /missing; do
  if curl -s "http://127.0.0.1:${PORT_A}${path}" | grep -q 'AXUM{'; then
    fail "flag-like content served at ${path}"
    LEAK=1
  fi
done
[ "$LEAK" = "0" ] && pass "no flag on the public surface"

expect_status "http://127.0.0.1:${PORT_A}/runtime/backups/northstar-site-backup.zip" 404
expect_status "http://127.0.0.1:${PORT_A}/src/server.js" 404
expect_status "http://127.0.0.1:${PORT_A}/backups/..%2f..%2fpackage.json" 404

info "Image hygiene"
if docker run --rm --entrypoint sh "$IMAGE" -c \
  'grep -rIl "AXUM{\|team_a_test_flag\|team_b_test_flag" /app --exclude-dir=node_modules' \
  >/dev/null 2>&1; then
  fail "image contains flag-like content"
else
  pass "image contains neither test flag"
fi

if [ -z "$(docker run --rm --entrypoint ls "$IMAGE" /app/runtime/backups)" ]; then
  pass "image ships no pre-built archive"
else
  fail "image contains a pre-built backup"
fi

IDENTITY=$(docker run --rm --entrypoint id "$IMAGE")
case "$IDENTITY" in
  *"uid=1000(node)"*) pass "runtime user is non-root ($IDENTITY)" ;;
  *) fail "unexpected runtime user: $IDENTITY" ;;
esac

info "Fail-closed behaviour"
if docker run --rm "$IMAGE" >"$WORK/noflag.log" 2>&1; then
  fail "container started without GZCTF_FLAG"
else
  pass "container refuses to start without GZCTF_FLAG"
fi
grep -q 'GZCTF_FLAG is not set' "$WORK/noflag.log" \
  && pass "missing-flag error is explicit" \
  || fail "missing-flag error message is unclear"

info "Recreate with a rotated flag"
docker rm -f "$NAME_A" >/dev/null
docker run -d --name "$NAME_A" -e 'GZCTF_FLAG=AXUM{team_a_rotated_flag}' -p 127.0.0.1::3000 "$IMAGE" >/dev/null
PORT_A=$(host_port "$NAME_A")
wait_ready "$PORT_A" || fail "recreated container did not become ready"
curl -s -o "$WORK/rotated.zip" "http://127.0.0.1:${PORT_A}/backups/northstar-site-backup.zip"
ROTATED=$(unzip -p "$WORK/rotated.zip" config/production.env | sed -n 's/^CTF_FLAG=//p')
[ "$ROTATED" = 'AXUM{team_a_rotated_flag}' ] \
  && pass "recreated container serves the rotated flag" \
  || fail "recreated container serves '$ROTATED'"

info "Restart keeps a working instance"
docker restart "$NAME_A" >/dev/null
PORT_A=$(host_port "$NAME_A")
wait_ready "$PORT_A" || fail "restarted container did not become ready"
curl -s -o "$WORK/restarted.zip" "http://127.0.0.1:${PORT_A}/backups/northstar-site-backup.zip"
RESTARTED=$(unzip -p "$WORK/restarted.zip" config/production.env | sed -n 's/^CTF_FLAG=//p')
[ "$RESTARTED" = 'AXUM{team_a_rotated_flag}' ] \
  && pass "restarted container rebuilds the archive with the same flag" \
  || fail "restarted container serves '$RESTARTED'"

info "Health"
if wait_healthy "$NAME_A"; then
  pass "container healthcheck reports healthy"
else
  fail "container healthcheck is not healthy"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  printf '\033[32mAll local Docker checks passed.\033[0m\n'
else
  printf '\033[31m%d check(s) failed.\033[0m\n' "$FAILURES"
  exit 1
fi
