#!/usr/bin/env bash
# Local Docker verification for WEB-02 — Not Your Account.
# Usage: ./tests/run-local-docker-tests.sh [image-tag]
set -euo pipefail

IMAGE="${1:-web-02-not-your-account:test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEAM_A='AXUM{team_a_test_flag}'
TEAM_B='AXUM{team_b_test_flag}'
USERNAME='alex'
PASSWORD='Northstar@2026'
NAME_A="web02-test-a-$$"
NAME_B="web02-test-b-$$"
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

json() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }

host_port() { docker port "$1" 3000/tcp | head -n1 | sed 's/.*://'; }

wait_ready() {
  local port=$1
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

login() {
  local port=$1 jar=$2
  curl -s -c "$jar" -o /dev/null -w '%{redirect_url}' \
    --data-urlencode "username=$USERNAME" --data-urlencode "password=$PASSWORD" \
    "http://127.0.0.1:${port}/login"
}

sid_of() { awk '$6 == "nbsid" { print $7 }' "$1"; }

info "Building $IMAGE"
docker build -q -t "$IMAGE" "$ROOT/source" >/dev/null
pass "image builds"

info "Starting one container per simulated team"
docker run -d --name "$NAME_A" -e "GZCTF_FLAG=$TEAM_A" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
docker run -d --name "$NAME_B" -e "GZCTF_FLAG=$TEAM_B" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
PORT_A=$(host_port "$NAME_A")
PORT_B=$(host_port "$NAME_B")
wait_ready "$PORT_A" || fail "instance A did not become ready"
wait_ready "$PORT_B" || fail "instance B did not become ready"
pass "both instances listen on mapped ports ($PORT_A, $PORT_B)"

info "Functional tests"
CODE=$(curl -s -o "$WORK/login.html" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/")
[ "$CODE" = "200" ] && pass "login page loads (200)" || fail "login page returned $CODE"
grep -q 'Northstar Bank' "$WORK/login.html" && pass "login page is branded" || fail "login page branding missing"

REDIRECT=$(curl -s -o /dev/null -w '%{redirect_url}' \
  --data-urlencode "username=$USERNAME" --data-urlencode 'password=wrong-password' \
  "http://127.0.0.1:${PORT_A}/login")
case "$REDIRECT" in
  *error=invalid*) pass "invalid credentials rejected" ;;
  *) fail "invalid credentials produced redirect '$REDIRECT'" ;;
esac

CODE=$(curl -s -o "$WORK/unauth.json" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/1001")
[ "$CODE" = "401" ] && pass "unauthenticated account API rejected (401)" || fail "unauthenticated API returned $CODE"

CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_A}/dashboard")
[ "$CODE" = "302" ] && pass "unauthenticated dashboard redirects to login" || fail "unauthenticated dashboard returned $CODE"

JAR_A="$WORK/a.cookies"
REDIRECT=$(login "$PORT_A" "$JAR_A")
case "$REDIRECT" in
  */dashboard) pass "valid credentials establish a session" ;;
  *) fail "valid login redirected to '$REDIRECT'" ;;
esac

curl -s -b "$JAR_A" "http://127.0.0.1:${PORT_A}/api/session" >"$WORK/session.json"
[ "$(json "['user']['accountId']" <"$WORK/session.json")" = "1001" ] \
  && pass "session belongs to account 1001" || fail "unexpected session payload"

CODE=$(curl -s -b "$JAR_A" -o "$WORK/acct1001.json" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/1001")
[ "$CODE" = "200" ] && pass "authenticated user can read account 1001" || fail "account 1001 returned $CODE"
[ "$(json "['customer']['name']" <"$WORK/acct1001.json")" = "Alex Morgan" ] \
  && pass "account 1001 belongs to Alex Morgan" || fail "account 1001 holder mismatch"

CODE=$(curl -s -b "$JAR_A" -o "$WORK/tx1001.json" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/1001/transactions")
COUNT=$(json "['transactions'].__len__()" <"$WORK/tx1001.json" 2>/dev/null || echo 0)
[ "$CODE" = "200" ] && [ "$COUNT" -gt 0 ] \
  && pass "authenticated user can read account 1001 transactions ($COUNT)" \
  || fail "account 1001 transactions failed (HTTP $CODE, count $COUNT)"

info "Intended IDOR"
CODE=$(curl -s -b "$JAR_A" -o "$WORK/acct1002.json" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/1002")
[ "$CODE" = "200" ] && pass "authenticated user can read account 1002 (IDOR)" || fail "IDOR request returned $CODE"
[ "$(json "['customer']['name']" <"$WORK/acct1002.json")" = "Jordan Lee" ] \
  && pass "account 1002 belongs to Jordan Lee" || fail "account 1002 holder mismatch"
[ "$(json "['flag']" <"$WORK/acct1002.json")" = "$TEAM_A" ] \
  && pass "account 1002 returns instance A's runtime flag" || fail "flag missing from account 1002"

CODE=$(curl -s -b "$JAR_A" -o "$WORK/tx1002.json" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/1002/transactions")
[ "$CODE" = "200" ] && pass "account 1002 transactions readable (same IDOR)" || fail "account 1002 transactions returned $CODE"

CODE=$(curl -s -b "$JAR_A" -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/9999")
[ "$CODE" = "404" ] && pass "unknown account returns 404" || fail "unknown account returned $CODE"

info "Session handling"
curl -s -b "$JAR_A" -c "$JAR_A" -o /dev/null -X POST "http://127.0.0.1:${PORT_A}/logout"
CODE=$(curl -s -b "$JAR_A" -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_A}/api/accounts/1001")
[ "$CODE" = "401" ] && pass "logout invalidates the session" || fail "API after logout returned $CODE"

JAR_1="$WORK/s1.cookies"
JAR_2="$WORK/s2.cookies"
login "$PORT_A" "$JAR_1" >/dev/null
login "$PORT_A" "$JAR_2" >/dev/null
[ "$(sid_of "$JAR_1")" != "$(sid_of "$JAR_2")" ] \
  && pass "each login issues a new session id" || fail "session id was reused across logins"

HEADERS=$(curl -s -D - -o /dev/null -c "$WORK/h.cookies" \
  --data-urlencode "username=$USERNAME" --data-urlencode "password=$PASSWORD" \
  "http://127.0.0.1:${PORT_A}/login" | grep -i '^set-cookie:')
case "$HEADERS" in
  *HttpOnly*) pass "session cookie is HttpOnly" ;;
  *) fail "session cookie is missing HttpOnly" ;;
esac
case "$HEADERS" in
  *SameSite=Lax*) pass "session cookie is SameSite=Lax" ;;
  *) fail "session cookie is missing SameSite=Lax" ;;
esac

info "Dynamic flag isolation"
JAR_B="$WORK/b.cookies"
login "$PORT_B" "$JAR_B" >/dev/null
curl -s -b "$JAR_B" -o "$WORK/acct1002_b.json" "http://127.0.0.1:${PORT_B}/api/accounts/1002"

[ "$(json "['flag']" <"$WORK/acct1002_b.json")" = "$TEAM_B" ] \
  && pass "instance B returns its own flag" || fail "instance B flag mismatch"

if grep -q "$TEAM_B" "$WORK/acct1002.json"; then
  fail "instance A returns instance B's flag"
else
  pass "instance A never returns instance B's flag"
fi

if grep -q "$TEAM_A" "$WORK/acct1002_b.json"; then
  fail "instance B returns instance A's flag"
else
  pass "instance B never returns instance A's flag"
fi

info "Flag leakage checks"
LEAK=0
for path in / /css/style.css /js/app.js /favicon.svg /dashboard.html /account.html /transactions.html /healthz; do
  if curl -s "http://127.0.0.1:${PORT_A}${path}" | grep -q 'AXUM{'; then
    fail "flag-like content served at ${path}"
    LEAK=1
  fi
done
[ "$LEAK" = "0" ] && pass "no flag in pages, assets or health endpoint"

for name in "$NAME_A" "$NAME_B"; do
  if docker logs "$name" 2>&1 | grep -qE 'AXUM\{'; then
    fail "container $name logs the flag"
  fi
done
pass "container logs contain no flag"

if docker run --rm --entrypoint sh "$IMAGE" -c \
  'grep -rIl "AXUM{\|team_a_test_flag\|team_b_test_flag" /app --exclude-dir=node_modules' \
  >/dev/null 2>&1; then
  fail "image contains flag-like content"
else
  pass "image contains no flag"
fi

info "Container security posture"
INSPECT=$(docker inspect "$NAME_A")
echo "$INSPECT" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0]
assert c["HostConfig"]["Privileged"] is False, "privileged"
assert c["Mounts"] == [], "mounts present"
assert c["Config"]["User"] == "node", "unexpected user"
' && pass "not privileged, no mounts, runs as node" || fail "container security posture is wrong"

IDENTITY=$(docker run --rm --entrypoint id "$IMAGE")
case "$IDENTITY" in
  *"uid=1000(node)"*) pass "runtime user is non-root ($IDENTITY)" ;;
  *) fail "unexpected runtime user: $IDENTITY" ;;
esac

SOCKET=$(echo "$INSPECT" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0]
print(any("docker.sock" in (m.get("Source","")+m.get("Destination","")) for m in c["Mounts"]))
')
[ "$SOCKET" = "False" ] && pass "Docker socket is not mounted" || fail "Docker socket is mounted"

info "Fail-closed and lifecycle"
if docker run --rm "$IMAGE" >"$WORK/noflag.log" 2>&1; then
  fail "container started without GZCTF_FLAG"
else
  pass "container refuses to start without GZCTF_FLAG"
fi
grep -q 'GZCTF_FLAG is missing or empty' "$WORK/noflag.log" \
  && pass "missing-flag error is explicit" || fail "missing-flag error is unclear"

docker stop "$NAME_A" >/dev/null
EXIT_CODE=$(docker inspect --format '{{.State.ExitCode}}' "$NAME_A")
[ "$EXIT_CODE" = "0" ] && pass "SIGTERM shuts the app down cleanly" || fail "container exited with $EXIT_CODE on stop"

info "Health"
for _ in $(seq 1 60); do
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$NAME_B")" = "healthy" ] && break
  sleep 1
done
[ "$(docker inspect --format '{{.State.Health.Status}}' "$NAME_B")" = "healthy" ] \
  && pass "container healthcheck reports healthy" || fail "container healthcheck is not healthy"

info "Participant simulation (documented path only)"
SIM="$WORK/sim.cookies"
login "$PORT_B" "$SIM" >/dev/null
curl -s -b "$SIM" "http://127.0.0.1:${PORT_B}/api/session" >"$WORK/sim-session.json"
ACCOUNT=$(json "['user']['accountId']" <"$WORK/sim-session.json")
curl -s -b "$SIM" "http://127.0.0.1:${PORT_B}/api/accounts/${ACCOUNT}" >"$WORK/sim-own.json"
curl -s -b "$SIM" "http://127.0.0.1:${PORT_B}/api/accounts/1002" >"$WORK/sim-target.json"
[ "$(json "['flag']" <"$WORK/sim-target.json")" = "$TEAM_B" ] \
  && pass "flag reachable by changing the account id in the observed API path" \
  || fail "participant simulation could not retrieve the flag"

echo
if [ "$FAILURES" -eq 0 ]; then
  printf '\033[32mAll WEB-02 Docker checks passed.\033[0m\n'
else
  printf '\033[31m%d check(s) failed.\033[0m\n' "$FAILURES"
  exit 1
fi
