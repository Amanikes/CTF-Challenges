#!/usr/bin/env bash
# Local Docker verification for WEB-03 — Hidden in Plain Sight.
# Usage: ./tests/run-local-docker-tests.sh [image-tag]
set -euo pipefail

IMAGE="${1:-web-03-hidden-in-plain-sight:test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEAM_A='AXUM{team_a_test_flag}'
TEAM_B='AXUM{team_b_test_flag}'
NAME_A="web03-test-a-$$"
NAME_B="web03-test-b-$$"
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
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}

expect_status() {
  local url=$1 expected=$2 actual
  actual=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  if [ "$actual" = "$expected" ]; then pass "$url -> $actual"
  else fail "$url -> $actual (expected $expected)"; fi
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

BASE_A="http://127.0.0.1:${PORT_A}"
BASE_B="http://127.0.0.1:${PORT_B}"

info "Functional tests"
expect_status "$BASE_A/" 200
expect_status "$BASE_A/assets/app.js" 200
expect_status "$BASE_A/assets/style.css" 200
expect_status "$BASE_A/health" 200

curl -s "$BASE_A/" -o "$WORK/index.html"
grep -qi 'Meridian' "$WORK/index.html" && pass "dashboard is Meridian-branded" || fail "dashboard branding missing"
grep -q '<script src="/assets/app.js"' "$WORK/index.html" \
  && pass "bundle is loaded through a normal script reference" || fail "script reference missing"

curl -s "$BASE_A/api/projects" -o "$WORK/projects.json"
[ "$(json "['workspace']['organization']" <"$WORK/projects.json")" = "Meridian Technologies" ] \
  && pass "public projects API returns valid JSON" || fail "projects API payload unexpected"
COUNT=$(json "['projects'].__len__()" <"$WORK/projects.json")
[ "$COUNT" -ge 5 ] && pass "public API exposes $COUNT portfolio projects" || fail "portfolio too small ($COUNT)"

curl -s "$BASE_A/api/internal/project-preview" -o "$WORK/internal_a.json"
[ "$(json "['project']['name']" <"$WORK/internal_a.json")" = "Orion Internal Platform" ] \
  && pass "internal preview returns the internal project record" || fail "internal project record missing"
[ "$(json "['flag']" <"$WORK/internal_a.json")" = "$TEAM_A" ] \
  && pass "internal preview returns instance A's runtime flag" || fail "flag missing from internal preview"

CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_A/api/internal/project-preview")
[ "$CODE" = "200" ] && pass "internal endpoint needs no authentication" || fail "internal endpoint returned $CODE"

if curl -s "$BASE_A/health" | grep -q 'AXUM{'; then fail "health endpoint exposes the flag";
else pass "health endpoint exposes no flag"; fi

info "JavaScript bundle disclosure"
curl -s "$BASE_A/assets/app.js" -o "$WORK/app.js"
grep -q 'api/internal/project-preview' "$WORK/app.js" \
  && pass "bundle references the internal preview route" || fail "bundle does not reference the internal route"
grep -q 'internalPreview' "$WORK/app.js" \
  && pass "route is part of a named configuration entry" || fail "configuration entry missing"

if grep -q 'AXUM{' "$WORK/app.js"; then fail "bundle contains the flag";
else pass "bundle contains no flag"; fi
if grep -q 'Orion Internal Platform' "$WORK/app.js"; then fail "bundle contains the internal record";
else pass "bundle contains no internal project record"; fi
if grep -q 'AXUM{' "$WORK/index.html"; then fail "HTML contains the flag";
else pass "HTML contains no flag"; fi
curl -s "$BASE_A/assets/style.css" -o "$WORK/style.css"
if grep -q 'AXUM{' "$WORK/style.css"; then fail "CSS contains the flag";
else pass "CSS contains no flag"; fi

expect_status "$BASE_A/assets/app.js.map" 404
expect_status "$BASE_A/assets/style.css.map" 404
find "$ROOT/source/public" -name '*.map' | grep -q . \
  && fail "source maps present in public assets" || pass "no source maps in public assets"

info "No automatic call on page load"
if node "$ROOT/tests/check-no-autoload.js" "$WORK/app.js" >"$WORK/autoload.json" 2>&1; then
  pass "loading the bundle requests only the public project API"
else
  fail "bundle requested an internal endpoint on load"
  sed -n '1,20p' "$WORK/autoload.json" | sed 's/^/        /'
fi
if grep -q 'features.internalPreview' "$WORK/app.js"; then
  pass "call is gated behind the internalPreview feature switch"
else
  fail "no feature gate protects the internal preview call"
fi
SWITCH=$(grep -o 'internalPreview: [a-z]*' "$WORK/app.js" | head -1 | awk '{print $2}')
[ "$SWITCH" = "false" ] && pass "internalPreview switch is off in the public bundle" \
  || fail "internalPreview switch is '$SWITCH'"

info "Dynamic flag isolation"
curl -s "$BASE_B/api/internal/project-preview" -o "$WORK/internal_b.json"
[ "$(json "['flag']" <"$WORK/internal_b.json")" = "$TEAM_B" ] \
  && pass "instance B returns its own flag" || fail "instance B flag mismatch"
if grep -q "$TEAM_B" "$WORK/internal_a.json"; then fail "instance A returns instance B's flag";
else pass "instance A never returns instance B's flag"; fi
if grep -q "$TEAM_A" "$WORK/internal_b.json"; then fail "instance B returns instance A's flag";
else pass "instance B never returns instance A's flag"; fi

info "Image hygiene"
if docker run --rm --entrypoint sh "$IMAGE" -c \
  'grep -rIl "AXUM{\|team_a_test_flag\|team_b_test_flag" /app --exclude-dir=node_modules' >/dev/null 2>&1; then
  fail "image contains flag-like content"
else
  pass "image contains no flag"
fi

for name in "$NAME_A" "$NAME_B"; do
  if docker logs "$name" 2>&1 | grep -qE 'AXUM\{'; then fail "container $name logs the flag"; fi
done
pass "container logs contain no flag"

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

echo "$INSPECT" | python3 -c '
import json,sys
c=json.load(sys.stdin)[0]
sys.exit(0 if not any("docker.sock" in (m.get("Source","")+m.get("Destination","")) for m in c["Mounts"]) else 1)
' && pass "Docker socket is not mounted" || fail "Docker socket is mounted"

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

echo
if [ "$FAILURES" -eq 0 ]; then
  printf '\033[32mAll WEB-03 Docker checks passed.\033[0m\n'
else
  printf '\033[31m%d check(s) failed.\033[0m\n' "$FAILURES"
  exit 1
fi
