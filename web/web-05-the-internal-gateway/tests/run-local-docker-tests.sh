#!/usr/bin/env bash
# Local Docker verification for WEB-05 — The Internal Gateway.
#
# Usage: ./tests/run-local-docker-tests.sh [image-tag]
set -uo pipefail

IMAGE="${1:-web-05-internal-gateway:test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FLAG_A='AXUM{team_a_test_flag}'
FLAG_B='AXUM{team_b_test_flag}'
SUFFIX="$$"
NET="w5-net-${SUFFIX}"
HELPER="w5-upstream-${SUFFIX}"
NAME_A="w5-team-a-${SUFFIX}"
NAME_B="w5-team-b-${SUFFIX}"
FAILURES=0
CHECKS=0

pass() { CHECKS=$((CHECKS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f "$NAME_A" "$NAME_B" "$HELPER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
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

jget() {
  python3 -c '
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except Exception:
    print("")
    raise SystemExit(0)
for key in sys.argv[1].split("."):
    if isinstance(data, list):
        data = data[int(key)]
    elif isinstance(data, dict):
        data = data.get(key)
    else:
        data = None
    if data is None:
        print("")
        raise SystemExit(0)
print(data)' "$1"
}

preview() {
  local port=$1 url=$2
  python3 - "$port" "$url" <<'PY'
import json, sys, urllib.request
port, url = sys.argv[1], sys.argv[2]
body = json.dumps({"url": url}).encode()
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/api/integrations/preview",
    data=body,
    headers={"content-type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        print(resp.read().decode("utf-8", "replace"))
except urllib.error.HTTPError as err:
    print(err.read().decode("utf-8", "replace"))
PY
}

preview_status() {
  local port=$1 url=$2
  python3 - "$port" "$url" <<'PY'
import json, sys, urllib.request, urllib.error
port, url = sys.argv[1], sys.argv[2]
body = json.dumps({"url": url}).encode()
req = urllib.request.Request(
    f"http://127.0.0.1:{port}/api/integrations/preview",
    data=body,
    headers={"content-type": "application/json"},
    method="POST",
)
try:
    with urllib.request.urlopen(req, timeout=20) as resp:
        print(resp.status)
except urllib.error.HTTPError as err:
    print(err.code)
except Exception:
    print("000")
PY
}

info "Building $IMAGE"
if docker build -q -t "$IMAGE" "$ROOT/source" >/dev/null 2>&1; then
  pass "image builds"
else
  fail "image build failed"
  exit 1
fi

info "Startup failure handling"
out=$(docker run --rm "$IMAGE" 2>&1); code=$?
if [ "$code" -ne 0 ] && printf '%s' "$out" | grep -q 'GZCTF_FLAG is missing'; then
  pass "container refuses to start without GZCTF_FLAG (exit $code)"
else
  fail "container started without GZCTF_FLAG (exit $code)"
fi

out=$(docker run --rm -e 'GZCTF_FLAG=' "$IMAGE" 2>&1); code=$?
if [ "$code" -ne 0 ]; then
  pass "container refuses to start with an empty GZCTF_FLAG (exit $code)"
else
  fail "container started with an empty GZCTF_FLAG"
fi

out=$(docker run --rm -e 'GZCTF_FLAG=   ' "$IMAGE" 2>&1); code=$?
if [ "$code" -ne 0 ]; then
  pass "container refuses to start with a blank GZCTF_FLAG (exit $code)"
else
  fail "container started with a blank GZCTF_FLAG"
fi

info "Starting fixture upstream and two team instances"
docker network create "$NET" >/dev/null 2>&1 || { fail "could not create test network"; exit 1; }

# The fixture is passed inline (base64) instead of bind-mounted so the suite
# also works on hosts with SELinux enforcing.
FIXTURE_B64=$(base64 -w0 "$ROOT/tests/fixtures/upstream-server.js")
docker run -d --name "$HELPER" --network "$NET" \
  node:22-alpine node -e "eval(Buffer.from(process.argv[1],'base64').toString())" "$FIXTURE_B64" >/dev/null
docker run -d --name "$NAME_A" --network "$NET" -e "GZCTF_FLAG=$FLAG_A" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
docker run -d --name "$NAME_B" --network "$NET" -e "GZCTF_FLAG=$FLAG_B" -p 127.0.0.1::3000 "$IMAGE" >/dev/null

PORT_A=$(host_port "$NAME_A")
PORT_B=$(host_port "$NAME_B")
[ -n "$PORT_A" ] && pass "team A published on 127.0.0.1:$PORT_A" || fail "team A has no published port"
[ -n "$PORT_B" ] && pass "team B published on 127.0.0.1:$PORT_B" || fail "team B has no published port"

wait_healthy "$NAME_A" && pass "team A container reports healthy" || fail "team A never became healthy"
wait_healthy "$NAME_B" && pass "team B container reports healthy" || fail "team B never became healthy"

HELPER_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HELPER" 2>/dev/null)
CHAL_A_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NAME_A" 2>/dev/null)

info "Gateway surface"
for path in / /assets/app.js /assets/styles.css /assets/favicon.svg /api/integrations /api/status /health; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT_A$path")
  [ "$code" = "200" ] && pass "GET $path -> 200" || fail "GET $path -> $code"
done

if curl -s "http://127.0.0.1:$PORT_A/" | grep -qi 'Meridian'; then
  pass "portal HTML renders the Meridian console"
else
  fail "portal HTML is missing the Meridian branding"
fi

if curl -s "http://127.0.0.1:$PORT_A/api/integrations" | grep -q '127.0.0.1:9000'; then
  pass "integration catalogue advertises the loopback diagnostics probe"
else
  fail "integration catalogue is missing the internal probe entry"
fi

info "Flag separation in assets and health"
for path in / /assets/app.js /assets/styles.css /api/status /health /api/integrations; do
  if curl -s "http://127.0.0.1:$PORT_A$path" | grep -qF "$FLAG_A"; then
    fail "$path leaks the runtime flag"
  else
    pass "$path does not contain the flag"
  fi
done

if docker logs "$NAME_A" 2>&1 | grep -qF "$FLAG_A"; then
  fail "container logs contain the flag"
else
  pass "container logs contain no flag"
fi

info "Process environment separation"
gw_pid=$(docker exec "$NAME_A" sh -c 'for p in /proc/[0-9]*; do cmd=$(tr "\0" " " < $p/cmdline 2>/dev/null); [ "$cmd" = "node /app/gateway/server.js " ] && echo "${p##*/}"; done' | head -n1)
in_pid=$(docker exec "$NAME_A" sh -c 'for p in /proc/[0-9]*; do cmd=$(tr "\0" " " < $p/cmdline 2>/dev/null); [ "$cmd" = "node /app/internal/server.js " ] && echo "${p##*/}"; done' | head -n1)

if [ -n "$gw_pid" ]; then
  hits=$(docker exec "$NAME_A" sh -c "grep -a -c GZCTF_FLAG= /proc/$gw_pid/environ 2>/dev/null")
  [ "$hits" = "0" ] && pass "gateway process environment has no GZCTF_FLAG" || fail "gateway process environment contains GZCTF_FLAG"
else
  fail "gateway process not found inside the container"
fi

if [ -n "$in_pid" ]; then
  hits=$(docker exec "$NAME_A" sh -c "grep -a -c GZCTF_FLAG= /proc/$in_pid/environ 2>/dev/null")
  [ "$hits" = "1" ] && pass "internal process environment carries GZCTF_FLAG" || fail "internal process is missing GZCTF_FLAG"
else
  fail "internal process not found inside the container"
fi

info "Internal service isolation"
if docker port "$NAME_A" 9000/tcp 2>/dev/null | grep -q .; then
  fail "internal port 9000 is published"
else
  pass "internal port 9000 is not published"
fi

published=$(docker port "$NAME_A" | wc -l | tr -d ' ')
[ "$published" = "1" ] && pass "exactly one port is published" || fail "$published ports are published"

if docker exec "$HELPER" sh -c "wget -q -T 2 -O /dev/null http://$CHAL_A_IP:9000/internal/health" >/dev/null 2>&1; then
  fail "another container on the same network can reach the internal service directly"
else
  pass "internal service is unreachable from other containers on the network"
fi

info "URL validation"
body=$(preview "$PORT_A" 'not-a-url')
[ "$(printf '%s' "$body" | jget error)" = "invalid_url" ] && pass "malformed URL -> invalid_url" || fail "malformed URL not rejected"

status=$(preview_status "$PORT_A" 'file:///etc/passwd')
[ "$status" = "400" ] && pass "file:// scheme rejected with 400" || fail "file:// scheme returned $status"

body=$(preview "$PORT_A" 'file:///etc/passwd')
[ "$(printf '%s' "$body" | jget error)" = "unsupported_scheme" ] && pass "file:// -> unsupported_scheme" || fail "file:// -> $(printf '%s' "$body" | jget error)"

status=$(preview_status "$PORT_A" 'gopher://127.0.0.1:9000/')
[ "$status" = "400" ] && pass "gopher:// scheme rejected with 400" || fail "gopher:// scheme returned $status"

status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$PORT_A/api/integrations/preview" -H 'Content-Type: application/json' -d '{}')
[ "$status" = "400" ] && pass "missing url -> 400" || fail "missing url -> $status"

info "Functional preview against the fixture"
body=$(preview "$PORT_A" "http://$HELPER_IP:9100/ok")
[ "$(printf '%s' "$body" | jget success)" = "True" ] && pass "preview of /ok succeeded" || fail "preview of /ok failed"
[ "$(printf '%s' "$body" | jget status)" = "200" ] && pass "preview reports upstream status 200" || fail "preview reported status $(printf '%s' "$body" | jget status)"
printf '%s' "$body" | jget body | grep -q 'fixture' && pass "preview relays the upstream body" || fail "preview did not relay the upstream body"

ctype=$(curl -s -o /dev/null -w '%{content_type}' -X POST "http://127.0.0.1:$PORT_A/api/integrations/preview" -H 'Content-Type: application/json' -d "{\"url\":\"http://$HELPER_IP:9100/html\"}")
printf '%s' "$ctype" | grep -q 'application/json' && pass "preview responses are JSON, never rendered HTML" || fail "preview content type is $ctype"

body=$(preview "$PORT_A" "http://$HELPER_IP:9100/html")
printf '%s' "$body" | jget body | grep -q '<script>' && pass "previewed HTML is returned as escaped text" || fail "previewed HTML body missing"

info "Redirect, size limit and timeout handling"
body=$(preview "$PORT_A" "http://$HELPER_IP:9100/redirect")
[ "$(printf '%s' "$body" | jget status)" = "302" ] && pass "redirect is not followed (302 relayed)" || fail "redirect produced status $(printf '%s' "$body" | jget status)"
if printf '%s' "$body" | jget body | grep -qF "$FLAG_A"; then
  fail "redirect-following leaked the flag"
else
  pass "redirect response does not contain the flag"
fi

body=$(preview "$PORT_A" "http://$HELPER_IP:9100/large")
[ "$(printf '%s' "$body" | jget truncated)" = "True" ] && pass "oversized response is flagged as truncated" || fail "oversized response was not truncated"
size=$(printf '%s' "$body" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["body"]))')
[ "$size" -le 65536 ] && pass "response body capped at 64 KiB (got ${size} bytes)" || fail "response body exceeded the cap (${size} bytes)"

status=$(preview_status "$PORT_A" "http://$HELPER_IP:9100/slow")
[ "$status" = "504" ] && pass "slow upstream times out with 504" || fail "slow upstream returned $status"

status=$(preview_status "$PORT_A" "http://127.0.0.1:9/closed")
[ "$status" = "502" ] && pass "closed port returns 502 without a stack trace" || fail "closed port returned $status"

info "Header filtering"
body=$(preview "$PORT_A" "http://$HELPER_IP:9100/headers")
if printf '%s' "$body" | grep -qi 'set-cookie'; then
  fail "set-cookie header was relayed to the client"
else
  pass "set-cookie header is not relayed"
fi
if printf '%s' "$body" | grep -qi 'x-secret-debug'; then
  fail "unlisted upstream header was relayed"
else
  pass "unlisted upstream headers are dropped"
fi
printf '%s' "$body" | grep -qi 'x-request-id' && pass "allowlisted upstream headers are relayed" || fail "allowlisted header missing"

info "SSRF solve path"
body=$(preview "$PORT_A" 'http://127.0.0.1:9000/internal/health')
[ "$(printf '%s' "$body" | jget success)" = "True" ] && pass "gateway reaches the hidden internal service" || fail "gateway cannot reach the internal service"
[ "$(printf '%s' "$body" | jget status)" = "200" ] && pass "internal health returns 200 through the gateway" || fail "internal health returned $(printf '%s' "$body" | jget status)"

body=$(preview "$PORT_A" 'http://127.0.0.1:9000/internal/services')
printf '%s' "$body" | jget body | grep -q 'diagnostics' && pass "service catalogue reveals the diagnostics service" || fail "service catalogue missing diagnostics entries"

body=$(preview "$PORT_A" 'http://127.0.0.1:9000/internal/diagnostics/record')
record_a=$(printf '%s' "$body" | jget body)
printf '%s' "$record_a" | grep -qF "$FLAG_A" && pass "diagnostics record returns team A's flag through the gateway" || fail "diagnostics record did not return team A's flag"
printf '%s' "$record_a" | grep -q 'MD-OPS-204' && pass "diagnostics record contains the restricted record id" || fail "diagnostics record id missing"

info "Two-instance flag isolation"
body_b=$(preview "$PORT_B" 'http://127.0.0.1:9000/internal/diagnostics/record')
record_b=$(printf '%s' "$body_b" | jget body)
printf '%s' "$record_b" | grep -qF "$FLAG_B" && pass "instance B returns team B's flag" || fail "instance B did not return its own flag"

if printf '%s' "$record_b" | grep -qF "$FLAG_A"; then
  fail "instance B leaked team A's flag"
else
  pass "instance B never returns team A's flag"
fi

if printf '%s' "$record_a" | grep -qF "$FLAG_B"; then
  fail "instance A leaked team B's flag"
else
  pass "instance A never returns team B's flag"
fi

[ "$record_a" != "$record_b" ] && pass "the two instances expose different flag values" || fail "both instances returned identical records"

info "Image and runtime hardening"
if docker run --rm --entrypoint sh "$IMAGE" -c "grep -rlF '$FLAG_A' /app /usr/src 2>/dev/null | head -n1" | grep -q .; then
  fail "the test flag is baked into the image"
else
  pass "no flag is baked into the image"
fi

user=$(docker inspect --format '{{.Config.User}}' "$NAME_A")
[ "$user" = "node" ] && pass "image runs as the non-root node user" || fail "image user is '$user'"
uid=$(docker exec "$NAME_A" id -u)
[ "$uid" = "1000" ] && pass "runtime uid is 1000" || fail "runtime uid is $uid"

[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$NAME_A")" = "false" ] && pass "container is not privileged" || fail "container is privileged"
[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NAME_A")" = "$NET" ] && pass "container uses a bridge network, not host networking" || fail "unexpected network mode"
[ "$(docker inspect --format '{{len .HostConfig.Binds}}' "$NAME_A")" = "0" ] && pass "no host directory is bind-mounted" || fail "host bind mounts present"
[ "$(docker inspect --format '{{len .Mounts}}' "$NAME_A")" = "0" ] && pass "container declares no mounts" || fail "container declares mounts"
if docker inspect --format '{{json .Mounts}}' "$NAME_A" | grep -q 'docker.sock'; then
  fail "the Docker socket is mounted"
else
  pass "the Docker socket is not mounted"
fi

info "Shutdown behaviour"
docker stop -t 10 "$NAME_A" >/dev/null 2>&1
code=$(docker inspect --format '{{.State.ExitCode}}' "$NAME_A" 2>/dev/null)
[ "$code" = "0" ] || [ "$code" = "143" ] && pass "container stops cleanly on SIGTERM (exit $code)" || fail "container exited with $code"

printf '\n\033[1mSummary\033[0m: %d checks, %d failed\n' "$CHECKS" "$FAILURES"
[ "$FAILURES" -eq 0 ]
