#!/usr/bin/env bash
# Local Docker verification for REV-01 — The Broken License.
#
# Usage: ./tests/run-local-docker-tests.sh [image-tag]
set -uo pipefail

IMAGE="${1:-rev-01-broken-license:test}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FLAG_A='GZCTF{REV01_TEST_FLAG}'
FLAG_B='GZCTF{TEAM_A_TEST}'
FLAG_C='GZCTF{TEAM_B_TEST}'
SUFFIX="$$"
NAME_A="rev01-a-${SUFFIX}"
NAME_B="rev01-b-${SUFFIX}"
NAME_C="rev01-c-${SUFFIX}"
WORK="$(mktemp -d)"
FAILURES=0
CHECKS=0

pass() { CHECKS=$((CHECKS + 1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { CHECKS=$((CHECKS + 1)); FAILURES=$((FAILURES + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
info() { printf '\n\033[1m%s\033[0m\n' "$1"; }

cleanup() {
  docker rm -f "$NAME_A" "$NAME_B" "$NAME_C" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

host_port() { docker port "$1" 3000/tcp 2>/dev/null | head -n1 | sed 's/.*://'; }

wait_healthy() {
  for _ in $(seq 1 60); do
    if [ "$(docker inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null)" = "healthy" ]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# Copies the packaged binary (and optionally a license.dat) into /tmp/nsl inside
# a container so the executable can be exercised without host execution.
prep_env() {
  docker exec "$1" sh -c 'rm -rf /tmp/nsl && mkdir -p /tmp/nsl && cp /app/bin/northstar-license /tmp/nsl/' >/dev/null 2>&1
  if [ -n "${2:-}" ]; then
    docker exec -i "$1" sh -c 'cat > /tmp/nsl/license.dat' < "$2"
  fi
}

run_binary() {
  if [ -n "${2:-}" ]; then
    printf '%s\n' "$2" | docker exec -i "$1" sh -c 'cd /tmp/nsl && ./northstar-license' 2>&1
  else
    docker exec -i "$1" sh -c 'cd /tmp/nsl && ./northstar-license' </dev/null 2>&1
  fi
}

fetch_zip() {
  local port=$1 out=$2
  curl -fsS --max-time 30 -o "$out" "http://127.0.0.1:${port}/download" 2>/dev/null
}

zip_list() { python3 -c 'import sys,zipfile; print("\n".join(sorted(zipfile.ZipFile(sys.argv[1]).namelist())))' "$1"; }
zip_entry_mode() {
  python3 -c '
import sys, zipfile
info = zipfile.ZipFile(sys.argv[1]).getinfo(sys.argv[2])
print(oct((info.external_attr >> 16) & 0o777))' "$1" "$2"
}
zip_extract() {
  rm -rf "$2"
  mkdir -p "$2"
  python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$1" "$2"
}

info "Building $IMAGE"
if docker build -q -t "$IMAGE" "$ROOT/source" >/dev/null 2>&1; then
  pass "image builds"
else
  fail "image build failed"
  printf '\n\033[1mSummary\033[0m: %d checks, %d failed\n' "$CHECKS" "$FAILURES"
  exit 1
fi

info "C source: compile diagnostics from the build stage"
if docker run --rm --entrypoint sh "$IMAGE" -c 'test -x /app/bin/northstar-license'; then
  pass "packaged executable is present and executable"
else
  fail "packaged executable is missing"
fi

docker create --name "$NAME_A" "$IMAGE" >/dev/null 2>&1
docker cp "$NAME_A:/app/bin/northstar-license" "$WORK/northstar-license" >/dev/null 2>&1 \
  && pass "executable extracted from the image" \
  || fail "could not extract the executable from the image"
docker rm -f "$NAME_A" >/dev/null 2>&1

if [ -f "$WORK/northstar-license" ]; then
  desc=$(file -b "$WORK/northstar-license")
  printf '       %s\n' "$desc"
  case "$desc" in
    *"ELF 64-bit"*"x86-64"*) pass "binary is ELF64 x86_64" ;;
    *) fail "binary is not ELF64 x86_64: $desc" ;;
  esac
  case "$desc" in
    *"statically linked"*|*"static-pie linked"*) pass "binary is statically linked and runs on any Linux x86_64 host" ;;
    *) fail "binary is not statically linked: $desc" ;;
  esac
  case "$desc" in
    *"not stripped"*) pass "symbols are retained for the intended analysis" ;;
    *) fail "binary was stripped" ;;
  esac

  if python3 - "$WORK/northstar-license" <<'PY'
import sys
blob = open(sys.argv[1], "rb").read()
e_shoff = int.from_bytes(blob[0x28:0x30], "little")
e_shentsize = int.from_bytes(blob[0x3A:0x3C], "little")
e_shnum = int.from_bytes(blob[0x3C:0x3E], "little")
e_shstrndx = int.from_bytes(blob[0x3E:0x40], "little")
def head(i):
    b = e_shoff + i * e_shentsize
    return (int.from_bytes(blob[b:b + 4], "little"), int.from_bytes(blob[b + 0x18:b + 0x20], "little"))
names_off = head(e_shstrndx)[1]
names = []
for i in range(e_shnum):
    idx = head(i)[0]
    names.append(blob[names_off + idx:blob.index(b"\x00", names_off + idx)].decode("latin-1"))
sys.exit(0 if not any(n.startswith(".debug") for n in names) else 1)
PY
  then
    pass "binary contains no debug information"
  else
    fail "binary contains debug sections"
  fi

  if grep -ao 'validate_license' "$WORK/northstar-license" >/dev/null 2>&1; then
    pass "validate_license symbol is present in the symbol table"
  else
    fail "validate_license symbol is missing"
  fi

  if grep -ao 'NorthstarK3y' "$WORK/northstar-license" >/dev/null 2>&1; then
    pass "transformation key is discoverable in .rodata"
  else
    fail "transformation key is not present in the binary"
  fi

  leaked=0
  for secret in "$FLAG_A" "$FLAG_B" "$FLAG_C"; do
    if grep -aoF "$secret" "$WORK/northstar-license" >/dev/null 2>&1; then
      fail "plaintext flag $secret appears in the binary"
      leaked=1
    fi
  done
  [ "$leaked" = "0" ] && pass "no plaintext team flag appears in the binary"
fi

info "Startup rejection of bad GZCTF_FLAG values"
out=$(docker run --rm "$IMAGE" 2>&1); code=$?
if [ "$code" -ne 0 ] && printf '%s' "$out" | grep -q 'GZCTF_FLAG is missing'; then
  pass "missing flag aborts startup (exit $code)"
else
  fail "container started without a flag (exit $code)"
fi

out=$(docker run --rm -e 'GZCTF_FLAG=' "$IMAGE" 2>&1); code=$?
[ "$code" -ne 0 ] && pass "empty flag aborts startup (exit $code)" || fail "container started with an empty flag"

out=$(docker run --rm -e 'GZCTF_FLAG=   ' "$IMAGE" 2>&1); code=$?
[ "$code" -ne 0 ] && pass "blank flag aborts startup (exit $code)" || fail "container started with a blank flag"

LONG_FLAG="GZCTF{$(python3 -c 'print("A"*140)')}"
out=$(docker run --rm -e "GZCTF_FLAG=$LONG_FLAG" "$IMAGE" 2>&1); code=$?
if [ "$code" -ne 0 ] && printf '%s' "$out" | grep -q 'outside the supported range'; then
  pass "over-long flag is rejected instead of truncated (exit $code)"
else
  fail "over-long flag was not rejected (exit $code)"
fi
if printf '%s' "$out" | grep -qF "$LONG_FLAG"; then
  fail "the rejection message discloses the rejected flag value"
else
  pass "rejection message does not disclose the flag"
fi

out=$(docker run --rm -e $'GZCTF_FLAG=GZCTF{bad\xc3\xa9}' "$IMAGE" 2>&1); code=$?
if [ "$code" -ne 0 ] && printf '%s' "$out" | grep -q 'outside the supported range'; then
  pass "non-ASCII flag is rejected (exit $code)"
else
  fail "non-ASCII flag was not rejected (exit $code)"
fi

info "Starting three instances"
docker run -d --name "$NAME_A" -e "GZCTF_FLAG=$FLAG_A" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
docker run -d --name "$NAME_B" -e "GZCTF_FLAG=$FLAG_B" -p 127.0.0.1::3000 "$IMAGE" >/dev/null
docker run -d --name "$NAME_C" -e "GZCTF_FLAG=$FLAG_C" -p 127.0.0.1::3000 "$IMAGE" >/dev/null

PORT_A=$(host_port "$NAME_A"); PORT_B=$(host_port "$NAME_B"); PORT_C=$(host_port "$NAME_C")
[ -n "$PORT_A" ] && [ -n "$PORT_B" ] && [ -n "$PORT_C" ] \
  && pass "three instances published on $PORT_A, $PORT_B, $PORT_C" \
  || fail "could not resolve published ports"

for pair in "A:$NAME_A" "B:$NAME_B" "C:$NAME_C"; do
  label=${pair%%:*}; name=${pair#*:}
  wait_healthy "$name" && pass "instance $label reports healthy" || fail "instance $label never became healthy"
done

info "Download service surface"
for path in / /assets/styles.css /assets/favicon.svg /health /download; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_A}${path}")
  [ "$code" = "200" ] && pass "GET $path -> 200" || fail "GET $path -> $code"
done

code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT_A}/does-not-exist")
[ "$code" = "404" ] && pass "unknown path -> 404" || fail "unknown path -> $code"

if curl -s "http://127.0.0.1:${PORT_A}/" | grep -q 'Northstar License Manager'; then
  pass "landing page renders the product identity"
else
  fail "landing page is missing the product identity"
fi

if curl -s "http://127.0.0.1:${PORT_A}/" | grep -qi 'x86_64'; then
  pass "landing page states the Linux x86_64 requirement"
else
  fail "landing page omits the platform requirement"
fi

if curl -s "http://127.0.0.1:${PORT_A}/" | grep -qiF 'NorthstarK3y'; then
  fail "landing page discloses the transformation key"
else
  pass "landing page does not disclose the transformation key"
fi

if curl -s "http://127.0.0.1:${PORT_A}/health" | grep -q '"archive":"ready"'; then
  pass "health endpoint reports the archive as ready"
else
  fail "health endpoint does not report archive readiness"
fi

headers=$(curl -sSD - -o /dev/null "http://127.0.0.1:${PORT_A}/download")
printf '%s' "$headers" | grep -qi 'content-type: application/zip' \
  && pass "download sends application/zip" || fail "download content type is wrong"
printf '%s' "$headers" | grep -qi 'content-disposition: attachment; filename="northstar-license-package.zip"' \
  && pass "download sets the expected filename" || fail "download filename header is wrong"

info "Artifact generation"
fetch_zip "$PORT_A" "$WORK/a.zip" && pass "package downloaded from instance A" || fail "package download failed"
fetch_zip "$PORT_B" "$WORK/b.zip" && pass "package downloaded from instance B" || fail "package download failed"

expected="northstar-license-package/README.txt
northstar-license-package/license.dat
northstar-license-package/northstar-license"
actual=$(zip_list "$WORK/a.zip")
if [ "$actual" = "$expected" ]; then
  pass "archive contains exactly the three expected files"
else
  fail "archive contents are unexpected: $(printf '%s' "$actual" | tr '\n' ' ')"
fi

[ "$(zip_entry_mode "$WORK/a.zip" 'northstar-license-package/northstar-license')" = "0o755" ] \
  && pass "packaged executable keeps mode 0755" \
  || fail "packaged executable mode is $(zip_entry_mode "$WORK/a.zip" 'northstar-license-package/northstar-license')"

if grep -aoF "$FLAG_A" "$WORK/a.zip" >/dev/null 2>&1; then
  fail "the ZIP archive contains the plaintext flag"
else
  pass "the ZIP archive contains no plaintext flag"
fi

zip_extract "$WORK/a.zip" "$WORK/pkg-a"
DATA_A="$WORK/pkg-a/northstar-license-package/license.dat"
BIN_A="$WORK/pkg-a/northstar-license-package/northstar-license"

if [ -f "$DATA_A" ] && [ -s "$DATA_A" ]; then
  pass "license.dat is generated ($(wc -c < "$DATA_A" | tr -d ' ') bytes)"
else
  fail "license.dat is missing or empty"
fi

if grep -aoF "$FLAG_A" "$DATA_A" >/dev/null 2>&1; then
  fail "license.dat contains the plaintext flag"
else
  pass "license.dat contains no plaintext flag"
fi

info "Independent static recovery (ELF + license.dat only)"
if recovered=$(python3 "$ROOT/tests/recover-flag.py" --binary "$BIN_A" --data "$DATA_A" --quiet 2>&1); then
  if [ "$recovered" = "$FLAG_A" ]; then
    pass "recovery from the artifact equals the injected flag"
  else
    fail "recovery returned '$recovered', expected '$FLAG_A'"
  fi
else
  fail "static recovery failed: $recovered"
fi

python3 "$ROOT/tests/recover-flag.py" --binary "$BIN_A" --data "$DATA_A" 2>&1 | sed 's/^/       /'

info "C validator behaviour"
prep_env "$NAME_A" "$DATA_A"
out=$(run_binary "$NAME_A" "$FLAG_A")
printf '%s' "$out" | grep -q 'License accepted' \
  && pass "recovered key is accepted by the packaged binary" \
  || fail "packaged binary rejected the recovered key: $out"

prep_env "$NAME_A" "$DATA_A"
out=$(run_binary "$NAME_A" 'GZCTF{WRONG_KEY}')
printf '%s' "$out" | grep -q 'License rejected' \
  && pass "incorrect key is rejected" || fail "incorrect key was accepted: $out"

prep_env "$NAME_A" "$DATA_A"
out=$(run_binary "$NAME_A" 'GZCTF{REV01_TEST_FLAG_EXTENDED}')
printf '%s' "$out" | grep -q 'License rejected' \
  && pass "key with the wrong length is rejected" || fail "wrong-length key was accepted: $out"

prep_env "$NAME_A" ''
out=$(run_binary "$NAME_A" "$FLAG_A")
printf '%s' "$out" | grep -q 'license.dat is missing' \
  && pass "missing license.dat is reported clearly" || fail "missing license.dat was not handled: $out"

: > "$WORK/empty.dat"
prep_env "$NAME_A" "$WORK/empty.dat"
out=$(run_binary "$NAME_A" "$FLAG_A")
printf '%s' "$out" | grep -q 'could not be read or is corrupted' \
  && pass "empty license.dat is rejected as malformed" || fail "empty license.dat was not rejected: $out"

python3 -c 'import sys; open(sys.argv[1], "wb").write(b"\x00" * 300)' "$WORK/oversized.dat"
prep_env "$NAME_A" "$WORK/oversized.dat"
out=$(run_binary "$NAME_A" "$FLAG_A")
printf '%s' "$out" | grep -q 'could not be read or is corrupted' \
  && pass "oversized license.dat is rejected as malformed" || fail "oversized license.dat was not rejected: $out"

prep_env "$NAME_A" "$DATA_A"
out=$(run_binary "$NAME_A" '')
printf '%s' "$out" | grep -qi 'No license key entered' \
  && pass "empty input is handled without a crash" || fail "empty input handling is wrong: $out"

info "Per-team isolation"
zip_extract "$WORK/b.zip" "$WORK/pkg-b"
DATA_B="$WORK/pkg-b/northstar-license-package/license.dat"

recovered_b=$(python3 "$ROOT/tests/recover-flag.py" --binary "$BIN_A" --data "$DATA_B" --quiet 2>&1)
[ "$recovered_b" = "$FLAG_B" ] \
  && pass "instance B's archive recovers instance B's flag" \
  || fail "instance B recovered '$recovered_b', expected '$FLAG_B'"

fetch_zip "$PORT_C" "$WORK/c.zip"
zip_extract "$WORK/c.zip" "$WORK/pkg-c"
recovered_c=$(python3 "$ROOT/tests/recover-flag.py" --binary "$BIN_A" \
  --data "$WORK/pkg-c/northstar-license-package/license.dat" --quiet 2>&1)
[ "$recovered_c" = "$FLAG_C" ] \
  && pass "instance C's archive recovers instance C's flag" \
  || fail "instance C recovered '$recovered_c', expected '$FLAG_C'"

if cmp -s "$DATA_A" "$DATA_B"; then
  fail "the two instances produced identical license data"
else
  pass "the two instances produced different license data"
fi

if grep -aoF "$FLAG_B" "$WORK/a.zip" >/dev/null 2>&1 || grep -aoF "$FLAG_C" "$WORK/a.zip" >/dev/null 2>&1; then
  fail "instance A's archive contains another team's flag"
else
  pass "instance A's archive contains no other team's flag"
fi

sha_a=$(sha256sum "$WORK/a.zip" | cut -d' ' -f1)
sha_b=$(sha256sum "$WORK/b.zip" | cut -d' ' -f1)
[ "$sha_a" != "$sha_b" ] && pass "per-team archives differ ($(printf '%.12s' "$sha_a") vs $(printf '%.12s' "$sha_b"))" \
  || fail "per-team archives are identical"

info "Flag handling in logs and runtime environment"
if docker logs "$NAME_A" 2>&1 | grep -qF "$FLAG_A"; then
  fail "container logs contain the plaintext flag"
else
  pass "container logs contain no plaintext flag"
fi

server_pid=$(docker exec "$NAME_A" sh -c 'for p in /proc/[0-9]*; do cmd=$(tr "\0" " " < $p/cmdline 2>/dev/null); [ "$cmd" = "node /app/server.js " ] && echo "${p##*/}"; done' | head -n1)
if [ -n "$server_pid" ]; then
  hits=$(docker exec "$NAME_A" sh -c "grep -a -c GZCTF_FLAG= /proc/$server_pid/environ 2>/dev/null")
  [ "$hits" = "0" ] && pass "download service environment has no GZCTF_FLAG" \
    || fail "download service environment contains GZCTF_FLAG"
else
  fail "download service process not found inside the container"
fi

if docker run --rm --entrypoint sh "$IMAGE" -c "grep -ralF '$FLAG_A' /app 2>/dev/null | head -n1" | grep -q .; then
  fail "a team flag is baked into the image"
else
  pass "no team flag is baked into the image"
fi

if docker inspect "$NAME_A" --format '{{json .Config.Env}}' | grep -q 'GZCTF_FLAG'; then
  fail "the running container still declares GZCTF_FLAG in its configuration"
else
  pass "the flag was consumed and is absent from the container configuration"
fi

info "Container hardening"
user=$(docker inspect --format '{{.Config.User}}' "$NAME_A")
[ "$user" = "node" ] && pass "image runs as the non-root node user" || fail "image user is '$user'"
uid=$(docker exec "$NAME_A" id -u)
[ "$uid" = "1000" ] && pass "runtime uid is 1000" || fail "runtime uid is $uid"
[ "$(docker inspect --format '{{.HostConfig.Privileged}}' "$NAME_A")" = "false" ] && pass "container is not privileged" || fail "container is privileged"
[ "$(docker inspect --format '{{len .HostConfig.Binds}}' "$NAME_A")" = "0" ] && pass "no host directory is bind-mounted" || fail "host bind mounts present"
[ "$(docker inspect --format '{{len .Mounts}}' "$NAME_A")" = "0" ] && pass "container declares no mounts" || fail "container declares mounts"
if docker inspect --format '{{json .Mounts}}' "$NAME_A" | grep -q 'docker.sock'; then
  fail "the Docker socket is mounted"
else
  pass "the Docker socket is not mounted"
fi
[ "$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$NAME_A")" = "bridge" ] \
  && pass "container uses bridge networking, not host networking" || fail "unexpected network mode"

published=$(docker port "$NAME_A" | wc -l | tr -d ' ')
[ "$published" = "1" ] && pass "exactly one port is published" || fail "$published ports are published"

info "Shutdown behaviour"
docker stop -t 10 "$NAME_A" >/dev/null 2>&1
code=$(docker inspect --format '{{.State.ExitCode}}' "$NAME_A" 2>/dev/null)
{ [ "$code" = "0" ] || [ "$code" = "143" ]; } && pass "container stops cleanly on SIGTERM (exit $code)" \
  || fail "container exited with $code"

printf '\n\033[1mSummary\033[0m: %d checks, %d failed\n' "$CHECKS" "$FAILURES"
[ "$FAILURES" -eq 0 ]
