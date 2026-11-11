#!/bin/sh
# Meridian Integration Console — single-container, two-process entrypoint.
#
# GZ::CTF 1.9.1 exposes exactly one image and one exposed port per dynamic
# container, so this challenge uses the documented fallback topology:
#
#   participant -> gateway 0.0.0.0:${PORT} (published)
#                       |
#                       v
#                 internal API 127.0.0.1:${INTERNAL_PORT} (never published)
#
# The flag is injected into the internal process only. It is removed from this
# shell's environment before the gateway starts, so the gateway process never
# inherits it.
set -eu

PORT="${PORT:-3000}"
INTERNAL_PORT="${INTERNAL_PORT:-9000}"

if [ -z "${GZCTF_FLAG:-}" ]; then
  echo '[entrypoint] GZCTF_FLAG is missing or empty; refusing to start' >&2
  exit 1
fi

case "$GZCTF_FLAG" in
  *[![:space:]]*) ;;
  *)
    echo '[entrypoint] GZCTF_FLAG is blank; refusing to start' >&2
    exit 1
    ;;
esac

internal_pid=''
gateway_pid=''

stop_all() {
  trap - TERM INT

  if [ -n "$gateway_pid" ]; then
    kill -TERM "$gateway_pid" 2>/dev/null || true
  fi
  if [ -n "$internal_pid" ]; then
    kill -TERM "$internal_pid" 2>/dev/null || true
  fi

  if [ -n "$gateway_pid" ]; then
    wait "$gateway_pid" 2>/dev/null || true
  fi
  if [ -n "$internal_pid" ]; then
    wait "$internal_pid" 2>/dev/null || true
  fi
}

trap 'stop_all; exit 143' TERM
trap 'stop_all; exit 130' INT

# The internal service is the only process that receives the flag.
GZCTF_FLAG="$GZCTF_FLAG" INTERNAL_PORT="$INTERNAL_PORT" node /app/internal/server.js &
internal_pid=$!

ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
  if ! kill -0 "$internal_pid" 2>/dev/null; then
    echo '[entrypoint] internal service exited during startup' >&2
    stop_all
    exit 1
  fi

  if wget -q -T 2 -O /dev/null "http://127.0.0.1:${INTERNAL_PORT}/internal/health" 2>/dev/null; then
    ready=1
    break
  fi

  attempt=$((attempt + 1))
  sleep 0.2
done

if [ "$ready" -ne 1 ]; then
  echo '[entrypoint] internal service did not become ready in time' >&2
  stop_all
  exit 1
fi

echo '[entrypoint] internal diagnostics service is ready'

# The gateway must never see the flag.
unset GZCTF_FLAG

PORT="$PORT" node /app/gateway/server.js &
gateway_pid=$!

# Supervise: if either required process exits, stop the other and fail.
while kill -0 "$gateway_pid" 2>/dev/null && kill -0 "$internal_pid" 2>/dev/null; do
  sleep 1
done

if kill -0 "$gateway_pid" 2>/dev/null; then
  echo '[entrypoint] internal service exited unexpectedly' >&2
else
  echo '[entrypoint] gateway exited unexpectedly' >&2
fi

stop_all
exit 1
