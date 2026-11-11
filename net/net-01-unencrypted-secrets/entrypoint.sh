#!/bin/sh
# Meridian Logistics — container entrypoint.
#
# The capture generator runs first and inherits GZCTF_FLAG. It writes and
# validates the PCAP, drops the variable from its own environment and exits, so
# the long-running download service never receives the flag. The HTTP service is
# only started after the capture exists.
set -eu

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

CAPTURE="${RUNTIME_DIR:-/app/runtime}/meridian-traffic.pcap"

python3 /app/scripts/generate_capture.py --output "$CAPTURE"

unset GZCTF_FLAG

exec node /app/server/server.js
