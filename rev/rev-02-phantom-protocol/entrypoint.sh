#!/bin/sh
# Phantom Protocol — container entrypoint.
#
# The generator runs first and inherits GZCTF_FLAG. It writes the participant
# ZIP, drops the variable from its own environment and exits, so the only
# long-running process never receives the flag.
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

python3 /app/generator/generate_package.py \
  --output-dir "${RUNTIME_DIR:-/app/runtime}" \
  --executable /app/bin/phantom-client \
  --readme /app/package/README.txt

unset GZCTF_FLAG

exec node /app/server/server.js
