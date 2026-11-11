#!/bin/sh
set -e

if [ -z "$GZCTF_FLAG" ]; then
    echo "[FATAL] GZCTF_FLAG is missing or empty; refusing to start." >&2
    exit 1
fi

exec node src/server.js
