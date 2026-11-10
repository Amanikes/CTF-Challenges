#!/bin/sh
set -eu

if [ -z "${GZCTF_FLAG:-}" ]; then
  echo "[entrypoint] GZCTF_FLAG is not set; refusing to start" >&2
  exit 1
fi

# The archive is rebuilt on every start so a recreated container always carries
# the flag currently assigned to the team by the platform.
node /app/src/generate-backup.js

# The web process has no use for the flag; drop it before exec'ing.
unset GZCTF_FLAG

exec node /app/src/server.js
