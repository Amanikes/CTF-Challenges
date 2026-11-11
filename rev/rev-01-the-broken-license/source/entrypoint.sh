#!/bin/sh
# Northstar License Manager — container entrypoint.
#
# The artifact generator runs first, inheriting the per-team GZCTF_FLAG. It
# encodes the flag into license.dat, packages the participant archive and exits,
# which drops the only process that ever held the plaintext. This shell then
# removes the variable and starts the download service, which never sees it.
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

node /app/scripts/generate-artifact.js

unset GZCTF_FLAG

exec node /app/server.js
