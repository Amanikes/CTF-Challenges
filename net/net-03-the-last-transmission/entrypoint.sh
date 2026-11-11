#!/bin/sh
# The Last Transmission — container entrypoint.
#
# The capture is generated and fully validated first, while GZCTF_FLAG is
# available. The flag is then removed from the environment so the long-lived
# HTTP process never receives it, and the server starts only after a valid
# artifact exists.
set -eu

if [ -z "${GZCTF_FLAG:-}" ]; then
  echo '[net03] GZCTF_FLAG is missing or empty; refusing to start' >&2
  exit 1
fi

case "$GZCTF_FLAG" in
  *[![:space:]]*) ;;
  *)
    echo '[net03] GZCTF_FLAG is blank; refusing to start' >&2
    exit 1
    ;;
esac

python3 /app/src/generate_capture.py

unset GZCTF_FLAG

exec python3 /app/src/app.py
