#!/usr/bin/env bash
# Build the NET-01 image and run the complete test suite.
#
# Usage: ./tests/run-tests.sh [image-tag]
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${1:-net-01-unencrypted-secrets:test}"
export NET01_IMAGE="$IMAGE"

cd "$ROOT" || exit 1

echo "== building $IMAGE =="
if ! docker build -q -t "$IMAGE" . >/dev/null; then
  echo "image build FAILED" >&2
  exit 1
fi
echo "image built"

STATUS=0
for suite in test_generation test_pcap_validity test_flag_exposure test_isolation; do
  echo
  echo "== $suite =="
  (cd "$ROOT/tests" && python3 -m unittest -v "$suite" 2>&1 | tail -n 45)
  if [ "${PIPESTATUS[0]}" -ne 0 ]; then
    STATUS=1
  fi
done

echo
if [ "$STATUS" -eq 0 ]; then
  echo "ALL SUITES PASSED"
else
  echo "SOME SUITES FAILED" >&2
fi

exit "$STATUS"
