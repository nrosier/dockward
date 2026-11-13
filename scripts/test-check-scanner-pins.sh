#!/usr/bin/env bash
# Test for check-scanner-pins.sh: passes on the real Dockerfile, fails on broken fixtures.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
check="$here/check-scanner-pins.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
status=0

expect() { # expect <0|nonzero> <label> <file>
  local want="$1" label="$2" file="$3" rc=0
  bash "$check" "$file" >/dev/null 2>&1 || rc=$?
  if { [ "$want" = 0 ] && [ "$rc" -eq 0 ]; } || { [ "$want" != 0 ] && [ "$rc" -ne 0 ]; }; then
    echo "PASS: $label"
  else
    echo "FAIL: $label (exit $rc)"; status=1
  fi
}

expect 0 "real Dockerfile" "$root/Dockerfile"

# Fixtures derived from the real Dockerfile.
grep -v '^FROM anchore/grype' "$root/Dockerfile" > "$tmp/missing-pin"
sed -E 's#^(FROM anchore/grype)@sha256:[0-9a-f]+#\1:latest#' "$root/Dockerfile" > "$tmp/floating-tag"
grep -v -E '^# (trivy|grype) v' "$root/Dockerfile" > "$tmp/no-version"
expect nonzero "missing grype pin" "$tmp/missing-pin"
expect nonzero "floating grype tag" "$tmp/floating-tag"
expect nonzero "missing version comments" "$tmp/no-version"
exit "$status"
