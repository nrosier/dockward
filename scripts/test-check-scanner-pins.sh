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
grep -v '^FROM gobuild AS grype' "$root/Dockerfile" > "$tmp/missing-stage"
sed -E 's#^(FROM .*golang:[^@ ]+)@sha256:[0-9a-f]+#\1#' "$root/Dockerfile" > "$tmp/floating-go"
sed -E 's/^ARG GO_VERSION=go.*/ARG GO_VERSION=go1.0.0/' "$root/Dockerfile" > "$tmp/go-mismatch"
grep -v -E '^# (trivy|grype) v' "$root/Dockerfile" > "$tmp/no-version"
sed -E 's/^ARG GRYPE_VERSION=.*/ARG GRYPE_VERSION=v0.0.1/' "$root/Dockerfile" > "$tmp/tag-mismatch"
sed -E 's/^ARG TRIVY_COMMIT=.*/ARG TRIVY_COMMIT=main/' "$root/Dockerfile" > "$tmp/floating-commit"
grep -v 'git rev-parse HEAD)" = "\$GRYPE_COMMIT"' "$root/Dockerfile" > "$tmp/no-commit-check"
sed -E 's#https://github.com/aquasecurity/trivy.git#https://example.com/trivy.git#' "$root/Dockerfile" > "$tmp/other-repo"
expect nonzero "missing grype source stage" "$tmp/missing-stage"
expect nonzero "Go builder not pinned by digest" "$tmp/floating-go"
expect nonzero "GO_VERSION differs from the builder tag" "$tmp/go-mismatch"
expect nonzero "missing version comments" "$tmp/no-version"
expect nonzero "grype tag differs from the version comment" "$tmp/tag-mismatch"
expect nonzero "trivy commit not a 40 hex commit" "$tmp/floating-commit"
expect nonzero "grype clone not checked against the commit" "$tmp/no-commit-check"
expect nonzero "trivy cloned from another repository" "$tmp/other-repo"
exit "$status"
