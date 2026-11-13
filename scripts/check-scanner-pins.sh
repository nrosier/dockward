#!/usr/bin/env bash
# Release check: the Dockerfile must pin Trivy and Grype by digest and record the release of each.
# Usage: scripts/check-scanner-pins.sh [Dockerfile]   (default: ./Dockerfile)
# Expects, for each scanner, a comment line "# trivy vX.Y.Z" / "# grype vX.Y.Z" directly above
# its FROM line, and a FROM line "FROM <image>@sha256:<64 hex> AS <name>".
set -euo pipefail

dockerfile="${1:-Dockerfile}"
[ -f "$dockerfile" ] || { echo "error: $dockerfile not found" >&2; exit 2; }

fail=0
check() {
  local name="$1" image="$2" from version
  from="$(grep -E "^FROM ${image}[@:].* AS ${name}\$" "$dockerfile" || true)"
  if [ -z "$from" ]; then
    echo "FAIL: no '${image}' FROM line (stage ${name}) in $dockerfile" >&2
    fail=1
    return
  fi
  if ! printf '%s\n' "$from" | grep -Eq "^FROM ${image}@sha256:[0-9a-f]{64} AS ${name}\$"; then
    echo "FAIL: ${name} is not pinned by @sha256:<64 hex> digest: $from" >&2
    fail=1
  fi
  version="$(grep -E "^# ${name} v[0-9]+\.[0-9]+\.[0-9]+\$" "$dockerfile" | head -n1 || true)"
  if [ -z "$version" ]; then
    echo "FAIL: no '# ${name} vX.Y.Z' version comment in $dockerfile" >&2
    fail=1
  else
    echo "ok: ${version#\# } ${from#FROM }"
  fi
}

check trivy aquasec/trivy
check grype anchore/grype
exit "$fail"
