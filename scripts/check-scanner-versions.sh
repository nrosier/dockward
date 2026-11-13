#!/usr/bin/env bash
# Release check: the bundled Trivy and Grype versions agree everywhere they are recorded (#368).
# Usage: scripts/check-scanner-versions.sh [Dockerfile] [CHANGELOG.md] [image]
#   Static mode (default, runs in CI without a build): the Dockerfile "# trivy vX.Y.Z" and
#   "# grype vX.Y.Z" comments must equal the expected versions below, and CHANGELOG.md must carry a
#   "Bundled scanners" line naming both.
#   Image mode (optional, needs docker and a built image, for example harborgate:latest): also runs
#     docker run --rm --entrypoint /usr/local/bin/trivy <image> --version
#     docker run --rm --entrypoint /usr/local/bin/grype <image> version
#   and requires each to report the expected version.
# When a scanner is bumped, update EXPECTED_* here together with the Dockerfile and CHANGELOG.md.
set -euo pipefail

EXPECTED_TRIVY="v0.76.2"
EXPECTED_GRYPE="v0.121.3"

dockerfile="${1:-Dockerfile}"
changelog="${2:-CHANGELOG.md}"
image="${3:-}"
[ -f "$dockerfile" ] || { echo "error: $dockerfile not found" >&2; exit 2; }
[ -f "$changelog" ] || { echo "error: $changelog not found" >&2; exit 2; }

fail=0

for pair in "trivy:$EXPECTED_TRIVY" "grype:$EXPECTED_GRYPE"; do
  name="${pair%%:*}"
  want="${pair#*:}"
  got="$(grep -E "^# ${name} v[0-9]+\.[0-9]+\.[0-9]+\$" "$dockerfile" | head -n1 | sed -E "s/^# ${name} //" || true)"
  if [ "$got" = "$want" ]; then
    echo "ok: Dockerfile records ${name} ${got}"
  else
    echo "FAIL: Dockerfile records ${name} '${got}', expected ${want}" >&2
    fail=1
  fi
done

notes="$(grep -E 'Bundled scanners' "$changelog" | head -n1 || true)"
if [ -n "$notes" ] && printf '%s' "$notes" | grep -Fq "Trivy ${EXPECTED_TRIVY}" \
  && printf '%s' "$notes" | grep -Fq "Grype ${EXPECTED_GRYPE}"; then
  echo "ok: ${changelog} states Trivy ${EXPECTED_TRIVY} and Grype ${EXPECTED_GRYPE}"
else
  echo "FAIL: ${changelog} has no 'Bundled scanners' line naming Trivy ${EXPECTED_TRIVY} and Grype ${EXPECTED_GRYPE}" >&2
  fail=1
fi

if [ -n "$image" ]; then
  trivy_out="$(docker run --rm --entrypoint /usr/local/bin/trivy "$image" --version 2>&1 || true)"
  grype_out="$(docker run --rm --entrypoint /usr/local/bin/grype "$image" version 2>&1 || true)"
  if printf '%s\n' "$trivy_out" | grep -Eq "^Version: *${EXPECTED_TRIVY#v}\$"; then
    echo "ok: image trivy ${EXPECTED_TRIVY}"
  else
    echo "FAIL: image trivy does not report ${EXPECTED_TRIVY}: $(printf '%s' "$trivy_out" | head -n1)" >&2
    fail=1
  fi
  if printf '%s\n' "$grype_out" | grep -Eq "^Version: *${EXPECTED_GRYPE#v}\$"; then
    echo "ok: image grype ${EXPECTED_GRYPE}"
  else
    echo "FAIL: image grype does not report ${EXPECTED_GRYPE}: $(printf '%s' "$grype_out" | head -n1)" >&2
    fail=1
  fi
fi
exit "$fail"
