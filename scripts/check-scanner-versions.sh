#!/usr/bin/env bash
# Release check: the bundled Trivy and Grype versions agree everywhere they are recorded (#368),
# and the source build pins the expected tag, commit and Go release (#482, #483).
# Usage: scripts/check-scanner-versions.sh [Dockerfile] [CHANGELOG.md] [image]
#   Static mode (default, runs in CI without a build): the Dockerfile "# trivy vX.Y.Z" and
#   "# grype vX.Y.Z" comments, the ARG <NAME>_VERSION and ARG <NAME>_COMMIT source pins and
#   ARG GO_VERSION must equal the expected values below, and CHANGELOG.md must carry a
#   "Bundled scanners" line naming both versions.
#   Image mode (optional, needs docker and a built image, for example dockward:latest): also runs
#     docker run --rm --entrypoint /usr/local/bin/trivy <image> --version
#     docker run --rm --entrypoint /usr/local/bin/grype <image> version
#   and requires each to report the expected version. When `go` is on PATH, it also copies each
#   binary out of the image and requires `go version <binary>` to report EXPECTED_GO.
# When a scanner or Go is bumped, update EXPECTED_* here together with the Dockerfile and CHANGELOG.md.
set -euo pipefail

EXPECTED_TRIVY="v0.76.2"
EXPECTED_TRIVY_COMMIT="3f6334d223b52188324af3b9923b4249cd206652"
EXPECTED_GRYPE="v0.122.1"
EXPECTED_GRYPE_COMMIT="8f3ddeddc4a4ed6314248aaf0a7c510f98db8882"
EXPECTED_GO="go1.27.4"

dockerfile="${1:-Dockerfile}"
changelog="${2:-CHANGELOG.md}"
image="${3:-}"
[ -f "$dockerfile" ] || { echo "error: $dockerfile not found" >&2; exit 2; }
[ -f "$changelog" ] || { echo "error: $changelog not found" >&2; exit 2; }

fail=0

# arg_value <NAME>: the value of the first "ARG <NAME>=..." line, or empty.
arg_value() {
  grep -E "^ARG $1=" "$dockerfile" | head -n1 | sed -E "s/^ARG $1=//" || true
}

for entry in "trivy:$EXPECTED_TRIVY:$EXPECTED_TRIVY_COMMIT" "grype:$EXPECTED_GRYPE:$EXPECTED_GRYPE_COMMIT"; do
  name="${entry%%:*}"
  rest="${entry#*:}"
  want="${rest%%:*}"
  want_commit="${rest#*:}"
  upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
  got="$(grep -E "^# ${name} v[0-9]+\.[0-9]+\.[0-9]+\$" "$dockerfile" | head -n1 | sed -E "s/^# ${name} //" || true)"
  if [ "$got" = "$want" ]; then
    echo "ok: Dockerfile records ${name} ${got}"
  else
    echo "FAIL: Dockerfile records ${name} '${got}', expected ${want}" >&2
    fail=1
  fi
  got_tag="$(arg_value "${upper}_VERSION")"
  if [ "$got_tag" = "$want" ]; then
    echo "ok: Dockerfile builds ${name} from tag ${got_tag}"
  else
    echo "FAIL: Dockerfile ARG ${upper}_VERSION is '${got_tag}', expected ${want}" >&2
    fail=1
  fi
  got_commit="$(arg_value "${upper}_COMMIT")"
  if [ "$got_commit" = "$want_commit" ]; then
    echo "ok: Dockerfile pins ${name} commit ${got_commit}"
  else
    echo "FAIL: Dockerfile ARG ${upper}_COMMIT is '${got_commit}', expected ${want_commit}" >&2
    fail=1
  fi
done

got_go="$(arg_value GO_VERSION)"
if [ "$got_go" = "$EXPECTED_GO" ]; then
  echo "ok: Dockerfile builds the scanners with ${got_go}"
else
  echo "FAIL: Dockerfile ARG GO_VERSION is '${got_go}', expected ${EXPECTED_GO}" >&2
  fail=1
fi

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

  if command -v go >/dev/null 2>&1; then
    out="$(mktemp -d)"
    container="$(docker create "$image" 2>/dev/null || true)"
    if [ -z "$container" ]; then
      echo "FAIL: could not create a container from ${image} to read the Go release" >&2
      fail=1
    else
      for name in trivy grype; do
        built=""
        if docker cp "${container}:/usr/local/bin/${name}" "${out}/${name}" >/dev/null 2>&1; then
          built="$(go version "${out}/${name}" 2>/dev/null | sed -E 's/^.*: //' || true)"
        fi
        if [ "$built" = "$EXPECTED_GO" ]; then
          echo "ok: image ${name} built with ${built}"
        else
          echo "FAIL: image ${name} built with '${built}', expected ${EXPECTED_GO}" >&2
          fail=1
        fi
      done
      docker rm "$container" >/dev/null 2>&1 || true
    fi
    rm -rf "$out"
  else
    echo "skip: go is not on PATH, the Go release of the image binaries is not read"
  fi
fi
exit "$fail"
