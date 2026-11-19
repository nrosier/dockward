#!/usr/bin/env bash
# Release check: the Dockerfile must build Trivy and Grype from a pinned source tag and commit, on
# a Go builder image pinned by digest (#482, #483).
# Usage: scripts/check-scanner-pins.sh [--remote] [Dockerfile]   (default: ./Dockerfile)
# Expects, for each scanner:
#   - a comment line "# trivy vX.Y.Z" / "# grype vX.Y.Z",
#   - a stage "FROM gobuild AS <name>",
#   - "ARG <NAME>_VERSION=vX.Y.Z" equal to the comment, and "ARG <NAME>_COMMIT=<40 hex>",
#   - a "git clone ... --branch "$<NAME>_VERSION" https://github.com/<repo>.git" line,
#   - a check that the clone's HEAD equals $<NAME>_COMMIT.
# And a builder stage "FROM [--platform=...] golang:<v>-alpine@sha256:<64 hex> AS gobuild" with
# "ARG GO_VERSION=go<v>" equal to the image tag's Go release.
# --remote (needs network and git): also checks that each upstream tag resolves to the pinned commit
# (git ls-remote, the peeled commit for an annotated tag). Use it in the release steps.
set -euo pipefail

remote=0
if [ "${1:-}" = "--remote" ]; then
  remote=1
  shift
fi
dockerfile="${1:-Dockerfile}"
[ -f "$dockerfile" ] || { echo "error: $dockerfile not found" >&2; exit 2; }

fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

# The Go builder stage.
builder="$(grep -E '^FROM (--platform=[^ ]+ )?golang:[^ ]+ AS gobuild$' "$dockerfile" || true)"
if [ -z "$builder" ]; then
  bad "no 'FROM golang:... AS gobuild' builder stage in $dockerfile"
else
  image="$(printf '%s\n' "$builder" | sed -E 's/^FROM (--platform=[^ ]+ )?//; s/ AS gobuild$//')"
  if ! printf '%s\n' "$image" | grep -Eq '^golang:[0-9]+\.[0-9]+\.[0-9]+-alpine@sha256:[0-9a-f]{64}$'; then
    bad "Go builder is not pinned as golang:<X.Y.Z>-alpine@sha256:<64 hex>: $image"
  else
    tag_go="go$(printf '%s\n' "$image" | sed -E 's/^golang:([0-9.]+)-alpine@.*/\1/')"
    arg_go="$(grep -E '^ARG GO_VERSION=go[0-9]+\.[0-9]+\.[0-9]+$' "$dockerfile" | head -n1 | sed -E 's/^ARG GO_VERSION=//' || true)"
    if [ "$arg_go" != "$tag_go" ]; then
      bad "ARG GO_VERSION '${arg_go}' does not match the builder image ${tag_go}"
    else
      echo "ok: go builder ${tag_go} ${image}"
    fi
  fi
fi

check() {
  local name="$1" repo="$2" upper version arg commit ok=1
  upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"
  version="$(grep -E "^# ${name} v[0-9]+\.[0-9]+\.[0-9]+\$" "$dockerfile" | head -n1 | sed -E "s/^# ${name} //" || true)"
  if [ -z "$version" ]; then
    ok=0; bad "no '# ${name} vX.Y.Z' version comment in $dockerfile"
    return
  fi
  if ! grep -Eq "^FROM gobuild AS ${name}\$" "$dockerfile"; then
    ok=0; bad "no 'FROM gobuild AS ${name}' source-build stage in $dockerfile"
  fi
  arg="$(grep -E "^ARG ${upper}_VERSION=" "$dockerfile" | head -n1 | sed -E "s/^ARG ${upper}_VERSION=//" || true)"
  if [ "$arg" != "$version" ]; then
    ok=0; bad "ARG ${upper}_VERSION '${arg}' does not match the '# ${name} ${version}' comment"
  fi
  commit="$(grep -E "^ARG ${upper}_COMMIT=" "$dockerfile" | head -n1 | sed -E "s/^ARG ${upper}_COMMIT=//" || true)"
  if ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
    ok=0; bad "ARG ${upper}_COMMIT is not a 40 hex commit: '${commit}'"
    return
  fi
  if ! grep -Fq "git clone --quiet --depth 1 --branch \"\$${upper}_VERSION\" https://github.com/${repo}.git" "$dockerfile"; then
    ok=0; bad "${name} is not cloned from https://github.com/${repo}.git at \$${upper}_VERSION"
  fi
  if ! grep -Fq "test \"\$(git rev-parse HEAD)\" = \"\$${upper}_COMMIT\"" "$dockerfile"; then
    ok=0; bad "${name} build does not check the clone against \$${upper}_COMMIT"
  fi
  if [ "$remote" = 1 ]; then
    local refs resolved
    refs="$(git ls-remote "https://github.com/${repo}.git" "refs/tags/${version}" "refs/tags/${version}^{}" || true)"
    resolved="$(printf '%s\n' "$refs" | awk -v t="refs/tags/${version}^{}" '$2 == t { print $1 }')"
    [ -n "$resolved" ] || resolved="$(printf '%s\n' "$refs" | awk -v t="refs/tags/${version}" '$2 == t { print $1 }')"
    if [ "$resolved" != "$commit" ]; then
      ok=0; bad "upstream ${repo} tag ${version} resolves to '${resolved}', the Dockerfile pins ${commit}"
    else
      echo "ok: upstream ${repo} ${version} is ${commit}"
    fi
  fi
  if [ "$ok" = 1 ]; then echo "ok: ${name} ${version} ${repo}@${commit}"; fi
}

check trivy aquasecurity/trivy
check grype anchore/grype
exit "$fail"
