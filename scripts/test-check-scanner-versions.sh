#!/usr/bin/env bash
# Test for check-scanner-versions.sh: passes on the real Dockerfile, fails on mismatched fixtures,
# and exercises the image mode with a stub docker and a stub go.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
check="$here/check-scanner-versions.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
status=0

expect() { # expect <0|nonzero> <label> <command...>
  local want="$1" label="$2" rc=0
  shift 2
  "$@" >/dev/null 2>&1 || rc=$?
  if { [ "$want" = 0 ] && [ "$rc" -eq 0 ]; } || { [ "$want" != 0 ] && [ "$rc" -ne 0 ]; }; then
    echo "PASS: $label"
  else
    echo "FAIL: $label (exit $rc)"; status=1
  fi
}

expect 0 "real Dockerfile and changelog" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md"

# Dockerfile records older versions, tags, commits or Go than expected.
sed 's/^# trivy v0.76.2$/# trivy v0.76.1/' "$root/Dockerfile" > "$tmp/old-trivy"
sed 's/^# grype v0.122.1$/# grype v0.122.0/' "$root/Dockerfile" > "$tmp/old-grype"
sed -E 's/^ARG GRYPE_VERSION=.*/ARG GRYPE_VERSION=v0.122.0/' "$root/Dockerfile" > "$tmp/old-grype-tag"
sed -E 's/^ARG TRIVY_COMMIT=.*/ARG TRIVY_COMMIT=0000000000000000000000000000000000000000/' "$root/Dockerfile" > "$tmp/other-trivy-commit"
sed -E 's/^ARG GO_VERSION=.*/ARG GO_VERSION=go1.27.3/' "$root/Dockerfile" > "$tmp/old-go"
expect nonzero "Dockerfile trivy v0.76.1 vs expected v0.76.2" bash "$check" "$tmp/old-trivy" "$root/CHANGELOG.md"
expect nonzero "Dockerfile grype v0.122.0 vs expected v0.122.1" bash "$check" "$tmp/old-grype" "$root/CHANGELOG.md"
expect nonzero "Dockerfile builds grype from tag v0.122.0" bash "$check" "$tmp/old-grype-tag" "$root/CHANGELOG.md"
expect nonzero "Dockerfile pins another trivy commit" bash "$check" "$tmp/other-trivy-commit" "$root/CHANGELOG.md"
expect nonzero "Dockerfile builds with go1.27.3" bash "$check" "$tmp/old-go" "$root/CHANGELOG.md"

# Changelog without the Bundled scanners line.
grep -v 'Bundled scanners' "$root/CHANGELOG.md" > "$tmp/no-notes"
expect nonzero "changelog without Bundled scanners line" bash "$check" "$root/Dockerfile" "$tmp/no-notes"

# Image mode with a stub docker that prints the version of each scanner and copies a placeholder
# binary out, and a stub go that reports STUB_GO for any binary.
mkdir "$tmp/bin"
cat > "$tmp/bin/docker" <<'S'
#!/usr/bin/env bash
case "$1" in
  create) echo "stub-container" ;;
  cp) : > "$3" ;;
  rm) : ;;
  run)
    case "$*" in
      *trivy*) echo "Version: ${STUB_TRIVY:-0.76.2}" ;;
      *grype*) echo "Application:         grype"; echo "Version:             ${STUB_GRYPE:-0.122.1}" ;;
    esac ;;
esac
S
cat > "$tmp/bin/go" <<'S'
#!/usr/bin/env bash
[ "$1" = version ] && echo "$2: ${STUB_GO:-go1.27.4}"
S
chmod +x "$tmp/bin/docker" "$tmp/bin/go"
expect 0 "image reports the pinned versions and Go" env PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
expect nonzero "image reports a different trivy" env STUB_TRIVY=0.76.1 PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
expect nonzero "image reports a different grype" env STUB_GRYPE=0.122.0 PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
expect nonzero "image binaries built with another Go" env STUB_GO=go1.27.3 PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
exit "$status"
