#!/usr/bin/env bash
# Test for check-scanner-versions.sh: passes on the real Dockerfile, fails on mismatched fixtures,
# and exercises the image mode with a stub docker.
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

# Dockerfile says v0.76.1 where v0.76.2 is expected.
sed 's/^# trivy v0.76.2$/# trivy v0.76.1/' "$root/Dockerfile" > "$tmp/old-trivy"
sed 's/^# grype v0.121.3$/# grype v0.121.2/' "$root/Dockerfile" > "$tmp/old-grype"
expect nonzero "Dockerfile trivy v0.76.1 vs expected v0.76.2" bash "$check" "$tmp/old-trivy" "$root/CHANGELOG.md"
expect nonzero "Dockerfile grype v0.121.2 vs expected v0.121.3" bash "$check" "$tmp/old-grype" "$root/CHANGELOG.md"

# Changelog without the Bundled scanners line.
grep -v 'Bundled scanners' "$root/CHANGELOG.md" > "$tmp/no-notes"
expect nonzero "changelog without Bundled scanners line" bash "$check" "$root/Dockerfile" "$tmp/no-notes"

# Image mode with a stub docker that prints the version of each scanner.
mkdir "$tmp/bin"
cat > "$tmp/bin/docker" <<'S'
#!/usr/bin/env bash
case "$*" in
  *trivy*) echo "Version: ${STUB_TRIVY:-0.76.2}" ;;
  *grype*) echo "Application:         grype"; echo "Version:             ${STUB_GRYPE:-0.121.3}" ;;
esac
S
chmod +x "$tmp/bin/docker"
expect 0 "image reports the pinned versions" env PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
expect nonzero "image reports a different trivy" env STUB_TRIVY=0.76.1 PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
expect nonzero "image reports a different grype" env STUB_GRYPE=0.121.0 PATH="$tmp/bin:$PATH" bash "$check" "$root/Dockerfile" "$root/CHANGELOG.md" img:test
exit "$status"
