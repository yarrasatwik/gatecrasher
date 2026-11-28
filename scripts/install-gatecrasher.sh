#!/usr/bin/env bash
# Installs a prebuilt Gatecrasher release binary and verifies its SHA-256
# against the release's checksums.txt. If the release has no asset for this
# platform it reports build=true so the caller can build from source.
#
# Inputs (environment):
#   GC_VERSION        release tag to install (e.g. v1.1.0); empty = resolve
#   GC_ACTION_REF     the ref the action was used at; used when it is a tag
#   GC_ACTION_REPO    owner/repo (default yarrasatwik/gatecrasher)
#   GC_INSTALL_DIR    where to put the binary
#   RUNNER_OS, RUNNER_ARCH  set by GitHub Actions (or auto-detected)
# Outputs (appended to $GITHUB_OUTPUT when set): build, bin, version
set -euo pipefail

repo="${GC_ACTION_REPO:-yarrasatwik/gatecrasher}"
dir="${GC_INSTALL_DIR:?GC_INSTALL_DIR is required}"
mkdir -p "$dir"

emit() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "$1=$2" >> "$GITHUB_OUTPUT"; fi
  echo "$1=$2"
}

case "${RUNNER_OS:-$(uname -s)}" in
  Linux) os=linux; ext="" ;;
  macOS|Darwin) os=darwin; ext="" ;;
  Windows|MINGW*|MSYS*|CYGWIN*) os=windows; ext=".exe" ;;
  *) echo "unsupported OS; building from source" >&2; emit build true; exit 0 ;;
esac
case "${RUNNER_ARCH:-$(uname -m)}" in
  X64|x86_64|amd64) arch=amd64 ;;
  ARM64|arm64|aarch64) arch=arm64 ;;
  *) echo "unsupported architecture; building from source" >&2; emit build true; exit 0 ;;
esac

version="${GC_VERSION:-}"
if [ -z "$version" ] && [[ "${GC_ACTION_REF:-}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  version="$GC_ACTION_REF"
fi
if [ -z "$version" ] && ! [[ "${GC_ACTION_REF:-}" =~ ^v[0-9]+$ ]]; then
  # A branch, a commit or a local checkout (uses: ./): run exactly that code.
  echo "action used at '${GC_ACTION_REF:-local checkout}', not a release tag; building from source" >&2
  emit build true; exit 0
fi
if [ -z "$version" ]; then
  # Major-version tag (v1): take the latest release.
  final="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest" || true)"
  version="${final##*/}"
  case "$version" in
    v[0-9]*) ;;
    *) echo "no release found; building from source" >&2; emit build true; exit 0 ;;
  esac
fi

asset="gatecrasher_${version}_${os}_${arch}${ext}"
base="https://github.com/$repo/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if ! curl -fsSL -o "$tmp/$asset" "$base/$asset"; then
  echo "release $version has no asset $asset; building from source" >&2
  emit build true
  exit 0
fi
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || { echo "checksums.txt missing for $version" >&2; exit 1; }

want="$(awk -v f="$asset" '$2==f || $2=="*"f {print $1; exit}' "$tmp/checksums.txt")"
[ -n "$want" ] || { echo "no checksum for $asset in checksums.txt" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
else
  got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
fi
if [ "$got" != "$want" ]; then
  echo "checksum mismatch for $asset (expected $want, got $got)" >&2
  exit 1
fi

bin="$dir/gatecrasher${ext}"
mv "$tmp/$asset" "$bin"
chmod +x "$bin"
echo "installed $asset (sha256 verified)"
emit build false
emit bin "$bin"
emit version "$version"
