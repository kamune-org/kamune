#!/usr/bin/env bash
set -euo pipefail

APP_NAME="relay"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"

VERSION="$(cat "$PROJECT_DIR/VERSION" 2>/dev/null | tr -d '[:space:]')"
VERSION="${RELAY_VERSION:-$VERSION}"

# Append commit hash and dirty flag
COMMIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	DIRTY="-dirty"
else
	DIRTY=""
fi
FULL_VERSION="${VERSION}+${COMMIT_HASH}${DIRTY}"

PLATFORMS="${RELAY_PLATFORMS:-darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64}"
DIST_DIR="${RELAY_DIST_DIR:-dist/relay}"

case "$DIST_DIR" in
	/*) DIST_PATH="$DIST_DIR" ;;
	*)  DIST_PATH="$REPO_ROOT/$DIST_DIR" ;;
esac

CONFIG_FILE="$PROJECT_DIR/assets/config.toml"
README_FILE="$PROJECT_DIR/README.md"
LICENSE_FILE="$REPO_ROOT/LICENSE"

mkdir -p "$DIST_PATH"

HAS_ZIP=true
if ! command -v zip >/dev/null 2>&1; then
	HAS_ZIP=false
	echo "WARNING: zip not found; leaving bare binaries without" \
		"config.toml, README.md and LICENSE" >&2
fi

staging=""
trap '[ -z "$staging" ] || rm -rf "$staging"' EXIT

failed=()
for plat in $PLATFORMS; do
	os="${plat%%/*}"
	arch="${plat#*/}"
	ext=""
	[ "$os" = "windows" ] && ext=".exe"

	binary="${APP_NAME}-v${VERSION}-${os}-${arch}${ext}"
	zipbase="${APP_NAME}-v${VERSION}-${os}-${arch}"

	echo "==> Building $APP_NAME for $plat..."

	# Drop what an earlier build left for this platform, so a failed build
	# leaves nothing that looks current and zip starts a new archive
	# instead of updating the old one.
	rm -f "$DIST_PATH/$binary" "$DIST_PATH/${zipbase}.zip"

	if ! GOOS="$os" GOARCH="$arch" go build -o "$DIST_PATH/$binary" \
		-ldflags="-s -w -X main.version=$FULL_VERSION" \
		"$PROJECT_DIR"; then
		echo "  FAILED: build for $plat" >&2
		failed+=("$plat")
		continue
	fi

	if $HAS_ZIP; then
		staging="$(mktemp -d)"
		cp "$DIST_PATH/$binary" "$staging/"
		cp "$CONFIG_FILE"      "$staging/config.toml"
		cp "$README_FILE"      "$staging/"
		cp "$LICENSE_FILE"     "$staging/"
		( cd "$staging" && zip -q "$DIST_PATH/${zipbase}.zip" ./* )
		rm -rf "$staging"
		staging=""
		rm "$DIST_PATH/$binary"
		echo "  $binary -> ${zipbase}.zip"
	fi
done

echo ""
if [ "${#failed[@]}" -gt 0 ]; then
	echo "==> Build FAILED for: ${failed[*]}" >&2
	ls -lh "$DIST_PATH/" 2>/dev/null || true
	exit 1
fi
echo "==> Build complete!"
ls -lh "$DIST_PATH/" 2>/dev/null || true
