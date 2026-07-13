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
command -v zip >/dev/null 2>&1 || HAS_ZIP=false

for plat in $PLATFORMS; do
	os="${plat%%/*}"
	arch="${plat#*/}"
	ext=""
	[ "$os" = "windows" ] && ext=".exe"

	binary="${APP_NAME}-v${VERSION}-${os}-${arch}${ext}"
	zipbase="${APP_NAME}-v${VERSION}-${os}-${arch}"

	echo "==> Building $APP_NAME for $plat..."

	if ! GOOS="$os" GOARCH="$arch" go build -o "$DIST_PATH/$binary" \
		-ldflags="-s -w -X main.version=$FULL_VERSION" \
		"$PROJECT_DIR"; then
		echo "  FAILED: build for $plat" >&2
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
		rm "$DIST_PATH/$binary"
		echo "  $binary -> ${zipbase}.zip"
	fi
done

echo ""
echo "==> Build complete!"
ls -lh "$DIST_PATH/" 2>/dev/null || true
