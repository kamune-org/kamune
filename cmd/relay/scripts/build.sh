#!/usr/bin/env bash
set -euo pipefail

APP_NAME="relay"
VERSION="${RELAY_VERSION:-1.2.0}"

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
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"

case "$DIST_DIR" in
	/*) DIST_PATH="$DIST_DIR" ;;
	*)  DIST_PATH="$REPO_ROOT/$DIST_DIR" ;;
esac

ZIP_DIR="${RELAY_ZIP_DIR:-$REPO_ROOT/dist}"

mkdir -p "$DIST_PATH"

for plat in $PLATFORMS; do
	os="${plat%%/*}"
	arch="${plat#*/}"
	ext=""
	[ "$os" = "windows" ] && ext=".exe"

	output="${APP_NAME}-v${VERSION}-${os}-${arch}${ext}"

	echo "==> Building $APP_NAME for $plat..."

	if ! GOOS="$os" GOARCH="$arch" go build -o "$DIST_PATH/$output" \
		-ldflags="-s -w -X main.version=$FULL_VERSION" \
		"$PROJECT_DIR"; then
		echo "  FAILED: build for $plat" >&2
		continue
	fi

done

if command -v zip >/dev/null 2>&1; then
	mkdir -p "$ZIP_DIR"
	echo ""
	echo "==> Creating release zips in $ZIP_DIR ..."
	for src in "$DIST_PATH"/*; do
		[ -e "$src" ] || continue
		binary="$(basename "$src")"
		zipbase="${binary%.exe}"
		zipbase="${zipbase%.app}"
		( cd "$DIST_PATH" && zip -r "$ZIP_DIR/${zipbase}.zip" "$binary" ) >/dev/null
		echo "  $binary -> ${zipbase}.zip"
	done
else
	echo ""
	echo "==> Skipping zip step: 'zip' not found in PATH" >&2
fi

echo ""
echo "==> Build complete!"
ls -lh "$DIST_PATH/" 2>/dev/null || true
