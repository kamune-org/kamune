#!/usr/bin/env bash
set -euo pipefail

APP_NAME="relay"
VERSION="${RELAY_VERSION:-1.1.0}"

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

echo ""
echo "==> Build complete!"
ls -lh "$DIST_PATH/" 2>/dev/null || true
