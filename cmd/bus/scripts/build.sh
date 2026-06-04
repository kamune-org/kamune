#!/usr/bin/env bash
set -euo pipefail

APP_NAME="bus"
VERSION="${BUS_VERSION:-2.1.0}"

# Append commit hash and dirty flag
COMMIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	DIRTY="-dirty"
else
	DIRTY=""
fi
FULL_VERSION="${VERSION}+${COMMIT_HASH}${DIRTY}"

PLATFORMS="${BUS_PLATFORMS:-darwin/amd64 darwin/arm64 windows/amd64 windows/arm64}"
DIST_DIR="${BUS_DIST_DIR:-dist/bus}"
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

	if ! (
		cd "$PROJECT_DIR"
		wails build -clean -platform "$plat" \
			-ldflags "-s -w -X main.appVersion=$FULL_VERSION" \
			-o "$output"
	); then
		echo "  FAILED: build for $plat" >&2
		continue
	fi

	src="$PROJECT_DIR/build/bin/$output"
	if [ -f "$src" ]; then
		mv "$src" "$DIST_PATH/"
	elif [ -d "$PROJECT_DIR/build/bin/$APP_NAME.app" ]; then
		cp -R "$PROJECT_DIR/build/bin/$APP_NAME.app" \
			"$DIST_PATH/${output}.app"
	else
		echo "  WARNING: artifact not found (looked for $src and .app bundle)" >&2
	fi

done

echo ""
echo "==> Build complete!"
ls -lh "$DIST_PATH/" 2>/dev/null || true
