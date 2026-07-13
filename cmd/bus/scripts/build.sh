#!/usr/bin/env bash
set -euo pipefail

APP_NAME="bus"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PROJECT_DIR/../.." && pwd)"

VERSION="$(cat "$PROJECT_DIR/VERSION" 2>/dev/null | tr -d '[:space:]')"
VERSION="${BUS_VERSION:-$VERSION}"

# Append commit hash and dirty flag
COMMIT_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	DIRTY="-dirty"
else
	DIRTY=""
fi
FULL_VERSION="${VERSION}+${COMMIT_HASH}${DIRTY}"

PLATFORMS="${BUS_PLATFORMS:-darwin/amd64 darwin/arm64 linux/amd64 windows/amd64 windows/arm64}"
DIST_DIR="${BUS_DIST_DIR:-dist/bus}"

case "$DIST_DIR" in
	/*) DIST_PATH="$DIST_DIR" ;;
	*)  DIST_PATH="$REPO_ROOT/$DIST_DIR" ;;
esac

README_FILE="$PROJECT_DIR/README.md"
LICENSE_FILE="$REPO_ROOT/LICENSE"

mkdir -p "$DIST_PATH"

HAS_ZIP=true
command -v zip >/dev/null 2>&1 || HAS_ZIP=false

DOCKER_IMAGE="kamune-bus-builder"
DOCKER_PLATFORM="linux/amd64"

build_docker_image() {
	if ! docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
		echo "  Building Docker image $DOCKER_IMAGE ($DOCKER_PLATFORM)..."
		docker build --platform "$DOCKER_PLATFORM" \
			-t "$DOCKER_IMAGE" -f "$SCRIPT_DIR/Dockerfile.linux" "$SCRIPT_DIR"
	fi
}

build_linux() {
	local output="$1"
	build_docker_image
	echo "  Building $APP_NAME for linux via Docker..."
	if ! docker run --rm --platform "$DOCKER_PLATFORM" \
		-v "$REPO_ROOT:/src" \
		-v bus-go-cache:/go/pkg/mod \
		-v bus-go-build-cache:/root/.cache/go-build \
		-w /src/cmd/bus \
		"$DOCKER_IMAGE" \
		/bin/sh -c "
			cd frontend && npm install && cd .. && \
			wails build -clean -platform linux/amd64 \
				-ldflags '-s -w -X main.appVersion=$FULL_VERSION' \
				-o '$output'
		"; then
		echo "  FAILED: build for linux/amd64" >&2
		return 1
	fi
}

build_native() {
	local plat="$1" output="$2"
	echo "==> Building $APP_NAME for $plat..."
	if ! (
		cd "$PROJECT_DIR"
		wails build -clean -platform "$plat" \
			-ldflags "-s -w -X main.appVersion=$FULL_VERSION" \
			-o "$output"
	); then
		echo "  FAILED: build for $plat" >&2
		return 1
	fi
}

for plat in $PLATFORMS; do
	os="${plat%%/*}"
	arch="${plat#*/}"
	ext=""
	[ "$os" = "windows" ] && ext=".exe"

	output="${APP_NAME}-v${VERSION}-${os}-${arch}${ext}"
	zipbase="${APP_NAME}-v${VERSION}-${os}-${arch}"

	if [ "$os" = "linux" ]; then
		if ! command -v docker >/dev/null 2>&1; then
			echo "==> Skipping $plat: docker not found" >&2
			continue
		fi
		echo "==> Building $APP_NAME for $plat (Docker)..."
		if ! build_linux "$output"; then
			continue
		fi
	else
		echo "==> Building $APP_NAME for $plat..."
		if ! build_native "$plat" "$output"; then
			continue
		fi
	fi

	# Move artifact from build/bin/ to DIST_PATH
	src="$PROJECT_DIR/build/bin/$output"
	if [ -f "$src" ]; then
		mv "$src" "$DIST_PATH/"
	elif [ -d "$PROJECT_DIR/build/bin/$APP_NAME.app" ]; then
		cp -R "$PROJECT_DIR/build/bin/$APP_NAME.app" \
			"$DIST_PATH/${output}.app"
	else
		echo "  WARNING: artifact not found (looked for $src and .app bundle)" >&2
	fi

	if $HAS_ZIP; then
		staging="$(mktemp -d)"
		if [ -f "$DIST_PATH/$output" ]; then
			cp "$DIST_PATH/$output" "$staging/"
		fi
		if [ -d "$DIST_PATH/${output}.app" ]; then
			cp -R "$DIST_PATH/${output}.app" "$staging/"
		fi
		cp "$README_FILE"  "$staging/"
		cp "$LICENSE_FILE" "$staging/"
		( cd "$staging" && zip -q -r "$DIST_PATH/${zipbase}.zip" ./* )
		rm -rf "$staging"
		rm -f "$DIST_PATH/$output" "$DIST_PATH/${output}.app"
		echo "  $output -> ${zipbase}.zip"
	fi
done

echo ""
echo "==> Build complete!"
ls -lh "$DIST_PATH/" 2>/dev/null || true
