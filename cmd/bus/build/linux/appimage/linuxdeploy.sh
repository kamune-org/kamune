#!/usr/bin/env bash
# Puts a pinned linuxdeploy, checked against its SHA-256, into the
# AppImage build directory given as the only argument. wails3 generate
# appimage uses the linuxdeploy it finds there instead of downloading the
# "continuous" release, which changes without notice and is not checked.
#
# To update, set VERSION to a release from
# https://github.com/linuxdeploy/linuxdeploy/releases and both checksums
# to the SHA-256 of that release's AppImages.
set -euo pipefail

VERSION="1-alpha-20251107-1"
BUILD_DIR="${1:?usage: linuxdeploy.sh <build dir>}"

case "$(uname -m)" in
x86_64)
	arch=x86_64
	sum=c20cd71e3a4e3b80c3483cef793cda3f4e990aca14014d23c544ca3ce1270b4d
	;;
aarch64 | arm64)
	arch=aarch64
	sum=620095110d693282b8ebeb244a95b5e911cf8f65f76c88b4b47d16ae6346fcff
	;;
*)
	echo "no linuxdeploy checksum for $(uname -m)" >&2
	exit 1
	;;
esac

file="linuxdeploy-$arch.AppImage"
dest="$BUILD_DIR/$file"

verify() {
	echo "$sum  $1" | sha256sum -c --status -
}

mkdir -p "$BUILD_DIR"
if [ -f "$dest" ] && verify "$dest"; then
	exit 0
fi
# A linuxdeploy that is there but does not match, such as a continuous
# build an earlier wails3 run downloaded, is replaced.
rm -f "$dest"

tmp="$(mktemp "$BUILD_DIR/.linuxdeploy.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
curl -fsSL -o "$tmp" \
	"https://github.com/linuxdeploy/linuxdeploy/releases/download/$VERSION/$file"
if ! verify "$tmp"; then
	echo "$file from linuxdeploy $VERSION does not match its SHA-256" >&2
	exit 1
fi
chmod 0755 "$tmp"
mv "$tmp" "$dest"
