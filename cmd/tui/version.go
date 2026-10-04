package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

type ver struct {
	major, minor int
}

func parseVer(version string) (ver, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return ver{}, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return ver{}, false
	}
	return ver{major: maj, minor: min}, true
}

// maxVersionLength is the most bytes of a version string that a peer sent
// that are shown.
const maxVersionLength = 32

// displayVersion returns a version string that a peer sent, for display on
// one line: sanitized (see sanitizeLine) and cut to maxVersionLength bytes,
// with "…" in place of what was cut.
func displayVersion(v string) string {
	v = sanitizeLine(v)
	if len(v) <= maxVersionLength {
		return v
	}
	var b strings.Builder
	for _, r := range v {
		if b.Len()+utf8.RuneLen(r) > maxVersionLength {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + "…"
}

// checkMinorMismatch returns a warning when the remote version has the
// same major version as local and another minor one. local is the
// version of this app; remote is what the peer sent and is shown through
// displayVersion.
func checkMinorMismatch(local, remote string) (string, bool) {
	if remote == "" {
		return "", false
	}
	lv, ok := parseVer(local)
	if !ok {
		return "", false
	}
	rv, ok := parseVer(remote)
	if !ok {
		return "", false
	}
	if lv.major == rv.major && lv.minor != rv.minor {
		return fmt.Sprintf(
			"Minor version mismatch (v%s vs v%s): things may not work as expected",
			local,
			displayVersion(remote),
		), true
	}
	return "", false
}
