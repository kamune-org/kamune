package kamune

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// AppVersion is the semantic version of the kamune protocol/library, in the
// form major.minor.patch. A [Server] or [Dialer] advertises it in its
// introduction and checks the peer's version against it.
//
// It may be overridden with -ldflags "-X", or by assigning it before the
// first [NewServer] or [NewDialer] call, for example in an init function.
// Each server and dialer reads it once, when it is created, and keeps that
// value; NewServer and NewDialer fail when it is not a valid version.
var AppVersion = "0.7.0"

// appVersion returns AppVersion after checking that it parses.
func appVersion() (string, error) {
	v := AppVersion
	if _, err := parseSemver(v); err != nil {
		return "", fmt.Errorf("invalid AppVersion %q: %w", v, err)
	}
	return v, nil
}

type semver struct {
	major, minor, patch int
}

func parseSemver(v string) (semver, error) {
	if v == "" {
		return semver{}, fmt.Errorf("empty version string")
	}
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return semver{}, fmt.Errorf(
			"invalid semver %q: expected major.minor.patch", v,
		)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, fmt.Errorf("invalid major version in %q: %w", v, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, fmt.Errorf("invalid minor version in %q: %w", v, err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, fmt.Errorf("invalid patch version in %q: %w", v, err)
	}
	return semver{major: major, minor: minor, patch: patch}, nil
}

// checkVersion checks the remote peer's version against local, a version
// that appVersion accepted.
func checkVersion(local, remote string) error {
	localSemver, err := parseSemver(local)
	if err != nil {
		return fmt.Errorf("parsing local version %q: %w", local, err)
	}
	rv, err := parseSemver(remote)
	if err != nil {
		return fmt.Errorf(
			"%w: parsing remote version %q: %w", ErrVersionMismatch, remote, err,
		)
	}

	switch {
	case localSemver.major != rv.major:
		return fmt.Errorf(
			"%w: major %d != %d",
			ErrVersionMismatch, localSemver.major, rv.major,
		)
	case localSemver.major == 0 && localSemver.minor != rv.minor:
		return fmt.Errorf(
			"%w: pre-1.0 minor %d != %d",
			ErrVersionMismatch, localSemver.minor, rv.minor,
		)
	case localSemver.minor != rv.minor:
		slog.Warn(
			"minor version mismatch",
			slog.String("local", local),
			slog.String("remote", remote),
		)
	}

	return nil
}
