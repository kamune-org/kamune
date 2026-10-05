package kamune

import (
	"errors"
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
var AppVersion = "0.8.0"

// MaxAppVersionLength is the longest version, in bytes, that a peer may
// introduce itself with. See [ValidateAppVersion].
const MaxAppVersionLength = 32

// ValidateAppVersion checks a version that a peer introduces itself with.
// It returns an error wrapping [ErrInvalidAppVersion] unless version is at
// most [MaxAppVersionLength] bytes of the form major.minor.patch: three
// decimal numbers of ASCII digits, with no sign and no leading zeros, such
// as 0.7.0.
//
// [AppVersion] must pass it, or [NewServer] and [NewDialer] fail. The
// server and the dialer reject an introduction whose version fails it
// before the [RemoteVerifier] runs, with an error that wraps both
// ErrInvalidAppVersion and [ErrVersionMismatch]. Applications can use it
// to check a version stored by an older release before showing it.
func ValidateAppVersion(version string) error {
	_, err := parseSemver(version)
	return err
}

// appVersion returns AppVersion after checking that it parses.
func appVersion() (string, error) {
	v := AppVersion
	if _, err := parseSemver(v); err != nil {
		return "", fmt.Errorf("invalid AppVersion: %w", err)
	}
	return v, nil
}

type semver struct {
	major, minor, patch int
}

// parseSemver parses a version that [ValidateAppVersion] accepts. Its
// errors wrap [ErrInvalidAppVersion].
func parseSemver(v string) (semver, error) {
	if v == "" {
		return semver{}, fmt.Errorf("%w: empty", ErrInvalidAppVersion)
	}
	// Check the length first, so that an error never quotes a long string.
	if len(v) > MaxAppVersionLength {
		return semver{}, fmt.Errorf(
			"%w: %d bytes, the limit is %d",
			ErrInvalidAppVersion, len(v), MaxAppVersionLength,
		)
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf(
			"%w: %q is not major.minor.patch", ErrInvalidAppVersion, v,
		)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := parseVersionNumber(p)
		if err != nil {
			return semver{}, fmt.Errorf(
				"%w: %q: %s", ErrInvalidAppVersion, v, err,
			)
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2]}, nil
}

// parseVersionNumber parses one number of a version: ASCII digits, with no
// sign and no leading zero unless the number is 0.
func parseVersionNumber(s string) (int, error) {
	switch {
	case s == "":
		return 0, errors.New("empty number")
	case len(s) > 1 && s[0] == '0':
		return 0, errors.New("leading zero")
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a decimal number")
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.New("number out of range")
	}
	return n, nil
}

// checkVersion checks the remote peer's version against local, a version
// that appVersion accepted.
func checkVersion(local, remote string) error {
	localSemver, err := parseSemver(local)
	if err != nil {
		return fmt.Errorf("parsing local version: %w", err)
	}
	rv, err := parseSemver(remote)
	if err != nil {
		return fmt.Errorf(
			"%w: parsing remote version: %w", ErrVersionMismatch, err,
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
