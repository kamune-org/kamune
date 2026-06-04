package kamune

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// AppVersion is the semantic version of the kamune protocol/library.
// Sub-modules may override this via ldflags or init() before package init.
var AppVersion = "0.5.0"

var localSemver semver

func init() {
	var err error
	localSemver, err = parseSemver(AppVersion)
	if err != nil {
		panic(fmt.Sprintf("kamune: invalid AppVersion %q: %v", AppVersion, err))
	}
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

func checkVersion(remote string) error {
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
			slog.String("local", AppVersion),
			slog.String("remote", remote),
		)
	}

	return nil
}
