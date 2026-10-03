package engine

import (
	"fmt"
	"os"
	"runtime"
)

// restrictFileMode removes group and other permission bits from the file
// at path. bolt applies its mode only when it creates a file, so a database
// that was copied, or created by other tooling, can be readable by other
// users. It returns the previous mode and whether it changed it, or
// [ErrInsecurePermissions] when the mode is too open and cannot be fixed.
// On Windows these bits do not control access and nothing is done.
func restrictFileMode(path string) (os.FileMode, bool, error) {
	if runtime.GOOS == "windows" {
		return 0, false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, false, err
	}
	mode := info.Mode().Perm()
	if mode&0o077 == 0 {
		return mode, false, nil
	}
	if err := os.Chmod(path, mode&0o700); err != nil {
		return mode, false, fmt.Errorf(
			"%w: %s has mode %v: %w", ErrInsecurePermissions, path, mode, err,
		)
	}
	return mode, true, nil
}
