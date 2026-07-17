package kamune

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func testCheckVersion(localVersion, remote string) error {
	lv, err := parseSemver(localVersion)
	if err != nil {
		return err
	}
	saved := localSemver
	localSemver = lv
	defer func() { localSemver = saved }()
	return checkVersion(remote)
}

func TestCheckVersion(t *testing.T) {
	tests := []struct {
		name    string
		local   string
		remote  string
		wantErr bool
	}{
		{"same version", "1.0.0", "1.0.0", false},
		{"patch bump", "1.0.0", "1.0.1", false},
		{"minor bump", "1.0.0", "1.1.0", false},
		{"major bump", "1.0.0", "2.0.0", true},
		{"major downgrade", "2.0.0", "1.0.0", true},
		{"pre-1.0 minor bump", "0.1.0", "0.2.0", true},
		{"pre-1.0 patch bump", "0.1.0", "0.1.1", false},
		{"empty remote", "1.0.0", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			err := testCheckVersion(tt.local, tt.remote)
			if tt.wantErr {
				a.Error(err)
				a.ErrorIs(err, ErrVersionMismatch)
			} else {
				a.NoError(err)
			}
		})
	}
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input string
		major int
		minor int
		patch int
		fail  bool
	}{
		{"1.2.3", 1, 2, 3, false},
		{"0.0.0", 0, 0, 0, false},
		{"", 0, 0, 0, true},
		{"1.2", 0, 0, 0, true},
		{"abc.def.ghi", 0, 0, 0, true},
		{"1.2.3.4", 0, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			a := require.New(t)
			v, err := parseSemver(tt.input)
			if tt.fail {
				a.Error(err)
				return
			}
			a.NoError(err)
			a.Equal(tt.major, v.major)
			a.Equal(tt.minor, v.minor)
			a.Equal(tt.patch, v.patch)
		})
	}
}
