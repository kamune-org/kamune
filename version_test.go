package kamune

import (
	"errors"
	"testing"
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
			err := testCheckVersion(tt.local, tt.remote)
			if tt.wantErr && err == nil {
				t.Errorf("checkVersion(%q) = nil, want error", tt.remote)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("checkVersion(%q) = %v, want nil", tt.remote, err)
			}
			if tt.wantErr && err != nil && !errors.Is(err, ErrVersionMismatch) {
				t.Errorf("checkVersion(%q) error %v does not wrap ErrVersionMismatch", tt.remote, err)
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
			v, err := parseSemver(tt.input)
			if tt.fail {
				if err == nil {
					t.Errorf("parseSemver(%q) = %+v, want error", tt.input, v)
				}
				return
			}
			if err != nil {
				t.Errorf("parseSemver(%q) = _, %v, want no error", tt.input, err)
				return
			}
			if v.major != tt.major || v.minor != tt.minor || v.patch != tt.patch {
				t.Errorf("parseSemver(%q) = %+v, want {%d,%d,%d}", tt.input, v, tt.major, tt.minor, tt.patch)
			}
		})
	}
}
