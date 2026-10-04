package kamune

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/pkg/storage"
)

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
			err := checkVersion(tt.local, tt.remote)
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

// appVersionChildEnv marks the child process of TestAppVersionSetAfterInit.
const appVersionChildEnv = "KAMUNE_TEST_APP_VERSION_CHILD"

// TestAppVersionSetAfterInit checks that a version assigned after package
// initialization, as an importer's init function would, is the one that a
// server and a dialer both advertise and check against, and that an
// invalid one fails at setup. It changes AppVersion, which other tests'
// handshakes read, so it runs in a child process of its own.
func TestAppVersionSetAfterInit(t *testing.T) {
	a := require.New(t)
	if os.Getenv(appVersionChildEnv) == "" {
		cmd := exec.Command(
			os.Args[0], "-test.run=^TestAppVersionSetAfterInit$",
			"-test.count=1",
		)
		cmd.Env = append(os.Environ(), appVersionChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		a.NoError(err, "child process output:\n%s", out)
		return
	}

	clientStore, cleanupClient := newTestStore(t)
	defer cleanupClient()
	serverStore, cleanupServer := newTestStore(t)
	defer cleanupServer()

	AppVersion = "0.8.0"
	a.NotEmpty(coldDial(t, clientStore, serverStore))

	accept := func(*storage.Storage, *storage.Peer) error { return nil }
	AppVersion = "dev"
	_, err := NewDialer("", clientStore, accept)
	a.ErrorContains(err, "invalid AppVersion")
	_, err = NewServer(
		"", nil, serverStore, accept,
		ServeWithListener(newTestListener(nil)),
	)
	a.ErrorContains(err, "invalid AppVersion")
}

func TestCheckVersionRejectsInvalidLocal(t *testing.T) {
	a := require.New(t)
	err := checkVersion("dev", "0.7.0")
	a.Error(err)
	a.NotErrorIs(err, ErrVersionMismatch)
}
