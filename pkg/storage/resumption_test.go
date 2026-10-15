package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune/internal/clock"
)

func testResumption(role ResumeRole, current byte) *Resumption {
	return &Resumption{
		Generation:  1,
		Current:     bytes.Repeat([]byte{current}, 64),
		PeerKey:     bytes.Repeat([]byte{0x05}, 44),
		ColdAt:      time.Unix(1_700_000_000, 0),
		RefreshedAt: time.Unix(1_700_000_100, 0),
		Role:        role,
	}
}

func TestSwapResumption_CAS(t *testing.T) {
	a := require.New(t)
	s, cleanup := newTestStorage(t)
	defer cleanup()

	next := testResumption(ResumeRoleInitiator, 0x11)
	a.NoError(s.SwapResumption("sess", 0, next))
	got, err := s.GetResumption("sess", ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(next.Generation, got.Generation)
	a.Equal(next.Current, got.Current)
	a.Equal(next.PeerKey, got.PeerKey)
	a.Equal(ResumeRoleInitiator, got.Role)
	a.Empty(got.Previous)

	updated := testResumption(ResumeRoleInitiator, 0x22)
	updated.Generation = 2
	a.NoError(s.SwapResumption("sess", 1, updated))
	got, err = s.GetResumption("sess", ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(uint64(2), got.Generation)
	a.Equal(updated.Current, got.Current)

	stale := testResumption(ResumeRoleInitiator, 0x33)
	stale.Generation = 3
	a.ErrorIs(s.SwapResumption("sess", 1, stale), ErrResumptionConflict)
	got, err = s.GetResumption("sess", ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(updated.Current, got.Current)

	again := testResumption(ResumeRoleInitiator, 0x44)
	a.ErrorIs(s.SwapResumption("sess", 0, again), ErrResumptionConflict)

	other := testResumption(ResumeRoleResponder, 0x55)
	other.Previous = bytes.Repeat([]byte{0x11}, 64)
	a.NoError(s.SwapResumption("sess", 0, other))
	gotI, err := s.GetResumption("sess", ResumeRoleInitiator)
	a.NoError(err)
	gotR, err := s.GetResumption("sess", ResumeRoleResponder)
	a.NoError(err)
	a.Equal(updated.Current, gotI.Current)
	a.Equal(other.Current, gotR.Current)
	a.Equal(other.Previous, gotR.Previous)
	_, err = s.GetResumption("missing", ResumeRoleInitiator)
	a.ErrorIs(err, ErrNoResumption)
}

func TestValidateResumption_StoredShape(t *testing.T) {
	a := require.New(t)
	s, cleanup := newTestStorage(t)
	defer cleanup()

	prev := testResumption(ResumeRoleInitiator, 0x11)
	prev.Previous = bytes.Repeat([]byte{0x22}, 64)
	a.Error(s.SwapResumption("sess", 0, prev))

	short := testResumption(ResumeRoleResponder, 0x11)
	short.PeerKey = []byte{1, 2, 3}
	a.Error(s.SwapResumption("sess", 0, short))

	cold := testResumption(ResumeRoleResponder, 0x11)
	cold.ColdAt = time.Time{}
	a.Error(s.SwapResumption("sess", 0, cold))

	refreshed := testResumption(ResumeRoleResponder, 0x11)
	refreshed.RefreshedAt = time.Time{}
	a.Error(s.SwapResumption("sess", 0, refreshed))

	_, err := s.GetResumption("sess", ResumeRoleInitiator)
	a.ErrorIs(err, ErrNoResumption)
}

func TestDeleteResumption_Generation(t *testing.T) {
	a := require.New(t)
	s, cleanup := newTestStorage(t)
	defer cleanup()

	next := testResumption(ResumeRoleInitiator, 0x11)
	a.NoError(s.SwapResumption("sess", 0, next))
	a.Error(s.DeleteResumption("sess", ResumeRoleInitiator, 0))
	got, err := s.GetResumption("sess", ResumeRoleInitiator)
	a.NoError(err)
	a.Equal(uint64(1), got.Generation)

	a.ErrorIs(
		s.DeleteResumption("sess", ResumeRoleInitiator, 9),
		ErrResumptionConflict,
	)
	_, err = s.GetResumption("sess", ResumeRoleInitiator)
	a.NoError(err)

	a.NoError(s.DeleteResumption("sess", ResumeRoleInitiator, 1))
	_, err = s.GetResumption("sess", ResumeRoleInitiator)
	a.ErrorIs(err, ErrNoResumption)

	a.NoError(s.DeleteResumption("absent", ResumeRoleResponder, 1))
	ids, err := s.ListSessions()
	a.NoError(err)
	a.NotContains(ids, "absent")

	a.NoError(s.SwapResumption("gone", 0, next))
	a.NoError(s.DeleteSession("gone"))
	a.NoError(s.DeleteResumption("gone", ResumeRoleInitiator, 1))
	ids, err = s.ListSessions()
	a.NoError(err)
	a.NotContains(ids, "gone")
}

func TestDeleteResumptionAll(t *testing.T) {
	a := require.New(t)
	s, cleanup := newTestStorage(t)
	defer cleanup()

	a.NoError(s.SwapResumption(
		"sess", 0, testResumption(ResumeRoleInitiator, 0x11),
	))
	a.NoError(s.SwapResumption(
		"sess", 0, testResumption(ResumeRoleResponder, 0x22),
	))
	a.NoError(s.DeleteResumptionAll("sess"))
	_, err := s.GetResumption("sess", ResumeRoleInitiator)
	a.ErrorIs(err, ErrNoResumption)
	_, err = s.GetResumption("sess", ResumeRoleResponder)
	a.ErrorIs(err, ErrNoResumption)
	a.NoError(s.DeleteResumptionAll("absent"))
	ids, err := s.ListSessions()
	a.NoError(err)
	a.NotContains(ids, "absent")
}

func TestTouchResumption_MatchOnly(t *testing.T) {
	a := require.New(t)
	s, cleanup := newTestStorage(t)
	defer cleanup()

	next := testResumption(ResumeRoleResponder, 0x11)
	a.NoError(s.SwapResumption("sess", 0, next))
	later := next.RefreshedAt.Add(time.Hour)
	a.NoError(s.TouchResumption(
		"sess", ResumeRoleResponder, 1, later,
	))
	got, err := s.GetResumption("sess", ResumeRoleResponder)
	a.NoError(err)
	a.True(got.RefreshedAt.Equal(later))
	a.Equal(next.Current, got.Current)

	a.NoError(s.TouchResumption(
		"sess", ResumeRoleResponder, 1, next.RefreshedAt,
	))
	got, err = s.GetResumption("sess", ResumeRoleResponder)
	a.NoError(err)
	a.True(got.RefreshedAt.Equal(later))

	a.ErrorIs(s.TouchResumption(
		"sess", ResumeRoleResponder, 4, later.Add(time.Hour),
	), ErrResumptionConflict)
	got, err = s.GetResumption("sess", ResumeRoleResponder)
	a.NoError(err)
	a.True(got.RefreshedAt.Equal(later))

	a.Error(s.TouchResumption(
		"missing", ResumeRoleInitiator, 1, later,
	))
	ids, err := s.ListSessions()
	a.NoError(err)
	a.NotContains(ids, "missing")
}

func TestStorage_SweepUnconfirmedRows(t *testing.T) {
	a := require.New(t)
	old := time.Now().Add(-8 * 24 * time.Hour).Truncate(time.Second)
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")),
		WithNoPassphrase(),
		WithClock(clock.NewFake(old)),
	)
	a.NoError(err)
	defer func() { a.NoError(s.Close()) }()

	expired := testResumption(ResumeRoleInitiator, 0x11)
	expired.ColdAt = old
	expired.RefreshedAt = old
	a.NoError(s.SwapResumption("old", 0, expired))

	named := testResumption(ResumeRoleInitiator, 0x22)
	named.ColdAt = old
	named.RefreshedAt = old
	a.NoError(s.SwapResumption("named", 0, named))
	a.NoError(s.SetSessionName("named", "kept"))

	chatting := testResumption(ResumeRoleInitiator, 0x33)
	chatting.ColdAt = old
	chatting.RefreshedAt = old
	a.NoError(s.SwapResumption("chat", 0, chatting))
	a.NoError(s.AddChatEntry("chat", []byte("hi"), old, SenderLocal))

	freshAt := time.Now().Truncate(time.Second)
	s.clock = clock.NewFake(freshAt)
	fresh := testResumption(ResumeRoleInitiator, 0x44)
	fresh.ColdAt = freshAt
	fresh.RefreshedAt = freshAt
	a.NoError(s.SwapResumption("fresh", 0, fresh))

	n, err := s.SweepSessions(
		freshAt, 24*time.Hour, 7*24*time.Hour,
	)
	a.NoError(err)
	a.Equal(1, n)
	ids, err := s.ListSessions()
	a.NoError(err)
	a.ElementsMatch([]string{"named", "chat", "fresh"}, ids)
	_, err = s.GetResumption("named", ResumeRoleInitiator)
	a.ErrorIs(err, ErrNoResumption)
	_, err = s.GetResumption("fresh", ResumeRoleInitiator)
	a.NoError(err)
}

func TestSweepSkipsHeldSession(t *testing.T) {
	a := require.New(t)
	now := time.Now().Truncate(time.Second)
	old := now.Add(-8 * 24 * time.Hour)
	s, err := OpenStorage(
		WithDBPath(filepath.Join(t.TempDir(), "db")),
		WithNoPassphrase(),
	)
	a.NoError(err)
	defer func() { a.NoError(s.Close()) }()

	held := testResumption(ResumeRoleResponder, 0x11)
	held.ColdAt = old
	held.RefreshedAt = old
	a.NoError(s.SwapResumption("held", 0, held))
	other := testResumption(ResumeRoleResponder, 0x22)
	other.ColdAt = old
	other.RefreshedAt = old
	a.NoError(s.SwapResumption("other", 0, other))

	s.HoldResumption("held")
	_, err = s.SweepSessions(now, 24*time.Hour, 7*24*time.Hour)
	a.NoError(err)
	_, err = s.GetResumption("held", ResumeRoleResponder)
	a.NoError(err)
	_, err = s.GetResumption("other", ResumeRoleResponder)
	a.ErrorIs(err, ErrNoResumption)

	s.ReleaseResumption("held")
	_, err = s.SweepSessions(now, 24*time.Hour, 7*24*time.Hour)
	a.NoError(err)
	_, err = s.GetResumption("held", ResumeRoleResponder)
	a.ErrorIs(err, ErrNoResumption)
}

func TestResumption_NotInBoltPlaintext(t *testing.T) {
	a := require.New(t)
	path := filepath.Join(t.TempDir(), "db")
	s, err := OpenStorage(WithDBPath(path), WithNoPassphrase())
	a.NoError(err)
	secret := bytes.Repeat([]byte{0xA5}, 64)
	next := testResumption(ResumeRoleInitiator, 0)
	next.Current = secret
	a.NoError(s.SwapResumption("sess", 0, next))
	a.NoError(s.Close())

	raw, err := os.ReadFile(path)
	a.NoError(err)
	a.NotContains(raw, secret)
}
