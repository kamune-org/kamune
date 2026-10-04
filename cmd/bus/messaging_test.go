package main

import (
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
)

func TestNotificationText(t *testing.T) {
	long := strings.Repeat("a", 60)
	persian := strings.Repeat("سلام ", 15)
	cases := []struct {
		name      string
		msg       string
		incognito bool
		want      string
	}{
		{name: "short", msg: "hello", want: "hello"},
		{name: "long", msg: long, want: long[:50] + "…"},
		{
			name: "multi-byte runes",
			msg:  persian,
			want: string([]rune(persian)[:50]) + "…",
		},
		{
			name:      "incognito",
			msg:       "meet at the usual place",
			incognito: true,
			want:      incognitoNotificationText,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			got := notificationText(tc.msg, tc.incognito)
			a.Equal(tc.want, got)
			a.True(utf8.ValidString(got))
		})
	}
}

// TestIncognitoNotificationHidesText receives a message on a session that
// is not the active one in incognito mode, and checks that the
// notification it raises does not carry the message text.
func TestIncognitoNotificationHidesText(t *testing.T) {
	a := require.New(t)
	app := newIncognitoApp(t)

	const secret = "meet at the usual place"
	notes := make(chan string, 1)
	var once sync.Once
	app.onEvent = func(name string, data ...any) {
		if name != "notification" || len(data) < 2 {
			return
		}
		body, _ := data[1].(string)
		once.Do(func() { notes <- body })
	}

	addr, _ := startTestServer(t, "srv", func(tr *kamune.Transport) error {
		if _, err := tr.Send(
			kamune.Bytes([]byte(secret)), kamune.RouteExchangeMessages,
		); err != nil {
			return err
		}
		for {
			if _, _, err := tr.ReceivePayload(); err != nil {
				return nil
			}
		}
	})
	_, err := app.ConnectToServer(
		addr, "tcp", "", "", "", "", "", "", "", false, false,
	)
	a.NoError(err)

	var body string
	a.Eventually(func() bool {
		select {
		case body = <-notes:
			return true
		default:
			return false
		}
	}, testWait, 10*time.Millisecond)
	a.NotContains(body, "usual place")
	a.Equal(incognitoNotificationText, body)
}
