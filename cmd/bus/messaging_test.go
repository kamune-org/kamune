package main

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/storage"
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
		addr, "tcp", "", "", "", "", "", "", "", false, false, "",
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

// numbered returns n messages whose texts are their numbers, from first.
func numbered(first, n int) []MessageInfo {
	msgs := make([]MessageInfo, n)
	for i := range msgs {
		msgs[i] = MessageInfo{Text: strconv.Itoa(first + i)}
	}
	return msgs
}

func TestAddMessageKeepsNewest(t *testing.T) {
	cases := []struct {
		name string
		held int
		// wantFirst is the text of the oldest message held afterwards.
		wantFirst string
		wantLen   int
	}{
		{"empty", 0, "new", 1},
		{"below the cap", maxLiveMessages - 1, "0", maxLiveMessages},
		{"at the cap", maxLiveMessages, "1", maxLiveMessages},
		{"over the cap", maxLiveMessages + 5, "6", maxLiveMessages},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := require.New(t)
			s := &liveSession{Messages: numbered(0, tc.held), msgCount: 7}
			s.addMessage(MessageInfo{Text: "new"})
			a.Len(s.Messages, tc.wantLen)
			a.Equal(tc.wantFirst, s.Messages[0].Text)
			a.Equal("new", s.Messages[len(s.Messages)-1].Text)
			a.Equal(8, s.msgCount)
		})
	}
}

// TestSessionMessagesEventHoldsACopy checks that the messages that a
// session-messages event carries stay as they were when the session
// takes a new message, as the window reads the event later.
func TestSessionMessagesEventHoldsACopy(t *testing.T) {
	a := require.New(t)
	app := NewApp()
	var got []MessageInfo
	app.onEvent = func(name string, data ...any) {
		if name == "session-messages" {
			got = data[1].([]MessageInfo)
		}
	}
	// A full session whose array has no room left, as loadChatHistory
	// leaves one, shifts its messages within that array.
	session := &liveSession{
		ID:       "SESSION",
		Messages: numbered(0, maxLiveMessages),
	}
	app.emitSessionMessages(session)
	app.mu.Lock()
	session.addMessage(MessageInfo{Text: "new"})
	app.mu.Unlock()

	a.Len(got, maxLiveMessages)
	a.Equal("0", got[0].Text)
	a.Equal(strconv.Itoa(maxLiveMessages-1), got[maxLiveMessages-1].Text)
}

// TestLiveSessionHoldsNewestMessages has a peer send more than
// maxLiveMessages messages and checks that the session holds only the
// newest of them, while it counts them all.
func TestLiveSessionHoldsNewestMessages(t *testing.T) {
	a := require.New(t)
	app := newIncognitoApp(t)
	const sent = maxLiveMessages + 10
	addr, _ := startTestServer(t, "srv", func(tr *kamune.Transport) error {
		for i := range sent {
			if _, err := tr.Send(
				kamune.Bytes([]byte(strconv.Itoa(i))),
				kamune.RouteExchangeMessages,
			); err != nil {
				return err
			}
		}
		return readUntilEnd(tr)
	})
	res, err := app.ConnectToServer(
		addr, "tcp", "", "", "", "", "", "", "", false, false, "",
	)
	a.NoError(err)

	a.Eventually(func() bool {
		sessions := app.GetSessions()
		return len(sessions) == 1 && sessions[0].MsgCount == sent
	}, testWait, 10*time.Millisecond)
	msgs := app.GetSessionMessages(res.SessionID)
	a.Len(msgs, maxLiveMessages)
	a.Equal(strconv.Itoa(sent-maxLiveMessages), msgs[0].Text)
	a.Equal(strconv.Itoa(sent-1), msgs[len(msgs)-1].Text)
}

// TestLoadChatHistoryKeepsNewest loads a history longer than
// maxLiveMessages into a resumed session.
func TestLoadChatHistoryKeepsNewest(t *testing.T) {
	a := require.New(t)
	app, cleanup := newTestAppWithStorage(t)
	defer cleanup()
	store := app.store()
	const id = "SESSIONWITHALONGHISTORY0"
	const stored = maxLiveMessages + 3
	for i := range stored {
		a.NoError(store.AddChatEntry(
			id, []byte(strconv.Itoa(i)), time.Now(), storage.SenderPeer,
		))
	}

	session := &liveSession{ID: id}
	app.loadChatHistory(session)
	a.Len(session.Messages, maxLiveMessages)
	a.Equal(stored, session.msgCount)
	a.Equal("3", session.Messages[0].Text)
	a.Equal(strconv.Itoa(stored-1), session.Messages[maxLiveMessages-1].Text)
}

func TestNotifyDue(t *testing.T) {
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s := &liveSession{}
	steps := []struct {
		after time.Duration
		want  bool
	}{
		{0, true},
		{time.Second, false},
		{notificationInterval - time.Millisecond, false},
		{notificationInterval, true},
		{notificationInterval + time.Second, false},
		{3 * notificationInterval, true},
	}
	a := require.New(t)
	for _, st := range steps {
		a.Equal(st.want, s.notifyDue(start.Add(st.after)),
			"message %v after the start", st.after)
	}
}

// TestFloodRaisesOneNotification has a peer send a burst of messages on
// a session that is not the active one, and checks that they raise a
// single notification.
func TestFloodRaisesOneNotification(t *testing.T) {
	a := require.New(t)
	app := newIncognitoApp(t)
	// The clock stands still, so the whole burst falls within one
	// notification interval however slowly it arrives.
	now := time.Now()
	app.clock = func() time.Time { return now }
	events := recordEvents(app)

	const sent = 20
	addr, _ := startTestServer(t, "srv", func(tr *kamune.Transport) error {
		for i := range sent {
			if _, err := tr.Send(
				kamune.Bytes([]byte(strconv.Itoa(i))),
				kamune.RouteExchangeMessages,
			); err != nil {
				return err
			}
		}
		return readUntilEnd(tr)
	})
	_, err := app.ConnectToServer(
		addr, "tcp", "", "", "", "", "", "", "", false, false, "",
	)
	a.NoError(err)

	a.Eventually(func() bool {
		return len(events.named("message-received")) == sent
	}, testWait, 10*time.Millisecond)
	a.Len(events.named("notification"), 1)
}
