package main

import (
	"bufio"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// repeatByte is an endless stream of one byte.
type repeatByte byte

func (b repeatByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

func TestReadLine(t *testing.T) {
	// readLine is given a 16-byte buffer, the smallest bufio allows.
	type line struct {
		text    string
		tooLong bool
		err     error
	}
	tests := []struct {
		name  string
		input string
		want  []line
	}{
		{
			name:  "lines",
			input: "one\ntwo\n",
			want:  []line{{text: "one\n"}, {text: "two\n"}, {err: io.EOF}},
		},
		{
			name:  "line that fills the buffer",
			input: strings.Repeat("a", 15) + "\n",
			want: []line{
				{text: strings.Repeat("a", 15) + "\n"}, {err: io.EOF},
			},
		},
		{
			name:  "line one byte too long",
			input: strings.Repeat("a", 16) + "\nok\n",
			want:  []line{{tooLong: true}, {text: "ok\n"}, {err: io.EOF}},
		},
		{
			name:  "long line",
			input: strings.Repeat("a", 100) + "\nok\n",
			want:  []line{{tooLong: true}, {text: "ok\n"}, {err: io.EOF}},
		},
		{
			name:  "last line without newline",
			input: "one\ntwo",
			want:  []line{{text: "one\n"}, {text: "two", err: io.EOF}},
		},
		{
			name:  "long last line without newline",
			input: strings.Repeat("a", 100),
			want:  []line{{tooLong: true, err: io.EOF}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := require.New(t)
			r := bufio.NewReaderSize(strings.NewReader(tt.input), 16)
			for _, want := range tt.want {
				got, tooLong, err := readLine(r)
				a.Equal(want.text, string(got))
				a.Equal(want.tooLong, tooLong)
				a.Equal(want.err, err)
			}
		})
	}
}

func TestReadCommandsDropsLongLineWhileReading(t *testing.T) {
	a := require.New(t)
	d := NewDaemon()
	rec := newEventRecorder()
	d.output = json.NewEncoder(rec)
	t.Cleanup(d.cancel)
	const lineSize = 64 << 20
	input := io.MultiReader(
		io.LimitReader(repeatByte('a'), lineSize),
		strings.NewReader(
			"\n"+`{"type":"cmd","cmd":"get_version","id":"v"}`+"\n",
		),
	)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	d.readCommands(input)
	runtime.ReadMemStats(&after)

	allocated := after.TotalAlloc - before.TotalAlloc
	a.Less(allocated, uint64(lineSize/4), "the long line was buffered")
	rec.mu.Lock()
	events := append([]recordedEvent(nil), rec.events...)
	rec.mu.Unlock()
	a.Len(events, 2)
	a.Equal(EvtError, events[0].Evt)
	a.Equal("line_too_long", events[0].Data["code"])
	a.Equal(EvtResponse, events[1].Evt)
	a.Equal(ID("v"), events[1].ID)
}
