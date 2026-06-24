package relayconn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestFraming_ReadWriteRoundtrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	fA := NewFraming(a, 0)
	fB := NewFraming(b, 0)

	want := []byte("hello from a")

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- fA.WriteBytes(want)
	}()

	got, err := fB.ReadBytes()
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if err := <-writeErr; err != nil {
		t.Errorf("WriteBytes: %v", err)
	}
}

func TestFraming_EmptyFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	fA := NewFraming(a, 0)
	fB := NewFraming(b, 0)

	go func() { _ = fA.WriteBytes(nil) }()

	got, err := fB.ReadBytes()
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(got))
	}
}

func TestFraming_MaxSizeEnforced(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// Max 10 bytes on the reader side.
	fB := NewFraming(b, 10)

	go func() {
		_ = binary.Write(a, binary.BigEndian, uint16(100))
		_, _ = a.Write(make([]byte, 100))
	}()

	_, err := fB.ReadBytes()
	if err == nil {
		t.Fatal("expected error for oversized frame, got nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("exceeds max")) {
		t.Errorf("err = %v, want it to mention 'exceeds max'", err)
	}
}

func TestFraming_NoMaxSize(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	fA := NewFraming(a, 0)
	fB := NewFraming(b, 0) // 0 = no limit

	want := bytes.Repeat([]byte("x"), 60000)

	go func() { _ = fA.WriteBytes(want) }()

	got, err := fB.ReadBytes()
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("payload length = %d, want %d", len(got), len(want))
	}
}

func TestFraming_TruncatedFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	fB := NewFraming(b, 0)

	go func() {
		defer a.Close()
		_, _ = a.Write([]byte{0x00, 0x64}) // length = 100
		_, _ = a.Write([]byte{1, 2, 3, 4, 5})
	}()

	_, err := fB.ReadBytes()
	if err == nil {
		t.Fatal("expected error for truncated frame, got nil")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) &&
		!bytes.Contains([]byte(err.Error()), []byte("read data")) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF or 'read data'", err)
	}
}

func TestFraming_Close(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()

	fA := NewFraming(a, 0)
	if err := fA.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := fA.WriteBytes([]byte("x")); err == nil {
		t.Error("expected error writing to closed conn, got nil")
	}
}

func TestFraming_SetDeadline_Delegates(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	// net.Pipe supports SetDeadline.
	fA := NewFraming(a, 0)
	if err := fA.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline: %v", err)
	}
}

func TestFraming_SetDeadline_NoOp(t *testing.T) {
	rwc := struct {
		io.ReadWriter
		io.Closer
	}{}

	f := NewFraming(rwc, 0)
	if err := f.SetDeadline(time.Time{}); err != nil {
		t.Errorf("SetDeadline on non-deadline conn: got %v, want nil", err)
	}
}
