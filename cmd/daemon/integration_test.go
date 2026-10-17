package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// buildDaemon builds the daemon into a temporary directory and returns
// the path of the binary.
func buildDaemon(t *testing.T) string {
	a := require.New(t)
	binaryPath := filepath.Join(t.TempDir(), "kamune-daemon")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Stderr = os.Stderr
	a.NoError(build.Run(), "failed to build daemon")
	return binaryPath
}

// jsonDaemon is one daemon subprocess driven over JSON stdio.
type jsonDaemon struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	events chan map[string]any
}

func startJSONDaemon(t *testing.T, binaryPath string) *jsonDaemon {
	t.Helper()
	a := require.New(t)
	cmd := exec.Command(binaryPath)
	stdin, err := cmd.StdinPipe()
	a.NoError(err)
	stdout, err := cmd.StdoutPipe()
	a.NoError(err)
	cmd.Stderr = os.Stderr
	a.NoError(cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	events := make(chan map[string]any, 64)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var evt map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &evt); err == nil {
				events <- evt
			}
		}
	}()
	return &jsonDaemon{t: t, cmd: cmd, stdin: stdin, events: events}
}

func (d *jsonDaemon) send(name string, params any) {
	d.t.Helper()
	data, err := json.Marshal(map[string]any{
		"type":   "cmd",
		"cmd":    name,
		"id":     name + "-id",
		"params": params,
	})
	require.New(d.t).NoError(err)
	_, _ = d.stdin.Write(data)
	_, _ = d.stdin.Write([]byte("\n"))
}

func (d *jsonDaemon) wait(
	name, expectedID string, timeout time.Duration,
) map[string]any {
	d.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case evt := <-d.events:
			if evt["evt"] == name {
				if expectedID == "" || evt["id"] == expectedID {
					return evt
				}
			}
		case <-deadline:
			require.New(d.t).FailNowf(
				"timeout waiting for event %s (id=%s)", name, expectedID,
			)
			return nil
		}
	}
}

func (d *jsonDaemon) waitExit(timeout time.Duration) {
	d.t.Helper()
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case err := <-done:
		require.New(d.t).NoError(err, "daemon exited with error")
	case <-time.After(timeout):
		require.New(d.t).FailNow("daemon did not shut down within timeout")
	}
}

func TestIntegrationEndToEnd(t *testing.T) {
	a := require.New(t)
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	binaryPath := buildDaemon(t)
	server := startJSONDaemon(t, binaryPath)
	client := startJSONDaemon(t, binaryPath)

	port := findFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	server.send("open_storage", map[string]any{
		"storage_path":     filepath.Join(t.TempDir(), "server.db"),
		"db_no_passphrase": true,
	})
	server.wait("response", "open_storage-id", 5*time.Second)
	client.send("open_storage", map[string]any{
		"storage_path":     filepath.Join(t.TempDir(), "client.db"),
		"db_no_passphrase": true,
	})
	client.wait("response", "open_storage-id", 5*time.Second)

	// AutoAccept so the handshake does not wait on verify_peer.
	server.send("set_verification_mode", map[string]any{"mode": 2})
	server.wait("response", "set_verification_mode-id", 5*time.Second)
	client.send("set_verification_mode", map[string]any{"mode": 2})
	client.wait("response", "set_verification_mode-id", 5*time.Second)

	server.send("start_server", map[string]any{"addr": addr})
	server.wait("server_started", "start_server-id", 5*time.Second)

	client.send("dial", map[string]any{"addr": addr})
	evt := client.wait("session_started", "dial-id", 10*time.Second)
	sessionData, _ := evt["data"].(map[string]any)
	sessionID, _ := sessionData["session_id"].(string)
	a.NotEmpty(sessionID, "dial session_started has no session_id")

	msg := "Hello, integration test!"
	client.send("send_message", map[string]any{
		"session_id":  sessionID,
		"data_base64": base64.StdEncoding.EncodeToString([]byte(msg)),
	})
	client.wait("message_sent", "send_message-id", 5*time.Second)

	client.send("close_session", map[string]any{"session_id": sessionID})
	client.wait("session_closed", "", 5*time.Second)

	client.send("refresh_history", nil)
	client.wait("history_updated", "", 5*time.Second)

	client.send("get_history_sessions", nil)
	resp := client.wait("response", "get_history_sessions-id", 5*time.Second)
	data, _ := resp["data"].(map[string]any)
	sessions, _ := data["sessions"].([]any)
	a.NotEmpty(sessions, "expected at least one history session after send + close")

	client.send("shutdown", nil)
	client.waitExit(5 * time.Second)
	server.send("shutdown", nil)
	server.waitExit(5 * time.Second)
}

// SIGTERM shuts the daemon down and ends the process while its stdin
// stays open: a supervisor that sends it need not also close the pipe or
// write to it.
func TestSignalEndsProcessWithStdinOpen(t *testing.T) {
	a := require.New(t)
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM cannot be sent on windows")
	}

	cmd := exec.Command(buildDaemon(t))
	stdin, err := cmd.StdinPipe()
	a.NoError(err)
	stdout, err := cmd.StdoutPipe()
	a.NoError(err)
	cmd.Stderr = os.Stderr
	a.NoError(cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = stdin.Close()
	})

	// events carries the event names the daemon writes, and is closed when
	// its stdout ends.
	events := make(chan string, 64)
	go func() {
		defer close(events)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var evt struct {
				Data any    `json:"data"`
				Evt  string `json:"evt"`
			}
			if json.Unmarshal(scanner.Bytes(), &evt) == nil {
				events <- evt.Evt + " " + fmt.Sprint(evt.Data)
			}
		}
	}()

	deadline := time.After(testEventTimeout)
	var seen []string
	next := func() (string, bool) {
		select {
		case evt, ok := <-events:
			return evt, ok
		case <-deadline:
			a.FailNow("the daemon did not exit after SIGTERM", "%q", seen)
			return "", false
		}
	}
	evt, ok := next()
	a.True(ok)
	a.True(strings.HasPrefix(evt, "ready "), evt)

	a.NoError(cmd.Process.Signal(syscall.SIGTERM))
	for {
		evt, ok := next()
		if !ok {
			break
		}
		seen = append(seen, evt)
	}
	a.Contains(seen, "response map[status:shutdown]")
	a.NoError(cmd.Wait())
}

func findFreePort(t *testing.T) int {
	a := require.New(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	a.NoError(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
