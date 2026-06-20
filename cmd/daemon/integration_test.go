package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestIntegrationEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "kamune-daemon")

	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("failed to build daemon: %v", err)
	}

	storageDir := t.TempDir()
	storagePath := filepath.Join(storageDir, "test.db")

	port := findFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	cmd := exec.Command(binaryPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	events := make(chan map[string]any, 64)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var evt map[string]any
			if err := json.Unmarshal(scanner.Bytes(), &evt); err == nil {
				events <- evt
			}
		}
	}()

	sendCmd := func(name string, params any) {
		data, _ := json.Marshal(map[string]any{
			"type":   "cmd",
			"cmd":    name,
			"id":     name + "-id",
			"params": params,
		})
		_, _ = stdin.Write(data)
		_, _ = stdin.Write([]byte("\n"))
	}

	waitEvent := func(name, expectedID string, timeout time.Duration) map[string]any {
		deadline := time.After(timeout)
		for {
			select {
			case evt := <-events:
				if evt["evt"] == name {
					if expectedID == "" || evt["id"] == expectedID {
						return evt
					}
				}
			case <-deadline:
				t.Fatalf("timeout waiting for event %s (id=%s)", name, expectedID)
				return nil
			}
		}
	}

	sendCmd("open_storage", map[string]any{
		"storage_path":     storagePath,
		"db_no_passphrase": true,
	})
	waitEvent("response", "open_storage-id", 5*time.Second)

	sendCmd("set_verification_mode", map[string]any{"mode": 2})
	waitEvent("response", "set_verification_mode-id", 5*time.Second)

	sendCmd("start_server", map[string]any{"addr": addr})
	waitEvent("server_started", "start_server-id", 5*time.Second)

	sendCmd("dial", map[string]any{"addr": addr})
	evt := waitEvent("session_started", "dial-id", 10*time.Second)
	sessionData, _ := evt["data"].(map[string]any)
	sessionID, _ := sessionData["session_id"].(string)
	if sessionID == "" {
		t.Fatal("dial session_started has no session_id")
	}

	msg := "Hello, integration test!"
	sendCmd("send_message", map[string]any{
		"session_id":  sessionID,
		"data_base64": base64.StdEncoding.EncodeToString([]byte(msg)),
	})
	waitEvent("message_sent", "send_message-id", 5*time.Second)

	sendCmd("close_session", map[string]any{"session_id": sessionID})
	waitEvent("session_closed", "", 5*time.Second)

	sendCmd("refresh_history", nil)
	waitEvent("history_updated", "", 5*time.Second)

	sendCmd("get_history_sessions", nil)
	resp := waitEvent("response", "get_history_sessions-id", 5*time.Second)
	data, _ := resp["data"].(map[string]any)
	sessions, _ := data["sessions"].([]any)
	if len(sessions) == 0 {
		t.Fatal("expected at least one history session after send + close")
	}

	sendCmd("shutdown", nil)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not shut down within 5s")
	}
}

func findFreePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
