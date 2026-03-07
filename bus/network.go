package main

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2/dialog"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/bus/logger"
	"github.com/kamune-org/kamune/pkg/fingerprint"
)

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// startServer initializes and starts the kamune server.
func (c *ChatApp) startServer(addr, dbPath string) {
	c.isServer = true

	logger.Infof("Starting server on %s", addr)

	go func() {
		var opts []kamune.StorageOption
		opts = append(opts,
			kamune.StorageWithDBPath(dbPath),
			kamune.StorageWithNoPassphrase(),
		)

		// Get the appropriate verifier based on current mode
		remoteVerifier := c.verifier.GetVerifier(c.verificationMode)

		srv, err := kamune.NewServer(
			addr,
			c.serverHandler,
			kamune.ServeWithStorageOpts(opts...),
			kamune.ServeWithRemoteVerifier(remoteVerifier),
		)
		if err != nil {
			c.showError(fmt.Errorf("starting server: %w", err))
			logger.Errorf("Failed to start server: %v", err)
			return
		}

		// Keep a reference so stopServer / cleanup can shut down the listener.
		c.mu.Lock()
		c.server = srv
		c.mu.Unlock()

		// Update fingerprint & UI on main thread
		pubKey := srv.PublicKey().Marshal()
		fp := strings.Join(fingerprint.Emoji(pubKey), " • ")
		hexFp := fingerprint.Hex(pubKey)
		c.emojiFingerprint = fp
		c.hexFingerprint = hexFp

		c.runOnMain(func() {
			c.fingerprintLbl.SetText(fp)
			c.serverRunning = true
			c.statusIndicator.SetStatus(StatusConnected, "Server running")
			c.updateStatusText(fmt.Sprintf("Server listening on %s", addr))
			if c.stopServerBtn != nil {
				c.stopServerBtn.Show()
			}
		})

		logger.Infof("Server started successfully on %s", addr)
		c.sendNotification("Server Started", fmt.Sprintf("Listening on %s", addr))

		if err := srv.ListenAndServe(); err != nil {
			// Ensure UI updates happen on main thread
			c.runOnMain(func() {
				c.serverRunning = false
				c.statusIndicator.SetStatus(StatusDisconnected, "Server stopped")
				c.updateStatusText("Server stopped")
				if c.stopServerBtn != nil {
					c.stopServerBtn.Hide()
				}
			})
			logger.Infof("Server stopped: %v", err)
		}

		c.mu.Lock()
		c.server = nil
		c.mu.Unlock()
	}()
}

// stopServer stops the running server.
func (c *ChatApp) stopServer() {
	if !c.serverRunning {
		dialog.ShowInformation("No Server", "No server is currently running.", c.window)
		return
	}

	dialog.ShowConfirm("Stop Server", "Stop the server?\n\nAll active sessions will be disconnected.", func(confirmed bool) {
		if !confirmed {
			return
		}

		logger.Info("Stopping server by user request")

		// Close the server listener so ListenAndServe returns and no new
		// connections are accepted.
		c.mu.Lock()
		if c.server != nil {
			if err := c.server.Close(); err != nil {
				logger.Errorf("failed to close server listener: %v", err)
			}
			c.server = nil
		}

		// Save state and close all active sessions.
		for _, session := range c.sessions {
			c.tabManager.CloseTab(session.ID)
		}
		c.sessions = make([]*Session, 0)
		c.activeSession = nil
		c.serverRunning = false
		c.mu.Unlock()

		c.runOnMain(func() {
			c.sessionList.Refresh()
			c.statusIndicator.SetStatus(StatusDisconnected, "Server stopped")
			c.updateStatusText("Server stopped")
			if c.stopServerBtn != nil {
				c.stopServerBtn.Hide()
			}
		})

		logger.Info("Server stopped successfully")
		c.sendNotification("Server Stopped", "All sessions disconnected")
	}, c.window)
}

// serverHandler handles incoming connections on the server.
// IMPORTANT: This function must block until the session is complete.
// If it returns early, the server's serve() defer will close the connection.
func (c *ChatApp) serverHandler(t *kamune.Transport) error {
	session := &Session{
		ID:           t.SessionID(),
		Transport:    t,
		Messages:     make([]ChatMessage, 0),
		LastActivity: time.Now(),
	}

	// Load persisted chat history so earlier messages are visible immediately.
	c.loadChatHistory(session)

	c.mu.Lock()
	c.sessions = append(c.sessions, session)
	c.mu.Unlock()

	// Open a tab for the new session and update UI on main thread
	c.tabManager.OpenSession(session)

	c.runOnMain(func() {
		c.sessionList.Refresh()
		c.updateStatusText(fmt.Sprintf("New session: %s", truncateSessionID(session.ID)))
		c.sendNotification("New Connection", fmt.Sprintf("Peer connected: %s", truncateSessionID(session.ID)))
	})

	logger.Infof("New session established: %s", session.ID)

	// CRITICAL FIX: Block here receiving messages instead of spawning goroutine.
	// The handler must stay alive to keep the connection open.
	c.receiveMessagesBlocking(session)

	// Clean up session from list and close its tab when connection closes
	c.tabManager.CloseTab(session.ID)

	c.mu.Lock()
	for i, s := range c.sessions {
		if s == session {
			c.sessions = append(c.sessions[:i], c.sessions[i+1:]...)
			break
		}
	}
	if c.activeSession == session {
		c.activeSession = nil
	}
	c.mu.Unlock()

	c.runOnMain(func() {
		c.sessionList.Refresh()
	})

	// Refresh history so the closed session appears in the History tab.
	go c.refreshHistorySessions()

	logger.Infof("Session closed: %s", session.ID)
	return nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// connectToServer connects to a kamune server as a client.
func (c *ChatApp) connectToServer(addr, dbPath string) {
	c.isServer = false

	logger.Infof("Connecting to server at %s", addr)

	go func() {
		var dialOpts []kamune.StorageOption
		dialOpts = append(dialOpts,
			kamune.StorageWithDBPath(dbPath),
			kamune.StorageWithNoPassphrase(),
		)

		// Get the appropriate verifier based on current mode
		remoteVerifier := c.verifier.GetVerifier(c.verificationMode)

		dialer, err := kamune.NewDialer(
			addr,
			kamune.DialWithStorageOpts(dialOpts...),
			kamune.DialWithRemoteVerifier(remoteVerifier),
		)
		if err != nil {
			c.showError(fmt.Errorf("creating dialer: %w", err))
			logger.Errorf("Failed to create dialer: %v", err)
			return
		}

		// Update fingerprint display on main thread
		pubKey := dialer.PublicKey().Marshal()
		fp := strings.Join(fingerprint.Emoji(pubKey), " • ")
		hexFp := fingerprint.Hex(pubKey)
		c.emojiFingerprint = fp
		c.hexFingerprint = hexFp

		c.runOnMain(func() {
			c.fingerprintLbl.SetText(fp)
			c.statusIndicator.SetStatus(StatusConnecting, "Connecting...")
			c.updateStatusText(fmt.Sprintf("Connecting to %s...", addr))
		})

		t, err := dialer.Dial()
		if err != nil {
			// UI updates on main thread
			c.runOnMain(func() {
				c.showError(fmt.Errorf("connecting: %w", err))
				c.statusIndicator.SetStatus(StatusError, "Connection failed")
			})
			logger.Errorf("Connection failed: %v", err)
			return
		}

		session := &Session{
			ID:           t.SessionID(),
			Transport:    t,
			Messages:     make([]ChatMessage, 0),
			LastActivity: time.Now(),
		}

		// Load persisted chat history so earlier messages are visible immediately.
		c.loadChatHistory(session)

		c.mu.Lock()
		c.sessions = append(c.sessions, session)
		c.mu.Unlock()

		// Open a tab for the new session and update UI on main thread
		c.tabManager.OpenSession(session)

		c.runOnMain(func() {
			c.sessionList.Refresh()
			c.statusIndicator.SetStatus(StatusConnected, "Connected")
			c.updateStatusText(fmt.Sprintf("Connected - Session: %s", truncateSessionID(session.ID)))
		})

		logger.Infof("Connected successfully, session: %s", session.ID)
		c.sendNotification("Connected", fmt.Sprintf("Session: %s", truncateSessionID(session.ID)))

		// Start receiving messages in its own goroutine
		go c.receiveMessages(session)
	}()
}
