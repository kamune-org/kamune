package main

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"

	"github.com/kamune-org/kamune/bus/logger"
)

// setupMenus configures the application menu bar.
func (c *ChatApp) setupMenus() {
	// File menu
	fileMenu := fyne.NewMenu("File",
		fyne.NewMenuItem("Start Server...", c.showServerDialog),
		fyne.NewMenuItem("Connect to Server...", c.showConnectDialog),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("View History...", c.historyViewer.ShowHistoryDialog),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() {
			c.cleanup()
			c.app.Quit()
		}),
	)

	// Edit menu
	editMenu := fyne.NewMenu("Edit",
		fyne.NewMenuItem("Clear Messages", func() {
			c.mu.Lock()
			if c.activeSession != nil {
				c.activeSession.Messages = make([]ChatMessage, 0)
			}
			c.mu.Unlock()
			c.refreshMessages()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Copy Session ID", func() {
			c.copyActiveSessionID()
		}),
		fyne.NewMenuItem("Copy Fingerprint", func() {
			c.copyFingerprint()
		}),
	)

	// Session menu
	sessionMenu := fyne.NewMenu("Session",
		fyne.NewMenuItem("Session Info", func() {
			c.showSessionInfo()
		}),
		fyne.NewMenuItem("Copy Session ID", func() {
			c.copyActiveSessionID()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("End Session", func() {
			c.disconnectActiveSession()
		}),
	)

	// View menu
	viewMenu := fyne.NewMenu("View",
		fyne.NewMenuItem("Toggle Logs", func() {
			c.toggleLogPanel()
		}),
		fyne.NewMenuItem("Clear Logs", func() {
			c.logViewer.Clear()
		}),
	)

	// Settings menu
	settingsMenu := fyne.NewMenu("Settings",
		fyne.NewMenuItem("Verification: Strict", func() {
			c.verificationMode = VerificationModeStrict
			c.showVerificationModeNotification()
		}),
		fyne.NewMenuItem("Verification: Quick", func() {
			c.verificationMode = VerificationModeQuick
			c.showVerificationModeNotification()
		}),
		fyne.NewMenuItem("Verification: Auto-Accept", func() {
			c.verificationMode = VerificationModeAutoAccept
			c.showVerificationModeNotification()
		}),
	)

	// Help menu
	helpMenu := fyne.NewMenu("Help",
		fyne.NewMenuItem("Keyboard Shortcuts", func() {
			c.showShortcutsHelp()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("About Kamune Chat", func() {
			dialog.ShowInformation("About Kamune Chat",
				fmt.Sprintf("Kamune Chat GUI v%s\n\nA secure messaging application built with Fyne.\n\nPowered by the Kamune protocol for end-to-end encrypted communication.\n\nShortcuts:\n• Ctrl+W - Close window\n• Ctrl+N - New connection\n• Ctrl+S - Start server\n• Ctrl+H - View history\n• Ctrl+L - Toggle logs", appVersion),
				c.window)
		}),
	)

	mainMenu := fyne.NewMainMenu(fileMenu, editMenu, sessionMenu, viewMenu, settingsMenu, helpMenu)
	c.window.SetMainMenu(mainMenu)
}

// setupShortcuts configures keyboard shortcuts.
func (c *ChatApp) setupShortcuts() {
	// Ctrl+W - Close window
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.cleanup()
		c.window.Close()
	})

	// Cmd+W for macOS
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierSuper,
	}, func(shortcut fyne.Shortcut) {
		c.cleanup()
		c.window.Close()
	})

	// Ctrl+N - New connection
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyN,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.showConnectDialog()
	})

	// Ctrl+S - Start server
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyS,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.showServerDialog()
	})

	// Ctrl+H - View history
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyH,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.historyViewer.ShowHistoryDialog()
	})

	// Ctrl+L - Toggle logs
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyL,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.toggleLogPanel()
	})

	// Escape - Close log panel if open
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName: fyne.KeyEscape,
	}, func(shortcut fyne.Shortcut) {
		if c.logPanelOpen {
			c.toggleLogPanel()
		}
	})
}

// showShortcutsHelp displays keyboard shortcuts.
func (c *ChatApp) showShortcutsHelp() {
	shortcuts := `Keyboard Shortcuts:

• Ctrl+W / Cmd+W - Close application
• Ctrl+N / Cmd+N - Connect to server
• Ctrl+S / Cmd+S - Start server
• Ctrl+H / Cmd+H - View history
• Ctrl+L / Cmd+L - Toggle log panel
• Enter - Send message (in message field)

Right-click on sessions or messages for context menus.`

	dialog.ShowInformation("Keyboard Shortcuts", shortcuts, c.window)
}

// showVerificationModeNotification displays the current verification mode.
func (c *ChatApp) showVerificationModeNotification() {
	var modeText string
	switch c.verificationMode {
	case VerificationModeStrict:
		modeText = "Strict - All peers require verification"
	case VerificationModeQuick:
		modeText = "Quick - Known peers auto-accepted"
	case VerificationModeAutoAccept:
		modeText = "Auto-Accept - All peers accepted (testing only)"
	}
	dialog.ShowInformation("Verification Mode", modeText, c.window)
	logger.Infof("Verification mode changed to: %s", modeText)
}
