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
		fyne.NewMenuItem("Refresh History", func() {
			c.refreshHistorySessions()
		}),
		fyne.NewMenuItem("Delete Session History...", func() {
			c.mu.RLock()
			hs := c.activeHistSession
			c.mu.RUnlock()
			if hs != nil {
				c.deleteHistorySession(hs)
			} else {
				dialog.ShowInformation("No History Session", "Select a history session first.", c.window)
			}
		}),
		fyne.NewMenuItem("Database Path...", func() {
			c.showDBPathDialog()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", func() {
			c.cleanup()
			c.app.Quit()
		}),
	)

	// Edit menu
	editMenu := fyne.NewMenu("Edit",
		fyne.NewMenuItem("Clear Messages", func() {
			ct := c.tabManager.SelectedTab()
			if ct == nil {
				return
			}
			c.mu.Lock()
			if ct.Kind == ChatTabLive && ct.Session != nil {
				ct.Session.Messages = make([]ChatMessage, 0)
			}
			c.mu.Unlock()
			c.tabManager.RefreshActiveTab()
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
		fyne.NewMenuItem("Rename Session", func() {
			c.mu.RLock()
			session := c.activeSession
			histSession := c.activeHistSession
			c.mu.RUnlock()
			if session != nil {
				c.showRenameSessionDialog(session)
			} else if histSession != nil {
				c.showRenameHistorySessionDialog(histSession)
			} else {
				dialog.ShowInformation("No Session", "Select a session to rename.", c.window)
			}
		}),
		fyne.NewMenuItem("Copy Session ID", func() {
			c.copyActiveSessionID()
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Close Other Tabs", func() {
			c.tabManager.CloseOtherTabs()
		}),
		fyne.NewMenuItem("Close Tabs to the Right", func() {
			c.tabManager.CloseTabsToTheRight()
		}),
		fyne.NewMenuItem("Close All Tabs", func() {
			c.tabManager.CloseAllTabs()
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
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Show Sessions Tab", func() {
			if c.sidebarTabs != nil {
				c.sidebarTabs.SelectIndex(0)
			}
		}),
		fyne.NewMenuItem("Show History Tab", func() {
			if c.sidebarTabs != nil {
				c.sidebarTabs.SelectIndex(1)
			}
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
		fyne.NewMenuItem("About Bus", func() {
			dialog.ShowInformation("About Bus",
				fmt.Sprintf("Bus — Kamune Chat v%s\n\nSecure end-to-end encrypted messaging.\nBuilt with Fyne and the Kamune protocol.\n\nShortcuts:\n  Ctrl+N — Connect\n  Ctrl+S — Start Server\n  Ctrl+H — View History\n  Ctrl+L — Toggle Logs\n  Ctrl+W — Close Tab\n  Ctrl+Shift+W — Close All Tabs", appVersion),
				c.window)
		}),
	)

	mainMenu := fyne.NewMainMenu(fileMenu, editMenu, sessionMenu, viewMenu, settingsMenu, helpMenu)
	c.window.SetMainMenu(mainMenu)
}

// setupShortcuts configures keyboard shortcuts.
func (c *ChatApp) setupShortcuts() {
	// Ctrl+W — Close active tab, or quit if no tabs open
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		if c.tabManager.TabCount() > 0 {
			c.tabManager.CloseActiveTab()
		} else {
			c.cleanup()
			c.window.Close()
		}
	})

	// Cmd+W for macOS — same behaviour
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierSuper,
	}, func(shortcut fyne.Shortcut) {
		if c.tabManager.TabCount() > 0 {
			c.tabManager.CloseActiveTab()
		} else {
			c.cleanup()
			c.window.Close()
		}
	})

	// Ctrl+Shift+W — Close all tabs
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierControl | fyne.KeyModifierShift,
	}, func(shortcut fyne.Shortcut) {
		c.tabManager.CloseAllTabs()
	})

	// Cmd+Shift+W for macOS — Close all tabs
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyW,
		Modifier: fyne.KeyModifierSuper | fyne.KeyModifierShift,
	}, func(shortcut fyne.Shortcut) {
		c.tabManager.CloseAllTabs()
	})

	// Ctrl+N — New connection
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyN,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.showConnectDialog()
	})

	// Ctrl+S — Start server
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyS,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.showServerDialog()
	})

	// Ctrl+H — View history / switch to history tab
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyH,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		if c.sidebarTabs != nil {
			c.sidebarTabs.SelectIndex(1)
		}
		c.refreshHistorySessions()
	})

	// Ctrl+L — Toggle logs
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyL,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.toggleLogPanel()
	})

	// Ctrl+R — Refresh history
	c.window.Canvas().AddShortcut(&desktop.CustomShortcut{
		KeyName:  fyne.KeyR,
		Modifier: fyne.KeyModifierControl,
	}, func(shortcut fyne.Shortcut) {
		c.refreshHistorySessions()
	})

	// Escape — Close log panel if open
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

  Ctrl+N / Cmd+N — Connect to server
  Ctrl+S / Cmd+S — Start server
  Ctrl+H / Cmd+H — Show history tab
  Ctrl+L / Cmd+L — Toggle log panel
  Ctrl+R / Cmd+R — Refresh history
  Ctrl+W / Cmd+W — Close active tab (quit if none)
  Ctrl+Shift+W   — Close all tabs
  Enter — Send message (in message field)
  Escape — Close log panel

Right-click on sessions or messages for context menus.`

	dialog.ShowInformation("Keyboard Shortcuts", shortcuts, c.window)
}

// showVerificationModeNotification displays the current verification mode.
func (c *ChatApp) showVerificationModeNotification() {
	var modeText string
	switch c.verificationMode {
	case VerificationModeStrict:
		modeText = "Strict — All peers require verification"
	case VerificationModeQuick:
		modeText = "Quick — Known peers auto-accepted"
	case VerificationModeAutoAccept:
		modeText = "Auto-Accept — All peers accepted (testing only)"
	}
	dialog.ShowInformation("Verification Mode", modeText, c.window)
	logger.Infof("Verification mode changed to: %s", modeText)
}
