package main

import (
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ---------------------------------------------------------------------------
// Log panel
// ---------------------------------------------------------------------------

// buildLogPanel creates the log viewer panel.
func (c *ChatApp) buildLogPanel() fyne.CanvasObject {
	logUI := c.logViewer.BuildUI()

	headerLabel := widget.NewLabelWithStyle("Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	headerLabel.Importance = widget.LowImportance

	clearBtn := widget.NewButtonWithIcon("", theme.DeleteIcon(), func() {
		c.logViewer.Clear()
	})
	clearBtn.Importance = widget.LowImportance

	autoScrollCheck := widget.NewCheck("Auto", func(checked bool) {
		c.logViewer.autoScroll = checked
	})
	autoScrollCheck.SetChecked(true)

	closeBtn := widget.NewButtonWithIcon("", theme.CancelIcon(), func() {
		c.toggleLogPanel()
	})
	closeBtn.Importance = widget.LowImportance

	header := container.NewBorder(nil, nil, headerLabel, container.NewHBox(clearBtn, autoScrollCheck, closeBtn))

	return container.NewBorder(
		header,
		nil, nil, nil,
		logUI,
	)
}

// toggleLogPanel shows or hides the log panel.
func (c *ChatApp) toggleLogPanel() {
	c.logPanelOpen = !c.logPanelOpen
	if c.logPanelOpen {
		c.logPanel.Show()
		c.mainSplit.SetOffset(0.55)
	} else {
		c.logPanel.Hide()
		c.mainSplit.SetOffset(1.0)
	}
}

// ---------------------------------------------------------------------------
// Session panel (left sidebar) with tabs
// ---------------------------------------------------------------------------

// buildSessionPanel creates the left sidebar with session list and history tabs.
func (c *ChatApp) buildSessionPanel() fyne.CanvasObject {
	// ── Sidebar background ──
	sidebarBg := canvas.NewRectangle(sidebarBgColor)

	// ── Connection action buttons ──
	serverBtn := widget.NewButtonWithIcon("Start Server", theme.ComputerIcon(), c.showServerDialog)
	serverBtn.Importance = widget.HighImportance

	clientBtn := widget.NewButtonWithIcon("Connect", theme.LoginIcon(), c.showConnectDialog)

	c.stopServerBtn = widget.NewButtonWithIcon("Stop Server", theme.CancelIcon(), c.stopServer)
	c.stopServerBtn.Importance = widget.DangerImportance
	c.stopServerBtn.Hide()

	buttonBox := container.NewVBox(serverBtn, clientBtn, c.stopServerBtn)

	// ── Active sessions list ──
	c.sessionList = widget.NewList(
		func() int {
			c.mu.RLock()
			defer c.mu.RUnlock()
			return len(c.sessions)
		},
		func() fyne.CanvasObject {
			return NewSessionItem("", false, 0, time.Time{})
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if id < len(c.sessions) {
				session := c.sessions[id]
				isActive := c.activeSession == session
				item := obj.(*SessionItem)
				item.UpdateWithName(session.ID, session.PeerName, isActive, len(session.Messages), session.LastActivity)
			}
		},
	)

	c.sessionList.OnSelected = func(id widget.ListItemID) {
		c.mu.RLock()
		var session *Session
		if id < len(c.sessions) {
			session = c.sessions[id]
		}
		c.mu.RUnlock()

		if session != nil {
			c.tabManager.OpenSession(session)
		}
	}

	// Empty state for session list
	noSessionsLabel := widget.NewLabelWithStyle(
		"No active sessions",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	noSessionsLabel.Importance = widget.LowImportance

	noSessionsHint := widget.NewLabelWithStyle(
		"Start a server or connect\nto a peer to begin.",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	noSessionsHint.Importance = widget.LowImportance
	noSessionsHint.Wrapping = fyne.TextWrapWord

	sessionsEmptyState := container.NewCenter(
		container.NewVBox(
			noSessionsLabel,
			noSessionsHint,
		),
	)

	sessionsContent := container.NewStack(sessionsEmptyState, c.sessionList)

	// Update empty state visibility based on sessions
	go func() {
		for {
			select {
			case <-c.stopChan:
				return
			case <-time.After(500 * time.Millisecond):
			}

			c.mu.RLock()
			count := len(c.sessions)
			c.mu.RUnlock()

			c.runOnMain(func() {
				if count == 0 {
					sessionsEmptyState.Show()
				} else {
					sessionsEmptyState.Hide()
				}
			})
		}
	}()

	sessionTab := container.NewBorder(
		container.NewVBox(buttonBox, widget.NewSeparator()),
		nil, nil, nil,
		sessionsContent,
	)

	// ── History sessions list ──
	c.historyList = widget.NewList(
		func() int {
			c.mu.RLock()
			defer c.mu.RUnlock()
			return len(c.historySessions)
		},
		func() fyne.CanvasObject {
			return NewHistorySessionItem()
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			c.mu.RLock()
			defer c.mu.RUnlock()
			if id < len(c.historySessions) {
				hs := c.historySessions[id]
				isActive := c.activeHistSession == hs
				item := obj.(*HistorySessionItem)
				item.UpdateWithName(hs.ID, hs.Name, hs.MessageCount, hs.LastMessage, isActive)
			}
		},
	)

	c.historyList.OnSelected = func(id widget.ListItemID) {
		c.mu.RLock()
		var hs *HistorySession
		if id < len(c.historySessions) {
			hs = c.historySessions[id]
		}
		c.mu.RUnlock()

		if hs != nil {
			// Load messages if needed, then open in a tab
			if !hs.Loaded {
				go func() {
					if err := c.loadHistoryMessages(hs); err != nil {
						c.showError(fmt.Errorf("loading session history: %w", err))
						return
					}
					c.tabManager.OpenHistory(hs)
				}()
			} else {
				c.tabManager.OpenHistory(hs)
			}
		}
	}

	// History controls
	refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
		c.refreshHistorySessions()
	})
	refreshBtn.Importance = widget.LowImportance
	c.historyRefreshBtn = refreshBtn

	historyControls := container.NewHBox(refreshBtn)

	// Empty state for history
	noHistoryLabel := widget.NewLabelWithStyle(
		"No session history found",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	noHistoryLabel.Importance = widget.LowImportance

	noHistoryHint := widget.NewLabelWithStyle(
		"Chat sessions will appear\nhere after your first\nconversation.",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	noHistoryHint.Importance = widget.LowImportance
	noHistoryHint.Wrapping = fyne.TextWrapWord

	historyEmptyState := container.NewCenter(
		container.NewVBox(
			noHistoryLabel,
			noHistoryHint,
		),
	)

	historyContent := container.NewStack(historyEmptyState, c.historyList)

	// Update history empty state
	go func() {
		for {
			select {
			case <-c.stopChan:
				return
			case <-time.After(500 * time.Millisecond):
			}

			c.mu.RLock()
			count := len(c.historySessions)
			c.mu.RUnlock()

			c.runOnMain(func() {
				if count == 0 {
					historyEmptyState.Show()
				} else {
					historyEmptyState.Hide()
				}
			})
		}
	}()

	historyTab := container.NewBorder(
		container.NewVBox(historyControls, widget.NewSeparator()),
		nil, nil, nil,
		historyContent,
	)

	// ── Create tabbed container ──
	c.sidebarTabs = container.NewAppTabs(
		container.NewTabItemWithIcon("Sessions", theme.AccountIcon(), sessionTab),
		container.NewTabItemWithIcon("History", theme.HistoryIcon(), historyTab),
	)
	c.sidebarTabs.SetTabLocation(container.TabLocationTop)

	// ── Fingerprint display ──
	c.fingerprintLbl = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	c.fingerprintLbl.Wrapping = fyne.TextWrapWord

	copyFingerprintBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		c.copyFingerprint()
	})
	copyFingerprintBtn.Importance = widget.LowImportance

	fingerprintContent := container.NewVBox(
		c.fingerprintLbl,
		container.NewCenter(copyFingerprintBtn),
	)

	fingerprintCard := widget.NewCard("Fingerprint", "", fingerprintContent)

	// ── Database path option ──
	dbPathLabel := canvas.NewText(c.dbPathDisplay(), textSecondary)
	dbPathLabel.TextSize = 11
	dbPathLabel.Alignment = fyne.TextAlignLeading

	changeDBBtn := widget.NewButtonWithIcon("Change", theme.FolderOpenIcon(), func() {
		c.showDBPathDialog()
	})
	changeDBBtn.Importance = widget.LowImportance

	dbIcon := canvas.NewText("🗄", textMuted)
	dbIcon.TextSize = 14

	dbRow := container.NewBorder(nil, nil,
		container.NewHBox(dbIcon),
		changeDBBtn,
		dbPathLabel,
	)

	dbCard := widget.NewCard("Database", "", dbRow)

	// Keep the label in sync with the current path
	go func() {
		var lastPath string
		for {
			select {
			case <-c.stopChan:
				return
			case <-time.After(500 * time.Millisecond):
			}

			p := c.dbPathDisplay()
			if p != lastPath {
				lastPath = p
				c.runOnMain(func() {
					dbPathLabel.Text = p
					dbPathLabel.Refresh()
				})
			}
		}
	}()

	// ── Combine sidebar ──
	bottomCards := container.NewVBox(dbCard, fingerprintCard)

	sidebar := container.NewBorder(
		nil,
		bottomCards,
		nil, nil,
		c.sidebarTabs,
	)

	return container.NewStack(sidebarBg, container.NewPadded(sidebar))
}

// showDBPathDialog shows a dialog to change the application database path.
// This single path is used by the server, client, history viewer, and history tab.
func (c *ChatApp) showDBPathDialog() {
	dbEntry := widget.NewEntry()
	dbEntry.SetPlaceHolder("Path to database directory")
	dbEntry.SetText(c.DBPath())

	resetBtn := widget.NewButtonWithIcon("Reset to Default", theme.ViewRefreshIcon(), func() {
		dbEntry.SetText(getDefaultDBDir())
	})
	resetBtn.Importance = widget.LowImportance

	form := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("Database Path", dbEntry),
		),
		container.NewHBox(layout.NewSpacer(), resetBtn),
	)

	dlg := newCustomConfirm("Database Path", "Apply", "Cancel", form, func(confirmed bool) {
		if confirmed && dbEntry.Text != "" {
			c.SetDBPath(dbEntry.Text)
		}
	}, c.window)
	dlg.Resize(fyne.NewSize(460, 190))
	dlg.Show()
}

// newCustomConfirm is a small wrapper that avoids importing dialog in this file
// for common cases. Callers who need dialog directly can still use it.
func newCustomConfirm(
	title, confirm, dismiss string,
	content fyne.CanvasObject,
	callback func(bool),
	parent fyne.Window,
) *widget.PopUp {
	// We build a lightweight confirm inline since this file avoids heavy dialog usage.
	// However, since we do need the dialog package elsewhere, just use it.
	// This is implemented via a small custom popup approach.

	var popup *widget.PopUp

	confirmBtn := widget.NewButton(confirm, func() {
		if popup != nil {
			popup.Hide()
		}
		callback(true)
	})
	confirmBtn.Importance = widget.HighImportance

	dismissBtn := widget.NewButton(dismiss, func() {
		if popup != nil {
			popup.Hide()
		}
		callback(false)
	})

	titleLabel := widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	buttons := container.NewHBox(layout.NewSpacer(), dismissBtn, confirmBtn)

	box := container.NewVBox(
		titleLabel,
		widget.NewSeparator(),
		container.NewPadded(content),
		widget.NewSeparator(),
		buttons,
	)

	bg := canvas.NewRectangle(cardBgColor)
	bg.CornerRadius = 10

	card := container.NewStack(bg, container.NewPadded(box))

	popup = widget.NewModalPopUp(card, parent.Canvas())
	return popup
}

// ---------------------------------------------------------------------------
// Chat panel (center)
// ---------------------------------------------------------------------------

// buildChatPanel creates the main chat area.
func (c *ChatApp) buildChatPanel() fyne.CanvasObject {
	// ── Welcome overlay (shown when no tabs are open) ──
	c.welcomeOverlay = BuildWelcomeOverlay()

	// ── DocTabs from the tab manager ──
	docTabs := c.tabManager.Widget()

	// Stack: welcome overlay behind the doc-tabs. We show/hide the welcome
	// overlay depending on whether any tabs are open, and show/hide the
	// DocTabs widget accordingly.
	tabArea := container.NewStack(c.welcomeOverlay, docTabs)
	docTabs.Hide() // hidden until a tab is opened

	// ── Message input area ──
	c.messageEntry = widget.NewMultiLineEntry()
	c.messageEntry.SetPlaceHolder("Type a message… (Enter to send)")
	c.messageEntry.SetMinRowsVisible(2)
	c.messageEntry.Wrapping = fyne.TextWrapWord

	c.messageEntry.OnSubmitted = func(s string) {
		c.sendMessage()
	}

	c.sendButton = widget.NewButtonWithIcon("", theme.MailSendIcon(), c.sendMessage)
	c.sendButton.Importance = widget.HighImportance

	inputRow := container.NewBorder(nil, nil, nil, c.sendButton, c.messageEntry)
	inputArea := container.NewPadded(inputRow)

	// ── Session info header ──
	sessionInfoBar := c.tabManager.BuildTabInfoBar()
	headerArea := container.NewVBox(sessionInfoBar)

	chatContent := container.NewBorder(headerArea, inputArea, nil, nil, tabArea)

	// Monitor tab count to toggle welcome overlay vs DocTabs, and
	// enable/disable input based on the selected tab kind.
	go func() {
		var lastCount int
		var lastIsHist bool
		for {
			select {
			case <-c.stopChan:
				return
			case <-time.After(200 * time.Millisecond):
			}

			count := c.tabManager.TabCount()
			isHist := c.isViewingHistory()

			if count != lastCount {
				lastCount = count
				c.runOnMain(func() {
					if count == 0 {
						c.welcomeOverlay.Show()
						docTabs.Hide()
					} else {
						c.welcomeOverlay.Hide()
						docTabs.Show()
					}
				})
			}

			if isHist != lastIsHist {
				lastIsHist = isHist
				c.runOnMain(func() {
					if isHist {
						c.messageEntry.Disable()
						c.sendButton.Disable()
					} else {
						c.messageEntry.Enable()
						c.sendButton.Enable()
					}
				})
			}
		}
	}()

	return chatContent
}

// ---------------------------------------------------------------------------
// Status bar
// ---------------------------------------------------------------------------

// buildStatusBar creates the bottom status bar.
func (c *ChatApp) buildStatusBar() fyne.CanvasObject {
	c.statusLabel = widget.NewLabel("Ready")
	c.statusLabel.Importance = widget.LowImportance

	logToggleBtn := widget.NewButtonWithIcon("", theme.ListIcon(), func() {
		c.toggleLogPanel()
	})
	logToggleBtn.Importance = widget.LowImportance

	versionLabel := widget.NewLabelWithStyle(
		"v"+appVersion,
		fyne.TextAlignTrailing,
		fyne.TextStyle{Monospace: true},
	)
	versionLabel.Importance = widget.LowImportance

	statusBox := container.NewHBox(
		c.statusIndicator,
		widget.NewSeparator(),
		c.statusLabel,
		layout.NewSpacer(),
		logToggleBtn,
		widget.NewSeparator(),
		versionLabel,
	)

	return container.NewVBox(
		widget.NewSeparator(),
		container.NewPadded(statusBox),
	)
}

// ---------------------------------------------------------------------------
// History session item widget
// ---------------------------------------------------------------------------

// HistorySessionItem is a widget for displaying a past session in the sidebar.
type HistorySessionItem struct {
	widget.BaseWidget
	sessionID    string
	name         string
	messageCount int
	lastMessage  time.Time
	isActive     bool
}

// NewHistorySessionItem creates a new history session item widget.
func NewHistorySessionItem() *HistorySessionItem {
	h := &HistorySessionItem{}
	h.ExtendBaseWidget(h)
	return h
}

// Update updates the history session item.
func (h *HistorySessionItem) Update(
	sessionID string, messageCount int, lastMessage time.Time, isActive bool,
) {
	h.sessionID = sessionID
	h.messageCount = messageCount
	h.lastMessage = lastMessage
	h.isActive = isActive

	fyne.Do(func() {
		h.Refresh()
	})
}

// UpdateWithName updates the history session item including the display name.
func (h *HistorySessionItem) UpdateWithName(
	sessionID, name string, messageCount int, lastMessage time.Time, isActive bool,
) {
	h.sessionID = sessionID
	h.name = name
	h.messageCount = messageCount
	h.lastMessage = lastMessage
	h.isActive = isActive

	fyne.Do(func() {
		h.Refresh()
	})
}

// CreateRenderer implements fyne.Widget.
func (h *HistorySessionItem) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(color.Transparent)
	background.CornerRadius = 8

	icon := canvas.NewText("📖", textSecondary)
	icon.TextSize = 16

	idLabel := canvas.NewText("", textPrimary)
	idLabel.TextStyle = fyne.TextStyle{Bold: true}
	idLabel.TextSize = 12

	metaLabel := canvas.NewText("", textMuted)
	metaLabel.TextSize = 10

	countBg := canvas.NewRectangle(accentSecondary)
	countBg.CornerRadius = 8

	countLabel := canvas.NewText("", badgeTextColor)
	countLabel.TextSize = 9
	countLabel.TextStyle = fyne.TextStyle{Bold: true}
	countLabel.Alignment = fyne.TextAlignCenter

	return &historySessionItemRenderer{
		item:       h,
		background: background,
		icon:       icon,
		idLabel:    idLabel,
		metaLabel:  metaLabel,
		countBg:    countBg,
		countLabel: countLabel,
	}
}

type historySessionItemRenderer struct {
	item       *HistorySessionItem
	background *canvas.Rectangle
	icon       *canvas.Text
	idLabel    *canvas.Text
	metaLabel  *canvas.Text
	countBg    *canvas.Rectangle
	countLabel *canvas.Text
}

func (r *historySessionItemRenderer) Layout(size fyne.Size) {
	r.background.Resize(size)
	r.background.Move(fyne.NewPos(0, 0))

	padding := float32(10)
	iconSize := float32(24)

	r.icon.Move(fyne.NewPos(padding, (size.Height-iconSize)/2))
	r.icon.Resize(fyne.NewSize(iconSize, iconSize))

	textX := padding + iconSize + 8

	// Count badge on right
	badgeW := float32(36)
	badgeH := float32(18)
	badgeX := size.Width - badgeW - padding
	badgeY := (size.Height - badgeH) / 2

	r.countBg.Move(fyne.NewPos(badgeX, badgeY))
	r.countBg.Resize(fyne.NewSize(badgeW, badgeH))
	r.countLabel.Move(fyne.NewPos(badgeX, badgeY+2))
	r.countLabel.Resize(fyne.NewSize(badgeW, badgeH-2))

	textW := badgeX - textX - 4

	r.idLabel.Move(fyne.NewPos(textX, padding))
	r.idLabel.Resize(fyne.NewSize(textW, 16))

	r.metaLabel.Move(fyne.NewPos(textX, padding+18))
	r.metaLabel.Resize(fyne.NewSize(textW, 14))
}

func (r *historySessionItemRenderer) MinSize() fyne.Size {
	return fyne.NewSize(180, 50)
}

func (r *historySessionItemRenderer) Refresh() {
	displayName := r.item.name
	if displayName == "" {
		displayName = r.item.sessionID
		if len(displayName) > 14 {
			displayName = displayName[:14] + "…"
		}
	} else if len(displayName) > 18 {
		displayName = displayName[:18] + "…"
	}
	r.idLabel.Text = displayName

	if r.item.isActive {
		r.background.FillColor = sessionActiveBg
	} else {
		r.background.FillColor = color.Transparent
	}

	if !r.item.lastMessage.IsZero() {
		r.metaLabel.Text = r.item.lastMessage.Format("Jan 2, 15:04")
	} else {
		r.metaLabel.Text = "No messages"
	}

	if r.item.messageCount > 0 {
		r.countLabel.Text = fmt.Sprintf("%d", r.item.messageCount)
		r.countBg.FillColor = accentSecondary
	} else {
		r.countLabel.Text = "0"
		r.countBg.FillColor = offlineDotColor
	}

	r.background.Refresh()
	r.icon.Refresh()
	r.idLabel.Refresh()
	r.metaLabel.Refresh()
	r.countBg.Refresh()
	r.countLabel.Refresh()
}

func (r *historySessionItemRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.icon, r.idLabel, r.metaLabel, r.countBg, r.countLabel}
}

func (r *historySessionItemRenderer) Destroy() {}
