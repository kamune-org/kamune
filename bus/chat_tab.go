package main

import (
	"fmt"
	"image/color"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/kamune-org/kamune/bus/logger"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ChatTabKind int

const (
	ChatTabLive    ChatTabKind = iota // connected session
	ChatTabHistory                    // read-only history session
)

// ChatTab holds the per-tab state: its own message list widget, overlays,
// and a reference to the underlying session or history session.
type ChatTab struct {
	ID   string      // session ID (used as stable key)
	Kind ChatTabKind // live vs history

	// Exactly one of these is non-nil.
	Session     *Session
	HistSession *HistorySession

	// Per-tab UI widgets (each tab owns its own list so scrolling is
	// independent).
	messageList  *widget.List
	emptyOverlay fyne.CanvasObject
	histBanner   fyne.CanvasObject
	content      fyne.CanvasObject // fully assembled CanvasObject
}

// ChatTabManager manages the set of open tabs and the DocTabs widget.
type ChatTabManager struct {
	app  *ChatApp
	tabs []*ChatTab
	mu   sync.RWMutex

	// The Fyne DocTabs container that lives in the UI.
	docTabs *container.DocTabs
}

// NewChatTabManager creates a new tab manager bound to the given app.
func NewChatTabManager(app *ChatApp) *ChatTabManager {
	m := &ChatTabManager{
		app:  app,
		tabs: make([]*ChatTab, 0),
	}

	m.docTabs = container.NewDocTabs()
	m.docTabs.CloseIntercept = m.onTabClose
	m.docTabs.OnSelected = m.onTabSelected
	m.docTabs.SetTabLocation(container.TabLocationTop)

	return m
}

// Widget returns the underlying DocTabs widget for embedding in the layout.
func (m *ChatTabManager) Widget() *container.DocTabs {
	return m.docTabs
}

// ---------------------------------------------------------------------------
// Open / select / close
// ---------------------------------------------------------------------------

// OpenSession opens a tab for a live session, or selects it if already open.
func (m *ChatTabManager) OpenSession(session *Session) {
	if session == nil {
		return
	}

	m.mu.RLock()
	for i, t := range m.tabs {
		if t.ID == session.ID && t.Kind == ChatTabLive {
			m.mu.RUnlock()
			m.selectIndex(i)
			return
		}
	}
	m.mu.RUnlock()

	tab := m.newLiveTab(session)

	m.mu.Lock()
	m.tabs = append(m.tabs, tab)
	m.mu.Unlock()

	m.app.runOnMain(func() {
		m.docTabs.Append(m.makeDocTabItem(tab))
		m.selectIndex(len(m.docTabs.Items) - 1)
	})
}

// OpenHistory opens a tab for a history session, or selects it if already open.
func (m *ChatTabManager) OpenHistory(hs *HistorySession) {
	if hs == nil {
		return
	}

	m.mu.RLock()
	for i, t := range m.tabs {
		if t.ID == hs.ID && t.Kind == ChatTabHistory {
			m.mu.RUnlock()
			m.selectIndex(i)
			return
		}
	}
	m.mu.RUnlock()

	tab := m.newHistoryTab(hs)

	m.mu.Lock()
	m.tabs = append(m.tabs, tab)
	m.mu.Unlock()

	m.app.runOnMain(func() {
		m.docTabs.Append(m.makeDocTabItem(tab))
		m.selectIndex(len(m.docTabs.Items) - 1)
	})
}

// CloseTab removes a tab by session ID (any kind). The underlying connection
// is NOT closed — use disconnectActiveSession for that.
func (m *ChatTabManager) CloseTab(sessionID string) {
	m.mu.Lock()
	idx := -1
	for i, t := range m.tabs {
		if t.ID == sessionID {
			idx = i
			break
		}
	}
	if idx < 0 {
		m.mu.Unlock()
		return
	}
	m.tabs = append(m.tabs[:idx], m.tabs[idx+1:]...)
	m.mu.Unlock()

	m.app.runOnMain(func() {
		if idx < len(m.docTabs.Items) {
			m.docTabs.Remove(m.docTabs.Items[idx])
		}
	})

	// If we just removed the active view, clear active pointers.
	m.syncActiveToSelected()
}

// CloseActiveTab closes whatever tab is currently selected.
func (m *ChatTabManager) CloseActiveTab() {
	ct := m.SelectedTab()
	if ct == nil {
		return
	}
	m.CloseTab(ct.ID)
}

// CloseAllTabs closes every open tab. Connections are NOT disconnected.
func (m *ChatTabManager) CloseAllTabs() {
	m.mu.Lock()
	tabs := make([]*ChatTab, len(m.tabs))
	copy(tabs, m.tabs)
	m.tabs = m.tabs[:0]
	m.mu.Unlock()

	m.app.runOnMain(func() {
		for len(m.docTabs.Items) > 0 {
			m.docTabs.Remove(m.docTabs.Items[0])
		}
	})

	for _, ct := range tabs {
		logger.Infof("Closed tab for session %s", ct.ID)
	}

	m.syncActiveToSelected()
	m.app.updateStatus()

	m.app.runOnMain(func() {
		m.app.sessionList.Refresh()
		if m.app.historyList != nil {
			m.app.historyList.Refresh()
		}
	})
}

// CloseOtherTabs closes every tab except the currently selected one.
func (m *ChatTabManager) CloseOtherTabs() {
	sel := m.SelectedTab()
	if sel == nil {
		return
	}

	m.mu.Lock()
	var keep []*ChatTab
	var closing []*ChatTab
	for _, t := range m.tabs {
		if t.ID == sel.ID {
			keep = append(keep, t)
		} else {
			closing = append(closing, t)
		}
	}
	m.tabs = keep
	m.mu.Unlock()

	m.app.runOnMain(func() {
		// Remove all DocTabs items that are not the selected one.
		selected := m.docTabs.Selected()
		var toRemove []*container.TabItem
		for _, item := range m.docTabs.Items {
			if item != selected {
				toRemove = append(toRemove, item)
			}
		}
		for _, item := range toRemove {
			m.docTabs.Remove(item)
		}
	})

	for _, ct := range closing {
		logger.Infof("Closed tab for session %s", ct.ID)
	}

	m.syncActiveToSelected()
	m.app.updateStatus()

	m.app.runOnMain(func() {
		m.app.sessionList.Refresh()
		if m.app.historyList != nil {
			m.app.historyList.Refresh()
		}
	})
}

// CloseTabsToTheRight closes all tabs to the right of the currently selected one.
func (m *ChatTabManager) CloseTabsToTheRight() {
	sel := m.SelectedTab()
	if sel == nil {
		return
	}

	m.mu.Lock()
	selIdx := -1
	for i, t := range m.tabs {
		if t.ID == sel.ID {
			selIdx = i
			break
		}
	}
	if selIdx < 0 || selIdx >= len(m.tabs)-1 {
		// Nothing to the right.
		m.mu.Unlock()
		return
	}
	closing := make([]*ChatTab, len(m.tabs[selIdx+1:]))
	copy(closing, m.tabs[selIdx+1:])
	m.tabs = m.tabs[:selIdx+1]
	m.mu.Unlock()

	m.app.runOnMain(func() {
		// Remove DocTabs items from the end back to selIdx+1.
		for len(m.docTabs.Items) > selIdx+1 {
			m.docTabs.Remove(m.docTabs.Items[len(m.docTabs.Items)-1])
		}
	})

	for _, ct := range closing {
		logger.Infof("Closed tab for session %s", ct.ID)
	}

	m.syncActiveToSelected()
	m.app.updateStatus()

	m.app.runOnMain(func() {
		m.app.sessionList.Refresh()
		if m.app.historyList != nil {
			m.app.historyList.Refresh()
		}
	})
}

// SelectedTab returns the ChatTab corresponding to the currently selected
// DocTabs item, or nil.
func (m *ChatTabManager) SelectedTab() *ChatTab {
	sel := m.docTabs.Selected()
	if sel == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	idx := m.docTabIndex(sel)
	if idx < 0 || idx >= len(m.tabs) {
		return nil
	}
	return m.tabs[idx]
}

// TabForSession returns the ChatTab for the given session ID, or nil.
func (m *ChatTabManager) TabForSession(sessionID string) *ChatTab {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tabs {
		if t.ID == sessionID {
			return t
		}
	}
	return nil
}

// RefreshTab refreshes the message list of the tab that owns the given
// session ID. If the tab is not open, this is a no-op.
func (m *ChatTabManager) RefreshTab(sessionID string) {
	ct := m.TabForSession(sessionID)
	if ct == nil {
		return
	}
	m.app.runOnMain(func() {
		m.refreshTabContent(ct)
	})
}

// RefreshActiveTab refreshes the currently selected tab.
func (m *ChatTabManager) RefreshActiveTab() {
	ct := m.SelectedTab()
	if ct == nil {
		return
	}
	m.app.runOnMain(func() {
		m.refreshTabContent(ct)
	})
}

// RefreshAllTabs refreshes message lists of every open tab (e.g. after
// a history reload that may have changed message counts).
func (m *ChatTabManager) RefreshAllTabs() {
	m.mu.RLock()
	tabs := make([]*ChatTab, len(m.tabs))
	copy(tabs, m.tabs)
	m.mu.RUnlock()

	m.app.runOnMain(func() {
		for i, ct := range tabs {
			m.refreshTabContent(ct)
			// Update the doc tab label so renames are reflected.
			if i < len(m.docTabs.Items) {
				m.docTabs.Items[i].Text = m.tabLabel(ct)
			}
		}
		m.docTabs.Refresh()
	})
}

// TabCount returns the number of open tabs.
func (m *ChatTabManager) TabCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tabs)
}

// HasTab returns true if a tab with the given session ID is open.
func (m *ChatTabManager) HasTab(sessionID string) bool {
	return m.TabForSession(sessionID) != nil
}

// RemoveSessionTab removes the tab for a live session that was disconnected
// or whose connection was lost.
func (m *ChatTabManager) RemoveSessionTab(sessionID string) {
	m.CloseTab(sessionID)
}

// ---------------------------------------------------------------------------
// Tab construction
// ---------------------------------------------------------------------------

func (m *ChatTabManager) newLiveTab(session *Session) *ChatTab {
	ct := &ChatTab{
		ID:      session.ID,
		Kind:    ChatTabLive,
		Session: session,
	}
	m.buildTabUI(ct)
	return ct
}

func (m *ChatTabManager) newHistoryTab(hs *HistorySession) *ChatTab {
	ct := &ChatTab{
		ID:          hs.ID,
		Kind:        ChatTabHistory,
		HistSession: hs,
	}
	m.buildTabUI(ct)
	return ct
}

// buildTabUI populates the tab's message list, overlays, and assembled
// content container.
func (m *ChatTabManager) buildTabUI(ct *ChatTab) {
	ct.messageList = widget.NewList(
		func() int {
			msgs := m.tabMessages(ct)
			if msgs == nil {
				return 0
			}
			return len(msgs)
		},
		func() fyne.CanvasObject {
			return NewStyledMessageBubble("", time.Time{}, false)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			msgs := m.tabMessages(ct)
			if msgs != nil && id < len(msgs) {
				msg := msgs[id]
				bubble := obj.(*StyledMessageBubble)
				bubble.Update(msg.Text, msg.Timestamp, msg.IsLocal)
				bubble.SetOnCopy(func(text string) {
					m.app.app.Clipboard().SetContent(text)
				})
			}
		},
	)

	// Empty overlay
	emptyIcon := canvas.NewText("📭", textMuted)
	emptyIcon.TextSize = 32
	emptyIcon.Alignment = fyne.TextAlignCenter
	emptyLabel := widget.NewLabelWithStyle("No messages yet", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	emptyLabel.Importance = widget.LowImportance
	emptySub := widget.NewLabelWithStyle("Send the first message to start the conversation.", fyne.TextAlignCenter, fyne.TextStyle{})
	emptySub.Importance = widget.LowImportance
	ct.emptyOverlay = container.NewCenter(container.NewVBox(container.NewCenter(emptyIcon), emptyLabel, emptySub))
	ct.emptyOverlay.Hide()

	// History banner
	histBannerBg := canvas.NewRectangle(color.RGBA{R: 0x2d, G: 0x1f, B: 0x05, A: 0xcc})
	histBannerBg.CornerRadius = 6
	histBannerLabel := widget.NewLabelWithStyle("📖  Viewing session history (read-only)", fyne.TextAlignCenter, fyne.TextStyle{})
	histBannerLabel.Importance = widget.WarningImportance
	ct.histBanner = container.NewStack(histBannerBg, container.NewPadded(histBannerLabel))
	if ct.Kind != ChatTabHistory {
		ct.histBanner.Hide()
	}

	messageArea := container.NewStack(ct.emptyOverlay, ct.messageList)
	ct.content = container.NewBorder(ct.histBanner, nil, nil, nil, messageArea)
}

// ---------------------------------------------------------------------------
// DocTabs helpers
// ---------------------------------------------------------------------------

func (m *ChatTabManager) makeDocTabItem(ct *ChatTab) *container.TabItem {
	label := m.tabLabel(ct)
	return container.NewTabItem(label, ct.content)
}

func (m *ChatTabManager) tabLabel(ct *ChatTab) string {
	prefix := "🔒 "
	if ct.Kind == ChatTabHistory {
		prefix = "📖 "
	}

	// Use display name as label when available.
	if ct.Kind == ChatTabLive && ct.Session != nil && ct.Session.PeerName != "" {
		name := ct.Session.PeerName
		if len(name) > 14 {
			name = name[:14] + "…"
		}
		return fmt.Sprintf("%s%s", prefix, name)
	}
	if ct.Kind == ChatTabHistory && ct.HistSession != nil && ct.HistSession.Name != "" {
		name := ct.HistSession.Name
		if len(name) > 14 {
			name = name[:14] + "…"
		}
		return fmt.Sprintf("%s%s", prefix, name)
	}

	id := ct.ID
	if len(id) > 10 {
		id = id[:10] + "…"
	}
	return fmt.Sprintf("%s%s", prefix, id)
}

// selectIndex safely selects a DocTabs item by index.
func (m *ChatTabManager) selectIndex(idx int) {
	m.app.runOnMain(func() {
		if idx >= 0 && idx < len(m.docTabs.Items) {
			m.docTabs.Select(m.docTabs.Items[idx])
		}
	})
}

// docTabIndex returns the index of the given TabItem in the DocTabs, or -1.
func (m *ChatTabManager) docTabIndex(item *container.TabItem) int {
	for i, it := range m.docTabs.Items {
		if it == item {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

// onTabSelected is called by DocTabs when the user clicks a tab.
func (m *ChatTabManager) onTabSelected(item *container.TabItem) {
	m.syncActiveToSelected()
	m.app.updateStatus()

	ct := m.SelectedTab()
	if ct != nil {
		m.refreshTabContent(ct)
	}
}

// onTabClose is called by DocTabs when the user clicks the × on a tab.
func (m *ChatTabManager) onTabClose(item *container.TabItem) {
	idx := m.docTabIndex(item)
	if idx < 0 {
		return
	}

	m.mu.RLock()
	var ct *ChatTab
	if idx < len(m.tabs) {
		ct = m.tabs[idx]
	}
	m.mu.RUnlock()

	if ct == nil {
		return
	}

	// Remove from our bookkeeping
	m.mu.Lock()
	m.tabs = append(m.tabs[:idx], m.tabs[idx+1:]...)
	m.mu.Unlock()

	// Let DocTabs actually remove it
	m.docTabs.Remove(item)

	logger.Infof("Closed tab for session %s", ct.ID)

	m.syncActiveToSelected()
	m.app.updateStatus()

	// Update sidebar highlights
	m.app.runOnMain(func() {
		m.app.sessionList.Refresh()
		if m.app.historyList != nil {
			m.app.historyList.Refresh()
		}
	})
}

// syncActiveToSelected updates the app's activeSession / activeHistSession
// pointers to match the currently selected tab.
func (m *ChatTabManager) syncActiveToSelected() {
	ct := m.SelectedTab()

	m.app.mu.Lock()
	defer m.app.mu.Unlock()

	if ct == nil {
		m.app.activeSession = nil
		m.app.activeHistSession = nil
		return
	}

	switch ct.Kind {
	case ChatTabLive:
		m.app.activeSession = ct.Session
		m.app.activeHistSession = nil
	case ChatTabHistory:
		m.app.activeSession = nil
		m.app.activeHistSession = ct.HistSession
	}
}

// ---------------------------------------------------------------------------
// Content refresh
// ---------------------------------------------------------------------------

// tabMessages returns the messages for a given tab.
func (m *ChatTabManager) tabMessages(ct *ChatTab) []ChatMessage {
	m.app.mu.RLock()
	defer m.app.mu.RUnlock()

	switch ct.Kind {
	case ChatTabLive:
		if ct.Session != nil {
			return ct.Session.Messages
		}
	case ChatTabHistory:
		if ct.HistSession != nil && ct.HistSession.Loaded {
			return ct.HistSession.Messages
		}
	}
	return nil
}

// refreshTabContent refreshes the message list and overlays of a single tab.
// Must be called on the main thread or wrapped in runOnMain.
func (m *ChatTabManager) refreshTabContent(ct *ChatTab) {
	if ct.messageList == nil {
		return
	}

	ct.messageList.Refresh()

	msgs := m.tabMessages(ct)
	msgCount := len(msgs)

	if msgCount == 0 {
		ct.emptyOverlay.Show()
	} else {
		ct.emptyOverlay.Hide()
	}

	if ct.Kind == ChatTabHistory {
		ct.histBanner.Show()
	} else {
		ct.histBanner.Hide()
	}

	if msgCount > 0 {
		ct.messageList.ScrollToBottom()
	}
}

// ---------------------------------------------------------------------------
// Welcome overlay (shown when no tabs are open)
// ---------------------------------------------------------------------------

// BuildWelcomeOverlay creates the welcome screen shown when no chat tabs exist.
func BuildWelcomeOverlay() fyne.CanvasObject {
	welcomeIcon := canvas.NewText("💬", textPrimary)
	welcomeIcon.TextSize = 42
	welcomeIcon.Alignment = fyne.TextAlignCenter

	welcomeTitle := widget.NewLabelWithStyle(
		"Welcome to Bus",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)

	welcomeSubtitle := widget.NewLabelWithStyle(
		"Secure messaging powered by Kamune.\nStart a server or connect to a peer to begin.",
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	welcomeSubtitle.Wrapping = fyne.TextWrapWord
	welcomeSubtitle.Importance = widget.LowImportance

	shortcutsInfo := widget.NewLabelWithStyle(
		"Ctrl+S  Start server   •   Ctrl+N  Connect\nCtrl+L  Toggle logs   •   Ctrl+H  View history",
		fyne.TextAlignCenter,
		fyne.TextStyle{Monospace: true},
	)
	shortcutsInfo.Importance = widget.LowImportance
	shortcutsInfo.Wrapping = fyne.TextWrapWord

	return container.NewCenter(
		container.NewVBox(
			container.NewCenter(welcomeIcon),
			layout.NewSpacer(),
			welcomeTitle,
			welcomeSubtitle,
			layout.NewSpacer(),
			shortcutsInfo,
		),
	)
}

// ---------------------------------------------------------------------------
// Session info bar for tab-based UI
// ---------------------------------------------------------------------------

// BuildTabInfoBar creates an info bar that updates based on the currently
// selected tab. It replaces the old polling-based buildSessionInfoBar.
func (m *ChatTabManager) BuildTabInfoBar() fyne.CanvasObject {
	// ── Left: type badge + session ID ──
	typeBadgeBg := canvas.NewRectangle(accentPrimary)
	typeBadgeBg.CornerRadius = 4

	typeBadgeLabel := canvas.NewText("", badgeTextColor)
	typeBadgeLabel.TextSize = 10
	typeBadgeLabel.TextStyle = fyne.TextStyle{Bold: true}
	typeBadgeLabel.Alignment = fyne.TextAlignCenter

	typeBadge := container.NewStack(typeBadgeBg, container.NewCenter(typeBadgeLabel))

	sessionLabel := canvas.NewText("", textPrimary)
	sessionLabel.TextStyle = fyne.TextStyle{Bold: true}
	sessionLabel.TextSize = 13

	leftGroup := container.NewHBox(typeBadge, sessionLabel)

	// ── Center: message count + last activity ──
	msgCountIcon := canvas.NewText("💬", textMuted)
	msgCountIcon.TextSize = 11
	msgCountLabel := canvas.NewText("", textSecondary)
	msgCountLabel.TextSize = 11

	activityIcon := canvas.NewText("🕐", textMuted)
	activityIcon.TextSize = 11
	activityLabel := canvas.NewText("", textSecondary)
	activityLabel.TextSize = 11

	metaGroup := container.NewHBox(
		msgCountIcon, msgCountLabel,
		widget.NewSeparator(),
		activityIcon, activityLabel,
	)

	// ── Right: action buttons ──
	copyIDBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		ct := m.SelectedTab()
		if ct != nil {
			m.app.app.Clipboard().SetContent(ct.ID)
			m.app.sendNotification("Copied", "Session ID copied to clipboard")
		}
	})
	copyIDBtn.Importance = widget.LowImportance
	copyIDBtn.Hide()

	infoBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		m.app.showSessionInfo()
	})
	infoBtn.Importance = widget.LowImportance
	infoBtn.Hide()

	renameBtn := widget.NewButtonWithIcon("", theme.DocumentCreateIcon(), func() {
		ct := m.SelectedTab()
		if ct == nil {
			return
		}
		if ct.Kind == ChatTabLive && ct.Session != nil {
			m.app.showRenameSessionDialog(ct.Session)
		} else if ct.Kind == ChatTabHistory && ct.HistSession != nil {
			m.app.showRenameHistorySessionDialog(ct.HistSession)
		}
	})
	renameBtn.Importance = widget.LowImportance
	renameBtn.Hide()

	endSessionBtn := widget.NewButtonWithIcon("Disconnect", theme.CancelIcon(), func() {
		m.app.disconnectActiveSession()
	})
	endSessionBtn.Importance = widget.DangerImportance
	endSessionBtn.Hide()

	deleteHistBtn := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() {
		m.app.mu.RLock()
		hs := m.app.activeHistSession
		m.app.mu.RUnlock()
		if hs != nil {
			m.app.deleteHistorySession(hs)
		}
	})
	deleteHistBtn.Importance = widget.DangerImportance
	deleteHistBtn.Hide()

	rightButtons := container.NewHBox(copyIDBtn, renameBtn, infoBtn, endSessionBtn, deleteHistBtn)

	// ── Assemble bar ──
	bar := container.NewBorder(nil, nil, leftGroup, rightButtons, container.NewCenter(metaGroup))

	// Wrap everything in a container that we can show/hide as a unit.
	barWrapper := container.NewVBox(container.NewPadded(bar), widget.NewSeparator())
	barWrapper.Hide()

	// Poll for changes from the selected tab.
	go func() {
		for {
			select {
			case <-m.app.stopChan:
				return
			case <-time.After(200 * time.Millisecond):
			}

			ct := m.SelectedTab()

			var dispID, dispName, modeStr string
			var count int
			var activity time.Time

			if ct != nil {
				dispID = ct.ID
				switch ct.Kind {
				case ChatTabLive:
					modeStr = "live"
					if ct.Session != nil {
						m.app.mu.RLock()
						count = len(ct.Session.Messages)
						activity = ct.Session.LastActivity
						dispName = ct.Session.PeerName
						m.app.mu.RUnlock()
					}
				case ChatTabHistory:
					modeStr = "history"
					if ct.HistSession != nil {
						m.app.mu.RLock()
						count = ct.HistSession.MessageCount
						activity = ct.HistSession.LastMessage
						dispName = ct.HistSession.Name
						m.app.mu.RUnlock()
					}
				}
			}

			m.app.runOnMain(func() {
				if dispID == "" {
					barWrapper.Hide()
					return
				}

				barWrapper.Show()

				// Type badge
				switch modeStr {
				case "live":
					typeBadgeLabel.Text = "LIVE"
					typeBadgeBg.FillColor = statusConnectedColor
				case "history":
					typeBadgeLabel.Text = "HISTORY"
					typeBadgeBg.FillColor = accentSecondary
				}
				typeBadgeBg.Refresh()
				typeBadgeLabel.Refresh()

				// Session label: prefer display name over raw ID
				label := dispName
				if label == "" {
					label = dispID
					if len(label) > 16 {
						label = label[:16] + "…"
					}
				} else if len(label) > 20 {
					label = label[:20] + "…"
				}
				sessionLabel.Text = label
				sessionLabel.Refresh()

				// Message count
				msgCountLabel.Text = fmt.Sprintf("%d messages", count)
				msgCountLabel.Refresh()

				// Last activity
				if !activity.IsZero() {
					elapsed := time.Since(activity)
					switch {
					case elapsed < time.Minute:
						activityLabel.Text = "just now"
					case elapsed < time.Hour:
						activityLabel.Text = fmt.Sprintf("%dm ago", int(elapsed.Minutes()))
					case elapsed < 24*time.Hour:
						activityLabel.Text = activity.Format("15:04")
					default:
						activityLabel.Text = activity.Format("Jan 2, 15:04")
					}
				} else {
					activityLabel.Text = "—"
				}
				activityLabel.Refresh()

				// Action buttons
				copyIDBtn.Show()
				renameBtn.Show()
				infoBtn.Show()

				if modeStr == "live" {
					endSessionBtn.Show()
					deleteHistBtn.Hide()
				} else {
					endSessionBtn.Hide()
					deleteHistBtn.Show()
				}
			})
		}
	}()

	return barWrapper
}
