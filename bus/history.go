package main

import (
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune"
)

// HistoryEntry represents a single chat history entry for display
type HistoryEntry struct {
	Timestamp time.Time
	Sender    string
	Message   string
	IsLocal   bool
}

// SessionInfo holds metadata about a session for display
type SessionInfo struct {
	ID           string
	MessageCount int
	FirstMessage time.Time
	LastMessage  time.Time
}

// HistoryViewer provides functionality to browse and display chat history
type HistoryViewer struct {
	window  fyne.Window
	parent  fyne.Window
	app     fyne.App
	storage *kamune.Storage
	entries []HistoryEntry
	list    *widget.List
	dbPath  string
}

// NewHistoryViewer creates a new history viewer
func NewHistoryViewer(app fyne.App, parent fyne.Window) *HistoryViewer {
	return &HistoryViewer{
		app:     app,
		parent:  parent,
		entries: make([]HistoryEntry, 0),
	}
}

// ShowHistoryDialog displays a dialog to select database and session for viewing history
func (h *HistoryViewer) ShowHistoryDialog() {
	dbEntry := widget.NewEntry()
	dbEntry.SetPlaceHolder("Path to database file")
	dbEntry.SetText(getDefaultDBDir())

	// Session selection - will be populated when database is loaded
	sessionSelect := widget.NewSelect([]string{}, nil)
	sessionSelect.PlaceHolder = "Load database first..."
	sessionSelect.Disable()

	var sessions []SessionInfo
	var selectedSessionID string

	// Load sessions button
	loadSessionsBtn := widget.NewButtonWithIcon("Load Sessions", theme.FolderOpenIcon(), func() {
		loadedSessions, err := h.ListSessionsWithInfo(dbEntry.Text)
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to load sessions: %w", err), h.parent)
			return
		}

		if len(loadedSessions) == 0 {
			dialog.ShowInformation("No Sessions", "No chat sessions found in this database.", h.parent)
			sessionSelect.SetOptions([]string{})
			sessionSelect.Disable()
			return
		}

		sessions = loadedSessions
		options := make([]string, len(sessions))
		for i, s := range sessions {
			// Format: truncated ID + message count + last activity
			displayID := s.ID
			if len(displayID) > 20 {
				displayID = displayID[:20] + "..."
			}
			options[i] = fmt.Sprintf("%s (%d msgs)", displayID, s.MessageCount)
		}
		sessionSelect.SetOptions(options)
		sessionSelect.Enable()
		if len(options) > 0 {
			sessionSelect.SetSelectedIndex(0)
		}
	})

	// Session info label
	infoLabel := widget.NewLabel("")
	infoLabel.Wrapping = fyne.TextWrapWord
	infoLabel.Importance = widget.LowImportance

	// Update info when selection changes
	sessionSelect.OnChanged = func(s string) {
		for i, opt := range sessionSelect.Options {
			if opt == s && i < len(sessions) {
				selectedSessionID = sessions[i].ID
				session := sessions[i]
				if !session.FirstMessage.IsZero() {
					infoLabel.SetText(fmt.Sprintf(
						"Full ID: %s\nFirst message: %s\nLast message: %s",
						session.ID,
						session.FirstMessage.Format("2006-01-02 15:04:05"),
						session.LastMessage.Format("2006-01-02 15:04:05"),
					))
				} else {
					infoLabel.SetText(fmt.Sprintf("Full ID: %s", session.ID))
				}
				break
			}
		}
	}

	// Copy session ID button
	copyIDBtn := widget.NewButtonWithIcon("Copy Session ID", theme.ContentCopyIcon(), func() {
		if selectedSessionID != "" {
			h.app.Clipboard().SetContent(selectedSessionID)
			dialog.ShowInformation("Copied", "Session ID copied to clipboard", h.parent)
		}
	})

	// Manual entry option
	manualEntry := widget.NewEntry()
	manualEntry.SetPlaceHolder("Or enter session ID manually...")

	// Form layout
	dbRow := container.NewBorder(nil, nil, nil, loadSessionsBtn, dbEntry)

	content := container.NewVBox(
		widget.NewLabel("Database Path:"),
		dbRow,
		widget.NewSeparator(),
		widget.NewLabel("Select Session:"),
		sessionSelect,
		copyIDBtn,
		widget.NewSeparator(),
		infoLabel,
		widget.NewSeparator(),
		widget.NewLabel("Manual Entry (optional):"),
		manualEntry,
	)

	d := dialog.NewCustomConfirm("View Chat History", "View History", "Cancel", content, func(confirmed bool) {
		if !confirmed {
			return
		}

		// Prefer manual entry if provided, otherwise use selected
		sessionID := manualEntry.Text
		if sessionID == "" {
			sessionID = selectedSessionID
		}

		if sessionID == "" {
			dialog.ShowError(fmt.Errorf("please select or enter a session ID"), h.parent)
			return
		}

		h.loadAndShowHistory(dbEntry.Text, sessionID)
	}, h.parent)
	d.Resize(fyne.NewSize(500, 400))
	d.Show()
}

// ListSessionsWithInfo returns a list of sessions with metadata from a database
func (h *HistoryViewer) ListSessionsWithInfo(dbPath string) ([]SessionInfo, error) {
	// Open storage to get session list
	storage, err := kamune.OpenStorage(
		kamune.StorageWithDBPath(dbPath),
		kamune.StorageWithNoPassphrase(),
	)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer func() {
		_ = storage.Close()
	}()

	// Use kamune's ListSessions method
	sessionIDs, err := storage.ListSessions()
	if err != nil {
		return nil, fmt.Errorf("listing sessions: %w", err)
	}

	if len(sessionIDs) == 0 {
		return []SessionInfo{}, nil
	}

	sessions := make([]SessionInfo, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		info := SessionInfo{ID: id}

		// Try to get message count and timestamps
		entries, err := storage.GetChatHistory(id)
		if err == nil && len(entries) > 0 {
			info.MessageCount = len(entries)
			info.FirstMessage = entries[0].Timestamp
			info.LastMessage = entries[len(entries)-1].Timestamp
		}

		sessions = append(sessions, info)
	}

	return sessions, nil
}

// loadAndShowHistory loads history from the database and displays it in a new window
func (h *HistoryViewer) loadAndShowHistory(dbPath, sessionID string) {
	h.dbPath = dbPath

	// Open storage
	storage, err := kamune.OpenStorage(
		kamune.StorageWithDBPath(dbPath),
		kamune.StorageWithNoPassphrase(),
	)
	if err != nil {
		dialog.ShowError(fmt.Errorf("failed to open database: %w", err), h.parent)
		return
	}
	h.storage = storage

	// Load chat history
	chatEntries, err := storage.GetChatHistory(sessionID)
	if err != nil {
		if closeErr := storage.Close(); closeErr != nil {
			dialog.ShowError(fmt.Errorf("failed to close database after history load failure: %w", closeErr), h.parent)
		}
		dialog.ShowError(fmt.Errorf("failed to load history: %w", err), h.parent)
		return
	}

	if len(chatEntries) == 0 {
		if closeErr := storage.Close(); closeErr != nil {
			dialog.ShowError(fmt.Errorf("failed to close database after empty history: %w", closeErr), h.parent)
		}
		dialog.ShowInformation("No History", fmt.Sprintf("No chat entries found for session: %s", sessionID), h.parent)
		return
	}

	// Convert to display entries
	h.entries = make([]HistoryEntry, len(chatEntries))
	for i, entry := range chatEntries {
		sender := "Peer"
		isLocal := false
		if entry.Sender == kamune.SenderLocal {
			sender = "You"
			isLocal = true
		}
		h.entries[i] = HistoryEntry{
			Timestamp: entry.Timestamp,
			Sender:    sender,
			Message:   string(entry.Data),
			IsLocal:   isLocal,
		}
	}

	// Create and show the history window
	h.showHistoryWindow(sessionID)
}

// showHistoryWindow creates and displays the history viewing window
func (h *HistoryViewer) showHistoryWindow(sessionID string) {
	h.window = h.app.NewWindow(fmt.Sprintf("Chat History - %s", truncateID(sessionID, 20)))
	h.window.Resize(fyne.NewSize(600, 500))

	// Header with session info and copy button
	headerLabel := widget.NewLabelWithStyle(
		fmt.Sprintf("Session: %s", truncateID(sessionID, 40)),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)

	copyIDBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		h.app.Clipboard().SetContent(sessionID)
		dialog.ShowInformation("Copied", "Session ID copied to clipboard", h.window)
	})
	copyIDBtn.Importance = widget.LowImportance

	countLabel := widget.NewLabel(fmt.Sprintf("%d messages", len(h.entries)))
	countLabel.Alignment = fyne.TextAlignTrailing

	header := container.NewBorder(nil, nil, container.NewHBox(headerLabel, copyIDBtn), countLabel)

	// Create message list
	h.list = widget.NewList(
		func() int {
			return len(h.entries)
		},
		func() fyne.CanvasObject {
			return NewHistoryMessageItem()
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < len(h.entries) {
				item := obj.(*HistoryMessageItem)
				entry := h.entries[id]
				item.Update(entry.Timestamp, entry.Sender, entry.Message, entry.IsLocal)
			}
		},
	)

	// Export button
	exportBtn := widget.NewButtonWithIcon("Export to Text", theme.DocumentSaveIcon(), func() {
		h.exportHistory(sessionID)
	})

	// Close button
	closeBtn := widget.NewButton("Close", func() {
		if h.storage != nil {
			if err := h.storage.Close(); err != nil {
				dialog.ShowError(fmt.Errorf("failed to close database: %w", err), h.window)
			}
		}
		h.window.Close()
	})

	buttonBar := container.NewHBox(exportBtn, widget.NewSeparator(), closeBtn)

	// Layout
	content := container.NewBorder(
		container.NewVBox(header, widget.NewSeparator()),
		container.NewPadded(buttonBar),
		nil,
		nil,
		h.list,
	)

	h.window.SetContent(container.NewPadded(content))
	h.window.SetOnClosed(func() {
		if h.storage != nil {
			if err := h.storage.Close(); err != nil {
				dialog.ShowError(fmt.Errorf("failed to close database: %w", err), h.window)
			}
		}
	})
	h.window.Show()
}

// exportHistory exports the chat history to a text format
func (h *HistoryViewer) exportHistory(sessionID string) {
	// Build export text
	var exportText string
	exportText = fmt.Sprintf("Chat History Export\nSession: %s\nExported: %s\n\n",
		sessionID, time.Now().Format(time.RFC3339))
	exportText += "----------------------------------------\n\n"

	for _, entry := range h.entries {
		exportText += fmt.Sprintf("[%s] %s:\n%s\n\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Sender,
			entry.Message,
		)
	}

	// Show in a dialog with copy functionality
	textEntry := widget.NewMultiLineEntry()
	textEntry.SetText(exportText)
	textEntry.SetMinRowsVisible(20)

	copyBtn := widget.NewButtonWithIcon("Copy to Clipboard", theme.ContentCopyIcon(), func() {
		h.app.Clipboard().SetContent(exportText)
		dialog.ShowInformation("Copied", "History copied to clipboard", h.window)
	})

	content := container.NewBorder(nil, copyBtn, nil, nil, textEntry)

	d := dialog.NewCustom("Export History", "Close", container.NewPadded(content), h.window)
	d.Resize(fyne.NewSize(500, 400))
	d.Show()
}

// HistoryMessageItem is a widget for displaying a single history message
type HistoryMessageItem struct {
	widget.BaseWidget
	timestamp time.Time
	sender    string
	message   string
	isLocal   bool
}

// NewHistoryMessageItem creates a new history message item
func NewHistoryMessageItem() *HistoryMessageItem {
	h := &HistoryMessageItem{}
	h.ExtendBaseWidget(h)
	return h
}

// Update updates the history message item content
func (h *HistoryMessageItem) Update(timestamp time.Time, sender, message string, isLocal bool) {
	h.timestamp = timestamp
	h.sender = sender
	h.message = message
	h.isLocal = isLocal
	h.Refresh()
}

// CreateRenderer implements fyne.Widget
func (h *HistoryMessageItem) CreateRenderer() fyne.WidgetRenderer {
	timestampLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{})
	timestampLabel.Importance = widget.LowImportance

	senderLabel := widget.NewLabelWithStyle("", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	messageLabel := widget.NewLabel("")
	messageLabel.Wrapping = fyne.TextWrapWord

	return &historyMessageRenderer{
		item:           h,
		timestampLabel: timestampLabel,
		senderLabel:    senderLabel,
		messageLabel:   messageLabel,
	}
}

type historyMessageRenderer struct {
	item           *HistoryMessageItem
	timestampLabel *widget.Label
	senderLabel    *widget.Label
	messageLabel   *widget.Label
}

func (r *historyMessageRenderer) Layout(size fyne.Size) {
	padding := float32(8)
	headerHeight := float32(20)

	// Timestamp and sender on same line
	r.timestampLabel.Move(fyne.NewPos(padding, padding))
	r.timestampLabel.Resize(fyne.NewSize(140, headerHeight))

	r.senderLabel.Move(fyne.NewPos(150, padding))
	r.senderLabel.Resize(fyne.NewSize(size.Width-150-padding, headerHeight))

	// Message below
	msgTop := padding + headerHeight + 4
	r.messageLabel.Move(fyne.NewPos(padding, msgTop))
	r.messageLabel.Resize(fyne.NewSize(size.Width-padding*2, size.Height-msgTop-padding))
}

func (r *historyMessageRenderer) MinSize() fyne.Size {
	msgSize := r.messageLabel.MinSize()
	return fyne.NewSize(300, fyne.Max(msgSize.Height+50, 60))
}

func (r *historyMessageRenderer) Refresh() {
	if !r.item.timestamp.IsZero() {
		r.timestampLabel.SetText(r.item.timestamp.Format("2006-01-02 15:04:05"))
	}

	r.senderLabel.SetText(r.item.sender)
	if r.item.isLocal {
		r.senderLabel.Importance = widget.HighImportance
	} else {
		r.senderLabel.Importance = widget.WarningImportance
	}

	r.messageLabel.SetText(r.item.message)

	r.timestampLabel.Refresh()
	r.senderLabel.Refresh()
	r.messageLabel.Refresh()
}

func (r *historyMessageRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.timestampLabel, r.senderLabel, r.messageLabel}
}

func (r *historyMessageRenderer) Destroy() {}

// truncateID truncates a session ID for display
func truncateID(id string, maxLen int) string {
	if len(id) <= maxLen {
		return id
	}
	return id[:maxLen] + "..."
}

// ListSessions shows available sessions in a database (deprecated - use ListSessionsWithInfo)
func (h *HistoryViewer) ListSessions(dbPath string) ([]string, error) {
	sessions, err := h.ListSessionsWithInfo(dbPath)
	if err != nil {
		return nil, err
	}

	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = s.ID
	}
	return ids, nil
}
