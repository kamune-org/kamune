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
	dbEntry.SetText("./client.db")

	sessionEntry := widget.NewEntry()
	sessionEntry.SetPlaceHolder("Session ID")

	form := widget.NewForm(
		widget.NewFormItem("Database Path", dbEntry),
		widget.NewFormItem("Session ID", sessionEntry),
	)

	d := dialog.NewCustomConfirm("View Chat History", "Load", "Cancel", form, func(confirmed bool) {
		if confirmed && sessionEntry.Text != "" {
			h.loadAndShowHistory(dbEntry.Text, sessionEntry.Text)
		}
	}, h.parent)
	d.Resize(fyne.NewSize(450, 200))
	d.Show()
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

	// Header with session info
	headerLabel := widget.NewLabelWithStyle(
		fmt.Sprintf("Session: %s", sessionID),
		fyne.TextAlignLeading,
		fyne.TextStyle{Bold: true},
	)

	countLabel := widget.NewLabel(fmt.Sprintf("%d messages", len(h.entries)))
	countLabel.Alignment = fyne.TextAlignTrailing

	header := container.NewBorder(nil, nil, headerLabel, countLabel)

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

// ListSessions shows available sessions in a database
func (h *HistoryViewer) ListSessions(dbPath string) ([]string, error) {
	storage, err := kamune.OpenStorage(
		kamune.StorageWithDBPath(dbPath),
		kamune.StorageWithNoPassphrase(),
	)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	defer func() {
		// Best-effort cleanup: explicitly ignore close errors here (no UI/logging available in this helper).
		_ = storage.Close()
	}()

	// Note: This would require additional method in kamune storage
	// For now, we'll return an empty list as a placeholder
	// The user would need to know the session ID
	return []string{}, nil
}
