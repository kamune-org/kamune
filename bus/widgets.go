package main

import (
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune/bus/logger"
)

// Enhanced color palette for modern chat look
var (
	// Message bubble colors
	localBubbleColor = color.RGBA{R: 0x1e, G: 0x40, B: 0x8f, A: 0xcc} // Deeper blue
	peerBubbleColor  = color.RGBA{R: 0x8f, G: 0x45, B: 0x25, A: 0xcc} // Warm amber
	localTextColor   = color.White
	peerTextColor    = color.White

	// Status colors
	statusConnectedColor    = color.RGBA{R: 0x22, G: 0xc5, B: 0x5e, A: 0xff} // Green
	statusConnectingColor   = color.RGBA{R: 0xf5, G: 0xa6, B: 0x23, A: 0xff} // Amber
	statusDisconnectedColor = color.RGBA{R: 0x6b, G: 0x72, B: 0x80, A: 0xff} // Gray
	statusErrorColor        = color.RGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff} // Red

	// UI accent colors
	accentPrimary   = color.RGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0xff} // Blue
	accentSecondary = color.RGBA{R: 0x8b, G: 0x5c, B: 0xf6, A: 0xff} // Purple
	surfaceColor    = color.RGBA{R: 0x1f, G: 0x25, B: 0x37, A: 0xff} // Dark surface

	// Log level colors
	logInfoColor  = color.RGBA{R: 0x60, G: 0xa5, B: 0xfa, A: 0xff} // Light blue
	logWarnColor  = color.RGBA{R: 0xfb, G: 0xbf, B: 0x24, A: 0xff} // Yellow
	logErrorColor = color.RGBA{R: 0xf8, G: 0x71, B: 0x71, A: 0xff} // Light red
	logDebugColor = color.RGBA{R: 0x9c, G: 0xa3, B: 0xaf, A: 0xff} // Gray
)

// StyledMessageBubble is an enhanced message widget with background styling
type StyledMessageBubble struct {
	widget.BaseWidget
	text      string
	timestamp time.Time
	isLocal   bool
	onCopy    func(string) // Callback for copy action
}

// NewStyledMessageBubble creates a new styled message bubble
func NewStyledMessageBubble(text string, timestamp time.Time, isLocal bool) *StyledMessageBubble {
	m := &StyledMessageBubble{
		text:      text,
		timestamp: timestamp,
		isLocal:   isLocal,
	}
	m.ExtendBaseWidget(m)
	return m
}

// Update updates the message content
func (m *StyledMessageBubble) Update(text string, timestamp time.Time, isLocal bool) {
	m.text = text
	m.timestamp = timestamp
	m.isLocal = isLocal

	fyne.Do(func() {
		m.Refresh()
	})
}

// SetOnCopy sets the copy callback
func (m *StyledMessageBubble) SetOnCopy(fn func(string)) {
	m.onCopy = fn
}

// CreateRenderer implements fyne.Widget
func (m *StyledMessageBubble) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(localBubbleColor)
	background.CornerRadius = 12
	background.StrokeWidth = 0

	senderLabel := canvas.NewText("You", localTextColor)
	senderLabel.TextStyle = fyne.TextStyle{Bold: true}
	senderLabel.TextSize = 11

	timeLabel := canvas.NewText("", theme.Color(theme.ColorNamePlaceHolder))
	timeLabel.TextSize = 10
	timeLabel.Alignment = fyne.TextAlignTrailing

	msgLabel := widget.NewLabel(m.text)
	msgLabel.Wrapping = fyne.TextWrapWord

	return &styledBubbleRenderer{
		bubble:      m,
		background:  background,
		senderLabel: senderLabel,
		timeLabel:   timeLabel,
		msgLabel:    msgLabel,
	}
}

type styledBubbleRenderer struct {
	bubble      *StyledMessageBubble
	background  *canvas.Rectangle
	senderLabel *canvas.Text
	timeLabel   *canvas.Text
	msgLabel    *widget.Label
}

func (r *styledBubbleRenderer) Layout(size fyne.Size) {
	padding := float32(14)
	headerHeight := float32(16)

	r.background.Resize(size)
	r.background.Move(fyne.NewPos(0, 0))

	r.senderLabel.Move(fyne.NewPos(padding, padding))
	r.senderLabel.Resize(fyne.NewSize(100, headerHeight))

	timeWidth := float32(60)
	r.timeLabel.Move(fyne.NewPos(size.Width-timeWidth-padding, padding))
	r.timeLabel.Resize(fyne.NewSize(timeWidth, headerHeight))

	msgTop := padding + headerHeight + 6
	r.msgLabel.Move(fyne.NewPos(padding, msgTop))
	r.msgLabel.Resize(fyne.NewSize(size.Width-padding*2, size.Height-msgTop-padding))
}

func (r *styledBubbleRenderer) MinSize() fyne.Size {
	textMin := r.msgLabel.MinSize()
	return fyne.NewSize(
		fyne.Max(textMin.Width+28, 220),
		fyne.Max(textMin.Height+56, 72),
	)
}

func (r *styledBubbleRenderer) Refresh() {
	fyne.Do(func() {
		if r.bubble.isLocal {
			r.senderLabel.Text = "You"
			r.senderLabel.Color = localTextColor
			r.background.FillColor = localBubbleColor
		} else {
			r.senderLabel.Text = "Peer"
			r.senderLabel.Color = peerTextColor
			r.background.FillColor = peerBubbleColor
		}

		if !r.bubble.timestamp.IsZero() {
			r.timeLabel.Text = r.bubble.timestamp.Format("15:04:05")
		} else {
			r.timeLabel.Text = ""
		}

		r.msgLabel.Text = r.bubble.text

		r.background.Refresh()
		r.senderLabel.Refresh()
		r.timeLabel.Refresh()
		r.msgLabel.Refresh()
	})
}

func (r *styledBubbleRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.senderLabel, r.timeLabel, r.msgLabel}
}

func (r *styledBubbleRenderer) Destroy() {}

// SessionItem is a custom widget for displaying sessions in the sidebar
type SessionItem struct {
	widget.BaseWidget
	sessionID  string
	isActive   bool
	msgCount   int
	lastActive time.Time
}

// NewSessionItem creates a new session item widget
func NewSessionItem(sessionID string, isActive bool, msgCount int, lastActive time.Time) *SessionItem {
	s := &SessionItem{
		sessionID:  sessionID,
		isActive:   isActive,
		msgCount:   msgCount,
		lastActive: lastActive,
	}
	s.ExtendBaseWidget(s)
	return s
}

// Update updates the session item
func (s *SessionItem) Update(sessionID string, isActive bool, msgCount int, lastActive time.Time) {
	s.sessionID = sessionID
	s.isActive = isActive
	s.msgCount = msgCount
	s.lastActive = lastActive

	fyne.Do(func() {
		s.Refresh()
	})
}

// CreateRenderer implements fyne.Widget
func (s *SessionItem) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(color.Transparent)
	background.CornerRadius = 8

	icon := canvas.NewText("💬", theme.Color(theme.ColorNameForeground))
	icon.TextSize = 18

	idLabel := canvas.NewText(s.sessionID, theme.Color(theme.ColorNameForeground))
	idLabel.TextStyle = fyne.TextStyle{Bold: true}
	idLabel.TextSize = 12

	statusLabel := canvas.NewText("", theme.Color(theme.ColorNamePlaceHolder))
	statusLabel.TextSize = 10

	return &sessionItemRenderer{
		item:        s,
		background:  background,
		icon:        icon,
		idLabel:     idLabel,
		statusLabel: statusLabel,
	}
}

type sessionItemRenderer struct {
	item        *SessionItem
	background  *canvas.Rectangle
	icon        *canvas.Text
	idLabel     *canvas.Text
	statusLabel *canvas.Text
}

func (r *sessionItemRenderer) Layout(size fyne.Size) {
	r.background.Resize(size)
	r.background.Move(fyne.NewPos(0, 0))

	padding := float32(10)
	iconSize := float32(28)

	r.icon.Move(fyne.NewPos(padding, (size.Height-iconSize)/2))
	r.icon.Resize(fyne.NewSize(iconSize, iconSize))

	textX := padding + iconSize + 10
	r.idLabel.Move(fyne.NewPos(textX, padding))
	r.idLabel.Resize(fyne.NewSize(size.Width-textX-padding, 16))

	r.statusLabel.Move(fyne.NewPos(textX, padding+18))
	r.statusLabel.Resize(fyne.NewSize(size.Width-textX-padding, 14))
}

func (r *sessionItemRenderer) MinSize() fyne.Size {
	return fyne.NewSize(180, 52)
}

func (r *sessionItemRenderer) Refresh() {
	fyne.Do(func() {
		displayID := r.item.sessionID
		if len(displayID) > 14 {
			displayID = displayID[:14] + "…"
		}
		r.idLabel.Text = displayID

		if r.item.isActive {
			r.background.FillColor = color.RGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0x40}
			r.statusLabel.Text = "● Active"
			r.statusLabel.Color = statusConnectedColor
		} else {
			r.background.FillColor = color.Transparent
			if !r.item.lastActive.IsZero() {
				r.statusLabel.Text = r.item.lastActive.Format("15:04")
			} else {
				r.statusLabel.Text = ""
			}
			r.statusLabel.Color = theme.Color(theme.ColorNamePlaceHolder)
		}

		r.background.Refresh()
		r.idLabel.Refresh()
		r.statusLabel.Refresh()
	})
}

func (r *sessionItemRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.icon, r.idLabel, r.statusLabel}
}

func (r *sessionItemRenderer) Destroy() {}

// ConnectionStatus represents the current connection state
type ConnectionStatus int

const (
	StatusDisconnected ConnectionStatus = iota
	StatusConnecting
	StatusConnected
	StatusError
)

// StatusIndicator is a widget showing connection status
type StatusIndicator struct {
	widget.BaseWidget
	status  ConnectionStatus
	message string
}

// NewStatusIndicator creates a new status indicator
func NewStatusIndicator() *StatusIndicator {
	s := &StatusIndicator{
		status:  StatusDisconnected,
		message: "Not connected",
	}
	s.ExtendBaseWidget(s)
	return s
}

// SetStatus updates the status
func (s *StatusIndicator) SetStatus(status ConnectionStatus, message string) {
	s.status = status
	s.message = message

	fyne.Do(func() {
		s.Refresh()
	})
}

// GetStatus returns the current status
func (s *StatusIndicator) GetStatus() ConnectionStatus {
	return s.status
}

// CreateRenderer implements fyne.Widget
func (s *StatusIndicator) CreateRenderer() fyne.WidgetRenderer {
	dot := canvas.NewCircle(statusDisconnectedColor)
	label := canvas.NewText(s.message, theme.Color(theme.ColorNameForeground))
	label.TextSize = 12

	return &statusRenderer{
		indicator: s,
		dot:       dot,
		label:     label,
	}
}

type statusRenderer struct {
	indicator *StatusIndicator
	dot       *canvas.Circle
	label     *canvas.Text
}

func (r *statusRenderer) Layout(size fyne.Size) {
	dotSize := float32(10)
	padding := float32(8)

	r.dot.Move(fyne.NewPos(padding, (size.Height-dotSize)/2))
	r.dot.Resize(fyne.NewSize(dotSize, dotSize))

	r.label.Move(fyne.NewPos(padding+dotSize+8, (size.Height-14)/2))
	r.label.Resize(fyne.NewSize(size.Width-padding*2-dotSize-8, 14))
}

func (r *statusRenderer) MinSize() fyne.Size {
	return fyne.NewSize(150, 24)
}

func (r *statusRenderer) Refresh() {
	fyne.Do(func() {
		r.label.Text = r.indicator.message

		switch r.indicator.status {
		case StatusDisconnected:
			r.dot.FillColor = statusDisconnectedColor
		case StatusConnecting:
			r.dot.FillColor = statusConnectingColor
		case StatusConnected:
			r.dot.FillColor = statusConnectedColor
		case StatusError:
			r.dot.FillColor = statusErrorColor
		}

		r.dot.Refresh()
		r.label.Refresh()
	})
}

func (r *statusRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.dot, r.label}
}

func (r *statusRenderer) Destroy() {}

// LogViewer is a component for displaying application logs
type LogViewer struct {
	entries     []logger.LogEntry
	list        *widget.List
	visible     bool
	autoScroll  bool
	unsubscribe func()
}

// NewLogViewer creates a new log viewer
func NewLogViewer() *LogViewer {
	lv := &LogViewer{
		entries:    make([]logger.LogEntry, 0),
		autoScroll: true,
	}
	return lv
}

// Start starts listening for log updates
func (lv *LogViewer) Start() {
	// Load existing entries
	lv.entries = logger.GetEntries()

	// Subscribe to new entries
	lv.unsubscribe = logger.Subscribe(func(entry logger.LogEntry) {
		fyne.Do(func() {
			lv.entries = append(lv.entries, entry)
			// Keep last 200 entries in UI
			if len(lv.entries) > 200 {
				lv.entries = lv.entries[len(lv.entries)-200:]
			}
			if lv.list != nil {
				lv.list.Refresh()
				if lv.autoScroll {
					lv.list.ScrollToBottom()
				}
			}
		})
	})
}

// Stop stops listening for log updates
func (lv *LogViewer) Stop() {
	if lv.unsubscribe != nil {
		lv.unsubscribe()
		lv.unsubscribe = nil
	}
}

// Clear clears the log entries
func (lv *LogViewer) Clear() {
	lv.entries = make([]logger.LogEntry, 0)
	logger.ClearEntries()
	if lv.list != nil {
		lv.list.Refresh()
	}
}

// GetEntryCount returns the number of log entries
func (lv *LogViewer) GetEntryCount() int {
	return len(lv.entries)
}

// BuildUI creates the log viewer UI
func (lv *LogViewer) BuildUI() fyne.CanvasObject {
	lv.list = widget.NewList(
		func() int {
			return len(lv.entries)
		},
		func() fyne.CanvasObject {
			return NewLogEntryItem()
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < len(lv.entries) {
				item := obj.(*LogEntryItem)
				item.Update(lv.entries[id])
			}
		},
	)

	// Control buttons
	clearBtn := widget.NewButtonWithIcon("Clear", theme.DeleteIcon(), func() {
		lv.Clear()
	})

	autoScrollCheck := widget.NewCheck("Auto-scroll", func(checked bool) {
		lv.autoScroll = checked
	})
	autoScrollCheck.SetChecked(true)

	controls := container.NewHBox(
		clearBtn,
		autoScrollCheck,
	)

	header := widget.NewLabelWithStyle("Application Logs", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	return container.NewBorder(
		container.NewVBox(header, controls, widget.NewSeparator()),
		nil, nil, nil,
		lv.list,
	)
}

// LogEntryItem is a widget for displaying a single log entry
type LogEntryItem struct {
	widget.BaseWidget
	entry logger.LogEntry
}

// NewLogEntryItem creates a new log entry item
func NewLogEntryItem() *LogEntryItem {
	l := &LogEntryItem{}
	l.ExtendBaseWidget(l)
	return l
}

// Update updates the log entry
func (l *LogEntryItem) Update(entry logger.LogEntry) {
	l.entry = entry
	fyne.Do(func() {
		l.Refresh()
	})
}

// CreateRenderer implements fyne.Widget
func (l *LogEntryItem) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(color.Transparent)

	timeLabel := canvas.NewText("", theme.Color(theme.ColorNamePlaceHolder))
	timeLabel.TextSize = 10

	levelLabel := canvas.NewText("", logInfoColor)
	levelLabel.TextSize = 10
	levelLabel.TextStyle = fyne.TextStyle{Bold: true}

	msgLabel := widget.NewLabel("")
	msgLabel.Wrapping = fyne.TextWrapWord
	msgLabel.TextStyle = fyne.TextStyle{Monospace: true}

	return &logEntryRenderer{
		item:       l,
		background: background,
		timeLabel:  timeLabel,
		levelLabel: levelLabel,
		msgLabel:   msgLabel,
	}
}

type logEntryRenderer struct {
	item       *LogEntryItem
	background *canvas.Rectangle
	timeLabel  *canvas.Text
	levelLabel *canvas.Text
	msgLabel   *widget.Label
}

func (r *logEntryRenderer) Layout(size fyne.Size) {
	padding := float32(6)

	r.background.Resize(size)
	r.background.Move(fyne.NewPos(0, 0))

	r.timeLabel.Move(fyne.NewPos(padding, padding))
	r.timeLabel.Resize(fyne.NewSize(60, 14))

	r.levelLabel.Move(fyne.NewPos(padding+65, padding))
	r.levelLabel.Resize(fyne.NewSize(50, 14))

	r.msgLabel.Move(fyne.NewPos(padding+120, padding))
	r.msgLabel.Resize(fyne.NewSize(size.Width-padding*2-120, size.Height-padding*2))
}

func (r *logEntryRenderer) MinSize() fyne.Size {
	msgMin := r.msgLabel.MinSize()
	return fyne.NewSize(300, fyne.Max(msgMin.Height+12, 28))
}

func (r *logEntryRenderer) Refresh() {
	fyne.Do(func() {
		r.timeLabel.Text = r.item.entry.Timestamp.Format("15:04:05")

		r.levelLabel.Text = r.item.entry.Level
		switch r.item.entry.Level {
		case "INFO":
			r.levelLabel.Color = logInfoColor
		case "WARN":
			r.levelLabel.Color = logWarnColor
		case "ERROR":
			r.levelLabel.Color = logErrorColor
		case "DEBUG":
			r.levelLabel.Color = logDebugColor
		default:
			r.levelLabel.Color = theme.Color(theme.ColorNameForeground)
		}

		r.msgLabel.Text = r.item.entry.Message

		r.timeLabel.Refresh()
		r.levelLabel.Refresh()
		r.msgLabel.Refresh()
	})
}

func (r *logEntryRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.timeLabel, r.levelLabel, r.msgLabel}
}

func (r *logEntryRenderer) Destroy() {}

// FingerprintDisplay is a component for displaying and copying fingerprints
type FingerprintDisplay struct {
	emojiFingerprint string
	hexFingerprint   string
	app              fyne.App
}

// NewFingerprintDisplay creates a new fingerprint display
func NewFingerprintDisplay(app fyne.App) *FingerprintDisplay {
	f := &FingerprintDisplay{
		app: app,
	}
	return f
}

// SetFingerprints sets the emoji and hex fingerprints
func (f *FingerprintDisplay) SetFingerprints(emoji, hex string) {
	f.emojiFingerprint = emoji
	f.hexFingerprint = hex
}

// SetEmojiFingerprint sets just the emoji fingerprint
func (f *FingerprintDisplay) SetEmojiFingerprint(emoji string) {
	f.emojiFingerprint = emoji
}

// BuildUI creates the fingerprint display UI with copy buttons
func (f *FingerprintDisplay) BuildUI() fyne.CanvasObject {
	emojiLabel := widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{})
	emojiLabel.Wrapping = fyne.TextWrapWord

	copyEmojiBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		if f.emojiFingerprint != "" {
			f.app.Clipboard().SetContent(f.emojiFingerprint)
		}
	})
	copyEmojiBtn.Importance = widget.LowImportance

	emojiRow := container.NewBorder(nil, nil, nil, copyEmojiBtn, emojiLabel)

	card := widget.NewCard("Your Fingerprint", "", container.NewVBox(emojiRow))

	// Subscribe to fingerprint updates
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			if f.emojiFingerprint != "" && emojiLabel.Text != f.emojiFingerprint {
				fyne.Do(func() {
					emojiLabel.SetText(f.emojiFingerprint)
				})
			}
		}
	}()

	return card
}

// ContextMenuItem represents a menu item in a context menu
type ContextMenuItem struct {
	Label  string
	Icon   fyne.Resource
	Action func()
}

// ShowContextMenu displays a context menu at the given position
func ShowContextMenu(window fyne.Window, items []ContextMenuItem, pos fyne.Position) {
	menu := fyne.NewMenu("")
	for _, item := range items {
		if item.Label == "---" {
			menu.Items = append(menu.Items, fyne.NewMenuItemSeparator())
		} else {
			menuItem := fyne.NewMenuItem(item.Label, item.Action)
			if item.Icon != nil {
				menuItem.Icon = item.Icon
			}
			menu.Items = append(menu.Items, menuItem)
		}
	}

	canvas := window.Canvas()
	widget.ShowPopUpMenuAtPosition(menu, canvas, pos)
}

// CreateSessionContextMenu creates context menu items for a session
func CreateSessionContextMenu(app fyne.App, window fyne.Window, sessionID string, onDisconnect, onInfo func()) []ContextMenuItem {
	return []ContextMenuItem{
		{
			Label: "Copy Session ID",
			Icon:  theme.ContentCopyIcon(),
			Action: func() {
				app.Clipboard().SetContent(sessionID)
			},
		},
		{Label: "---"},
		{
			Label:  "Session Info",
			Icon:   theme.InfoIcon(),
			Action: onInfo,
		},
		{Label: "---"},
		{
			Label:  "Disconnect",
			Icon:   theme.CancelIcon(),
			Action: onDisconnect,
		},
	}
}

// CreateMessageContextMenu creates context menu items for a message
func CreateMessageContextMenu(app fyne.App, messageText string) []ContextMenuItem {
	return []ContextMenuItem{
		{
			Label: "Copy Message",
			Icon:  theme.ContentCopyIcon(),
			Action: func() {
				app.Clipboard().SetContent(messageText)
			},
		},
	}
}

// AnimatedDot is a pulsing dot indicator for connecting state
type AnimatedDot struct {
	widget.BaseWidget
	color   color.Color
	visible bool
}

// NewAnimatedDot creates a new animated dot
func NewAnimatedDot(c color.Color) *AnimatedDot {
	d := &AnimatedDot{
		color:   c,
		visible: true,
	}
	d.ExtendBaseWidget(d)
	return d
}

// SetColor sets the dot color
func (d *AnimatedDot) SetColor(c color.Color) {
	d.color = c
	fyne.Do(func() {
		d.Refresh()
	})
}

// CreateRenderer implements fyne.Widget
func (d *AnimatedDot) CreateRenderer() fyne.WidgetRenderer {
	circle := canvas.NewCircle(d.color)

	return &animatedDotRenderer{
		dot:    d,
		circle: circle,
	}
}

type animatedDotRenderer struct {
	dot    *AnimatedDot
	circle *canvas.Circle
}

func (r *animatedDotRenderer) Layout(size fyne.Size) {
	minDim := fyne.Min(size.Width, size.Height)
	r.circle.Resize(fyne.NewSize(minDim, minDim))
	r.circle.Move(fyne.NewPos((size.Width-minDim)/2, (size.Height-minDim)/2))
}

func (r *animatedDotRenderer) MinSize() fyne.Size {
	return fyne.NewSize(12, 12)
}

func (r *animatedDotRenderer) Refresh() {
	fyne.Do(func() {
		r.circle.FillColor = r.dot.color
		r.circle.Refresh()
	})
}

func (r *animatedDotRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.circle}
}

func (r *animatedDotRenderer) Destroy() {}
