package main

import (
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Color constants for message bubbles
var (
	localBubbleColor = color.RGBA{R: 0x0f, G: 0x6f, B: 0xff, A: 0x33}
	peerBubbleColor  = color.RGBA{R: 0xff, G: 0xa5, B: 0x00, A: 0x22}
	localTextColor   = color.RGBA{R: 0x7a, G: 0xb8, B: 0xff, A: 0xff}
	peerTextColor    = color.RGBA{R: 0xff, G: 0xc1, B: 0x66, A: 0xff}
)

// StyledMessageBubble is an enhanced message widget with background styling
type StyledMessageBubble struct {
	widget.BaseWidget
	text      string
	timestamp time.Time
	isLocal   bool
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

	// Ensure UI refresh happens on the Fyne UI thread.
	fyne.Do(func() {
		m.Refresh()
	})
}

// CreateRenderer implements fyne.Widget
func (m *StyledMessageBubble) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(localBubbleColor)
	background.CornerRadius = 8

	senderLabel := canvas.NewText("You", localTextColor)
	senderLabel.TextStyle = fyne.TextStyle{Bold: true}
	senderLabel.TextSize = 12

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
	padding := float32(12)
	headerHeight := float32(18)

	// Background fills the entire bubble
	r.background.Resize(size)
	r.background.Move(fyne.NewPos(0, 0))

	// Sender label at top left
	r.senderLabel.Move(fyne.NewPos(padding, padding))
	r.senderLabel.Resize(fyne.NewSize(100, headerHeight))

	// Time label at top right
	timeWidth := float32(50)
	r.timeLabel.Move(fyne.NewPos(size.Width-timeWidth-padding, padding))
	r.timeLabel.Resize(fyne.NewSize(timeWidth, headerHeight))

	// Message text below header
	msgTop := padding + headerHeight + 4
	r.msgLabel.Move(fyne.NewPos(padding, msgTop))
	r.msgLabel.Resize(fyne.NewSize(size.Width-padding*2, size.Height-msgTop-padding))
}

func (r *styledBubbleRenderer) MinSize() fyne.Size {
	textMin := r.msgLabel.MinSize()
	return fyne.NewSize(
		fyne.Max(textMin.Width+24, 200),
		fyne.Max(textMin.Height+50, 70),
	)
}

func (r *styledBubbleRenderer) Refresh() {
	// Renderer refresh must not mutate widget objects from a non-UI thread.
	// Marshal to the UI thread to avoid "Error in Fyne call thread" issues.
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

		// Avoid calling widget methods inside renderer refresh; set canvas/widget fields directly.
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

	// Ensure UI refresh happens on the Fyne UI thread.
	fyne.Do(func() {
		s.Refresh()
	})
}

// CreateRenderer implements fyne.Widget
func (s *SessionItem) CreateRenderer() fyne.WidgetRenderer {
	background := canvas.NewRectangle(color.Transparent)
	background.CornerRadius = 6

	icon := canvas.NewText("💬", theme.Color(theme.ColorNameForeground))
	icon.TextSize = 20

	idLabel := canvas.NewText(s.sessionID, theme.Color(theme.ColorNameForeground))
	idLabel.TextStyle = fyne.TextStyle{Bold: true}
	idLabel.TextSize = 13

	statusLabel := canvas.NewText("", theme.Color(theme.ColorNamePlaceHolder))
	statusLabel.TextSize = 11

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

	padding := float32(8)
	iconSize := float32(30)

	r.icon.Move(fyne.NewPos(padding, (size.Height-iconSize)/2))
	r.icon.Resize(fyne.NewSize(iconSize, iconSize))

	textX := padding + iconSize + 8
	r.idLabel.Move(fyne.NewPos(textX, padding))
	r.idLabel.Resize(fyne.NewSize(size.Width-textX-padding, 18))

	r.statusLabel.Move(fyne.NewPos(textX, padding+20))
	r.statusLabel.Resize(fyne.NewSize(size.Width-textX-padding, 16))
}

func (r *sessionItemRenderer) MinSize() fyne.Size {
	return fyne.NewSize(180, 50)
}

func (r *sessionItemRenderer) Refresh() {
	// Renderer refresh must not mutate widget objects from a non-UI thread.
	fyne.Do(func() {
		displayID := r.item.sessionID
		if len(displayID) > 16 {
			displayID = displayID[:16] + "..."
		}
		r.idLabel.Text = displayID

		if r.item.isActive {
			r.background.FillColor = color.RGBA{R: 0x0f, G: 0x6f, B: 0xff, A: 0x33}
			r.statusLabel.Text = "● Active"
			r.statusLabel.Color = color.RGBA{R: 0x4a, G: 0xde, B: 0x80, A: 0xff}
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

	// Ensure UI refresh happens on the Fyne UI thread.
	fyne.Do(func() {
		s.Refresh()
	})
}

// CreateRenderer implements fyne.Widget
func (s *StatusIndicator) CreateRenderer() fyne.WidgetRenderer {
	dot := canvas.NewCircle(theme.Color(theme.ColorNamePlaceHolder))
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
	// Renderer refresh must not mutate widget objects from a non-UI thread.
	fyne.Do(func() {
		r.label.Text = r.indicator.message

		switch r.indicator.status {
		case StatusDisconnected:
			r.dot.FillColor = color.RGBA{R: 0x6b, G: 0x6b, B: 0x8d, A: 0xff}
		case StatusConnecting:
			r.dot.FillColor = color.RGBA{R: 0xff, G: 0xc1, B: 0x07, A: 0xff}
		case StatusConnected:
			r.dot.FillColor = color.RGBA{R: 0x4a, G: 0xde, B: 0x80, A: 0xff}
		case StatusError:
			r.dot.FillColor = color.RGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff}
		}

		r.dot.Refresh()
		r.label.Refresh()
	})
}

func (r *statusRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.dot, r.label}
}

func (r *statusRenderer) Destroy() {}
