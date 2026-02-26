package main

import (
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// SessionItem is a custom widget for displaying sessions in the sidebar.
type SessionItem struct {
	widget.BaseWidget
	sessionID  string
	isActive   bool
	msgCount   int
	lastActive time.Time
}

// NewSessionItem creates a new session item widget.
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

// Update updates the session item.
func (s *SessionItem) Update(sessionID string, isActive bool, msgCount int, lastActive time.Time) {
	s.sessionID = sessionID
	s.isActive = isActive
	s.msgCount = msgCount
	s.lastActive = lastActive

	fyne.Do(func() {
		s.Refresh()
	})
}

// CreateRenderer implements fyne.Widget.
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
}

func (r *sessionItemRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.icon, r.idLabel, r.statusLabel}
}

func (r *sessionItemRenderer) Destroy() {}
