package main

import (
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

// SessionItem is a custom widget for displaying sessions in the sidebar.
type SessionItem struct {
	widget.BaseWidget
	sessionID  string
	peerName   string
	isActive   bool
	msgCount   int
	lastActive time.Time
}

// NewSessionItem creates a new session item widget.
func NewSessionItem(
	sessionID string, isActive bool, msgCount int, lastActive time.Time,
) *SessionItem {
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
func (s *SessionItem) Update(
	sessionID string, isActive bool, msgCount int, lastActive time.Time,
) {
	s.sessionID = sessionID
	s.isActive = isActive
	s.msgCount = msgCount
	s.lastActive = lastActive
}

// UpdateWithName updates the session item including the peer display name.
func (s *SessionItem) UpdateWithName(
	sessionID, peerName string, isActive bool, msgCount int, lastActive time.Time,
) {
	s.sessionID = sessionID
	s.peerName = peerName
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
	background.CornerRadius = 10

	// Active indicator bar on the left
	activeBar := canvas.NewRectangle(accentPrimary)
	activeBar.CornerRadius = 2

	// Online status dot
	statusDot := canvas.NewCircle(onlineDotColor)

	// Session icon
	icon := canvas.NewText("🔒", textPrimary)
	icon.TextSize = 18

	// Session ID label
	idLabel := canvas.NewText("", textPrimary)
	idLabel.TextStyle = fyne.TextStyle{Bold: true}
	idLabel.TextSize = 12

	// Status / time label
	statusLabel := canvas.NewText("", textMuted)
	statusLabel.TextSize = 10

	// Message count badge background
	badgeBg := canvas.NewRectangle(accentPrimary)
	badgeBg.CornerRadius = 9

	// Message count badge text
	badgeText := canvas.NewText("", badgeTextColor)
	badgeText.TextSize = 9
	badgeText.TextStyle = fyne.TextStyle{Bold: true}
	badgeText.Alignment = fyne.TextAlignCenter

	return &sessionItemRenderer{
		item:        s,
		background:  background,
		activeBar:   activeBar,
		statusDot:   statusDot,
		icon:        icon,
		idLabel:     idLabel,
		statusLabel: statusLabel,
		badgeBg:     badgeBg,
		badgeText:   badgeText,
	}
}

type sessionItemRenderer struct {
	item        *SessionItem
	background  *canvas.Rectangle
	activeBar   *canvas.Rectangle
	statusDot   *canvas.Circle
	icon        *canvas.Text
	idLabel     *canvas.Text
	statusLabel *canvas.Text
	badgeBg     *canvas.Rectangle
	badgeText   *canvas.Text
}

func (r *sessionItemRenderer) Layout(size fyne.Size) {
	r.background.Resize(size)
	r.background.Move(fyne.NewPos(0, 0))

	padding := float32(10)

	// Active bar on the left edge
	barWidth := float32(3)
	barHeight := size.Height - padding*2
	r.activeBar.Move(fyne.NewPos(3, padding))
	r.activeBar.Resize(fyne.NewSize(barWidth, barHeight))

	// Icon area
	iconX := float32(12)
	iconSize := float32(26)
	r.icon.Move(fyne.NewPos(iconX, (size.Height-iconSize)/2))
	r.icon.Resize(fyne.NewSize(iconSize, iconSize))

	// Status dot overlapping the icon bottom-right
	dotSize := float32(8)
	r.statusDot.Move(fyne.NewPos(iconX+iconSize-dotSize+1, (size.Height+iconSize)/2-dotSize+1))
	r.statusDot.Resize(fyne.NewSize(dotSize, dotSize))

	// Text area
	textX := iconX + iconSize + 10

	// Badge on right
	badgeW := float32(34)
	badgeH := float32(18)
	badgeX := size.Width - badgeW - padding
	badgeY := (size.Height - badgeH) / 2

	r.badgeBg.Move(fyne.NewPos(badgeX, badgeY))
	r.badgeBg.Resize(fyne.NewSize(badgeW, badgeH))
	r.badgeText.Move(fyne.NewPos(badgeX, badgeY+2))
	r.badgeText.Resize(fyne.NewSize(badgeW, badgeH-2))

	textW := badgeX - textX - 4

	r.idLabel.Move(fyne.NewPos(textX, padding))
	r.idLabel.Resize(fyne.NewSize(textW, 16))

	r.statusLabel.Move(fyne.NewPos(textX, padding+19))
	r.statusLabel.Resize(fyne.NewSize(textW, 14))
}

func (r *sessionItemRenderer) MinSize() fyne.Size {
	return fyne.NewSize(190, 54)
}

func (r *sessionItemRenderer) Refresh() {
	displayName := r.item.peerName
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
		r.activeBar.FillColor = accentPrimary
		r.activeBar.Show()
		r.statusLabel.Text = "● Active"
		r.statusLabel.Color = statusConnectedColor
		r.statusDot.FillColor = onlineDotColor
		r.idLabel.Color = textPrimary
	} else {
		r.background.FillColor = color.Transparent
		r.activeBar.Hide()
		r.statusDot.FillColor = onlineDotColor

		if !r.item.lastActive.IsZero() {
			elapsed := time.Since(r.item.lastActive)
			switch {
			case elapsed < time.Minute:
				r.statusLabel.Text = "just now"
			case elapsed < time.Hour:
				r.statusLabel.Text = fmt.Sprintf("%dm ago", int(elapsed.Minutes()))
			default:
				r.statusLabel.Text = r.item.lastActive.Format("15:04")
			}
		} else {
			r.statusLabel.Text = "Connected"
		}
		r.statusLabel.Color = textMuted
		r.idLabel.Color = textSecondary
	}

	// Message count badge
	if r.item.msgCount > 0 {
		if r.item.msgCount > 999 {
			r.badgeText.Text = "999+"
		} else {
			r.badgeText.Text = fmt.Sprintf("%d", r.item.msgCount)
		}
		if r.item.isActive {
			r.badgeBg.FillColor = accentPrimary
		} else {
			r.badgeBg.FillColor = surfaceLightColor
		}
		r.badgeBg.Show()
		r.badgeText.Show()
	} else {
		r.badgeBg.Hide()
		r.badgeText.Hide()
	}

	r.background.Refresh()
	r.activeBar.Refresh()
	r.statusDot.Refresh()
	r.icon.Refresh()
	r.idLabel.Refresh()
	r.statusLabel.Refresh()
	r.badgeBg.Refresh()
	r.badgeText.Refresh()
}

func (r *sessionItemRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{
		r.background,
		r.activeBar,
		r.icon,
		r.statusDot,
		r.idLabel,
		r.statusLabel,
		r.badgeBg,
		r.badgeText,
	}
}

func (r *sessionItemRenderer) Destroy() {}
