package main

import (
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// StyledMessageBubble is an enhanced message widget with background styling.
type StyledMessageBubble struct {
	widget.BaseWidget
	text      string
	timestamp time.Time
	isLocal   bool
	onCopy    func(string) // Callback for copy action
}

// NewStyledMessageBubble creates a new styled message bubble.
func NewStyledMessageBubble(text string, timestamp time.Time, isLocal bool) *StyledMessageBubble {
	m := &StyledMessageBubble{
		text:      text,
		timestamp: timestamp,
		isLocal:   isLocal,
	}
	m.ExtendBaseWidget(m)
	return m
}

// Update updates the message content.
func (m *StyledMessageBubble) Update(text string, timestamp time.Time, isLocal bool) {
	m.text = text
	m.timestamp = timestamp
	m.isLocal = isLocal

	fyne.Do(func() {
		m.Refresh()
	})
}

// SetOnCopy sets the copy callback.
func (m *StyledMessageBubble) SetOnCopy(fn func(string)) {
	m.onCopy = fn
}

// CreateRenderer implements fyne.Widget.
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
}

func (r *styledBubbleRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.senderLabel, r.timeLabel, r.msgLabel}
}

func (r *styledBubbleRenderer) Destroy() {}
