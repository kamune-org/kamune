package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ConnectionStatus represents the current connection state.
type ConnectionStatus int

const (
	StatusDisconnected ConnectionStatus = iota
	StatusConnecting
	StatusConnected
	StatusError
)

// StatusIndicator is a widget showing connection status.
type StatusIndicator struct {
	widget.BaseWidget
	status  ConnectionStatus
	message string
}

// NewStatusIndicator creates a new status indicator.
func NewStatusIndicator() *StatusIndicator {
	s := &StatusIndicator{
		status:  StatusDisconnected,
		message: "Not connected",
	}
	s.ExtendBaseWidget(s)
	return s
}

// SetStatus updates the status.
func (s *StatusIndicator) SetStatus(status ConnectionStatus, message string) {
	s.status = status
	s.message = message

	fyne.Do(func() {
		s.Refresh()
	})
}

// GetStatus returns the current status.
func (s *StatusIndicator) GetStatus() ConnectionStatus {
	return s.status
}

// CreateRenderer implements fyne.Widget.
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
}

func (r *statusRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.dot, r.label}
}

func (r *statusRenderer) Destroy() {}
