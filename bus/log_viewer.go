package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune/bus/logger"
)

// LogViewer is a component for displaying application logs.
type LogViewer struct {
	entries     []logger.LogEntry
	list        *widget.List
	autoScroll  bool
	unsubscribe func()
}

// NewLogViewer creates a new log viewer.
func NewLogViewer() *LogViewer {
	lv := &LogViewer{
		entries:    make([]logger.LogEntry, 0),
		autoScroll: true,
	}
	return lv
}

// Start starts listening for log updates.
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

// Stop stops listening for log updates.
func (lv *LogViewer) Stop() {
	if lv.unsubscribe != nil {
		lv.unsubscribe()
		lv.unsubscribe = nil
	}
}

// Clear clears the log entries.
func (lv *LogViewer) Clear() {
	lv.entries = make([]logger.LogEntry, 0)
	logger.ClearEntries()
	if lv.list != nil {
		lv.list.Refresh()
	}
}

// GetEntryCount returns the number of log entries.
func (lv *LogViewer) GetEntryCount() int {
	return len(lv.entries)
}

// BuildUI creates the log viewer UI (just the list — chrome is added by the log panel).
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

	return lv.list
}

// ---------------------------------------------------------------------------
// LogEntryItem
// ---------------------------------------------------------------------------

// LogEntryItem is a widget for displaying a single log entry.
type LogEntryItem struct {
	widget.BaseWidget
	entry logger.LogEntry
}

// NewLogEntryItem creates a new log entry item.
func NewLogEntryItem() *LogEntryItem {
	l := &LogEntryItem{}
	l.ExtendBaseWidget(l)
	return l
}

// Update updates the log entry.
func (l *LogEntryItem) Update(entry logger.LogEntry) {
	l.entry = entry
	fyne.Do(func() {
		l.Refresh()
	})
}

// CreateRenderer implements fyne.Widget.
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
}

func (r *logEntryRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.background, r.timeLabel, r.levelLabel, r.msgLabel}
}

func (r *logEntryRenderer) Destroy() {}
