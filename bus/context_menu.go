package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// ContextMenuItem represents a menu item in a context menu.
type ContextMenuItem struct {
	Label  string
	Icon   fyne.Resource
	Action func()
}

// ShowContextMenu displays a context menu at the given position.
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

// CreateSessionContextMenu creates context menu items for a session.
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

// CreateMessageContextMenu creates context menu items for a message.
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
