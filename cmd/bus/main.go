package main

import (
	"context"
	"embed"
	"log/slog"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/menu"
	"github.com/wailsapp/wails/v2/pkg/menu/keys"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func buildMenu(app *App) *menu.Menu {
	conn := menu.NewMenu()

	// Verification Mode submenu
	verifSub := menu.NewMenu()
	strict := verifSub.AddRadio("Strict", false, keys.CmdOrCtrl("0"), nil)
	quick := verifSub.AddRadio("Quick", true, keys.CmdOrCtrl("1"), nil)
	auto := verifSub.AddRadio("Auto-Accept", false, keys.CmdOrCtrl("2"), nil)

	radioItems := []*menu.MenuItem{strict, quick, auto}
	app.verifRadioItems = radioItems

	setVerifMode := func(ctx context.Context, mode int) {
		if !app.SetVerificationMode(mode) {
			prev := app.GetVerificationMode()
			for _, item := range radioItems {
				item.Checked = false
			}
			radioItems[prev].Checked = true
			runtime.MenuUpdateApplicationMenu(ctx)
			return
		}
		for _, item := range radioItems {
			item.Checked = false
		}
		radioItems[mode].Checked = true
		runtime.MenuUpdateApplicationMenu(ctx)
	}

	strict.Click = func(_ *menu.CallbackData) { setVerifMode(app.ctx, 0) }
	quick.Click = func(_ *menu.CallbackData) { setVerifMode(app.ctx, 1) }
	auto.Click = func(_ *menu.CallbackData) { setVerifMode(app.ctx, 2) }

	conn.Append(&menu.MenuItem{
		Label:   "Verification Mode",
		Type:    menu.SubmenuType,
		SubMenu: verifSub,
	})

	conn.AddSeparator()

	insecureItem := conn.AddCheckbox("Skip TLS Verification", app.GetInsecureTLS(), nil, func(_ *menu.CallbackData) {
		newVal := !app.GetInsecureTLS()
		if app.SetInsecureTLS(newVal) {
			runtime.MenuUpdateApplicationMenu(app.ctx)
			return
		}
		app.insecureMenuItem.Checked = app.GetInsecureTLS()
		runtime.MenuUpdateApplicationMenu(app.ctx)
	})
	app.insecureMenuItem = insecureItem

	conn.AddSeparator()

	conn.AddText("Share Connection Card…", keys.CmdOrCtrl("e"), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "show-share-card")
	})

	conn.AddText("Import from Clipboard", nil, func(_ *menu.CallbackData) {
		text, err := runtime.ClipboardGetText(app.ctx)
		if err != nil || text == "" {
			app.SendNotification("Clipboard", "No connection URL found in clipboard")
			return
		}
		runtime.EventsEmit(app.ctx, "import-from-clipboard", text)
	})

	conn.AddText("Import Connection URL…", keys.CmdOrCtrl("i"), func(_ *menu.CallbackData) {
		runtime.EventsEmit(app.ctx, "show-import-url")
	})

	view := menu.NewMenu()
	view.AddText("Toggle Full Screen", keys.Key("f11"), func(_ *menu.CallbackData) {
		app.ToggleFullscreen()
	})

	idMenu := menu.NewMenu()
	idMenu.AddText("Copy as Hex", nil, func(_ *menu.CallbackData) {
		fp := app.GetFingerprint()
		if fp["hex"] == "" {
			app.SendNotification("Identity", "No identity key — start a server first")
			return
		}
		_ = app.CopyToClipboard(fp["hex"])
		runtime.EventsEmit(app.ctx, "toast", "Copied! (Hex)", "info")
	})
	idMenu.AddText("Copy as Sum", nil, func(_ *menu.CallbackData) {
		fp := app.GetFingerprint()
		if fp["sum"] == "" {
			app.SendNotification("Identity", "No identity key — start a server first")
			return
		}
		_ = app.CopyToClipboard(fp["sum"])
		runtime.EventsEmit(app.ctx, "toast", "Copied! (Sum)", "info")
	})
	idMenu.AddText("Copy as Base64", nil, func(_ *menu.CallbackData) {
		fp := app.GetFingerprint()
		if fp["b64"] == "" {
			app.SendNotification("Identity", "No identity key — start a server first")
			return
		}
		_ = app.CopyToClipboard(fp["b64"])
		runtime.EventsEmit(app.ctx, "toast", "Copied! (Base64)", "info")
	})

	idMenu.AddSeparator()
	idMenu.AddText("Forget Saved Passphrase…", nil, func(_ *menu.CallbackData) {
		answer, err := runtime.MessageDialog(app.ctx, runtime.MessageDialogOptions{
			Title:         "Clear Saved Passphrase",
			Message:       "Remove the passphrase for the current database from your system keychain?\n\nThe passphrase will be requested again on next startup.",
			Type:          runtime.QuestionDialog,
			Buttons:       []string{"Clear", "Cancel"},
			DefaultButton: "Cancel",
			CancelButton:  "Cancel",
		})
		if err != nil || answer == "Cancel" || answer == "" {
			return
		}
		if err := app.ClearKeychainPassphrase(); err != nil {
			app.SendNotification("Identity", "No saved passphrase to forget.")
		} else {
			app.SendNotification("Identity", "Saved passphrase removed from keychain.")
		}
	})

	m := menu.NewMenu()
	m.Append(menu.AppMenu())
	m.Append(menu.EditMenu())
	m.Append(&menu.MenuItem{
		Label:   "Connection",
		Type:    menu.SubmenuType,
		SubMenu: conn,
	})
	m.Append(&menu.MenuItem{
		Label:   "View",
		Type:    menu.SubmenuType,
		SubMenu: view,
	})
	m.Append(&menu.MenuItem{
		Label:   "Identity",
		Type:    menu.SubmenuType,
		SubMenu: idMenu,
	})
	m.Append(menu.WindowMenu())

	return m
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "Bus — Kamune Chat",
		Width:     1050,
		Height:    720,
		MinWidth:  800,
		MinHeight: 600,
		Menu:      buildMenu(app),
		Mac:       &mac.Options{},
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 13, G: 16, B: 39, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []any{app},
	})

	if err != nil {
		slog.Error("Application error", "error", err)
	}
}
