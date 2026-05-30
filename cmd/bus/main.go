package main

import (
	"context"
	"embed"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"

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
	strict := conn.AddRadio("Strict", false, keys.CmdOrCtrl("0"), nil)
	quick := conn.AddRadio("Quick", true, keys.CmdOrCtrl("1"), nil)
	auto := conn.AddRadio("Auto-Accept", false, keys.CmdOrCtrl("2"), nil)

	radioItems := []*menu.MenuItem{strict, quick, auto}

	setVerifMode := func(ctx context.Context, mode int) {
		app.SetVerificationMode(mode)
		for _, item := range radioItems {
			item.Checked = false
		}
		radioItems[mode].Checked = true
		runtime.MenuUpdateApplicationMenu(ctx)
	}

	strict.Click = func(_ *menu.CallbackData) { setVerifMode(app.ctx, 0) }
	quick.Click = func(_ *menu.CallbackData) { setVerifMode(app.ctx, 1) }
	auto.Click = func(_ *menu.CallbackData) { setVerifMode(app.ctx, 2) }

	conn.AddSeparator()
	conn.AddText("Forget Saved Passphrase…", nil, func(_ *menu.CallbackData) {
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
			app.SendNotification("Keychain", "No saved passphrase to forget.")
		} else {
			app.SendNotification("Keychain", "Saved passphrase removed from keychain.")
		}
	})

	view := menu.NewMenu()
	view.AddText("Toggle Full Screen", keys.Key("f11"), func(_ *menu.CallbackData) {
		app.ToggleFullscreen()
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
	m.Append(menu.WindowMenu())

	return m
}

func main() {
	logPath := filepath.Join(os.TempDir(), "kamune-bus.log")

	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 5<<20 {
		os.Remove(logPath)
	}

	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		mw := io.MultiWriter(os.Stderr, logFile)
		slog.SetDefault(slog.New(slog.NewTextHandler(mw, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
		log.SetOutput(logFile)
		defer func() { _ = logFile.Close() }()
		slog.Info("Logger initialized", "path", logPath)
	} else {
		slog.Warn("Failed to create log file, using stderr only", "error", err)
	}

	app := NewApp()

	err = wails.Run(&options.App{
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
