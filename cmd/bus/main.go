package main

import (
	"embed"
	"errors"
	"log/slog"
	"os"
	"runtime"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/appicon.png
var appIcon []byte

func buildMenu(app *App) *application.Menu {
	menu := app.wails.NewMenu()
	if runtime.GOOS == "darwin" {
		menu.AddRole(application.AppMenu)
	}
	menu.AddRole(application.EditMenu)

	conn := menu.AddSubmenu("Connection")
	verifSub := conn.AddSubmenu("Verification Mode")
	strict := verifSub.AddRadio("Strict", false).
		SetAccelerator("CmdOrCtrl+0")
	quick := verifSub.AddRadio("Quick", true).
		SetAccelerator("CmdOrCtrl+1")
	auto := verifSub.AddRadio("Auto-Accept", false).
		SetAccelerator("CmdOrCtrl+2")

	radioItems := []*application.MenuItem{strict, quick, auto}
	app.verifRadioItems = radioItems

	setVerifMode := func(mode int) {
		if !app.SetVerificationMode(mode) {
			mode = app.GetVerificationMode()
		}
		checkVerifRadio(radioItems, mode)
		menu.Update()
	}

	strict.OnClick(func(_ *application.Context) { setVerifMode(0) })
	quick.OnClick(func(_ *application.Context) { setVerifMode(1) })
	auto.OnClick(func(_ *application.Context) { setVerifMode(2) })

	incognitoItem := conn.AddCheckbox("Incognito Mode", false)
	app.incognitoMenuItem = incognitoItem
	incognitoItem.OnClick(func(_ *application.Context) {
		current := app.GetIncognito()
		if current {
			// The click has unchecked the item already, and the mode
			// may stay on: the user can decline the server restart, and
			// a start or a dial in progress keeps it.
			app.SetIncognito(false)
			incognitoItem.SetChecked(app.GetIncognito())
			menu.Update()
			return
		}
		incognitoItem.SetChecked(false)
		menu.Update()
		app.emitEvent("request-incognito-confirm")
	})

	conn.AddSeparator()
	conn.Add("Share Connection").
		SetAccelerator("CmdOrCtrl+E").
		OnClick(func(_ *application.Context) {
			app.emitEvent("show-share-card")
		})
	conn.Add("Import Connection").
		SetAccelerator("CmdOrCtrl+I").
		OnClick(func(_ *application.Context) {
			app.emitEvent("show-import-url")
		})
	conn.Add("Import from Clipboard").
		SetAccelerator("CmdOrCtrl+Shift+I").
		OnClick(func(_ *application.Context) {
			text, ok := app.wails.Clipboard.Text()
			if !ok || text == "" {
				app.SendNotification(
					"Clipboard",
					"No connection URL found in clipboard",
				)
				return
			}
			app.emitEvent("import-from-clipboard", text)
		})

	view := menu.AddSubmenu("View")
	view.Add("Toggle Full Screen").
		SetAccelerator("F11").
		OnClick(func(_ *application.Context) {
			app.ToggleFullscreen()
		})

	idMenu := menu.AddSubmenu("Identity")
	// The numeric fingerprint is the one peers compare to verify the key.
	idMenu.Add("Copy Numeric Fingerprint").
		OnClick(func(_ *application.Context) {
			fp := app.GetFingerprint()
			if fp["numeric"] == "" {
				app.SendNotification(
					"Identity",
					"No identity key — start a server first",
				)
				return
			}
			_ = app.CopyToClipboard(fp["numeric"])
			app.emitEvent("toast", "Copied! (Numeric)", "info")
		})
	idMenu.Add("Copy as Hex").OnClick(func(_ *application.Context) {
		fp := app.GetFingerprint()
		if fp["hex"] == "" {
			app.SendNotification(
				"Identity",
				"No identity key — start a server first",
			)
			return
		}
		_ = app.CopyToClipboard(fp["hex"])
		app.emitEvent("toast", "Copied! (Hex)", "info")
	})
	idMenu.Add("Copy as Sum").OnClick(func(_ *application.Context) {
		fp := app.GetFingerprint()
		if fp["sum"] == "" {
			app.SendNotification(
				"Identity",
				"No identity key — start a server first",
			)
			return
		}
		_ = app.CopyToClipboard(fp["sum"])
		app.emitEvent("toast", "Copied! (Sum)", "info")
	})
	idMenu.Add("Copy as Base64").OnClick(func(_ *application.Context) {
		fp := app.GetFingerprint()
		if fp["b64"] == "" {
			app.SendNotification(
				"Identity",
				"No identity key — start a server first",
			)
			return
		}
		_ = app.CopyToClipboard(fp["b64"])
		app.emitEvent("toast", "Copied! (Base64)", "info")
	})

	idMenu.AddSeparator()
	idMenu.Add("Change Passphrase…").
		OnClick(func(_ *application.Context) {
			if app.store() == nil {
				app.SendNotification(
					"Identity", "Unlock the database first.",
				)
				return
			}
			app.emitEvent("show-change-passphrase")
		})
	idMenu.Add("Forget Saved Passphrase…").
		OnClick(func(_ *application.Context) {
			forgot, err := app.ForgetSavedPassphrase(app.GetDBPath())
			switch {
			case errors.Is(err, ErrNoSavedPassphrase):
				app.SendNotification(
					"Identity",
					"No saved passphrase to forget.",
				)
			case err != nil:
				app.SendNotification("Identity", err.Error())
			case forgot:
				app.SendNotification(
					"Identity",
					"Saved passphrase removed from keychain.",
				)
			}
		})

	menu.AddRole(application.WindowMenu)
	app.wails.Menu.Set(menu)
	app.appMenu = menu
	return menu
}

func main() {
	stderrHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slog.SetDefault(slog.New(stderrHandler))

	bus := NewApp()
	slog.SetDefault(slog.New(&appLogHandler{
		app:    bus,
		stderr: stderrHandler,
	}))

	wailsApp := application.New(application.Options{
		Name:        "Bus",
		Description: "Kamune Chat",
		Icon:        appIcon,
		Services: []application.Service{
			application.NewService(bus),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})
	bus.wails = wailsApp
	buildMenu(bus)

	bus.window = wailsApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:              "Bus — Kamune Chat",
		Width:              1050,
		Height:             720,
		MinWidth:           800,
		MinHeight:          600,
		BackgroundColour:   application.NewRGB(13, 16, 39),
		URL:                "/",
		UseApplicationMenu: true,
		Linux: application.LinuxWindow{
			Icon: appIcon,
		},
	})

	if err := wailsApp.Run(); err != nil {
		slog.Error("Application error", "error", err)
	}
}
