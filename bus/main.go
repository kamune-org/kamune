package main

import (
	"log"
	"os"
	"path/filepath"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"

	"github.com/kamune-org/kamune/bus/logger"
)

func main() {
	// Initialize file logger (best-effort). If initialization fails we continue
	// but emit a console warning. Logger writes to a temp directory by default.

	path, err := os.MkdirTemp("", "kamune-chat-logs")
	if err != nil {
		log.Printf("warning: failed to create temp log directory: %v\n", err)
		path = "."
	}
	path = filepath.Join(path, "bus.log")
	if err := logger.Init(path); err != nil {
		log.Printf("warning: failed to initialize logger: %v\n", err)
	} else {
		// Close logger on exit; ignore close error here.
		defer func() { _ = logger.Close() }()
	}

	logger.Info("Bus starting...")

	a := app.NewWithID("org.kamune.bus")
	a.Settings().SetTheme(&chatTheme{})

	w := a.NewWindow("Bus — Kamune Chat")
	w.Resize(fyne.NewSize(1050, 720))
	w.SetMaster()

	chatApp := NewChatApp(a, w)
	w.SetContent(chatApp.BuildUI())

	// Handle window close to cleanup properly
	w.SetCloseIntercept(func() {
		logger.Info("Window close requested, cleaning up...")
		chatApp.cleanup()
		w.Close()
	})

	logger.Info("Bus started successfully")
	w.ShowAndRun()
}
