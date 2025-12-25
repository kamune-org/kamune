package main

import (
	"image/color"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"

	"github.com/kamune-org/kamune/bus/logger"
)

func main() {
	// Initialize file logger (best-effort). If initialization fails we continue
	// but emit a console warning. Logger writes to ./errors.log by default.
	if err := logger.Init("./errors.log"); err != nil {
		log.Printf("warning: failed to initialize logger: %v\n", err)
	} else {
		// Close logger on exit; ignore close error here.
		defer func() { _ = logger.Close() }()
	}

	a := app.NewWithID("org.kamune.chat-gui")
	a.Settings().SetTheme(&chatTheme{})

	w := a.NewWindow("Kamune Chat")
	w.Resize(fyne.NewSize(900, 600))
	w.SetMaster()

	chatApp := NewChatApp(a, w)
	w.SetContent(chatApp.BuildUI())

	w.ShowAndRun()
}

// chatTheme extends the default dark theme with custom colors for a modern chat look
type chatTheme struct{}

func (t *chatTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{R: 0x1a, G: 0x1a, B: 0x2e, A: 0xff}
	case theme.ColorNameButton:
		return color.RGBA{R: 0x16, G: 0x21, B: 0x3e, A: 0xff}
	case theme.ColorNamePrimary:
		return color.RGBA{R: 0x0f, G: 0x6f, B: 0xff, A: 0xff}
	case theme.ColorNameForeground:
		return color.RGBA{R: 0xea, G: 0xea, B: 0xea, A: 0xff}
	case theme.ColorNameInputBackground:
		return color.RGBA{R: 0x16, G: 0x21, B: 0x3e, A: 0xff}
	case theme.ColorNamePlaceHolder:
		return color.RGBA{R: 0x6b, G: 0x6b, B: 0x8d, A: 0xff}
	case theme.ColorNameSeparator:
		return color.RGBA{R: 0x2d, G: 0x2d, B: 0x4a, A: 0xff}
	case theme.ColorNameDisabled:
		return color.RGBA{R: 0x4a, G: 0x4a, B: 0x6a, A: 0xff}
	case theme.ColorNameScrollBar:
		return color.RGBA{R: 0x3d, G: 0x3d, B: 0x5c, A: 0xff}
	case theme.ColorNameShadow:
		return color.RGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x66}
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (t *chatTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *chatTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *chatTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 6
	case theme.SizeNameInnerPadding:
		return 8
	case theme.SizeNameText:
		return 14
	case theme.SizeNameInputBorder:
		return 1
	}
	return theme.DefaultTheme().Size(name)
}
