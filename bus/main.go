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

	logger.Info("Kamune Chat starting...")

	a := app.NewWithID("org.kamune.chat-gui")
	a.Settings().SetTheme(&chatTheme{})

	w := a.NewWindow("Kamune Chat")
	w.Resize(fyne.NewSize(950, 650))
	w.SetMaster()

	chatApp := NewChatApp(a, w)
	w.SetContent(chatApp.BuildUI())

	// Handle window close to cleanup properly
	w.SetCloseIntercept(func() {
		logger.Info("Window close requested, cleaning up...")
		chatApp.cleanup()
		w.Close()
	})

	logger.Info("Kamune Chat started successfully")
	w.ShowAndRun()
}

// chatTheme extends the default dark theme with custom colors for a modern chat look
type chatTheme struct{}

func (t *chatTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		// Deep dark blue-gray background
		return color.RGBA{R: 0x0f, G: 0x11, B: 0x1a, A: 0xff}
	case theme.ColorNameButton:
		// Slightly lighter surface for buttons
		return color.RGBA{R: 0x1e, G: 0x22, B: 0x30, A: 0xff}
	case theme.ColorNamePrimary:
		// Vibrant blue accent
		return color.RGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0xff}
	case theme.ColorNameForeground:
		// Off-white text for better readability
		return color.RGBA{R: 0xf1, G: 0xf5, B: 0xf9, A: 0xff}
	case theme.ColorNameInputBackground:
		// Dark input fields
		return color.RGBA{R: 0x1e, G: 0x22, B: 0x30, A: 0xff}
	case theme.ColorNamePlaceHolder:
		// Muted placeholder text
		return color.RGBA{R: 0x64, G: 0x74, B: 0x8b, A: 0xff}
	case theme.ColorNameSeparator:
		// Subtle separators
		return color.RGBA{R: 0x33, G: 0x3a, B: 0x4d, A: 0xff}
	case theme.ColorNameDisabled:
		// Disabled elements
		return color.RGBA{R: 0x47, G: 0x53, B: 0x69, A: 0xff}
	case theme.ColorNameScrollBar:
		// Visible but unobtrusive scrollbar
		return color.RGBA{R: 0x47, G: 0x53, B: 0x69, A: 0xff}
	case theme.ColorNameShadow:
		// Soft shadows
		return color.RGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x55}
	case theme.ColorNameHover:
		// Hover state
		return color.RGBA{R: 0x2d, G: 0x33, B: 0x48, A: 0xff}
	case theme.ColorNameFocus:
		// Focus ring - same as primary but slightly transparent
		return color.RGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0xcc}
	case theme.ColorNameSelection:
		// Text selection
		return color.RGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0x66}
	case theme.ColorNameSuccess:
		// Green for success states
		return color.RGBA{R: 0x22, G: 0xc5, B: 0x5e, A: 0xff}
	case theme.ColorNameWarning:
		// Amber for warnings
		return color.RGBA{R: 0xf5, G: 0xa6, B: 0x23, A: 0xff}
	case theme.ColorNameError:
		// Red for errors
		return color.RGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff}
	case theme.ColorNameInputBorder:
		// Input border color
		return color.RGBA{R: 0x3d, G: 0x45, B: 0x5c, A: 0xff}
	case theme.ColorNameMenuBackground:
		// Menu background
		return color.RGBA{R: 0x1a, G: 0x1e, B: 0x2c, A: 0xf0}
	case theme.ColorNameOverlayBackground:
		// Dialog/overlay background
		return color.RGBA{R: 0x1a, G: 0x1e, B: 0x2c, A: 0xf5}
	case theme.ColorNameHeaderBackground:
		// Header areas
		return color.RGBA{R: 0x16, G: 0x1a, B: 0x26, A: 0xff}
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
		return 10
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 18
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameCaptionText:
		return 11
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameScrollBar:
		return 10
	case theme.SizeNameScrollBarSmall:
		return 4
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameLineSpacing:
		return 4
	}
	return theme.DefaultTheme().Size(name)
}
