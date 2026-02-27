package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// chatTheme extends the default dark theme with custom colors for a modern chat look.
type chatTheme struct{}

func (t *chatTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{R: 0x0d, G: 0x10, B: 0x17, A: 0xff}
	case theme.ColorNameButton:
		return color.RGBA{R: 0x1c, G: 0x21, B: 0x2e, A: 0xff}
	case theme.ColorNamePrimary:
		return color.RGBA{R: 0x63, G: 0x66, B: 0xf1, A: 0xff} // indigo-500
	case theme.ColorNameForeground:
		return color.RGBA{R: 0xe2, G: 0xe8, B: 0xf0, A: 0xff}
	case theme.ColorNameInputBackground:
		return color.RGBA{R: 0x15, G: 0x1a, B: 0x26, A: 0xff}
	case theme.ColorNamePlaceHolder:
		return color.RGBA{R: 0x52, G: 0x5c, B: 0x6f, A: 0xff}
	case theme.ColorNameSeparator:
		return color.RGBA{R: 0x1e, G: 0x25, B: 0x36, A: 0xff}
	case theme.ColorNameDisabled:
		return color.RGBA{R: 0x3a, G: 0x42, B: 0x55, A: 0xff}
	case theme.ColorNameScrollBar:
		return color.RGBA{R: 0x3a, G: 0x42, B: 0x55, A: 0x99}
	case theme.ColorNameShadow:
		return color.RGBA{R: 0x00, G: 0x00, B: 0x00, A: 0x66}
	case theme.ColorNameHover:
		return color.RGBA{R: 0x1e, G: 0x25, B: 0x38, A: 0xff}
	case theme.ColorNameFocus:
		return color.RGBA{R: 0x63, G: 0x66, B: 0xf1, A: 0xaa}
	case theme.ColorNameSelection:
		return color.RGBA{R: 0x63, G: 0x66, B: 0xf1, A: 0x44}
	case theme.ColorNameSuccess:
		return color.RGBA{R: 0x10, G: 0xb9, B: 0x81, A: 0xff}
	case theme.ColorNameWarning:
		return color.RGBA{R: 0xf5, G: 0x9e, B: 0x0b, A: 0xff}
	case theme.ColorNameError:
		return color.RGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff}
	case theme.ColorNameInputBorder:
		return color.RGBA{R: 0x2a, G: 0x31, B: 0x44, A: 0xff}
	case theme.ColorNameMenuBackground:
		return color.RGBA{R: 0x14, G: 0x19, B: 0x25, A: 0xf8}
	case theme.ColorNameOverlayBackground:
		return color.RGBA{R: 0x14, G: 0x19, B: 0x25, A: 0xf8}
	case theme.ColorNameHeaderBackground:
		return color.RGBA{R: 0x10, G: 0x14, B: 0x1e, A: 0xff}
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
		return 7
	case theme.SizeNameInnerPadding:
		return 12
	case theme.SizeNameText:
		return 14
	case theme.SizeNameHeadingText:
		return 20
	case theme.SizeNameSubHeadingText:
		return 16
	case theme.SizeNameCaptionText:
		return 11
	case theme.SizeNameInputBorder:
		return 1
	case theme.SizeNameScrollBar:
		return 8
	case theme.SizeNameScrollBarSmall:
		return 4
	case theme.SizeNameSeparatorThickness:
		return 1
	case theme.SizeNameLineSpacing:
		return 5
	}
	return theme.DefaultTheme().Size(name)
}
