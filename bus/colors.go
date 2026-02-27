package main

import "image/color"

// Modern dark theme color palette.

// Sidebar & surface colors.
var (
	sidebarBgColor    = color.RGBA{R: 0x10, G: 0x14, B: 0x1e, A: 0xff}
	surfaceLightColor = color.RGBA{R: 0x1c, G: 0x22, B: 0x30, A: 0xff}
	cardBgColor       = color.RGBA{R: 0x18, G: 0x1e, B: 0x2c, A: 0xff}
)

// Message bubble colors.
var (
	localBubbleColor = color.RGBA{R: 0x4f, G: 0x46, B: 0xe5, A: 0xcc} // Indigo
	peerBubbleColor  = color.RGBA{R: 0x1e, G: 0x29, B: 0x3b, A: 0xee} // Slate-dark
	localTextColor   = color.White
	peerTextColor    = color.RGBA{R: 0xe2, G: 0xe8, B: 0xf0, A: 0xff}
)

// Status colors.
var (
	statusConnectedColor    = color.RGBA{R: 0x10, G: 0xb9, B: 0x81, A: 0xff} // Emerald
	statusConnectingColor   = color.RGBA{R: 0xf5, G: 0x9e, B: 0x0b, A: 0xff} // Amber
	statusDisconnectedColor = color.RGBA{R: 0x64, G: 0x6e, B: 0x82, A: 0xff} // Slate-gray
	statusErrorColor        = color.RGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff} // Red
)

// Accent colors.
var (
	accentPrimary   = color.RGBA{R: 0x63, G: 0x66, B: 0xf1, A: 0xff} // Indigo-500
	accentSecondary = color.RGBA{R: 0x8b, G: 0x5c, B: 0xf6, A: 0xff} // Violet-500
)

// Session list colors.
var (
	sessionActiveBg = color.RGBA{R: 0x63, G: 0x66, B: 0xf1, A: 0x30} // Indigo translucent
)

// Log level colors.
var (
	logInfoColor  = color.RGBA{R: 0x60, G: 0xa5, B: 0xfa, A: 0xff} // Blue-400
	logWarnColor  = color.RGBA{R: 0xfb, G: 0xbf, B: 0x24, A: 0xff} // Amber-400
	logErrorColor = color.RGBA{R: 0xf8, G: 0x71, B: 0x71, A: 0xff} // Red-400
	logDebugColor = color.RGBA{R: 0x94, G: 0xa3, B: 0xb8, A: 0xff} // Slate-400
)

// Badge & indicator colors.
var (
	badgeTextColor  = color.White
	onlineDotColor  = color.RGBA{R: 0x10, G: 0xb9, B: 0x81, A: 0xff}
	offlineDotColor = color.RGBA{R: 0x47, G: 0x50, B: 0x63, A: 0xff}
)

// Text shades.
var (
	textPrimary   = color.RGBA{R: 0xe2, G: 0xe8, B: 0xf0, A: 0xff}
	textSecondary = color.RGBA{R: 0x94, G: 0xa3, B: 0xb8, A: 0xff}
	textMuted     = color.RGBA{R: 0x64, G: 0x6e, B: 0x82, A: 0xff}
	textTimestamp = color.RGBA{R: 0x78, G: 0x85, B: 0x9e, A: 0xff}
)
