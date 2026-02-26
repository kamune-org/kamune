package main

import "image/color"

// Enhanced color palette for modern chat look.

// Message bubble colors.
var (
	localBubbleColor = color.RGBA{R: 0x1e, G: 0x40, B: 0x8f, A: 0xcc} // Deeper blue
	peerBubbleColor  = color.RGBA{R: 0x8f, G: 0x45, B: 0x25, A: 0xcc} // Warm amber
	localTextColor   = color.White
	peerTextColor    = color.White
)

// Status colors.
var (
	statusConnectedColor    = color.RGBA{R: 0x22, G: 0xc5, B: 0x5e, A: 0xff} // Green
	statusConnectingColor   = color.RGBA{R: 0xf5, G: 0xa6, B: 0x23, A: 0xff} // Amber
	statusDisconnectedColor = color.RGBA{R: 0x6b, G: 0x72, B: 0x80, A: 0xff} // Gray
	statusErrorColor        = color.RGBA{R: 0xef, G: 0x44, B: 0x44, A: 0xff} // Red
)

// UI accent colors.
var (
	accentPrimary   = color.RGBA{R: 0x3b, G: 0x82, B: 0xf6, A: 0xff} // Blue
	accentSecondary = color.RGBA{R: 0x8b, G: 0x5c, B: 0xf6, A: 0xff} // Purple
	surfaceColor    = color.RGBA{R: 0x1f, G: 0x25, B: 0x37, A: 0xff} // Dark surface
)

// Log level colors.
var (
	logInfoColor  = color.RGBA{R: 0x60, G: 0xa5, B: 0xfa, A: 0xff} // Light blue
	logWarnColor  = color.RGBA{R: 0xfb, G: 0xbf, B: 0x24, A: 0xff} // Yellow
	logErrorColor = color.RGBA{R: 0xf8, G: 0x71, B: 0x71, A: 0xff} // Light red
	logDebugColor = color.RGBA{R: 0x9c, G: 0xa3, B: 0xaf, A: 0xff} // Gray
)
