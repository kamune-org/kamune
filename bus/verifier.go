package main

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/kamune-org/kamune"
	"github.com/kamune-org/kamune/pkg/fingerprint"
)

// PeerVerificationResult represents the outcome of peer verification
type PeerVerificationResult struct {
	Accepted bool
	Error    error
}

// GUIVerifier provides GUI-based peer verification functionality
type GUIVerifier struct {
	window fyne.Window
	app    fyne.App
}

// NewGUIVerifier creates a new GUI-based verifier
func NewGUIVerifier(app fyne.App, window fyne.Window) *GUIVerifier {
	return &GUIVerifier{
		app:    app,
		window: window,
	}
}

// CreateRemoteVerifier returns a RemoteVerifier function that uses GUI dialogs
// This function can be passed to kamune.DialWithRemoteVerifier or kamune.ServeWithRemoteVerifier
func (v *GUIVerifier) CreateRemoteVerifier() kamune.RemoteVerifier {
	return func(store *kamune.Storage, peer *kamune.Peer) error {
		// Use a channel to synchronize between the GUI and the handshake goroutine
		resultChan := make(chan PeerVerificationResult, 1)

		// Get peer information
		key := peer.PublicKey.Marshal()
		emojiFingerprint := strings.Join(fingerprint.Emoji(key), " • ")
		hexFingerprint := fingerprint.Hex(key)

		// Check if peer is known
		var isPeerNew bool
		var firstSeenText string
		existingPeer, err := store.FindPeer(key)
		if err != nil {
			isPeerNew = true
			firstSeenText = "New peer - not previously seen"
		} else {
			firstSeenText = fmt.Sprintf("Known peer - first seen: %s",
				existingPeer.FirstSeen.Local().Format("2006-01-02 15:04:05"))
		}

		// Show verification dialog on the main thread
		// Fyne requires UI updates to happen on the main thread
		v.showVerificationDialog(peer.Name, emojiFingerprint, hexFingerprint, firstSeenText, isPeerNew, resultChan)

		// Wait for user response
		result := <-resultChan

		if result.Error != nil {
			return result.Error
		}

		if !result.Accepted {
			return kamune.ErrVerificationFailed
		}

		// Store new peer if accepted
		if isPeerNew {
			peer.FirstSeen = time.Now()
			if err := store.StorePeer(peer); err != nil {
				// Log error but don't fail - connection was accepted
				v.app.SendNotification(fyne.NewNotification("Warning",
					fmt.Sprintf("Failed to save peer: %s", err)))
			}
		}

		return nil
	}
}

// showVerificationDialog displays the peer verification dialog
func (v *GUIVerifier) showVerificationDialog(
	peerName string,
	emojiFingerprint string,
	hexFingerprint string,
	firstSeenText string,
	isNewPeer bool,
	resultChan chan<- PeerVerificationResult,
) {
	// Build the dialog content
	content := v.buildVerificationContent(peerName, emojiFingerprint, hexFingerprint, firstSeenText, isNewPeer)

	// Create custom dialog
	var d dialog.Dialog

	// Accept button
	acceptBtn := widget.NewButtonWithIcon("Accept", theme.ConfirmIcon(), func() {
		resultChan <- PeerVerificationResult{Accepted: true}
		d.Hide()
	})
	acceptBtn.Importance = widget.HighImportance

	// Reject button
	rejectBtn := widget.NewButtonWithIcon("Reject", theme.CancelIcon(), func() {
		resultChan <- PeerVerificationResult{Accepted: false}
		d.Hide()
	})
	rejectBtn.Importance = widget.DangerImportance

	// Button container
	buttons := container.NewHBox(
		layout.NewSpacer(),
		rejectBtn,
		acceptBtn,
	)

	// Full content with buttons
	fullContent := container.NewBorder(nil, buttons, nil, nil, content)

	d = dialog.NewCustomWithoutButtons("Verify Peer Connection", fullContent, v.window)
	d.Resize(fyne.NewSize(500, 380))

	// Handle dialog close (e.g., clicking outside or pressing Escape)
	d.SetOnClosed(func() {
		// Send rejection if channel is not already written to
		select {
		case resultChan <- PeerVerificationResult{Accepted: false}:
		default:
			// Already sent a result
		}
	})

	d.Show()
}

// buildVerificationContent creates the content for the verification dialog
func (v *GUIVerifier) buildVerificationContent(
	peerName string,
	emojiFingerprint string,
	hexFingerprint string,
	firstSeenText string,
	isNewPeer bool,
) fyne.CanvasObject {
	// Title
	titleLabel := widget.NewLabelWithStyle(
		"Connection Request",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)

	// Peer name
	peerNameLabel := widget.NewLabelWithStyle(
		fmt.Sprintf("From: %s", peerName),
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	peerNameLabel.Importance = widget.HighImportance

	// Status indicator (new or known peer)
	var statusColor fyne.ThemeColorName
	var statusText string
	if isNewPeer {
		statusColor = theme.ColorNameWarning
		statusText = "⚠ Unknown Peer"
	} else {
		statusColor = theme.ColorNameSuccess
		statusText = "✓ Known Peer"
	}

	statusLabel := canvas.NewText(statusText, theme.Color(statusColor))
	statusLabel.Alignment = fyne.TextAlignCenter
	statusLabel.TextSize = 14
	statusLabel.TextStyle = fyne.TextStyle{Bold: true}

	// First seen info
	firstSeenLabel := widget.NewLabel(firstSeenText)
	firstSeenLabel.Alignment = fyne.TextAlignCenter
	firstSeenLabel.Importance = widget.LowImportance

	// Emoji fingerprint section
	emojiFingerprintTitle := widget.NewLabelWithStyle(
		"Emoji Fingerprint",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)

	emojiFingerprintLabel := widget.NewLabelWithStyle(
		emojiFingerprint,
		fyne.TextAlignCenter,
		fyne.TextStyle{},
	)
	emojiFingerprintLabel.Wrapping = fyne.TextWrapWord

	// Create a card-like container for emoji fingerprint
	emojiCard := widget.NewCard("", "", container.NewVBox(
		emojiFingerprintTitle,
		emojiFingerprintLabel,
	))

	// Hex fingerprint (collapsible/secondary)
	hexFingerprintTitle := widget.NewLabelWithStyle(
		"Hex Fingerprint",
		fyne.TextAlignLeading,
		fyne.TextStyle{},
	)
	hexFingerprintTitle.Importance = widget.LowImportance

	hexFingerprintEntry := widget.NewEntry()
	hexFingerprintEntry.SetText(hexFingerprint)
	hexFingerprintEntry.Disable() // Read-only

	copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
		v.app.Clipboard().SetContent(hexFingerprint)
	})
	copyBtn.Importance = widget.LowImportance

	hexRow := container.NewBorder(nil, nil, nil, copyBtn, hexFingerprintEntry)

	// Warning message for new peers
	var warningWidget fyne.CanvasObject
	if isNewPeer {
		warningLabel := widget.NewLabel(
			"This peer is not in your trusted list. Verify their fingerprint through a secure channel before accepting.",
		)
		warningLabel.Wrapping = fyne.TextWrapWord
		warningLabel.Importance = widget.WarningImportance
		warningWidget = container.NewPadded(warningLabel)
	} else {
		warningWidget = layout.NewSpacer()
	}

	// Assemble the content
	content := container.NewVBox(
		titleLabel,
		widget.NewSeparator(),
		peerNameLabel,
		container.NewCenter(statusLabel),
		firstSeenLabel,
		widget.NewSeparator(),
		emojiCard,
		widget.NewSeparator(),
		hexFingerprintTitle,
		hexRow,
		warningWidget,
	)

	return container.NewPadded(content)
}

// QuickVerifier creates a simple verifier that auto-accepts known peers
// and shows a dialog only for new peers
func (v *GUIVerifier) CreateQuickVerifier() kamune.RemoteVerifier {
	return func(store *kamune.Storage, peer *kamune.Peer) error {
		key := peer.PublicKey.Marshal()

		// Check if peer is known
		_, err := store.FindPeer(key)
		if err == nil {
			// Known peer - auto-accept
			v.app.SendNotification(fyne.NewNotification("Peer Connected",
				fmt.Sprintf("Known peer %s connected", peer.Name)))
			return nil
		}

		// New peer - show verification dialog
		return v.CreateRemoteVerifier()(store, peer)
	}
}

// CreateAutoAcceptVerifier creates a verifier that accepts all connections
// Warning: This should only be used for testing or trusted networks
func (v *GUIVerifier) CreateAutoAcceptVerifier() kamune.RemoteVerifier {
	return func(store *kamune.Storage, peer *kamune.Peer) error {
		key := peer.PublicKey.Marshal()

		// Check if peer is new
		_, err := store.FindPeer(key)
		if err != nil {
			// Store new peer
			peer.FirstSeen = time.Now()
			if storeErr := store.StorePeer(peer); storeErr != nil {
				v.app.SendNotification(fyne.NewNotification("Warning",
					fmt.Sprintf("Failed to save peer: %s", storeErr)))
			}
		}

		// Send notification
		emojiFingerprint := strings.Join(fingerprint.Emoji(key), " • ")
		v.app.SendNotification(fyne.NewNotification("Peer Connected",
			fmt.Sprintf("%s\n%s", peer.Name, emojiFingerprint)))

		return nil
	}
}

// VerificationMode represents different verification behaviors
type VerificationMode int

const (
	// VerificationModeStrict always shows dialog for all peers
	VerificationModeStrict VerificationMode = iota
	// VerificationModeQuick auto-accepts known peers, shows dialog for new
	VerificationModeQuick
	// VerificationModeAutoAccept accepts all (for testing only)
	VerificationModeAutoAccept
)

// GetVerifier returns the appropriate verifier for the given mode
func (v *GUIVerifier) GetVerifier(mode VerificationMode) kamune.RemoteVerifier {
	switch mode {
	case VerificationModeStrict:
		return v.CreateRemoteVerifier()
	case VerificationModeQuick:
		return v.CreateQuickVerifier()
	case VerificationModeAutoAccept:
		return v.CreateAutoAcceptVerifier()
	default:
		return v.CreateRemoteVerifier()
	}
}
