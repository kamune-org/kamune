package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
)

// AnimatedDot is a pulsing dot indicator for connecting state.
type AnimatedDot struct {
	widget.BaseWidget
	color   color.Color
	visible bool
}

// NewAnimatedDot creates a new animated dot.
func NewAnimatedDot(c color.Color) *AnimatedDot {
	d := &AnimatedDot{
		color:   c,
		visible: true,
	}
	d.ExtendBaseWidget(d)
	return d
}

// SetColor sets the dot color.
func (d *AnimatedDot) SetColor(c color.Color) {
	d.color = c
	fyne.Do(func() {
		d.Refresh()
	})
}

// CreateRenderer implements fyne.Widget.
func (d *AnimatedDot) CreateRenderer() fyne.WidgetRenderer {
	circle := canvas.NewCircle(d.color)

	return &animatedDotRenderer{
		dot:    d,
		circle: circle,
	}
}

type animatedDotRenderer struct {
	dot    *AnimatedDot
	circle *canvas.Circle
}

func (r *animatedDotRenderer) Layout(size fyne.Size) {
	minDim := fyne.Min(size.Width, size.Height)
	r.circle.Resize(fyne.NewSize(minDim, minDim))
	r.circle.Move(fyne.NewPos((size.Width-minDim)/2, (size.Height-minDim)/2))
}

func (r *animatedDotRenderer) MinSize() fyne.Size {
	return fyne.NewSize(12, 12)
}

func (r *animatedDotRenderer) Refresh() {
	r.circle.FillColor = r.dot.color
	r.circle.Refresh()
}

func (r *animatedDotRenderer) Objects() []fyne.CanvasObject {
	return []fyne.CanvasObject{r.circle}
}

func (r *animatedDotRenderer) Destroy() {}
