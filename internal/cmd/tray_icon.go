package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
)

// generateTrayIcon generates a 32x32 crisp PNG icon for the system tray
func generateTrayIcon(connected bool) []byte {
	const size = 32
	img := image.NewRGBA(image.Rect(0, 0, size, size))

	// Base color: Emerald green for connected, Sky blue for disconnected
	var primaryColor color.RGBA
	if connected {
		primaryColor = color.RGBA{R: 16, G: 185, B: 129, A: 255} // #10B981
	} else {
		primaryColor = color.RGBA{R: 2, G: 132, B: 199, A: 255} // #0284C7
	}

	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}

	// Draw rounded square background (radius ~6)
	for y := 2; y < size-2; y++ {
		for x := 2; x < size-2; x++ {
			dx := 0
			if x < 6 {
				dx = 6 - x
			} else if x > size-7 {
				dx = x - (size - 7)
			}
			dy := 0
			if y < 6 {
				dy = 6 - y
			} else if y > size-7 {
				dy = y - (size - 7)
			}
			if dx*dx+dy*dy <= 20 {
				img.Set(x, y, primaryColor)
			}
		}
	}

	// Draw crisp "V" emblem
	for t := 0; t <= 13; t++ {
		lx := 8 + t/2
		ly := 9 + t
		img.Set(lx, ly, white)
		img.Set(lx+1, ly, white)
		img.Set(lx-1, ly, white)

		rx := 24 - t/2
		ry := 9 + t
		img.Set(rx, ry, white)
		img.Set(rx+1, ry, white)
		img.Set(rx-1, ry, white)
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}
