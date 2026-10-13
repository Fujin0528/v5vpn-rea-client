package main

import (
	"bytes"
	"image/png"
	"testing"
)

func TestGenerateTrayIcon(t *testing.T) {
	for _, conn := range []bool{true, false} {
		data := generateTrayIcon(conn)
		if len(data) == 0 {
			t.Fatalf("expected non-empty PNG data for connected=%v", conn)
		}
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("failed to decode generated PNG: %v", err)
		}
		bounds := img.Bounds()
		if bounds.Dx() != 32 || bounds.Dy() != 32 {
			t.Fatalf("unexpected image bounds: got %dx%d, want 32x32", bounds.Dx(), bounds.Dy())
		}
	}
}
