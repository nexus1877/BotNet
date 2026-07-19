//go:build !windows

package main

import (
	"fmt"
	"image"
)

func captureScreen() (image.Image, error) {
	return nil, fmt.Errorf("screenshot not supported on this platform")
}
