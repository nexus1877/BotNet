//go:build windows

package main

import (
	"fmt"
	"image"
	"unsafe"

	"golang.org/x/sys/windows"
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

func captureScreen() (image.Image, error) {
	user32 := windows.NewLazySystemDLL("user32.dll")
	gdi32 := windows.NewLazySystemDLL("gdi32.dll")
	getDC := user32.NewProc("GetDC")
	relDC := user32.NewProc("ReleaseDC")
	getSM := user32.NewProc("GetSystemMetrics")
	createDC := gdi32.NewProc("CreateCompatibleDC")
	createBMP := gdi32.NewProc("CreateCompatibleBitmap")
	selObj := gdi32.NewProc("SelectObject")
	bitBlt := gdi32.NewProc("BitBlt")
	delObj := gdi32.NewProc("DeleteObject")
	delDC := gdi32.NewProc("DeleteDC")
	getDIB := gdi32.NewProc("GetDIBits")
	hDC, _, _ := getDC.Call(0)
	if hDC == 0 {
		return nil, fmt.Errorf("GetDC failed")
	}
	defer relDC.Call(0, hDC)
	w, _, _ := getSM.Call(0)
	h, _, _ := getSM.Call(1)
	width, height := int(w), int(h)
	if width <= 0 || height <= 0 {
		return nil, fmt.Errorf("invalid screen dimensions: %dx%d", width, height)
	}
	hMem, _, _ := createDC.Call(hDC)
	if hMem == 0 {
		return nil, fmt.Errorf("CreateCompatibleDC failed")
	}
	defer delDC.Call(hMem)
	hBmp, _, _ := createBMP.Call(hDC, uintptr(width), uintptr(height))
	if hBmp == 0 {
		return nil, fmt.Errorf("CreateCompatibleBitmap failed")
	}
	defer delObj.Call(hBmp)
	selObj.Call(hMem, hBmp)
	const SRCCOPY = 0x00CC0020
	r, _, _ := bitBlt.Call(hMem, 0, 0, uintptr(width), uintptr(height), hDC, 0, 0, SRCCOPY)
	if r == 0 {
		return nil, fmt.Errorf("BitBlt failed")
	}
	var bi bitmapInfoHeader
	bi.BiSize = uint32(unsafe.Sizeof(bi))
	bi.BiWidth = int32(width)
	bi.BiHeight = -int32(height)
	bi.BiPlanes = 1
	bi.BiBitCount = 32
	bi.BiCompression = 0
	buf := make([]byte, width*height*4)
	getDIB.Call(hMem, hBmp, 0, uintptr(height), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bi)), 0)
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			i := (y*width + x) * 4
			off := (y*width + x) * 4
			img.Pix[off+0] = buf[i+2]
			img.Pix[off+1] = buf[i+1]
			img.Pix[off+2] = buf[i+0]
			img.Pix[off+3] = 255
		}
	}
	return img, nil
}
