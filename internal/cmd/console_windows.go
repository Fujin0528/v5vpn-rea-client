//go:build windows

package main

import (
	"syscall"
)

func attachConsole() {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	attach := kernel32.NewProc("AttachConsole")
	_, _, _ = attach.Call(^uintptr(0))
}
