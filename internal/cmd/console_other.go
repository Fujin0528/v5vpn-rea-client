//go:build !windows

package main

import (
	"fmt"
	"os"
)

func attachConsole() {
	// No-op on non-Windows platforms
}

func showErrorBox(title, message string) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", title, message)
}
