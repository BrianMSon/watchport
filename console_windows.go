//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode             = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode             = kernel32.NewProc("SetConsoleMode")
	procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
	originalStdoutMode             uint32
	stdoutHandle                   syscall.Handle
	stdinHandle                    syscall.Handle
	originalStdinMode              uint32
)

const (
	_ENABLE_LINE_INPUT = 0x0002
	_ENABLE_ECHO_INPUT = 0x0004
)

type winCoord struct {
	X int16
	Y int16
}

type winSmallRect struct {
	Left   int16
	Top    int16
	Right  int16
	Bottom int16
}

type consoleScreenBufferInfo struct {
	Size              winCoord
	CursorPosition    winCoord
	Attributes        uint16
	Window            winSmallRect
	MaximumWindowSize winCoord
}

const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

func setupConsole() {
	stdoutHandle, _ = syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	procGetConsoleMode.Call(uintptr(stdoutHandle), uintptr(unsafe.Pointer(&originalStdoutMode)))
	procSetConsoleMode.Call(uintptr(stdoutHandle), uintptr(originalStdoutMode|ENABLE_VIRTUAL_TERMINAL_PROCESSING))
}

func restoreConsole() {
	procSetConsoleMode.Call(uintptr(stdoutHandle), uintptr(originalStdoutMode))
}

func clearScreen() {
	cmd := exec.Command("cmd", "/c", "cls")
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func moveCursor(row, col int) {
	fmt.Printf("\033[%d;%dH", row, col)
}

func clearToEnd() {
	fmt.Print("\033[J")
}

func clearLine() {
	fmt.Print("\033[K")
}

func enableRawInput() {
	stdinHandle, _ = syscall.GetStdHandle(syscall.STD_INPUT_HANDLE)
	r, _, _ := procGetConsoleMode.Call(uintptr(stdinHandle), uintptr(unsafe.Pointer(&originalStdinMode)))
	if r == 0 {
		return
	}
	newMode := originalStdinMode &^ (_ENABLE_LINE_INPUT | _ENABLE_ECHO_INPUT)
	procSetConsoleMode.Call(uintptr(stdinHandle), uintptr(newMode))
}

func disableRawInput() {
	if stdinHandle != 0 {
		procSetConsoleMode.Call(uintptr(stdinHandle), uintptr(originalStdinMode))
	}
}

func readKey() (byte, bool) {
	buf := make([]byte, 1)
	n, err := os.Stdin.Read(buf)
	if err != nil || n == 0 {
		return 0, false
	}
	// Windows: special keys (arrows, F1-F12) start with 0x00 or 0xE0
	if buf[0] == 0x00 || buf[0] == 0xE0 {
		os.Stdin.Read(buf) // read and discard scan code
		return 0, false
	}
	return buf[0], true
}

func getTerminalSize() (cols, rows int) {
	var info consoleScreenBufferInfo
	r, _, _ := procGetConsoleScreenBufferInfo.Call(uintptr(stdoutHandle), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return 80, 25
	}
	return int(info.Window.Right-info.Window.Left) + 1, int(info.Window.Bottom-info.Window.Top) + 1
}
