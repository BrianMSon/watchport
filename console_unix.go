//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

var savedTermState string

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func setupConsole() {
	// Unix/Linux에서는 터미널이 기본적으로 ANSI 이스케이프 지원
}

func restoreConsole() {
	// 복원할 것 없음
}

func clearScreen() {
	fmt.Print("\033[2J\033[H")
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
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	if err == nil {
		savedTermState = strings.TrimSpace(string(out))
	}
	cmd2 := exec.Command("stty", "cbreak", "-echo")
	cmd2.Stdin = os.Stdin
	cmd2.Run()
}

func disableRawInput() {
	if savedTermState != "" {
		cmd := exec.Command("stty", savedTermState)
		cmd.Stdin = os.Stdin
		cmd.Run()
	}
}

func readKey() (byte, bool) {
	buf := make([]byte, 1)
	n, err := os.Stdin.Read(buf)
	if err != nil || n == 0 {
		return 0, false
	}
	return buf[0], true
}

func getTerminalSize() (cols, rows int) {
	var ws winsize
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(syscall.Stdout), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if err != 0 {
		return 80, 25
	}
	return int(ws.Col), int(ws.Row)
}
