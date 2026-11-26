//go:build windows

package gateway

import (
	"os"
	"time"
)

func requestSelfTerminate() {
	if p, err := os.FindProcess(os.Getpid()); err == nil && p != nil {
		if err := p.Signal(os.Interrupt); err == nil {
			time.Sleep(5 * time.Second)
		}
	}
	os.Exit(0)
}
