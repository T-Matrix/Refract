//go:build !windows

package gateway

import (
	"os"
	"syscall"
	"time"
)

func requestSelfTerminate() {
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		os.Exit(0)
	}
	time.Sleep(5 * time.Second)
	os.Exit(0)
}
